//! Production Smart-HTTP v2 `packfile-uris` runtime bridge connecting
//! `crate::blob_git_gateway` to `#184` `VerifiedFetchPlanProof` planning,
//! live PostgreSQL/RBAC re-authorization, and signed Axum packfile serving.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use uuid::Uuid;

use crate::{cache_wake::replica_cache::lease_pin::AuthTask, ref_store::GitObjectFormat};

use super::{
    cover_builder::{RepoCoverBuildParams, build_residual_pack_bytes, build_verified_cover_proof_from_repo},
    delivery::{PackHttpServerState, PackStreamMeta},
    planner::{CdnCircuitBreaker, CdnHealthState, DeliveryPlanRequest, DeliveryPlanner, VerifiedPackCoverInput},
    protocol_v2::{
        encode_fetch_v2_response_with_acks, parse_fetch_v2_request, should_advertise_packfile_uris,
    },
    retention::{OffloadPackPinGuard, PackDeliveryLeaseRegistry},
    signing::{LivePackReadAuthorizer, PackUriKeyring},
    ssrf_guard::PackUriDnsResolver,
    types::{
        DeliveryMode, DownloadSubjectContext, FallbackReason, OffloadPolicyConfig, PackObjectFormat, PackfileUriError,
    },
};

/// Async callback re-running live gateway authority (`ReadAuthorization::revalidate`).
pub type LiveRevalidatorFn = Arc<dyn Fn() -> AuthTask<'static, Result<(), PackfileUriError>> + Send + Sync>;

struct RegisteredPinAuth {
    tenant_id: Uuid,
    repository_id: Uuid,
    subject: DownloadSubjectContext,
    expires_at_unix: u64,
    revalidate: LiveRevalidatorFn,
    _pin_guard: Arc<OffloadPackPinGuard>,
}

struct GatewayLiveAuthorizer {
    pins: Mutex<HashMap<Uuid, RegisteredPinAuth>>,
    preflight: Mutex<HashMap<(Uuid, Uuid, DownloadSubjectContext), LiveRevalidatorFn>>,
    clock_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl GatewayLiveAuthorizer {
    fn sweep(&self, now_unix: u64) {
        let mut guard = self.pins.lock().unwrap_or_else(|p| p.into_inner());
        guard.retain(|_, v| now_unix <= v.expires_at_unix);
    }
}

impl LivePackReadAuthorizer for GatewayLiveAuthorizer {
    fn authorize_pack_download<'a>(
        &'a self,
        tenant_id: Uuid,
        repository_id: Uuid,
        subject: &'a DownloadSubjectContext,
        _pack_oid: &'a str,
        pin_id: Uuid,
    ) -> AuthTask<'a, Result<(), PackfileUriError>> {
        if let Err(e) = subject.validate() {
            return Box::pin(async move { Err(e) });
        }
        if tenant_id.is_nil() || repository_id.is_nil() {
            return Box::pin(async { Err(PackfileUriError::Unauthorized) });
        }
        let cb = if pin_id.is_nil() {
            let guard = self.preflight.lock().unwrap_or_else(|p| p.into_inner());
            guard.get(&(tenant_id, repository_id, *subject)).cloned()
        } else {
            let now = (self.clock_unix)();
            let guard = self.pins.lock().unwrap_or_else(|p| p.into_inner());
            guard
                .get(&pin_id)
                .filter(|rec| {
                    rec.tenant_id == tenant_id
                        && rec.repository_id == repository_id
                        && rec.subject == *subject
                        && now <= rec.expires_at_unix
                })
                .map(|rec| Arc::clone(&rec.revalidate))
        };
        let Some(revalidator) = cb else {
            return Box::pin(async { Err(PackfileUriError::Unauthorized) });
        };
        Box::pin(async move { (revalidator)().await })
    }
}

/// Request inputs passed from `blob_git_gateway::smart_http::upload_pack`.
pub struct GatewayFetchBridgeInput<'a> {
    pub git_binary: &'a Path,
    pub repo_dir: &'a Path,
    pub object_format: GitObjectFormat,
    pub request_bytes: &'a [u8],
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub subject: DownloadSubjectContext,
    pub provider: &'a str,
    pub backend_identity_hex: &'a str,
    pub live_revalidator: LiveRevalidatorFn,
}

/// Shared Smart-HTTP v2 `packfile-uris` offload runtime attached to a gateway router.
pub struct GatewayPackfileOffload {
    planner: Arc<DeliveryPlanner>,
    pack_server: Arc<PackHttpServerState>,
    live_auth: Arc<GatewayLiveAuthorizer>,
    cdn_health: RwLock<CdnHealthState>,
    allowed_host: String,
    pub offload_responses: AtomicU64,
    pub inline_fallback_responses: AtomicU64,
    last_fallback: Mutex<Option<FallbackReason>>,
}

impl GatewayPackfileOffload {
    pub fn new(
        keyring: Arc<PackUriKeyring>,
        policy: OffloadPolicyConfig,
        allowed_host: impl Into<String>,
        resolver: Arc<dyn PackUriDnsResolver>,
    ) -> Self {
        let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs()
        });
        let leases = PackDeliveryLeaseRegistry::with_max_leases(Default::default(), policy.max_active_leases);
        let live_auth = Arc::new(GatewayLiveAuthorizer {
            pins: Mutex::new(HashMap::new()),
            preflight: Mutex::new(HashMap::new()),
            clock_unix: Arc::clone(&clock),
        });
        let auth_dyn: Arc<dyn LivePackReadAuthorizer> = live_auth.clone();
        let pack_server = Arc::new(PackHttpServerState::new(
            Arc::clone(&keyring),
            leases.clone(),
            policy,
            resolver,
            auth_dyn,
            clock,
        ));
        let breaker = Arc::new(CdnCircuitBreaker::new(2, Duration::from_secs(30)));
        let planner = Arc::new(DeliveryPlanner::new(keyring, leases, breaker));
        Self {
            planner,
            pack_server,
            live_auth,
            cdn_health: RwLock::new(CdnHealthState::Healthy),
            allowed_host: allowed_host.into(),
            offload_responses: AtomicU64::new(0),
            inline_fallback_responses: AtomicU64::new(0),
            last_fallback: Mutex::new(None),
        }
    }

    pub fn pack_server(&self) -> &Arc<PackHttpServerState> {
        &self.pack_server
    }

    pub fn planner(&self) -> &Arc<DeliveryPlanner> {
        &self.planner
    }

    pub fn current_policy(&self) -> OffloadPolicyConfig {
        self.pack_server.current_policy()
    }

    pub fn set_policy(&self, policy: OffloadPolicyConfig) {
        self.pack_server.set_policy(policy);
    }

    pub fn set_cdn_health(&self, state: CdnHealthState) {
        *self.cdn_health.write().unwrap_or_else(|p| p.into_inner()) = state;
    }

    pub fn should_advertise_capability(&self) -> bool {
        should_advertise_packfile_uris(&self.current_policy())
    }

    pub fn last_fallback_reason(&self) -> Option<FallbackReason> {
        *self.last_fallback.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn record_fallback(&self, reason: FallbackReason) {
        self.inline_fallback_responses.fetch_add(1, Ordering::Relaxed);
        *self.last_fallback.lock().unwrap_or_else(|p| p.into_inner()) = Some(reason);
    }

    /// Evaluates a Protocol v2 upload-pack request; returns `Ok(Some(body))` for offload+residual
    /// or `Ok(None)` when `ls-refs`/negotiation/inline-fallback should run native `git upload-pack`.
    pub async fn try_serve_upload_pack_v2(
        &self,
        input: GatewayFetchBridgeInput<'_>,
    ) -> Result<Option<Vec<u8>>, PackfileUriError> {
        input.subject.validate()?;
        if !std::str::from_utf8(input.request_bytes)
            .unwrap_or_default()
            .contains("command=fetch")
        {
            return Ok(None);
        }
        let pack_fmt = match input.object_format {
            GitObjectFormat::Sha1 => PackObjectFormat::Sha1,
            GitObjectFormat::Sha256 => PackObjectFormat::Sha256,
        };
        let fetch_req = parse_fetch_v2_request(input.request_bytes, pack_fmt)?;
        if fetch_req.wants.is_empty() || (!fetch_req.done && (fetch_req.haves.is_empty() || fetch_req.wait_for_done)) {
            return Ok(None);
        }
        let policy = self.current_policy();
        if !policy.enabled {
            self.record_fallback(FallbackReason::FeatureDisabled);
            return Ok(None);
        }
        if fetch_req.uri_protocols.is_none() {
            self.record_fallback(FallbackReason::ClientOmittedPackfileUris);
            return Ok(None);
        }
        if !fetch_req.client_supports_https_offload() {
            self.record_fallback(FallbackReason::ClientUnsupportedProtocols);
            return Ok(None);
        }

        let Some(bundle) = build_verified_cover_proof_from_repo(&RepoCoverBuildParams {
            git_binary: input.git_binary,
            repo_dir: input.repo_dir,
            wants: &fetch_req.wants,
            haves: &fetch_req.haves,
            tenant_id: input.tenant_id,
            repository_id: input.repository_id,
            history_incarnation: input.history_incarnation,
            authority_epoch: u64::try_from(input.authority_epoch.max(1)).unwrap_or(1),
            group_epoch: u64::try_from(input.group_epoch.max(1)).unwrap_or(1),
            object_format: input.object_format,
            subject: input.subject,
            provider: input.provider,
            backend_identity_hex: input.backend_identity_hex,
        })?
        else {
            self.record_fallback(FallbackReason::IncompleteClosure);
            return Ok(None);
        };

        let acked_haves: Vec<String> = if fetch_req.done {
            Vec::new()
        } else {
            if bundle.plan.verified_have_commits.is_empty() {
                return Ok(None);
            }
            let needed_set: HashSet<_> = bundle.plan.needed_commits.iter().copied().collect();
            let has_unacked_root = bundle
                .cover_index
                .all_covers()
                .flat_map(|c| c.covered_commits().iter())
                .any(|link| needed_set.contains(&link.commit_oid) && link.parent_oids.is_empty());
            if has_unacked_root {
                return Ok(None);
            }
            bundle.plan.verified_have_commits.iter().copied().map(crate::ref_store::GitOid::as_hex).collect()
        };

        let now_unix = (self.pack_server.clock_unix)();
        self.live_auth.sweep(now_unix);
        let pf_key = (input.tenant_id, input.repository_id, input.subject);
        self.live_auth
            .preflight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(pf_key, Arc::clone(&input.live_revalidator));

        let cover_in = VerifiedPackCoverInput {
            auth: &bundle.auth,
            plan: &bundle.plan,
            proof: &bundle.proof,
            cover_index: &bundle.cover_index,
            retention_index: &bundle.retention_index,
            wire_packs: &bundle.wire_packs,
            residual_inline_bytes: 0,
            full_fallback_inline_bytes: bundle.plan.total_selected_bytes,
        };
        let cdn_health = *self.cdn_health.read().unwrap_or_else(|p| p.into_inner());
        let planned_res = self
            .planner
            .plan_fetch(
                self.live_auth.as_ref(),
                &DeliveryPlanRequest {
                    tenant_id: input.tenant_id,
                    repository_id: input.repository_id,
                    gate_revision: input.authority_epoch,
                    object_format: pack_fmt,
                    fetch_req: &fetch_req,
                    cover: &cover_in,
                    cdn_health,
                    allowed_host: &self.allowed_host,
                    now_unix,
                    resolver: self.pack_server.resolver.as_ref(),
                    policy: &policy,
                    active_queue_saturated: false,
                },
            )
            .await;
        self.live_auth
            .preflight
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&pf_key);
        let planned = planned_res?;

        let DeliveryMode::OffloadPlusResidual { ref offloaded, ref lease_pins, .. } = planned.mode else {
            if let DeliveryMode::InlineFallback { reason, .. } = planned.mode {
                self.record_fallback(reason);
            }
            return Ok(None);
        };

        let mut offloaded_oids: HashSet<String> = HashSet::new();
        for desc in offloaded {
            let Some(raw) = bundle.raw_pack_bytes.get(&desc.pack_oid) else {
                self.record_fallback(FallbackReason::IncompleteClosure);
                return Ok(None);
            };
            if let Some(oids) = bundle.pack_defined_oids.get(&desc.pack_oid) {
                offloaded_oids.extend(oids.iter().cloned());
            }
            self.pack_server.insert_pack(PackStreamMeta {
                tenant_id: input.tenant_id,
                repository_id: input.repository_id,
                pack_oid: desc.pack_oid.clone(),
                pack_hash_hex: desc.pack_hash_hex.clone(),
                object_format: pack_fmt,
                sha256_hex: desc.sha256_hex.clone(),
                payload: Bytes::from(raw.clone()),
            })?;
        }

        let residual_pack = build_residual_pack_bytes(
            input.git_binary,
            input.repo_dir,
            &fetch_req.wants,
            &fetch_req.haves,
            &offloaded_oids,
        )?;
        let encoded = encode_fetch_v2_response_with_acks(&policy, &planned.mode, &acked_haves, &residual_pack, true)?;
        for (desc, pin_guard) in offloaded.iter().zip(lease_pins.iter()) {
            self.live_auth.pins.lock().unwrap_or_else(|p| p.into_inner()).insert(
                desc.pin_id,
                RegisteredPinAuth {
                    tenant_id: input.tenant_id,
                    repository_id: input.repository_id,
                    subject: desc.subject,
                    expires_at_unix: desc.expires_at_unix.saturating_add(policy.retention_grace_secs),
                    revalidate: Arc::clone(&input.live_revalidator),
                    _pin_guard: Arc::clone(pin_guard),
                },
            );
        }
        self.offload_responses.fetch_add(1, Ordering::Relaxed);
        Ok(Some(encoded))
    }
}
