//! Production Smart-HTTP v2 `packfile-uris` runtime bridge connecting
//! `crate::blob_git_gateway` to advertised-ref `wants` & whole-pack closure
//! verification, native fallback on unknown v2 args, bounded helpers, and
//! cancellation-safe RAII preflight/pin guards.

use std::{
    collections::HashSet,
    path::Path,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use uuid::Uuid;

use crate::ref_store::GitObjectFormat;

pub use super::preflight_guard::LiveRevalidatorFn;
use super::{
    cover_builder::{
        CoverBuildOutcome, HelperResourceLimits, RepoCoverBuildParams, build_residual_pack_bytes,
        build_verified_cover_proof_from_repo,
    },
    delivery::{PackHttpServerState, PackStreamMeta},
    planner::{CdnCircuitBreaker, CdnHealthState, DeliveryPlanRequest, DeliveryPlanner, VerifiedPackCoverInput},
    preflight_guard::{GatewayLiveAuthorizer, RegisteredPinAuth, StagedPinBatchGuard},
    protocol_v2::{
        encode_fetch_v2_response_bounded, is_v2_fetch_command_request, parse_fetch_v2_request,
        should_advertise_packfile_uris,
    },
    retention::PackDeliveryLeaseRegistry,
    signing::{LivePackReadAuthorizer, PackUriKeyring},
    ssrf_guard::PackUriDnsResolver,
    types::{
        DeliveryMode, DownloadSubjectContext, FallbackReason, OffloadPolicyConfig, PackObjectFormat, PackfileUriError,
    },
};

/// Request inputs passed from `blob_git_gateway::smart_http::upload_pack`.
pub struct GatewayFetchBridgeInput<'a> {
    pub git_binary: &'a Path,
    pub repo_dir: &'a Path,
    pub advertised_refs: &'a [(String, String)],
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
    pub request_timeout: Duration,
    pub max_response_bytes: u64,
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
        let live_auth = Arc::new(GatewayLiveAuthorizer::new(policy.max_concurrent_preflights, Arc::clone(&clock)));
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

    pub fn active_preflight_count(&self) -> usize {
        self.live_auth.active_preflight_count()
    }

    pub fn available_preflight_permits(&self) -> usize {
        self.live_auth.available_preflight_permits()
    }

    pub fn preflight_saturation_fallbacks(&self) -> u64 {
        self.live_auth.preflight_rejections.load(Ordering::Relaxed)
    }

    fn record_fallback(&self, reason: FallbackReason) {
        self.inline_fallback_responses.fetch_add(1, Ordering::Relaxed);
        *self.last_fallback.lock().unwrap_or_else(|p| p.into_inner()) = Some(reason);
    }

    /// Evaluates a Protocol v2 upload-pack request; returns `Ok(Some(body))` for offload+residual
    /// or `Ok(None)` when `ls-refs`, negotiation, unsupported v2 args, or fallback should run native `upload-pack`.
    pub async fn try_serve_upload_pack_v2(
        &self,
        input: GatewayFetchBridgeInput<'_>,
    ) -> Result<Option<Vec<u8>>, PackfileUriError> {
        Ok(self.try_serve_upload_pack_v2_with_guard(input, |_| Ok(())).await?.map(|(body, ())| body))
    }

    /// Evaluates a Protocol v2 upload-pack request while reserving the caller's response byte guard
    /// *before* inserting packs into `PackHttpServerState` or committing pin leases, and holding
    /// `PreflightSessionGuard` across residual pack creation, encoding, live revalidation, and commit.
    pub async fn try_serve_upload_pack_v2_with_guard<G, F>(
        &self,
        input: GatewayFetchBridgeInput<'_>,
        reserve_response: F,
    ) -> Result<Option<(Vec<u8>, G)>, PackfileUriError>
    where
        F: FnOnce(u64) -> Result<G, PackfileUriError>,
    {
        input.subject.validate()?;
        if !is_v2_fetch_command_request(input.request_bytes) {
            return Ok(None);
        }
        let pack_fmt = match input.object_format {
            GitObjectFormat::Sha1 => PackObjectFormat::Sha1,
            GitObjectFormat::Sha256 => PackObjectFormat::Sha256,
        };
        let fetch_req = parse_fetch_v2_request(input.request_bytes, pack_fmt)?;
        if fetch_req.has_unsupported_args() {
            self.record_fallback(FallbackReason::UnsupportedFetchArgs);
            return Ok(None);
        }
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
        if !super::pack_bijection::is_handle_confinement_available() {
            self.record_fallback(FallbackReason::HandleConfinementUnavailable);
            return Ok(None);
        }

        let now_unix = (self.pack_server.clock_unix)();
        let preflight_exp = now_unix.saturating_add(policy.ttl_secs.max(30));
        let Ok(preflight_guard) = self.live_auth.begin_preflight(
            input.tenant_id,
            input.repository_id,
            input.subject,
            preflight_exp,
            Arc::clone(&input.live_revalidator),
        ) else {
            self.record_fallback(FallbackReason::OverloadedOrQueueSaturated);
            return Ok(None);
        };

        let limits = HelperResourceLimits::for_gateway(&policy, input.request_timeout, input.max_response_bytes);
        let bundle = match build_verified_cover_proof_from_repo(&RepoCoverBuildParams {
            git_binary: input.git_binary,
            repo_dir: input.repo_dir,
            advertised_refs: input.advertised_refs,
            wants: &fetch_req.wants,
            haves: &fetch_req.haves,
            include_tag: fetch_req.include_tag,
            tenant_id: input.tenant_id,
            repository_id: input.repository_id,
            history_incarnation: input.history_incarnation,
            authority_epoch: u64::try_from(input.authority_epoch.max(1)).unwrap_or(1),
            group_epoch: u64::try_from(input.group_epoch.max(1)).unwrap_or(1),
            object_format: input.object_format,
            subject: input.subject,
            provider: input.provider,
            backend_identity_hex: input.backend_identity_hex,
            limits,
        })
        .await
        {
            Ok(CoverBuildOutcome::Planned(b)) => b,
            Ok(CoverBuildOutcome::Fallback(reason)) => {
                self.record_fallback(reason);
                return Ok(None);
            }
            Err(PackfileUriError::Unauthorized) => return Err(PackfileUriError::Unauthorized),
            Err(PackfileUriError::CapacityExceeded(_) | PackfileUriError::Timeout(_)) => {
                self.record_fallback(FallbackReason::ResourceBoundsExceeded);
                return Ok(None);
            }
            Err(PackfileUriError::IntegrityMismatch(_)) => {
                self.record_fallback(FallbackReason::PackContainsUnauthorizedObjects);
                return Ok(None);
            }
            Err(_) => {
                self.record_fallback(FallbackReason::IncompleteClosure);
                return Ok(None);
            }
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

        let cover_in = VerifiedPackCoverInput {
            auth: &bundle.auth,
            plan: &bundle.plan,
            proof: &bundle.proof,
            cover_index: &bundle.cover_index,
            retention_index: &bundle.retention_index,
            wire_packs: &bundle.wire_packs,
            residual_inline_bytes: 0,
            full_fallback_inline_bytes: bundle.plan.total_selected_bytes,
            rejected_unauthorized_pack: bundle.rejected_unauthorized_pack,
        };
        let effective_host = if !self.allowed_host.is_empty() {
            self.allowed_host.as_str()
        } else {
            policy.allowed_hosts.first().map_or("", String::as_str)
        };
        let cdn_health = *self.cdn_health.read().unwrap_or_else(|p| p.into_inner());
        let planned = match self
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
                    allowed_host: effective_host,
                    now_unix,
                    resolver: self.pack_server.resolver.as_ref(),
                    policy: &policy,
                    active_queue_saturated: false,
                },
            )
            .await
        {
            Ok(p) => p,
            Err(PackfileUriError::Unauthorized) => return Err(PackfileUriError::Unauthorized),
            Err(PackfileUriError::CapacityExceeded(_) | PackfileUriError::Timeout(_)) => {
                self.record_fallback(FallbackReason::ResourceBoundsExceeded);
                return Ok(None);
            }
            Err(PackfileUriError::RetentionPinMissing(_)) => {
                self.record_fallback(FallbackReason::PinAcquisitionFailed);
                return Ok(None);
            }
            Err(_) => {
                self.record_fallback(FallbackReason::CdnUnhealthy);
                return Ok(None);
            }
        };

        let DeliveryMode::OffloadPlusResidual { offloaded, residual_inline_bytes, residual_objects, lease_pins } =
            planned.mode
        else {
            if let DeliveryMode::InlineFallback { reason, .. } = planned.mode {
                self.record_fallback(reason);
            }
            return Ok(None);
        };

        let mut staged = StagedPinBatchGuard::new(
            lease_pins,
            self.planner.leases().clone(),
            Arc::clone(&self.live_auth),
            now_unix,
        );
        let mut offloaded_oids: HashSet<String> = HashSet::new();
        let mut pending_packs: Vec<PackStreamMeta> = Vec::with_capacity(offloaded.len());
        for desc in &offloaded {
            let (Some(raw), Some(oids)) =
                (bundle.raw_pack_bytes.get(&desc.pack_oid), bundle.pack_defined_oids.get(&desc.pack_oid))
            else {
                self.record_fallback(FallbackReason::IncompleteClosure);
                return Ok(None);
            };
            if oids.is_empty() || !oids.iter().all(|oid| bundle.wanted_closure_oids.contains(oid)) {
                self.record_fallback(FallbackReason::PackContainsUnauthorizedObjects);
                return Ok(None);
            }
            let meta = PackStreamMeta {
                tenant_id: input.tenant_id,
                repository_id: input.repository_id,
                pack_oid: desc.pack_oid.clone(),
                pack_hash_hex: desc.pack_hash_hex.clone(),
                object_format: pack_fmt,
                sha256_hex: desc.sha256_hex.clone(),
                payload: raw.clone(),
            };
            if meta.validate_bytes().is_err() {
                self.record_fallback(FallbackReason::PackContainsUnauthorizedObjects);
                return Ok(None);
            }
            offloaded_oids.extend(oids.iter().cloned());
            pending_packs.push(meta);
        }

        let residual_pack = match build_residual_pack_bytes(
            input.git_binary,
            input.repo_dir,
            &fetch_req.wants,
            &fetch_req.haves,
            &offloaded_oids,
            &bundle.wanted_closure_oids,
            &limits,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(PackfileUriError::Unauthorized) => return Err(PackfileUriError::Unauthorized),
            Err(PackfileUriError::CapacityExceeded(_) | PackfileUriError::Timeout(_)) => {
                self.record_fallback(FallbackReason::ResourceBoundsExceeded);
                return Ok(None);
            }
            Err(_) => {
                self.record_fallback(FallbackReason::IncompleteClosure);
                return Ok(None);
            }
        };

        let grace = policy.retention_grace_secs;
        let cloned_pins = staged.pins().to_vec();
        for (desc, pin_guard) in offloaded.iter().zip(cloned_pins.iter()) {
            staged.stage_registered_pin(
                desc.pin_id,
                RegisteredPinAuth {
                    tenant_id: input.tenant_id,
                    repository_id: input.repository_id,
                    subject: input.subject,
                    expires_at_unix: desc.expires_at_unix.saturating_add(grace),
                    revalidate: Arc::clone(&input.live_revalidator),
                    _pin_guard: Arc::clone(pin_guard),
                },
            );
        }

        let mode_ref = DeliveryMode::OffloadPlusResidual {
            offloaded,
            residual_inline_bytes,
            residual_objects,
            lease_pins: cloned_pins,
        };
        let body = match encode_fetch_v2_response_bounded(
            &policy,
            &mode_ref,
            &acked_haves,
            &residual_pack,
            true,
            input.max_response_bytes,
        ) {
            Ok(encoded) => encoded,
            Err(PackfileUriError::CapacityExceeded(_)) => {
                self.record_fallback(FallbackReason::ResourceBoundsExceeded);
                return Ok(None);
            }
            Err(_) => {
                self.record_fallback(FallbackReason::IncompleteClosure);
                return Ok(None);
            }
        };
        (input.live_revalidator)().await?;
        let response_guard = reserve_response(body.len() as u64)?;
        if self.pack_server.insert_packs_atomic(pending_packs).is_err() {
            drop(response_guard);
            self.record_fallback(FallbackReason::OverloadedOrQueueSaturated);
            return Ok(None);
        }
        staged.commit();
        drop(preflight_guard);
        self.offload_responses.fetch_add(1, Ordering::Relaxed);
        Ok(Some((body, response_guard)))
    }
}
