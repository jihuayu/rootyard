//! Bounded Git fetch delivery planner integrating #184 `VerifiedFetchPlanProof`
//! closure verification, live auth binding, active retention pins with rollback,
//! CDN circuit breaker, and deterministic inline fallback.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use uuid::Uuid;

use crate::ref_store::ref_version::{
    MAX_CLOSURE_PACKS,
    pack_cover::{
        AuthorizationContext, CoverHierarchyIndex, FetchPlan, PackRetentionState, RetentionClassificationIndex,
        VerifiedFetchPlanProof,
    },
};

use super::{
    protocol_v2::FetchV2Request,
    retention::{AcquireLeaseParams, OffloadPackPinGuard, PackDeliveryLeaseRegistry},
    signing::{LivePackReadAuthorizer, MintUriRequest, PackUriKeyring, mint_signed_offload_uri},
    ssrf_guard::{PackUriDnsResolver, validate_policy_config},
    types::{
        DeliveryMode, DeliveryTelemetry, DownloadSubjectContext, FallbackReason, OffloadPolicyConfig, PackObjectFormat,
        PackfileClosureMember, PackfileUriError,
    },
};

/// Operational health hint for an offload CDN origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdnHealthState {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Default)]
struct BreakerInner {
    failures: u32,
    open_until: Option<Instant>,
    probing: bool,
}

/// Half-open CDN circuit breaker enabling fast pre-negotiation inline fallback.
pub struct CdnCircuitBreaker {
    state: Mutex<BreakerInner>,
    threshold: u32,
    cooldown: Duration,
}

impl CdnCircuitBreaker {
    pub fn new(threshold: u32, cooldown: Duration) -> Self {
        Self { state: Mutex::new(BreakerInner::default()), threshold: threshold.max(1), cooldown }
    }

    pub fn try_begin(&self) -> Option<CdnProbeGuard<'_>> {
        let now = Instant::now();
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match st.open_until {
            None => Some(CdnProbeGuard { breaker: self, half_open: false, settled: false }),
            Some(until) if now < until => None,
            Some(_) if st.probing => None,
            Some(_) => {
                st.probing = true;
                Some(CdnProbeGuard { breaker: self, half_open: true, settled: false })
            }
        }
    }

    pub fn record_ok(&self) {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.failures = 0;
        st.open_until = None;
        st.probing = false;
    }

    pub fn record_err(&self) {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let was_open = st.open_until.is_some();
        st.probing = false;
        st.failures = st.failures.saturating_add(1);
        if was_open || st.failures >= self.threshold {
            st.open_until = Instant::now().checked_add(self.cooldown);
        }
    }

    pub fn is_open(&self) -> bool {
        let now = Instant::now();
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.open_until.is_some_and(|until| now < until)
    }
}

pub struct CdnProbeGuard<'a> {
    breaker: &'a CdnCircuitBreaker,
    half_open: bool,
    settled: bool,
}

impl CdnProbeGuard<'_> {
    pub fn record_ok(mut self) {
        self.settled = true;
        self.breaker.record_ok();
    }

    pub fn record_err(mut self) {
        self.settled = true;
        self.breaker.record_err();
    }
}

impl Drop for CdnProbeGuard<'_> {
    fn drop(&mut self) {
        if !self.settled && self.half_open {
            let mut st = self.breaker.state.lock().unwrap_or_else(|p| p.into_inner());
            st.probing = false;
        }
    }
}

/// Verified wire hashes and byte length for one `#184` `pack_id` staged on CDN/pack cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackWireMeta {
    pub pack_oid: String,
    pub pack_hash_hex: String,
    pub sha256_hex: String,
    pub byte_len: u64,
    pub cache_warm: bool,
}

/// Proof-bound `#184` closure input replacing unverified caller object counters.
pub struct VerifiedPackCoverInput<'a> {
    pub auth: &'a AuthorizationContext,
    pub plan: &'a FetchPlan,
    pub proof: &'a VerifiedFetchPlanProof,
    pub cover_index: &'a CoverHierarchyIndex,
    pub retention_index: &'a RetentionClassificationIndex,
    pub wire_packs: &'a HashMap<Uuid, PackWireMeta>,
    pub residual_inline_bytes: u64,
    pub full_fallback_inline_bytes: u64,
}

impl VerifiedPackCoverInput<'_> {
    pub fn total_planned_commits(&self) -> u64 {
        self.plan.needed_commits.len() as u64
    }
}

/// Inputs for planning whether to offload packs via `packfile-uris` or fall back inline.
pub struct DeliveryPlanRequest<'a> {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub gate_revision: i64,
    pub object_format: PackObjectFormat,
    pub fetch_req: &'a FetchV2Request,
    pub cover: &'a VerifiedPackCoverInput<'a>,
    pub cdn_health: CdnHealthState,
    pub allowed_host: &'a str,
    pub now_unix: u64,
    pub resolver: &'a dyn PackUriDnsResolver,
    pub policy: &'a OffloadPolicyConfig,
    pub active_queue_saturated: bool,
}

/// Output of [`DeliveryPlanner::plan_fetch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedFetchResponse {
    pub mode: DeliveryMode,
    pub telemetry: DeliveryTelemetry,
}

/// Stateful planner owning signing keys, active retention pin registry, and CDN breaker.
pub struct DeliveryPlanner {
    keyring: Arc<PackUriKeyring>,
    leases: PackDeliveryLeaseRegistry,
    breaker: Arc<CdnCircuitBreaker>,
    nonce_seq: AtomicU64,
}

impl DeliveryPlanner {
    pub fn new(
        keyring: Arc<PackUriKeyring>,
        leases: PackDeliveryLeaseRegistry,
        breaker: Arc<CdnCircuitBreaker>,
    ) -> Self {
        Self { keyring, leases, breaker, nonce_seq: AtomicU64::new(1) }
    }

    pub fn leases(&self) -> &PackDeliveryLeaseRegistry {
        &self.leases
    }

    pub fn breaker(&self) -> &Arc<CdnCircuitBreaker> {
        &self.breaker
    }

    /// Evaluates `#184` proof + live auth, protocol support, CDN health, bounds, and retention pins.
    pub async fn plan_fetch(
        &self,
        authorizer: &dyn LivePackReadAuthorizer,
        req: &DeliveryPlanRequest<'_>,
    ) -> Result<PlannedFetchResponse, PackfileUriError> {
        let auth = req.cover.auth;
        let subject = DownloadSubjectContext::new(auth.actor_id, auth.token_id, auth.auth_epoch)?;
        if req.tenant_id.is_nil()
            || req.repository_id.is_nil()
            || auth.tenant_id != req.tenant_id
            || auth.repository_id != req.repository_id
            || !req.cover.proof.binds_live_auth(auth)
        {
            return Err(PackfileUriError::Unauthorized);
        }
        authorizer
            .authorize_pack_download(req.tenant_id, req.repository_id, &subject, "closure-plan", Uuid::nil())
            .await?;

        if let Some(reason) = self.check_fallback_preconditions(req)? {
            return Ok(Self::build_inline_response(req.cover, reason));
        }

        let (selected, residual_inline_bytes, residual_objects) = match Self::select_proof_bound_candidates(req)? {
            Some(tuple) => tuple,
            None => return Ok(Self::build_inline_response(req.cover, FallbackReason::IncompleteClosure)),
        };
        if selected.is_empty() {
            return Ok(Self::build_inline_response(req.cover, FallbackReason::BelowOffloadThreshold));
        }
        self.mint_offloaded_descriptors(req, subject, &selected, residual_inline_bytes, residual_objects)
    }

    /// Explicit clean pre-body escalation to a full inline pack response after bounded retries fail.
    pub fn plan_full_inline_retry(cover: &VerifiedPackCoverInput<'_>, reason: FallbackReason) -> PlannedFetchResponse {
        Self::build_inline_response(cover, reason)
    }

    fn check_fallback_preconditions(
        &self,
        req: &DeliveryPlanRequest<'_>,
    ) -> Result<Option<FallbackReason>, PackfileUriError> {
        if !req.policy.enabled {
            return Ok(Some(FallbackReason::FeatureDisabled));
        }
        validate_policy_config(req.policy)?;
        if req.fetch_req.uri_protocols.is_none() {
            return Ok(Some(FallbackReason::ClientOmittedPackfileUris));
        }
        if !req.fetch_req.client_supports_https_offload() {
            return Ok(Some(FallbackReason::ClientUnsupportedProtocols));
        }
        if req.cover.proof.selected_cover_ids().len() > MAX_CLOSURE_PACKS
            || req.cover.plan.selected_covers.len() > MAX_CLOSURE_PACKS
            || req.cover.wire_packs.len() > MAX_CLOSURE_PACKS
        {
            return Err(PackfileUriError::CapacityExceeded(
                "closure candidate count exceeds MAX_CLOSURE_PACKS".to_owned(),
            ));
        }
        if !req.cover.proof.binds(req.cover.plan)
            || req.cover.proof.realm().tenant_id() != req.tenant_id
            || req.cover.proof.realm().repository_id() != req.repository_id
        {
            return Ok(Some(FallbackReason::IncompleteClosure));
        }
        if req.active_queue_saturated {
            return Ok(Some(FallbackReason::OverloadedOrQueueSaturated));
        }
        if req.policy.fallback_on_unhealthy_cdn {
            if self.breaker.is_open() {
                return Ok(Some(FallbackReason::CdnBreakerOpen));
            }
            if req.cdn_health == CdnHealthState::Unavailable {
                return Ok(Some(FallbackReason::CdnUnhealthy));
            }
        }
        Ok(None)
    }

    fn select_proof_bound_candidates(
        req: &DeliveryPlanRequest<'_>,
    ) -> Result<Option<(Vec<PackfileClosureMember>, u64, u64)>, PackfileUriError> {
        let cover_ids = req.cover.proof.selected_cover_ids();
        let pack_ids = req.cover.proof.selected_pack_ids();
        if cover_ids.is_empty() || cover_ids.len() != pack_ids.len() {
            return Ok(None);
        }
        let mut selected = Vec::new();
        let mut selected_bytes = 0u64;
        let mut residual_inline_bytes = req.cover.residual_inline_bytes;
        let mut residual_objects = 0u64;

        for (cover_id, pack_id) in cover_ids.iter().zip(pack_ids.iter()) {
            let Some(record) = req.cover.cover_index.get(cover_id) else {
                return Ok(None);
            };
            if record.verify_digest().is_err() || record.pack().entry().pack_id() != *pack_id {
                return Ok(None);
            }
            let commit_cnt = record.covered_commits().len() as u64;
            let cls = req.cover.retention_index.classify_cover(record);
            let retention_ok = cls.state == Some(PackRetentionState::PlannableForFetch)
                && cls.physically_present
                && cls.plannable_for_fetch
                && !cls.gc_eligible
                && !record.artifacts().is_thin_pack;

            let Some(wire) = req.cover.wire_packs.get(pack_id) else {
                residual_inline_bytes = residual_inline_bytes.saturating_add(record.artifacts().pack_locator.length());
                residual_objects = residual_objects.saturating_add(commit_cnt);
                continue;
            };
            if wire.byte_len != record.artifacts().pack_locator.length() {
                return Ok(None);
            }
            let member = PackfileClosureMember {
                pack_oid: wire.pack_oid.clone(),
                pack_hash_hex: wire.pack_hash_hex.clone(),
                sha256_hex: wire.sha256_hex.clone(),
                byte_len: wire.byte_len,
                covered_objects: commit_cnt.max(1),
                cache_warm: wire.cache_warm,
            };
            member.validate(req.object_format)?;

            let within_count = selected.len() < req.policy.max_uris_per_fetch;
            let fits_budget = selected_bytes.saturating_add(member.byte_len) <= req.policy.max_pack_bytes_per_request;
            if retention_ok && within_count && fits_budget && member.byte_len >= req.policy.min_pack_bytes_for_offload {
                selected_bytes = selected_bytes.saturating_add(member.byte_len);
                selected.push(member);
            } else {
                residual_inline_bytes = residual_inline_bytes.saturating_add(member.byte_len);
                residual_objects = residual_objects.saturating_add(commit_cnt);
            }
        }
        Ok(Some((selected, residual_inline_bytes, residual_objects)))
    }

    fn mint_offloaded_descriptors(
        &self,
        req: &DeliveryPlanRequest<'_>,
        subject: DownloadSubjectContext,
        selected: &[PackfileClosureMember],
        residual_inline_bytes: u64,
        residual_objects: u64,
    ) -> Result<PlannedFetchResponse, PackfileUriError> {
        let expires_at_unix = req.now_unix.saturating_add(req.policy.ttl_secs);
        let mut offloaded = Vec::with_capacity(selected.len());
        let mut lease_pins: Vec<Arc<OffloadPackPinGuard>> = Vec::with_capacity(selected.len());
        let mut telemetry = DeliveryTelemetry { offload_used: true, inline_bytes: residual_inline_bytes, ..Default::default() };

        for candidate in selected {
            let Ok(pin_guard) = self.leases.acquire_offload_pin(&AcquireLeaseParams {
                tenant_id: req.tenant_id,
                repository_id: req.repository_id,
                pack_oid: &candidate.pack_oid,
                subject,
                gate_revision: req.gate_revision,
                now_unix: req.now_unix,
                expires_at_unix,
                grace_secs: req.policy.retention_grace_secs,
            }) else {
                self.rollback_leases(&mut lease_pins, req.now_unix);
                return Ok(Self::build_inline_response(req.cover, FallbackReason::PinAcquisitionFailed));
            };
            let seq = self.nonce_seq.fetch_add(1, Ordering::Relaxed);
            let nonce = format!("{:016x}{:016x}", Uuid::new_v4().as_u128() >> 64, seq);
            let desc = match mint_signed_offload_uri(
                &self.keyring,
                &MintUriRequest {
                    tenant_id: req.tenant_id,
                    repository_id: req.repository_id,
                    subject,
                    pack_oid: &candidate.pack_oid,
                    pack_hash_hex: &candidate.pack_hash_hex,
                    sha256_hex: &candidate.sha256_hex,
                    byte_len: candidate.byte_len,
                    object_format: req.object_format,
                    allowed_host: req.allowed_host,
                    pin_id: pin_guard.pin_id(),
                    scope_nonce: &nonce,
                    now_unix: req.now_unix,
                    policy: req.policy,
                    resolver: req.resolver,
                },
            ) {
                Ok(d) => d,
                Err(err) => {
                    lease_pins.push(pin_guard);
                    self.rollback_leases(&mut lease_pins, req.now_unix);
                    return Err(err);
                }
            };
            telemetry.offloaded_bytes = telemetry.offloaded_bytes.saturating_add(desc.byte_len);
            if candidate.cache_warm {
                telemetry.cache_hits = telemetry.cache_hits.saturating_add(1);
            } else {
                telemetry.blob_get_count = telemetry.blob_get_count.saturating_add(1);
                telemetry.blob_get_bytes = telemetry.blob_get_bytes.saturating_add(desc.byte_len);
            }
            offloaded.push(desc);
            lease_pins.push(pin_guard);
        }

        Ok(PlannedFetchResponse {
            mode: DeliveryMode::OffloadPlusResidual {
                offloaded,
                residual_inline_bytes,
                residual_objects,
                lease_pins,
            },
            telemetry,
        })
    }

    fn rollback_leases(&self, lease_pins: &mut Vec<Arc<OffloadPackPinGuard>>, now_unix: u64) {
        for pin in lease_pins.drain(..) {
            let id = pin.pin_id();
            drop(pin);
            self.leases.revoke_pin(id);
        }
        self.leases.sweep_expired(now_unix);
    }

    fn build_inline_response(cover: &VerifiedPackCoverInput<'_>, reason: FallbackReason) -> PlannedFetchResponse {
        let total_inline_bytes = cover.full_fallback_inline_bytes;
        let total_objects = cover.total_planned_commits();
        PlannedFetchResponse {
            mode: DeliveryMode::InlineFallback { reason, total_inline_bytes, total_objects },
            telemetry: DeliveryTelemetry {
                offload_used: false,
                fallback_reason: Some(reason),
                blob_get_count: u64::from(total_inline_bytes > 0),
                blob_get_bytes: total_inline_bytes,
                inline_bytes: total_inline_bytes,
                ..Default::default()
            },
        }
    }
}
