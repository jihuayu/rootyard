//! Bounded Git fetch delivery planner combining live auth, Protocol v2
//! negotiation, closure validation, active retention pins, CDN health breaker,
//! and deterministic inline fallback.

use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use uuid::Uuid;

use super::{
    protocol_v2::FetchV2Request,
    retention::{AcquireLeaseParams, PackDeliveryLeaseRegistry},
    signing::{LivePackReadAuthorizer, MintUriRequest, PackUriKeyring, mint_signed_offload_uri},
    ssrf_guard::validate_policy_config,
    types::{
        DeliveryMode, DeliveryTelemetry, FallbackReason, OffloadPolicyConfig, PackObjectFormat,
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

/// Exact object closure accounting for one repository `fetch` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackClosurePlan {
    pub total_objects: u64,
    pub total_inline_bytes: u64,
    pub offload_candidates: Vec<PackfileClosureMember>,
    pub residual_inline_objects: u64,
    pub residual_inline_bytes: u64,
}

impl PackClosurePlan {
    /// Ensures selected offload candidates plus residual objects cover the exact requested closure.
    pub fn is_closure_complete(&self) -> bool {
        let mut seen_packs = HashSet::with_capacity(self.offload_candidates.len());
        let mut seen_hashes = HashSet::with_capacity(self.offload_candidates.len());
        let mut offloaded_objs = 0u64;
        for c in &self.offload_candidates {
            if c.covered_objects == 0 || !seen_packs.insert(&c.pack_oid) || !seen_hashes.insert(&c.pack_hash_hex) {
                return false;
            }
            offloaded_objs = offloaded_objs.saturating_add(c.covered_objects);
        }
        self.total_objects > 0 && offloaded_objs.saturating_add(self.residual_inline_objects) == self.total_objects
    }
}

/// Inputs for planning whether to offload packs via `packfile-uris` or fall back inline.
pub struct DeliveryPlanRequest<'a> {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub actor_id: Uuid,
    pub gate_revision: i64,
    pub object_format: PackObjectFormat,
    pub fetch_req: &'a FetchV2Request,
    pub closure: &'a PackClosurePlan,
    pub cdn_health: CdnHealthState,
    pub allowed_host: &'a str,
    pub now_unix: u64,
    pub resolved_ips: &'a [IpAddr],
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

    /// Evaluates live auth, protocol support, CDN health, bounds, and retention pins.
    pub async fn plan_fetch(
        &self,
        authorizer: &dyn LivePackReadAuthorizer,
        req: &DeliveryPlanRequest<'_>,
    ) -> Result<PlannedFetchResponse, PackfileUriError> {
        authorizer
            .authorize_pack_download(
                req.tenant_id,
                req.repository_id,
                req.actor_id,
                "closure-plan",
                Uuid::nil(),
            )
            .await?;

        if let Some(reason) = self.check_fallback_preconditions(req)? {
            return Ok(Self::build_inline_response(req.closure, reason));
        }

        let mut selected = Vec::new();
        let mut selected_bytes = 0u64;
        let mut residual_inline_bytes = req.closure.residual_inline_bytes;
        let mut residual_objects = req.closure.residual_inline_objects;

        for candidate in &req.closure.offload_candidates {
            candidate.validate(req.object_format)?;
            let within_count = selected.len() < req.policy.max_uris_per_fetch;
            let fits_budget = selected_bytes.saturating_add(candidate.byte_len) <= req.policy.max_pack_bytes_per_request;
            if within_count && fits_budget && candidate.byte_len >= req.policy.min_pack_bytes_for_offload {
                selected.push(candidate);
                selected_bytes = selected_bytes.saturating_add(candidate.byte_len);
            } else {
                residual_inline_bytes = residual_inline_bytes.saturating_add(candidate.byte_len);
                residual_objects = residual_objects.saturating_add(candidate.covered_objects);
            }
        }
        if selected.is_empty() {
            return Ok(Self::build_inline_response(req.closure, FallbackReason::BelowOffloadThreshold));
        }
        self.mint_offloaded_descriptors(req, &selected, residual_inline_bytes, residual_objects)
    }

    /// Explicit clean pre-body escalation to a full inline pack response after bounded retries fail.
    pub fn plan_full_inline_retry(closure: &PackClosurePlan, reason: FallbackReason) -> PlannedFetchResponse {
        Self::build_inline_response(closure, reason)
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
        if !req.closure.is_closure_complete() {
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

    fn mint_offloaded_descriptors(
        &self,
        req: &DeliveryPlanRequest<'_>,
        selected: &[&PackfileClosureMember],
        residual_inline_bytes: u64,
        residual_objects: u64,
    ) -> Result<PlannedFetchResponse, PackfileUriError> {
        let expires_at_unix = req.now_unix.saturating_add(req.policy.ttl_secs);
        let mut offloaded = Vec::with_capacity(selected.len());
        let mut lease_pins = Vec::with_capacity(selected.len());
        let mut telemetry = DeliveryTelemetry { offload_used: true, inline_bytes: residual_inline_bytes, ..Default::default() };

        for candidate in selected {
            let Ok(pin_guard) = self.leases.acquire_offload_pin(&AcquireLeaseParams {
                tenant_id: req.tenant_id,
                repository_id: req.repository_id,
                pack_oid: &candidate.pack_oid,
                gate_revision: req.gate_revision,
                now_unix: req.now_unix,
                expires_at_unix,
                grace_secs: req.policy.retention_grace_secs,
            }) else {
                return Ok(Self::build_inline_response(req.closure, FallbackReason::PinAcquisitionFailed));
            };
            let seq = self.nonce_seq.fetch_add(1, Ordering::Relaxed);
            let nonce = format!("{:016x}{:016x}", Uuid::new_v4().as_u128() >> 64, seq);
            let desc = mint_signed_offload_uri(
                &self.keyring,
                &MintUriRequest {
                    tenant_id: req.tenant_id,
                    repository_id: req.repository_id,
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
                    resolved_ips: req.resolved_ips,
                },
            )?;
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

    fn build_inline_response(closure: &PackClosurePlan, reason: FallbackReason) -> PlannedFetchResponse {
        PlannedFetchResponse {
            mode: DeliveryMode::InlineFallback {
                reason,
                total_inline_bytes: closure.total_inline_bytes,
                total_objects: closure.total_objects,
            },
            telemetry: DeliveryTelemetry {
                offload_used: false,
                fallback_reason: Some(reason),
                blob_get_count: u64::from(closure.total_inline_bytes > 0),
                blob_get_bytes: closure.total_inline_bytes,
                inline_bytes: closure.total_inline_bytes,
                ..Default::default()
            },
        }
    }
}
