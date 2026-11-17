//! Version-aware disposable Rubicon compute replica cache & bounded routing
//! scheduler (Issue #163).
//!
//! Architecture:
//! - Layer 1 ([`pack_cache::PackCacheCatalog`]): verified immutable `.pack`/`.idx`
//!   cache scoped strictly by `(tenant_id, repo_id, backend_identity, digests)`.
//! - Layer 2 ([`catalog::ViewCacheCatalog`]): read-only compute views under
//!   `DisposableViewRoot` (`<replica_root>/views`) bound to `(tenant_id, repo_id,
//!   history_id, cluster_incarnation, backend_identity, authority_epoch,
//!   gate_revision, membership_digest)`.
//! - Mandatory live per-request authorization + `check_version` + #174 session
//!   lower-bound check before any cache lookup; active [`ReplicaViewGuard`]s
//!   preserve both local view directories and authoritative [`DurablePinHold`]s.
//! - Same-version single-flight coalescing + bounded waiter queue + bounded
//!   eviction + hot-replica affinity routing + drain/failover + tenant fair-share.

pub mod catalog;
pub mod error;
pub mod fair_admission;
pub mod lease_pin;
pub mod materializer;
pub mod pack_cache;
pub mod scheduler;
pub mod singleflight;
pub mod types;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_e2e;

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

use uuid::Uuid;

use crate::blob_store::{key_provider::KeyProvider, opendal::BlobStore};

pub use catalog::{CachedViewSlot, PushScratchGuard, ViewCacheCatalog};
pub use error::{ReplicaCacheError, compute_membership_digests, is_retryable_failover_error};
pub use lease_pin::{
    ActiveViewSlot, AuthoritativeSnapshot, DurablePinHold, DurablePinRegistry, LiveAuthorizer, ReplicaViewGuard,
    verify_session_lower_bound,
};
pub use materializer::verify_read_only_view_files;
pub use pack_cache::{PackCacheCatalog, PackCachePin};
pub use scheduler::{
    FairAdmissionPermit, FairnessStatsSnapshot, ReplicaBackend, ReplicaHealthState, ReplicaScheduler,
    ScheduledServeOutcome, TenantFairShareConfig, TenantFairShareGate,
};
pub use singleflight::{BoundedSingleFlight, FlightEntry, FlightOutcome};
pub use types::{
    PackCacheKey, PackObjectSpec, REPLICA_CACHE_SCHEMA, ReplicaCacheLimits, ReplicaCacheStats, ReplicaObjectFormat,
    ReplicaOperation, ReplicaReadRequest, ReplicaRefSpec, ReplicaRequestMetrics, ReplicaServeSource, ReplicaViewKey,
    RouteDirectoryHint, SessionLowerBound, VersionCheckVerdict,
};

#[derive(Default)]
struct NodeCounters {
    version_checks: AtomicU64,
    live_auth_checks: AtomicU64,
    auth_denials: AtomicU64,
    session_behind_rejects: AtomicU64,
    view_hits: AtomicU64,
    view_misses: AtomicU64,
    pack_hits: AtomicU64,
    pack_misses: AtomicU64,
    blob_gets: AtomicU64,
    blob_bytes: AtomicU64,
    reused_pack_bytes: AtomicU64,
    copied_bytes: AtomicU64,
    singleflight_waits: AtomicU64,
    queue_wait_us: AtomicU64,
    corrupt_rebuilds: AtomicU64,
    push_scratch_allocations: AtomicU64,
}

/// Single-node version-aware disposable Rubicon compute replica cache.
pub struct ReplicaCacheNode {
    node_id: String,
    store: BlobStore,
    key_provider: Option<Arc<dyn KeyProvider>>,
    limits: ReplicaCacheLimits,
    packs: PackCacheCatalog,
    views: ViewCacheCatalog,
    singleflight: BoundedSingleFlight,
    accepting: AtomicBool,
    counters: NodeCounters,
}

impl ReplicaCacheNode {
    pub fn open(
        node_id: impl Into<String>,
        replica_root: &Path,
        store: BlobStore,
        key_provider: Option<Arc<dyn KeyProvider>>,
        limits: ReplicaCacheLimits,
    ) -> Result<Self, ReplicaCacheError> {
        let node_id = node_id.into();
        if node_id.is_empty() || node_id.len() > 64 {
            return Err(ReplicaCacheError::InvalidConfig("invalid replica node_id"));
        }
        limits.validate()?;
        let packs = PackCacheCatalog::open(replica_root, limits)?;
        let views = ViewCacheCatalog::open(replica_root, limits)?;
        let singleflight = BoundedSingleFlight::new(limits)?;
        Ok(Self {
            node_id,
            store,
            key_provider,
            limits,
            packs,
            views,
            singleflight,
            accepting: AtomicBool::new(true),
            counters: NodeCounters::default(),
        })
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn store(&self) -> &BlobStore {
        &self.store
    }

    pub fn pack_cache(&self) -> &PackCacheCatalog {
        &self.packs
    }

    pub fn view_cache(&self) -> &ViewCacheCatalog {
        &self.views
    }

    pub fn set_accepting_traffic(&self, accepting: bool) {
        self.accepting.store(accepting, Ordering::Release);
    }

    pub fn clear_cache(&self) {
        self.views.clear_all();
        self.packs.clear_all();
    }

    pub fn allocate_push_scratch(
        &self,
        tenant_id: Uuid,
        repo_id: Uuid,
        reserved_bytes: u64,
    ) -> Result<PushScratchGuard, ReplicaCacheError> {
        self.counters.push_scratch_allocations.fetch_add(1, Ordering::Relaxed);
        self.views.allocate_push_scratch(tenant_id, repo_id, reserved_bytes)
    }

    pub fn stats(&self) -> ReplicaCacheStats {
        let (evicted_packs, pack_pins) = self.packs.stats();
        let (evicted_views, view_pins) = self.views.stats();
        let (coalesced, rejections) = self.singleflight.counters();
        ReplicaCacheStats {
            version_checks: self.counters.version_checks.load(Ordering::Relaxed),
            live_auth_checks: self.counters.live_auth_checks.load(Ordering::Relaxed),
            auth_denials: self.counters.auth_denials.load(Ordering::Relaxed),
            session_behind_rejects: self.counters.session_behind_rejects.load(Ordering::Relaxed),
            view_hits: self.counters.view_hits.load(Ordering::Relaxed),
            view_misses: self.counters.view_misses.load(Ordering::Relaxed),
            pack_hits: self.counters.pack_hits.load(Ordering::Relaxed),
            pack_misses: self.counters.pack_misses.load(Ordering::Relaxed),
            blob_gets: self.counters.blob_gets.load(Ordering::Relaxed),
            blob_bytes: self.counters.blob_bytes.load(Ordering::Relaxed),
            reused_pack_bytes: self.counters.reused_pack_bytes.load(Ordering::Relaxed),
            copied_bytes: self.counters.copied_bytes.load(Ordering::Relaxed),
            singleflight_coalesced: coalesced,
            singleflight_waits: self.counters.singleflight_waits.load(Ordering::Relaxed),
            queue_wait_us: self.counters.queue_wait_us.load(Ordering::Relaxed),
            queue_rejections: rejections,
            evicted_packs,
            evicted_views,
            active_pin_protections: pack_pins.saturating_add(view_pins),
            corrupt_rebuilds: self.counters.corrupt_rebuilds.load(Ordering::Relaxed),
            push_scratch_allocations: self.counters.push_scratch_allocations.load(Ordering::Relaxed),
        }
    }

    pub async fn serve_view(
        &self,
        req: &ReplicaReadRequest,
        authorizer: &dyn LiveAuthorizer,
        deadline: Instant,
    ) -> Result<ReplicaViewGuard, ReplicaCacheError> {
        let total_started = Instant::now();
        if !self.accepting.load(Ordering::Acquire) {
            return Err(ReplicaCacheError::ReplicaDraining);
        }
        self.counters.live_auth_checks.fetch_add(1, Ordering::Relaxed);
        self.counters.version_checks.fetch_add(1, Ordering::Relaxed);
        let auth = match authorizer.authorize_and_check_version(req).await {
            Ok(auth) => auth,
            Err(err) => {
                self.counters.auth_denials.fetch_add(1, Ordering::Relaxed);
                return Err(err);
            }
        };
        if let Err(err) = auth.validate_for_request(req, self.store.backend_identity()) {
            if matches!(err, ReplicaCacheError::BehindSessionLowerBound { .. }) {
                self.counters.session_behind_rejects.fetch_add(1, Ordering::Relaxed);
            } else if matches!(err, ReplicaCacheError::Unauthorized(_)) {
                self.counters.auth_denials.fetch_add(1, Ordering::Relaxed);
            }
            return Err(err);
        }

        let view_key = auth.build_view_key(self.store.backend_identity())?;
        let session_checked = req.session_lower_bound.is_some();

        let (cached, corrupt_view) = self.views.checkout(&view_key)?;
        if corrupt_view {
            self.counters.corrupt_rebuilds.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(slot) = cached {
            self.counters.view_hits.fetch_add(1, Ordering::Relaxed);
            let metrics = ReplicaRequestMetrics {
                version_checked: true,
                live_authorized: true,
                total_ms: total_started.elapsed().as_millis() as u64,
                ..ReplicaRequestMetrics::default()
            };
            return Ok(ReplicaViewGuard::new(
                self.node_id.clone(),
                slot,
                auth.durable_pin,
                ReplicaServeSource::ViewCacheHit,
                metrics,
                session_checked,
            ));
        }
        self.counters.view_misses.fetch_add(1, Ordering::Relaxed);

        let mut total_wait_us = 0u64;
        loop {
            match self.singleflight.enter(&view_key)? {
                FlightEntry::Leader(leader) => {
                    let mat_started = Instant::now();
                    let mat_deadline = deadline.min(mat_started + self.limits.materialization_timeout);
                    let res = materializer::materialize_version_view(
                        &self.store,
                        self.key_provider.as_ref(),
                        &self.packs,
                        &self.views,
                        &auth,
                        view_key.clone(),
                        self.limits,
                        mat_deadline,
                    )
                    .await;
                    match res {
                        Ok(out) => {
                            self.counters.blob_gets.fetch_add(out.blob_gets, Ordering::Relaxed);
                            self.counters.blob_bytes.fetch_add(out.blob_bytes, Ordering::Relaxed);
                            self.counters.pack_hits.fetch_add(out.pack_hits, Ordering::Relaxed);
                            self.counters.pack_misses.fetch_add(out.pack_misses, Ordering::Relaxed);
                            self.counters.reused_pack_bytes.fetch_add(out.reused_pack_bytes, Ordering::Relaxed);
                            self.counters.copied_bytes.fetch_add(out.copied_bytes, Ordering::Relaxed);
                            self.counters.corrupt_rebuilds.fetch_add(out.corrupt_detections, Ordering::Relaxed);
                            leader.complete_ready(Arc::clone(&out.slot), out.source);
                            let metrics = ReplicaRequestMetrics {
                                version_checked: true,
                                live_authorized: true,
                                blob_gets: out.blob_gets,
                                blob_bytes: out.blob_bytes,
                                reused_pack_count: out.reused_pack_count,
                                reused_pack_bytes: out.reused_pack_bytes,
                                copied_bytes: out.copied_bytes,
                                queue_wait_us: total_wait_us,
                                materialize_ms: mat_started.elapsed().as_millis() as u64,
                                total_ms: total_started.elapsed().as_millis() as u64,
                            };
                            return Ok(ReplicaViewGuard::new(
                                self.node_id.clone(),
                                out.slot,
                                auth.durable_pin,
                                out.source,
                                metrics,
                                session_checked,
                            ));
                        }
                        Err(err) => {
                            leader.complete_failed(&err.to_string());
                            return Err(err);
                        }
                    }
                }
                FlightEntry::Waiter(waiter) => {
                    let (outcome, waited_us) = waiter.wait_for_outcome(self.limits.waiter_timeout, deadline).await?;
                    total_wait_us = total_wait_us.saturating_add(waited_us);
                    self.counters.singleflight_waits.fetch_add(1, Ordering::Relaxed);
                    self.counters.queue_wait_us.fetch_add(waited_us, Ordering::Relaxed);
                    match outcome {
                        FlightOutcome::Ready { slot, .. } => {
                            if slot.try_acquire_reader(self.limits.min_serve_ttl) {
                                self.counters.view_hits.fetch_add(1, Ordering::Relaxed);
                                let metrics = ReplicaRequestMetrics {
                                    version_checked: true,
                                    live_authorized: true,
                                    queue_wait_us: total_wait_us,
                                    total_ms: total_started.elapsed().as_millis() as u64,
                                    ..ReplicaRequestMetrics::default()
                                };
                                return Ok(ReplicaViewGuard::new(
                                    self.node_id.clone(),
                                    slot,
                                    auth.durable_pin,
                                    ReplicaServeSource::ViewCacheHit,
                                    metrics,
                                    session_checked,
                                ));
                            }
                            continue;
                        }
                        FlightOutcome::LeaderCancelled => continue,
                        FlightOutcome::Failed(msg) => return Err(ReplicaCacheError::ReplicaUnhealthy(msg)),
                        FlightOutcome::Pending => continue,
                    }
                }
            }
        }
    }
}

impl ReplicaBackend for ReplicaCacheNode {
    fn node_id(&self) -> &str {
        &self.node_id
    }

    fn serve_replica_view<'a>(
        &'a self,
        req: &'a ReplicaReadRequest,
        authorizer: &'a dyn LiveAuthorizer,
        deadline: Instant,
    ) -> lease_pin::AuthTask<'a, Result<ReplicaViewGuard, ReplicaCacheError>> {
        Box::pin(async move { self.serve_view(req, authorizer, deadline).await })
    }

    fn is_accepting_traffic(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }
}
