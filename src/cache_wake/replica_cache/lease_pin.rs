//! Live per-request authorization, durable pin/hold preservation,
//! #174 session lower-bound checks, and active reader reference guards.

use std::{
    collections::HashMap,
    future::Future,
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use uuid::Uuid;

use crate::blob_store::BlobBackendIdentity;

use super::types::{
    PackObjectSpec, ReplicaCacheError, ReplicaObjectFormat, ReplicaReadRequest, ReplicaRefSpec, ReplicaRequestMetrics,
    ReplicaServeSource, ReplicaViewKey, SessionLowerBound, VersionCheckVerdict,
};

pub type AuthTask<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Opaque durable pin/hold guard issued by the authoritative RefStore/Retention
/// owner. Cache eviction, cache clear, or unrelated request cancellation must
/// never drop or release this hold early while any active reader still holds it.
pub trait DurablePinHold: Send + Sync {
    fn pin_id(&self) -> Uuid;
    fn tenant_id(&self) -> Uuid;
    fn repo_id(&self) -> Uuid;
    fn is_active(&self) -> bool;
}

#[derive(Debug, Clone)]
struct PinStateRecord {
    tenant_id: Uuid,
    repo_id: Uuid,
    gate_revision: i64,
}

#[derive(Default)]
struct PinRegistryInner {
    active: HashMap<Uuid, PinStateRecord>,
    total_issued: u64,
    total_released: u64,
}

/// Thread-safe registry tracking active durable pins/holds across live readers.
#[derive(Clone, Default)]
pub struct DurablePinRegistry {
    inner: Arc<Mutex<PinRegistryInner>>,
}

impl DurablePinRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn acquire(&self, tenant_id: Uuid, repo_id: Uuid, gate_revision: i64) -> Arc<dyn DurablePinHold> {
        let pin_id = Uuid::new_v4();
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.active.insert(pin_id, PinStateRecord { tenant_id, repo_id, gate_revision });
        guard.total_issued = guard.total_issued.saturating_add(1);
        Arc::new(TrackedDurablePin {
            pin_id,
            tenant_id,
            repo_id,
            active: AtomicBool::new(true),
            registry: Arc::clone(&self.inner),
        })
    }

    pub fn is_pin_active(&self, pin_id: Uuid) -> bool {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.active.contains_key(&pin_id)
    }

    pub fn active_count(&self) -> usize {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.active.len()
    }

    pub fn total_issued(&self) -> u64 {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.total_issued
    }

    pub fn total_released(&self) -> u64 {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.total_released
    }

    pub fn revision_for_pin(&self, pin_id: Uuid) -> Option<i64> {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.active.get(&pin_id).map(|r| r.gate_revision)
    }

    pub fn scope_for_pin(&self, pin_id: Uuid) -> Option<(Uuid, Uuid)> {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.active.get(&pin_id).map(|r| (r.tenant_id, r.repo_id))
    }
}

pub struct TrackedDurablePin {
    pin_id: Uuid,
    tenant_id: Uuid,
    repo_id: Uuid,
    active: AtomicBool,
    registry: Arc<Mutex<PinRegistryInner>>,
}

impl DurablePinHold for TrackedDurablePin {
    fn pin_id(&self) -> Uuid {
        self.pin_id
    }

    fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    fn repo_id(&self) -> Uuid {
        self.repo_id
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}

impl Drop for TrackedDurablePin {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        let mut guard = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        if guard.active.remove(&self.pin_id).is_some() {
            guard.total_released = guard.total_released.saturating_add(1);
        }
    }
}

/// Authoritative repository version & membership observation produced only by
/// [`LiveAuthorizer::authorize_and_check_version`].
#[derive(Clone)]
pub struct AuthoritativeSnapshot {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub cluster_incarnation: Uuid,
    pub object_format: ReplicaObjectFormat,
    pub authority_epoch: i64,
    pub gate_revision: i64,
    pub version_check: VersionCheckVerdict,
    pub head_ref: String,
    pub refs: Vec<ReplicaRefSpec>,
    pub packs: Vec<PackObjectSpec>,
    pub durable_pin: Arc<dyn DurablePinHold>,
}

impl AuthoritativeSnapshot {
    pub fn validate_for_request(
        &self,
        req: &ReplicaReadRequest,
        node_backend: &BlobBackendIdentity,
    ) -> Result<(), ReplicaCacheError> {
        if self.tenant_id.is_nil()
            || self.repo_id.is_nil()
            || self.history_id.is_nil()
            || self.cluster_incarnation.is_nil()
        {
            return Err(ReplicaCacheError::InvalidInput("authoritative snapshot contains nil identity".into()));
        }
        if self.tenant_id != req.tenant_id || self.repo_id != req.repo_id {
            return Err(ReplicaCacheError::TenantIsolationViolation(
                "authoritative snapshot tenant/repo disagrees with request",
            ));
        }
        if self.durable_pin.tenant_id() != req.tenant_id
            || self.durable_pin.repo_id() != req.repo_id
            || !self.durable_pin.is_active()
        {
            return Err(ReplicaCacheError::TenantIsolationViolation("durable pin missing, inactive, or wrong tenant"));
        }
        if let Some(expected_backend) = &req.expected_backend_identity
            && expected_backend != node_backend
        {
            return Err(ReplicaCacheError::BackendIdentityMismatch);
        }
        if self.packs.is_empty() {
            return Err(ReplicaCacheError::InvalidInput("authoritative pack set must not be empty".into()));
        }
        verify_session_lower_bound(req.session_lower_bound.as_ref(), self)?;
        Ok(())
    }

    pub fn build_view_key(&self, backend_identity: &BlobBackendIdentity) -> Result<ReplicaViewKey, ReplicaCacheError> {
        ReplicaViewKey::build(
            self.tenant_id,
            self.repo_id,
            self.history_id,
            self.cluster_incarnation,
            backend_identity,
            self.object_format,
            self.authority_epoch,
            self.gate_revision,
            &self.packs,
            &self.refs,
            &self.head_ref,
        )
    }
}

/// Mandatory per-request live authorization and authoritative `check_version`
/// boundary. Cache hits never bypass this trait.
pub trait LiveAuthorizer: Send + Sync {
    fn authorize_and_check_version<'a>(
        &'a self,
        req: &'a ReplicaReadRequest,
    ) -> AuthTask<'a, Result<AuthoritativeSnapshot, ReplicaCacheError>>;

    fn recheck_read_auth<'a>(&'a self, req: &'a ReplicaReadRequest) -> AuthTask<'a, Result<(), ReplicaCacheError>> {
        Box::pin(async move {
            let _ = self.authorize_and_check_version(req).await?;
            Ok(())
        })
    }
}

/// Enforce #174 session lower-bound compatibility without ever silently
/// returning stale cached state or weakening realm/incarnation checks.
pub fn verify_session_lower_bound(
    bound: Option<&SessionLowerBound>,
    auth: &AuthoritativeSnapshot,
) -> Result<(), ReplicaCacheError> {
    let Some(bound) = bound else {
        return Ok(());
    };
    if bound.tenant_id != auth.tenant_id
        || bound.repo_id != auth.repo_id
        || bound.history_id != auth.history_id
        || bound.cluster_incarnation != auth.cluster_incarnation
        || bound.authority_epoch != auth.authority_epoch
    {
        return Err(ReplicaCacheError::SessionRealmMismatch(
            "session lower-bound realm or cluster incarnation does not match live authority",
        ));
    }
    if auth.gate_revision < bound.min_gate_revision {
        return Err(ReplicaCacheError::BehindSessionLowerBound {
            required: bound.min_gate_revision,
            observed: auth.gate_revision,
        });
    }
    Ok(())
}

/// Internal view-slot handle implemented by the Layer 2 view catalog so active
/// reader guards hold the directory and pack pins alive until drop.
pub trait ActiveViewSlot: Send + Sync {
    fn view_key(&self) -> &ReplicaViewKey;
    fn repo_path(&self) -> Result<&Path, ReplicaCacheError>;
    fn ensure_live(&self) -> Result<(), ReplicaCacheError>;
    fn release_reader(&self);
}

/// RAII active reader guard returned to serving callers (`git upload-pack`,
/// browse, archive read). Guarantees the underlying read-only view directory,
/// Layer 1 pack pins, and authoritative [`DurablePinHold`] stay alive until all
/// active readers finish, even under cache eviction, flush, or peer cancellation.
pub struct ReplicaViewGuard {
    node_id: String,
    slot: Arc<dyn ActiveViewSlot>,
    durable_pin: Arc<dyn DurablePinHold>,
    source: ReplicaServeSource,
    metrics: ReplicaRequestMetrics,
    session_bound_checked: bool,
    released: bool,
}

impl ReplicaViewGuard {
    pub fn new(
        node_id: String,
        slot: Arc<dyn ActiveViewSlot>,
        durable_pin: Arc<dyn DurablePinHold>,
        source: ReplicaServeSource,
        metrics: ReplicaRequestMetrics,
        session_bound_checked: bool,
    ) -> Self {
        Self { node_id, slot, durable_pin, source, metrics, session_bound_checked, released: false }
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn view_key(&self) -> &ReplicaViewKey {
        self.slot.view_key()
    }

    pub fn source(&self) -> ReplicaServeSource {
        self.source
    }

    pub fn metrics(&self) -> &ReplicaRequestMetrics {
        &self.metrics
    }

    pub fn session_bound_checked(&self) -> bool {
        self.session_bound_checked
    }

    pub fn durable_pin(&self) -> &Arc<dyn DurablePinHold> {
        &self.durable_pin
    }

    pub fn repo_path(&self) -> Result<&Path, ReplicaCacheError> {
        self.slot.repo_path()
    }

    pub fn ensure_live(&self) -> Result<(), ReplicaCacheError> {
        if !self.durable_pin.is_active() {
            return Err(ReplicaCacheError::IntegrityFailed("durable pin is no longer active"));
        }
        self.slot.ensure_live()
    }

    pub async fn revalidate_live_auth(
        &self,
        authorizer: &dyn LiveAuthorizer,
        req: &ReplicaReadRequest,
    ) -> Result<(), ReplicaCacheError> {
        if req.tenant_id != self.slot.view_key().tenant_id || req.repo_id != self.slot.view_key().repo_id {
            return Err(ReplicaCacheError::TenantIsolationViolation("revalidation tenant/repo mismatch"));
        }
        authorizer.recheck_read_auth(req).await
    }
}

impl Drop for ReplicaViewGuard {
    fn drop(&mut self) {
        if !self.released {
            self.released = true;
            self.slot.release_reader();
        }
    }
}
