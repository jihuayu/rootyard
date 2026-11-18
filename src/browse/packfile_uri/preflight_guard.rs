//! Cancellation-safe RAII preflight & staged-pin guards with hard concurrent
//! preflight capacity bounds for `GatewayPackfileOffload`.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::cache_wake::replica_cache::lease_pin::AuthTask;

use super::{
    retention::{OffloadPackPinGuard, PackDeliveryLeaseRegistry},
    signing::LivePackReadAuthorizer,
    types::{DownloadSubjectContext, PackfileUriError},
};

/// Async callback re-running live gateway authority (`ReadAuthorization::revalidate`).
pub type LiveRevalidatorFn = Arc<dyn Fn() -> AuthTask<'static, Result<(), PackfileUriError>> + Send + Sync>;

pub(super) struct RegisteredPinAuth {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub subject: DownloadSubjectContext,
    pub expires_at_unix: u64,
    pub revalidate: LiveRevalidatorFn,
    pub _pin_guard: Arc<OffloadPackPinGuard>,
}

struct PreflightAuthEntry {
    tenant_id: Uuid,
    repository_id: Uuid,
    subject: DownloadSubjectContext,
    expires_at_unix: u64,
    revalidate: LiveRevalidatorFn,
}

pub(super) struct GatewayLiveAuthorizer {
    pins: Mutex<HashMap<Uuid, RegisteredPinAuth>>,
    preflights: Mutex<HashMap<Uuid, PreflightAuthEntry>>,
    preflight_semaphore: Arc<Semaphore>,
    max_preflights: usize,
    pub preflight_rejections: AtomicU64,
    clock_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl GatewayLiveAuthorizer {
    pub fn new(max_preflights: usize, clock_unix: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        let cap = max_preflights.max(1);
        Self {
            pins: Mutex::new(HashMap::new()),
            preflights: Mutex::new(HashMap::new()),
            preflight_semaphore: Arc::new(Semaphore::new(cap)),
            max_preflights: cap,
            preflight_rejections: AtomicU64::new(0),
            clock_unix,
        }
    }

    pub fn sweep(&self, now_unix: u64) {
        self.pins.lock().unwrap_or_else(|p| p.into_inner()).retain(|_, v| now_unix <= v.expires_at_unix);
        self.preflights.lock().unwrap_or_else(|p| p.into_inner()).retain(|_, v| now_unix <= v.expires_at_unix);
    }

    pub fn begin_preflight(
        self: &Arc<Self>,
        tenant_id: Uuid,
        repository_id: Uuid,
        subject: DownloadSubjectContext,
        expires_at_unix: u64,
        revalidate: LiveRevalidatorFn,
    ) -> Result<PreflightSessionGuard, PackfileUriError> {
        let now = (self.clock_unix)();
        self.sweep(now);
        let Ok(permit) = Arc::clone(&self.preflight_semaphore).try_acquire_owned() else {
            self.preflight_rejections.fetch_add(1, Ordering::Relaxed);
            return Err(PackfileUriError::CapacityExceeded("concurrent preflight capacity exhausted".to_owned()));
        };
        let session_id = Uuid::new_v4();
        let mut guard = self.preflights.lock().unwrap_or_else(|p| p.into_inner());
        if guard.len() >= self.max_preflights {
            self.preflight_rejections.fetch_add(1, Ordering::Relaxed);
            return Err(PackfileUriError::CapacityExceeded("preflight registry full".to_owned()));
        }
        guard.insert(
            session_id,
            PreflightAuthEntry { tenant_id, repository_id, subject, expires_at_unix, revalidate },
        );
        drop(guard);
        Ok(PreflightSessionGuard {
            session_id,
            auth: Arc::clone(self),
            _permit: permit,
        })
    }

    pub fn insert_pin(&self, pin_id: Uuid, entry: RegisteredPinAuth) {
        self.pins.lock().unwrap_or_else(|p| p.into_inner()).insert(pin_id, entry);
    }

    pub fn remove_pins(&self, pin_ids: &[Uuid]) {
        let mut guard = self.pins.lock().unwrap_or_else(|p| p.into_inner());
        for id in pin_ids {
            guard.remove(id);
        }
    }

    pub fn active_preflight_count(&self) -> usize {
        self.preflights.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn available_preflight_permits(&self) -> usize {
        self.preflight_semaphore.available_permits()
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
        let now = (self.clock_unix)();
        let cb = if pin_id.is_nil() {
            let guard = self.preflights.lock().unwrap_or_else(|p| p.into_inner());
            guard
                .values()
                .find(|rec| {
                    rec.tenant_id == tenant_id
                        && rec.repository_id == repository_id
                        && rec.subject == *subject
                        && now <= rec.expires_at_unix
                })
                .map(|rec| Arc::clone(&rec.revalidate))
        } else {
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

/// RAII guard cleaning up preflight auth state and concurrency slot on drop/cancellation.
pub(super) struct PreflightSessionGuard {
    session_id: Uuid,
    auth: Arc<GatewayLiveAuthorizer>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for PreflightSessionGuard {
    fn drop(&mut self) {
        self.auth.preflights.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.session_id);
    }
}

/// RAII rollback guard revoking and sweeping minted pin leases if the response is cancelled before commit.
pub(super) struct StagedPinBatchGuard {
    lease_pins: Vec<Arc<OffloadPackPinGuard>>,
    registered_ids: Vec<Uuid>,
    leases: PackDeliveryLeaseRegistry,
    auth: Arc<GatewayLiveAuthorizer>,
    now_unix: u64,
    committed: bool,
}

impl StagedPinBatchGuard {
    pub fn new(
        lease_pins: Vec<Arc<OffloadPackPinGuard>>,
        leases: PackDeliveryLeaseRegistry,
        auth: Arc<GatewayLiveAuthorizer>,
        now_unix: u64,
    ) -> Self {
        Self { lease_pins, registered_ids: Vec::new(), leases, auth, now_unix, committed: false }
    }

    pub fn pins(&self) -> &[Arc<OffloadPackPinGuard>] {
        &self.lease_pins
    }

    pub fn stage_registered_pin(&mut self, pin_id: Uuid, entry: RegisteredPinAuth) {
        self.auth.insert_pin(pin_id, entry);
        self.registered_ids.push(pin_id);
    }

    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for StagedPinBatchGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        self.auth.remove_pins(&self.registered_ids);
        for pin in self.lease_pins.drain(..) {
            let id = pin.pin_id();
            drop(pin);
            self.leases.revoke_pin(id);
        }
        self.leases.sweep_expired(self.now_unix);
    }
}
