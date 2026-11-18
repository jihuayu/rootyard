//! Active pack retention pin/hold registry integrating #163 `DurablePinRegistry`
//! with bounded lease capacity, automatic expired-lease sweeping, and strict
//! `(actor_id, token_id, auth_epoch)` subject binding.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use uuid::Uuid;

use crate::cache_wake::replica_cache::{DurablePinHold, DurablePinRegistry};

use super::types::{DEFAULT_MAX_ACTIVE_LEASES, DownloadSubjectContext, PackfileUriError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionLeaseState {
    Active,
    Revoked,
    Expired,
}

struct PackLeaseRecord {
    tenant_id: Uuid,
    repository_id: Uuid,
    pack_oid: String,
    subject: DownloadSubjectContext,
    expires_at_unix: u64,
    grace_until_unix: u64,
    inflight_downloads: usize,
    guard_refs: usize,
    revoked: bool,
    durable_hold: Arc<dyn DurablePinHold>,
}

/// Registry binding signed offload URLs to active `#163` [`DurablePinHold`] leases.
#[derive(Clone)]
pub struct PackDeliveryLeaseRegistry {
    durable_pins: DurablePinRegistry,
    leases: Arc<Mutex<HashMap<Uuid, PackLeaseRecord>>>,
    max_active_leases: usize,
}

impl Default for PackDeliveryLeaseRegistry {
    fn default() -> Self {
        Self::new(DurablePinRegistry::new())
    }
}

/// Arguments specifying one scoped retention pin acquisition window.
pub struct AcquireLeaseParams<'a> {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pack_oid: &'a str,
    pub subject: DownloadSubjectContext,
    pub gate_revision: i64,
    pub now_unix: u64,
    pub expires_at_unix: u64,
    pub grace_secs: u64,
}

impl PackDeliveryLeaseRegistry {
    pub fn new(durable_pins: DurablePinRegistry) -> Self {
        Self::with_max_leases(durable_pins, DEFAULT_MAX_ACTIVE_LEASES)
    }

    pub fn with_max_leases(durable_pins: DurablePinRegistry, max_active_leases: usize) -> Self {
        Self {
            durable_pins,
            leases: Arc::new(Mutex::new(HashMap::new())),
            max_active_leases: max_active_leases.max(1),
        }
    }

    pub fn durable_pins(&self) -> &DurablePinRegistry {
        &self.durable_pins
    }

    pub const fn max_active_leases(&self) -> usize {
        self.max_active_leases
    }

    /// Sweeps expired unreferenced leases, enforces `max_active_leases`, and acquires a scoped pin.
    pub fn acquire_offload_pin(&self, req: &AcquireLeaseParams<'_>) -> Result<Arc<OffloadPackPinGuard>, PackfileUriError> {
        req.subject.validate()?;
        if req.tenant_id.is_nil() || req.repository_id.is_nil() {
            return Err(PackfileUriError::Unauthorized);
        }
        if req.expires_at_unix < req.now_unix {
            return Err(PackfileUriError::RetentionPinMissing(
                "cannot issue pin already past expiration".to_owned(),
            ));
        }
        let mut guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        Self::sweep_expired_locked(&mut guard, req.now_unix);
        if guard.len() >= self.max_active_leases {
            return Err(PackfileUriError::CapacityExceeded(
                "active retention lease capacity exceeded".to_owned(),
            ));
        }
        let durable_hold = self
            .durable_pins
            .acquire(req.tenant_id, req.repository_id, req.gate_revision);
        let pin_id = durable_hold.pin_id();
        let grace_until_unix = req.expires_at_unix.saturating_add(req.grace_secs);
        guard.insert(
            pin_id,
            PackLeaseRecord {
                tenant_id: req.tenant_id,
                repository_id: req.repository_id,
                pack_oid: req.pack_oid.to_owned(),
                subject: req.subject,
                expires_at_unix: req.expires_at_unix,
                grace_until_unix,
                inflight_downloads: 0,
                guard_refs: 1,
                revoked: false,
                durable_hold,
            },
        );
        drop(guard);
        Ok(Arc::new(OffloadPackPinGuard {
            pin_id,
            leases: Arc::clone(&self.leases),
            released: Mutex::new(false),
        }))
    }

    /// Validates active hold + exact `(tenant_id, repository_id, pack_oid, subject)` before streaming.
    pub fn begin_download_hold(
        &self,
        pin_id: Uuid,
        tenant_id: Uuid,
        repository_id: Uuid,
        pack_oid: &str,
        subject: &DownloadSubjectContext,
        now_unix: u64,
    ) -> Result<InflightDownloadGuard, PackfileUriError> {
        subject.validate()?;
        let mut guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        let rec = guard
            .get_mut(&pin_id)
            .ok_or_else(|| PackfileUriError::RetentionPinMissing("unknown pack pin".to_owned()))?;
        if rec.revoked || !rec.durable_hold.is_active() || !self.durable_pins.is_pin_active(pin_id) {
            return Err(PackfileUriError::RetentionPinMissing("pack pin revoked".to_owned()));
        }
        if rec.tenant_id != tenant_id
            || rec.repository_id != repository_id
            || rec.pack_oid != pack_oid
            || rec.subject != *subject
        {
            return Err(PackfileUriError::ScopeMismatch(
                "pin does not match tenant, repo, pack, or subject".to_owned(),
            ));
        }
        if now_unix > rec.grace_until_unix {
            return Err(PackfileUriError::RetentionPinMissing(
                "pin lease and retry grace elapsed".to_owned(),
            ));
        }
        rec.inflight_downloads = rec.inflight_downloads.saturating_add(1);
        Ok(InflightDownloadGuard {
            pin_id,
            leases: Arc::clone(&self.leases),
            released: false,
        })
    }

    /// Re-verifies mid-stream that the active hold has not been revoked or dropped.
    pub fn is_hold_still_valid(&self, pin_id: Uuid) -> bool {
        let guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        guard
            .get(&pin_id)
            .is_some_and(|rec| !rec.revoked && rec.durable_hold.is_active() && self.durable_pins.is_pin_active(pin_id))
    }

    /// Returns `false` while ANY active pin/grace window or live inflight reader protects `pack_oid`.
    pub fn can_sweep_pack(&self, tenant_id: Uuid, repository_id: Uuid, pack_oid: &str, now_unix: u64) -> bool {
        let guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        !guard.values().any(|rec| {
            rec.tenant_id == tenant_id
                && rec.repository_id == repository_id
                && rec.pack_oid == pack_oid
                && !rec.revoked
                && rec.durable_hold.is_active()
                && (rec.inflight_downloads > 0 || rec.guard_refs > 0 || now_unix <= rec.grace_until_unix)
        })
    }

    /// Inspects lease status (`Active`, `Revoked`, or `Expired`).
    pub fn lease_state(&self, pin_id: Uuid, now_unix: u64) -> Option<RetentionLeaseState> {
        let guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        guard.get(&pin_id).map(|rec| {
            if rec.revoked || !rec.durable_hold.is_active() {
                RetentionLeaseState::Revoked
            } else if now_unix > rec.expires_at_unix && now_unix > rec.grace_until_unix && rec.inflight_downloads == 0 {
                RetentionLeaseState::Expired
            } else {
                RetentionLeaseState::Active
            }
        })
    }

    /// Immediately revokes one pin, preventing new downloads and failing live streaming checks.
    pub fn revoke_pin(&self, pin_id: Uuid) -> bool {
        let mut guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(rec) = guard.get_mut(&pin_id) {
            rec.revoked = true;
            true
        } else {
            false
        }
    }

    /// Sweeps only unreferenced, expired (or revoked with zero inflight readers) pin leases.
    pub fn sweep_expired(&self, now_unix: u64) -> usize {
        let mut guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        Self::sweep_expired_locked(&mut guard, now_unix)
    }

    fn sweep_expired_locked(guard: &mut HashMap<Uuid, PackLeaseRecord>, now_unix: u64) -> usize {
        let before = guard.len();
        guard.retain(|_, rec| {
            rec.inflight_downloads > 0 || rec.guard_refs > 0 || (!rec.revoked && now_unix <= rec.grace_until_unix)
        });
        before.saturating_sub(guard.len())
    }

    pub fn active_pin_count(&self) -> usize {
        let guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        guard.values().filter(|rec| !rec.revoked && rec.durable_hold.is_active()).count()
    }

    pub fn inflight_download_count(&self) -> usize {
        let guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        guard.values().map(|rec| rec.inflight_downloads).sum()
    }
}

/// RAII retention pin guard held by a planned delivery mode.
pub struct OffloadPackPinGuard {
    pin_id: Uuid,
    leases: Arc<Mutex<HashMap<Uuid, PackLeaseRecord>>>,
    released: Mutex<bool>,
}

impl std::fmt::Debug for OffloadPackPinGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OffloadPackPinGuard").field("pin_id", &self.pin_id).finish()
    }
}

impl PartialEq for OffloadPackPinGuard {
    fn eq(&self, other: &Self) -> bool {
        self.pin_id == other.pin_id
    }
}

impl Eq for OffloadPackPinGuard {}

impl OffloadPackPinGuard {
    pub fn pin_id(&self) -> Uuid {
        self.pin_id
    }
}

impl Drop for OffloadPackPinGuard {
    fn drop(&mut self) {
        let mut flag = self.released.lock().unwrap_or_else(|p| p.into_inner());
        if *flag {
            return;
        }
        *flag = true;
        let mut guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(rec) = guard.get_mut(&self.pin_id) {
            rec.guard_refs = rec.guard_refs.saturating_sub(1);
        }
    }
}

/// RAII inflight HTTP download hold guaranteeing zero deletion while streaming a pack.
pub struct InflightDownloadGuard {
    pin_id: Uuid,
    leases: Arc<Mutex<HashMap<Uuid, PackLeaseRecord>>>,
    released: bool,
}

impl InflightDownloadGuard {
    pub fn pin_id(&self) -> Uuid {
        self.pin_id
    }
}

impl Drop for InflightDownloadGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let mut guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(rec) = guard.get_mut(&self.pin_id) {
            rec.inflight_downloads = rec.inflight_downloads.saturating_sub(1);
        }
    }
}
