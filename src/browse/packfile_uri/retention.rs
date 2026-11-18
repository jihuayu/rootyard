//! Active pack retention pin/hold registry integrating #163 `DurablePinRegistry`
//! so concurrent GC, compaction, and history-switch sweeps never delete packs
//! needed by issued `packfile-uris` downloads or retry windows.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use uuid::Uuid;

use crate::cache_wake::replica_cache::{DurablePinHold, DurablePinRegistry};

use super::types::PackfileUriError;

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
    expires_at_unix: u64,
    grace_until_unix: u64,
    inflight_downloads: usize,
    guard_refs: usize,
    revoked: bool,
    durable_hold: Arc<dyn DurablePinHold>,
}

/// Registry binding signed offload URLs to active `#163` [`DurablePinHold`] leases.
#[derive(Clone, Default)]
pub struct PackDeliveryLeaseRegistry {
    durable_pins: DurablePinRegistry,
    leases: Arc<Mutex<HashMap<Uuid, PackLeaseRecord>>>,
}

/// Arguments specifying one scoped retention pin acquisition window.
pub struct AcquireLeaseParams<'a> {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pack_oid: &'a str,
    pub gate_revision: i64,
    pub now_unix: u64,
    pub expires_at_unix: u64,
    pub grace_secs: u64,
}

impl PackDeliveryLeaseRegistry {
    pub fn new(durable_pins: DurablePinRegistry) -> Self {
        Self { durable_pins, leases: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub fn durable_pins(&self) -> &DurablePinRegistry {
        &self.durable_pins
    }

    /// Acquires an active retention hold protecting `pack_oid` through `expires_at + grace`.
    pub fn acquire_offload_pin(&self, req: &AcquireLeaseParams<'_>) -> Result<Arc<OffloadPackPinGuard>, PackfileUriError> {
        let pack_oid = req.pack_oid.to_owned();
        if req.expires_at_unix < req.now_unix {
            return Err(PackfileUriError::RetentionPinMissing(
                "cannot issue pin already past expiration".to_owned(),
            ));
        }
        let durable_hold = self
            .durable_pins
            .acquire(req.tenant_id, req.repository_id, req.gate_revision);
        let pin_id = durable_hold.pin_id();
        let grace_until_unix = req.expires_at_unix.saturating_add(req.grace_secs);
        {
            let mut guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
            guard.insert(
                pin_id,
                PackLeaseRecord {
                    tenant_id: req.tenant_id,
                    repository_id: req.repository_id,
                    pack_oid,
                    expires_at_unix: req.expires_at_unix,
                    grace_until_unix,
                    inflight_downloads: 0,
                    guard_refs: 1,
                    revoked: false,
                    durable_hold,
                },
            );
        }
        Ok(Arc::new(OffloadPackPinGuard {
            pin_id,
            leases: Arc::clone(&self.leases),
            released: Mutex::new(false),
        }))
    }

    /// Validates an active retention hold before starting download streaming.
    pub fn begin_download_hold(
        &self,
        pin_id: Uuid,
        tenant_id: Uuid,
        repository_id: Uuid,
        pack_oid: &str,
        now_unix: u64,
    ) -> Result<InflightDownloadGuard, PackfileUriError> {
        let mut guard = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        let rec = guard
            .get_mut(&pin_id)
            .ok_or_else(|| PackfileUriError::RetentionPinMissing("unknown pack pin".to_owned()))?;
        if rec.revoked || !rec.durable_hold.is_active() || !self.durable_pins.is_pin_active(pin_id) {
            return Err(PackfileUriError::RetentionPinMissing("pack pin revoked".to_owned()));
        }
        if rec.tenant_id != tenant_id || rec.repository_id != repository_id || rec.pack_oid != pack_oid {
            return Err(PackfileUriError::ScopeMismatch(
                "pin does not match tenant, repo, or pack".to_owned(),
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

    /// Re-verifies mid-stream that the active hold has not been revoked or killed.
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
        let before = guard.len();
        guard.retain(|_, rec| {
            rec.inflight_downloads > 0
                || rec.guard_refs > 0
                || (!rec.revoked && now_unix <= rec.grace_until_unix)
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
