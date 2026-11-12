//! Per-workspace in-memory mutation coordinator, `ScanToken` fencing, and
//! directory cleanup guards.
use crate::Error;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::sync::OwnedMutexGuard;
use uuid::Uuid;

use super::lock;

struct MutationEntry {
    mutex: Arc<tokio::sync::Mutex<()>>,
    notify: Arc<tokio::sync::Notify>,
    refs: usize,
    active: bool,
    waiters: usize,
    active_scans: usize,
    generation: u64,
}

impl MutationEntry {
    fn new() -> Self {
        Self {
            mutex: Arc::new(tokio::sync::Mutex::new(())),
            notify: Arc::new(tokio::sync::Notify::new()),
            refs: 0,
            active: false,
            waiters: 0,
            active_scans: 0,
            generation: 0,
        }
    }

    fn is_idle(&self) -> bool {
        self.refs == 0 && !self.active && self.waiters == 0 && self.active_scans == 0
    }
}

fn mutations() -> &'static Mutex<HashMap<Uuid, MutationEntry>> {
    static MAP: OnceLock<Mutex<HashMap<Uuid, MutationEntry>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
pub(super) fn test_waiters_and_present(id: Uuid) -> (usize, bool) {
    let map = lock(mutations());
    (map.get(&id).map_or(0, |e| e.waiters), map.contains_key(&id))
}

struct WaiterGuard {
    id: Uuid,
    waiting: bool,
    ref_armed: bool,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        if !self.waiting && !self.ref_armed {
            return;
        }
        let mut map = lock(mutations());
        let remove = if let Some(entry) = map.get_mut(&self.id) {
            if self.waiting {
                entry.waiters = entry.waiters.saturating_sub(1);
            }
            if self.ref_armed {
                entry.refs = entry.refs.saturating_sub(1);
            }
            entry.is_idle()
        } else {
            false
        };
        if remove {
            map.remove(&self.id);
        }
    }
}

/// Exclusive in-memory per-workspace mutation guard. Held across off-TX
/// filesystem/Git execution and the short commit TX so concurrent API writes on
/// the same workspace serialize cleanly without holding PostgreSQL row locks.
pub(in crate::workspaces) struct MutationGuard {
    id: Uuid,
    _owned: OwnedMutexGuard<()>,
}

impl MutationGuard {
    /// Hold `active_scans > 0` across a foreground blocking mutation, FUSE
    /// freeze, or rollback/cleanup guard so even a timed-out or cancelled caller
    /// cannot allow another mutation or scan on `id` until disk work finishes.
    pub(in crate::workspaces) fn freeze_guard(&self) -> ScanToken {
        let mut map = lock(mutations());
        let entry = map.get_mut(&self.id).expect("workspace mutation entry retained by active guard");
        entry.refs += 1;
        entry.active_scans += 1;
        let generation = entry.generation;
        ScanToken { slot: Arc::new(ScanSlot { id: self.id, generation }) }
    }
}

impl Drop for MutationGuard {
    fn drop(&mut self) {
        let mut map = lock(mutations());
        let remove = if let Some(entry) = map.get_mut(&self.id) {
            entry.active = false;
            entry.generation = entry.generation.wrapping_add(1);
            entry.refs = entry.refs.saturating_sub(1);
            entry.is_idle()
        } else {
            false
        };
        if remove {
            map.remove(&self.id);
        }
    }
}

pub(in crate::workspaces) async fn lock_mutation(id: Uuid, timeout: Duration) -> Result<MutationGuard, Error> {
    let deadline = tokio::time::Instant::now() + timeout;
    let (mutex, notify) = {
        let mut map = lock(mutations());
        let entry = map.entry(id).or_insert_with(MutationEntry::new);
        entry.refs += 1;
        entry.waiters += 1;
        (entry.mutex.clone(), entry.notify.clone())
    };
    let mut waiter = WaiterGuard { id, waiting: true, ref_armed: true };
    let owned = tokio::time::timeout_at(deadline, mutex.lock_owned()).await.map_err(|_| Error::timeout())?;
    loop {
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        {
            let mut map = lock(mutations());
            let entry = map.get_mut(&id).expect("workspace mutation entry retained by refcount");
            if entry.active_scans == 0 {
                entry.waiters = entry.waiters.saturating_sub(1);
                waiter.waiting = false;
                entry.active = true;
                entry.generation = entry.generation.wrapping_add(1);
                waiter.ref_armed = false;
                break;
            }
        }
        tokio::time::timeout_at(deadline, notified).await.map_err(|_| Error::timeout())?;
    }
    Ok(MutationGuard { id, _owned: owned })
}

/// Removes an uncommitted newly created directory if a failure or idempotent
/// race unwinds before the database `COMMIT` is sent.
pub(in crate::workspaces) struct DirCleanupGuard {
    path: PathBuf,
    fence: Option<ScanToken>,
    kept: bool,
}

impl DirCleanupGuard {
    pub(in crate::workspaces) fn new(path: PathBuf) -> Self {
        Self { path, fence: None, kept: false }
    }

    pub(in crate::workspaces) fn with_fence(path: PathBuf, fence: Option<ScanToken>) -> Self {
        Self { path, fence, kept: false }
    }

    pub(in crate::workspaces) fn keep(mut self) {
        self.kept = true;
        self.fence = None;
    }

    pub(in crate::workspaces) async fn cleanup(mut self) {
        if !self.kept {
            self.kept = true;
            let fence = self.fence.take();
            super::super::cleanup::cleanup_paths_async(Some(self.path.clone()), None, false, fence).await;
        }
    }
}

impl Drop for DirCleanupGuard {
    fn drop(&mut self) {
        if !self.kept {
            let fence = self.fence.take();
            super::super::cleanup::cleanup_paths_on_drop(Some(self.path.clone()), None, false, fence);
        }
    }
}

struct ScanSlot {
    id: Uuid,
    generation: u64,
}

impl Drop for ScanSlot {
    fn drop(&mut self) {
        let notify = {
            let mut map = lock(mutations());
            let mut wake = None;
            let remove = if let Some(entry) = map.get_mut(&self.id) {
                entry.active_scans = entry.active_scans.saturating_sub(1);
                entry.refs = entry.refs.saturating_sub(1);
                if entry.active_scans == 0 {
                    wake = Some(entry.notify.clone());
                }
                entry.is_idle()
            } else {
                false
            };
            if remove {
                map.remove(&self.id);
            }
            wake
        };
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
    }
}

/// Refcounted observation/fence token held by `capture::reconcile_one`,
/// foreground mutating OS workers, and pre-`COMMIT` rollback/cleanup guards.
#[derive(Clone)]
pub(in crate::workspaces) struct ScanToken {
    slot: Arc<ScanSlot>,
}

impl ScanToken {
    pub(in crate::workspaces) fn is_unchanged(&self) -> bool {
        let map = lock(mutations());
        map.get(&self.slot.id).is_some_and(|entry| !entry.active && entry.generation == self.slot.generation)
    }
}

pub(in crate::workspaces) fn begin_scan(id: Uuid) -> Option<ScanToken> {
    let mut map = lock(mutations());
    let entry = map.entry(id).or_insert_with(MutationEntry::new);
    if entry.active || entry.waiters > 0 || entry.active_scans > 0 {
        if entry.is_idle() {
            map.remove(&id);
        }
        return None;
    }
    entry.refs += 1;
    entry.active_scans += 1;
    let generation = entry.generation;
    Some(ScanToken { slot: Arc::new(ScanSlot { id, generation }) })
}
