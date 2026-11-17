//! Layer 2 version-bound read-only compute view catalog backed by
//! [`DisposableViewRoot`] on `<replica_root>/views` plus isolated push scratch.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use uuid::Uuid;

use crate::blob_store::disposable_view::{DisposableViewRoot, TempViewLease};

use super::{
    lease_pin::ActiveViewSlot,
    pack_cache::{PackCachePin, check_regular_file_len, ensure_private_dir},
    types::{ReplicaCacheError, ReplicaCacheLimits, ReplicaViewKey},
};

const VIEW_DIR_NAME: &str = "views";

struct SlotInner {
    active_readers: usize,
    unindexed: bool,
}

/// Active Layer 2 read-only compute view slot keeping the `TempViewLease` and
/// Layer 1 `PackCachePin`s alive until all readers drop.
pub struct CachedViewSlot {
    view_key: ReplicaViewKey,
    lease: Mutex<Option<TempViewLease>>,
    repo_path: PathBuf,
    reserved_bytes: u64,
    accounted: AtomicBool,
    _pack_pins: Vec<PackCachePin>,
    expected_pack_files: Vec<(String, u64, u64)>,
    state: Mutex<SlotInner>,
    catalog: Arc<Mutex<ViewCatalogInner>>,
}

impl CachedViewSlot {
    pub fn repo_path_unchecked(&self) -> &Path {
        &self.repo_path
    }

    pub fn try_acquire_reader(&self, min_margin: std::time::Duration) -> bool {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if st.unindexed || !self.ensure_live_with_margin(min_margin) || !self.verify_files_intact() {
            return false;
        }
        st.active_readers = st.active_readers.saturating_add(1);
        true
    }

    pub fn active_readers(&self) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).active_readers
    }

    pub fn verify_files_intact(&self) -> bool {
        let Ok(()) = self.ensure_live() else {
            return false;
        };
        for (stem, pack_len, idx_len) in &self.expected_pack_files {
            let pack_p = self.repo_path.join("objects/pack").join(format!("{stem}.pack"));
            let idx_p = self.repo_path.join("objects/pack").join(format!("{stem}.idx"));
            if !check_regular_file_len(&pack_p, *pack_len) || !check_regular_file_len(&idx_p, *idx_len) {
                return false;
            }
        }
        true
    }

    fn ensure_live_with_margin(&self, min_margin: std::time::Duration) -> bool {
        let guard = self.lease.lock().unwrap_or_else(|p| p.into_inner());
        let Some(lease) = guard.as_ref() else {
            return false;
        };
        if lease.ensure_live().is_err() {
            return false;
        }
        lease.expires_at().saturating_duration_since(Instant::now()) >= min_margin
    }
}

impl ActiveViewSlot for CachedViewSlot {
    fn view_key(&self) -> &ReplicaViewKey {
        &self.view_key
    }

    fn repo_path(&self) -> Result<&Path, ReplicaCacheError> {
        self.ensure_live()?;
        Ok(&self.repo_path)
    }

    fn ensure_live(&self) -> Result<(), ReplicaCacheError> {
        let guard = self.lease.lock().unwrap_or_else(|p| p.into_inner());
        let lease = guard.as_ref().ok_or(ReplicaCacheError::IntegrityFailed("view lease released"))?;
        lease.ensure_live()?;
        Ok(())
    }

    fn release_reader(&self) {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.active_readers = st.active_readers.saturating_sub(1);
    }
}

impl Drop for CachedViewSlot {
    fn drop(&mut self) {
        let _ = self.lease.lock().unwrap_or_else(|p| p.into_inner()).take();
        if self.accounted.swap(false, Ordering::SeqCst) {
            let mut guard = self.catalog.lock().unwrap_or_else(|p| p.into_inner());
            guard.resident_bytes = guard.resident_bytes.saturating_sub(self.reserved_bytes);
        }
    }
}

struct IndexedViewEntry {
    slot: Arc<CachedViewSlot>,
    lru_seq: u64,
}

#[derive(Default)]
struct ViewCatalogInner {
    entries: HashMap<String, IndexedViewEntry>,
    resident_bytes: u64,
    lru_counter: u64,
    evicted_count: u64,
    pin_protections: u64,
}

/// Layer 2 version-bound read-only compute view catalog backed by
/// [`DisposableViewRoot`] on `<replica_root>/views`.
#[derive(Clone)]
pub struct ViewCacheCatalog {
    view_root: DisposableViewRoot,
    limits: ReplicaCacheLimits,
    inner: Arc<Mutex<ViewCatalogInner>>,
}

/// Isolated push scratch directory lease strictly separate from shared views.
pub struct PushScratchGuard {
    lease: TempViewLease,
}

impl PushScratchGuard {
    pub fn dir_path(&self) -> Result<&Path, ReplicaCacheError> {
        Ok(self.lease.dir_path()?)
    }

    pub fn repo_path(&self) -> Result<&Path, ReplicaCacheError> {
        Ok(self.lease.repo_path()?)
    }

    pub fn is_isolated_from(&self, shared_view_repo: &Path) -> bool {
        let Ok(scratch_dir) = self.lease.dir_path() else {
            return false;
        };
        scratch_dir != shared_view_repo
            && !shared_view_repo.starts_with(scratch_dir)
            && !scratch_dir.starts_with(shared_view_repo)
    }
}

impl ViewCacheCatalog {
    pub fn open(replica_root: &Path, limits: ReplicaCacheLimits) -> Result<Self, ReplicaCacheError> {
        limits.validate()?;
        ensure_private_dir(replica_root)?;
        let views_subdir = replica_root.join(VIEW_DIR_NAME);
        let view_root =
            DisposableViewRoot::open(&views_subdir, limits.max_active_views, limits.max_view_bytes, limits.view_ttl)?;
        let _ = view_root.sweep_expired();
        Ok(Self { view_root, limits, inner: Arc::new(Mutex::new(ViewCatalogInner::default())) })
    }

    pub fn view_root(&self) -> &DisposableViewRoot {
        &self.view_root
    }

    pub fn cached_count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).entries.len()
    }

    pub fn resident_bytes(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).resident_bytes
    }

    pub fn active_view_dir_count(&self) -> usize {
        self.view_root.active_view_count()
    }

    pub fn stats(&self) -> (u64, u64) {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        (guard.evicted_count, guard.pin_protections)
    }

    pub fn checkout(&self, key: &ReplicaViewKey) -> Result<(Option<Arc<CachedViewSlot>>, bool), ReplicaCacheError> {
        let candidate = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let next_seq = guard.lru_counter.saturating_add(1);
            let slot = {
                let Some(entry) = guard.entries.get_mut(&key.view_key_hex) else {
                    return Ok((None, false));
                };
                if entry.slot.view_key != *key {
                    return Err(ReplicaCacheError::TenantIsolationViolation("view cache key mismatch"));
                }
                entry.lru_seq = next_seq;
                let mut st = entry.slot.state.lock().unwrap_or_else(|p| p.into_inner());
                st.active_readers = st.active_readers.saturating_add(1);
                Arc::clone(&entry.slot)
            };
            guard.lru_counter = next_seq;
            slot
        };

        if !candidate.ensure_live_with_margin(self.limits.min_serve_ttl) || !candidate.verify_files_intact() {
            candidate.release_reader();
            self.unindex_key(&key.view_key_hex);
            return Ok((None, true));
        }
        Ok((Some(candidate), false))
    }

    pub fn ensure_admission_room(&self, needed_bytes: u64) -> Result<(), ReplicaCacheError> {
        if needed_bytes > self.limits.max_view_bytes {
            return Err(ReplicaCacheError::CacheCapacityExhausted("requested view exceeds max_view_bytes"));
        }
        let dropped = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            evict_idle_in_lock(&mut guard, &self.limits, needed_bytes)?
        };
        drop(dropped);
        Ok(())
    }

    pub fn admit_and_checkout(
        &self,
        view_key: ReplicaViewKey,
        lease: TempViewLease,
        pack_pins: Vec<PackCachePin>,
        reserved_bytes: u64,
        expected_pack_files: Vec<(String, u64, u64)>,
    ) -> Result<Arc<CachedViewSlot>, ReplicaCacheError> {
        if reserved_bytes > self.limits.max_view_bytes {
            return Err(ReplicaCacheError::CacheCapacityExhausted("view exceeds max_view_bytes"));
        }
        let repo_path = lease.repo_path()?.to_path_buf();
        let slot = Arc::new(CachedViewSlot {
            view_key: view_key.clone(),
            lease: Mutex::new(Some(lease)),
            repo_path,
            reserved_bytes,
            accounted: AtomicBool::new(false),
            _pack_pins: pack_pins,
            expected_pack_files,
            state: Mutex::new(SlotInner { active_readers: 1, unindexed: false }),
            catalog: Arc::clone(&self.inner),
        });
        let dropped = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let mut dropped = evict_idle_in_lock(&mut guard, &self.limits, reserved_bytes)?;
            guard.lru_counter = guard.lru_counter.saturating_add(1);
            let lru_seq = guard.lru_counter;
            guard.resident_bytes = guard.resident_bytes.saturating_add(reserved_bytes);
            slot.accounted.store(true, Ordering::SeqCst);
            if let Some(old) =
                guard.entries.insert(view_key.view_key_hex, IndexedViewEntry { slot: Arc::clone(&slot), lru_seq })
            {
                old.slot.state.lock().unwrap_or_else(|p| p.into_inner()).unindexed = true;
                dropped.push(old.slot);
            }
            dropped
        };
        drop(dropped);
        Ok(slot)
    }

    pub fn unindex_key(&self, view_key_hex: &str) {
        let removed = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            guard.entries.remove(view_key_hex).map(|e| {
                e.slot.state.lock().unwrap_or_else(|p| p.into_inner()).unindexed = true;
                e.slot
            })
        };
        drop(removed);
    }

    pub fn clear_all(&self) {
        let removed: Vec<Arc<CachedViewSlot>> = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let mut out = Vec::with_capacity(guard.entries.len());
            for (_, entry) in guard.entries.drain() {
                entry.slot.state.lock().unwrap_or_else(|p| p.into_inner()).unindexed = true;
                out.push(entry.slot);
            }
            out
        };
        drop(removed);
    }

    pub fn allocate_push_scratch(
        &self,
        tenant_id: Uuid,
        repo_id: Uuid,
        reserved_bytes: u64,
    ) -> Result<PushScratchGuard, ReplicaCacheError> {
        let lease = self.view_root.create_view("push-scratch", tenant_id, repo_id, reserved_bytes, None)?;
        Ok(PushScratchGuard { lease })
    }
}

fn evict_idle_in_lock(
    guard: &mut ViewCatalogInner,
    limits: &ReplicaCacheLimits,
    needed_bytes: u64,
) -> Result<Vec<Arc<CachedViewSlot>>, ReplicaCacheError> {
    let mut candidates: Vec<(u64, String, u64)> = guard
        .entries
        .iter()
        .filter(|(_, e)| e.slot.active_readers() == 0)
        .map(|(k, e)| (e.lru_seq, k.clone(), e.slot.reserved_bytes))
        .collect();
    candidates.sort_by_key(|(seq, _, _)| *seq);

    let mut projected_count = guard.entries.len();
    let mut projected_bytes = guard.resident_bytes;
    let mut victims = Vec::new();
    for (_, key, bytes) in candidates {
        if projected_count < limits.max_view_entries
            && projected_bytes.saturating_add(needed_bytes) <= limits.max_view_bytes
        {
            break;
        }
        projected_count = projected_count.saturating_sub(1);
        projected_bytes = projected_bytes.saturating_sub(bytes);
        victims.push(key);
    }
    if projected_count >= limits.max_view_entries
        || projected_bytes.saturating_add(needed_bytes) > limits.max_view_bytes
    {
        guard.pin_protections = guard.pin_protections.saturating_add(1);
        return Err(ReplicaCacheError::CacheCapacityExhausted("view cache capacity pinned by active readers"));
    }

    let mut dropped = Vec::with_capacity(victims.len());
    for key in victims {
        if let Some(entry) = guard.entries.remove(&key) {
            entry.slot.state.lock().unwrap_or_else(|p| p.into_inner()).unindexed = true;
            guard.evicted_count = guard.evicted_count.saturating_add(1);
            dropped.push(entry.slot);
        }
    }
    Ok(dropped)
}
