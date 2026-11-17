//! Layer 1 verified immutable `.pack` / `.idx` cache scoped strictly by
//! `(tenant_id, repo_id, backend_identity_hex, object_format, digests)`.

use std::{
    collections::HashMap,
    fs::{DirBuilder, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::error::{PackRootLockGuard, is_lower_hex_exact, sweep_orphan_cache_dirs, validate_canonical_child_path};
use super::types::{PackCacheKey, ReplicaCacheError, ReplicaCacheLimits};

const PACK_DIR_NAME: &str = "packs";
const HASH_CHUNK_BYTES: usize = 64 * 1024;

struct PackCacheEntry {
    key: PackCacheKey,
    dir_path: PathBuf,
    pack_path: PathBuf,
    idx_path: PathBuf,
    total_bytes: u64,
    pin_count: usize,
    lru_seq: u64,
}

#[derive(Default)]
struct PackCatalogInner {
    entries: HashMap<String, PackCacheEntry>,
    retired_entries: HashMap<PathBuf, PackCacheEntry>,
    total_bytes: u64,
    lru_counter: u64,
    evicted_count: u64,
    pin_protections: u64,
}

/// Layer 1 verified immutable `.pack` / `.idx` cache.
#[derive(Clone)]
pub struct PackCacheCatalog {
    root_dir: PathBuf,
    limits: ReplicaCacheLimits,
    inner: Arc<Mutex<PackCatalogInner>>,
    _root_lock: Arc<PackRootLockGuard>,
}

pub struct PackCachePin {
    root_dir: PathBuf,
    key_digest: String,
    dir_path: PathBuf,
    pack_path: PathBuf,
    idx_path: PathBuf,
    inner: Arc<Mutex<PackCatalogInner>>,
    released: bool,
}

impl PackCachePin {
    pub fn pack_path(&self) -> &Path {
        &self.pack_path
    }

    pub fn idx_path(&self) -> &Path {
        &self.idx_path
    }
}

impl Drop for PackCachePin {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let remove_dir = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = guard.entries.get_mut(&self.key_digest)
                && entry.dir_path == self.dir_path
            {
                entry.pin_count = entry.pin_count.saturating_sub(1);
                None
            } else if let Some(entry) = guard.retired_entries.get_mut(&self.dir_path) {
                entry.pin_count = entry.pin_count.saturating_sub(1);
                if entry.pin_count == 0 {
                    guard.retired_entries.remove(&self.dir_path).map(|e| (e.dir_path, e.total_bytes))
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some((dir, bytes)) = remove_dir {
            let _ = remove_child_safely(&self.root_dir, &dir);
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            guard.total_bytes = guard.total_bytes.saturating_sub(bytes);
        }
    }
}

impl PackCacheCatalog {
    pub fn open(replica_root: &Path, limits: ReplicaCacheLimits) -> Result<Self, ReplicaCacheError> {
        limits.validate()?;
        ensure_private_dir(replica_root)?;
        let raw_root = replica_root.join(PACK_DIR_NAME);
        ensure_private_dir(&raw_root)?;
        let root_dir = std::fs::canonicalize(&raw_root)
            .map_err(|e| ReplicaCacheError::Io(format!("failed canonicalizing pack cache root: {e}")))?;
        let root_lock = Arc::new(PackRootLockGuard::acquire(&root_dir)?);
        let _ = sweep_orphan_cache_dirs(&root_dir)?;
        Ok(Self { root_dir, limits, inner: Arc::new(Mutex::new(PackCatalogInner::default())), _root_lock: root_lock })
    }

    pub fn staging_dir(&self) -> Result<PathBuf, ReplicaCacheError> {
        verify_private_dir(&self.root_dir)?;
        let stage = validate_canonical_child_path(
            &self.root_dir,
            &self.root_dir.join(format!(".stage-{}", Uuid::new_v4().simple())),
        )?;
        DirBuilder::new()
            .mode(0o700)
            .create(&stage)
            .map_err(|e| ReplicaCacheError::Io(format!("failed creating pack staging dir: {e}")))?;
        Ok(stage)
    }

    fn make_pin(&self, key_digest: String, dir_path: PathBuf, pack_path: PathBuf, idx_path: PathBuf) -> PackCachePin {
        PackCachePin {
            root_dir: self.root_dir.clone(),
            key_digest,
            dir_path,
            pack_path,
            idx_path,
            inner: Arc::clone(&self.inner),
            released: false,
        }
    }

    pub fn entry_count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).entries.len()
    }

    pub fn total_bytes(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).total_bytes
    }

    pub fn stats(&self) -> (u64, u64) {
        let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        (guard.evicted_count, guard.pin_protections)
    }

    pub fn pin_if_valid(
        &self,
        key: &PackCacheKey,
        verify_sha256: bool,
    ) -> Result<(Option<PackCachePin>, bool), ReplicaCacheError> {
        key.validate()?;
        verify_private_dir(&self.root_dir)?;
        let paths = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let next_seq = guard.lru_counter.saturating_add(1);
            let paths = {
                let Some(entry) = guard.entries.get_mut(key.key_digest()) else {
                    return Ok((None, false));
                };
                if entry.key != *key {
                    return Err(ReplicaCacheError::TenantIsolationViolation("pack cache key mismatch"));
                }
                entry.lru_seq = next_seq;
                entry.pin_count = entry.pin_count.saturating_add(1);
                (entry.dir_path.clone(), entry.pack_path.clone(), entry.idx_path.clone())
            };
            guard.lru_counter = next_seq;
            paths
        };

        let pin = self.make_pin(key.key_digest().to_owned(), paths.0.clone(), paths.1.clone(), paths.2.clone());
        let paths_ok = validate_canonical_child_path(&self.root_dir, &paths.0).is_ok()
            && validate_canonical_child_path(&paths.0, &paths.1).is_ok()
            && validate_canonical_child_path(&paths.0, &paths.2).is_ok();
        if !paths_ok || !verify_cached_pack_files(&paths.1, &paths.2, key, verify_sha256) {
            drop(pin);
            self.retire_key(key.key_digest());
            return Ok((None, true));
        }
        Ok((Some(pin), false))
    }

    pub fn install_and_pin(
        &self,
        key: PackCacheKey,
        staged_pack: &Path,
        staged_idx: &Path,
    ) -> Result<PackCachePin, ReplicaCacheError> {
        key.validate()?;
        verify_private_dir(&self.root_dir)?;
        let entry_bytes = key
            .pack_length()
            .checked_add(key.idx_length())
            .ok_or(ReplicaCacheError::CacheCapacityExhausted("pack byte count overflow"))?;
        if entry_bytes > self.limits.max_pack_bytes {
            return Err(ReplicaCacheError::CacheCapacityExhausted("pack pair exceeds max_pack_bytes"));
        }

        let target_dir = validate_canonical_child_path(
            &self.root_dir,
            &self.root_dir.join(format!("{}-{}", key.key_digest(), Uuid::new_v4().simple())),
        )?;
        let pack_name = format!("{}.pack", key.pack_stem());
        let idx_name = format!("{}.idx", key.pack_stem());
        let target_pack = validate_canonical_child_path(&self.root_dir, &target_dir.join(&pack_name))?;
        let target_idx = validate_canonical_child_path(&self.root_dir, &target_dir.join(&idx_name))?;

        let to_remove = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let next_seq = guard.lru_counter.saturating_add(1);
            let hit = guard.entries.get_mut(key.key_digest()).map(|existing| {
                existing.lru_seq = next_seq;
                existing.pin_count = existing.pin_count.saturating_add(1);
                (existing.dir_path.clone(), existing.pack_path.clone(), existing.idx_path.clone())
            });
            if let Some((dir_path, pack_path, idx_path)) = hit {
                guard.lru_counter = next_seq;
                return Ok(self.make_pin(key.key_digest().to_owned(), dir_path, pack_path, idx_path));
            }
            evict_unpinned_packs(&mut guard, &self.limits, entry_bytes)?
        };
        for dir in to_remove {
            let _ = remove_child_safely(&self.root_dir, &dir);
        }

        let staging_dir = validate_canonical_child_path(
            &self.root_dir,
            &self.root_dir.join(format!(".install-{}", Uuid::new_v4().simple())),
        )?;
        DirBuilder::new()
            .mode(0o700)
            .create(&staging_dir)
            .map_err(|e| ReplicaCacheError::Io(format!("failed creating pack install dir: {e}")))?;
        let install_res = (|| -> Result<(), ReplicaCacheError> {
            let stage_pack = validate_canonical_child_path(&staging_dir, &staging_dir.join(&pack_name))?;
            let stage_idx = validate_canonical_child_path(&staging_dir, &staging_dir.join(&idx_name))?;
            copy_readonly(staged_pack, &stage_pack)?;
            copy_readonly(staged_idx, &stage_idx)?;
            std::fs::rename(&staging_dir, &target_dir)
                .map_err(|e| ReplicaCacheError::Io(format!("failed committing pack dir: {e}")))?;
            validate_canonical_child_path(&target_dir, &target_pack)?;
            validate_canonical_child_path(&target_dir, &target_idx)?;
            Ok(())
        })();
        if let Err(err) = install_res {
            let _ = remove_child_safely(&self.root_dir, &staging_dir);
            return Err(err);
        }

        let (to_remove_late, pin) = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let next_seq = guard.lru_counter.saturating_add(1);
            if let Some((dir_path, pack_path, idx_path)) = guard.entries.get_mut(key.key_digest()).map(|existing| {
                existing.lru_seq = next_seq;
                existing.pin_count = existing.pin_count.saturating_add(1);
                (existing.dir_path.clone(), existing.pack_path.clone(), existing.idx_path.clone())
            }) {
                guard.lru_counter = next_seq;
                drop(guard);
                let _ = remove_child_safely(&self.root_dir, &target_dir);
                return Ok(self.make_pin(key.key_digest().to_owned(), dir_path, pack_path, idx_path));
            }
            let evicted = match evict_unpinned_packs(&mut guard, &self.limits, entry_bytes) {
                Ok(v) => v,
                Err(err) => {
                    drop(guard);
                    let _ = remove_child_safely(&self.root_dir, &target_dir);
                    return Err(err);
                }
            };
            let key_digest = key.key_digest().to_owned();
            guard.lru_counter = next_seq;
            guard.total_bytes = guard.total_bytes.saturating_add(entry_bytes);
            guard.entries.insert(
                key_digest.clone(),
                PackCacheEntry {
                    key,
                    dir_path: target_dir.clone(),
                    pack_path: target_pack.clone(),
                    idx_path: target_idx.clone(),
                    total_bytes: entry_bytes,
                    pin_count: 1,
                    lru_seq: next_seq,
                },
            );
            (evicted, self.make_pin(key_digest, target_dir, target_pack, target_idx))
        };
        for dir in to_remove_late {
            let _ = remove_child_safely(&self.root_dir, &dir);
        }
        Ok(pin)
    }

    pub fn retire_key(&self, key_digest: &str) {
        if !is_lower_hex_exact(key_digest, 64) {
            return;
        }
        let remove_dir = {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = guard.entries.remove(key_digest) {
                if entry.pin_count == 0 {
                    guard.total_bytes = guard.total_bytes.saturating_sub(entry.total_bytes);
                    Some(entry.dir_path)
                } else {
                    guard.retired_entries.insert(entry.dir_path.clone(), entry);
                    None
                }
            } else {
                None
            }
        };
        if let Some(dir) = remove_dir {
            let _ = remove_child_safely(&self.root_dir, &dir);
        }
    }

    pub fn clear_all(&self) {
        let mut to_remove = Vec::new();
        {
            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let keys: Vec<String> = guard.entries.keys().cloned().collect();
            for key in keys {
                if let Some(entry) = guard.entries.remove(&key) {
                    if entry.pin_count == 0 {
                        guard.total_bytes = guard.total_bytes.saturating_sub(entry.total_bytes);
                        to_remove.push(entry.dir_path);
                    } else {
                        guard.retired_entries.insert(entry.dir_path.clone(), entry);
                    }
                }
            }
        }
        for dir in to_remove {
            let _ = remove_child_safely(&self.root_dir, &dir);
        }
    }
}

fn evict_unpinned_packs(
    guard: &mut PackCatalogInner,
    limits: &ReplicaCacheLimits,
    needed_bytes: u64,
) -> Result<Vec<PathBuf>, ReplicaCacheError> {
    let mut candidates: Vec<(u64, String, u64)> = guard
        .entries
        .iter()
        .filter(|(_, e)| e.pin_count == 0)
        .map(|(k, e)| (e.lru_seq, k.clone(), e.total_bytes))
        .collect();
    candidates.sort_by_key(|(seq, _, _)| *seq);

    let mut projected_count = guard.entries.len();
    let mut projected_bytes = guard.total_bytes;
    let mut victims = Vec::new();
    for (_, key, bytes) in candidates {
        if projected_count < limits.max_pack_entries
            && projected_bytes.saturating_add(needed_bytes) <= limits.max_pack_bytes
        {
            break;
        }
        projected_count = projected_count.saturating_sub(1);
        projected_bytes = projected_bytes.saturating_sub(bytes);
        victims.push(key);
    }
    if projected_count >= limits.max_pack_entries
        || projected_bytes.saturating_add(needed_bytes) > limits.max_pack_bytes
    {
        guard.pin_protections = guard.pin_protections.saturating_add(1);
        return Err(ReplicaCacheError::CacheCapacityExhausted("pack cache capacity pinned by active views"));
    }
    let mut dirs = Vec::with_capacity(victims.len());
    for key in victims {
        if let Some(removed) = guard.entries.remove(&key) {
            guard.total_bytes = guard.total_bytes.saturating_sub(removed.total_bytes);
            guard.evicted_count = guard.evicted_count.saturating_add(1);
            dirs.push(removed.dir_path);
        }
    }
    Ok(dirs)
}

pub fn ensure_private_dir(dir: &Path) -> Result<(), ReplicaCacheError> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => verify_private_dir(dir),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => verify_private_dir(dir),
        Err(e) => Err(ReplicaCacheError::Io(format!("failed creating private dir: {e}"))),
    }
}

pub fn verify_private_dir(path: &Path) -> Result<(), ReplicaCacheError> {
    let meta =
        std::fs::symlink_metadata(path).map_err(|e| ReplicaCacheError::Io(format!("failed inspecting dir: {e}")))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(ReplicaCacheError::IntegrityFailed("cache directory must not be a symlink"));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(ReplicaCacheError::IntegrityFailed("cache directory must remain 0o700 private"));
    }
    Ok(())
}

fn remove_child_safely(root: &Path, dir: &Path) -> Result<(), ReplicaCacheError> {
    let safe = validate_canonical_child_path(root, dir)?;
    remove_dir_safely(&safe)
}

pub fn remove_dir_safely(dir: &Path) -> Result<(), ReplicaCacheError> {
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(ReplicaCacheError::Io(format!("failed inspecting dir for removal: {e}"))),
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(ReplicaCacheError::IntegrityFailed("refusing to remove symlink or non-directory"));
            }
            std::fs::remove_dir_all(dir)
                .map_err(|e| ReplicaCacheError::Io(format!("failed removing cache dir: {e}")))?;
            Ok(())
        }
    }
}

pub fn copy_readonly(src: &Path, dst: &Path) -> Result<u64, ReplicaCacheError> {
    let mut reader = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(src)
        .map_err(|e| ReplicaCacheError::Io(format!("failed opening source file: {e}")))?;
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dst)
        .map_err(|e| ReplicaCacheError::Io(format!("failed creating readonly target: {e}")))?;
    let mut buf = vec![0u8; HASH_CHUNK_BYTES];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).map_err(|e| ReplicaCacheError::Io(format!("read failed: {e}")))?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).map_err(|e| ReplicaCacheError::Io(format!("write failed: {e}")))?;
        total = total.saturating_add(n as u64);
    }
    writer.sync_all().map_err(|e| ReplicaCacheError::Io(format!("sync failed: {e}")))?;
    std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o444))
        .map_err(|e| ReplicaCacheError::Io(format!("chmod 0444 failed: {e}")))?;
    Ok(total)
}

pub(super) fn check_regular_file_len(path: &Path, expected_len: u64) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    !meta.file_type().is_symlink() && meta.is_file() && meta.len() == expected_len
}

fn verify_cached_pack_files(pack_path: &Path, idx_path: &Path, key: &PackCacheKey, verify_sha256: bool) -> bool {
    if !check_regular_file_len(pack_path, key.pack_length()) || !check_regular_file_len(idx_path, key.idx_length()) {
        return false;
    }
    if !verify_sha256 {
        return true;
    }
    hash_file_matches(pack_path, key.pack_sha256(), key.pack_length())
        && hash_file_matches(idx_path, key.idx_sha256(), key.idx_length())
}

pub(super) fn hash_file_matches(path: &Path, expected_sha256: &str, expected_len: u64) -> bool {
    let Ok(mut file) = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path) else {
        return false;
    };
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; HASH_CHUNK_BYTES];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
                total = total.saturating_add(n as u64);
            }
            Err(_) => return false,
        }
    }
    total == expected_len && hex::encode(hasher.finalize()) == expected_sha256
}
