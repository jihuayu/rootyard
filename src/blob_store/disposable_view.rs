//! Isolated, bounded-TTL discardable scratch directories for local Git views.
//!
//! Temporary Git repositories materialized on compute nodes carry zero
//! authoritative state: durable blobs live in the remote [`BlobStore`] and refs
//! live in `RefStore`. Every view gets a private `0o700` directory with strict
//! symlink/traversal guards, an explicit TTL lease, RAII drop cleanup, and
//! bounded expired-view reclamation across process restarts.

mod fs;

use std::{
    collections::HashMap,
    fmt,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use fs::{
    ViewLeaseRecord, ensure_private_dir, init_view_dirs, read_lease_record, remove_view_dir_safely, unix_ms_now,
    validate_purpose, verify_private_dir,
};
use uuid::Uuid;

pub const MAX_ACTIVE_VIEWS_LIMIT: usize = 4096;
pub const MAX_VIEW_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const MAX_PURPOSE_BYTES: usize = 32;
const VIEW_LEASE_SCHEMA: u32 = 1;
const VIEW_DIR_PREFIX: &str = "rv1-";
const LEASE_FILE_NAME: &str = "lease.json";
const REPO_SUBDIR_NAME: &str = "repo.git";
const MAX_LEASE_JSON_BYTES: u64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisposableViewError {
    InvalidConfig(&'static str),
    InvalidArgument(&'static str),
    UnsafePath(&'static str),
    CapacityExceeded(&'static str),
    Expired,
    Io(&'static str),
}

impl fmt::Display for DisposableViewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid disposable view config: {reason}"),
            Self::InvalidArgument(reason) => write!(f, "invalid disposable view argument: {reason}"),
            Self::UnsafePath(reason) => write!(f, "disposable view path rejected: {reason}"),
            Self::CapacityExceeded(reason) => write!(f, "disposable view capacity exceeded: {reason}"),
            Self::Expired => f.write_str("disposable view lease has expired"),
            Self::Io(reason) => write!(f, "disposable view IO error: {reason}"),
        }
    }
}

impl std::error::Error for DisposableViewError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepReport {
    pub removed_views: usize,
    pub skipped_live_views: usize,
    pub reclaimed_reserved_bytes: u64,
}

struct ActiveViewEntry {
    reserved_bytes: u64,
    expires_at: Instant,
}

struct ViewRegistry {
    root_dir: PathBuf,
    max_active_views: usize,
    max_total_bytes: u64,
    default_ttl: Duration,
    active_views: HashMap<Uuid, ActiveViewEntry>,
    total_reserved_bytes: u64,
}

/// Root scratch manager governing bounded, isolated `0o700` temporary Git view
/// directories.
#[derive(Clone)]
pub struct DisposableViewRoot {
    registry: Arc<Mutex<ViewRegistry>>,
}

impl DisposableViewRoot {
    pub fn open(
        root_dir: &Path,
        max_active_views: usize,
        max_total_bytes: u64,
        default_ttl: Duration,
    ) -> Result<Self, DisposableViewError> {
        if !root_dir.is_absolute() || root_dir.as_os_str().is_empty() {
            return Err(DisposableViewError::InvalidConfig("view root must be an absolute path"));
        }
        if max_active_views == 0 || max_active_views > MAX_ACTIVE_VIEWS_LIMIT {
            return Err(DisposableViewError::InvalidConfig("max_active_views out of range"));
        }
        if max_total_bytes == 0 {
            return Err(DisposableViewError::InvalidConfig("max_total_bytes must be positive"));
        }
        if default_ttl.is_zero() || default_ttl > MAX_VIEW_TTL {
            return Err(DisposableViewError::InvalidConfig("default_ttl out of range"));
        }
        ensure_private_dir(root_dir)?;
        let registry = ViewRegistry {
            root_dir: root_dir.to_path_buf(),
            max_active_views,
            max_total_bytes,
            default_ttl,
            active_views: HashMap::new(),
            total_reserved_bytes: 0,
        };
        Ok(Self { registry: Arc::new(Mutex::new(registry)) })
    }

    pub fn active_view_count(&self) -> usize {
        let guard = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        guard.active_views.len()
    }

    pub fn total_reserved_bytes(&self) -> u64 {
        let guard = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        guard.total_reserved_bytes
    }

    /// Allocate one isolated, TTL-bounded temporary view under the root.
    pub fn create_view(
        &self,
        purpose: &str,
        tenant_id: Uuid,
        authority_id: Uuid,
        reserved_bytes: u64,
        ttl: Option<Duration>,
    ) -> Result<TempViewLease, DisposableViewError> {
        validate_purpose(purpose)?;
        if tenant_id.is_nil() || authority_id.is_nil() {
            return Err(DisposableViewError::InvalidArgument("view requires non-nil tenant and authority"));
        }

        let (effective_ttl, view_id, root_dir, dir_path) = {
            let mut guard = self.registry.lock().unwrap_or_else(|p| p.into_inner());
            verify_private_dir(&guard.root_dir)?;
            let effective_ttl = ttl.unwrap_or(guard.default_ttl);
            if effective_ttl.is_zero() || effective_ttl > MAX_VIEW_TTL {
                return Err(DisposableViewError::InvalidArgument("view ttl out of range"));
            }
            if guard.active_views.len() >= guard.max_active_views {
                return Err(DisposableViewError::CapacityExceeded("active disposable view limit reached"));
            }
            let next_bytes = guard
                .total_reserved_bytes
                .checked_add(reserved_bytes)
                .ok_or(DisposableViewError::CapacityExceeded("reserved byte counter overflow"))?;
            if next_bytes > guard.max_total_bytes {
                return Err(DisposableViewError::CapacityExceeded("disposable view byte budget exceeded"));
            }
            let view_id = Uuid::new_v4();
            let root_dir = guard.root_dir.clone();
            let dir_path = root_dir.join(format!("{VIEW_DIR_PREFIX}{}", view_id.simple()));
            let expires_at = Instant::now() + effective_ttl;
            guard.active_views.insert(view_id, ActiveViewEntry { reserved_bytes, expires_at });
            guard.total_reserved_bytes = next_bytes;
            (effective_ttl, view_id, root_dir, dir_path)
        };

        let expires_at_unix_ms =
            unix_ms_now()?.saturating_add(u64::try_from(effective_ttl.as_millis()).unwrap_or(u64::MAX));
        let record = ViewLeaseRecord {
            schema: VIEW_LEASE_SCHEMA,
            view_id,
            purpose: purpose.to_owned(),
            tenant_id,
            authority_id,
            reserved_bytes,
            pid: std::process::id(),
            expires_at_unix_ms,
        };
        if let Err(err) = init_view_dirs(&root_dir, view_id, &dir_path, &record) {
            let _ = remove_view_dir_safely(&dir_path);
            let mut guard = self.registry.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(entry) = guard.active_views.remove(&view_id) {
                guard.total_reserved_bytes = guard.total_reserved_bytes.saturating_sub(entry.reserved_bytes);
            }
            return Err(err);
        }

        let repo_path = dir_path.join(REPO_SUBDIR_NAME);
        let expires_at = Instant::now() + effective_ttl;
        Ok(TempViewLease {
            registry: Arc::clone(&self.registry),
            view_id,
            tenant_id,
            authority_id,
            reserved_bytes,
            dir_path,
            repo_path,
            expires_at,
        })
    }

    /// Reclaim expired view directories under `root_dir`, including orphaned
    /// views left by crashed or restarted processes, while skipping live
    /// unexpired handles.
    pub fn sweep_expired(&self) -> Result<SweepReport, DisposableViewError> {
        let now = Instant::now();
        let now_unix_ms = unix_ms_now()?;
        let (root_dir, expired_active) = {
            let mut guard = self.registry.lock().unwrap_or_else(|p| p.into_inner());
            verify_private_dir(&guard.root_dir)?;
            let expired_ids: Vec<Uuid> = guard
                .active_views
                .iter()
                .filter_map(|(id, entry)| if entry.expires_at <= now { Some(*id) } else { None })
                .collect();
            let mut removed_map = Vec::with_capacity(expired_ids.len());
            for id in expired_ids {
                if let Some(entry) = guard.active_views.remove(&id) {
                    guard.total_reserved_bytes = guard.total_reserved_bytes.saturating_sub(entry.reserved_bytes);
                    removed_map.push((id, entry.reserved_bytes));
                }
            }
            (guard.root_dir.clone(), removed_map)
        };

        let mut report = SweepReport { removed_views: 0, skipped_live_views: 0, reclaimed_reserved_bytes: 0 };
        for (expired_id, reserved) in expired_active {
            let candidate = root_dir.join(format!("{VIEW_DIR_PREFIX}{}", expired_id.simple()));
            if remove_view_dir_safely(&candidate)? {
                report.removed_views += 1;
                report.reclaimed_reserved_bytes = report.reclaimed_reserved_bytes.saturating_add(reserved);
            }
        }

        let entries = std::fs::read_dir(&root_dir).map_err(|_| DisposableViewError::Io("failed reading view root"))?;
        for entry_res in entries {
            let entry = entry_res.map_err(|_| DisposableViewError::Io("failed inspecting view entry"))?;
            let file_name = entry.file_name();
            let Some(name_str) = file_name.to_str() else {
                continue;
            };
            let Some(id_hex) = name_str.strip_prefix(VIEW_DIR_PREFIX) else {
                continue;
            };
            let Ok(view_id) = Uuid::parse_str(id_hex) else {
                continue;
            };
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() || !meta.is_dir() {
                continue;
            }
            {
                let guard = self.registry.lock().unwrap_or_else(|p| p.into_inner());
                if guard.active_views.contains_key(&view_id) {
                    report.skipped_live_views += 1;
                    continue;
                }
            }
            let Ok(record) = read_lease_record(&path.join(LEASE_FILE_NAME)) else {
                if remove_view_dir_safely(&path)? {
                    report.removed_views += 1;
                }
                continue;
            };
            if record.expires_at_unix_ms <= now_unix_ms {
                if remove_view_dir_safely(&path)? {
                    report.removed_views += 1;
                    report.reclaimed_reserved_bytes =
                        report.reclaimed_reserved_bytes.saturating_add(record.reserved_bytes);
                }
            } else {
                report.skipped_live_views += 1;
            }
        }
        Ok(report)
    }
}

impl fmt::Debug for DisposableViewRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DisposableViewRoot").field("root", &"<redacted>").finish()
    }
}

/// RAII lease guarding one private temporary Git view directory. Fails closed
/// once its TTL deadline passes and deletes its directory on drop.
pub struct TempViewLease {
    registry: Arc<Mutex<ViewRegistry>>,
    view_id: Uuid,
    tenant_id: Uuid,
    authority_id: Uuid,
    reserved_bytes: u64,
    dir_path: PathBuf,
    repo_path: PathBuf,
    expires_at: Instant,
}

impl TempViewLease {
    pub fn view_id(&self) -> Uuid {
        self.view_id
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub fn authority_id(&self) -> Uuid {
        self.authority_id
    }

    pub fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Verify the lease is unexpired and its view directories retain strict
    /// private `0o700` non-symlink isolation.
    pub fn ensure_live(&self) -> Result<(), DisposableViewError> {
        if self.is_expired() {
            return Err(DisposableViewError::Expired);
        }
        verify_private_dir(&self.dir_path)?;
        verify_private_dir(&self.repo_path)?;
        Ok(())
    }

    pub fn dir_path(&self) -> Result<&Path, DisposableViewError> {
        self.ensure_live()?;
        Ok(&self.dir_path)
    }

    pub fn repo_path(&self) -> Result<&Path, DisposableViewError> {
        self.ensure_live()?;
        Ok(&self.repo_path)
    }

    /// Resolve a safe relative path strictly inside `repo.git` after verifying
    /// lease liveness and rejecting `..`, absolute segments, NUL bytes or symlinks.
    pub fn resolve_repo_relative_path(&self, rel: &Path) -> Result<PathBuf, DisposableViewError> {
        self.ensure_live()?;
        if rel.as_os_str().is_empty() || rel.is_absolute() {
            return Err(DisposableViewError::UnsafePath("view child path must be non-empty relative"));
        }
        let Some(raw) = rel.to_str() else {
            return Err(DisposableViewError::UnsafePath("view child path must be valid UTF-8"));
        };
        if raw.contains('\0') {
            return Err(DisposableViewError::UnsafePath("view child path contains NUL"));
        }
        let mut cursor = self.repo_path.clone();
        for component in rel.components() {
            match component {
                Component::Normal(part) => {
                    cursor.push(part);
                    if let Ok(meta) = std::fs::symlink_metadata(&cursor)
                        && meta.file_type().is_symlink()
                    {
                        return Err(DisposableViewError::UnsafePath("view child path crosses a symlink"));
                    }
                }
                _ => return Err(DisposableViewError::UnsafePath("view child path contains disallowed segment")),
            }
        }
        Ok(cursor)
    }

    /// Explicitly delete this view directory and release its reservation.
    pub fn reap(self) {
        drop(self);
    }
}

impl Drop for TempViewLease {
    fn drop(&mut self) {
        let _ = remove_view_dir_safely(&self.dir_path);
        let mut guard = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = guard.active_views.remove(&self.view_id) {
            guard.total_reserved_bytes = guard.total_reserved_bytes.saturating_sub(entry.reserved_bytes);
        }
    }
}

impl fmt::Debug for TempViewLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempViewLease")
            .field("view_id", &self.view_id)
            .field("reserved_bytes", &self.reserved_bytes)
            .field("expired", &self.is_expired())
            .finish()
    }
}
