//! Error types and canonical identity/digest validators for the disposable
//! Rubicon compute replica cache (Issue #163).

use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
    sync::{Mutex, OnceLock},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::{BlobError, disposable_view::DisposableViewError, envelope::EnvelopeError};

use super::types::{PackObjectSpec, ReplicaObjectFormat, ReplicaRefSpec};

#[derive(Debug)]
pub enum ReplicaCacheError {
    InvalidConfig(&'static str),
    InvalidInput(String),
    Unauthorized(&'static str),
    RepositoryNotFound,
    TenantIsolationViolation(&'static str),
    BackendIdentityMismatch,
    SessionRealmMismatch(&'static str),
    BehindSessionLowerBound { required: i64, observed: i64 },
    QueueFull(&'static str),
    WaitTimeout,
    CacheCapacityExhausted(&'static str),
    AllReplicasOverloaded,
    ReplicaDraining,
    ReplicaUnhealthy(String),
    Blob(BlobError),
    Envelope(EnvelopeError),
    DisposableView(DisposableViewError),
    IntegrityFailed(&'static str),
    GitFailed { command: &'static str, detail: String },
    DeadlineExceeded,
    Io(String),
}

impl fmt::Display for ReplicaCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid replica cache config: {msg}"),
            Self::InvalidInput(msg) => write!(f, "invalid replica cache input: {msg}"),
            Self::Unauthorized(msg) => write!(f, "unauthorized replica cache access: {msg}"),
            Self::RepositoryNotFound => f.write_str("repository not found"),
            Self::TenantIsolationViolation(msg) => write!(f, "tenant isolation violation: {msg}"),
            Self::BackendIdentityMismatch => f.write_str("blob backend identity mismatch"),
            Self::SessionRealmMismatch(msg) => write!(f, "session realm mismatch: {msg}"),
            Self::BehindSessionLowerBound { required, observed } => {
                write!(f, "authoritative revision {observed} is behind session lower bound {required}")
            }
            Self::QueueFull(msg) => write!(f, "replica cache queue full: {msg}"),
            Self::WaitTimeout => f.write_str("replica cache singleflight wait timed out"),
            Self::CacheCapacityExhausted(msg) => write!(f, "replica cache capacity exhausted: {msg}"),
            Self::AllReplicasOverloaded => f.write_str("all compute replicas are overloaded or unavailable"),
            Self::ReplicaDraining => f.write_str("compute replica is draining"),
            Self::ReplicaUnhealthy(msg) => write!(f, "compute replica unhealthy: {msg}"),
            Self::Blob(err) => write!(f, "{err}"),
            Self::Envelope(err) => write!(f, "{err}"),
            Self::DisposableView(err) => write!(f, "{err}"),
            Self::IntegrityFailed(msg) => write!(f, "replica cache integrity check failed: {msg}"),
            Self::GitFailed { command, detail } => write!(f, "git `{command}` failed: {detail}"),
            Self::DeadlineExceeded => f.write_str("replica cache deadline exceeded"),
            Self::Io(msg) => write!(f, "replica cache IO error: {msg}"),
        }
    }
}

impl std::error::Error for ReplicaCacheError {}

impl From<BlobError> for ReplicaCacheError {
    fn from(value: BlobError) -> Self {
        Self::Blob(value)
    }
}

impl From<EnvelopeError> for ReplicaCacheError {
    fn from(value: EnvelopeError) -> Self {
        Self::Envelope(value)
    }
}

impl From<DisposableViewError> for ReplicaCacheError {
    fn from(value: DisposableViewError) -> Self {
        Self::DisposableView(value)
    }
}

pub fn is_retryable_failover_error(err: &ReplicaCacheError) -> bool {
    matches!(
        err,
        ReplicaCacheError::QueueFull(_)
            | ReplicaCacheError::WaitTimeout
            | ReplicaCacheError::CacheCapacityExhausted(_)
            | ReplicaCacheError::ReplicaDraining
            | ReplicaCacheError::ReplicaUnhealthy(_)
    )
}

pub fn is_lower_hex_exact(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn validate_pack_stem(stem: &str, format: ReplicaObjectFormat) -> Result<(), ReplicaCacheError> {
    let Some(oid) = stem.strip_prefix("pack-") else {
        return Err(ReplicaCacheError::InvalidInput("pack_stem must begin with `pack-`".into()));
    };
    if !is_lower_hex_exact(oid, format.oid_hex_len()) {
        return Err(ReplicaCacheError::InvalidInput("pack_stem OID does not match object_format".into()));
    }
    Ok(())
}

pub fn validate_ref_name_and_oid(name: &str, oid: &str, format: ReplicaObjectFormat) -> Result<(), ReplicaCacheError> {
    if !name.starts_with("refs/") || name.contains("..") || name.contains('\0') || name.ends_with('/') {
        return Err(ReplicaCacheError::InvalidInput("ref name must be canonical `refs/...`".into()));
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.')) {
        return Err(ReplicaCacheError::InvalidInput("ref name contains disallowed characters".into()));
    }
    if !is_lower_hex_exact(oid, format.oid_hex_len()) {
        return Err(ReplicaCacheError::InvalidInput("ref OID does not match object_format".into()));
    }
    Ok(())
}

pub fn compute_membership_digests(
    tenant_id: Uuid,
    repo_id: Uuid,
    format: ReplicaObjectFormat,
    packs: &[PackObjectSpec],
    refs: &[ReplicaRefSpec],
    head_ref: &str,
) -> Result<(String, String, String), ReplicaCacheError> {
    if !head_ref.starts_with("refs/heads/") || head_ref.contains("..") || head_ref.contains('\0') {
        return Err(ReplicaCacheError::InvalidInput("head_ref must be canonical `refs/heads/...`".into()));
    }
    let mut sorted_packs: Vec<&PackObjectSpec> = packs.iter().collect();
    for p in &sorted_packs {
        p.validate(tenant_id, repo_id, format)?;
    }
    sorted_packs.sort_by(|a, b| {
        (&a.pack_stem, a.pack_locator.sha256(), a.idx_locator.sha256()).cmp(&(
            &b.pack_stem,
            b.pack_locator.sha256(),
            b.idx_locator.sha256(),
        ))
    });
    let mut seen_stems = BTreeSet::new();
    let mut pack_buf = String::new();
    for p in &sorted_packs {
        if !seen_stems.insert(p.pack_stem.as_str()) {
            return Err(ReplicaCacheError::InvalidInput("duplicate pack_stem in snapshot".into()));
        }
        push_field(&mut pack_buf, "stem", &p.pack_stem);
        push_field(&mut pack_buf, "pack_sha", p.pack_locator.sha256());
        push_field(&mut pack_buf, "pack_len", &p.pack_locator.length().to_string());
        push_field(&mut pack_buf, "idx_sha", p.idx_locator.sha256());
        push_field(&mut pack_buf, "idx_len", &p.idx_locator.length().to_string());
    }
    let pack_digest = hex::encode(Sha256::digest(pack_buf.as_bytes()));

    let mut sorted_refs: Vec<&ReplicaRefSpec> = refs.iter().collect();
    for r in &sorted_refs {
        validate_ref_name_and_oid(&r.name, &r.oid, format)?;
    }
    sorted_refs.sort_by(|a, b| a.name.cmp(&b.name));
    let mut seen_refs = BTreeSet::new();
    let mut ref_buf = String::new();
    push_field(&mut ref_buf, "head", head_ref);
    for r in &sorted_refs {
        if !seen_refs.insert(r.name.as_str()) {
            return Err(ReplicaCacheError::InvalidInput("duplicate ref name in snapshot".into()));
        }
        push_field(&mut ref_buf, &r.name, &r.oid);
    }
    let refs_digest = hex::encode(Sha256::digest(ref_buf.as_bytes()));

    let mut total_buf = String::new();
    push_field(&mut total_buf, "packs", &pack_digest);
    push_field(&mut total_buf, "refs", &refs_digest);
    let membership_digest = hex::encode(Sha256::digest(total_buf.as_bytes()));
    Ok((pack_digest, refs_digest, membership_digest))
}

pub(super) fn push_field(buf: &mut String, name: &str, val: &str) {
    buf.push_str(name);
    buf.push('=');
    buf.push_str(&val.len().to_string());
    buf.push(':');
    buf.push_str(val);
    buf.push('\n');
}

pub fn validate_canonical_child_path(root: &Path, child: &Path) -> Result<PathBuf, ReplicaCacheError> {
    let canon_root = std::fs::canonicalize(root)
        .map_err(|e| ReplicaCacheError::Io(format!("failed canonicalizing cache root: {e}")))?;
    let rel = child
        .strip_prefix(root)
        .map_err(|_| ReplicaCacheError::TenantIsolationViolation("cache path escapes pack cache root"))?;
    if rel.as_os_str().is_empty() {
        return Err(ReplicaCacheError::TenantIsolationViolation("cache child path must not equal root"));
    }
    for comp in rel.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_string_lossy();
                if s.is_empty() || s == "." || s == ".." || s.contains('/') || s.contains('\\') {
                    return Err(ReplicaCacheError::TenantIsolationViolation("invalid cache path segment"));
                }
            }
            _ => return Err(ReplicaCacheError::TenantIsolationViolation("non-normal cache path component")),
        }
    }
    if let Ok(meta) = std::fs::symlink_metadata(child) {
        if meta.file_type().is_symlink() {
            return Err(ReplicaCacheError::IntegrityFailed("cache path must not be a symlink"));
        }
        let canon_child = std::fs::canonicalize(child)
            .map_err(|e| ReplicaCacheError::Io(format!("failed canonicalizing cache child: {e}")))?;
        if !canon_child.starts_with(&canon_root) {
            return Err(ReplicaCacheError::TenantIsolationViolation("canonical cache path escapes root"));
        }
    } else if let Some(parent) = child.parent()
        && parent.exists()
    {
        let canon_parent = std::fs::canonicalize(parent)
            .map_err(|e| ReplicaCacheError::Io(format!("failed canonicalizing cache parent: {e}")))?;
        if !canon_parent.starts_with(&canon_root) {
            return Err(ReplicaCacheError::TenantIsolationViolation("canonical parent escapes root"));
        }
    }
    Ok(canon_root.join(rel))
}

pub const CATALOG_LOCK_FILE: &str = ".catalog.lock";

static ACTIVE_PACK_ROOTS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

fn active_pack_roots() -> &'static Mutex<HashSet<PathBuf>> {
    ACTIVE_PACK_ROOTS.get_or_init(|| Mutex::new(HashSet::new()))
}

struct InProcessRootClaim {
    root_dir: PathBuf,
}

impl Drop for InProcessRootClaim {
    fn drop(&mut self) {
        let mut active = active_pack_roots().lock().unwrap_or_else(|p| p.into_inner());
        active.remove(&self.root_dir);
    }
}

pub struct PackRootLockGuard {
    file: File,
    _in_proc: InProcessRootClaim,
}

impl PackRootLockGuard {
    pub fn acquire(root_dir: &Path) -> Result<Self, ReplicaCacheError> {
        let canon_root = std::fs::canonicalize(root_dir)
            .map_err(|e| ReplicaCacheError::Io(format!("failed canonicalizing pack lock root: {e}")))?;
        let claim = {
            let mut active = active_pack_roots().lock().unwrap_or_else(|p| p.into_inner());
            if !active.insert(canon_root.clone()) {
                return Err(ReplicaCacheError::Io(format!(
                    "pack cache root is already owned in-process: {}",
                    canon_root.display()
                )));
            }
            InProcessRootClaim { root_dir: canon_root.clone() }
        };
        let lock_path = validate_canonical_child_path(&canon_root, &canon_root.join(CATALOG_LOCK_FILE))?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|e| ReplicaCacheError::Io(format!("failed opening pack catalog lock: {e}")))?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|e| {
            ReplicaCacheError::Io(format!("pack cache root {} is exclusively locked: {e}", canon_root.display()))
        })?;
        Ok(Self { file, _in_proc: claim })
    }
}

impl Drop for PackRootLockGuard {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub fn sweep_orphan_cache_dirs(root: &Path) -> Result<u64, ReplicaCacheError> {
    let entries = std::fs::read_dir(root)
        .map_err(|e| ReplicaCacheError::Io(format!("failed reading cache root during reconcile: {e}")))?;
    let mut swept = 0u64;
    for entry in entries {
        let entry = entry.map_err(|e| ReplicaCacheError::Io(format!("failed reading cache entry: {e}")))?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| ReplicaCacheError::Io(format!("failed inspecting cache entry: {e}")))?;
        if entry.file_name() == CATALOG_LOCK_FILE {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(ReplicaCacheError::IntegrityFailed("catalog lock file must remain a regular file"));
            }
            continue;
        }
        if meta.file_type().is_symlink() {
            std::fs::remove_file(&path)
                .map_err(|e| ReplicaCacheError::Io(format!("failed removing orphan symlink: {e}")))?;
            swept = swept.saturating_add(1);
            continue;
        }
        let safe_path = validate_canonical_child_path(root, &path)?;
        if meta.is_dir() {
            std::fs::remove_dir_all(&safe_path)
                .map_err(|e| ReplicaCacheError::Io(format!("failed sweeping orphan cache dir: {e}")))?;
        } else {
            std::fs::remove_file(&safe_path)
                .map_err(|e| ReplicaCacheError::Io(format!("failed sweeping orphan cache file: {e}")))?;
        }
        swept = swept.saturating_add(1);
    }
    Ok(swept)
}
