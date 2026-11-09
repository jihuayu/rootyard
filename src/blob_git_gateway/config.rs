//! Validated configuration of the Blob-only Git gateway.
//!
//! The Root constructs the real OpenDAL store
//! (`BlobConfig::from_env` + `BlobStore::open`) and passes it together with the
//! PostgreSQL pool, one absolute trusted Git binary and one private scratch
//! root. This module performs only local validation: no IO besides metadata
//! checks, no ambient `PATH` lookup and no default that could silently widen a
//! bound.
use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use deadpool_postgres::Pool;

use crate::blob_store::opendal::BlobStore;

/// Small, reviewable limits used by the gateway.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobGitLimits {
    /// Whole Smart-HTTP request ceiling; also the received pack ceiling.
    pub max_request_bytes: u64,
    /// Advertised/upload-pack response stream ceiling.
    pub max_response_bytes: u64,
    /// Admission ceiling for every concurrent inbound request body.
    pub max_inflight_bytes: u64,
}

/// Per-child OS limits and process-wide native/workspace ceilings.
///
/// These are applied inside the child's `pre_exec` hook (CPU, address space,
/// file size, descriptor count) and to the gateway's own global admission
/// (native process groups and captured temporary workspace). They are *not* a
/// cgroup and do not claim to bound total process RSS: a child may allocate up
/// to `address_space_bytes`, and the kernel enforces that per-process limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobGitNativeLimits {
    /// `RLIMIT_CPU` soft/hard seconds for one native child.
    pub cpu_seconds: u64,
    /// `RLIMIT_AS` address-space bytes for one native child.
    pub address_space_bytes: u64,
    /// `RLIMIT_FSIZE` maximum bytes of one file written by a native child.
    pub max_file_bytes: u64,
    /// `RLIMIT_NOFILE` open descriptor ceiling for one native child.
    pub max_open_files: u64,
    /// Process-wide captured temporary/workspace byte budget.
    pub max_workspace_bytes: u64,
    /// Process-wide bound on concurrent native process groups/views.
    pub max_native_processes: usize,
}

impl Default for BlobGitNativeLimits {
    fn default() -> Self {
        Self {
            cpu_seconds: DEFAULT_NATIVE_CPU_SECONDS,
            address_space_bytes: DEFAULT_NATIVE_ADDRESS_SPACE_BYTES,
            max_file_bytes: DEFAULT_NATIVE_MAX_FILE_BYTES,
            max_open_files: DEFAULT_NATIVE_MAX_OPEN_FILES,
            max_workspace_bytes: DEFAULT_NATIVE_MAX_WORKSPACE_BYTES,
            max_native_processes: DEFAULT_NATIVE_MAX_PROCESSES,
        }
    }
}

/// Inputs and bounds of one gateway instance.
#[derive(Clone)]
pub struct BlobGitConfig {
    pub pool: Pool,
    pub store: BlobStore,
    pub git_binary: PathBuf,
    pub scratch_root: PathBuf,
    pub max_concurrent_requests: usize,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_inflight_bytes: u64,
    pub operation_deadline: Duration,
    /// OS and process-wide native limits. Use `Default::default()` for the
    /// reviewed defaults; Root may override individual fields.
    pub native_limits: BlobGitNativeLimits,
}

/// Fixed validation refusal; never carries the offending path or value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobGitConfigError(pub &'static str);

impl fmt::Display for BlobGitConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for BlobGitConfigError {}

pub(super) const MIN_BOUND_BYTES: u64 = 64 * 1024;
pub(super) const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub(super) const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub(super) const MAX_INFLIGHT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(super) const MIN_DEADLINE: Duration = Duration::from_secs(5);
pub(super) const MAX_DEADLINE: Duration = Duration::from_secs(900);

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// Reviewed native defaults. CPU/memory/file/descriptor limits are per child;
/// workspace and process-group budgets are global to one gateway instance.
pub const DEFAULT_NATIVE_CPU_SECONDS: u64 = 300;
pub const DEFAULT_NATIVE_ADDRESS_SPACE_BYTES: u64 = 2 * GIB;
pub const DEFAULT_NATIVE_MAX_FILE_BYTES: u64 = 8 * GIB;
pub const DEFAULT_NATIVE_MAX_OPEN_FILES: u64 = 256;
pub const DEFAULT_NATIVE_MAX_WORKSPACE_BYTES: u64 = 8 * GIB;
pub const DEFAULT_NATIVE_MAX_PROCESSES: usize = 16;

const MIN_NATIVE_CPU_SECONDS: u64 = 1;
const MAX_NATIVE_CPU_SECONDS: u64 = 3600;
const MIN_NATIVE_ADDRESS_SPACE_BYTES: u64 = 64 * MIB;
const MAX_NATIVE_ADDRESS_SPACE_BYTES: u64 = 64 * GIB;
const MIN_NATIVE_MAX_OPEN_FILES: u64 = 32;
const MAX_NATIVE_MAX_OPEN_FILES: u64 = 4096;
const MAX_NATIVE_MAX_FILE_BYTES: u64 = 256 * GIB;
const MAX_NATIVE_MAX_WORKSPACE_BYTES: u64 = 512 * GIB;
const MAX_NATIVE_MAX_PROCESSES: usize = 256;

/// Canonical, private scratch root. A non-directory, a relative path, `/` or a
/// symlinked escape is refused; the gateway later creates per-request
/// subdirectories with `create_dir` (never by following an existing entry).
pub(super) fn canonical_scratch(root: &Path) -> Result<PathBuf, BlobGitConfigError> {
    if !root.is_absolute() {
        return Err(BlobGitConfigError("scratch root must be an absolute path"));
    }
    let canonical = std::fs::canonicalize(root).map_err(|_| BlobGitConfigError("scratch root is not accessible"))?;
    if !canonical.is_dir() || canonical.parent().is_none() {
        return Err(BlobGitConfigError("scratch root must be an existing non-root directory"));
    }
    Ok(canonical)
}

/// The trusted Git binary is absolute, a regular file and executable by the
/// owner. It is never resolved through `PATH`.
pub(super) fn validate_git_binary(path: &Path) -> Result<(), BlobGitConfigError> {
    if !path.is_absolute() {
        return Err(BlobGitConfigError("git binary must be an absolute path"));
    }
    let metadata = path.metadata().map_err(|_| BlobGitConfigError("git binary is not accessible"))?;
    if !metadata.is_file() {
        return Err(BlobGitConfigError("git binary must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o100 == 0 {
            return Err(BlobGitConfigError("git binary is not executable by its owner"));
        }
    }
    Ok(())
}

impl BlobGitNativeLimits {
    /// Validate every native bound against fixed reviewable ranges.
    pub(super) fn validate(self, max_request_bytes: u64) -> Result<(), BlobGitConfigError> {
        if !(MIN_NATIVE_CPU_SECONDS..=MAX_NATIVE_CPU_SECONDS).contains(&self.cpu_seconds) {
            return Err(BlobGitConfigError("native cpu_seconds is outside its fixed bound"));
        }
        if !(MIN_NATIVE_ADDRESS_SPACE_BYTES..=MAX_NATIVE_ADDRESS_SPACE_BYTES).contains(&self.address_space_bytes) {
            return Err(BlobGitConfigError("native address_space_bytes is outside its fixed bound"));
        }
        if self.max_file_bytes < max_request_bytes.max(MIN_BOUND_BYTES)
            || self.max_file_bytes > MAX_NATIVE_MAX_FILE_BYTES
        {
            return Err(BlobGitConfigError("native max_file_bytes must cover one request and stay bounded"));
        }
        if !(MIN_NATIVE_MAX_OPEN_FILES..=MAX_NATIVE_MAX_OPEN_FILES).contains(&self.max_open_files) {
            return Err(BlobGitConfigError("native max_open_files is outside its fixed bound"));
        }
        // A gzip request is streamed through the decoder, so the staged output is
        // the expanded payload. Two requests' worth still leaves headroom for a
        // bounded materialized view; never allow a budget smaller than one
        // request plus its decoded ceiling.
        let minimum_workspace = max_request_bytes.saturating_mul(3);
        if self.max_workspace_bytes < minimum_workspace || self.max_workspace_bytes > MAX_NATIVE_MAX_WORKSPACE_BYTES {
            return Err(BlobGitConfigError(
                "native max_workspace_bytes must cover spool and computed view and stay bounded",
            ));
        }
        if !(1..=MAX_NATIVE_MAX_PROCESSES).contains(&self.max_native_processes) {
            return Err(BlobGitConfigError("native max_native_processes must be 1..=256"));
        }
        Ok(())
    }
}

impl BlobGitConfig {
    /// Validate every static bound once at startup. Per-request checks still
    /// re-read the limits from the immutable state.
    pub(super) fn validate(&self) -> Result<(PathBuf, BlobGitLimits, BlobGitNativeLimits), BlobGitConfigError> {
        // Group teardown must distinguish a reserved zombie leader from live
        // descendants. The Linux runtime requires procfs for that proof; fail
        // at startup rather than pretend kill(pgid, 0) proves quiescence.
        std::fs::read_dir("/proc")
            .and_then(|_| std::fs::read_to_string("/proc/self/stat"))
            .map_err(|_| BlobGitConfigError("native Git requires readable Linux procfs"))?;
        if !(1..=256).contains(&self.max_concurrent_requests) {
            return Err(BlobGitConfigError("max_concurrent_requests must be 1..=256"));
        }
        if !(MIN_BOUND_BYTES..=MAX_REQUEST_BYTES).contains(&self.max_request_bytes) {
            return Err(BlobGitConfigError("max_request_bytes is outside its fixed bound"));
        }
        if !(MIN_BOUND_BYTES..=MAX_RESPONSE_BYTES).contains(&self.max_response_bytes) {
            return Err(BlobGitConfigError("max_response_bytes is outside its fixed bound"));
        }
        if self.max_inflight_bytes < self.max_request_bytes || self.max_inflight_bytes > MAX_INFLIGHT_BYTES {
            return Err(BlobGitConfigError("max_inflight_bytes must cover one request and stay bounded"));
        }
        if !(MIN_DEADLINE..=MAX_DEADLINE).contains(&self.operation_deadline) {
            return Err(BlobGitConfigError("operation_deadline is outside its fixed bound"));
        }
        self.native_limits.validate(self.max_request_bytes)?;
        validate_git_binary(&self.git_binary)?;
        let scratch = canonical_scratch(&self.scratch_root)?;
        if self.store.backend_identity().as_hex().len() != 64 {
            return Err(BlobGitConfigError("Blob store has no canonical physical backend identity"));
        }
        Ok((
            scratch,
            BlobGitLimits {
                max_request_bytes: self.max_request_bytes,
                max_response_bytes: self.max_response_bytes,
                max_inflight_bytes: self.max_inflight_bytes,
            },
            self.native_limits,
        ))
    }
}

impl fmt::Debug for BlobGitConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlobGitConfig")
            .field("git_binary", &self.git_binary)
            .field("scratch_root", &self.scratch_root)
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_inflight_bytes", &self.max_inflight_bytes)
            .field("operation_deadline", &self.operation_deadline)
            .field("native_limits", &self.native_limits)
            .field("store", &self.store.backend_identity())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_native_defaults_validate() {
        let limits = BlobGitNativeLimits::default();
        limits.validate(128 * MIB).expect("reviewed defaults must validate");
        assert_eq!(limits.max_native_processes, DEFAULT_NATIVE_MAX_PROCESSES);
        assert!(limits.max_workspace_bytes >= 256 * MIB);
    }

    #[test]
    fn native_limits_refuse_unbounded_or_undersized_values() {
        let limits = BlobGitNativeLimits { cpu_seconds: 0, ..Default::default() };
        assert!(limits.validate(128 * MIB).is_err());

        let limits = BlobGitNativeLimits { address_space_bytes: u64::MAX, ..Default::default() };
        assert!(limits.validate(128 * MIB).is_err());

        let limits = BlobGitNativeLimits { max_file_bytes: 1024, ..Default::default() };
        assert!(limits.validate(128 * MIB).is_err());

        let limits = BlobGitNativeLimits { max_open_files: 1, ..Default::default() };
        assert!(limits.validate(128 * MIB).is_err());

        let limits = BlobGitNativeLimits { max_workspace_bytes: 1024, ..Default::default() };
        assert!(limits.validate(128 * MIB).is_err());

        let limits = BlobGitNativeLimits { max_native_processes: 0, ..Default::default() };
        assert!(limits.validate(128 * MIB).is_err());
    }
}
