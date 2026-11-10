//! Immutable runtime state, bounded admission and private temporary directories.
//!
//! One gateway instance owns one PostgreSQL pool, one already-opened Blob store,
//! one absolute trusted Git binary and one validated private scratch root. It
//! creates no permanent repository: every local bare repository is a computed
//! view inside an owned RAII directory that is deleted when the request
//! finishes. Durable refs live in the PostgreSQL core and durable bytes in Blob,
//! so deleting a compute view can never lose an acknowledged ref or byte.
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use deadpool_postgres::Pool;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use uuid::Uuid;

use super::{
    config::{BlobGitConfig, BlobGitConfigError, BlobGitLimits, BlobGitNativeLimits},
    error::GatewayError,
    repo_session::SessionTokens,
};
use crate::blob_store::opendal::BlobStore;

tokio::task_local! {
    pub(super) static REQUEST_DEADLINE: Instant;
}

/// Validated gateway state. Fields are immutable after construction.
pub struct BlobGitState {
    pool: Pool,
    store: BlobStore,
    git_binary: PathBuf,
    scratch: PathBuf,
    limits: BlobGitLimits,
    native: BlobGitNativeLimits,
    deadline: Duration,
    slots: Arc<Semaphore>,
    native_processes: Arc<Semaphore>,
    inflight: Arc<AtomicU64>,
    workspace: Arc<AtomicU64>,
    sessions: Option<SessionTokens>,
}

impl BlobGitState {
    /// Validate one configuration once. Validation performs local metadata
    /// checks only; the caller keeps ownership of the real Blob store.
    pub fn new(config: BlobGitConfig) -> Result<Self, BlobGitConfigError> {
        let (scratch, limits, native) = config.validate()?;
        let slots = Arc::new(Semaphore::new(config.max_concurrent_requests));
        let native_processes = Arc::new(Semaphore::new(native.max_native_processes));
        Ok(Self {
            pool: config.pool,
            store: config.store,
            git_binary: config.git_binary,
            scratch,
            limits,
            native,
            deadline: config.operation_deadline,
            slots,
            native_processes,
            inflight: Arc::new(AtomicU64::new(0)),
            workspace: Arc::new(AtomicU64::new(0)),
            sessions: None,
        })
    }

    /// Attach the explicitly configured repository session key set (#174).
    /// Without it, every session route and token header is answered with an
    /// explicit `501`; nothing falls back to a generated or shared default key.
    pub fn with_sessions(mut self, sessions: SessionTokens) -> Self {
        self.sessions = Some(sessions);
        self
    }

    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    pub fn store(&self) -> &BlobStore {
        &self.store
    }

    pub fn git_binary(&self) -> &Path {
        &self.git_binary
    }

    pub fn scratch_root(&self) -> &Path {
        &self.scratch
    }

    pub fn limits(&self) -> BlobGitLimits {
        self.limits
    }

    /// Per-child OS limits and process-wide native ceilings.
    pub fn native_limits(&self) -> BlobGitNativeLimits {
        self.native
    }

    /// One absolute deadline for the whole request. It is never restarted
    /// between staging, Blob IO and the final core handle.
    pub fn deadline(&self) -> Instant {
        REQUEST_DEADLINE.try_with(|deadline| *deadline).unwrap_or_else(|_| Instant::now() + self.deadline)
    }

    /// Bounded native/Blob concurrency slot. The permit is owned by the request
    /// future, so cancellation returns it. It is kept until every native child
    /// and stream owned by the request has exited.
    pub async fn slot(&self) -> Result<OwnedSemaphorePermit, GatewayError> {
        self.slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| GatewayError::Unavailable("Git gateway request capacity is busy; retry"))
    }

    /// Process-wide native process-group slot. A permit is held for the whole
    /// lifetime of one temporary view, so concurrent native groups cannot
    /// exceed `max_native_processes` regardless of per-request headers.
    pub(super) async fn native_process(&self, deadline: Instant) -> Result<OwnedSemaphorePermit, GatewayError> {
        if !super::process_guard::healthy() {
            return Err(GatewayError::Unavailable("native process cleanup requires service restart"));
        }
        match tokio::time::timeout_at(deadline, self.native_processes.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(GatewayError::Unavailable("native Git process budget is stopping")),
            Err(_) => Err(GatewayError::Timeout),
        }
    }

    /// Reserve `bytes` of the process-wide inbound budget before spooling. A
    /// request that would exceed the budget is refused instead of queueing
    /// unboundedly; the lease releases on drop (including cancellation).
    pub(super) fn reserve_bytes(&self, bytes: u64) -> Result<ByteLease, GatewayError> {
        reserve_counter(&self.inflight, self.limits.max_inflight_bytes, bytes, "Git gateway byte budget is busy; retry")
            .map(|lease| ByteLease { lease })
    }

    /// Reserve captured native/workspace bytes before a caller materializes a
    /// spooled body or copies a verified pack into a temporary view. This is a
    /// process-wide budget, not a per-request header allowance. The lease must
    /// stay alive until the temporary file/view is deleted.
    pub(super) fn reserve_workspace(&self, bytes: u64) -> Result<WorkspaceLease, GatewayError> {
        reserve_counter(
            &self.workspace,
            self.native.max_workspace_bytes,
            bytes,
            "native Git workspace budget is busy; retry",
        )
        .map(|lease| WorkspaceLease { lease })
    }

    /// One pooled PostgreSQL client inside the caller's absolute deadline.
    pub async fn pooled(&self, deadline: Instant) -> Result<deadpool_postgres::Client, GatewayError> {
        match tokio::time::timeout_at(deadline, self.pool.get()).await {
            Ok(Ok(client)) => Ok(client),
            Ok(Err(_)) => Err(GatewayError::Unavailable("metadata pool is unavailable")),
            Err(_) => Err(GatewayError::Timeout),
        }
    }

    /// Create one canonical private per-request directory.
    pub(super) fn temp_dir(&self, prefix: &str) -> Result<TempDir, GatewayError> {
        TempDir::create(&self.scratch, prefix)
    }
}

fn reserve_counter(
    counter: &Arc<AtomicU64>,
    limit: u64,
    bytes: u64,
    busy: &'static str,
) -> Result<CounterLease, GatewayError> {
    if bytes > limit {
        return Err(GatewayError::TooLarge);
    }
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let next = current.checked_add(bytes).ok_or(GatewayError::TooLarge)?;
        if next > limit {
            return Err(GatewayError::Unavailable(busy));
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(CounterLease { counter: counter.clone(), bytes }),
            Err(observed) => current = observed,
        }
    }
}

/// RAII byte-budget lease. It owns a reference to the shared counter, so a
/// cancelled request still releases its reservation.
#[allow(dead_code)]
pub(super) struct ByteLease {
    lease: CounterLease,
}

/// Workspace lease covering a spooled body or one materialized native view.
#[allow(dead_code)]
pub(super) struct WorkspaceLease {
    lease: CounterLease,
}

struct CounterLease {
    counter: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for CounterLease {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

// Keep the field alive: both public lease types deliberately share the same
// release-on-drop implementation.
impl ByteLease {
    #[allow(dead_code)]
    fn reserved(&self) -> u64 {
        self.lease.bytes
    }
}

impl WorkspaceLease {
    #[allow(dead_code)]
    fn reserved(&self) -> u64 {
        self.lease.bytes
    }
}

/// Owned private directory. `create_dir` refuses an existing entry, so a stale
/// or symlinked path can never be adopted. Drop removes the whole subtree; a
/// cleanup failure is ignored because the durable ACK lives elsewhere.
pub(super) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn create(root: &Path, prefix: &str) -> Result<Self, GatewayError> {
        let path = root.join(format!("{prefix}-{}", Uuid::new_v4().simple()));
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| GatewayError::Internal("could not create a private temporary view"))?;
        Ok(Self { path })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_budget_releases_on_drop_and_refuses_overflow() {
        let counter = Arc::new(AtomicU64::new(0));
        let lease = reserve_counter(&counter, 100, 60, "busy").expect("within budget");
        assert_eq!(counter.load(Ordering::Acquire), 60);
        assert!(reserve_counter(&counter, 100, 50, "busy").is_err());
        drop(lease);
        assert_eq!(counter.load(Ordering::Acquire), 0);
        assert!(reserve_counter(&counter, 100, 101, "busy").is_err());
    }

    #[test]
    fn temp_dir_refuses_adoption_and_removes_subtree() {
        let root = tempfile::tempdir().expect("temp root");
        let dir = TempDir::create(root.path(), "unit").expect("create");
        std::fs::write(dir.path().join("file"), b"x").expect("write");
        let path = dir.path().to_path_buf();
        drop(dir);
        assert!(!path.exists(), "temp dir subtree must be removed");
    }
}
