//! Bounded off-thread execution and in-memory per-workspace mutation fencing.
//!
//! Foreground workspace routes must never execute full-tree walks, SHA-256
//! inventories, checkpoint copies, sparse file staging or FUSE control RPCs on
//! Tokio async worker threads, and must never spawn unbounded OS blocking
//! threads when storage slows down. This module provides two isolated bulkheads
//! plus an in-memory per-workspace mutation coordinator:
//!
//! * **Data I/O bulkhead** ([`run`]): gates `tokio::task::spawn_blocking` behind
//!   a bounded [`Semaphore`] (`ROOTYARD_WORKSPACE_IO_CONCURRENCY`, default 8).
//!   The [`OwnedSemaphorePermit`] travels inside the blocking closure, so a
//!   timed-out or disconnected caller never releases capacity before the kernel
//!   syscall actually returns.
//! * **Control bulkhead** ([`run_control`], [`spawn_observe`]): separate
//!   bounded [`Semaphore`] so FUSE mount, freeze and lease-observation RPCs
//!   stay responsive even when all Data I/O permits are saturated.
//! * **Per-workspace mutation coordinator** ([`lock_mutation`], [`begin_scan`]):
//!   serializes in-place API mutations (`files::put`, `files::git`) per
//!   workspace in memory without holding PostgreSQL transactions or row locks
//!   across filesystem or Git execution, and fences overlapping background
//!   capture scans via a refcounted monotonic generation counter.
use crate::{Error, observability::worker};
use axum::http::StatusCode;
use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::Duration,
};
use tokio::sync::{OwnedMutexGuard, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

const IO_CONCURRENCY_ENV: &str = "ROOTYARD_WORKSPACE_IO_CONCURRENCY";
const IO_ACQUIRE_TIMEOUT_ENV: &str = "ROOTYARD_WORKSPACE_IO_ACQUIRE_TIMEOUT_MS";
const IO_TIMEOUT_ENV: &str = "ROOTYARD_WORKSPACE_IO_TIMEOUT_MS";

const DEFAULT_IO_CONCURRENCY: usize = 8;
const CONTROL_CONCURRENCY: usize = 16;
const PUT_JOB_CAPACITY: usize = 32;
const DEFAULT_ACQUIRE_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_IO_TIMEOUT_MS: u64 = 120_000;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn io_concurrency() -> usize {
    std::env::var(IO_CONCURRENCY_ENV)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|count| (1..=64).contains(count))
        .unwrap_or(DEFAULT_IO_CONCURRENCY)
}

pub(super) fn acquire_timeout() -> Duration {
    Duration::from_millis(
        std::env::var(IO_ACQUIRE_TIMEOUT_ENV)
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|millis| (1..=300_000).contains(millis))
            .unwrap_or(DEFAULT_ACQUIRE_TIMEOUT_MS),
    )
}

pub(super) fn io_timeout() -> Duration {
    Duration::from_millis(
        std::env::var(IO_TIMEOUT_ENV)
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|millis| (1..=600_000).contains(millis))
            .unwrap_or(DEFAULT_IO_TIMEOUT_MS),
    )
}

fn io_slots() -> &'static Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(io_concurrency())))
}

fn control_slots() -> &'static Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(CONTROL_CONCURRENCY)))
}

fn put_slots() -> &'static Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(PUT_JOB_CAPACITY)))
}

/// Reserve one disconnect-safe `files::put` job admission slot before spawning
/// into the owned workspace job registry.
pub(super) fn try_put_slot() -> Result<OwnedSemaphorePermit, Error> {
    put_slots()
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "workspace write capacity exhausted; retry later"))
}

/// Execute blocking workspace filesystem work on Tokio's blocking pool gated by
/// the bounded Data I/O semaphore.
pub(super) async fn run<T, F>(work: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Error> + Send + 'static,
{
    run_on(io_slots(), acquire_timeout(), io_timeout(), work).await
}

/// Execute fast mount/lease control operations on the isolated control bulkhead
/// so saturated data copies never starve lease handoff or fencing.
pub(super) async fn run_control<T, F>(work: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Error> + Send + 'static,
{
    run_on(control_slots(), Duration::from_secs(10), Duration::from_secs(30), work).await
}

/// Best-effort bounded background lease observation for the FUSE helper. Never
/// spawns an unbounded OS thread when helper observations back up.
pub(super) fn spawn_observe<F>(work: F)
where
    F: FnOnce() + Send + 'static,
{
    let Ok(permit) = control_slots().clone().try_acquire_owned() else {
        return;
    };
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn_blocking(move || {
            let _permit = permit;
            let _ = catch_unwind(AssertUnwindSafe(work));
        });
    } else {
        let _permit = permit;
        let _ = catch_unwind(AssertUnwindSafe(work));
    }
}

async fn run_on<T, F>(
    semaphore: &Arc<Semaphore>,
    wait_limit: Duration,
    work_limit: Duration,
    work: F,
) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Error> + Send + 'static,
{
    let permit = match tokio::time::timeout(wait_limit, semaphore.clone().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => return Err(Error::internal("workspace I/O bulkhead closed")),
        Err(_) => {
            return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "workspace I/O capacity exhausted; retry later"));
        }
    };
    let operation = worker::blocking_scope();
    let mut handle = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        catch_unwind(AssertUnwindSafe(|| worker::blocking(operation, work)))
    });
    match tokio::time::timeout(work_limit, &mut handle).await {
        Ok(Ok(Ok(outcome))) => outcome,
        Ok(Ok(Err(_))) => Err(Error::internal("workspace I/O worker panicked")),
        Ok(Err(_)) => Err(Error::internal("workspace I/O worker cancelled")),
        Err(_) => Err(Error::timeout()),
    }
}

struct MutationEntry {
    mutex: Arc<tokio::sync::Mutex<()>>,
    refs: usize,
    active: bool,
    generation: u64,
}

fn mutations() -> &'static Mutex<HashMap<Uuid, MutationEntry>> {
    static MAP: OnceLock<Mutex<HashMap<Uuid, MutationEntry>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn release_ref(id: Uuid, end_mutation: bool) {
    let mut map = lock(mutations());
    let remove = if let Some(entry) = map.get_mut(&id) {
        if end_mutation {
            entry.active = false;
            entry.generation = entry.generation.wrapping_add(1);
        }
        entry.refs = entry.refs.saturating_sub(1);
        entry.refs == 0 && !entry.active
    } else {
        false
    };
    if remove {
        map.remove(&id);
    }
}

struct RefDecrement {
    id: Uuid,
    armed: bool,
}

impl Drop for RefDecrement {
    fn drop(&mut self) {
        if self.armed {
            release_ref(self.id, false);
        }
    }
}

/// Exclusive in-memory per-workspace mutation guard. Held across off-TX
/// filesystem/Git execution and the short commit TX so concurrent API writes on
/// the same workspace serialize cleanly without holding PostgreSQL row locks.
pub(super) struct MutationGuard {
    id: Uuid,
    _owned: OwnedMutexGuard<()>,
}

impl Drop for MutationGuard {
    fn drop(&mut self) {
        release_ref(self.id, true);
    }
}

pub(super) async fn lock_mutation(id: Uuid, timeout: Duration) -> Result<MutationGuard, Error> {
    let mutex = {
        let mut map = lock(mutations());
        let entry = map.entry(id).or_insert_with(|| MutationEntry {
            mutex: Arc::new(tokio::sync::Mutex::new(())),
            refs: 0,
            active: false,
            generation: 0,
        });
        entry.refs += 1;
        entry.mutex.clone()
    };
    let mut ref_guard = RefDecrement { id, armed: true };
    let owned = tokio::time::timeout(timeout, mutex.lock_owned()).await.map_err(|_| Error::timeout())?;
    {
        let mut map = lock(mutations());
        let entry = map.get_mut(&id).expect("workspace mutation entry retained by refcount");
        entry.active = true;
        entry.generation = entry.generation.wrapping_add(1);
    }
    ref_guard.armed = false;
    Ok(MutationGuard { id, _owned: owned })
}

/// Removes an uncommitted newly created directory if a failure or idempotent
/// race unwinds before the database `COMMIT` is sent.
pub(super) struct DirCleanupGuard {
    path: PathBuf,
    kept: bool,
}

impl DirCleanupGuard {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path, kept: false }
    }

    pub(super) fn keep(mut self) {
        self.kept = true;
    }

    pub(super) async fn cleanup(mut self) {
        if !self.kept {
            self.kept = true;
            super::cleanup::cleanup_paths_async(Some(self.path.clone()), None, false).await;
        }
    }
}

impl Drop for DirCleanupGuard {
    fn drop(&mut self) {
        if !self.kept {
            super::cleanup::cleanup_paths_on_drop(Some(self.path.clone()), None, false);
        }
    }
}

/// Observation token held by `capture::reconcile_one` while scanning `id`.
pub(super) struct ScanToken {
    id: Uuid,
    generation: u64,
}

impl ScanToken {
    /// Returns `true` iff no in-process API mutation is active or ran on `id`
    /// since this scan token was acquired.
    pub(super) fn is_unchanged(&self) -> bool {
        let map = lock(mutations());
        map.get(&self.id).is_some_and(|entry| !entry.active && entry.generation == self.generation)
    }
}

impl Drop for ScanToken {
    fn drop(&mut self) {
        release_ref(self.id, false);
    }
}

/// Acquire a scan observation token if no in-process API mutation currently
/// owns `id`. Returns `None` while a mutation is active so background capture
/// skips `id` and retries on the next fair round.
pub(super) fn begin_scan(id: Uuid) -> Option<ScanToken> {
    let mut map = lock(mutations());
    let entry = map.entry(id).or_insert_with(|| MutationEntry {
        mutex: Arc::new(tokio::sync::Mutex::new(())),
        refs: 0,
        active: false,
        generation: 0,
    });
    if entry.active {
        if entry.refs == 0 {
            map.remove(&id);
        }
        return None;
    }
    entry.refs += 1;
    let generation = entry.generation;
    Some(ScanToken { id, generation })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bulkhead_bounds_concurrency_and_retains_permit_across_caller_timeout() {
        let sem = Arc::new(Semaphore::new(2));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let sem = sem.clone();
            let active = active.clone();
            let peak = peak.clone();
            let started_tx = started_tx.clone();
            let release_rx = release_rx.clone();
            handles.push(tokio::spawn(async move {
                run_on(&sem, Duration::from_millis(200), Duration::from_millis(80), move || {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    started_tx.send(()).unwrap();
                    let _ = lock(&release_rx).recv();
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
            }));
        }
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();

        // Both caller futures time out, but the OS closures still hold both permits.
        for handle in handles {
            assert_eq!(handle.await.unwrap().unwrap_err().0, StatusCode::GATEWAY_TIMEOUT);
        }
        let third = run_on(&sem, Duration::from_millis(50), Duration::from_secs(1), || Ok(())).await;
        assert_eq!(third.unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);

        release_tx.send(()).unwrap();
        release_tx.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while sem.available_permits() < 2 {
            assert!(std::time::Instant::now() < deadline, "permits did not return after work unwound");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        run_on(&sem, Duration::from_secs(1), Duration::from_secs(1), || Ok(())).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_propagates_worker_scope_only() {
        let context = worker::OperationContext::new(worker::WorkerKind::WorkspaceCapture);
        let (caller, observed) = worker::run(&context, worker::Phase::Reconcile, async {
            let caller = worker::blocking_scope().expect("worker scope");
            let observed = run(|| Ok(worker::current())).await.expect("run ok");
            (caller, observed)
        })
        .await;
        let observed = observed.expect("worker scope on blocking thread");
        assert_eq!(observed.operation_id, caller.operation_id);
        assert!(run(|| Ok(worker::current())).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mutation_guard_invalidates_overlapping_scan_and_prunes_idle_entry() {
        let id = Uuid::new_v4();
        let scan = begin_scan(id).expect("idle workspace allows scan");
        assert!(scan.is_unchanged());

        let guard = lock_mutation(id, Duration::from_secs(1)).await.expect("mutation lock");
        assert!(begin_scan(id).is_none(), "active mutation blocks new scan");
        assert!(!scan.is_unchanged(), "active mutation invalidates in-flight scan");

        drop(guard);
        assert!(!scan.is_unchanged(), "completed mutation still invalidates overlapping scan");
        drop(scan);
        assert!(!lock(mutations()).contains_key(&id), "idle entry must be pruned");
    }
}
