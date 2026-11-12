//! Bounded off-thread execution and in-memory per-workspace mutation fencing.
//!
//! * **Data I/O bulkhead** ([`run`], [`run_mutating`]): gates `spawn_blocking`
//!   behind a bounded [`Semaphore`] (`ROOTYARD_WORKSPACE_IO_CONCURRENCY`,
//!   default 8) with the permit and any mutation [`ScanToken`] retained inside
//!   the OS closure until syscalls return.
//! * **Cleanup bulkhead** ([`run_cleanup`]): non-rejecting [`Semaphore`] for
//!   pre-`COMMIT` rollbacks, directory/file cleanup, and freeze completion.
//! * **Control bulkhead** ([`run_control`], [`acquire_control_permit`],
//!   [`spawn_observe`]): isolated [`Semaphore`] for FUSE control RPCs.
//! * **Mutation coordinator** ([`lock_mutation`], [`begin_scan`]): serializes
//!   per-workspace mutations in memory and drains in-flight [`ScanToken`]s.
use crate::{Error, observability::worker};
use axum::http::StatusCode;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[path = "blocking_coordinator.rs"]
mod coordinator;

pub(super) use self::coordinator::{DirCleanupGuard, MutationGuard, ScanToken, begin_scan, lock_mutation};

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

pub(super) fn io_slots() -> &'static Arc<Semaphore> {
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

/// Acquire a control-bulkhead permit with bounded admission wait so FUSE freeze
/// callers can decouple admission from unbounded Phase 3 commit lifetimes.
pub(super) async fn acquire_control_permit() -> Result<OwnedSemaphorePermit, Error> {
    match tokio::time::timeout(Duration::from_secs(10), control_slots().clone().acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) => Err(Error::internal("workspace control bulkhead closed")),
        Err(_) => Err(Error(StatusCode::SERVICE_UNAVAILABLE, "workspace control capacity exhausted; retry later")),
    }
}

/// Signals to a `spawn_blocking` worker that the async caller timed out or was
/// dropped before receiving the closure's return value.
#[derive(Clone)]
pub(super) struct AbandonToken {
    flag: Arc<AtomicBool>,
}

impl AbandonToken {
    pub(super) fn is_abandoned(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}

struct CallerWaitGuard {
    flag: Arc<AtomicBool>,
    completed: bool,
}

impl Drop for CallerWaitGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.flag.store(true, Ordering::Release);
        }
    }
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

/// Execute workspace-mutating blocking I/O while holding a [`ScanToken`] inside
/// the OS worker until syscalls return, plus a second [`ScanToken`] for any
/// returned pre-`COMMIT` rollback/publication guard and an [`AbandonToken`] so
/// timed-out/cancelled workers roll back synchronously instead of racing.
pub(super) async fn run_mutating<T, F>(mutation: &MutationGuard, work: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce(AbandonToken, ScanToken) -> Result<T, Error> + Send + 'static,
{
    let worker_fence = mutation.freeze_guard();
    let guard_fence = mutation.freeze_guard();
    run_on_with_abandon(io_slots(), acquire_timeout(), io_timeout(), move |abandoned| {
        let _worker_fence = worker_fence;
        work(abandoned, guard_fence)
    })
    .await
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

struct ArmedCleanup<F: FnOnce() + Send + 'static> {
    work: Option<F>,
}

impl<F: FnOnce() + Send + 'static> Drop for ArmedCleanup<F> {
    fn drop(&mut self) {
        if let Some(work) = self.work.take() {
            super::cleanup::dispatch_cleanup(work);
        }
    }
}

/// Execute mandatory rollback or freeze-release work on the non-rejecting
/// cleanup bulkhead without admission or execution timeouts. Retains an armed
/// `Drop` guard until the blocking worker starts so task cancellation
/// mid-`acquire_owned().await` still dispatches `work` on the cleanup bulkhead.
pub(super) async fn run_cleanup<T, F>(work: F) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let out = Arc::new(Mutex::new(None::<T>));
    let out_slot = out.clone();
    let mut armed = ArmedCleanup {
        work: Some(move || {
            let value = work();
            *lock(&out_slot) = Some(value);
        }),
    };
    let Ok(permit) = super::cleanup::cleanup_bulkhead().clone().acquire_owned().await else {
        return Err(Error::internal("workspace cleanup bulkhead closed"));
    };
    let operation = worker::blocking_scope();
    let joined = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let Some(run_work) = armed.work.take() else {
            return Ok(());
        };
        catch_unwind(AssertUnwindSafe(|| worker::blocking(operation, run_work)))
    })
    .await;
    match joined {
        Ok(Ok(())) => lock(&out).take().ok_or_else(|| Error::internal("workspace cleanup missing output")),
        Ok(Err(_)) => Err(Error::internal("workspace cleanup worker panicked")),
        Err(_) => Err(Error::internal("workspace cleanup worker cancelled")),
    }
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
    run_on_with_abandon(semaphore, wait_limit, work_limit, move |_| work()).await
}

async fn run_on_with_abandon<T, F>(
    semaphore: &Arc<Semaphore>,
    wait_limit: Duration,
    work_limit: Duration,
    work: F,
) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce(AbandonToken) -> Result<T, Error> + Send + 'static,
{
    let permit = match tokio::time::timeout(wait_limit, semaphore.clone().acquire_owned()).await {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => return Err(Error::internal("workspace I/O bulkhead closed")),
        Err(_) => {
            return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "workspace I/O capacity exhausted; retry later"));
        }
    };
    let flag = Arc::new(AtomicBool::new(false));
    let abandon_token = AbandonToken { flag: flag.clone() };
    let mut caller = CallerWaitGuard { flag, completed: false };
    let operation = worker::blocking_scope();
    let mut handle = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        catch_unwind(AssertUnwindSafe(|| worker::blocking(operation, move || work(abandon_token))))
    });
    match tokio::time::timeout(work_limit, &mut handle).await {
        Ok(Ok(Ok(outcome))) => {
            caller.completed = true;
            outcome
        }
        Ok(Ok(Err(_))) => {
            caller.completed = true;
            Err(Error::internal("workspace I/O worker panicked"))
        }
        Ok(Err(_)) => {
            caller.completed = true;
            Err(Error::internal("workspace I/O worker cancelled"))
        }
        Err(_) => Err(Error::timeout()),
    }
}

#[cfg(test)]
#[path = "blocking_tests.rs"]
mod tests;
