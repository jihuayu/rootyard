//! Bounded off-thread workspace scans.
//!
//! Reconciliation must never run a full-tree hash on an async worker or while a
//! PostgreSQL row lock is held. Jobs here run on a fixed pool of ordinary
//! threads, with one bounded queue per worker. A timed-out or cancelled caller
//! only loses its result: the worker keeps the FUSE freeze and its capacity
//! until the filesystem closure really returns. Each job also carries the
//! caller's selected worker operation scope, because a std thread inherits no
//! task locals and would otherwise report its own failures as detached.
use crate::{Error, observability::worker};
use std::{
    collections::HashSet,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc::{SyncSender, TrySendError, sync_channel},
    },
    time::Duration,
};
use uuid::Uuid;

const WORKERS_ENV: &str = "ROOTYARD_WORKSPACE_SCAN_WORKERS";
const QUEUE_ENV: &str = "ROOTYARD_WORKSPACE_SCAN_QUEUE";
const TIMEOUT_ENV: &str = "ROOTYARD_WORKSPACE_SCAN_TIMEOUT_MS";

type Job = Box<dyn FnOnce() + Send + 'static>;

pub(super) enum ScanFailure {
    /// Every worker already owns a running scan (or its queue is full).
    Busy,
    /// The caller stopped waiting; the filesystem closure still owns capacity.
    Timeout,
    Failed(Error),
}

struct Pool {
    queues: Vec<SyncSender<Job>>,
    next: AtomicUsize,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn pool() -> Result<&'static Arc<Pool>, ScanFailure> {
    static POOL: OnceLock<Result<Arc<Pool>, String>> = OnceLock::new();
    POOL.get_or_init(|| Pool::new().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(|error| ScanFailure::Failed(Error::internal(error)))
}

impl Pool {
    fn new() -> std::io::Result<Arc<Pool>> {
        let workers = worker_count();
        let capacity = queue_capacity();
        let mut queues = Vec::with_capacity(workers);
        for index in 0..workers {
            let (sender, receiver) = sync_channel::<Job>(capacity);
            std::thread::Builder::new().name(format!("rootyard-workspace-scan-{index}")).spawn(move || {
                while let Ok(job) = receiver.recv() {
                    // A panic in one scan must not remove a worker or release
                    // capacity before its closure has unwound.
                    let _ = std::panic::catch_unwind(AssertUnwindSafe(job));
                }
            })?;
            queues.push(sender);
        }
        Ok(Arc::new(Pool { queues, next: AtomicUsize::new(0) }))
    }

    fn submit(&self, job: Job) -> bool {
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let mut job = Some(job);
        for offset in 0..self.queues.len() {
            let index = (start + offset) % self.queues.len();
            match self.queues[index].try_send(job.take().expect("scan job moved once")) {
                Ok(()) => return true,
                Err(TrySendError::Full(returned)) | Err(TrySendError::Disconnected(returned)) => {
                    job = Some(returned);
                }
            }
        }
        // Dropping the final copy removes the in-flight marker, so the next
        // reconciliation round can retry once capacity returns.
        false
    }
}

static INFLIGHT: OnceLock<Mutex<HashSet<Uuid>>> = OnceLock::new();

fn inflight() -> &'static Mutex<HashSet<Uuid>> {
    INFLIGHT.get_or_init(|| Mutex::new(HashSet::new()))
}

struct InflightGuard(Uuid);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        lock(inflight()).remove(&self.0);
    }
}

/// Run one frozen filesystem operation on a bounded worker.
///
/// `with_frozen` is entered *inside* the worker, so cancelling the caller never
/// releases the mutation gate before the scan itself has finished. The caller's
/// worker operation scope is captured here, on the async side, and reinstated on
/// the pool thread so `Error::internal` inside the closure is attributed to the
/// real worker and phase instead of a detached scope. Only that operation scope
/// is carried: an HTTP request scope is never captured.
pub(super) async fn frozen<T, F>(id: Uuid, timeout: Duration, work: F) -> Result<T, ScanFailure>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Error> + Send + 'static,
{
    {
        let mut set = lock(inflight());
        if !set.insert(id) {
            return Err(ScanFailure::Busy);
        }
    }
    let guard = InflightGuard(id);
    let operation = worker::blocking_scope();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let job: Job = Box::new(move || {
        let _guard = guard;
        let outcome = worker::blocking(operation, move || super::mounts::with_frozen(id, work));
        let _ = sender.send(outcome);
    });
    let pool = pool()?;
    if !pool.submit(job) {
        return Err(ScanFailure::Busy);
    }
    match tokio::time::timeout(timeout, receiver).await {
        Ok(Ok(Ok(value))) => Ok(value),
        Ok(Ok(Err(error))) => Err(ScanFailure::Failed(error)),
        Ok(Err(_)) => Err(ScanFailure::Failed(Error::internal("workspace scan worker stopped"))),
        Err(_) => Err(ScanFailure::Timeout),
    }
}

/// Reconciliation fan-out. Each scan still consumes exactly one pool worker.
pub(super) fn concurrency() -> usize {
    worker_count().saturating_mul(2).max(2)
}

pub(super) fn timeout() -> Duration {
    Duration::from_millis(
        std::env::var(TIMEOUT_ENV)
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|millis| (1..=300_000).contains(millis))
            .unwrap_or(30_000),
    )
}

fn worker_count() -> usize {
    std::env::var(WORKERS_ENV)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|workers| (1..=16).contains(workers))
        .unwrap_or(3)
}

fn queue_capacity() -> usize {
    std::env::var(QUEUE_ENV)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|capacity| (1..=64).contains(capacity))
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_workspace_is_never_scanned_by_two_workers_at_once() {
        let id = Uuid::new_v4();
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let work = {
            let active = active.clone();
            let peak = peak.clone();
            move || {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }
        };
        let first = tokio::spawn(frozen(id, Duration::from_secs(5), work));
        started_rx.recv_timeout(Duration::from_secs(5)).expect("scan did not start");
        assert!(matches!(frozen(id, Duration::from_millis(50), || Ok(())).await, Err(ScanFailure::Busy)));
        release_tx.send(()).unwrap();
        assert!(first.await.unwrap().is_ok());
        assert_eq!(peak.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timeout_keeps_capacity_and_inflight_until_work_returns() {
        let id = Uuid::new_v4();
        let finished = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let work = {
            let finished = finished.clone();
            move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                finished.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        };
        let first = tokio::spawn(frozen(id, Duration::from_millis(80), work));
        started_rx.recv_timeout(Duration::from_secs(5)).expect("scan did not start");
        assert!(matches!(first.await.unwrap(), Err(ScanFailure::Timeout)));
        assert!(matches!(frozen(id, Duration::from_millis(50), || Ok(())).await, Err(ScanFailure::Busy)));
        release_tx.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while finished.load(Ordering::SeqCst) == 0 {
            assert!(std::time::Instant::now() < deadline, "blocking closure never completed");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_scan_thread_runs_with_the_caller_worker_scope_only() {
        let context = worker::OperationContext::new(worker::WorkerKind::WorkspaceCapture);
        let (caller, on_thread) = worker::run(&context, worker::Phase::Reconcile, async {
            let caller = worker::blocking_scope().expect("caller has a worker scope");
            let on_thread = frozen(Uuid::new_v4(), Duration::from_secs(5), || {
                (worker::current(), std::thread::current().name().map(str::to_owned), Ok(()))
            })
            .await;
            (caller, on_thread)
        })
        .await;
        let (observed, name, outcome) = on_thread.expect("scan completed");
        let observed = observed.expect("scan thread lost its worker scope");
        assert_eq!(observed.worker, worker::WorkerKind::WorkspaceCapture);
        assert_eq!(observed.phase, worker::Phase::Reconcile);
        assert_eq!(observed.operation_id, caller.operation_id);
        assert!(name.is_some_and(|name| name.starts_with("rootyard-workspace-scan-")), "not a pool thread");
        assert!(outcome.is_ok());
        // A caller without an explicit worker scope never invents one.
        let detached = frozen(Uuid::new_v4(), Duration::from_secs(5), || Ok(worker::current())).await;
        assert!(detached.expect("scan completed").is_none(), "detached scan gained an operation scope");
    }
}
