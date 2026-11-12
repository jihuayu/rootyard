//! Bounded off-thread execution and in-memory per-workspace mutation fencing.
//!
//! * **Data I/O bulkhead** ([`run`]): gates `spawn_blocking` behind a bounded
//!   [`Semaphore`] (`ROOTYARD_WORKSPACE_IO_CONCURRENCY`, default 8) with the
//!   permit retained inside the OS closure until syscalls return.
//! * **Control bulkhead** ([`run_control`], [`spawn_observe`]): isolated
//!   [`Semaphore`] so FUSE mount/freeze/observe RPCs stay responsive.
//! * **Mutation coordinator** ([`lock_mutation`], [`begin_scan`]): serializes
//!   per-workspace mutations in memory, drains in-flight `ScanToken`s before
//!   admitting foreground mutations, and fences overlapping background scans.
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
pub(super) struct MutationGuard {
    id: Uuid,
    _owned: OwnedMutexGuard<()>,
}

impl MutationGuard {
    /// Hold `active_scans > 0` across a foreground `mounts::with_frozen` call so
    /// even a timed-out `blocking::run` caller cannot allow another freeze or
    /// scan on `id` until `mounts::with_frozen` actually exits.
    pub(super) fn freeze_guard(&self) -> ScanToken {
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

pub(super) async fn lock_mutation(id: Uuid, timeout: Duration) -> Result<MutationGuard, Error> {
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

/// Refcounted observation token held by `capture::reconcile_one` (and cloned
/// into the `scan::frozen` OS worker closure so `active_scans > 0` holds until
/// `mounts::with_frozen` actually exits).
#[derive(Clone)]
pub(super) struct ScanToken {
    slot: Arc<ScanSlot>,
}

impl ScanToken {
    pub(super) fn is_unchanged(&self) -> bool {
        let map = lock(mutations());
        map.get(&self.slot.id).is_some_and(|entry| !entry.active && entry.generation == self.slot.generation)
    }
}

pub(super) fn begin_scan(id: Uuid) -> Option<ScanToken> {
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lock_mutation_drains_inflight_scans_blocks_new_scans_and_cleans_up_on_timeout() {
        let id = Uuid::new_v4();
        let scan = begin_scan(id).expect("idle workspace allows scan");
        let worker_clone = scan.clone();
        assert!(scan.is_unchanged());

        // Wedged scan causes lock_mutation to time out cleanly without leaking waiters.
        let timed_out = lock_mutation(id, Duration::from_millis(40)).await;
        assert_eq!(timed_out.err().map(|e| e.0), Some(StatusCode::GATEWAY_TIMEOUT));

        // Healthy in-flight scan finishes unimpeded while queued waiter blocks new scans.
        let waiter_task = tokio::spawn(async move { lock_mutation(id, Duration::from_secs(2)).await });
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while lock(mutations()).get(&id).map_or(0, |e| e.waiters) == 0 {
            assert!(std::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(begin_scan(id).is_none(), "queued foreground mutation must block new background scans");
        assert!(scan.is_unchanged(), "in-flight scan remains valid until it completes");

        drop(scan);
        assert!(!waiter_task.is_finished(), "cloned worker token still holds active_scans > 0");
        drop(worker_clone);

        let guard = waiter_task.await.unwrap().expect("mutation acquired once scan drains");
        assert!(begin_scan(id).is_none());
        drop(guard);
        assert!(!lock(mutations()).contains_key(&id), "idle entry must be pruned");
    }
}
