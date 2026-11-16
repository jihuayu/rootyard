//! Retained owner and bounded observer for legacy in-process FUSE teardown.
//!
//! The registry stores this ticket before the ordinary OS worker is spawned.
//! The worker exclusively drains captured [`LegacyOwner`] slots on one batch
//! thread; a caller timeout or dropped waiter only stops observing, never
//! cancels the worker or releases an owner. A ticket is reachable after the
//! caller has timed out, so a later observer reaps the same worker instead of
//! starting a second teardown.
use std::{
    any::Any,
    io,
    panic::{self, AssertUnwindSafe},
    sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use uuid::Uuid;

/// One legacy mount slot that can be fenced quickly and torn down without
/// dropping its native owner on failure.
pub(super) trait LegacyOwner: Send + 'static {
    /// Quick request-stop: fence the mutation gate and close the dispatch queue.
    fn fence_for_shutdown(&self);

    /// Owner-preserving teardown. The implementation must retain its live
    /// session and reader when it returns `Err`.
    fn teardown_owned(&mut self) -> Result<(), String>;
}

struct Owned<O> {
    id: Uuid,
    owner: O,
}

struct State<O> {
    pending: usize,
    queued: Vec<Owned<O>>,
    retained: Vec<Owned<O>>,
    in_flight: usize,
    /// Exact owners whose actor join, exact unmount and session join all
    /// completed. Kept only for bounded source-completion evidence; an empty
    /// list is not evidence that any mount existed.
    joined: Vec<Uuid>,
    failures: Vec<String>,
    completion: Option<Result<(), String>>,
    finished: bool,
}

struct WorkerState {
    handle: Option<JoinHandle<()>>,
    started: bool,
    reaped: bool,
    spawn_error: Option<String>,
    reap_result: Option<Result<(), String>>,
}

/// Non-blocking status of one retained teardown owner. `success` is never true
/// merely because the worker signalled completion; it requires an observed,
/// finished worker that has actually been reaped and validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LegacyShutdownObservation {
    pub(super) pending: usize,
    pub(super) owned: usize,
    pub(super) joined: usize,
    pub(super) failures: Vec<String>,
    pub(super) worker_spawn_error: Option<String>,
    pub(super) worker_finished: bool,
    pub(super) worker_reaped: bool,
    pub(super) reaped_result: Option<Result<(), String>>,
}

impl LegacyShutdownObservation {
    pub(super) fn success(&self) -> bool {
        self.worker_reaped
            && self.reaped_result.as_ref().is_some_and(Result::is_ok)
            && self.pending == 0
            && self.owned == 0
            && self.failures.is_empty()
    }

    /// A spawned worker cannot make further progress once it has been reaped or
    /// failed to spawn. A timeout is deliberately not terminal: the same ticket
    /// can still complete later.
    pub(super) fn is_terminal(&self) -> bool {
        self.worker_spawn_error.is_some() || self.worker_reaped
    }
}

/// A retained batch teardown owner. It is stored under the registry authority
/// before its ordinary OS worker is spawned.
pub(super) struct LegacyShutdownTicket<O> {
    state: Mutex<State<O>>,
    wake: Condvar,
    worker: Mutex<WorkerState>,
}

impl<O> LegacyShutdownTicket<O> {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                pending: 0,
                queued: Vec::new(),
                retained: Vec::new(),
                in_flight: 0,
                joined: Vec::new(),
                failures: Vec::new(),
                completion: None,
                finished: false,
            }),
            wake: Condvar::new(),
            worker: Mutex::new(WorkerState {
                handle: None,
                started: false,
                reaped: false,
                spawn_error: None,
                reap_result: None,
            }),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, State<O>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_worker(&self) -> MutexGuard<'_, WorkerState> {
        self.worker.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Include every admission reserved before close in the completion
    /// condition. This is called once while the registry authority is held.
    pub(super) fn add_pending(&self, count: usize) {
        let mut state = self.lock_state();
        state.pending = state.pending.saturating_add(count);
    }

    /// Seed already-confirmed owners captured by close.
    pub(super) fn seed_owners(&self, owners: Vec<(Uuid, O)>) {
        self.adopt_owners(owners);
    }

    /// Add captured owners without changing the pending-admission count. Used
    /// only for a repeated close/extraction of the same retained identity.
    pub(super) fn adopt_owners(&self, owners: Vec<(Uuid, O)>) {
        if owners.is_empty() {
            return;
        }
        let mut state = self.lock_state();
        for (id, owner) in owners {
            if state.finished {
                state.failures.push(format!("workspace {id}: owner arrived after teardown completion"));
                state.retained.push(Owned { id, owner });
            } else {
                state.queued.push(Owned { id, owner });
            }
        }
        drop(state);
        self.wake.notify_all();
    }

    /// A pre-close pending admission created an owner after close. The owner is
    /// retained in this same ticket and can never disappear from the completion
    /// condition.
    pub(super) fn resolve_with_owner(&self, id: Uuid, owner: O) {
        let mut state = self.lock_state();
        if state.pending == 0 {
            state.failures.push(format!("workspace {id}: owner arrived after its pending admission resolved"));
        } else {
            state.pending -= 1;
        }
        if state.finished {
            state.failures.push(format!("workspace {id}: owner arrived after teardown completion"));
            state.retained.push(Owned { id, owner });
        } else {
            state.queued.push(Owned { id, owner });
        }
        drop(state);
        self.wake.notify_all();
    }

    /// A pre-close pending admission failed before creating a mount. No owner
    /// exists, but the admission must still leave the completion condition
    /// before the ticket can report success.
    pub(super) fn resolve_without_owner(&self, id: Uuid) {
        let mut state = self.lock_state();
        if state.pending == 0 {
            state.failures.push(format!("workspace {id}: admission resolved after teardown completion"));
        } else {
            state.pending -= 1;
        }
        drop(state);
        self.wake.notify_all();
    }

    /// Short, non-blocking observer. A finished worker is reaped before the
    /// snapshot; no status mutex is held across a native join.
    pub(super) fn observe(&self) -> LegacyShutdownObservation {
        let _ = self.try_reap();
        let (spawn_error, reaped, reap_result) = {
            let worker = self.lock_worker();
            (worker.spawn_error.clone(), worker.reaped, worker.reap_result.clone())
        };
        let state = self.lock_state();
        LegacyShutdownObservation {
            pending: state.pending,
            owned: state.queued.len() + state.retained.len() + state.in_flight,
            joined: state.joined.len(),
            failures: state.failures.clone(),
            worker_spawn_error: spawn_error,
            worker_finished: state.finished,
            worker_reaped: reaped,
            reaped_result: reap_result,
        }
    }

    /// Exact completion identities for source evidence. The caller must first
    /// observe a clean ticket; an empty vector is returned as `None` so an
    /// empty/no-work ticket can never be reported as a joined mount.
    pub(super) fn completion_evidence(&self) -> Option<(usize, Vec<Uuid>)> {
        let state = self.lock_state();
        if state.joined.is_empty() { None } else { Some((state.joined.len(), state.joined.clone())) }
    }

    /// Bounded wait for one caller. Expiry returns the current incomplete
    /// observation; the ticket and every owner remain retained for a later
    /// observer.
    pub(super) fn wait_until(&self, deadline: Instant) -> LegacyShutdownObservation {
        loop {
            let observation = self.observe();
            if observation.success() || observation.is_terminal() {
                return observation;
            }
            let now = Instant::now();
            if now >= deadline {
                return observation;
            }
            let wait = (deadline - now).min(Duration::from_millis(10));
            let state = self.lock_state();
            if state.finished {
                drop(state);
                continue;
            }
            let _ = self.wake.wait_timeout(state, wait).unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn try_reap(&self) -> Option<Result<(), String>> {
        let handle = {
            let mut worker = self.lock_worker();
            if worker.reaped {
                return worker.reap_result.clone();
            }
            if worker.spawn_error.is_some() {
                return None;
            }
            let finished = worker.handle.as_ref().is_some_and(|handle| handle.is_finished());
            if !finished {
                return None;
            }
            worker.handle.take()?
        };
        // The worker mutex is intentionally released before joining. Status
        // observation must never wait on a native teardown.
        let result = match handle.join() {
            Ok(()) => {
                let state = self.lock_state();
                match &state.completion {
                    Some(Ok(())) if state.pending == 0 && state.retained.is_empty() && state.failures.is_empty() => {
                        Ok(())
                    }
                    Some(Err(error)) => Err(error.clone()),
                    Some(Ok(())) => Err("legacy teardown worker finished with retained ownership".into()),
                    None => Err("legacy teardown worker exited without a completion result".into()),
                }
            }
            Err(_) => Err("legacy teardown worker panicked".into()),
        };
        let mut worker = self.lock_worker();
        worker.reaped = true;
        worker.reap_result = Some(result.clone());
        Some(result)
    }
}

impl<O: LegacyOwner> LegacyShutdownTicket<O> {
    /// Spawn the single retained batch worker. The ticket must already be
    /// stored by the caller, so a spawn failure still leaves every owner in the
    /// same retained ticket.
    pub(super) fn spawn_worker(self: &Arc<Self>) -> Result<(), String> {
        self.spawn_worker_with(|work| thread::Builder::new().name("rootyard-legacy-teardown".into()).spawn(work))
    }

    fn spawn_worker_with<F>(self: &Arc<Self>, spawn: F) -> Result<(), String>
    where
        F: FnOnce(Box<dyn FnOnce() + Send>) -> io::Result<JoinHandle<()>>,
    {
        {
            let mut worker = self.lock_worker();
            if worker.started {
                return match &worker.spawn_error {
                    Some(error) => Err(error.clone()),
                    None => Ok(()),
                };
            }
            // Mark the launch before spawning so concurrent/repeated observers
            // cannot start a second competing worker.
            worker.started = true;
        }
        let ticket = self.clone();
        let work: Box<dyn FnOnce() + Send> = Box::new(move || ticket.run_worker());
        match spawn(work) {
            Ok(handle) => {
                self.lock_worker().handle = Some(handle);
                Ok(())
            }
            Err(error) => {
                let message = error.to_string();
                self.lock_worker().spawn_error = Some(message.clone());
                Err(message)
            }
        }
    }

    fn run_worker(self: Arc<Self>) {
        loop {
            let batch = {
                let mut state = self.lock_state();
                if state.finished {
                    return;
                }
                let batch = std::mem::take(&mut state.queued);
                if batch.is_empty() {
                    if state.pending == 0 {
                        let result = if state.retained.is_empty() && state.failures.is_empty() {
                            Ok(())
                        } else {
                            Err("legacy teardown retained owned mounts".into())
                        };
                        state.completion = Some(result);
                        state.finished = true;
                        drop(state);
                        self.wake.notify_all();
                        return;
                    }
                    let _ = self
                        .wake
                        .wait_timeout(state, Duration::from_millis(50))
                        .unwrap_or_else(PoisonError::into_inner);
                    continue;
                }
                state.in_flight = batch.len();
                batch
            };
            // Fence every captured slot before any slow actor/session join, so
            // an unprocessed slot is already stopped even if an earlier one
            // stalls the batch.
            for item in &batch {
                item.owner.fence_for_shutdown();
            }
            for mut item in batch {
                let result = panic::catch_unwind(AssertUnwindSafe(|| item.owner.teardown_owned()));
                let failure = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(error),
                    Err(payload) => Some(panic_message(payload.as_ref())),
                };
                let mut state = self.lock_state();
                state.in_flight = state.in_flight.saturating_sub(1);
                match failure {
                    None => {
                        state.joined.push(item.id);
                        drop(item);
                    }
                    Some(error) => {
                        state.failures.push(format!("workspace {}: {error}", item.id));
                        // Failed owners stay owned by the ticket. They are not
                        // retried automatically and never become clean success.
                        state.retained.push(item);
                    }
                }
            }
        }
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "panic while tearing down a legacy mount".into()
    }
}

#[cfg(test)]
#[path = "legacy_shutdown_tests.rs"]
mod tests;
