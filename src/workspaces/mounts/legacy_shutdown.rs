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
            let Some(handle) = worker.handle.take() else { return None };
            handle
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
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };

    #[derive(Clone, Default)]
    struct GateState {
        entered: bool,
        released: bool,
    }

    struct RecordingOwner {
        id: usize,
        events: Arc<Mutex<Vec<String>>>,
        fences: Arc<AtomicUsize>,
        teardowns: Arc<AtomicUsize>,
        gate: Option<Arc<(Mutex<GateState>, Condvar)>>,
    }

    impl RecordingOwner {
        fn immediate(id: usize, events: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                id,
                events,
                fences: Arc::new(AtomicUsize::new(0)),
                teardowns: Arc::new(AtomicUsize::new(0)),
                gate: None,
            }
        }

        fn blocking(id: usize, events: Arc<Mutex<Vec<String>>>, gate: Arc<(Mutex<GateState>, Condvar)>) -> Self {
            Self {
                id,
                events,
                fences: Arc::new(AtomicUsize::new(0)),
                teardowns: Arc::new(AtomicUsize::new(0)),
                gate: Some(gate),
            }
        }
    }

    impl LegacyOwner for RecordingOwner {
        fn fence_for_shutdown(&self) {
            self.fences.fetch_add(1, Ordering::SeqCst);
            self.events.lock().unwrap().push(format!("fence:{}", self.id));
        }

        fn teardown_owned(&mut self) -> Result<(), String> {
            self.teardowns.fetch_add(1, Ordering::SeqCst);
            self.events.lock().unwrap().push(format!("teardown:{}", self.id));
            if let Some(gate) = &self.gate {
                let (lock, changed) = &**gate;
                let mut state = lock.lock().unwrap();
                state.entered = true;
                changed.notify_all();
                while !state.released {
                    state = changed.wait(state).unwrap();
                }
            }
            Ok(())
        }
    }

    fn wait_entered(gate: &Arc<(Mutex<GateState>, Condvar)>) {
        let (lock, changed) = &**gate;
        let mut state = lock.lock().unwrap();
        while !state.entered {
            let (next, timeout) = changed.wait_timeout(state, Duration::from_secs(2)).unwrap();
            assert!(!timeout.timed_out(), "teardown worker never entered");
            state = next;
        }
    }

    fn release(gate: &Arc<(Mutex<GateState>, Condvar)>) {
        let (lock, changed) = &**gate;
        lock.lock().unwrap().released = true;
        changed.notify_all();
    }

    #[test]
    fn fences_every_captured_owner_before_sequential_teardown() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let first = RecordingOwner::immediate(1, events.clone());
        let second = RecordingOwner::immediate(2, events.clone());
        let ticket = Arc::new(LegacyShutdownTicket::new());
        ticket.seed_owners(vec![(Uuid::new_v4(), first), (Uuid::new_v4(), second)]);
        ticket.spawn_worker().unwrap();
        let observation = ticket.wait_until(Instant::now() + Duration::from_secs(2));
        assert!(observation.success(), "{observation:?}");
        let observed = events.lock().unwrap().clone();
        assert_eq!(observed, vec!["fence:1", "fence:2", "teardown:1", "teardown:2"]);
    }

    #[test]
    fn worker_spawn_failure_keeps_owner_and_is_never_success() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner = RecordingOwner::immediate(1, events.clone());
        let ticket = Arc::new(LegacyShutdownTicket::new());
        ticket.seed_owners(vec![(Uuid::new_v4(), owner)]);
        let error = ticket
            .spawn_worker_with(|_| Err(io::Error::other("injected worker spawn failure")))
            .expect_err("injected spawn must fail");
        assert_eq!(error, "injected worker spawn failure");
        let observation = ticket.observe();
        assert_eq!(observation.owned, 1, "spawn failure must not drop the retained owner");
        assert_eq!(observation.worker_spawn_error.as_deref(), Some("injected worker spawn failure"));
        assert!(!observation.success());
        assert!(!events.lock().unwrap().iter().any(|event| event.starts_with("teardown:")));
    }

    #[test]
    fn waiter_timeout_drop_and_reobserve_keep_the_same_owned_worker() {
        let gate = Arc::new((Mutex::new(GateState::default()), Condvar::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner = RecordingOwner::blocking(1, events.clone(), gate.clone());
        let teardowns = owner.teardowns.clone();
        let ticket = Arc::new(LegacyShutdownTicket::new());
        ticket.seed_owners(vec![(Uuid::new_v4(), owner)]);
        ticket.spawn_worker().unwrap();
        wait_entered(&gate);

        let timed_out = ticket.wait_until(Instant::now() + Duration::from_millis(25));
        assert!(!timed_out.success(), "a timed-out waiter must not claim cleanup");
        assert_eq!(timed_out.pending, 0);
        assert_eq!(timed_out.owned, 1, "the in-flight owner remains retained by the ticket");
        drop(timed_out);

        // Dropping the waiter did not cancel or drop the native owner; the same
        // ticket remains observably incomplete.
        assert!(!ticket.observe().success());
        release(&gate);

        let completed = ticket.wait_until(Instant::now() + Duration::from_secs(2));
        assert!(completed.success(), "{completed:?}");
        assert_eq!(teardowns.load(Ordering::SeqCst), 1, "reobserve must not double-join the owner");
        assert!(ticket.observe().success(), "a repeated observer reaps the same completed ticket");
        assert_eq!(teardowns.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pending_admission_late_owner_is_retained_and_finishes_the_batch() {
        let ticket = Arc::new(LegacyShutdownTicket::new());
        ticket.add_pending(1);
        ticket.spawn_worker().unwrap();
        let id = Uuid::new_v4();
        let events = Arc::new(Mutex::new(Vec::new()));
        ticket.resolve_with_owner(id, RecordingOwner::immediate(7, events.clone()));
        let observation = ticket.wait_until(Instant::now() + Duration::from_secs(2));
        assert!(observation.success(), "{observation:?}");
        assert_eq!(observation.pending, 0);
        assert_eq!(observation.owned, 0);
    }

    #[test]
    fn failed_owner_stays_retained_even_after_teardown_returns() {
        struct FailingOwner;
        impl LegacyOwner for FailingOwner {
            fn fence_for_shutdown(&self) {}
            fn teardown_owned(&mut self) -> Result<(), String> {
                Err("exact unmount refused".into())
            }
        }

        let ticket = Arc::new(LegacyShutdownTicket::new());
        ticket.seed_owners(vec![(Uuid::new_v4(), FailingOwner)]);
        ticket.spawn_worker().unwrap();
        let observation = ticket.wait_until(Instant::now() + Duration::from_secs(2));
        assert!(!observation.success());
        assert_eq!(observation.owned, 1, "a failed slot must remain ticket-owned");
        assert_eq!(observation.failures.len(), 1);
        assert!(observation.failures[0].contains("exact unmount refused"));
    }

    #[test]
    fn empty_ticket_has_no_completion_evidence() {
        let ticket = Arc::new(LegacyShutdownTicket::new());
        ticket.spawn_worker().unwrap();
        assert!(ticket.wait_until(Instant::now() + Duration::from_secs(2)).success());
        assert!(ticket.completion_evidence().is_none(), "an empty/no-work ticket is not proof of one mount");
    }

    #[test]
    fn joined_owner_is_recorded_only_after_successful_teardown() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let owner = RecordingOwner::immediate(41, events);
        let id = Uuid::new_v4();
        let ticket = Arc::new(LegacyShutdownTicket::new());
        ticket.seed_owners(vec![(id, owner)]);
        ticket.spawn_worker().unwrap();
        assert!(ticket.wait_until(Instant::now() + Duration::from_secs(2)).success());
        assert_eq!(ticket.completion_evidence(), Some((1, vec![id])));
    }

    #[test]
    fn failed_owner_is_not_recorded_as_joined() {
        struct FailingOwner;
        impl LegacyOwner for FailingOwner {
            fn fence_for_shutdown(&self) {}
            fn teardown_owned(&mut self) -> Result<(), String> {
                Err("exact unmount refused".into())
            }
        }

        let ticket = Arc::new(LegacyShutdownTicket::new());
        ticket.seed_owners(vec![(Uuid::new_v4(), FailingOwner)]);
        ticket.spawn_worker().unwrap();
        let observation = ticket.wait_until(Instant::now() + Duration::from_secs(2));
        assert!(!observation.success());
        assert_eq!(observation.joined, 0);
        assert!(ticket.completion_evidence().is_none());
    }

    #[test]
    fn resolve_without_owner_resolves_the_pending_condition() {
        let ticket = Arc::new(LegacyShutdownTicket::new());
        ticket.add_pending(1);
        ticket.spawn_worker().unwrap();
        ticket.resolve_without_owner(Uuid::new_v4());
        let observation = ticket.wait_until(Instant::now() + Duration::from_secs(2));
        assert!(observation.success(), "{observation:?}");
        assert_eq!(observation.pending, 0);
    }

    // A channel-based start barrier keeps this test independent of sleep order
    // when the worker thread begins before the assertion.
    #[test]
    fn worker_start_is_observed_before_timeout_probe() {
        let (started_tx, started_rx) = mpsc::channel();
        struct SignallingOwner {
            started: mpsc::Sender<()>,
        }
        impl LegacyOwner for SignallingOwner {
            fn fence_for_shutdown(&self) {}
            fn teardown_owned(&mut self) -> Result<(), String> {
                self.started.send(()).unwrap();
                Ok(())
            }
        }
        let ticket = Arc::new(LegacyShutdownTicket::new());
        ticket.seed_owners(vec![(Uuid::new_v4(), SignallingOwner { started: started_tx })]);
        ticket.spawn_worker().unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(ticket.wait_until(Instant::now() + Duration::from_secs(2)).success());
    }
}
