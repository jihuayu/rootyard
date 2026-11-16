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
        Self { id, events, fences: Arc::new(AtomicUsize::new(0)), teardowns: Arc::new(AtomicUsize::new(0)), gate: None }
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
