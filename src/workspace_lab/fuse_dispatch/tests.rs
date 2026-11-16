use super::*;

#[test]
fn budget_caps_ops_and_bytes_and_releases_exactly() {
    let budget = Budget::new(2, 100);
    assert!(budget.try_acquire(60));
    assert!(!budget.try_acquire(50), "byte cap must reject oversize operations");
    assert!(budget.try_acquire(40));
    assert!(!budget.try_acquire(1), "operation cap must reject a third operation");
    assert_eq!(budget.used(), (2, 100));
    budget.release(60);
    assert_eq!(budget.used(), (1, 40));
    budget.release(40);
    assert_eq!(budget.used(), (0, 0));
}

#[test]
fn permit_charges_both_budgets_and_releases_on_drop() {
    let mount = Arc::new(Budget::new(8, 1024));
    let global = Arc::new(Budget::new(8, 2048));
    let permit = Permit::acquire(&mount, &global, 128).expect("permit");
    assert_eq!(mount.used(), (1, 128));
    assert_eq!(global.used(), (1, 128));
    drop(permit);
    assert_eq!(mount.used(), (0, 0));
    assert_eq!(global.used(), (0, 0));
}

#[test]
fn queued_mutation_epoch_must_match_the_admitted_guard_epoch() {
    assert!(epoch_matches(Some(7), 7));
    assert!(!epoch_matches(Some(7), 8), "a parked old-epoch mutation must not run on the new epoch");
    assert!(!epoch_matches(None, 7), "an unstamped mutation fails closed");
}

#[test]
fn diagnostic_counters_are_actor_observations_not_fence_calls() {
    let shared = Shared::new();
    let gate = MutationGate::new_with_lease(1, i64::MAX).unwrap();
    gate.fence();
    assert_eq!(shared.diagnostics(), (0, 0), "MutationGate::fence itself is not an actor observation");
    shared.observe_fenced();
    shared.observe_fenced();
    shared.reject_epoch_mismatch();
    assert_eq!(shared.diagnostics(), (2, 1));
    assert_eq!(QueueUsage::default().fence_observations, 0);
    assert_eq!(QueueUsage::default().epoch_mismatch_rejections, 0);
}

#[test]
fn closed_work_queue_refuses_pops_but_drain_paths_still_clean_up() {
    let mut queue = WorkQueue::<u32>::new();
    assert_eq!(queue.push_ready(1), None);
    queue.push_frozen_back(2);
    queue.close();
    assert!(queue.is_shutdown());
    assert_eq!(queue.push_ready(3), Some(3), "a closed queue rejects new ready work");
    assert_eq!(queue.pop_ready(), None);
    assert_eq!(queue.pop_frozen(), None);
    assert_eq!(queue.lens(), (1, 1), "refusing a pop must not discard queued replies");
    assert_eq!(queue.pop_ready_for_drain(), Some(1));
    assert_eq!(queue.pop_frozen_for_drain(), Some(2));
    assert_eq!(queue.pop_ready_for_drain(), None);
    assert_eq!(queue.pop_frozen_for_drain(), None);
}

#[test]
fn actor_join_panic_is_a_cached_typed_failure_never_success() {
    let dispatcher = Dispatcher {
        shared: Shared::new(),
        mount_budget: Arc::new(Budget::new(1, 1)),
        global_budget: Arc::new(Budget::new(1, 1)),
        gate: MutationGate::new_with_lease(1, i64::MAX).unwrap(),
        worker: Mutex::new(ActorWorker {
            handle: Some(std::thread::spawn(|| panic!("injected actor failure"))),
            outcome: None,
        }),
    };
    assert_eq!(dispatcher.join_actor(), Err(ActorJoinFailure::Panicked));
    assert_eq!(
        dispatcher.join_actor(),
        Err(ActorJoinFailure::Panicked),
        "a cached actor panic must never become a clean second join"
    );
}

#[test]
fn request_stop_does_not_wait_for_a_blocked_actor_join() {
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let dispatcher = Dispatcher {
        shared: Shared::new(),
        mount_budget: Arc::new(Budget::new(1, 1)),
        global_budget: Arc::new(Budget::new(1, 1)),
        gate: MutationGate::new_with_lease(1, i64::MAX).unwrap(),
        worker: Mutex::new(ActorWorker {
            handle: Some(std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })),
            outcome: None,
        }),
    };
    started_rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
    // This would block forever if the quick stop still joined the actor.
    dispatcher.request_stop();
    assert!(dispatcher.worker.lock().unwrap().outcome.is_none());
    release_tx.send(()).unwrap();
    assert_eq!(dispatcher.join_actor(), Ok(()));
    assert_eq!(dispatcher.join_actor(), Ok(()));
}
