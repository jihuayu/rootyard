//! Deterministic tests for the workspace mutation gate.
//!
//! Thread handoff uses barriers and channels, never sleeps: every wait either
//! blocks on a message the test itself sends or polls a gate state that the test
//! drives. `MutationGuard` is created and dropped on the same thread, because its
//! drop touches a thread-local admission list.

use super::*;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Barrier, mpsc},
};

fn deadline() -> i64 {
    unix_now().unwrap() + 3600
}

fn mutation_error(gate: &MutationGate) -> Option<i32> {
    gate.mutation().err().and_then(|error| error.raw_os_error())
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() {
        assert!(Instant::now() < deadline, "condition was not reached");
        std::thread::yield_now();
    }
}

#[test]
fn freeze_drains_existing_mutator_before_running_and_rejects_new_ones() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let (admitted_tx, admitted_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (dropped_tx, dropped_rx) = mpsc::channel();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (freeze_release_tx, freeze_release_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let mutator_gate = gate.clone();
        scope.spawn(move || {
            let guard = mutator_gate.mutation().expect("healthy gate admits");
            admitted_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(guard);
            dropped_tx.send(()).unwrap();
        });
        // Confirm the old mutation owns its permit before the freezer races it.
        admitted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let freeze_gate = gate.clone();
        scope.spawn(move || {
            freeze_gate.freeze(|| {
                entered_tx.send(()).unwrap();
                freeze_release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            });
            done_tx.send(()).unwrap();
        });
        wait_until(|| gate.is_frozen());
        assert_eq!(mutation_error(&gate), Some(libc::EAGAIN));
        assert!(entered_rx.try_recv().is_err(), "freeze closure ran before the admitted mutation drained");
        release_tx.send(()).unwrap();
        dropped_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(gate.active_mutators(), 0);
        assert_eq!(mutation_error(&gate), Some(libc::EAGAIN));
        freeze_release_tx.send(()).unwrap();
        done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(gate.phase(), GatePhase::Healthy);
        drop(gate.mutation().expect("thaw admits mutations"));
        assert_eq!(gate.active_mutators(), 0);
    });
}

#[test]
fn fence_is_immediate_during_freeze_and_only_a_higher_epoch_restores() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (freeze_release_tx, freeze_release_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let freeze_gate = gate.clone();
        scope.spawn(move || {
            freeze_gate.freeze(|| {
                entered_tx.send(()).unwrap();
                freeze_release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            });
            done_tx.send(()).unwrap();
        });
        wait_until(|| gate.is_frozen());
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let (fence_tx, fence_rx) = mpsc::channel();
        let fence_gate = gate.clone();
        scope.spawn(move || {
            fence_gate.fence();
            fence_tx.send(()).unwrap();
        });
        fence_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(gate.is_fenced());
        assert_eq!(mutation_error(&gate), Some(libc::EROFS));
        assert!(!gate.renew(1, deadline()), "a fenced gate must ignore its old lease renewal");
        assert_eq!(mutation_error(&gate), Some(libc::EROFS));
        assert_eq!(gate.re_authorize(1, deadline()).unwrap_err().raw_os_error(), Some(libc::ESTALE));
        assert_eq!(gate.re_authorize(2, deadline()).unwrap_err().raw_os_error(), Some(libc::EWOULDBLOCK));
        assert!(!gate.renew(1, deadline()), "a fenced gate must ignore its old lease renewal");
        freeze_release_tx.send(()).unwrap();
        done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(gate.phase(), GatePhase::Fenced);
        gate.re_authorize(2, deadline()).expect("a higher epoch restores writes after the freeze");
        assert_eq!(gate.phase(), GatePhase::Healthy);
        let guard = gate.mutation().expect("re-authorized gate admits after freeze");
        assert_eq!(guard.epoch(), 2);
        drop(guard);

        gate.fence();
        assert!(!gate.renew(2, deadline()), "renewal must not clear a fence");
        assert_eq!(gate.re_authorize(2, deadline()).unwrap_err().raw_os_error(), Some(libc::ESTALE));
        gate.re_authorize(3, deadline()).expect("only a strictly higher epoch restores writes");
        assert_eq!(gate.phase(), GatePhase::Healthy);
    });
}

#[test]
fn fence_wakes_a_frozen_waiter_with_erofs() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (freeze_release_tx, freeze_release_rx) = mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let freeze_gate = gate.clone();
        scope.spawn(move || {
            freeze_gate.freeze(|| {
                entered_tx.send(()).unwrap();
                freeze_release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            });
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let (result_tx, result_rx) = mpsc::channel();
        let waiter_gate = gate.clone();
        scope.spawn(move || {
            let outcome = waiter_gate.wait_for_mutation(Duration::from_secs(30));
            result_tx.send(outcome.err().and_then(|error| error.raw_os_error())).unwrap();
        });
        gate.fence();
        let error = result_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(error, Some(libc::EROFS));
        freeze_release_tx.send(()).unwrap();
    });
}

#[test]
fn panic_and_error_paths_release_admission_and_preserve_fence() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let panicking_gate = gate.clone();
    let panicked = std::thread::spawn(move || {
        let _guard = panicking_gate.mutation().expect("healthy gate admits");
        panic!("mutator panic");
    });
    assert!(panicked.join().is_err());
    assert_eq!(gate.active_mutators(), 0);
    assert_eq!(gate.phase(), GatePhase::Healthy);

    let errored = catch_unwind(AssertUnwindSafe(|| {
        gate.freeze(|| -> io::Result<()> { Err(io::Error::other("mutation failed")) })
    }));
    assert_eq!(errored.expect("error path must not panic").unwrap_err().to_string(), "mutation failed");
    assert_eq!(gate.phase(), GatePhase::Healthy);

    let freeze_panic = catch_unwind(AssertUnwindSafe(|| gate.freeze(|| panic!("freeze panic"))));
    assert!(freeze_panic.is_err());
    assert_eq!(gate.phase(), GatePhase::Healthy);

    gate.fence();
    let fenced_panic = catch_unwind(AssertUnwindSafe(|| gate.freeze(|| panic!("fenced freeze panic"))));
    assert!(fenced_panic.is_err());
    assert!(gate.is_fenced());
    assert_eq!(mutation_error(&gate), Some(libc::EROFS));
    gate.re_authorize(2, deadline()).unwrap();
}

#[test]
fn freeze_from_an_admitted_mutation_fails_fast_instead_of_deadlocking() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let guard = gate.mutation().unwrap();
    let outcome = catch_unwind(AssertUnwindSafe(|| gate.freeze(|| ())));
    assert!(outcome.is_err());
    drop(guard);
    assert_eq!(gate.active_mutators(), 0);
    assert_eq!(gate.phase(), GatePhase::Healthy);
}

#[test]
fn concurrent_freezes_are_serialized_until_the_first_closure_releases() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let (first_entered_tx, first_entered_rx) = mpsc::channel();
    let (first_release_tx, first_release_rx) = mpsc::channel::<()>();
    let (first_done_tx, first_done_rx) = mpsc::channel();
    let (second_entered_tx, second_entered_rx) = mpsc::channel();
    let (second_done_tx, second_done_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let first_gate = gate.clone();
        scope.spawn(move || {
            first_gate.freeze(|| {
                first_entered_tx.send(()).unwrap();
                first_release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            });
            first_done_tx.send(()).unwrap();
        });
        first_entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let second_gate = gate.clone();
        scope.spawn(move || {
            second_gate.freeze(|| {
                second_entered_tx.send(()).unwrap();
            });
            second_done_tx.send(()).unwrap();
        });
        assert!(second_entered_rx.try_recv().is_err(), "second freeze entered before the first released");
        assert_eq!(gate.phase(), GatePhase::Frozen);
        assert_eq!(mutation_error(&gate), Some(libc::EAGAIN));
        first_release_tx.send(()).unwrap();
        first_done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        second_entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        second_done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(gate.phase(), GatePhase::Healthy);
        drop(gate.mutation().unwrap());
    });
}

#[test]
fn nested_freeze_on_one_thread_fails_fast_instead_of_deadlocking() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let outcome = catch_unwind(AssertUnwindSafe(|| gate.freeze(|| gate.freeze(|| ()))));
    assert!(outcome.is_err());
    assert_eq!(gate.phase(), GatePhase::Healthy);
    assert!(!gate.active_freeze());
}

#[test]
fn re_authorize_is_busy_until_the_old_active_guard_is_dropped() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let (admitted_tx, admitted_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (dropped_tx, dropped_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let mutator_gate = gate.clone();
        scope.spawn(move || {
            let guard = mutator_gate.mutation().expect("initial epoch admits");
            admitted_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(guard);
            dropped_tx.send(()).unwrap();
        });
        admitted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        gate.fence();
        assert_eq!(gate.re_authorize(2, deadline()).unwrap_err().raw_os_error(), Some(libc::EWOULDBLOCK));
        assert_eq!(mutation_error(&gate), Some(libc::EROFS));
        release_tx.send(()).unwrap();
        dropped_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(gate.active_mutators(), 0);
        assert!(gate.is_fenced());
        gate.re_authorize(2, deadline()).expect("explicit retry succeeds after the old guard drains");
        assert_eq!(gate.phase(), GatePhase::Healthy);
        let guard = gate.mutation().expect("new epoch admits mutations");
        assert_eq!(guard.epoch(), 2);
        drop(guard);
    });
}

#[test]
fn handoff_renews_the_same_epoch_without_fencing() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    gate.handoff(1, deadline() + 60).expect("an unchanged epoch only renews the deadline");
    assert_eq!(gate.phase(), GatePhase::Healthy);
    assert_eq!(gate.epoch(), 1);
    let guard = gate.mutation().expect("the renewed epoch still admits mutations");
    assert_eq!(guard.epoch(), 1);
    drop(guard);
}

#[test]
fn lease_handoff_fences_the_old_epoch_before_authorizing_the_new_one() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let (admitted_tx, admitted_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let (dropped_tx, dropped_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let old = gate.clone();
        scope.spawn(move || {
            let guard = old.mutation().expect("epoch 1 admits a mutation before the commit");
            assert_eq!(guard.epoch(), 1);
            admitted_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(guard);
            dropped_tx.send(()).unwrap();
        });
        admitted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // The database committed epoch 2 while a mutation admitted under epoch 1
        // has not drained: the handoff fences first and reports the busy gate.
        assert_eq!(gate.handoff(2, deadline()).unwrap_err().raw_os_error(), Some(libc::EWOULDBLOCK));
        assert_eq!(gate.phase(), GatePhase::Fenced);
        assert_eq!(gate.fenced_epoch(), 1);
        assert_eq!(mutation_error(&gate), Some(libc::EROFS), "a second old-epoch mutation is refused");
        release_tx.send(()).unwrap();
        dropped_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(gate.active_mutators(), 0);
        assert_eq!(gate.phase(), GatePhase::Fenced, "dropping the old guard must not thaw the fence");
        gate.handoff(2, deadline()).expect("the committed epoch is authorized once the old guard drains");
        assert_eq!(gate.phase(), GatePhase::Healthy);
        let guard = gate.mutation().expect("epoch 2 admits mutations");
        assert_eq!(guard.epoch(), 2);
        drop(guard);
        // The same handoff path refuses to move back to the superseded epoch.
        assert_eq!(gate.handoff(1, deadline()).unwrap_err().raw_os_error(), Some(libc::ESTALE));
        assert_eq!(gate.phase(), GatePhase::Healthy);
        let guard = gate.mutation().expect("a stale handoff leaves the committed epoch writable");
        assert_eq!(guard.epoch(), 2, "the old epoch never comes back");
        drop(guard);
    });
}

#[test]
fn frozen_handoff_stays_fenced_when_the_commit_fails_panics_or_is_cancelled() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let failed = gate.freeze_then_fence(|| Err::<(), _>(io::Error::other("commit failed")));
    assert_eq!(failed.expect_err("the commit error is returned to the caller").to_string(), "commit failed");
    assert!(gate.is_fenced(), "a failed commit leaves the old epoch fenced");
    assert!(!gate.active_freeze());
    assert_eq!(mutation_error(&gate), Some(libc::EROFS));
    assert!(!gate.renew(1, deadline()), "renewal must not clear the fence");
    gate.handoff(2, deadline()).expect("the next committed epoch restores writes");
    assert_eq!(gate.phase(), GatePhase::Healthy);

    let panicked = catch_unwind(AssertUnwindSafe(|| gate.freeze_then_fence(|| panic!("commit panicked"))));
    assert!(panicked.is_err());
    assert!(gate.is_fenced(), "an unknown commit result leaves the gate fenced");
    assert!(!gate.active_freeze());
    gate.handoff(3, deadline()).expect("only an explicit higher epoch thaws the fence");

    // Cancellation: the caller drops its future, so the frozen closure ends
    // without a commit result. The dropped completion signal is not a thaw.
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let cancelled = gate.clone();
        scope.spawn(move || {
            cancelled.freeze_then_fence(|| {
                entered_tx.send(()).unwrap();
                assert!(release_rx.recv().is_err(), "the cancelled caller dropped its completion signal");
            });
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(gate.is_frozen());
        drop(release_tx);
        wait_until(|| !gate.active_freeze() && gate.is_fenced());
    });
    assert_eq!(gate.epoch(), 3, "a cancellation must not authorize another epoch");
    assert_eq!(mutation_error(&gate), Some(libc::EROFS));
    gate.handoff(4, deadline()).expect("the retried lease commit re-authorizes the mount");
    assert_eq!(gate.phase(), GatePhase::Healthy);
}

#[test]
fn known_precommit_rollback_thaws_the_original_epoch() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let outcome = gate.freeze_with_decision(|| {
        (Err::<(), _>(io::Error::other("lease conflict before commit")), FreezeDecision::Thaw)
    });
    assert_eq!(outcome.expect_err("the conflict reaches the caller").to_string(), "lease conflict before commit");
    assert_eq!(gate.phase(), GatePhase::Healthy, "a proven rollback must not leave epoch 1 fenced");
    assert_eq!(gate.epoch(), 1);
    let guard = gate.mutation().expect("the rolled-back epoch still admits writes");
    assert_eq!(guard.epoch(), 1);
    drop(guard);
}

#[test]
fn unknown_commit_outcome_fences_until_the_next_handoff() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let outcome =
        gate.freeze_with_decision(|| (Err::<(), _>(io::Error::other("commit transport error")), FreezeDecision::Fence));
    assert!(outcome.is_err());
    assert!(gate.is_fenced(), "an unknown COMMIT outcome must stay fenced");
    assert_eq!(mutation_error(&gate), Some(libc::EROFS));
    assert!(!gate.renew(1, deadline()));
    gate.handoff(2, deadline()).expect("only the next committed epoch restores writes");
    assert_eq!(gate.phase(), GatePhase::Healthy);
}

#[test]
fn committed_success_fences_until_the_next_handoff() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let outcome = gate.freeze_with_decision(|| (Ok::<_, io::Error>(()), FreezeDecision::Fence));
    assert!(outcome.is_ok());
    assert!(gate.is_fenced(), "a successful commit leaves the superseded epoch fenced");
    assert_eq!(mutation_error(&gate), Some(libc::EROFS));
    gate.handoff(2, deadline()).expect("the committed epoch is authorized explicitly");
    assert_eq!(gate.phase(), GatePhase::Healthy);
    let guard = gate.mutation().unwrap();
    assert_eq!(guard.epoch(), 2);
    drop(guard);
}

#[test]
fn cancelled_frozen_commit_defaults_to_fence() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let cancelled = gate.clone();
        scope.spawn(move || {
            cancelled.freeze_with_decision(|| {
                entered_tx.send(()).unwrap();
                let decision = match release_rx.recv() {
                    Ok(()) => FreezeDecision::Thaw,
                    Err(_) => FreezeDecision::Fence,
                };
                ((), decision)
            });
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(gate.is_frozen());
        drop(release_tx);
        wait_until(|| !gate.active_freeze() && gate.is_fenced());
    });
    assert_eq!(gate.epoch(), 1, "cancellation must not authorize another epoch");
    assert_eq!(mutation_error(&gate), Some(libc::EROFS));
    gate.handoff(2, deadline()).expect("a later committed epoch restores writes");
}

#[test]
fn a_stale_lease_observation_after_handoff_keeps_the_new_epoch_healthy() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let newer = deadline() + 600;
    gate.handoff(2, newer).expect("epoch 2 is authorized");
    let barrier = Arc::new(Barrier::new(2));
    let observer = {
        let gate = gate.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            gate.observe_lease(1, 0)
        })
    };
    barrier.wait();
    assert_eq!(observer.join().unwrap(), LeaseObservation::Stale);
    assert_eq!(gate.phase(), GatePhase::Healthy);
    assert_eq!(gate.epoch(), 2);
    assert_eq!(gate.writable_until(), newer, "a stale observation must not lower the deadline");
    assert_eq!(gate.observe_lease(2, newer + 60), LeaseObservation::Renewed);
    assert_eq!(gate.writable_until(), newer + 60, "an equal healthy observation renews");
    let guard = gate.mutation().expect("the newer handoff remains writable");
    assert_eq!(guard.epoch(), 2);
    drop(guard);
}

#[test]
fn a_newer_lease_observation_fences_but_does_not_authorize() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    gate.handoff(2, deadline()).expect("epoch 2 is authorized");
    assert_eq!(gate.observe_lease(3, deadline()), LeaseObservation::Fenced);
    assert_eq!(gate.phase(), GatePhase::Fenced);
    assert_eq!(gate.epoch(), 2, "observation never authorizes the epoch it saw");
    assert_eq!(mutation_error(&gate), Some(libc::EROFS));
    assert!(!gate.renew(2, deadline()));
    assert_eq!(
        gate.observe_lease(2, deadline()),
        LeaseObservation::Stale,
        "epoch 2 is below the highest observed epoch and is ignored"
    );
    assert!(gate.is_fenced());
    gate.handoff(3, deadline()).expect("only an explicit epoch-3 handoff restores writes");
    assert_eq!(gate.phase(), GatePhase::Healthy);
    assert_eq!(gate.epoch(), 3);
}

#[test]
fn a_missing_row_fences_only_when_the_gate_did_not_advance() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    let before_handoff = gate.lease_marker();
    gate.handoff(2, deadline()).expect("a concurrent handoff advances the gate");
    assert!(!gate.fence_if_unchanged(before_handoff), "an old missing snapshot must not fence epoch 2");
    assert_eq!(gate.phase(), GatePhase::Healthy);
    assert_eq!(gate.epoch(), 2);
    let current = gate.lease_marker();
    assert!(gate.fence_if_unchanged(current), "a current missing row fences the epoch");
    assert!(gate.is_fenced());
    assert_eq!(gate.observe_lease(2, deadline()), LeaseObservation::Blocked);
    assert!(!gate.fence_if_unchanged(current), "a fenced gate is not fenced twice");
    gate.handoff(3, deadline()).expect("an explicit newer handoff restores writes");
    assert_eq!(gate.phase(), GatePhase::Healthy);
    assert_eq!(gate.epoch(), 3);
}

#[test]
fn a_delayed_handoff_below_the_observed_epoch_stays_fenced() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    assert_eq!(gate.observe_lease(3, deadline()), LeaseObservation::Fenced);
    assert_eq!(gate.epoch(), 1, "observation never authorizes the epoch it saw");
    assert_eq!(gate.fenced_epoch(), 1, "the fence floor names the epoch that was actually served");
    let stale = gate.handoff(2, deadline()).unwrap_err();
    assert_eq!(stale.raw_os_error(), Some(libc::ESTALE), "epoch 2 is older than the observed epoch 3");
    assert_eq!(gate.phase(), GatePhase::Fenced);
    assert_eq!(gate.epoch(), 1);
    assert_eq!(mutation_error(&gate), Some(libc::EROFS));
    let stale = gate.re_authorize(2, deadline()).unwrap_err();
    assert_eq!(stale.raw_os_error(), Some(libc::ESTALE), "re_authorize must not bypass the observed epoch");
    assert_eq!(gate.phase(), GatePhase::Fenced);
    assert_eq!(gate.epoch(), 1);
    gate.handoff(3, deadline()).expect("the explicitly observed epoch is still authorized");
    assert_eq!(gate.phase(), GatePhase::Healthy);
    assert_eq!(gate.epoch(), 3);
    let guard = gate.mutation().expect("the epoch-3 handoff is writable");
    assert_eq!(guard.epoch(), 3);
}

#[test]
fn a_higher_observation_advances_the_marker_even_while_fenced() {
    let gate = MutationGate::new_with_lease(1, deadline()).unwrap();
    assert_eq!(gate.observe_lease(3, deadline()), LeaseObservation::Fenced);
    let after_three = gate.lease_marker();
    assert_eq!(after_three.0, 1, "observation never changes the authorized epoch");
    assert_eq!(gate.observe_lease(4, deadline()), LeaseObservation::Fenced);
    let after_four = gate.lease_marker();
    assert_ne!(after_four.1, after_three.1, "a higher observation must advance the generation while fenced");
    assert_eq!(after_four.0, 1);
    assert_eq!(gate.handoff(3, deadline()).unwrap_err().raw_os_error(), Some(libc::ESTALE));
    assert_eq!(gate.epoch(), 1);
    assert_eq!(gate.phase(), GatePhase::Fenced);
    assert_eq!(
        gate.observe_lease(3, deadline()),
        LeaseObservation::Stale,
        "an observation below the highest is ignored"
    );
    assert!(gate.is_fenced());
    gate.handoff(4, deadline()).expect("the highest observed epoch restores writes");
    assert_eq!(gate.epoch(), 4);
    let until = gate.writable_until();
    assert_eq!(gate.observe_lease(2, 0), LeaseObservation::Stale);
    assert_eq!(gate.writable_until(), until, "a stale observation must not lower the deadline");
}
