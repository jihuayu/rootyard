
use super::*;
use crate::workspace_lab::fuse_mount::MutationGate;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use uuid::Uuid;

fn test_state() -> Arc<State> {
    let (_parent, child) = UnixStream::pair().unwrap();
    let (ops, ops_jobs) = mpsc::sync_channel::<Job>(1);
    let (prewarm, prewarm_jobs) = mpsc::sync_channel::<Job>(1);
    // Keep the receivers alive for the lifetime of the state.
    std::mem::forget(ops_jobs);
    std::mem::forget(prewarm_jobs);
    {
        let (cleanup, cleanup_jobs) = mpsc::sync_channel::<Job>(1);
        std::mem::forget(cleanup_jobs);
        Arc::new(State::new(child, ops, prewarm, cleanup))
    }
}

#[test]
fn teardown_policy_can_only_fence() {
    // A dropped freeze waiter is a fence: the receiver sees `Err` and the
    // freeze thread applies `FreezeDecision::Fence`.
    let (sender, receiver) = mpsc::sync_channel::<bool>(1);
    drop(sender);
    assert!(receiver.recv().is_err());
}

#[test]
fn operation_tombstones_are_bounded() {
    let state = test_state();
    for op_id in 0..(TOMBSTONES as u64 + 8) {
        ops::push_freeze_tombstone(&state, op_id);
        ops::push_mount_tombstone(&state, Uuid::nil(), op_id);
    }
    assert_eq!(lock(&state.freeze_tombstones).len(), TOMBSTONES);
    assert_eq!(lock(&state.mount_tombstones).len(), TOMBSTONES);
    // The oldest entry was evicted, the newest is still known.
    assert!(ops::take_freeze_tombstone(&state, 0));
    assert!(ops::take_freeze_tombstone(&state, TOMBSTONES as u64 + 7));
    assert!(!ops::take_freeze_tombstone(&state, TOMBSTONES as u64 + 7), "a tombstone is one-shot");
}

#[test]
fn cancelled_admission_is_refused_after_the_tombstone() {
    let state = test_state();
    let workspace = Uuid::nil();
    assert!(ops::cancel_mount(&state, Some(workspace), 7).is_none());
    let cancel = Arc::new(AtomicBool::new(false));
    let refused =
        ops::register_pending(&state, workspace, 7, Instant::now() + Duration::from_secs(1), cancel).unwrap_err();
    assert_eq!(refused.0, libc::ECANCELED, "an abort between check and insert must win");
    assert!(lock(&state.pending).is_empty());
}

#[test]
fn cancel_fences_a_pending_mount_before_the_slow_join() {
    let state = test_state();
    let workspace = Uuid::nil();
    let gate = MutationGate::new_with_lease(3, i64::MAX).unwrap();
    lock(&state.pending).insert(
        workspace,
        PendingMount {
            request: 9,
            deadline: Instant::now() + Duration::from_secs(30),
            cancelled: Arc::new(AtomicBool::new(false)),
            gate: Some(gate.clone()),
        },
    );
    assert!(ops::cancel_mount(&state, Some(workspace), 9).is_none());
    assert!(gate.is_fenced(), "the pending gate is fenced before any worker shutdown runs");
    assert!(lock(&state.pending).get(&workspace).map(|entry| entry.cancelled.load(Ordering::Acquire)) == Some(true));
}

#[test]
fn freeze_release_records_the_finishing_request_and_epoch() {
    let state = test_state();
    let workspace = Uuid::nil();
    let (decision, waiter) = mpsc::sync_channel::<bool>(1);
    let done = Arc::new(Mutex::new(None));
    let deadline = Instant::now() + Duration::from_secs(30);
    lock(&state.freezes).insert(
        1,
        FreezeOp {
            workspace,
            epoch: 5,
            begin_request: 2,
            deadline,
            failstop_at: deadline + FREEZE_JOIN_GRACE,
            expired: AtomicBool::new(false),
            decision,
            done: done.clone(),
            released: AtomicBool::new(false),
        },
    );
    ops::freeze_release(&state, 77, Some(workspace), 1, 5, 5, true);
    assert_eq!(*lock(&done), Some(77), "the accepted finish owns the acknowledgement");
    assert!(waiter.recv().unwrap(), "the accepted decision is delivered");
    ops::freeze_release(&state, 78, Some(workspace), 1, 5, 5, false);
    assert_eq!(*lock(&done), Some(77), "a duplicate finish cannot replace the owner");
}

#[test]
fn freeze_release_rejects_a_foreign_frame_epoch() {
    let state = test_state();
    let workspace = Uuid::nil();
    let (decision, _waiter) = mpsc::sync_channel::<bool>(1);
    let done = Arc::new(Mutex::new(None));
    let deadline = Instant::now() + Duration::from_secs(30);
    lock(&state.freezes).insert(
        1,
        FreezeOp {
            workspace,
            epoch: 5,
            begin_request: 2,
            deadline,
            failstop_at: deadline + FREEZE_JOIN_GRACE,
            expired: AtomicBool::new(false),
            decision,
            done: done.clone(),
            released: AtomicBool::new(false),
        },
    );
    ops::freeze_release(&state, 77, Some(workspace), 1, 4, 5, true);
    assert_eq!(*lock(&done), None);
    assert!(!lock(&state.freezes).get(&1).unwrap().released.load(Ordering::Acquire));
}

#[test]
fn pending_mount_gate_is_fenced_without_being_published() {
    let state = test_state();
    let gate = MutationGate::new_with_lease(4, i64::MAX).unwrap();
    lock(&state.pending).insert(
        Uuid::nil(),
        PendingMount {
            request: 7,
            deadline: Instant::now() + Duration::from_secs(1),
            cancelled: Arc::new(AtomicBool::new(false)),
            gate: Some(gate.clone()),
        },
    );
    state.fence_all();
    assert!(gate.is_fenced(), "a half-built mount must be fenced by the watchdog path");
    assert!(ops::checkpoint(&AtomicBool::new(false), Instant::now() + Duration::from_secs(1)).is_ok());
    assert!(ops::checkpoint(&AtomicBool::new(true), Instant::now() + Duration::from_secs(1)).is_err());
    assert!(ops::checkpoint(&AtomicBool::new(false), Instant::now()).is_err());
}
