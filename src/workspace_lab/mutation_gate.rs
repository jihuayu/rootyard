//! Process-local mutation gate for the workspace FUSE overlay.
//!
//! This gate is a *prerequisite* for an independent FUSE helper, not the helper
//! itself. The session still runs as a `fuser::BackgroundSession` inside the
//! service process, so an operator `SIGKILL` can still leave a thread blocked in
//! `request_wait_answer` while it owns the same-process FUSE descriptor. The
//! helper/parent-loss lifecycle remains open.
//!
//! Design constraints:
//!
//! * FUSE dispatch is one session thread. A write callback must never sleep on a
//!   condition variable while a read is queued behind it, so [`MutationGate::mutation`]
//!   never waits: a frozen gate returns `EAGAIN` and a fenced/expired gate returns
//!   `EROFS` before any content is changed. [`MutationGate::wait_for_mutation`]
//!   exists for future non-FUSE callers and must not be used on the session thread.
//! * A freeze stops new admissions first, then drains already admitted mutations
//!   before running its closure. The freeze acknowledgement spans the whole
//!   closure, including error and panic unwinding.
//! * [`MutationGate::fence`] is terminal for the current epoch. It never waits for
//!   a freeze, cannot be undone by the legacy deadline-only [`MutationGate::update`],
//!   and wakes blocked waiters with `EROFS`. Only an explicitly higher epoch through
//!   [`MutationGate::re_authorize`] restores the healthy state.
//! * Reads are deliberately not gated.
//!
//! The epoch/generation fields are reserved for the future helper protocol. The
//! current service only uses the legacy deadline path, and `fence` is not yet
//! wired into lease handoff.
use std::{
    cell::RefCell,
    io,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Observable gate phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatePhase {
    /// Mutations are admitted while the lease deadline is in the future.
    Healthy,
    /// A freeze owns the gate. New mutations fail with `EAGAIN`.
    Frozen,
    /// The current epoch is fenced. New mutations fail with `EROFS`.
    Fenced,
}

struct GateState {
    phase: GatePhase,
    active_mutators: usize,
    freeze_depth: usize,
    generation: u64,
    epoch: u64,
    fence_floor: u64,
    writable_until: i64,
}

/// Cooperative, process-local mutation gate.
///
/// It cannot stop arbitrary host writers and it does not survive process death;
/// both are why it is only a pre-gate for a separate helper.
pub struct MutationGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

thread_local! {
    static HELD_GATES: RefCell<Vec<*const MutationGate>> = RefCell::new(Vec::new());
}

fn mark_held(gate: &MutationGate) {
    let gate = std::ptr::from_ref(gate);
    HELD_GATES.with(|held| held.borrow_mut().push(gate));
}

fn unmark_held(gate: &MutationGate) {
    let gate = std::ptr::from_ref(gate);
    HELD_GATES.with(|held| {
        let mut held = held.borrow_mut();
        if let Some(index) = held.iter().rposition(|candidate| std::ptr::eq(*candidate, gate)) {
            held.remove(index);
        }
    });
}

fn held_on_this_thread(gate: &MutationGate) -> bool {
    let gate = std::ptr::from_ref(gate);
    HELD_GATES.with(|held| held.borrow().iter().any(|candidate| std::ptr::eq(*candidate, gate)))
}

impl MutationGate {
    /// Create a healthy gate whose lease deadline is `writable_until` (Unix
    /// seconds). The legacy constructor interface is unchanged.
    pub fn new(writable_until: i64) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(GateState {
                phase: GatePhase::Healthy,
                active_mutators: 0,
                freeze_depth: 0,
                generation: 0,
                epoch: 0,
                fence_floor: 0,
                writable_until,
            }),
            changed: Condvar::new(),
        })
    }

    fn lock_state(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Legacy deadline-only update. It is intentionally unable to clear a fence:
    /// the helper must call [`Self::re_authorize`] with a strictly higher epoch.
    pub fn update(&self, until: i64) {
        let mut state = self.lock_state();
        if state.phase == GatePhase::Fenced {
            return;
        }
        state.writable_until = until;
        drop(state);
        self.changed.notify_all();
    }

    /// Freeze the gate for the duration of `work`.
    ///
    /// New mutations are rejected before `work` starts, already admitted mutations
    /// are drained, and the closure runs only after they are gone. If the gate is
    /// fenced while frozen, dropping the guard leaves it fenced. This synchronous
    /// facade is kept for the existing checkpoint/scan callers.
    pub fn freeze<T>(&self, work: impl FnOnce() -> T) -> T {
        let _freeze = self.begin_freeze();
        work()
    }

    fn begin_freeze(&self) -> FreezeGuard<'_> {
        assert!(
            !held_on_this_thread(self),
            "MutationGate::freeze cannot run on a thread that holds an admitted mutation; it would wait on itself"
        );
        let mut state = self.lock_state();
        if state.freeze_depth == 0 {
            if state.phase == GatePhase::Healthy {
                state.phase = GatePhase::Frozen;
                state.generation = state.generation.saturating_add(1);
            }
            state.freeze_depth = 1;
        } else {
            state.freeze_depth = state.freeze_depth.saturating_add(1);
        }
        while state.active_mutators > 0 {
            state = self.changed.wait(state).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        drop(state);
        FreezeGuard { gate: self }
    }

    /// Permanently fence the current epoch until an explicit higher epoch is
    /// authorized. This never waits for a freeze or for an admitted mutator.
    pub fn fence(&self) {
        let mut state = self.lock_state();
        if state.phase == GatePhase::Fenced {
            return;
        }
        state.phase = GatePhase::Fenced;
        state.fence_floor = state.fence_floor.max(state.epoch);
        state.writable_until = 0;
        state.generation = state.generation.saturating_add(1);
        drop(state);
        self.changed.notify_all();
    }

    /// Explicitly authorize a new lease epoch and deadline.
    ///
    /// The epoch must be strictly greater than both the current epoch and the
    /// epoch that was fenced. Re-authorization during a freeze records the new
    /// epoch but does not admit mutations until the freeze guard is dropped.
    pub fn re_authorize(&self, epoch: u64, until: i64) -> io::Result<()> {
        let mut state = self.lock_state();
        if epoch <= state.epoch || epoch <= state.fence_floor {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        state.epoch = epoch;
        state.writable_until = until;
        state.phase = if state.freeze_depth == 0 { GatePhase::Healthy } else { GatePhase::Frozen };
        state.generation = state.generation.saturating_add(1);
        drop(state);
        self.changed.notify_all();
        Ok(())
    }

    /// Admit one mutation without ever blocking the caller.
    ///
    /// The returned RAII guard keeps the mutation counted until it is dropped, so
    /// errors, early returns and panics cannot leak the count. A frozen gate
    /// returns `EAGAIN`; a fenced or lease-expired gate returns `EROFS`.
    pub fn mutation(&self) -> io::Result<MutationGuard<'_>> {
        let now = unix_now()?;
        let mut state = self.lock_state();
        self.admit_locked(&mut state, now)
    }

    /// Wait for a mutation admission for a non-FUSE caller.
    ///
    /// A freeze blocks admission, a fence or lease expiry wakes the waiter with
    /// `EROFS`, and the overall timeout returns `EAGAIN`. This must not be called
    /// on the single FUSE session thread.
    pub fn wait_for_mutation(&self, timeout: Duration) -> io::Result<MutationGuard<'_>> {
        let started = Instant::now();
        let mut state = self.lock_state();
        loop {
            let now = unix_now()?;
            match state.phase {
                GatePhase::Fenced => return Err(io::Error::from_raw_os_error(libc::EROFS)),
                GatePhase::Healthy => return self.admit_locked(&mut state, now),
                GatePhase::Frozen => {}
            }
            if now >= state.writable_until {
                return Err(io::Error::from_raw_os_error(libc::EROFS));
            }
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Err(io::Error::from_raw_os_error(libc::EAGAIN));
            }
            let lease_seconds = state.writable_until.saturating_sub(now).max(1) as u64;
            let wait = (timeout - elapsed).min(Duration::from_secs(lease_seconds));
            let (next, _) = self
                .changed
                .wait_timeout(state, wait)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
        }
    }

    fn admit_locked<'a>(&'a self, state: &mut GateState, now: i64) -> io::Result<MutationGuard<'a>> {
        match state.phase {
            GatePhase::Fenced => return Err(io::Error::from_raw_os_error(libc::EROFS)),
            GatePhase::Frozen => return Err(io::Error::from_raw_os_error(libc::EAGAIN)),
            GatePhase::Healthy => {}
        }
        if now >= state.writable_until {
            return Err(io::Error::from_raw_os_error(libc::EROFS));
        }
        state.active_mutators += 1;
        let epoch = state.epoch;
        let generation = state.generation;
        mark_held(self);
        Ok(MutationGuard { gate: self, epoch, generation })
    }

    pub fn phase(&self) -> GatePhase {
        self.lock_state().phase
    }

    pub fn is_frozen(&self) -> bool {
        self.phase() == GatePhase::Frozen
    }

    pub fn is_fenced(&self) -> bool {
        self.phase() == GatePhase::Fenced
    }

    pub fn active_mutators(&self) -> usize {
        self.lock_state().active_mutators
    }

    pub fn writable_until(&self) -> i64 {
        self.lock_state().writable_until
    }

    /// Monotonic state-transition counter, reserved for the helper protocol.
    pub fn generation(&self) -> u64 {
        self.lock_state().generation
    }

    /// Current authorized lease epoch.
    pub fn epoch(&self) -> u64 {
        self.lock_state().epoch
    }

    /// Highest epoch invalidated by a fence.
    pub fn fenced_epoch(&self) -> u64 {
        self.lock_state().fence_floor
    }
}

/// RAII admission permit. The mutation count is released on drop on every path.
pub struct MutationGuard<'a> {
    gate: &'a MutationGate,
    epoch: u64,
    generation: u64,
}

impl MutationGuard<'_> {
    /// Epoch that was authorized when this mutation was admitted.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Generation observed at admission.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Drop for MutationGuard<'_> {
    fn drop(&mut self) {
        unmark_held(self.gate);
        let mut state = self.gate.lock_state();
        if state.active_mutators > 0 {
            state.active_mutators -= 1;
        }
        let drained = state.active_mutators == 0;
        drop(state);
        if drained {
            self.gate.changed.notify_all();
        }
    }
}

struct FreezeGuard<'a> {
    gate: &'a MutationGate,
}

impl Drop for FreezeGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.gate.lock_state();
        if state.freeze_depth > 0 {
            state.freeze_depth -= 1;
        }
        let thawed = state.freeze_depth == 0 && state.phase == GatePhase::Frozen;
        if thawed {
            state.phase = GatePhase::Healthy;
            state.generation = state.generation.saturating_add(1);
        }
        drop(state);
        if thawed {
            self.gate.changed.notify_all();
        }
    }
}

fn unix_now() -> io::Result<i64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::mpsc,
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
        let gate = MutationGate::new(deadline());
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
                release_rx.recv().unwrap();
                drop(guard);
                dropped_tx.send(()).unwrap();
            });
            let freeze_gate = gate.clone();
            scope.spawn(move || {
                freeze_gate.freeze(|| {
                    entered_tx.send(()).unwrap();
                    freeze_release_rx.recv().unwrap();
                });
                done_tx.send(()).unwrap();
            });
            admitted_rx.recv_timeout(Duration::from_secs(2)).unwrap();
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
        let gate = MutationGate::new(deadline());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (freeze_release_tx, freeze_release_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let freeze_gate = gate.clone();
            scope.spawn(move || {
                freeze_gate.freeze(|| {
                    entered_tx.send(()).unwrap();
                    freeze_release_rx.recv().unwrap();
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
            gate.update(deadline());
            assert_eq!(mutation_error(&gate), Some(libc::EROFS));
            assert_eq!(
                gate.re_authorize(0, deadline()).unwrap_err().raw_os_error(),
                Some(libc::ESTALE)
            );

            gate.re_authorize(1, deadline()).expect("a higher epoch authorizes while frozen");
            assert_eq!(gate.phase(), GatePhase::Frozen);
            assert_eq!(mutation_error(&gate), Some(libc::EAGAIN));
            freeze_release_tx.send(()).unwrap();
            done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(gate.phase(), GatePhase::Healthy);
            let guard = gate.mutation().expect("re-authorized gate admits after freeze");
            assert_eq!(guard.epoch(), 1);
            drop(guard);

            gate.fence();
            assert_eq!(
                gate.re_authorize(1, deadline()).unwrap_err().raw_os_error(),
                Some(libc::ESTALE)
            );
            gate.re_authorize(2, deadline()).expect("only a strictly higher epoch restores writes");
            assert_eq!(gate.phase(), GatePhase::Healthy);
        });
    }

    #[test]
    fn fence_wakes_a_frozen_waiter_with_erofs() {
        let gate = MutationGate::new(deadline());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (freeze_release_tx, freeze_release_rx) = mpsc::channel::<()>();
        std::thread::scope(|scope| {
            let freeze_gate = gate.clone();
            scope.spawn(move || {
                freeze_gate.freeze(|| {
                    entered_tx.send(()).unwrap();
                    freeze_release_rx.recv().unwrap();
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
        let gate = MutationGate::new(deadline());
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
        gate.re_authorize(1, deadline()).unwrap();
    }

    #[test]
    fn freeze_from_an_admitted_mutation_fails_fast_instead_of_deadlocking() {
        let gate = MutationGate::new(deadline());
        let guard = gate.mutation().unwrap();
        let outcome = catch_unwind(AssertUnwindSafe(|| gate.freeze(|| ())));
        assert!(outcome.is_err());
        drop(guard);
        assert_eq!(gate.active_mutators(), 0);
        assert_eq!(gate.phase(), GatePhase::Healthy);
    }

    #[test]
    fn nested_freeze_keeps_writes_blocked_until_the_outermost_guard_drops() {
        let gate = MutationGate::new(deadline());
        let (entered_tx, entered_rx) = mpsc::channel();
        let (outer_release_tx, outer_release_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let freeze_gate = gate.clone();
            scope.spawn(move || {
                freeze_gate.freeze(|| {
                    entered_tx.send(()).unwrap();
                    outer_release_rx.recv().unwrap();
                });
                done_tx.send(()).unwrap();
            });
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            gate.freeze(|| ());
            assert_eq!(gate.phase(), GatePhase::Frozen);
            assert_eq!(mutation_error(&gate), Some(libc::EAGAIN));
            outer_release_tx.send(()).unwrap();
            done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(gate.phase(), GatePhase::Healthy);
            drop(gate.mutation().unwrap());
        });
    }
}
