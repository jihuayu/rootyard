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
//!   a freeze, cannot be undone by the deadline-only [`MutationGate::renew`],
//!   and wakes blocked waiters with `EROFS`. Only an explicitly higher epoch, through
//!   [`MutationGate::re_authorize`] or the fence-then-authorize
//!   [`MutationGate::handoff`], restores the healthy state.
//! * Reads are deliberately not gated.
//!
//! Lease epochs are bound to the gate: [`MutationGate::handoff`] is the only path
//! that moves the gate to a new database epoch, and it fences the old epoch
//! before it authorizes the new one, so a rejected authorization fails closed
//! instead of leaving the superseded epoch writable. [`MutationGate::freeze_then_fence`]
//! is the frozen variant used by the same-host lease commit: the fence is taken
//! while the freeze still owns the gate, so a failed, panicking, unknown or
//! cancelled commit stays fenced rather than thawing back to the old epoch.
//!
//! This is still not the native FUSE helper. Nothing here survives process death
//! or fences a second process, and the parent-loss lifecycle remains open.
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
    freeze_active: bool,
    generation: u64,
    epoch: i64,
    fence_floor: i64,
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
    static FROZEN_GATES: RefCell<Vec<*const MutationGate>> = RefCell::new(Vec::new());
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

fn mark_frozen(gate: &MutationGate) {
    let gate = std::ptr::from_ref(gate);
    FROZEN_GATES.with(|held| held.borrow_mut().push(gate));
}

fn unmark_frozen(gate: &MutationGate) {
    let gate = std::ptr::from_ref(gate);
    FROZEN_GATES.with(|held| {
        let mut held = held.borrow_mut();
        if let Some(index) = held.iter().rposition(|candidate| std::ptr::eq(*candidate, gate)) {
            held.remove(index);
        }
    });
}

fn frozen_on_this_thread(gate: &MutationGate) -> bool {
    let gate = std::ptr::from_ref(gate);
    FROZEN_GATES.with(|held| held.borrow().iter().any(|candidate| std::ptr::eq(*candidate, gate)))
}

impl MutationGate {
    /// Create a healthy gate from the real database lease epoch and deadline.
    ///
    /// There is no zero-epoch fallback: a database epoch must be positive, and
    /// both the authorized epoch and the fence floor start at that value so an
    /// old `re_authorize` can never revive the lease.
    pub fn new_with_lease(db_epoch: i64, writable_until: i64) -> io::Result<Arc<Self>> {
        if db_epoch <= 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(Arc::new(Self {
            state: Mutex::new(GateState {
                phase: GatePhase::Healthy,
                active_mutators: 0,
                freeze_active: false,
                generation: 0,
                epoch: db_epoch,
                fence_floor: db_epoch,
                writable_until,
            }),
            changed: Condvar::new(),
        }))
    }

    fn lock_state(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Renew the deadline only for the currently authorized database epoch.
    ///
    /// A stale epoch or any fenced state is rejected without changing the
    /// deadline. This never lifts a fence and never changes the epoch.
    pub fn renew(&self, db_epoch: i64, until: i64) -> bool {
        let mut state = self.lock_state();
        if state.phase == GatePhase::Fenced || db_epoch != state.epoch {
            return false;
        }
        state.writable_until = until;
        drop(state);
        self.changed.notify_all();
        true
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
        assert!(
            !frozen_on_this_thread(self),
            "MutationGate::freeze is not re-entrant on one thread; nested freezes must be sequenced"
        );
        let mut state = self.lock_state();
        while state.freeze_active {
            state = self.changed.wait(state).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        state.freeze_active = true;
        if state.phase == GatePhase::Healthy {
            state.phase = GatePhase::Frozen;
            state.generation = state.generation.saturating_add(1);
        }
        while state.active_mutators > 0 {
            state = self.changed.wait(state).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        drop(state);
        mark_frozen(self);
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
    /// epoch that was fenced. It is rejected with `EWOULDBLOCK` while a freeze
    /// owns the gate or an old mutation guard is still alive, so a control
    /// caller must retry after those have drained. This function never waits.
    pub fn re_authorize(&self, epoch: i64, until: i64) -> io::Result<()> {
        let mut state = self.lock_state();
        if epoch <= state.epoch || epoch <= state.fence_floor {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        if state.active_mutators > 0 || state.freeze_active {
            return Err(io::Error::from_raw_os_error(libc::EWOULDBLOCK));
        }
        state.epoch = epoch;
        state.writable_until = until;
        state.phase = GatePhase::Healthy;
        state.generation = state.generation.saturating_add(1);
        drop(state);
        self.changed.notify_all();
        Ok(())
    }

    /// Move the gate to the lease epoch the database just committed.
    ///
    /// A same-epoch call only renews the deadline, exactly like [`MutationGate::renew`].
    /// Otherwise the epoch must be strictly higher than both the epoch this gate
    /// still serves and the epoch a fence invalidated; the old epoch is fenced
    /// *before* authorization is attempted. A rejection therefore surfaces as
    /// `EWOULDBLOCK` (a freeze owns the gate, or a guard admitted under the old
    /// epoch has not drained) with the gate already `Fenced`, never as a still
    /// `Healthy` old epoch. A stale or already fenced epoch is rejected with
    /// `ESTALE` and changes nothing, so a late handoff cannot resurrect an epoch
    /// the database has moved past. This never waits.
    pub fn handoff(&self, epoch: i64, until: i64) -> io::Result<()> {
        let mut state = self.lock_state();
        if epoch < state.epoch || epoch <= state.fence_floor {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        if epoch == state.epoch && state.phase != GatePhase::Fenced {
            state.writable_until = until;
            drop(state);
            self.changed.notify_all();
            return Ok(());
        }
        state.phase = GatePhase::Fenced;
        state.fence_floor = state.fence_floor.max(state.epoch);
        state.writable_until = 0;
        state.generation = state.generation.saturating_add(1);
        if state.active_mutators > 0 || state.freeze_active {
            drop(state);
            self.changed.notify_all();
            return Err(io::Error::from_raw_os_error(libc::EWOULDBLOCK));
        }
        state.epoch = epoch;
        state.writable_until = until;
        state.phase = GatePhase::Healthy;
        state.generation = state.generation.saturating_add(1);
        drop(state);
        self.changed.notify_all();
        Ok(())
    }

    /// Freeze the gate, run `work`, and leave the old epoch fenced.
    ///
    /// This is the lease-handoff variant of [`MutationGate::freeze`]. The fence
    /// is taken while the freeze still owns the gate, before any thaw, so no
    /// mutation can be admitted under the epoch the database has just superseded
    /// in the window between the commit and the new-epoch authorization. A
    /// `work` that returns an error, panics, or never reports a result (the
    /// caller dropped its future and with it the completion signal) leaves the
    /// gate `Fenced`: dropping that signal is not a successful thaw, and the old
    /// epoch stays unwritable until [`MutationGate::handoff`] authorizes a higher
    /// one.
    pub fn freeze_then_fence<T>(&self, work: impl FnOnce() -> T) -> T {
        self.freeze(|| {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
            self.fence();
            match outcome {
                Ok(value) => value,
                Err(payload) => std::panic::resume_unwind(payload),
            }
        })
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
            let (next, _) = self.changed.wait_timeout(state, wait).unwrap_or_else(std::sync::PoisonError::into_inner);
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
    pub fn epoch(&self) -> i64 {
        self.lock_state().epoch
    }

    /// Highest epoch invalidated by a fence.
    pub fn fenced_epoch(&self) -> i64 {
        self.lock_state().fence_floor
    }

    /// Whether a freeze closure currently owns the gate.
    pub fn active_freeze(&self) -> bool {
        self.lock_state().freeze_active
    }
}

/// RAII admission permit. The mutation count is released on drop on every path.
pub struct MutationGuard<'a> {
    gate: &'a MutationGate,
    epoch: i64,
    generation: u64,
}

impl MutationGuard<'_> {
    /// Epoch that was authorized when this mutation was admitted.
    pub fn epoch(&self) -> i64 {
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
        drop(state);
        self.gate.changed.notify_all();
    }
}

struct FreezeGuard<'a> {
    gate: &'a MutationGate,
}

impl Drop for FreezeGuard<'_> {
    fn drop(&mut self) {
        unmark_frozen(self.gate);
        let mut state = self.gate.lock_state();
        state.freeze_active = false;
        let thawed = state.phase == GatePhase::Frozen;
        if thawed {
            state.phase = GatePhase::Healthy;
            state.generation = state.generation.saturating_add(1);
        }
        drop(state);
        self.gate.changed.notify_all();
    }
}

fn unix_now() -> io::Result<i64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH).map_err(io::Error::other)?.as_secs() as i64)
}

#[cfg(test)]
mod tests;
