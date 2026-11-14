//! Process-wide LFS verification concurrency limiter and singleflight table.
//!
//! Asynchronous HTTP Batch/download entrypoints (`verify_local`,
//! `open_verified_file`) and synchronous integrity callers (`verify_path_blocking`
//! from CI dependency checks, mirror preparation, backup inventory, and
//! publication race fallback) share one deadline-bounded eight-slot FIFO pool.
//! Async callers wait on `tokio::sync::Notify` before `spawn_blocking` so queued
//! requests never consume blocking-pool threads; synchronous callers wait on the
//! same FIFO ticket queue through `std::sync::Condvar::wait_timeout`. Every caller
//! enters `register_flight` only after holding its `SlotPermit`, so a
//! `FlightLeader` never waits for a second slot while singleflight followers hold
//! permits.
use super::verification::FileIdentity;
use anyhow::{Result, ensure};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Condvar, LazyLock, Mutex},
    time::Instant,
};
use tokio::sync::Notify;

pub(super) const MAX_CONCURRENT_VERIFICATIONS: usize = 8;

#[derive(Default)]
struct LimiterState {
    in_use: usize,
    next_ticket: u64,
    queue: VecDeque<u64>,
}

struct VerificationLimiter {
    state: Mutex<LimiterState>,
    condvar: Condvar,
    notify: Notify,
}

pub(super) struct SlotPermit {
    limiter: &'static VerificationLimiter,
}

impl Drop for SlotPermit {
    fn drop(&mut self) {
        let should_wake = {
            let mut state = self.limiter.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            debug_assert!(state.in_use > 0);
            state.in_use = state.in_use.saturating_sub(1);
            state.in_use < MAX_CONCURRENT_VERIFICATIONS && !state.queue.is_empty()
        };
        if should_wake {
            self.limiter.wake_waiters();
        }
    }
}

struct WaitTicketGuard {
    limiter: &'static VerificationLimiter,
    ticket: u64,
    queued: bool,
}

impl WaitTicketGuard {
    fn remove_from_queue(state: &mut LimiterState, ticket: u64) -> bool {
        let was_front = state.queue.front() == Some(&ticket);
        if was_front {
            state.queue.pop_front();
        } else if let Some(pos) = state.queue.iter().position(|entry| *entry == ticket) {
            state.queue.remove(pos);
        }
        was_front && state.in_use < MAX_CONCURRENT_VERIFICATIONS && !state.queue.is_empty()
    }
}

impl Drop for WaitTicketGuard {
    fn drop(&mut self) {
        if !self.queued {
            return;
        }
        let should_wake = {
            let mut state = self.limiter.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            Self::remove_from_queue(&mut state, self.ticket)
        };
        if should_wake {
            self.limiter.wake_waiters();
        }
    }
}

impl VerificationLimiter {
    fn new() -> Self {
        Self { state: Mutex::new(LimiterState::default()), condvar: Condvar::new(), notify: Notify::new() }
    }

    fn wake_waiters(&self) {
        self.condvar.notify_all();
        self.notify.notify_waiters();
    }

    async fn acquire_async(&'static self, deadline: tokio::time::Instant) -> Result<SlotPermit> {
        ensure!(tokio::time::Instant::now() < deadline, "LFS verification concurrency wait timed out");
        let mut ticket_guard = {
            let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.in_use < MAX_CONCURRENT_VERIFICATIONS && state.queue.is_empty() {
                state.in_use += 1;
                return Ok(SlotPermit { limiter: self });
            }
            let ticket = state.next_ticket;
            state.next_ticket = state.next_ticket.wrapping_add(1);
            state.queue.push_back(ticket);
            WaitTicketGuard { limiter: self, ticket, queued: true }
        };
        let ticket = ticket_guard.ticket;
        loop {
            ensure!(tokio::time::Instant::now() < deadline, "LFS verification concurrency wait timed out");
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Enable the waiter before checking the FIFO predicate under the mutex so
            // a concurrent `SlotPermit::drop` or front-ticket removal cannot fall
            // between the predicate check and `.await` without waking this future.
            notified.as_mut().enable();
            let acquired = {
                let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if state.in_use < MAX_CONCURRENT_VERIFICATIONS && state.queue.front() == Some(&ticket) {
                    state.queue.pop_front();
                    state.in_use += 1;
                    ticket_guard.queued = false;
                    Some(state.in_use < MAX_CONCURRENT_VERIFICATIONS && !state.queue.is_empty())
                } else {
                    None
                }
            };
            if let Some(wake_next) = acquired {
                if wake_next {
                    self.wake_waiters();
                }
                return Ok(SlotPermit { limiter: self });
            }
            tokio::time::timeout_at(deadline, notified)
                .await
                .map_err(|_| anyhow::anyhow!("LFS verification concurrency wait timed out"))?;
        }
    }

    fn acquire_blocking(&'static self, deadline: Instant) -> Result<SlotPermit> {
        ensure!(Instant::now() < deadline, "LFS verification concurrency wait timed out");
        // Declare `ticket_guard` before `state` so reverse drop order always
        // unlocks `state` before `WaitTicketGuard::drop` re-locks `self.state`.
        let mut ticket_guard = WaitTicketGuard { limiter: self, ticket: 0, queued: false };
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.in_use < MAX_CONCURRENT_VERIFICATIONS && state.queue.is_empty() {
            state.in_use += 1;
            return Ok(SlotPermit { limiter: self });
        }
        let ticket = state.next_ticket;
        state.next_ticket = state.next_ticket.wrapping_add(1);
        state.queue.push_back(ticket);
        ticket_guard.ticket = ticket;
        ticket_guard.queued = true;

        loop {
            if state.in_use < MAX_CONCURRENT_VERIFICATIONS && state.queue.front() == Some(&ticket) {
                state.queue.pop_front();
                state.in_use += 1;
                ticket_guard.queued = false;
                let wake_next = state.in_use < MAX_CONCURRENT_VERIFICATIONS && !state.queue.is_empty();
                drop(state);
                if wake_next {
                    self.wake_waiters();
                }
                return Ok(SlotPermit { limiter: self });
            }
            let now = Instant::now();
            if now >= deadline {
                drop(state);
                anyhow::bail!("LFS verification concurrency wait timed out");
            }
            let (next, timeout) = self
                .condvar
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if timeout.timed_out()
                && !(state.in_use < MAX_CONCURRENT_VERIFICATIONS && state.queue.front() == Some(&ticket))
            {
                drop(state);
                anyhow::bail!("LFS verification concurrency wait timed out");
            }
        }
    }

    #[cfg(test)]
    fn available_slots(&self) -> usize {
        let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        MAX_CONCURRENT_VERIFICATIONS.saturating_sub(state.in_use)
    }

    #[cfg(test)]
    fn queued_waiters(&self) -> usize {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).queue.len()
    }
}

static VERIFICATION_LIMITER: LazyLock<VerificationLimiter> = LazyLock::new(VerificationLimiter::new);

pub(super) async fn acquire_verification_slot(deadline: tokio::time::Instant) -> Result<SlotPermit> {
    VERIFICATION_LIMITER.acquire_async(deadline).await
}

pub(super) fn acquire_verification_slot_blocking(deadline: Instant) -> Result<SlotPermit> {
    VERIFICATION_LIMITER.acquire_blocking(deadline)
}

#[cfg(test)]
pub(super) fn available_verification_slots() -> usize {
    VERIFICATION_LIMITER.available_slots()
}

#[cfg(test)]
pub(super) fn queued_verification_waiters() -> usize {
    VERIFICATION_LIMITER.queued_waiters()
}

/// Result shared by every caller that admitted the same exact file identity.
#[derive(Clone, Debug)]
pub(super) enum FlightResult {
    Verified,
    Mismatch,
    /// The leader's own caller deadline expired before completing the hash pass;
    /// followers whose own deadlines remain valid re-register and elect a new leader.
    LeaderTimedOut,
    Failed(String),
}

struct FlightState {
    result: Option<FlightResult>,
}

/// One digest pass per admitted identity. The leader hashes its descriptor;
/// followers wait on a deadline-bounded condition variable and never open the
/// path again, so they cannot observe a different inode. A cancelled async
/// request cannot abandon a published partial cache entry: the blocking leader
/// owns the flight and only inserts the cache after the identity re-check.
pub(super) struct VerificationFlight {
    state: Mutex<FlightState>,
    finished: Condvar,
}

impl VerificationFlight {
    fn new() -> Self {
        Self { state: Mutex::new(FlightState { result: None }), finished: Condvar::new() }
    }

    pub(super) fn wait(&self, deadline: Instant) -> Result<FlightResult> {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if let Some(result) = state.result.clone() {
                return Ok(result);
            }
            let now = Instant::now();
            ensure!(now < deadline, "LFS integrity verification timed out");
            let (next, timeout) = self
                .finished
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if timeout.timed_out() && state.result.is_none() {
                anyhow::bail!("LFS integrity verification timed out");
            }
        }
    }

    fn complete(&self, result: FlightResult) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.result.is_none() {
            state.result = Some(result);
            self.finished.notify_all();
        }
    }
}

static VERIFICATION_FLIGHTS: LazyLock<Mutex<HashMap<FileIdentity, Arc<VerificationFlight>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn flights() -> std::sync::MutexGuard<'static, HashMap<FileIdentity, Arc<VerificationFlight>>> {
    VERIFICATION_FLIGHTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Leader ownership guard: even a panic inside the blocking digest pass removes
/// the map entry first and then wakes followers with a failure instead of
/// wedging future readers behind a permanently incomplete flight.
pub(super) struct FlightLeader {
    identity: FileIdentity,
    flight: Arc<VerificationFlight>,
    completed: bool,
}

impl FlightLeader {
    pub(super) fn complete(mut self, result: FlightResult) {
        self.publish(result);
        self.completed = true;
    }

    fn publish(&self, result: FlightResult) {
        {
            let mut flights = flights();
            if flights.get(&self.identity).is_some_and(|entry| Arc::ptr_eq(entry, &self.flight)) {
                flights.remove(&self.identity);
            }
        }
        self.flight.complete(result);
    }
}

impl Drop for FlightLeader {
    fn drop(&mut self) {
        if !self.completed {
            self.publish(FlightResult::Failed("LFS verification worker panicked".to_owned()));
        }
    }
}

pub(super) enum FlightRegistration {
    Leader(FlightLeader),
    Follower(Arc<VerificationFlight>),
}

#[cfg(test)]
static FLIGHT_FOLLOWERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(super) fn register_flight(identity: &FileIdentity) -> FlightRegistration {
    let mut flights = flights();
    if let Some(existing) = flights.get(identity) {
        #[cfg(test)]
        FLIGHT_FOLLOWERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        FlightRegistration::Follower(existing.clone())
    } else {
        let flight = Arc::new(VerificationFlight::new());
        flights.insert(identity.clone(), flight.clone());
        FlightRegistration::Leader(FlightLeader { identity: identity.clone(), flight, completed: false })
    }
}

#[cfg(test)]
pub(super) fn flight_follower_count() -> usize {
    FLIGHT_FOLLOWERS.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
pub(super) fn active_flight_count() -> usize {
    flights().len()
}

#[cfg(test)]
#[derive(Default)]
struct TestHashGateState {
    active: usize,
    hold: bool,
}

#[cfg(test)]
pub(super) struct TestHashGate {
    state: Mutex<TestHashGateState>,
    changed: Condvar,
}

#[cfg(test)]
impl TestHashGate {
    fn enter(&self, deadline: Instant) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.hold {
            return true;
        }
        state.active += 1;
        self.changed.notify_all();
        let mut timed_out = false;
        while state.hold {
            let now = Instant::now();
            if now >= deadline {
                timed_out = true;
                break;
            }
            let (next, wait_res) = self
                .changed
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if wait_res.timed_out() && state.hold {
                timed_out = true;
                break;
            }
        }
        state.active -= 1;
        self.changed.notify_all();
        !timed_out
    }

    pub(super) fn set_hold(&self, hold: bool) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.hold = hold;
        self.changed.notify_all();
    }

    pub(super) fn active(&self) -> usize {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).active
    }
}

#[cfg(test)]
pub(super) static HASH_GATE: LazyLock<TestHashGate> =
    LazyLock::new(|| TestHashGate { state: Mutex::new(TestHashGateState::default()), changed: Condvar::new() });

pub(super) fn hash_gate_enter(deadline: Instant) -> bool {
    #[cfg(test)]
    {
        HASH_GATE.enter(deadline)
    }
    #[cfg(not(test))]
    {
        let _ = deadline;
        true
    }
}

#[cfg(test)]
#[path = "verification_limiter_tests.rs"]
mod tests;
