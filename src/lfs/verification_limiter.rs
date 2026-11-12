//! Process-wide LFS verification concurrency limiter and singleflight table.
//!
//! Asynchronous HTTP Batch/download entrypoints (`verify_local`,
//! `open_verified_file`) and synchronous integrity callers (`verify_path_blocking`
//! from CI dependency checks, mirror preparation, backup inventory, and
//! publication race fallback) share one deadline-bounded eight-slot pool.
//! Async callers wait on `tokio::sync::Notify` before `spawn_blocking` so queued
//! requests never consume blocking-pool threads; synchronous callers wait on the
//! same counter through `std::sync::Condvar::wait_timeout`. Every caller enters
//! `register_flight` only after holding its `SlotPermit`, so a `FlightLeader`
//! never waits for a second slot while singleflight followers hold permits.
use super::verification::FileIdentity;
use anyhow::{Result, ensure};
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, LazyLock, Mutex},
    time::Instant,
};
use tokio::sync::Notify;

pub(super) const MAX_CONCURRENT_VERIFICATIONS: usize = 8;

struct VerificationLimiter {
    in_use: Mutex<usize>,
    condvar: Condvar,
    notify: Notify,
}

pub(super) struct SlotPermit {
    limiter: &'static VerificationLimiter,
}

impl Drop for SlotPermit {
    fn drop(&mut self) {
        {
            let mut in_use = self.limiter.in_use.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            debug_assert!(*in_use > 0);
            *in_use = in_use.saturating_sub(1);
        }
        self.limiter.condvar.notify_all();
        self.limiter.notify.notify_waiters();
    }
}

impl VerificationLimiter {
    fn new() -> Self {
        Self { in_use: Mutex::new(0), condvar: Condvar::new(), notify: Notify::new() }
    }

    fn try_acquire(&'static self) -> Option<SlotPermit> {
        let mut in_use = self.in_use.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if *in_use < MAX_CONCURRENT_VERIFICATIONS {
            *in_use += 1;
            Some(SlotPermit { limiter: self })
        } else {
            None
        }
    }

    async fn acquire_async(&'static self, deadline: tokio::time::Instant) -> Result<SlotPermit> {
        loop {
            ensure!(tokio::time::Instant::now() < deadline, "LFS verification concurrency wait timed out");
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Enable the waiter before checking `in_use` under the mutex so a
            // concurrent `SlotPermit::drop` cannot fall between `try_acquire()`
            // and `.await` without waking this future.
            notified.as_mut().enable();
            if let Some(permit) = self.try_acquire() {
                return Ok(permit);
            }
            tokio::time::timeout_at(deadline, notified)
                .await
                .map_err(|_| anyhow::anyhow!("LFS verification concurrency wait timed out"))?;
        }
    }

    fn acquire_blocking(&'static self, deadline: Instant) -> Result<SlotPermit> {
        let mut in_use = self.in_use.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            let now = Instant::now();
            ensure!(now < deadline, "LFS verification concurrency wait timed out");
            if *in_use < MAX_CONCURRENT_VERIFICATIONS {
                *in_use += 1;
                return Ok(SlotPermit { limiter: self });
            }
            let (next, timeout) = self
                .condvar
                .wait_timeout(in_use, deadline.saturating_duration_since(now))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            in_use = next;
            if timeout.timed_out() && *in_use >= MAX_CONCURRENT_VERIFICATIONS {
                anyhow::bail!("LFS verification concurrency wait timed out");
            }
        }
    }

    #[cfg(test)]
    fn available_slots(&self) -> usize {
        let in_use = *self.in_use.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        MAX_CONCURRENT_VERIFICATIONS.saturating_sub(in_use)
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

/// Result shared by every caller that admitted the same exact file identity.
#[derive(Clone, Debug)]
pub(super) enum FlightResult {
    Verified,
    Mismatch,
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

/// Leader ownership guard: even a panic inside the blocking digest pass wakes
/// followers with a failure and removes the map entry instead of wedging every
/// future reader of that identity behind a permanently incomplete flight.
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
        self.flight.complete(result);
        let mut flights = flights();
        if flights.get(&self.identity).is_some_and(|entry| Arc::ptr_eq(entry, &self.flight)) {
            flights.remove(&self.identity);
        }
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
    fn enter(&self) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.hold {
            return;
        }
        state.active += 1;
        self.changed.notify_all();
        while state.hold {
            state = self.changed.wait(state).unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        state.active -= 1;
        self.changed.notify_all();
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

pub(super) fn hash_gate_enter() {
    #[cfg(test)]
    HASH_GATE.enter();
}
