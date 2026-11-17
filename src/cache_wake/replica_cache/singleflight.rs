//! Same-version single-flight coalescing with a bounded waiter queue and
//! cancellation-safe leader/waiter cleanup.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::watch;

use super::{
    catalog::CachedViewSlot,
    types::{ReplicaCacheError, ReplicaCacheLimits, ReplicaServeSource, ReplicaViewKey},
};

#[derive(Clone)]
pub enum FlightOutcome {
    Pending,
    Ready { slot: Arc<CachedViewSlot>, source: ReplicaServeSource },
    LeaderCancelled,
    Failed(String),
}

struct InflightFlight {
    generation: u64,
    waiters: usize,
    sender: watch::Sender<FlightOutcome>,
}

struct FlightState {
    inflight: HashMap<String, InflightFlight>,
    total_waiters: usize,
    next_generation: u64,
}

pub struct LeaderFlightGuard {
    key_hex: String,
    generation: u64,
    sender: watch::Sender<FlightOutcome>,
    state: Arc<Mutex<FlightState>>,
    completed: bool,
}

impl LeaderFlightGuard {
    pub fn complete_ready(mut self, slot: Arc<CachedViewSlot>, source: ReplicaServeSource) {
        self.completed = true;
        {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if guard.inflight.get(&self.key_hex).is_some_and(|e| e.generation == self.generation) {
                guard.inflight.remove(&self.key_hex);
            }
        }
        let _ = self.sender.send(FlightOutcome::Ready { slot, source });
    }

    pub fn complete_failed(mut self, reason: &str) {
        self.completed = true;
        {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if guard.inflight.get(&self.key_hex).is_some_and(|e| e.generation == self.generation) {
                guard.inflight.remove(&self.key_hex);
            }
        }
        let _ = self.sender.send(FlightOutcome::Failed(reason.to_owned()));
    }
}

impl Drop for LeaderFlightGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if guard.inflight.get(&self.key_hex).is_some_and(|e| e.generation == self.generation) {
                guard.inflight.remove(&self.key_hex);
            }
        }
        let _ = self.sender.send(FlightOutcome::LeaderCancelled);
    }
}

pub struct WaiterFlightGuard {
    key_hex: String,
    generation: u64,
    receiver: watch::Receiver<FlightOutcome>,
    state: Arc<Mutex<FlightState>>,
    released: bool,
}

impl WaiterFlightGuard {
    pub async fn wait_for_outcome(
        mut self,
        wait_timeout: Duration,
        deadline: Instant,
    ) -> Result<(FlightOutcome, u64), ReplicaCacheError> {
        let started = Instant::now();
        let remaining = deadline
            .checked_duration_since(started)
            .filter(|d| !d.is_zero())
            .ok_or(ReplicaCacheError::DeadlineExceeded)?;
        let budget = wait_timeout.min(remaining);
        let res =
            tokio::time::timeout(budget, self.receiver.wait_for(|outcome| !matches!(outcome, FlightOutcome::Pending)))
                .await;
        let waited_us = started.elapsed().as_micros() as u64;
        self.release_slot();
        match res {
            Ok(Ok(outcome)) => Ok((outcome.clone(), waited_us)),
            Ok(Err(_)) => Ok((FlightOutcome::LeaderCancelled, waited_us)),
            Err(_) => Err(ReplicaCacheError::WaitTimeout),
        }
    }

    fn release_slot(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        guard.total_waiters = guard.total_waiters.saturating_sub(1);
        if let Some(entry) = guard.inflight.get_mut(&self.key_hex)
            && entry.generation == self.generation
        {
            entry.waiters = entry.waiters.saturating_sub(1);
        }
    }
}

impl Drop for WaiterFlightGuard {
    fn drop(&mut self) {
        self.release_slot();
    }
}

pub enum FlightEntry {
    Leader(LeaderFlightGuard),
    Waiter(WaiterFlightGuard),
}

/// Bounded same-version single-flight coalescer.
/// Keyed by exact [`ReplicaViewKey::view_key_hex`] so distinct tenants,
/// histories, backends, or revisions never coalesce into the same flight.
pub struct BoundedSingleFlight {
    limits: ReplicaCacheLimits,
    state: Arc<Mutex<FlightState>>,
    coalesced_count: AtomicU64,
    queue_rejections: AtomicU64,
}

impl BoundedSingleFlight {
    pub fn new(limits: ReplicaCacheLimits) -> Result<Self, ReplicaCacheError> {
        limits.validate()?;
        Ok(Self {
            limits,
            state: Arc::new(Mutex::new(FlightState { inflight: HashMap::new(), total_waiters: 0, next_generation: 1 })),
            coalesced_count: AtomicU64::new(0),
            queue_rejections: AtomicU64::new(0),
        })
    }

    pub fn enter(&self, key: &ReplicaViewKey) -> Result<FlightEntry, ReplicaCacheError> {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = guard.inflight.get_mut(&key.view_key_hex) {
            if entry.waiters >= self.limits.max_waiters_per_key || guard.total_waiters >= self.limits.max_total_waiters
            {
                self.queue_rejections.fetch_add(1, Ordering::Relaxed);
                return Err(ReplicaCacheError::QueueFull("singleflight waiter queue exhausted"));
            }
            entry.waiters = entry.waiters.saturating_add(1);
            let generation = entry.generation;
            let receiver = entry.sender.subscribe();
            guard.total_waiters = guard.total_waiters.saturating_add(1);
            self.coalesced_count.fetch_add(1, Ordering::Relaxed);
            return Ok(FlightEntry::Waiter(WaiterFlightGuard {
                key_hex: key.view_key_hex.clone(),
                generation,
                receiver,
                state: Arc::clone(&self.state),
                released: false,
            }));
        }

        if guard.inflight.len() >= self.limits.max_inflight_builds {
            self.queue_rejections.fetch_add(1, Ordering::Relaxed);
            return Err(ReplicaCacheError::QueueFull("max concurrent materializations reached"));
        }

        let generation = guard.next_generation;
        guard.next_generation = guard.next_generation.saturating_add(1);
        let (sender, _) = watch::channel(FlightOutcome::Pending);
        guard
            .inflight
            .insert(key.view_key_hex.clone(), InflightFlight { generation, waiters: 0, sender: sender.clone() });
        Ok(FlightEntry::Leader(LeaderFlightGuard {
            key_hex: key.view_key_hex.clone(),
            generation,
            sender,
            state: Arc::clone(&self.state),
            completed: false,
        }))
    }

    pub fn inflight_keys(&self) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).inflight.len()
    }

    pub fn total_waiters(&self) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).total_waiters
    }

    pub fn counters(&self) -> (u64, u64) {
        (self.coalesced_count.load(Ordering::Relaxed), self.queue_rejections.load(Ordering::Relaxed))
    }
}
