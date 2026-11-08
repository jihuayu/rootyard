//! Bounded origin fallback and cancellation-safe ephemeral warmup coordination.
//!
//! These structures reduce concurrent origin work and duplicate warmups. They
//! are not mutual exclusion for durable state: a singleflight lease may expire,
//! a leader may be cancelled, and duplicate computation is allowed. Any final
//! artifact/ref publication must use the authoritative PostgreSQL/RefStore CAS
//! or fence, never a Redis lock or this in-process map.
use super::CacheLimits;
use anyhow::{Result, ensure};
use std::{
    collections::HashMap,
    fmt,
    future::Future,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, watch};

/// Origin fallback outcome. `Busy`, `CircuitOpen` and `Deadline` are advisory
/// failures that must cause a caller to retry, degrade, or return an explicit
/// unavailable result; they never authorize a durable mutation.
#[derive(Debug, PartialEq, Eq)]
pub enum OriginError<E> {
    Busy,
    CircuitOpen,
    Deadline,
    Origin(E),
}

struct Breaker {
    failures: u32,
    open_until: Option<Instant>,
}

/// Bounds concurrent origin loads with a semaphore, a per-call absolute
/// deadline and a consecutive-failure circuit breaker. No task is spawned here.
/// Dropping the timed-out future is cooperative cancellation; it is not a claim
/// that an underlying kernel/network operation was forcibly cancelled.
pub struct OriginGuard {
    permits: Semaphore,
    state: Mutex<Breaker>,
    wait: Duration,
    deadline: Duration,
    failure_threshold: u32,
    cooldown: Duration,
}

impl OriginGuard {
    pub fn new(limits: CacheLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            permits: Semaphore::new(limits.origin_permits),
            state: Mutex::new(Breaker { failures: 0, open_until: None }),
            wait: limits.origin_wait,
            deadline: limits.origin_deadline,
            failure_threshold: limits.breaker_failures,
            cooldown: limits.breaker_cooldown,
        })
    }

    fn circuit_open(&self) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        match state.open_until {
            Some(until) if until > now => true,
            Some(_) => {
                state.open_until = None;
                state.failures = 0;
                false
            }
            None => false,
        }
    }

    fn record_success(&self) {
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        state.failures = 0;
        state.open_until = None;
    }

    fn record_failure(&self) {
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        state.failures = state.failures.saturating_add(1);
        if state.failures >= self.failure_threshold {
            state.open_until = Instant::now().checked_add(self.cooldown);
        }
    }

    /// Run at most `origin_permits` origin loads concurrently. Permit acquisition
    /// is capped by `origin_wait`; after acquisition the origin body gets its own
    /// absolute `origin_deadline`. A queue timeout is `Busy`; an exhausted work
    /// deadline is `Deadline`.
    pub async fn call<T, E, F, Fut>(&self, call: F) -> Result<T, OriginError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let queue_deadline = Instant::now().checked_add(self.wait).unwrap_or_else(Instant::now);
        let queue_wait = queue_deadline.saturating_duration_since(Instant::now());
        if queue_wait.is_zero() {
            return Err(OriginError::Busy);
        }
        let permit = match tokio::time::timeout(queue_wait, self.permits.acquire()).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => return Err(OriginError::CircuitOpen),
            Err(_) => return Err(OriginError::Busy),
        };
        if self.circuit_open() {
            drop(permit);
            return Err(OriginError::CircuitOpen);
        }
        let work_deadline = Instant::now().checked_add(self.deadline).unwrap_or_else(Instant::now);
        let work = work_deadline.saturating_duration_since(Instant::now());
        if work.is_zero() {
            drop(permit);
            return Err(OriginError::Deadline);
        }
        match tokio::time::timeout(work, call()).await {
            Ok(Ok(value)) => {
                self.record_success();
                drop(permit);
                Ok(value)
            }
            Ok(Err(error)) => {
                self.record_failure();
                drop(permit);
                Err(OriginError::Origin(error))
            }
            Err(_) => {
                self.record_failure();
                drop(permit);
                Err(OriginError::Deadline)
            }
        }
    }
}

/// Result of a singleflight attempt. `Waited` means another caller owned the
/// ephemeral computation; the caller should re-read the advisory cache and may
/// still observe a miss. `Computed` is this caller's origin result.
#[derive(Debug, PartialEq, Eq)]
pub enum WarmupOutcome<T> {
    Computed(T),
    Waited,
}

struct Inflight {
    generation: u64,
    sender: watch::Sender<bool>,
}

enum Role {
    Leader { sender: watch::Sender<bool>, generation: u64 },
    Follower(watch::Receiver<bool>),
    Direct,
}

/// Removes only this leader's generation and closes its watch channel. Drop runs
/// on normal completion, error, panic unwind and task cancellation/abort.
struct LeaderGuard<'a> {
    flight: &'a SingleFlight,
    key: String,
    generation: u64,
    sender: watch::Sender<bool>,
}

impl Drop for LeaderGuard<'_> {
    fn drop(&mut self) {
        {
            let mut inflight = self.flight.inflight.lock().unwrap_or_else(|poison| poison.into_inner());
            if inflight.get(&self.key).is_some_and(|entry| entry.generation == self.generation) {
                inflight.remove(&self.key);
            }
        }
        // Waiting followers wake and retry/re-read even if computation failed or
        // was cancelled. If a newer leader already owns the key, this old sender
        // only closes its own waiters and cannot remove the newer map entry.
        let _ = self.sender.send(true);
    }
}

/// Ephemeral warmup singleflight with a bounded number of tracked keys.
/// Entries are removed by the leader guard, including cancellation. A follower
/// never receives authority from this map; final publish must be authoritative CAS.
pub struct SingleFlight {
    inflight: Mutex<HashMap<String, Inflight>>,
    max_keys: usize,
    wait: Duration,
    next_generation: AtomicU64,
}

impl SingleFlight {
    pub fn new(max_keys: usize, wait: Duration) -> Result<Self> {
        ensure!(max_keys > 0, "singleflight max_keys must be positive");
        ensure!(!wait.is_zero(), "singleflight wait must be positive");
        Ok(Self { inflight: Mutex::new(HashMap::new()), max_keys, wait, next_generation: AtomicU64::new(1) })
    }

    pub async fn run<T, F, Fut>(&self, key: String, compute: F) -> Result<WarmupOutcome<T>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        ensure!(key.len() <= 320, "singleflight key too long");
        let role = {
            let mut inflight = self.inflight.lock().unwrap_or_else(|poison| poison.into_inner());
            match inflight.get(&key) {
                Some(entry) => Role::Follower(entry.sender.subscribe()),
                None if inflight.len() < self.max_keys => {
                    let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
                    let (sender, _) = watch::channel(false);
                    inflight.insert(key.clone(), Inflight { generation, sender: sender.clone() });
                    Role::Leader { sender, generation }
                }
                None => Role::Direct,
            }
        };
        match role {
            Role::Follower(mut receiver) => {
                // A watch channel retains `true`, so a follower that arrives
                // after leader publication does not wait for a lost Notify.
                let _ = tokio::time::timeout(self.wait, receiver.wait_for(|done| *done)).await;
                Ok(WarmupOutcome::Waited)
            }
            Role::Leader { sender, generation } => {
                let guard = LeaderGuard { flight: self, key: key.clone(), generation, sender };
                let result = compute().await;
                drop(guard);
                Ok(WarmupOutcome::Computed(result?))
            }
            Role::Direct => Ok(WarmupOutcome::Computed(compute().await?)),
        }
    }

    pub fn tracked_keys(&self) -> usize {
        self.inflight.lock().unwrap_or_else(|poison| poison.into_inner()).len()
    }
}

impl fmt::Debug for SingleFlight {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("SingleFlight").field("max_keys", &self.max_keys).field("wait", &self.wait).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicBool};
    use tokio::sync::{Notify, oneshot};

    fn limits() -> CacheLimits {
        CacheLimits {
            origin_permits: 1,
            origin_wait: Duration::from_millis(20),
            origin_deadline: Duration::from_secs(15),
            breaker_failures: 2,
            breaker_cooldown: Duration::from_millis(40),
            ..CacheLimits::default()
        }
    }

    #[tokio::test]
    async fn origin_permits_bound_concurrency_without_spawning() {
        let limits = limits();
        let queue_budget = limits.origin_wait;
        let guard = Arc::new(OriginGuard::new(limits).unwrap());
        let started = Arc::new(Notify::new());
        let (release, wait) = oneshot::channel();
        let first = tokio::spawn({
            let guard = guard.clone();
            let started = started.clone();
            async move {
                guard
                    .call(|| async move {
                        started.notify_one();
                        let _ = wait.await;
                        Ok::<_, ()>(1)
                    })
                    .await
            }
        });
        started.notified().await;
        let body_polled = Arc::new(AtomicBool::new(false));
        let queued_at = Instant::now();
        let second = guard
            .call({
                let body_polled = body_polled.clone();
                move || {
                    body_polled.store(true, Ordering::SeqCst);
                    async { Ok::<_, ()>(2) }
                }
            })
            .await;
        let waited = queued_at.elapsed();
        assert_eq!(second, Err(OriginError::Busy));
        assert!(!body_polled.load(Ordering::SeqCst), "origin body ran after queue deadline");
        assert!(
            waited >= queue_budget.saturating_sub(Duration::from_millis(5)),
            "queue Busy returned before its budget: {waited:?}"
        );
        assert!(waited < Duration::from_secs(2), "queue wait exceeded its bound: {waited:?}");
        release.send(()).unwrap();
        assert_eq!(first.await.unwrap(), Ok(1));
    }

    #[tokio::test]
    async fn origin_work_has_absolute_deadline_and_releases_permit() {
        let guard = OriginGuard::new(CacheLimits {
            origin_permits: 1,
            origin_wait: Duration::from_secs(1),
            origin_deadline: Duration::from_millis(20),
            breaker_failures: 10,
            ..limits()
        })
        .unwrap();
        let result = guard.call(std::future::pending::<Result<(), ()>>).await;
        assert_eq!(result, Err(OriginError::Deadline));
        assert_eq!(guard.call(|| async { Ok::<_, ()>(4) }).await, Ok(4));
    }

    #[tokio::test]
    async fn breaker_opens_after_consecutive_origin_failures() {
        let guard = OriginGuard::new(limits()).unwrap();
        for _ in 0..2 {
            assert_eq!(guard.call(|| async { Err::<(), _>(()) }).await, Err(OriginError::Origin(())));
        }
        assert_eq!(guard.call(|| async { Ok::<_, ()>(1) }).await, Err(OriginError::CircuitOpen));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(guard.call(|| async { Ok::<_, ()>(3) }).await, Ok(3));
    }

    #[tokio::test]
    async fn singleflight_coalesces_and_releases_leader() {
        let flight = Arc::new(SingleFlight::new(4, Duration::from_secs(1)).unwrap());
        let started = Arc::new(Notify::new());
        let (release, wait) = oneshot::channel();
        let leader = tokio::spawn({
            let flight = flight.clone();
            let started = started.clone();
            async move {
                flight
                    .run("warmup:key".into(), || async move {
                        started.notify_one();
                        let _ = wait.await;
                        Ok::<_, anyhow::Error>(7)
                    })
                    .await
            }
        });
        started.notified().await;
        let follower: WarmupOutcome<i32> =
            flight.run("warmup:key".into(), || async { anyhow::bail!("must not run") }).await.unwrap();
        assert_eq!(follower, WarmupOutcome::Waited);
        release.send(()).unwrap();
        assert_eq!(leader.await.unwrap().unwrap(), WarmupOutcome::Computed(7));
        assert_eq!(flight.tracked_keys(), 0);
    }

    #[tokio::test]
    async fn aborted_leader_removes_its_entry_and_wakes_follower() {
        let flight = Arc::new(SingleFlight::new(4, Duration::from_secs(1)).unwrap());
        let started = Arc::new(Notify::new());
        let leader = tokio::spawn({
            let flight = flight.clone();
            let started = started.clone();
            async move {
                flight
                    .run("cancel:key".into(), || async move {
                        started.notify_one();
                        std::future::pending::<Result<i32, anyhow::Error>>().await
                    })
                    .await
            }
        });
        started.notified().await;

        let follower = {
            let flight = flight.clone();
            async move { flight.run("cancel:key".into(), || async { Ok::<_, anyhow::Error>(99) }).await }
        };
        tokio::pin!(follower);
        // Poll once so the follower has registered on the leader's watch channel.
        std::future::poll_fn(|context| {
            let _ = std::future::Future::poll(follower.as_mut(), context);
            std::task::Poll::Ready(())
        })
        .await;

        leader.abort();
        let _ = leader.await;
        let follower_result = tokio::time::timeout(Duration::from_secs(1), follower)
            .await
            .expect("follower stuck after leader abort")
            .unwrap();
        assert_eq!(follower_result, WarmupOutcome::Waited);

        let recovered = flight.run("cancel:key".into(), || async { Ok::<_, anyhow::Error>(7) }).await.unwrap();
        assert_eq!(recovered, WarmupOutcome::Computed(7));
        assert_eq!(flight.tracked_keys(), 0);
    }
}
