//! Bounded concurrency semaphores and per-repository sync rate limiting for CI read mirrors.
use crate::{AppState, Error, mirror::observability};
use anyhow::{Context, Result, ensure};
use axum::http::StatusCode;
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

pub const DEFAULT_MAX_CONCURRENT_SYNCS: usize = 4;
pub const DEFAULT_MAX_CONCURRENT_CLOSURES: usize = 4;
pub const DEFAULT_SYNC_COOLDOWN_MS: u64 = 0;

static REGISTRY: LazyLock<Mutex<HashMap<Uuid, Arc<MirrorLimiter>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Default)]
struct RepoSyncSlot {
    in_flight: bool,
    last_completed: Option<Instant>,
}

pub struct MirrorLimiter {
    pub max_concurrent_syncs: usize,
    pub max_concurrent_closures: usize,
    pub sync_cooldown: Duration,
    sync_semaphore: Arc<Semaphore>,
    closure_semaphore: Arc<Semaphore>,
    repo_slots: Arc<Mutex<HashMap<Uuid, RepoSyncSlot>>>,
}

#[derive(Debug)]
pub struct SyncPermit {
    repo_id: Uuid,
    repo_slots: Arc<Mutex<HashMap<Uuid, RepoSyncSlot>>>,
    _permit: OwnedSemaphorePermit,
    completed: bool,
}

impl SyncPermit {
    pub fn mark_completed(&mut self) {
        self.completed = true;
    }
}

impl Drop for SyncPermit {
    fn drop(&mut self) {
        if let Ok(mut map) = self.repo_slots.lock() {
            if let Some(slot) = map.get_mut(&self.repo_id) {
                slot.in_flight = false;
                if self.completed {
                    slot.last_completed = Some(Instant::now());
                }
            }
        }
    }
}

impl MirrorLimiter {
    pub fn new(
        max_concurrent_syncs: usize,
        max_concurrent_closures: usize,
        sync_cooldown: Duration,
    ) -> Self {
        let syncs = max_concurrent_syncs.max(1);
        let closures = max_concurrent_closures.max(1);
        Self {
            max_concurrent_syncs: syncs,
            max_concurrent_closures: closures,
            sync_cooldown,
            sync_semaphore: Arc::new(Semaphore::new(syncs)),
            closure_semaphore: Arc::new(Semaphore::new(closures)),
            repo_slots: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn from_env() -> Result<Self> {
        let max_syncs = match std::env::var("ROOTYARD_MIRROR_MAX_CONCURRENT_SYNCS") {
            Ok(val) => {
                let parsed: usize = val
                    .parse()
                    .context("invalid ROOTYARD_MIRROR_MAX_CONCURRENT_SYNCS")?;
                ensure!(
                    (1..=256).contains(&parsed),
                    "ROOTYARD_MIRROR_MAX_CONCURRENT_SYNCS must be in 1..=256"
                );
                parsed
            }
            Err(_) => DEFAULT_MAX_CONCURRENT_SYNCS,
        };
        let max_closures = match std::env::var("ROOTYARD_MIRROR_MAX_CONCURRENT_CLOSURES") {
            Ok(val) => {
                let parsed: usize = val
                    .parse()
                    .context("invalid ROOTYARD_MIRROR_MAX_CONCURRENT_CLOSURES")?;
                ensure!(
                    (1..=256).contains(&parsed),
                    "ROOTYARD_MIRROR_MAX_CONCURRENT_CLOSURES must be in 1..=256"
                );
                parsed
            }
            Err(_) => DEFAULT_MAX_CONCURRENT_CLOSURES,
        };
        let cooldown_ms = match std::env::var("ROOTYARD_MIRROR_SYNC_COOLDOWN_MS") {
            Ok(val) => val
                .parse::<u64>()
                .context("invalid ROOTYARD_MIRROR_SYNC_COOLDOWN_MS")?,
            Err(_) => DEFAULT_SYNC_COOLDOWN_MS,
        };
        Ok(Self::new(
            max_syncs,
            max_closures,
            Duration::from_millis(cooldown_ms),
        ))
    }

    pub fn sync_in_flight(&self) -> usize {
        self.max_concurrent_syncs
            .saturating_sub(self.sync_semaphore.available_permits())
    }

    pub fn closure_in_flight(&self) -> usize {
        self.max_concurrent_closures
            .saturating_sub(self.closure_semaphore.available_permits())
    }

    pub fn try_acquire_sync_raw(&self, repo_id: Uuid) -> std::result::Result<SyncPermit, &'static str> {
        let mut slots = self.repo_slots.lock().expect("repo_slots mutex poisoned");
        let slot = slots.entry(repo_id).or_default();
        if slot.in_flight {
            return Err("mirror sync already in progress for repository");
        }
        if self.sync_cooldown > Duration::ZERO
            && slot
                .last_completed
                .is_some_and(|t| t.elapsed() < self.sync_cooldown)
        {
            return Err("mirror sync rate limit cooldown active");
        }
        let permit = self
            .sync_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| "mirror concurrent sync limit reached")?;
        slot.in_flight = true;
        Ok(SyncPermit {
            repo_id,
            repo_slots: self.repo_slots.clone(),
            _permit: permit,
            completed: false,
        })
    }

    pub fn try_acquire_sync(&self, state: &AppState, repo_id: Uuid) -> Result<SyncPermit, Error> {
        match self.try_acquire_sync_raw(repo_id) {
            Ok(permit) => Ok(permit),
            Err(reason) => {
                observability::for_state(state).record_rate_limited();
                Err(Error(StatusCode::TOO_MANY_REQUESTS, reason))
            }
        }
    }

    pub fn try_acquire_closure(&self, state: &AppState) -> Result<OwnedSemaphorePermit, Error> {
        self.closure_semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                observability::for_state(state).record_rate_limited();
                Error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "mirror concurrent closure materialization limit reached",
                )
            })
    }
}

pub fn init_for_state(state: &AppState) -> Result<Arc<MirrorLimiter>> {
    let limiter = Arc::new(MirrorLimiter::from_env()?);
    let mut map = REGISTRY.lock().expect("mirror limiter registry poisoned");
    map.insert(state.storage.volume_id, limiter.clone());
    Ok(limiter)
}

pub fn for_state(state: &AppState) -> Arc<MirrorLimiter> {
    let mut map = REGISTRY.lock().expect("mirror limiter registry poisoned");
    map.entry(state.storage.volume_id)
        .or_insert_with(|| {
            Arc::new(
                MirrorLimiter::from_env().unwrap_or_else(|_| {
                    MirrorLimiter::new(
                        DEFAULT_MAX_CONCURRENT_SYNCS,
                        DEFAULT_MAX_CONCURRENT_CLOSURES,
                        Duration::from_millis(DEFAULT_SYNC_COOLDOWN_MS),
                    )
                }),
            )
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_repo_and_global_sync_limits_reject_contention() {
        let limiter = MirrorLimiter::new(2, 2, Duration::from_millis(50));
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();
        let repo_c = Uuid::new_v4();

        let mut permit_a = limiter.try_acquire_sync_raw(repo_a).unwrap();
        assert_eq!(limiter.sync_in_flight(), 1);

        // Concurrent sync for the same repository is rejected immediately.
        assert_eq!(
            limiter.try_acquire_sync_raw(repo_a).unwrap_err(),
            "mirror sync already in progress for repository"
        );

        // Second repository succeeds up to max_concurrent_syncs = 2.
        let _permit_b = limiter.try_acquire_sync_raw(repo_b).unwrap();
        assert_eq!(limiter.sync_in_flight(), 2);

        // Third repository hits global concurrency bound.
        assert_eq!(
            limiter.try_acquire_sync_raw(repo_c).unwrap_err(),
            "mirror concurrent sync limit reached"
        );

        // Mark repo_a completed and drop permit_a -> triggers cooldown window.
        permit_a.mark_completed();
        drop(permit_a);
        assert_eq!(limiter.sync_in_flight(), 1);
        assert_eq!(
            limiter.try_acquire_sync_raw(repo_a).unwrap_err(),
            "mirror sync rate limit cooldown active"
        );
    }
}
