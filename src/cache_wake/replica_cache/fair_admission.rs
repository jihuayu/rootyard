//! Deficit Round-Robin (DRR) / Fair-Share tenant admission gate preventing
//! noisy tenants from starving normal tenants under concurrency contention.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::sync::oneshot;
use uuid::Uuid;

use super::types::ReplicaCacheError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantFairShareConfig {
    pub max_total_inflight: usize,
    pub max_per_tenant_inflight: usize,
    pub max_waiters_per_tenant: usize,
    pub max_total_waiters: usize,
    pub admission_timeout: Duration,
}

impl Default for TenantFairShareConfig {
    fn default() -> Self {
        Self {
            max_total_inflight: 16,
            max_per_tenant_inflight: 6,
            max_waiters_per_tenant: 16,
            max_total_waiters: 128,
            admission_timeout: Duration::from_secs(5),
        }
    }
}

impl TenantFairShareConfig {
    pub fn validate(&self) -> Result<(), ReplicaCacheError> {
        if self.max_total_inflight == 0
            || self.max_per_tenant_inflight == 0
            || self.max_per_tenant_inflight > self.max_total_inflight
        {
            return Err(ReplicaCacheError::InvalidConfig("invalid fair-share inflight limits"));
        }
        if self.max_waiters_per_tenant == 0 || self.max_total_waiters < self.max_waiters_per_tenant {
            return Err(ReplicaCacheError::InvalidConfig("invalid fair-share waiter limits"));
        }
        if self.admission_timeout.is_zero() {
            return Err(ReplicaCacheError::InvalidConfig("admission_timeout must be positive"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FairnessStatsSnapshot {
    pub total_admitted: u64,
    pub total_rejected: u64,
    pub active_inflight: usize,
    pub queued_waiters: usize,
    pub per_tenant_admitted: HashMap<Uuid, u64>,
    pub per_tenant_rejected: HashMap<Uuid, u64>,
    pub per_tenant_wait_us: HashMap<Uuid, u64>,
}

struct QueuedTenantWaiter {
    tx: oneshot::Sender<()>,
}

#[derive(Default)]
struct FairGateState {
    total_active: usize,
    tenant_active: HashMap<Uuid, usize>,
    wait_queues: HashMap<Uuid, VecDeque<QueuedTenantWaiter>>,
    rr_order: VecDeque<Uuid>,
    total_waiters: usize,
    total_admitted: u64,
    total_rejected: u64,
    per_tenant_admitted: HashMap<Uuid, u64>,
    per_tenant_rejected: HashMap<Uuid, u64>,
    per_tenant_wait_us: HashMap<Uuid, u64>,
}

#[derive(Clone)]
pub struct TenantFairShareGate {
    cfg: TenantFairShareConfig,
    state: Arc<Mutex<FairGateState>>,
}

pub struct FairAdmissionPermit {
    tenant_id: Uuid,
    cfg: TenantFairShareConfig,
    state: Arc<Mutex<FairGateState>>,
    released: bool,
}

impl Drop for FairAdmissionPermit {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        guard.total_active = guard.total_active.saturating_sub(1);
        if let Some(count) = guard.tenant_active.get_mut(&self.tenant_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                guard.tenant_active.remove(&self.tenant_id);
            }
        }
        dispatch_next_fair_waiters(&mut guard, &self.cfg);
    }
}

impl TenantFairShareGate {
    pub fn new(cfg: TenantFairShareConfig) -> Result<Self, ReplicaCacheError> {
        cfg.validate()?;
        Ok(Self { cfg, state: Arc::new(Mutex::new(FairGateState::default())) })
    }

    pub async fn acquire(
        &self,
        tenant_id: Uuid,
        deadline: Instant,
    ) -> Result<(FairAdmissionPermit, u64), ReplicaCacheError> {
        let started = Instant::now();
        let _initial_remaining = deadline
            .checked_duration_since(started)
            .filter(|d| !d.is_zero())
            .ok_or(ReplicaCacheError::DeadlineExceeded)?;

        let mut waiter = {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if deadline.checked_duration_since(Instant::now()).is_none_or(|d| d.is_zero()) {
                return Err(ReplicaCacheError::DeadlineExceeded);
            }
            let t_active = guard.tenant_active.get(&tenant_id).copied().unwrap_or(0);
            if guard.total_active < self.cfg.max_total_inflight
                && t_active < self.cfg.max_per_tenant_inflight
                && guard.wait_queues.get(&tenant_id).is_none_or(VecDeque::is_empty)
            {
                grant_slot(&mut guard, tenant_id);
                return Ok((
                    FairAdmissionPermit { tenant_id, cfg: self.cfg, state: Arc::clone(&self.state), released: false },
                    0,
                ));
            }
            let t_queue_len = guard.wait_queues.get(&tenant_id).map_or(0, VecDeque::len);
            if t_queue_len >= self.cfg.max_waiters_per_tenant || guard.total_waiters >= self.cfg.max_total_waiters {
                guard.total_rejected = guard.total_rejected.saturating_add(1);
                *guard.per_tenant_rejected.entry(tenant_id).or_insert(0) += 1;
                return Err(ReplicaCacheError::QueueFull("tenant fair-share admission queue exhausted"));
            }
            let (tx, rx) = oneshot::channel();
            guard.wait_queues.entry(tenant_id).or_default().push_back(QueuedTenantWaiter { tx });
            if !guard.rr_order.contains(&tenant_id) {
                guard.rr_order.push_back(tenant_id);
            }
            guard.total_waiters = guard.total_waiters.saturating_add(1);
            FairWaiterGuard { tenant_id, cfg: self.cfg, state: Arc::clone(&self.state), rx, completed: false }
        };

        let Some(remaining) = deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) else {
            drop(waiter);
            return Err(ReplicaCacheError::DeadlineExceeded);
        };
        let budget = self.cfg.admission_timeout.min(remaining);
        match tokio::time::timeout(budget, &mut waiter.rx).await {
            Ok(Ok(())) => {
                waiter.completed = true;
                let waited_us = started.elapsed().as_micros() as u64;
                let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
                *guard.per_tenant_wait_us.entry(tenant_id).or_insert(0) += waited_us;
                Ok((
                    FairAdmissionPermit { tenant_id, cfg: self.cfg, state: Arc::clone(&self.state), released: false },
                    waited_us,
                ))
            }
            _ => {
                drop(waiter);
                let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
                guard.total_rejected = guard.total_rejected.saturating_add(1);
                *guard.per_tenant_rejected.entry(tenant_id).or_insert(0) += 1;
                if Instant::now() >= deadline {
                    Err(ReplicaCacheError::DeadlineExceeded)
                } else {
                    Err(ReplicaCacheError::QueueFull("tenant fair-share admission timed out"))
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn rr_order_snapshot(&self) -> Vec<Uuid> {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).rr_order.iter().copied().collect()
    }

    pub fn stats(&self) -> FairnessStatsSnapshot {
        let guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        FairnessStatsSnapshot {
            total_admitted: guard.total_admitted,
            total_rejected: guard.total_rejected,
            active_inflight: guard.total_active,
            queued_waiters: guard.total_waiters,
            per_tenant_admitted: guard.per_tenant_admitted.clone(),
            per_tenant_rejected: guard.per_tenant_rejected.clone(),
            per_tenant_wait_us: guard.per_tenant_wait_us.clone(),
        }
    }
}

struct FairWaiterGuard {
    tenant_id: Uuid,
    cfg: TenantFairShareConfig,
    state: Arc<Mutex<FairGateState>>,
    rx: oneshot::Receiver<()>,
    completed: bool,
}

impl Drop for FairWaiterGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.completed = true;
        self.rx.close();
        if self.rx.try_recv().is_ok() {
            drop(FairAdmissionPermit {
                tenant_id: self.tenant_id,
                cfg: self.cfg,
                state: Arc::clone(&self.state),
                released: false,
            });
        } else {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            prune_closed_waiters(&mut guard, self.tenant_id);
        }
    }
}

fn grant_slot(guard: &mut FairGateState, tenant_id: Uuid) {
    guard.total_active = guard.total_active.saturating_add(1);
    *guard.tenant_active.entry(tenant_id).or_insert(0) += 1;
    guard.total_admitted = guard.total_admitted.saturating_add(1);
    *guard.per_tenant_admitted.entry(tenant_id).or_insert(0) += 1;
}

fn prune_closed_waiters(guard: &mut FairGateState, tenant_id: Uuid) {
    if let Some(q) = guard.wait_queues.get_mut(&tenant_id) {
        let before = q.len();
        q.retain(|w| !w.tx.is_closed());
        let removed = before.saturating_sub(q.len());
        guard.total_waiters = guard.total_waiters.saturating_sub(removed);
        if q.is_empty() {
            guard.wait_queues.remove(&tenant_id);
            guard.rr_order.retain(|id| *id != tenant_id);
        }
    } else {
        guard.rr_order.retain(|id| *id != tenant_id);
    }
}

fn dispatch_next_fair_waiters(guard: &mut FairGateState, cfg: &TenantFairShareConfig) {
    while guard.total_active < cfg.max_total_inflight {
        let rounds = guard.rr_order.len();
        if rounds == 0 {
            break;
        }
        let mut made_progress = false;
        for _ in 0..rounds {
            if guard.total_active >= cfg.max_total_inflight {
                break;
            }
            let Some(tenant_id) = guard.rr_order.pop_front() else {
                break;
            };
            prune_closed_waiters(guard, tenant_id);
            let t_active = guard.tenant_active.get(&tenant_id).copied().unwrap_or(0);
            if t_active >= cfg.max_per_tenant_inflight {
                if guard.wait_queues.contains_key(&tenant_id) {
                    guard.rr_order.push_back(tenant_id);
                }
                continue;
            }
            while let Some(waiter) = guard.wait_queues.get_mut(&tenant_id).and_then(VecDeque::pop_front) {
                guard.total_waiters = guard.total_waiters.saturating_sub(1);
                if waiter.tx.send(()).is_ok() {
                    grant_slot(guard, tenant_id);
                    made_progress = true;
                    break;
                }
            }
            if guard.wait_queues.get(&tenant_id).is_some_and(VecDeque::is_empty) {
                guard.wait_queues.remove(&tenant_id);
            }
            if guard.wait_queues.contains_key(&tenant_id) {
                guard.rr_order.push_back(tenant_id);
            }
        }
        if !made_progress {
            break;
        }
    }
}
