//! Bounded fail-closed admission controller and backpressure accounting.
//!
//! Enforces authorization, object/pack/object-count limits, frontier pack
//! bounds, workspace/memory/FD ceilings, disk headroom, bounded waiter queues,
//! and <= 50% maintenance sub-caps without false-OK returns.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use super::{
    admission_types::{
        AdmissionClass, AdmissionLimits, AdmissionRejection, AdmissionRequest, AdmissionTelemetrySnapshot,
    },
    limits::CapacityContractError,
};

#[derive(Default)]
struct AccountingState {
    telemetry: AdmissionTelemetrySnapshot,
}

impl AccountingState {
    fn record_rejection(&mut self, rejection: &AdmissionRejection) {
        self.telemetry.rejected_total = self.telemetry.rejected_total.saturating_add(1);
        *self.telemetry.rejected_by_reason.entry(rejection.reason_key().to_owned()).or_insert(0) += 1;
    }

    fn try_reserve_resources(&mut self, limits: &AdmissionLimits, req: &AdmissionRequest) -> bool {
        let next_ws = self.telemetry.current_workspace_bytes.checked_add(req.estimated_workspace_bytes);
        let next_mem = self.telemetry.current_memory_bytes.checked_add(req.estimated_memory_bytes);
        let next_fds = self.telemetry.current_fds.checked_add(req.required_fds);
        match (next_ws, next_mem, next_fds) {
            (Some(ws), Some(mem), Some(fds))
                if ws <= limits.max_workspace_bytes && mem <= limits.max_memory_bytes && fds <= limits.max_open_fds =>
            {
                self.telemetry.current_workspace_bytes = ws;
                self.telemetry.current_memory_bytes = mem;
                self.telemetry.current_fds = fds;
                self.telemetry.peak_workspace_bytes = self.telemetry.peak_workspace_bytes.max(ws);
                self.telemetry.peak_memory_bytes = self.telemetry.peak_memory_bytes.max(mem);
                self.telemetry.peak_fds = self.telemetry.peak_fds.max(fds);
                true
            }
            _ => false,
        }
    }
}

pub struct AdmissionController {
    limits: AdmissionLimits,
    global_slots: Arc<Semaphore>,
    maint_slots: Arc<Semaphore>,
    state: Arc<Mutex<AccountingState>>,
    notify: Arc<Notify>,
}

struct QueueGuard {
    state: Arc<Mutex<AccountingState>>,
    armed: bool,
}

impl Drop for QueueGuard {
    fn drop(&mut self) {
        if self.armed {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            guard.telemetry.queued_waiters = guard.telemetry.queued_waiters.saturating_sub(1);
        }
    }
}

pub struct AdmissionPermit {
    _global: OwnedSemaphorePermit,
    _maint: Option<OwnedSemaphorePermit>,
    is_maint: bool,
    workspace_bytes: u64,
    memory_bytes: u64,
    fds: u64,
    state: Arc<Mutex<AccountingState>>,
    notify: Arc<Notify>,
}

impl AdmissionPermit {
    pub fn reserved_workspace_bytes(&self) -> u64 {
        self.workspace_bytes
    }

    pub fn shrink_workspace(&mut self, keep_bytes: u64) {
        if keep_bytes >= self.workspace_bytes {
            return;
        }
        let freed = self.workspace_bytes - keep_bytes;
        self.workspace_bytes = keep_bytes;
        {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            guard.telemetry.current_workspace_bytes = guard.telemetry.current_workspace_bytes.saturating_sub(freed);
        }
        self.notify.notify_waiters();
    }
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            guard.telemetry.active_slots = guard.telemetry.active_slots.saturating_sub(1);
            if self.is_maint {
                guard.telemetry.active_maintenance_slots = guard.telemetry.active_maintenance_slots.saturating_sub(1);
            }
            guard.telemetry.current_workspace_bytes =
                guard.telemetry.current_workspace_bytes.saturating_sub(self.workspace_bytes);
            guard.telemetry.current_memory_bytes =
                guard.telemetry.current_memory_bytes.saturating_sub(self.memory_bytes);
            guard.telemetry.current_fds = guard.telemetry.current_fds.saturating_sub(self.fds);
        }
        self.notify.notify_waiters();
    }
}

impl AdmissionController {
    pub fn new(limits: AdmissionLimits) -> Result<Self, CapacityContractError> {
        limits.validate()?;
        Ok(Self {
            limits,
            global_slots: Arc::new(Semaphore::new(limits.max_concurrent_verifiers)),
            maint_slots: Arc::new(Semaphore::new(limits.max_maintenance_verifiers)),
            state: Arc::new(Mutex::new(AccountingState::default())),
            notify: Arc::new(Notify::new()),
        })
    }

    pub fn limits(&self) -> AdmissionLimits {
        self.limits
    }

    pub fn telemetry(&self) -> AdmissionTelemetrySnapshot {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).telemetry.clone()
    }

    fn preflight_static(&self, req: &AdmissionRequest) -> Result<(), AdmissionRejection> {
        if !req.caller_authorized {
            return Err(AdmissionRejection::Unauthorized);
        }
        if req.tenant_id.is_nil() || req.repo_id.is_nil() {
            return Err(AdmissionRejection::InvalidScope("tenant_id and repo_id must be non-nil"));
        }
        if req.max_single_object_bytes > self.limits.max_object_bytes {
            return Err(AdmissionRejection::OversizedObject {
                requested: req.max_single_object_bytes,
                limit: self.limits.max_object_bytes,
            });
        }
        if req.declared_pack_bytes > self.limits.max_pack_bytes_per_push {
            return Err(AdmissionRejection::PackBytesExceeded {
                requested: req.declared_pack_bytes,
                limit: self.limits.max_pack_bytes_per_push,
            });
        }
        if req.declared_objects > self.limits.max_objects_per_window {
            return Err(AdmissionRejection::TooManyObjects {
                requested: req.declared_objects,
                limit: self.limits.max_objects_per_window,
            });
        }
        let next_packs = req.active_frontier_packs.saturating_add(req.new_pack_count);
        if req.new_pack_count > 0 && next_packs > self.limits.max_active_frontier_packs {
            return Err(AdmissionRejection::PackCountLimitReached {
                active: req.active_frontier_packs,
                new_packs: req.new_pack_count,
                limit: self.limits.max_active_frontier_packs,
            });
        }
        if req.estimated_workspace_bytes > self.limits.max_workspace_bytes {
            return Err(AdmissionRejection::WorkspaceBudgetExceeded {
                requested: req.estimated_workspace_bytes,
                limit: self.limits.max_workspace_bytes,
            });
        }
        if req.estimated_memory_bytes > self.limits.max_memory_bytes {
            return Err(AdmissionRejection::MemoryBudgetExceeded {
                requested: req.estimated_memory_bytes,
                limit: self.limits.max_memory_bytes,
            });
        }
        if req.required_fds > self.limits.max_open_fds {
            return Err(AdmissionRejection::FdBudgetExceeded {
                requested: req.required_fds,
                limit: self.limits.max_open_fds,
            });
        }
        let required_disk = req.estimated_workspace_bytes.saturating_add(self.limits.disk_headroom_bytes);
        if req.free_disk_bytes < required_disk {
            return Err(AdmissionRejection::DiskHeadroomExhausted {
                free_bytes: req.free_disk_bytes,
                required_bytes: required_disk,
            });
        }
        Ok(())
    }

    fn reject(&self, rejection: AdmissionRejection) -> AdmissionRejection {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).record_rejection(&rejection);
        rejection
    }

    pub async fn acquire(
        &self,
        req: &AdmissionRequest,
        deadline: Instant,
    ) -> Result<AdmissionPermit, AdmissionRejection> {
        if let Err(err) = self.preflight_static(req) {
            return Err(self.reject(err));
        }
        let cap_deadline = Instant::now() + Duration::from_millis(self.limits.queue_timeout_ms);
        let effective_deadline = deadline.min(cap_deadline);
        if effective_deadline <= Instant::now() {
            return Err(self.reject(AdmissionRejection::DeadlineExceeded));
        }
        let started = Instant::now();
        {
            let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if guard.telemetry.queued_waiters >= self.limits.max_queue_waiters {
                let err = AdmissionRejection::QueueFull {
                    queued: guard.telemetry.queued_waiters,
                    limit: self.limits.max_queue_waiters,
                };
                guard.record_rejection(&err);
                return Err(err);
            }
            guard.telemetry.queued_waiters += 1;
            guard.telemetry.max_queued_waiters_observed =
                guard.telemetry.max_queued_waiters_observed.max(guard.telemetry.queued_waiters);
        }
        let mut q_guard = QueueGuard { state: Arc::clone(&self.state), armed: true };
        let tokio_deadline = tokio::time::Instant::from_std(effective_deadline);
        let is_maint = req.class == AdmissionClass::CompactionMaintenance;
        let maint_permit = if is_maint {
            match tokio::time::timeout_at(tokio_deadline, self.maint_slots.clone().acquire_owned()).await {
                Ok(Ok(p)) => Some(p),
                _ => return Err(self.reject(AdmissionRejection::DeadlineExceeded)),
            }
        } else {
            None
        };
        let global_permit =
            match tokio::time::timeout_at(tokio_deadline, self.global_slots.clone().acquire_owned()).await {
                Ok(Ok(p)) => p,
                _ => return Err(self.reject(AdmissionRejection::DeadlineExceeded)),
            };

        loop {
            let notified = self.notify.notified();
            {
                let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
                if guard.try_reserve_resources(&self.limits, req) {
                    q_guard.armed = false;
                    guard.telemetry.queued_waiters = guard.telemetry.queued_waiters.saturating_sub(1);
                    guard.telemetry.admitted_total = guard.telemetry.admitted_total.saturating_add(1);
                    guard.telemetry.active_slots += 1;
                    if is_maint {
                        guard.telemetry.active_maintenance_slots += 1;
                    }
                    let wait_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                    guard.telemetry.total_queue_wait_us = guard.telemetry.total_queue_wait_us.saturating_add(wait_us);
                    break;
                }
            }
            if tokio::time::timeout_at(tokio_deadline, notified).await.is_err() {
                return Err(self.reject(AdmissionRejection::DeadlineExceeded));
            }
        }

        Ok(AdmissionPermit {
            _global: global_permit,
            _maint: maint_permit,
            is_maint,
            workspace_bytes: req.estimated_workspace_bytes,
            memory_bytes: req.estimated_memory_bytes,
            fds: req.required_fds,
            state: Arc::clone(&self.state),
            notify: Arc::clone(&self.notify),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_store::capacity_contract::limits::PandoCapacityContract;
    use uuid::Uuid;

    fn base_req() -> AdmissionRequest {
        AdmissionRequest {
            tenant_id: Uuid::new_v4(),
            repo_id: Uuid::new_v4(),
            caller_authorized: true,
            class: AdmissionClass::ForegroundPush,
            new_pack_count: 1,
            active_frontier_packs: 2,
            declared_pack_bytes: 1024,
            declared_objects: 10,
            max_single_object_bytes: 512,
            estimated_memory_bytes: 64 * 1024,
            estimated_workspace_bytes: 4096,
            required_fds: 8,
            free_disk_bytes: 64 * 1024 * 1024,
        }
    }

    #[tokio::test]
    async fn rejects_boundary_violations_and_tracks_backpressure() {
        let contract = PandoCapacityContract::current_standalone();
        let ctrl = AdmissionController::new(AdmissionLimits::from_contract(&contract).unwrap()).unwrap();
        let dl = Instant::now() + Duration::from_secs(5);

        let mut unauth = base_req();
        unauth.caller_authorized = false;
        assert!(matches!(ctrl.acquire(&unauth, dl).await, Err(AdmissionRejection::Unauthorized)));

        let mut oversized = base_req();
        oversized.max_single_object_bytes = ctrl.limits().max_object_bytes + 1;
        assert!(matches!(ctrl.acquire(&oversized, dl).await, Err(AdmissionRejection::OversizedObject { .. })));

        let mut permit = ctrl.acquire(&base_req(), dl).await.unwrap();
        permit.shrink_workspace(1024);
        assert_eq!(ctrl.telemetry().current_workspace_bytes, 1024);
        drop(permit);
        assert_eq!(ctrl.telemetry().current_workspace_bytes, 0);
    }
}
