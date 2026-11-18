//! Typed admission limits, rejections, requests, and telemetry snapshots.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::limits::{CapacityContractError, PandoCapacityContract};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionClass {
    ForegroundPush,
    ForegroundRead,
    CompactionMaintenance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionRejection {
    Unauthorized,
    InvalidScope(&'static str),
    OversizedObject { requested: u64, limit: u64 },
    PackBytesExceeded { requested: u64, limit: u64 },
    TooManyObjects { requested: u64, limit: u64 },
    PackCountLimitReached { active: usize, new_packs: usize, limit: usize },
    WorkspaceBudgetExceeded { requested: u64, limit: u64 },
    MemoryBudgetExceeded { requested: u64, limit: u64 },
    FdBudgetExceeded { requested: u64, limit: u64 },
    DiskHeadroomExhausted { free_bytes: u64, required_bytes: u64 },
    QueueFull { queued: usize, limit: usize },
    DeadlineExceeded,
}

impl AdmissionRejection {
    pub const fn reason_key(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::InvalidScope(_) => "invalid_scope",
            Self::OversizedObject { .. } => "oversized_object",
            Self::PackBytesExceeded { .. } => "pack_bytes_exceeded",
            Self::TooManyObjects { .. } => "too_many_objects",
            Self::PackCountLimitReached { .. } => "pack_count_limit_reached",
            Self::WorkspaceBudgetExceeded { .. } => "workspace_budget_exceeded",
            Self::MemoryBudgetExceeded { .. } => "memory_budget_exceeded",
            Self::FdBudgetExceeded { .. } => "fd_budget_exceeded",
            Self::DiskHeadroomExhausted { .. } => "disk_headroom_exhausted",
            Self::QueueFull { .. } => "queue_full",
            Self::DeadlineExceeded => "deadline_exceeded",
        }
    }
}

impl fmt::Display for AdmissionRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("admission denied: caller is not authorized"),
            Self::InvalidScope(msg) => write!(f, "admission denied: invalid scope ({msg})"),
            Self::OversizedObject { requested, limit } => write!(f, "object size {requested} exceeds limit {limit}"),
            Self::PackBytesExceeded { requested, limit } => write!(f, "pack bytes {requested} exceed limit {limit}"),
            Self::TooManyObjects { requested, limit } => write!(f, "object count {requested} exceeds limit {limit}"),
            Self::PackCountLimitReached { active, new_packs, limit } => {
                write!(f, "pack frontier ({active} + {new_packs}) exceeds limit {limit}")
            }
            Self::WorkspaceBudgetExceeded { requested, limit } => {
                write!(f, "workspace bytes {requested} exceed limit {limit}")
            }
            Self::MemoryBudgetExceeded { requested, limit } => {
                write!(f, "memory bytes {requested} exceed limit {limit}")
            }
            Self::FdBudgetExceeded { requested, limit } => write!(f, "open FDs {requested} exceed limit {limit}"),
            Self::DiskHeadroomExhausted { free_bytes, required_bytes } => {
                write!(f, "free scratch disk {free_bytes} below required {required_bytes}")
            }
            Self::QueueFull { queued, limit } => write!(f, "admission queue saturated ({queued} >= {limit})"),
            Self::DeadlineExceeded => f.write_str("admission queue/resource deadline exceeded"),
        }
    }
}

impl std::error::Error for AdmissionRejection {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionLimits {
    pub max_object_bytes: u64,
    pub max_pack_bytes_per_push: u64,
    pub max_objects_per_window: u64,
    pub max_active_frontier_packs: usize,
    pub max_workspace_bytes: u64,
    pub max_memory_bytes: u64,
    pub max_open_fds: u64,
    pub max_concurrent_verifiers: usize,
    pub max_maintenance_verifiers: usize,
    pub max_queue_waiters: usize,
    pub disk_headroom_bytes: u64,
    pub queue_timeout_ms: u64,
}

impl AdmissionLimits {
    pub fn from_contract(contract: &PandoCapacityContract) -> Result<Self, CapacityContractError> {
        contract.validate()?;
        let max_concurrent = contract.verifier.max_concurrent_native;
        let max_maint = (max_concurrent / 2).max(1).min(max_concurrent);
        Ok(Self {
            max_object_bytes: contract.streaming.max_single_object_bytes,
            max_pack_bytes_per_push: contract.verifier.max_total_bytes_per_window,
            max_objects_per_window: contract.verifier.max_objects_per_window,
            max_active_frontier_packs: contract.streaming.max_active_frontier_packs,
            max_workspace_bytes: contract.verifier.view_max_logical_bytes,
            max_memory_bytes: contract.streaming.max_memory_bytes,
            max_open_fds: contract.verifier.git_nofile,
            max_concurrent_verifiers: max_concurrent,
            max_maintenance_verifiers: max_maint,
            max_queue_waiters: contract.streaming.max_queue_waiters,
            disk_headroom_bytes: contract.verifier.disk_headroom_bytes,
            queue_timeout_ms: contract.verifier.deadline_seconds.saturating_mul(1000),
        })
    }

    pub fn validate(&self) -> Result<(), CapacityContractError> {
        if self.max_object_bytes == 0
            || self.max_pack_bytes_per_push == 0
            || self.max_objects_per_window == 0
            || self.max_active_frontier_packs == 0
            || self.max_workspace_bytes == 0
            || self.max_memory_bytes == 0
            || self.max_open_fds == 0
            || self.max_concurrent_verifiers == 0
            || self.max_maintenance_verifiers == 0
            || self.max_maintenance_verifiers > self.max_concurrent_verifiers
            || self.max_queue_waiters == 0
            || self.queue_timeout_ms == 0
        {
            return Err(CapacityContractError::InvalidBound("admission limits must be positive and coherent"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AdmissionRequest {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub caller_authorized: bool,
    pub class: AdmissionClass,
    pub new_pack_count: usize,
    pub active_frontier_packs: usize,
    pub declared_pack_bytes: u64,
    pub declared_objects: u64,
    pub max_single_object_bytes: u64,
    pub estimated_memory_bytes: u64,
    pub estimated_workspace_bytes: u64,
    pub required_fds: u64,
    pub free_disk_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionTelemetrySnapshot {
    pub admitted_total: u64,
    pub rejected_total: u64,
    pub rejected_by_reason: BTreeMap<String, u64>,
    pub active_slots: usize,
    pub active_maintenance_slots: usize,
    pub queued_waiters: usize,
    pub max_queued_waiters_observed: usize,
    pub total_queue_wait_us: u64,
    pub current_workspace_bytes: u64,
    pub peak_workspace_bytes: u64,
    pub current_memory_bytes: u64,
    pub peak_memory_bytes: u64,
    pub current_fds: u64,
    pub peak_fds: u64,
}
