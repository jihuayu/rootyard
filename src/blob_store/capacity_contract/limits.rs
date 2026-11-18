//! Multi-layer Blob-only Pando capacity contract and codebase fact constants.
//!
//! Separates gateway wire/native limits, RefStore 8 MiB metadata ledger budgets,
//! OpenDAL Blob staging budgets, native verifier window limits, and bounded
//! streaming-growth/compaction limits so no layer conflates metadata row bytes
//! with Blob pack capacity or gateway input ceilings with verifier admission.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::blob_store::budget::{
    DEFAULT_ACTIVE_READERS, DEFAULT_ACTIVE_UPLOADS, DEFAULT_STAGING_BYTES, LEASE_UNIT_BYTES, MAX_ACTIVE_SLOTS,
    MAX_STAGING_BYTES,
};
use crate::blob_store::opendal::{DOWNLOAD_CHUNK_BYTES, MAX_RANGE_BYTES, UPLOAD_CHUNK_BYTES};
use crate::blob_store::types::{MAX_NAMESPACE_BYTES, MAX_OBJECT_BYTES};

use super::inventory::{LayerLimitFact, build_fact_inventory};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

pub const GATEWAY_DEFAULT_MAX_REQUEST_BYTES: u64 = 128 * MIB;
pub const GATEWAY_HARD_MAX_REQUEST_BYTES: u64 = 4 * GIB;
pub const GATEWAY_DEFAULT_MAX_RESPONSE_BYTES: u64 = 512 * MIB;
pub const GATEWAY_HARD_MAX_RESPONSE_BYTES: u64 = 8 * GIB;
pub const GATEWAY_HARD_MAX_INFLIGHT_BYTES: u64 = 64 * GIB;
pub const GATEWAY_MAX_COMMAND_BYTES: usize = 128 * 1024;
pub const GATEWAY_MAX_COMMANDS: usize = 128;
pub const GATEWAY_MAX_NEW_PACKS_PER_PUSH: usize = 8;
pub const GATEWAY_DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 16;
pub const GATEWAY_DEFAULT_NATIVE_CPU_SECONDS: u64 = 300;
pub const GATEWAY_DEFAULT_NATIVE_ADDRESS_SPACE_BYTES: u64 = 2 * GIB;
pub const GATEWAY_DEFAULT_NATIVE_MAX_FILE_BYTES: u64 = 8 * GIB;
pub const GATEWAY_DEFAULT_NATIVE_MAX_OPEN_FILES: u64 = 256;
pub const GATEWAY_DEFAULT_NATIVE_MAX_WORKSPACE_BYTES: u64 = 8 * GIB;
pub const GATEWAY_DEFAULT_NATIVE_MAX_PROCESSES: usize = 16;

pub const LEDGER_REPO_MAX_REGISTRATIONS: i64 = 128;
pub const LEDGER_REPO_MAX_ARTIFACTS: i64 = 256;
pub const LEDGER_REPO_MAX_ACTIVE_MEMBERSHIPS: usize = 16;
/// Metadata ledger row+body byte bound (8 MiB), NOT repository Blob content size.
pub const LEDGER_REPO_MAX_LOGICAL_BYTES: i64 = 8 * MIB as i64;
pub const LEDGER_REPO_MAX_RECEIPTS: i64 = 2048;
pub const LEDGER_TENANT_FACTOR: i64 = 4;
pub const LEDGER_MAX_ACK_BODY_BYTES: usize = 64 * 1024;
pub const LEDGER_MAX_CAPTURE_REFS: usize = 4096;
pub const LEDGER_MAX_PLAN_REFS: usize = 128;

pub const VERIFIER_WINDOW_MAX_PAIRS: usize = 16;
pub const VERIFIER_WINDOW_MAX_TOTAL_BYTES: u64 = 64 * MIB;
pub const VERIFIER_WINDOW_MAX_OBJECTS: u64 = 16_384;
pub const VERIFIER_MAX_CONCURRENT_NATIVE: usize = 2;
pub const VERIFIER_MAX_CONCURRENT_VIEWS: usize = 2;
pub const VERIFIER_VIEW_MAX_LOGICAL_BYTES: u64 = 160 * MIB;
pub const VERIFIER_DOWNLOAD_MAX_CONCURRENT: usize = 4;
pub const VERIFIER_STAGING_MAX_BYTES: u64 = 384 * MIB;
pub const VERIFIER_DISK_HEADROOM_BYTES: u64 = 16 * MIB;
pub const VERIFIER_DEADLINE_SECONDS: u64 = 30;
pub const VERIFIER_GIT_CPU_SECONDS: u64 = 20;
pub const VERIFIER_GIT_ADDRESS_SPACE_BYTES: u64 = 512 * MIB;
pub const VERIFIER_GIT_FILE_SIZE_BYTES: u64 = 128 * MIB;
pub const VERIFIER_GIT_NOFILE: u64 = 64;
pub const VERIFIER_PIPE_BYTES: usize = 2 * MIB as usize;

pub const STREAMING_DEFAULT_COMPACT_TRIGGER_PACKS: usize = 12;
pub const STREAMING_WINDOW_PAIR_BATCH: usize = 8;
pub const STREAMING_IO_CHUNK_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_QUEUE_WAITERS: usize = 32;
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 64 * MIB;
pub const RESERVED_GIT_OPEN_FDS: u64 = 24;
pub const DEFAULT_MAX_RESIDENT_LEDGER_ENTRIES: usize = 4096;
pub const DEFAULT_MAX_RETAINED_PACK_RECORDS: usize = 1024;
pub const DEFAULT_MAX_RETAINED_PACK_BYTES: u64 = 4 * GIB;
pub const DEFAULT_MAX_RESIDENT_REPLAY_OPS: usize = 4096;
pub const DEFAULT_MAX_RESIDENT_OP_FENCES: usize = 65_536;
pub const LEDGER_REPO_MAX_HOLDS: usize = 256;
pub const LEDGER_REPO_MAX_NESTED_HOLDS: usize = 4096;
pub const MAX_REF_NAME_BYTES: usize = 255;
pub const MAX_HOLD_LABEL_BYTES: usize = 256;
pub const DEFAULT_MAX_RESIDENT_REF_AND_HOLD_BYTES: u64 = 2 * MIB;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayLayerContract {
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_inflight_bytes: u64,
    pub max_command_bytes: usize,
    pub max_commands: usize,
    pub max_new_packs_per_push: usize,
    pub max_concurrent_requests: usize,
    pub native_cpu_seconds: u64,
    pub native_address_space_bytes: u64,
    pub native_max_file_bytes: u64,
    pub native_max_open_files: u64,
    pub native_max_workspace_bytes: u64,
    pub native_max_processes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataLedgerContract {
    pub repo_max_registrations: i64,
    pub repo_max_artifacts: i64,
    pub repo_max_active_memberships: usize,
    pub repo_max_logical_bytes: i64,
    pub repo_max_receipts: i64,
    pub tenant_factor: i64,
    pub max_ack_body_bytes: usize,
    pub max_capture_refs: usize,
    pub max_plan_refs: usize,
    pub repo_max_resident_entries: usize,
    pub repo_max_holds: usize,
    pub repo_max_nested_holds: usize,
    pub max_resident_ref_and_hold_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobLayerContract {
    pub max_object_bytes: u64,
    pub max_namespace_bytes: usize,
    pub lease_unit_bytes: u64,
    pub active_uploads: usize,
    pub active_readers: usize,
    pub max_active_slots: usize,
    pub default_staging_bytes: u64,
    pub max_staging_bytes: u64,
    pub upload_chunk_bytes: usize,
    pub download_chunk_bytes: usize,
    pub max_range_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierLayerContract {
    pub max_pairs_per_window: usize,
    pub max_total_bytes_per_window: u64,
    pub max_objects_per_window: u64,
    pub max_concurrent_native: usize,
    pub max_concurrent_views: usize,
    pub view_max_logical_bytes: u64,
    pub download_max_concurrent: usize,
    pub staging_max_bytes: u64,
    pub disk_headroom_bytes: u64,
    pub deadline_seconds: u64,
    pub git_cpu_seconds: u64,
    pub git_address_space_bytes: u64,
    pub git_file_size_bytes: u64,
    pub git_nofile: u64,
    pub pipe_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamingGrowthContract {
    pub compact_trigger_packs: usize,
    pub max_active_frontier_packs: usize,
    pub window_pair_batch: usize,
    pub io_chunk_bytes: usize,
    pub max_queue_waiters: usize,
    pub max_memory_bytes: u64,
    pub max_single_object_bytes: u64,
    pub max_retained_pack_records: usize,
    pub max_retained_pack_bytes: u64,
    pub max_resident_replay_ops: usize,
    pub max_resident_op_fences: usize,
    pub delete_during_compaction_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PandoCapacityContract {
    pub gateway: GatewayLayerContract,
    pub metadata_ledger: MetadataLedgerContract,
    pub blob: BlobLayerContract,
    pub verifier: VerifierLayerContract,
    pub streaming: StreamingGrowthContract,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapacityContractError {
    InvalidBound(&'static str),
    CrossLayerViolation(&'static str),
}

impl fmt::Display for CapacityContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBound(msg) => write!(f, "invalid capacity contract bound: {msg}"),
            Self::CrossLayerViolation(msg) => write!(f, "capacity contract invariant violated: {msg}"),
        }
    }
}

impl std::error::Error for CapacityContractError {}

impl PandoCapacityContract {
    pub fn current_standalone() -> Self {
        Self {
            gateway: GatewayLayerContract {
                max_request_bytes: GATEWAY_DEFAULT_MAX_REQUEST_BYTES,
                max_response_bytes: GATEWAY_DEFAULT_MAX_RESPONSE_BYTES,
                max_inflight_bytes: GATEWAY_HARD_MAX_INFLIGHT_BYTES,
                max_command_bytes: GATEWAY_MAX_COMMAND_BYTES,
                max_commands: GATEWAY_MAX_COMMANDS,
                max_new_packs_per_push: GATEWAY_MAX_NEW_PACKS_PER_PUSH,
                max_concurrent_requests: GATEWAY_DEFAULT_MAX_CONCURRENT_REQUESTS,
                native_cpu_seconds: GATEWAY_DEFAULT_NATIVE_CPU_SECONDS,
                native_address_space_bytes: GATEWAY_DEFAULT_NATIVE_ADDRESS_SPACE_BYTES,
                native_max_file_bytes: GATEWAY_DEFAULT_NATIVE_MAX_FILE_BYTES,
                native_max_open_files: GATEWAY_DEFAULT_NATIVE_MAX_OPEN_FILES,
                native_max_workspace_bytes: GATEWAY_DEFAULT_NATIVE_MAX_WORKSPACE_BYTES,
                native_max_processes: GATEWAY_DEFAULT_NATIVE_MAX_PROCESSES,
            },
            metadata_ledger: MetadataLedgerContract {
                repo_max_registrations: LEDGER_REPO_MAX_REGISTRATIONS,
                repo_max_artifacts: LEDGER_REPO_MAX_ARTIFACTS,
                repo_max_active_memberships: LEDGER_REPO_MAX_ACTIVE_MEMBERSHIPS,
                repo_max_logical_bytes: LEDGER_REPO_MAX_LOGICAL_BYTES,
                repo_max_receipts: LEDGER_REPO_MAX_RECEIPTS,
                tenant_factor: LEDGER_TENANT_FACTOR,
                max_ack_body_bytes: LEDGER_MAX_ACK_BODY_BYTES,
                max_capture_refs: LEDGER_MAX_CAPTURE_REFS,
                max_plan_refs: LEDGER_MAX_PLAN_REFS,
                repo_max_resident_entries: DEFAULT_MAX_RESIDENT_LEDGER_ENTRIES,
                repo_max_holds: LEDGER_REPO_MAX_HOLDS,
                repo_max_nested_holds: LEDGER_REPO_MAX_NESTED_HOLDS,
                max_resident_ref_and_hold_bytes: DEFAULT_MAX_RESIDENT_REF_AND_HOLD_BYTES,
            },
            blob: BlobLayerContract {
                max_object_bytes: MAX_OBJECT_BYTES,
                max_namespace_bytes: MAX_NAMESPACE_BYTES,
                lease_unit_bytes: LEASE_UNIT_BYTES,
                active_uploads: DEFAULT_ACTIVE_UPLOADS,
                active_readers: DEFAULT_ACTIVE_READERS,
                max_active_slots: MAX_ACTIVE_SLOTS,
                default_staging_bytes: DEFAULT_STAGING_BYTES,
                max_staging_bytes: MAX_STAGING_BYTES,
                upload_chunk_bytes: UPLOAD_CHUNK_BYTES,
                download_chunk_bytes: DOWNLOAD_CHUNK_BYTES,
                max_range_bytes: MAX_RANGE_BYTES,
            },
            verifier: VerifierLayerContract {
                max_pairs_per_window: VERIFIER_WINDOW_MAX_PAIRS,
                max_total_bytes_per_window: VERIFIER_WINDOW_MAX_TOTAL_BYTES,
                max_objects_per_window: VERIFIER_WINDOW_MAX_OBJECTS,
                max_concurrent_native: VERIFIER_MAX_CONCURRENT_NATIVE,
                max_concurrent_views: VERIFIER_MAX_CONCURRENT_VIEWS,
                view_max_logical_bytes: VERIFIER_VIEW_MAX_LOGICAL_BYTES,
                download_max_concurrent: VERIFIER_DOWNLOAD_MAX_CONCURRENT,
                staging_max_bytes: VERIFIER_STAGING_MAX_BYTES,
                disk_headroom_bytes: VERIFIER_DISK_HEADROOM_BYTES,
                deadline_seconds: VERIFIER_DEADLINE_SECONDS,
                git_cpu_seconds: VERIFIER_GIT_CPU_SECONDS,
                git_address_space_bytes: VERIFIER_GIT_ADDRESS_SPACE_BYTES,
                git_file_size_bytes: VERIFIER_GIT_FILE_SIZE_BYTES,
                git_nofile: VERIFIER_GIT_NOFILE,
                pipe_bytes: VERIFIER_PIPE_BYTES,
            },
            streaming: StreamingGrowthContract {
                compact_trigger_packs: STREAMING_DEFAULT_COMPACT_TRIGGER_PACKS,
                max_active_frontier_packs: LEDGER_REPO_MAX_ACTIVE_MEMBERSHIPS,
                window_pair_batch: STREAMING_WINDOW_PAIR_BATCH,
                io_chunk_bytes: STREAMING_IO_CHUNK_BYTES,
                max_queue_waiters: DEFAULT_MAX_QUEUE_WAITERS,
                max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
                max_single_object_bytes: VERIFIER_WINDOW_MAX_TOTAL_BYTES,
                max_retained_pack_records: DEFAULT_MAX_RETAINED_PACK_RECORDS,
                max_retained_pack_bytes: DEFAULT_MAX_RETAINED_PACK_BYTES,
                max_resident_replay_ops: DEFAULT_MAX_RESIDENT_REPLAY_OPS,
                max_resident_op_fences: DEFAULT_MAX_RESIDENT_OP_FENCES,
                delete_during_compaction_enabled: false,
            },
        }
    }

    pub fn validate(&self) -> Result<(), CapacityContractError> {
        if self.gateway.max_request_bytes == 0 || self.gateway.max_request_bytes > GATEWAY_HARD_MAX_REQUEST_BYTES {
            return Err(CapacityContractError::InvalidBound("gateway max_request_bytes out of range"));
        }
        if self.gateway.max_inflight_bytes < self.gateway.max_request_bytes {
            return Err(CapacityContractError::InvalidBound("gateway max_inflight_bytes below max_request_bytes"));
        }
        if self.metadata_ledger.repo_max_logical_bytes <= 0 || self.metadata_ledger.tenant_factor <= 0 {
            return Err(CapacityContractError::InvalidBound("metadata ledger budgets must be positive"));
        }
        if self.metadata_ledger.repo_max_active_memberships == 0
            || self.metadata_ledger.repo_max_active_memberships > self.verifier.max_pairs_per_window
        {
            return Err(CapacityContractError::InvalidBound("active memberships must fit within verifier pair window"));
        }
        if self.verifier.max_pairs_per_window == 0
            || self.verifier.max_total_bytes_per_window == 0
            || self.verifier.max_objects_per_window == 0
            || self.verifier.view_max_logical_bytes == 0
            || self.verifier.max_concurrent_native == 0
            || self.verifier.max_concurrent_views == 0
        {
            return Err(CapacityContractError::InvalidBound("verifier bounds must be positive"));
        }
        if self.streaming.compact_trigger_packs == 0
            || self.streaming.compact_trigger_packs > self.streaming.max_active_frontier_packs
        {
            return Err(CapacityContractError::InvalidBound(
                "compact_trigger_packs must be 1..=max_active_frontier_packs",
            ));
        }
        if self.streaming.max_active_frontier_packs > self.verifier.max_pairs_per_window {
            return Err(CapacityContractError::InvalidBound(
                "max_active_frontier_packs cannot exceed verifier max_pairs_per_window",
            ));
        }
        if self.streaming.window_pair_batch == 0
            || self.streaming.window_pair_batch > self.verifier.max_pairs_per_window
        {
            return Err(CapacityContractError::InvalidBound("window_pair_batch must be 1..=max_pairs_per_window"));
        }
        if self.streaming.io_chunk_bytes == 0 || self.streaming.max_memory_bytes < self.streaming.io_chunk_bytes as u64
        {
            return Err(CapacityContractError::InvalidBound("streaming memory budget below chunk size"));
        }
        if self.streaming.max_queue_waiters == 0 || self.streaming.max_single_object_bytes == 0 {
            return Err(CapacityContractError::InvalidBound("queue and object limits must be positive"));
        }
        if self.metadata_ledger.repo_max_resident_entries == 0
            || self.metadata_ledger.max_capture_refs == 0
            || self.metadata_ledger.max_plan_refs == 0
            || self.metadata_ledger.repo_max_holds == 0
            || self.metadata_ledger.repo_max_nested_holds == 0
            || self.metadata_ledger.max_resident_ref_and_hold_bytes == 0
            || self.streaming.max_retained_pack_records == 0
            || self.streaming.max_retained_pack_bytes == 0
            || self.streaming.max_resident_replay_ops == 0
            || self.streaming.max_resident_op_fences < self.streaming.max_resident_replay_ops
        {
            return Err(CapacityContractError::InvalidBound(
                "resident ledger, ref/hold caps, retained pack, and replay/fence caps must be valid",
            ));
        }
        if self.streaming.delete_during_compaction_enabled {
            return Err(CapacityContractError::CrossLayerViolation(
                "compaction must remain no-delete while physical GC is separated",
            ));
        }
        self.check_cross_layer_invariants()
    }

    pub fn check_cross_layer_invariants(&self) -> Result<(), CapacityContractError> {
        let fds_needed =
            (self.streaming.max_active_frontier_packs as u64).saturating_mul(2).saturating_add(RESERVED_GIT_OPEN_FDS);
        if fds_needed > self.verifier.git_nofile {
            return Err(CapacityContractError::CrossLayerViolation(
                "active frontier pack/idx pairs plus Git FDs exceed verifier git_nofile",
            ));
        }
        if self.verifier.max_total_bytes_per_window > self.verifier.view_max_logical_bytes {
            return Err(CapacityContractError::CrossLayerViolation(
                "verifier total pack bytes exceed verifier view logical workspace bound",
            ));
        }
        if self.verifier.staging_max_bytes < self.verifier.view_max_logical_bytes {
            return Err(CapacityContractError::CrossLayerViolation(
                "verifier staging pool cannot accommodate a single full view workspace",
            ));
        }
        if self.blob.max_object_bytes <= self.metadata_ledger.repo_max_logical_bytes as u64 {
            return Err(CapacityContractError::CrossLayerViolation(
                "metadata ledger 8 MiB bound must remain distinct from Blob object ceiling",
            ));
        }
        Ok(())
    }

    pub fn gateway_exceeds_verifier_window(&self) -> bool {
        self.gateway.max_request_bytes > self.verifier.max_total_bytes_per_window
    }

    pub fn fact_inventory(&self) -> Vec<LayerLimitFact> {
        build_fact_inventory(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_contract_validates_and_separates_layers() {
        let contract = PandoCapacityContract::current_standalone();
        assert!(contract.validate().is_ok());
        assert!(contract.gateway_exceeds_verifier_window());
        assert_eq!(contract.metadata_ledger.repo_max_logical_bytes, 8 * 1024 * 1024);
        assert_eq!(contract.metadata_ledger.repo_max_active_memberships, 16);
        assert_eq!(contract.metadata_ledger.max_resident_ref_and_hold_bytes, 2 * 1024 * 1024);
        assert_eq!(contract.verifier.max_pairs_per_window, 16);
        assert_eq!(contract.verifier.max_total_bytes_per_window, 64 * 1024 * 1024);
        assert_eq!(contract.verifier.max_objects_per_window, 16_384);
        assert_eq!(contract.verifier.view_max_logical_bytes, 160 * 1024 * 1024);
        assert!(!contract.streaming.delete_during_compaction_enabled);
        assert!(contract.fact_inventory().iter().any(|f| f.metric == "repo_max_logical_bytes"));
    }

    #[test]
    fn invalid_cross_layer_limits_fail_closed() {
        let mut bad_fds = PandoCapacityContract::current_standalone();
        bad_fds.verifier.git_nofile = 32;
        assert!(matches!(bad_fds.validate(), Err(CapacityContractError::CrossLayerViolation(_))));

        let mut bad_delete = PandoCapacityContract::current_standalone();
        bad_delete.streaming.delete_during_compaction_enabled = true;
        assert!(matches!(bad_delete.validate(), Err(CapacityContractError::CrossLayerViolation(_))));

        let mut bad_ref_hold = PandoCapacityContract::current_standalone();
        bad_ref_hold.metadata_ledger.max_resident_ref_and_hold_bytes = 0;
        assert!(matches!(bad_ref_hold.validate(), Err(CapacityContractError::InvalidBound(_))));
    }
}
