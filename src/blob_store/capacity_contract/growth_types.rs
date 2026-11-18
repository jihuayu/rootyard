//! Types, requests, outcomes, and errors for the bounded streaming growth engine.

use std::{fmt, path::PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    admission_types::AdmissionRejection,
    git_ops::{GitOpsError, ObjectFormat, PackDownloadRef},
    ledger_types::{LedgerRetentionError, LedgerRetentionSummary},
    limits::CapacityContractError,
};
use crate::blob_store::{BlobError, BlobLocator};

#[derive(Debug, Clone)]
pub struct VerifiedPackRecord {
    pub pack_id: Uuid,
    pub registration_id: Uuid,
    pub pack_locator: BlobLocator,
    pub pack_sha256: String,
    pub pack_length: u64,
    pub idx_locator: BlobLocator,
    pub idx_sha256: String,
    pub idx_length: u64,
    pub object_count: u64,
    pub joined_epoch: u64,
}

impl VerifiedPackRecord {
    pub fn as_download_ref(&self) -> PackDownloadRef {
        PackDownloadRef {
            pack_locator: self.pack_locator.clone(),
            pack_sha256: self.pack_sha256.clone(),
            pack_length: self.pack_length,
            idx_locator: self.idx_locator.clone(),
            idx_sha256: self.idx_sha256.clone(),
            idx_length: self.idx_length,
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.pack_length.saturating_add(self.idx_length)
    }
}

#[derive(Debug, Clone)]
pub struct FailedAttemptRecord {
    pub locators: Vec<BlobLocator>,
    pub pack_count: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefMutation {
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
}

#[derive(Debug, Clone)]
pub struct IncrementalPushRequest {
    pub operation_id: Uuid,
    pub request_digest: String,
    pub caller_authorized: bool,
    pub ref_mutations: Vec<RefMutation>,
    pub new_pack_paths: Vec<(PathBuf, PathBuf)>,
    pub free_disk_bytes: u64,
    pub max_single_object_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushOutcome {
    pub epoch: u64,
    pub added_packs: usize,
    pub no_new_pack: bool,
    pub active_frontier_len: usize,
    pub cumulative_packs_added: u64,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionOutcome {
    pub compaction_epoch: u64,
    pub replaced_packs: usize,
    pub compacted_pack_id: Uuid,
    pub preserved_concurrent_packs: usize,
    pub oid_count: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrowthEngineSnapshot {
    pub epoch: u64,
    pub closure_revision: u64,
    pub active_frontier_len: usize,
    pub cumulative_packs_added: u64,
    pub no_new_pack_pushes: u64,
    pub compactions_completed: u64,
    pub active_serving_pack_bytes: u64,
    pub historical_retained_pack_bytes: u64,
    pub failed_attempt_count: u64,
    pub failed_attempt_blob_bytes: u64,
    pub resident_replay_ops: usize,
    pub total_blob_put_bytes: u64,
    pub total_blob_get_bytes: u64,
    pub peak_scratch_bytes: u64,
    pub acked_ref_count: usize,
    pub ledger: LedgerRetentionSummary,
}

#[derive(Debug)]
pub enum GrowthEngineError {
    Contract(CapacityContractError),
    Admission(AdmissionRejection),
    Ledger(LedgerRetentionError),
    GitOps(GitOpsError),
    Blob(BlobError),
    OperationCancelled(Uuid),
    DigestConflict(Uuid),
    CasPreconditionFailed { ref_name: String },
    CompactionConflict,
    InvalidInput(&'static str),
}

impl fmt::Display for GrowthEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(err) => write!(f, "{err}"),
            Self::Admission(err) => write!(f, "{err}"),
            Self::Ledger(err) => write!(f, "{err}"),
            Self::GitOps(err) => write!(f, "{err}"),
            Self::Blob(err) => write!(f, "{err}"),
            Self::OperationCancelled(id) => write!(f, "operation {id} was cancelled"),
            Self::DigestConflict(id) => write!(f, "operation {id} reused with mismatched request digest"),
            Self::CasPreconditionFailed { ref_name } => write!(f, "CAS old_oid mismatch on {ref_name}"),
            Self::CompactionConflict => f.write_str("compaction target packs already superseded"),
            Self::InvalidInput(msg) => write!(f, "invalid growth engine input: {msg}"),
        }
    }
}

impl std::error::Error for GrowthEngineError {}

impl From<CapacityContractError> for GrowthEngineError {
    fn from(v: CapacityContractError) -> Self {
        Self::Contract(v)
    }
}
impl From<AdmissionRejection> for GrowthEngineError {
    fn from(v: AdmissionRejection) -> Self {
        Self::Admission(v)
    }
}
impl From<LedgerRetentionError> for GrowthEngineError {
    fn from(v: LedgerRetentionError) -> Self {
        Self::Ledger(v)
    }
}
impl From<GitOpsError> for GrowthEngineError {
    fn from(v: GitOpsError) -> Self {
        Self::GitOps(v)
    }
}
impl From<BlobError> for GrowthEngineError {
    fn from(v: BlobError) -> Self {
        Self::Blob(v)
    }
}

pub struct EngineScope {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub authority_id: Uuid,
    pub object_format: ObjectFormat,
    pub auto_compact: bool,
}
