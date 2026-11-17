//! Types and budget policy for historical ledger retention accounting.

use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::limits::PandoCapacityContract;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerEntryKind {
    Membership,
    Registration,
    Receipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionHold {
    ActiveServingFrontier { epoch: u64 },
    Pin { pin_id: Uuid, purpose: String },
    RetentionRoot { root_id: Uuid, kind: String },
    BackupManifest { backup_id: Uuid },
}

impl ProtectionHold {
    pub fn hold_id(&self) -> Uuid {
        match self {
            Self::ActiveServingFrontier { .. } => Uuid::nil(),
            Self::Pin { pin_id, .. } => *pin_id,
            Self::RetentionRoot { root_id, .. } => *root_id,
            Self::BackupManifest { backup_id } => *backup_id,
        }
    }

    pub const fn label(&self) -> &'static str {
        match self {
            Self::ActiveServingFrontier { .. } => "active_serving_frontier",
            Self::Pin { .. } => "pin",
            Self::RetentionRoot { .. } => "retention_root",
            Self::BackupManifest { .. } => "backup_manifest",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClassification {
    ActiveProtected,
    CompactedProtected,
    ReleasedEligibleForArchive,
    ArchivedColdCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    pub entry_id: Uuid,
    pub kind: LedgerEntryKind,
    pub pack_id: Option<Uuid>,
    pub operation_id: Option<Uuid>,
    pub logical_bytes: u64,
    pub created_epoch: u64,
    pub superseded_at_epoch: Option<u64>,
    pub holds: BTreeMap<String, ProtectionHold>,
    pub archived: bool,
}

impl LedgerEntry {
    pub fn classification(&self) -> RetentionClassification {
        if self.archived {
            return RetentionClassification::ArchivedColdCheckpoint;
        }
        if self.superseded_at_epoch.is_none() {
            return RetentionClassification::ActiveProtected;
        }
        if !self.holds.is_empty() {
            return RetentionClassification::CompactedProtected;
        }
        RetentionClassification::ReleasedEligibleForArchive
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerBudgetPolicy {
    pub repo_max_logical_bytes: u64,
    pub repo_max_registrations: usize,
    pub repo_max_active_memberships: usize,
    pub repo_max_receipts: usize,
    pub repo_max_resident_entries: usize,
    pub repo_max_holds: usize,
    pub repo_max_nested_holds: usize,
}

impl LedgerBudgetPolicy {
    pub fn from_contract(contract: &PandoCapacityContract) -> Self {
        Self {
            repo_max_logical_bytes: contract.metadata_ledger.repo_max_logical_bytes.max(0) as u64,
            repo_max_registrations: contract.metadata_ledger.repo_max_registrations.max(0) as usize,
            repo_max_active_memberships: contract.metadata_ledger.repo_max_active_memberships,
            repo_max_receipts: contract.metadata_ledger.repo_max_receipts.max(0) as usize,
            repo_max_resident_entries: contract.metadata_ledger.repo_max_resident_entries,
            repo_max_holds: contract.metadata_ledger.repo_max_holds,
            repo_max_nested_holds: contract.metadata_ledger.repo_max_nested_holds,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerRetentionError {
    InvalidArgument(&'static str),
    DuplicateEntry(Uuid),
    EntryNotFound(Uuid),
    HoldNotFound(Uuid),
    ProtectedByHold { entry_id: Uuid, classification: RetentionClassification, holds: Vec<String> },
    CompactionDoesNotAuthorizeDelete { entry_id: Uuid },
    LedgerBudgetExhausted { resource: &'static str, current: u64, limit: u64 },
}

impl fmt::Display for LedgerRetentionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(msg) => write!(f, "invalid ledger argument: {msg}"),
            Self::DuplicateEntry(id) => write!(f, "duplicate ledger entry {id}"),
            Self::EntryNotFound(id) => write!(f, "ledger entry {id} not found"),
            Self::HoldNotFound(id) => write!(f, "retention hold {id} not found"),
            Self::ProtectedByHold { entry_id, classification, holds } => {
                write!(f, "ledger entry {entry_id} ({classification:?}) protected by holds: {}", holds.join(","))
            }
            Self::CompactionDoesNotAuthorizeDelete { entry_id } => {
                write!(f, "compaction does not authorize deleting historical ledger entry {entry_id}")
            }
            Self::LedgerBudgetExhausted { resource, current, limit } => {
                write!(f, "ledger hot budget exhausted on {resource}: {current} >= {limit}")
            }
        }
    }
}

impl std::error::Error for LedgerRetentionError {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRetentionSummary {
    pub active_memberships: usize,
    pub compacted_protected_memberships: usize,
    pub released_memberships: usize,
    pub archived_memberships: usize,
    pub protected_registrations: usize,
    pub released_registrations: usize,
    pub archived_registrations: usize,
    pub protected_receipts: usize,
    pub released_receipts: usize,
    pub archived_receipts: usize,
    pub hot_logical_bytes: u64,
    pub active_logical_bytes: u64,
    pub protected_historical_logical_bytes: u64,
    pub released_logical_bytes: u64,
    pub archived_cold_logical_bytes: u64,
    pub archived_checkpoint_digest: String,
}
