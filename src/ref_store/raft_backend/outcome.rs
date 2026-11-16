//! Durable typed outcomes for Root Ref-CAS application commands.
//!
//! Expected business refusals are replicated application decisions, not storage errors. The
//! reducer records one typed outcome per applied business command in its sealed application state,
//! so a caller can recover the actual result after reply loss/restart without re-deriving it from a
//! raw local snapshot.

use rootyard_refcas_log::state_machine::ApplicationLogId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::CoreGateVersion;
use crate::ref_store::contract::{OperationState, RefStoreError};
use crate::ref_store::core::state_machine::{ApplyResponse, RefCasCommand, ScopeLifecycle, StateMachineError};
use crate::ref_store::core::terminal::CommitTerminal;
use crate::ref_store::core::types::GitObjectFormat;

/// One result of applying a Root business command at an exact Raft coordinate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RootRefCasOutcome {
    Applied(RootRefCasApplied),
    Refused(RootRefCasRefusal),
}

impl RootRefCasOutcome {
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied(_))
    }

    pub fn is_refused(&self) -> bool {
        matches!(self, Self::Refused(_))
    }
}

/// Successful typed application response. This is an explicit, bounded mirror of the core
/// `ApplyResponse`; it carries the actual business fields without requiring a core serde change.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RootRefCasApplied {
    Noop,
    AlreadyApplied {
        log_id: ApplicationLogId,
    },
    GateInitialized {
        version: GateVersionSnapshot,
        created: bool,
    },
    RepositoryLaneUpdated {
        version: GateVersionSnapshot,
        lifecycle: ScopeLifecycle,
        authz_floor: i64,
    },
    OperationBegun {
        operation_id: Uuid,
        state: OperationStateSnapshot,
        created: bool,
    },
    RefsCommitted {
        operation_id: Uuid,
        state: OperationStateSnapshot,
        replayed: bool,
        terminal: CommitTerminal,
    },
    OperationCancelled {
        operation_id: Option<Uuid>,
        state: Option<OperationStateSnapshot>,
        tombstone_created: bool,
        decision_cancelled: Option<Uuid>,
    },
    CancelCutoffAdvanced {
        cutoff_sequence: i64,
        pruned_tombstones: usize,
    },
    DecisionInstalled {
        decision_id: Uuid,
        replayed: bool,
    },
    SnapshotPinCreated {
        snapshot_id: Uuid,
        pin_id: Uuid,
        generation: i64,
        gate_revision: i64,
        expires_at_tick: u64,
        replayed: bool,
    },
    PinRenewed {
        pin_id: Uuid,
        generation: i64,
        expires_at_tick: u64,
        replayed: bool,
    },
    PinReleased {
        pin_id: Uuid,
        generation: i64,
        replayed: bool,
    },
    RootRegistered {
        root_id: Uuid,
        roots_revision: i64,
        replayed: bool,
    },
    RootReleased {
        root_id: Uuid,
        tombstone_created: bool,
        replayed: bool,
    },
    HoldBatchAcquired {
        request_id: Uuid,
        consume_request_id: Uuid,
        hold_count: usize,
        replayed: bool,
    },
    HoldsConsumed {
        consume_request_id: Uuid,
        hold_count: usize,
        replayed: bool,
    },
    HoldsRetired {
        retired_count: usize,
    },
}

impl RootRefCasApplied {
    /// Converts the actual core response without changing core types.
    pub fn from_response(response: ApplyResponse) -> Self {
        match response {
            ApplyResponse::Noop => Self::Noop,
            ApplyResponse::AlreadyApplied { log_id } => {
                Self::AlreadyApplied { log_id: ApplicationLogId::new(log_id.term, log_id.index) }
            }
            ApplyResponse::GateInitialized { version, created } => {
                Self::GateInitialized { version: GateVersionSnapshot::from_core(&version), created }
            }
            ApplyResponse::RepositoryLaneUpdated { version, lifecycle, authz_floor } => Self::RepositoryLaneUpdated {
                version: GateVersionSnapshot::from_core(&version),
                lifecycle,
                authz_floor,
            },
            ApplyResponse::OperationBegun(receipt) => Self::OperationBegun {
                operation_id: receipt.record.identity().operation_id(),
                state: OperationStateSnapshot::from(receipt.record.state()),
                created: receipt.created,
            },
            ApplyResponse::RefsCommitted(receipt) => Self::RefsCommitted {
                operation_id: receipt.record.identity().operation_id(),
                state: OperationStateSnapshot::from(receipt.record.state()),
                replayed: receipt.replayed,
                terminal: receipt.terminal,
            },
            ApplyResponse::OperationCancelled { receipt, decision_cancelled } => Self::OperationCancelled {
                operation_id: receipt.record.as_ref().map(|record| record.identity().operation_id()),
                state: receipt.record.as_ref().map(|record| OperationStateSnapshot::from(record.state())),
                tombstone_created: receipt.tombstone_created,
                decision_cancelled,
            },
            ApplyResponse::CancelCutoffAdvanced { cutoff_sequence, pruned_tombstones } => {
                Self::CancelCutoffAdvanced { cutoff_sequence, pruned_tombstones }
            }
            ApplyResponse::DecisionInstalled { decision_id, replayed } => {
                Self::DecisionInstalled { decision_id, replayed }
            }
            ApplyResponse::SnapshotPinCreated {
                snapshot_id,
                pin_id,
                generation,
                gate_revision,
                expires_at_tick,
                replayed,
            } => Self::SnapshotPinCreated { snapshot_id, pin_id, generation, gate_revision, expires_at_tick, replayed },
            ApplyResponse::PinRenewed { pin_id, generation, expires_at_tick, replayed } => {
                Self::PinRenewed { pin_id, generation, expires_at_tick, replayed }
            }
            ApplyResponse::PinReleased { pin_id, generation, replayed } => {
                Self::PinReleased { pin_id, generation, replayed }
            }
            ApplyResponse::RootRegistered { root_id, roots_revision, replayed } => {
                Self::RootRegistered { root_id, roots_revision, replayed }
            }
            ApplyResponse::RootReleased { root_id, tombstone_created, replayed } => {
                Self::RootReleased { root_id, tombstone_created, replayed }
            }
            ApplyResponse::HoldBatchAcquired { request_id, consume_request_id, hold_count, replayed } => {
                Self::HoldBatchAcquired { request_id, consume_request_id, hold_count, replayed }
            }
            ApplyResponse::HoldsConsumed { consume_request_id, hold_count, replayed } => {
                Self::HoldsConsumed { consume_request_id, hold_count, replayed }
            }
            ApplyResponse::HoldsRetired { retired_count } => Self::HoldsRetired { retired_count },
        }
    }
}

/// Serializable mirror of `CoreGateVersion` captured at the applied coordinate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateVersionSnapshot {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub head_ref: String,
    pub revision: i64,
    pub digest_hex: String,
}

impl GateVersionSnapshot {
    pub fn from_core(version: &CoreGateVersion) -> Self {
        Self {
            repository_id: version.repository_id(),
            tenant_id: version.tenant_id(),
            object_format: version.object_format(),
            history_incarnation: version.history_incarnation(),
            authority_epoch: version.authority_epoch(),
            group_epoch: version.group_epoch(),
            head_ref: version.head_ref().as_str().to_owned(),
            revision: version.revision(),
            digest_hex: version.digest().as_hex(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStateSnapshot {
    Pending,
    Committed,
    Rejected,
    Cancelled,
}

impl From<OperationState> for OperationStateSnapshot {
    fn from(state: OperationState) -> Self {
        match state {
            OperationState::Pending => Self::Pending,
            OperationState::Committed => Self::Committed,
            OperationState::Rejected => Self::Rejected,
            OperationState::Cancelled => Self::Cancelled,
        }
    }
}

/// Typed deterministic business refusal. The `detail` is diagnostic only; classification is the
/// explicit `kind`, never string matching.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootRefCasRefusal {
    pub kind: RootRefCasRefusalKind,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootRefCasRefusalKind {
    BelowCancelCutoff,
    ScopeClosingOrClosed,
    AuthzFloorViolation,
    AuthzFloorRegression,
    LifecycleRegression,
    DecisionNotFound,
    DecisionConflict,
    DecisionExpired,
    DecisionDigestMismatch,
    HoldNotFound,
    HoldNotActive,
    HoldProtectedByRoot,
    HoldScopeMismatch,
    PinNotFound,
    PinExpired,
    PinReleased,
    PinGenerationMismatch,
    SnapshotNotFound,
    RootConflict,
    RootReleased,
    RootDigestConflict,
    QuotaExceeded,
    RepositoryNotFound,
    DigestConflict,
    IdentityConflict,
    CancellationConflict,
    Cancelled,
    UnknownOperation,
    OperationPending,
    GateConflict,
    TerminalImmutable,
    Unsupported,
    MetadataSnapshotNotFound,
    MetadataPinNotFound,
    MetadataPinReleased,
    MetadataPinExpired,
    MetadataPinGenerationMismatch,
    MetadataSnapshotTooLarge,
    MetadataScopeMismatch,
    MetadataCursorScopeMismatch,
    MetadataQuotaExceeded,
    MetadataGateVersionMismatch,
}

impl RootRefCasRefusalKind {
    /// Explicit classification. `None` is fatal: malformed/corrupt input, log-coordinate
    /// invariants, and uncertain storage/transaction state must never become business outcomes.
    pub fn from_state_machine(error: &StateMachineError) -> Option<Self> {
        match error {
            StateMachineError::BelowCancelCutoff { .. } => Some(Self::BelowCancelCutoff),
            StateMachineError::ScopeClosingOrClosed { .. } => Some(Self::ScopeClosingOrClosed),
            StateMachineError::AuthzFloorViolation { .. } => Some(Self::AuthzFloorViolation),
            StateMachineError::AuthzFloorRegression { .. } => Some(Self::AuthzFloorRegression),
            StateMachineError::LifecycleRegression { .. } => Some(Self::LifecycleRegression),
            StateMachineError::DecisionNotFound { .. } => Some(Self::DecisionNotFound),
            StateMachineError::DecisionConflict { .. } => Some(Self::DecisionConflict),
            StateMachineError::DecisionExpired { .. } => Some(Self::DecisionExpired),
            StateMachineError::DecisionDigestMismatch { .. } => Some(Self::DecisionDigestMismatch),
            StateMachineError::HoldNotFound { .. } => Some(Self::HoldNotFound),
            StateMachineError::HoldNotActive { .. } => Some(Self::HoldNotActive),
            StateMachineError::HoldProtectedByRoot { .. } => Some(Self::HoldProtectedByRoot),
            StateMachineError::HoldScopeMismatch { .. } => Some(Self::HoldScopeMismatch),
            StateMachineError::PinNotFound { .. } => Some(Self::PinNotFound),
            StateMachineError::PinExpired { .. } => Some(Self::PinExpired),
            StateMachineError::PinReleased { .. } => Some(Self::PinReleased),
            StateMachineError::PinGenerationMismatch { .. } => Some(Self::PinGenerationMismatch),
            StateMachineError::SnapshotNotFound { .. } => Some(Self::SnapshotNotFound),
            StateMachineError::RootConflict(_) => Some(Self::RootConflict),
            StateMachineError::RootReleased { .. } => Some(Self::RootReleased),
            StateMachineError::RootDigestConflict(_) => Some(Self::RootDigestConflict),
            StateMachineError::QuotaExceeded(_) => Some(Self::QuotaExceeded),
            StateMachineError::Store(error) => Self::from_store(error),
            StateMachineError::InvalidInput(_)
            | StateMachineError::SnapshotCorrupted(_)
            | StateMachineError::NonMonotonicLogIndex { .. } => None,
        }
    }

    fn from_store(error: &RefStoreError) -> Option<Self> {
        match error {
            RefStoreError::RepositoryNotFound => Some(Self::RepositoryNotFound),
            RefStoreError::DigestConflict => Some(Self::DigestConflict),
            RefStoreError::IdentityConflict => Some(Self::IdentityConflict),
            RefStoreError::CancellationConflict => Some(Self::CancellationConflict),
            RefStoreError::Cancelled { .. } => Some(Self::Cancelled),
            RefStoreError::UnknownOperation { .. } => Some(Self::UnknownOperation),
            RefStoreError::OperationPending { .. } => Some(Self::OperationPending),
            RefStoreError::GateConflict => Some(Self::GateConflict),
            RefStoreError::TerminalImmutable => Some(Self::TerminalImmutable),
            RefStoreError::Unsupported(_) => Some(Self::Unsupported),
            RefStoreError::MetadataSnapshotNotFound { .. } => Some(Self::MetadataSnapshotNotFound),
            RefStoreError::MetadataPinNotFound { .. } => Some(Self::MetadataPinNotFound),
            RefStoreError::MetadataPinReleased { .. } => Some(Self::MetadataPinReleased),
            RefStoreError::MetadataPinExpired { .. } => Some(Self::MetadataPinExpired),
            RefStoreError::MetadataPinGenerationMismatch { .. } => Some(Self::MetadataPinGenerationMismatch),
            RefStoreError::MetadataSnapshotTooLarge { .. } => Some(Self::MetadataSnapshotTooLarge),
            RefStoreError::MetadataScopeMismatch(_) => Some(Self::MetadataScopeMismatch),
            RefStoreError::MetadataCursorScopeMismatch => Some(Self::MetadataCursorScopeMismatch),
            RefStoreError::MetadataQuotaExceeded { .. } => Some(Self::MetadataQuotaExceeded),
            RefStoreError::MetadataGateVersionMismatch => Some(Self::MetadataGateVersionMismatch),
            RefStoreError::InvalidIdentity(_)
            | RefStoreError::Timeout
            | RefStoreError::CommitUnknown { .. }
            | RefStoreError::MetadataCommitUnknown { .. }
            | RefStoreError::Database(_) => None,
        }
    }
}

/// Stable lookup key for an idempotent command. Commands without an operation/request/decision id
/// remain queryable by canonical command digest or exact log coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKey {
    Operation(Uuid),
    Request(Uuid),
    Decision(Uuid),
}

/// Public idempotent query selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutcomeQuery {
    Operation(Uuid),
    Request(Uuid),
    Decision(Uuid),
    /// Lowercase 64-character SHA-256 of the canonical command payload.
    CommandDigest(String),
    LogId(ApplicationLogId),
}

/// Persisted typed outcome at one exact application coordinate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredOutcome {
    pub log_id: ApplicationLogId,
    pub command_digest_hex: String,
    pub key: Option<OutcomeKey>,
    pub outcome: RootRefCasOutcome,
}

impl StoredOutcome {
    pub fn matches(&self, query: &OutcomeQuery) -> bool {
        match query {
            OutcomeQuery::Operation(id) => self.key == Some(OutcomeKey::Operation(*id)),
            OutcomeQuery::Request(id) => self.key == Some(OutcomeKey::Request(*id)),
            OutcomeQuery::Decision(id) => self.key == Some(OutcomeKey::Decision(*id)),
            OutcomeQuery::CommandDigest(digest) => self.command_digest_hex.as_str() == digest.as_str(),
            OutcomeQuery::LogId(log_id) => self.log_id == *log_id,
        }
    }
}

/// Canonical command digest used by the outcome ledger and idempotent queries.
pub fn command_digest_hex(payload: &[u8]) -> String {
    hex::encode(Sha256::digest(payload))
}

/// Extracts the stable idempotency key when the command carries one.
pub(crate) fn outcome_key(command: &RefCasCommand) -> Option<OutcomeKey> {
    match command {
        RefCasCommand::BeginOperation(cmd) => Some(OutcomeKey::Operation(cmd.identity.operation_id)),
        RefCasCommand::CommitRefs(cmd) => Some(OutcomeKey::Operation(cmd.request.identity.operation_id)),
        RefCasCommand::Cancel(cmd) => Some(OutcomeKey::Operation(cmd.identity.operation_id)),
        RefCasCommand::CreateSnapshotPin(cmd) => Some(OutcomeKey::Request(cmd.request_id)),
        RefCasCommand::RenewPin(cmd) => Some(OutcomeKey::Request(cmd.request_id)),
        RefCasCommand::ReleasePin(cmd) => Some(OutcomeKey::Request(cmd.request_id)),
        RefCasCommand::RegisterRoot(cmd) => Some(OutcomeKey::Request(cmd.request_id)),
        RefCasCommand::ReleaseRoot(cmd) => Some(OutcomeKey::Request(cmd.request_id)),
        RefCasCommand::AcquireHoldBatch(cmd) => Some(OutcomeKey::Request(cmd.request_id)),
        RefCasCommand::MarkHoldConsumed(cmd) => Some(OutcomeKey::Request(cmd.request_id)),
        RefCasCommand::RetireHoldBatch(cmd) => Some(OutcomeKey::Request(cmd.request_id)),
        RefCasCommand::InstallDecision(cmd) => Some(OutcomeKey::Decision(cmd.decision_id)),
        RefCasCommand::Noop(_)
        | RefCasCommand::InitializeGate(_)
        | RefCasCommand::SetRepositoryLane(_)
        | RefCasCommand::AdvanceCancelCutoff(_) => None,
    }
}

/// One actual propose result: the committed coordinate plus the replicated typed outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposeOutcome {
    pub log_id: ApplicationLogId,
    pub outcome: RootRefCasOutcome,
}
