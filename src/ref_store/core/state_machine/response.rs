//! Deterministic responses and error types returned by `RefCasStateMachine::apply` and queries.

use super::commands::{AppliedLogId, ScopeLifecycle, SmDecisionState, SmHoldState};
use crate::ref_store::contract::{BeginReceipt, CancelReceipt, OperationRecord, RefStoreError};
use crate::ref_store::core::contract::{CoreGateVersion, VersionCheck};
use crate::ref_store::core::terminal::CommitRefsReceipt;
use std::fmt;
use uuid::Uuid;

/// Response produced deterministically by applying one [`super::RefCasCommand`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplyResponse {
    Noop,
    AlreadyApplied {
        log_id: AppliedLogId,
    },
    GateInitialized {
        version: CoreGateVersion,
        created: bool,
    },
    RepositoryLaneUpdated {
        version: CoreGateVersion,
        lifecycle: ScopeLifecycle,
        authz_floor: i64,
    },
    OperationBegun(BeginReceipt),
    RefsCommitted(CommitRefsReceipt),
    OperationCancelled {
        receipt: CancelReceipt,
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

/// Query output for [`super::RefCasStateMachine::check_version`] (wraps [`VersionCheck`]).
pub type SmVersionCheck = VersionCheck;
/// Query output for [`super::RefCasStateMachine::query_operation`].
pub type SmOperationRecord = OperationRecord;

/// Deterministic error returned without mutating state-machine tables.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateMachineError {
    Store(RefStoreError),
    NonMonotonicLogIndex { expected_gt: u64, got: u64 },
    BelowCancelCutoff { operation_id: Uuid, sequence: i64, cutoff: i64 },
    ScopeClosingOrClosed { repository_id: Uuid, lifecycle: ScopeLifecycle },
    AuthzFloorViolation { authz_epoch: i64, floor: i64 },
    AuthzFloorRegression { current_floor: i64, requested_floor: i64 },
    LifecycleRegression { current: ScopeLifecycle, requested: ScopeLifecycle },
    DecisionNotFound { decision_id: Uuid },
    DecisionConflict { decision_id: Uuid, state: SmDecisionState },
    DecisionExpired { decision_id: Uuid, not_after_tick: u64, current_tick: u64 },
    DecisionDigestMismatch { decision_id: Uuid, reason: &'static str },
    HoldNotFound { hold_id: Uuid },
    HoldNotActive { hold_id: Uuid, state: SmHoldState },
    HoldProtectedByRoot { hold_id: Uuid, root_id: Uuid },
    HoldScopeMismatch { hold_id: Uuid },
    PinNotFound { pin_id: Uuid },
    PinExpired { pin_id: Uuid, expires_at_tick: u64, current_tick: u64 },
    PinReleased { pin_id: Uuid },
    PinGenerationMismatch { pin_id: Uuid, expected: i64, actual: i64 },
    SnapshotNotFound { snapshot_id: Uuid },
    RootConflict(&'static str),
    RootReleased { root_id: Uuid },
    RootDigestConflict(&'static str),
    QuotaExceeded(&'static str),
    InvalidInput(String),
    SnapshotCorrupted(String),
}

impl From<RefStoreError> for StateMachineError {
    fn from(error: RefStoreError) -> Self {
        Self::Store(error)
    }
}

impl fmt::Display for StateMachineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(err) => write!(f, "{err}"),
            Self::NonMonotonicLogIndex { expected_gt, got } => {
                write!(f, "non-monotonic Raft log index {got}; expected > {expected_gt}")
            }
            Self::BelowCancelCutoff { operation_id, sequence, cutoff } => {
                write!(f, "operation {operation_id} sequence {sequence} is <= cancel_cutoff {cutoff}")
            }
            Self::ScopeClosingOrClosed { repository_id, lifecycle } => {
                write!(f, "repository {repository_id} scope is {lifecycle:?} and refuses fresh mutations")
            }
            Self::AuthzFloorViolation { authz_epoch, floor } => {
                write!(f, "authorization epoch {authz_epoch} is below monotonic floor {floor}")
            }
            Self::AuthzFloorRegression { current_floor, requested_floor } => {
                write!(f, "cannot lower authz_floor from {current_floor} to {requested_floor}")
            }
            Self::LifecycleRegression { current, requested } => {
                write!(f, "cannot regress scope lifecycle from {current:?} to {requested:?}")
            }
            Self::DecisionNotFound { decision_id } => write!(f, "decision {decision_id} not found"),
            Self::DecisionConflict { decision_id, state } => {
                write!(f, "decision {decision_id} conflict in state {state:?}")
            }
            Self::DecisionExpired { decision_id, not_after_tick, current_tick } => {
                write!(f, "decision {decision_id} expired at tick {not_after_tick} (current {current_tick})")
            }
            Self::DecisionDigestMismatch { decision_id, reason } => {
                write!(f, "decision {decision_id} digest/scope mismatch: {reason}")
            }
            Self::HoldNotFound { hold_id } => write!(f, "hold {hold_id} not found"),
            Self::HoldNotActive { hold_id, state } => write!(f, "hold {hold_id} is {state:?}, not active"),
            Self::HoldProtectedByRoot { hold_id, root_id } => {
                write!(f, "hold {hold_id} is protected by active retention root {root_id}")
            }
            Self::HoldScopeMismatch { hold_id } => write!(f, "hold {hold_id} scope/operation mismatch"),
            Self::PinNotFound { pin_id } => write!(f, "pin {pin_id} not found"),
            Self::PinExpired { pin_id, expires_at_tick, current_tick } => {
                write!(f, "pin {pin_id} expired at tick {expires_at_tick} (current {current_tick})")
            }
            Self::PinReleased { pin_id } => write!(f, "pin {pin_id} is permanently released"),
            Self::PinGenerationMismatch { pin_id, expected, actual } => {
                write!(f, "pin {pin_id} expected generation {expected}, got {actual}")
            }
            Self::SnapshotNotFound { snapshot_id } => write!(f, "snapshot {snapshot_id} not found"),
            Self::RootConflict(msg) | Self::RootDigestConflict(msg) | Self::QuotaExceeded(msg) => {
                write!(f, "{msg}")
            }
            Self::RootReleased { root_id } => write!(f, "retention root {root_id} already released"),
            Self::InvalidInput(msg) => write!(f, "invalid command input: {msg}"),
            Self::SnapshotCorrupted(msg) => write!(f, "corrupted state-machine snapshot: {msg}"),
        }
    }
}

impl std::error::Error for StateMachineError {}
