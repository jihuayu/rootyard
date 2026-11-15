//! Deterministic Ref-CAS Raft state machine (`#116`).
//!
//! Covers `CommitRefs` (atomic & accepted-subset), `Cancel` (including
//! cancel-before-register tombstones and monotonic per-lane `cancel_cutoff`),
//! publication decisions, snapshot/pin leases, retention roots, artifact hold
//! references, idempotent terminal replay/lookup, and SHA-256-sealed snapshots
//! with zero wall-clock reads, Git spawns, Blob I/O, or PostgreSQL calls inside `apply`.

mod apply_commit;
mod apply_decisions;
mod apply_holds;
mod apply_pins;
mod apply_refs;
mod apply_roots;
pub mod commands;
pub mod machine;
pub mod response;
pub mod snapshot;
pub mod state;
pub mod wire;

pub use commands::{
    AcquireHoldBatchCommand, AdvanceCancelCutoffCommand, AppliedLogId, BeginOperationCommand, CancelCommand,
    CommitRefsCommand, CreateSnapshotPinCommand, InitializeGateCommand, InstallDecisionCommand,
    MarkHoldConsumedCommand, NoopCommand, RefCasCommand, RegisterRootCommand, ReleasePinCommand, ReleaseRootCommand,
    RenewPinCommand, RepositoryLane, RetireHoldBatchCommand, ScopeLifecycle, SetRepositoryLaneCommand, SmDecisionState,
    SmHoldState, SmPackMode, SmPinState, SmRootState, WireDecisionKind, WireDecisionVerdict, WireHoldArtifactSpec,
};
pub use machine::{RefCasLogEntry, RefCasStateMachine, decode_command, encode_command};
pub use response::{ApplyResponse, SmOperationRecord, SmVersionCheck, StateMachineError};
pub use snapshot::{RefCasSnapshot, SnapshotBody};
pub use state::{
    CancelTombstone, DecisionRecord, GateState, HoldBatchRecord, HoldConsumeRecord, HoldEntry, HoldRetireRecord,
    LaneKey, LaneState, OperationEntry, PinReceiptRecord, PinRecord, QuotaCounters, QuotaEntry, RepoEntityKey,
    RepoRefsSnapshot, RootReceiptRecord, RootRecordSm, RootReleaseTombstone, SNAPSHOT_FORMAT_VERSION, SnapshotRecord,
    StateMachineEvent,
};
pub use wire::{
    WireCommitRefsRequest, WireCommitRejection, WireCommitTerminal, WireGateInit, WireHeadUpdate, WireHeadUpdateKind,
    WireOperationIdentity, WireOperationRecord, WireRefCommitResult, WireRefUpdate,
};
