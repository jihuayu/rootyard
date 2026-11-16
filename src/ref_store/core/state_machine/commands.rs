//! Deterministic commands serialized into the Ref-CAS Raft log.
//!
//! `apply` takes only immutable [`AppliedLogId`] metadata plus one [`RefCasCommand`],
//! never querying system clocks, Git processes, Blob storage, or PostgreSQL.

use super::wire::{WireCommitRefsRequest, WireGateInit, WireOperationIdentity};
use crate::ref_store::contract::MetadataPinPurpose;
use crate::ref_store::core::pack_commit::PackMode;
use crate::ref_store::core::terminal::CommitRejectCode;
use crate::ref_store::core::types::GitObjectFormat;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Raft log position fed monotonically into deterministic `apply`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedLogId {
    pub term: u64,
    pub index: u64,
}

/// One-way repository serving lifecycle (`OPEN -> CLOSING -> CLOSED`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeLifecycle {
    Open,
    Closing,
    Closed,
}

/// Mirror of [`PackMode`] with deterministic Serde representation for Raft log & snapshots.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmPackMode {
    MetadataOnly,
    PackVerified,
}

impl From<PackMode> for SmPackMode {
    fn from(value: PackMode) -> Self {
        match value {
            PackMode::MetadataOnly => Self::MetadataOnly,
            PackMode::PackVerified => Self::PackVerified,
        }
    }
}

impl From<SmPackMode> for PackMode {
    fn from(value: SmPackMode) -> Self {
        match value {
            SmPackMode::MetadataOnly => Self::MetadataOnly,
            SmPackMode::PackVerified => Self::PackVerified,
        }
    }
}

/// Authoritative lane for a repository inside the state machine.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryLane {
    LegacyUnservedGitfs,
    ServingRefStore,
}

/// Decision commit mode on wire commands.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireDecisionKind {
    Atomic,
    AcceptedSubset,
}

/// Lifecycle state of an installed publication decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmDecisionState {
    Open,
    Consumed,
    Cancelled,
    Rejected,
}

/// One per-ref policy verdict persisted inside an `OPEN` decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireDecisionVerdict {
    pub ref_name: String,
    pub accepted: bool,
    pub reject_code: Option<CommitRejectCode>,
}

/// Pin/snapshot lifecycle state inside the state machine.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmPinState {
    Active,
    Released,
}

/// Retention root lifecycle state inside the state machine.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmRootState {
    Active,
    Released,
}

/// Artifact hold reference lifecycle state inside the state machine.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmHoldState {
    Active,
    Consumed,
    Retired,
}

/// Specification of one hold reference slot registered into the state machine.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireHoldArtifactSpec {
    pub hold_id: Uuid,
    pub slot: i16,
    pub artifact_digest: String,
    pub declared_bytes: i64,
    pub logical_bytes: i64,
}

/// Initialize a repository core gate cleanly or verify idempotent replay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitializeGateCommand {
    pub gate: WireGateInit,
    pub lane: RepositoryLane,
    pub pack_mode: SmPackMode,
    pub authz_floor: i64,
}

/// Transition repository lane, one-way lifecycle, epochs, or monotonic `authz_floor`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetRepositoryLaneCommand {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub lane: RepositoryLane,
    pub lifecycle: ScopeLifecycle,
    pub authz_floor: i64,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub pack_mode: SmPackMode,
}

/// Register a pending operation in the migration-138-compatible registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BeginOperationCommand {
    pub identity: WireOperationIdentity,
    pub logical_tick: u64,
}

/// Deterministically commit (atomic or accepted-subset) ref updates and HEAD.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRefsCommand {
    pub request: WireCommitRefsRequest,
    pub decision_id: Option<Uuid>,
    pub required_holds: Vec<Uuid>,
    pub policy_rejects: BTreeMap<String, CommitRejectCode>,
    pub logical_tick: u64,
}

/// Cancel an operation (including cancel-before-register tombstone) and optional open decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelCommand {
    pub identity: WireOperationIdentity,
    pub reason: Option<String>,
    pub logical_tick: u64,
}

/// Advance the monotonic per-lane cancellation cutoff sequence watermark.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdvanceCancelCutoffCommand {
    pub repository_id: Uuid,
    pub issuer_id: Uuid,
    pub lane: String,
    pub cutoff_sequence: i64,
    pub prune_tombstones_up_to_cutoff: bool,
}

/// Install an `OPEN` publication decision referencing sealed policy/facts/selection digests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallDecisionCommand {
    pub decision_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub operation_id: Uuid,
    pub kind: WireDecisionKind,
    pub base_revision: i64,
    pub command_digest: String,
    pub selection_digest: String,
    pub policy_digest: String,
    pub facts_digest: String,
    pub authz_digest: String,
    pub dependencies_digest: String,
    pub verdicts: Vec<WireDecisionVerdict>,
    pub authz_epoch: i64,
    pub not_after_tick: u64,
    pub logical_tick: u64,
}

/// Capture an immutable metadata/pack snapshot and create its leased pin deterministically.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSnapshotPinCommand {
    pub request_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: MetadataPinPurpose,
    pub snapshot_id: Uuid,
    pub pin_id: Uuid,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub expected_gate_digest: String,
    pub lease_ticks: u64,
    pub logical_tick: u64,
    pub pack_digests: Vec<String>,
    pub request_digest: String,
}

/// Renew an active, unexpired pin generation cleanly using logical ticks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RenewPinCommand {
    pub request_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub pin_id: Uuid,
    pub expected_generation: i64,
    pub lease_ticks: u64,
    pub logical_tick: u64,
    pub request_digest: String,
}

/// Release a pin permanently (allowed even after logical-tick lease expiry).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePinCommand {
    pub request_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub pin_id: Uuid,
    pub reason: String,
    pub logical_tick: u64,
    pub request_digest: String,
}

/// Register an immutable, non-expiring retention root reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRootCommand {
    pub request_id: Uuid,
    pub root_id: Uuid,
    pub operation_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: String,
    pub business_intent_digest: String,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub source_snapshot_id: Uuid,
    pub source_pin_id: Uuid,
    pub source_pin_generation: i64,
    pub selector_kind: String,
    pub selector_digest: String,
    pub refs_digest: String,
    pub pack_set_digest: String,
    pub bound_hold_ids: Vec<Uuid>,
    pub register_digest: String,
    pub request_digest: String,
}

/// Permanently release (or tombstone before register) one retention root reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRootCommand {
    pub request_id: Uuid,
    pub root_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub expected_register_digest: String,
    pub intent_digest: String,
}

/// Register an artifact hold batch reference inside the state machine (no Blob I/O).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcquireHoldBatchCommand {
    pub request_id: Uuid,
    pub consume_request_id: Uuid,
    pub operation_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: String,
    pub backend_identity: String,
    pub authority_id: Uuid,
    pub authority_generation: i64,
    pub expected_gate_digest: String,
    pub artifacts: Vec<WireHoldArtifactSpec>,
}

/// Mark a batch of active holds consumed one-way.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MarkHoldConsumedCommand {
    pub consume_request_id: Uuid,
    pub request_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub hold_ids: Vec<Uuid>,
}

/// Retire hold references that are no longer protected by any active retention root.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetireHoldBatchCommand {
    pub request_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub hold_ids: Vec<Uuid>,
}

/// Blank/barrier entry (maps cleanly to Raft `EntryPayload::Blank`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NoopCommand {
    pub logical_tick: Option<u64>,
}

/// Persisted PostgreSQL `ref_store_decision_dependencies` binding carried on a scoped grant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireDecisionScopeDep {
    pub scope_kind: String,
    pub scope_id: Uuid,
    pub observed_version: i64,
    pub observed_digest: String,
}

/// Project PG `OPEN -> CLOSING` (or `Closed`) scope revocation monotonically onto Raft (`#152`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloseAuthScopeCommand {
    pub scope_kind: String,
    pub scope_id: Uuid,
    pub repository_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub lifecycle: ScopeLifecycle,
    pub authz_floor: i64,
    pub change_id: Uuid,
    pub logical_tick: u64,
}

/// Signed remote authorization grant commitments bound through install & commit (`#152`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireDecisionGrantCommitment {
    pub base_gate_digest: String,
    pub packs_digest: String,
    pub hold_receipts_digest: String,
    pub captured_oid_digest: String,
    pub required_holds: Vec<Uuid>,
}

/// Install a decision together with its indexed `(scope_kind, scope_id)` dependencies (`#152`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstallScopedDecisionCommand {
    pub decision: InstallDecisionCommand,
    pub scope_dependencies: Vec<WireDecisionScopeDep>,
    pub grant_commitment: WireDecisionGrantCommitment,
}

/// Commit refs under an installed scoped decision while enforcing signed grant commitments (`#152`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitScopedRefsCommand {
    pub commit: CommitRefsCommand,
    pub expected_commitment: WireDecisionGrantCommitment,
}

/// Deterministic command union accepted by [`super::RefCasStateMachine`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum RefCasCommand {
    Noop(NoopCommand),
    InitializeGate(InitializeGateCommand),
    SetRepositoryLane(SetRepositoryLaneCommand),
    BeginOperation(BeginOperationCommand),
    CommitRefs(CommitRefsCommand),
    CommitScopedRefs(CommitScopedRefsCommand),
    Cancel(CancelCommand),
    AdvanceCancelCutoff(AdvanceCancelCutoffCommand),
    InstallDecision(InstallDecisionCommand),
    InstallScopedDecision(InstallScopedDecisionCommand),
    CloseAuthScope(CloseAuthScopeCommand),
    CreateSnapshotPin(CreateSnapshotPinCommand),
    RenewPin(RenewPinCommand),
    ReleasePin(ReleasePinCommand),
    RegisterRoot(RegisterRootCommand),
    ReleaseRoot(ReleaseRootCommand),
    AcquireHoldBatch(AcquireHoldBatchCommand),
    MarkHoldConsumed(MarkHoldConsumedCommand),
    RetireHoldBatch(RetireHoldBatchCommand),
}
