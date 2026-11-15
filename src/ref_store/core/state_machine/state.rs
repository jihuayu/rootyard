//! Durable deterministic state records, quota accounting, and `SmState` maps.
//!
//! Every persisted snapshot record carries `#[serde(deny_unknown_fields)]` and
//! `BTreeMap`-ordered fields so identical Raft log execution across replicas
//! yields identical canonical SHA-256 `state_digest()` and `RefCasSnapshot` checksums.

use super::commands::{
    AppliedLogId, RepositoryLane, ScopeLifecycle, SmDecisionState, SmHoldState, SmPinState, SmRootState,
    WireDecisionKind, WireDecisionVerdict, WireHoldArtifactSpec,
};
use super::response::StateMachineError;
use super::wire::{WireOperationIdentity, WireOperationRecord};
use crate::ref_store::contract::{MetadataMutationAction, MetadataPinPurpose, OperationRecord};
use crate::ref_store::core::contract::{CoreGate, CoreGateVersion};
use crate::ref_store::core::pack_commit::PackMode;
use crate::ref_store::core::types::{GitObjectFormat, RefName};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

pub const SNAPSHOT_FORMAT_VERSION: &str = "rootyard-refcas-sm-snapshot/1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepoEntityKey {
    pub repository_id: Uuid,
    pub entity_id: Uuid,
}

impl RepoEntityKey {
    pub fn new(repository_id: Uuid, entity_id: Uuid) -> Self {
        Self { repository_id, entity_id }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaneKey {
    pub repository_id: Uuid,
    pub issuer_id: Uuid,
    pub lane: String,
}

impl LaneKey {
    pub fn new(repository_id: Uuid, issuer_id: Uuid, lane: impl Into<String>) -> Self {
        Self { repository_id, issuer_id, lane: lane.into() }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GateState {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub revision: i64,
    pub roots_revision: i64,
    pub head_ref: String,
    pub pack_mode: PackMode,
    pub lane: RepositoryLane,
    pub lifecycle: ScopeLifecycle,
    pub authz_floor: i64,
}

impl GateState {
    pub fn version(&self) -> Result<CoreGateVersion, StateMachineError> {
        let head = RefName::branch(&self.head_ref)?;
        let gate = CoreGate::new(
            self.repository_id,
            self.tenant_id,
            self.object_format,
            self.history_incarnation,
            self.authority_epoch,
            self.group_epoch,
            head,
            self.revision,
        )?;
        Ok(gate.version())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepoRefsSnapshot {
    pub repository_id: Uuid,
    pub refs: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaneSeqOperation {
    pub sequence: i64,
    pub operation_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaneState {
    pub key: LaneKey,
    pub last_sequence: i64,
    pub cancel_cutoff: i64,
    pub sequence_operations: Vec<LaneSeqOperation>,
}

impl LaneState {
    pub fn new(key: LaneKey) -> Self {
        Self { key, last_sequence: 0, cancel_cutoff: 0, sequence_operations: Vec::new() }
    }

    pub fn record_sequence(&mut self, sequence: i64, operation_id: Uuid) {
        if sequence > self.last_sequence {
            self.last_sequence = sequence;
        }
        if !self.sequence_operations.iter().any(|entry| entry.sequence == sequence) {
            self.sequence_operations.push(LaneSeqOperation { sequence, operation_id });
            self.sequence_operations.sort_by_key(|entry| entry.sequence);
        }
    }

    pub fn operation_for_sequence(&self, sequence: i64) -> Option<Uuid> {
        self.sequence_operations.iter().find(|entry| entry.sequence == sequence).map(|entry| entry.operation_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationEntry {
    pub key: RepoEntityKey,
    pub record: WireOperationRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CancelTombstone {
    pub key: RepoEntityKey,
    pub identity: WireOperationIdentity,
    pub reason: Option<String>,
    pub cancelled_at_tick: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    pub decision_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub operation_id: Uuid,
    pub kind: WireDecisionKind,
    pub state: SmDecisionState,
    pub base_revision: i64,
    pub command_digest: String,
    pub selection_digest: String,
    pub policy_digest: String,
    pub facts_digest: String,
    pub authz_digest: String,
    pub dependencies_digest: String,
    pub verdicts: Vec<WireDecisionVerdict>,
    pub authz_epoch: i64,
    pub installed_at_tick: u64,
    pub not_after_tick: u64,
    pub closed_code: Option<String>,
    pub consume_receipt_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRecord {
    pub snapshot_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: MetadataPinPurpose,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub head_ref: String,
    pub head_oid: Option<String>,
    pub refs: BTreeMap<String, String>,
    pub pack_mode: PackMode,
    pub pack_digests: Vec<String>,
    pub created_tick: u64,
    pub logical_bytes: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PinRecord {
    pub pin_id: Uuid,
    pub snapshot_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: MetadataPinPurpose,
    pub state: SmPinState,
    pub generation: i64,
    pub created_tick: u64,
    pub expires_at_tick: u64,
    pub release_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PinReceiptRecord {
    pub request_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub action: MetadataMutationAction,
    pub pin_id: Uuid,
    pub snapshot_id: Uuid,
    pub pin_generation: i64,
    pub expires_at_tick: u64,
    pub gate_revision: i64,
    pub request_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootRecordSm {
    pub root_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub operation_id: Uuid,
    pub state: SmRootState,
    pub generation: i64,
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
    pub gate_revision: i64,
    pub gate_digest: String,
    pub roots_revision: i64,
    pub register_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootReleaseTombstone {
    pub key: RepoEntityKey,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub expected_register_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootReceiptRecord {
    pub request_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub root_id: Uuid,
    pub action: String,
    pub state: SmRootState,
    pub generation: i64,
    pub roots_revision: i64,
    pub request_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldEntry {
    pub hold_id: Uuid,
    pub batch_request_id: Uuid,
    pub consume_request_id: Uuid,
    pub operation_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: String,
    pub slot: i16,
    pub state: SmHoldState,
    pub generation: i64,
    pub artifact_digest: String,
    pub backend_identity: String,
    pub authority_id: Uuid,
    pub authority_generation: i64,
    pub declared_bytes: i64,
    pub logical_bytes: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldBatchRecord {
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
    pub request_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HoldConsumeRecord {
    pub consume_request_id: Uuid,
    pub request_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub hold_ids: Vec<Uuid>,
    pub request_digest: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaCounters {
    pub snapshots: i64,
    pub snapshot_refs: i64,
    pub snapshot_logical_bytes: i64,
    pub pin_receipts: i64,
    pub roots: i64,
    pub root_receipts: i64,
    pub decisions: i64,
    pub holds: i64,
    pub hold_declared_bytes: i64,
    pub hold_receipts: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaEntry {
    pub scope_id: Uuid,
    pub counters: QuotaCounters,
}

/// Immutable state-machine event ready for cursor-based `#117` replay projections.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateMachineEvent {
    pub event_seq: u64,
    pub log_index: u64,
    pub log_term: u64,
    pub repository_id: Uuid,
    pub revision: i64,
    pub operation_id: Uuid,
    pub outcome: String,
    pub payload: Value,
}

/// In-memory deterministic store owned by [`super::RefCasStateMachine`].
#[derive(Clone, Debug, Default)]
pub(super) struct SmState {
    pub last_applied: Option<AppliedLogId>,
    pub logical_clock_floor: u64,
    pub next_event_seq: u64,
    pub gates: BTreeMap<Uuid, GateState>,
    pub refs: BTreeMap<Uuid, BTreeMap<String, String>>,
    pub lanes: BTreeMap<LaneKey, LaneState>,
    pub operations: BTreeMap<RepoEntityKey, OperationRecord>,
    pub cancellations: BTreeMap<RepoEntityKey, CancelTombstone>,
    pub decisions: BTreeMap<Uuid, DecisionRecord>,
    pub decisions_by_op: BTreeMap<RepoEntityKey, Uuid>,
    pub snapshots: BTreeMap<Uuid, SnapshotRecord>,
    pub pins: BTreeMap<Uuid, PinRecord>,
    pub pin_receipts: BTreeMap<Uuid, PinReceiptRecord>,
    pub roots: BTreeMap<Uuid, RootRecordSm>,
    pub root_tombstones: BTreeMap<RepoEntityKey, RootReleaseTombstone>,
    pub root_receipts: BTreeMap<Uuid, RootReceiptRecord>,
    pub holds: BTreeMap<Uuid, HoldEntry>,
    pub hold_batches: BTreeMap<Uuid, HoldBatchRecord>,
    pub hold_consumes: BTreeMap<Uuid, HoldConsumeRecord>,
    pub repo_quotas: BTreeMap<Uuid, QuotaCounters>,
    pub tenant_quotas: BTreeMap<Uuid, QuotaCounters>,
    pub events: Vec<StateMachineEvent>,
}

impl SmState {
    pub fn advance_clock(&mut self, tick: u64) {
        if tick > self.logical_clock_floor {
            self.logical_clock_floor = tick;
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn push_event(
        &mut self,
        log_id: AppliedLogId,
        repository_id: Uuid,
        revision: i64,
        operation_id: Uuid,
        outcome: &str,
        payload: Value,
    ) {
        self.next_event_seq += 1;
        self.events.push(StateMachineEvent {
            event_seq: self.next_event_seq,
            log_index: log_id.index,
            log_term: log_id.term,
            repository_id,
            revision,
            operation_id,
            outcome: outcome.to_owned(),
            payload,
        });
    }
}
