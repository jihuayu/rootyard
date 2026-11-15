//! Canonical SHA-256-sealed snapshot representation and state recovery for `RefCasStateMachine`.
//!
//! Snapshots persist pins, snapshot headers, retention roots, publication decisions,
//! artifact hold references, operation records, gates, refs, and per-lane `cancel_cutoff`
//! watermarks, with `#[serde(deny_unknown_fields)]` on every persisted structure.

use super::commands::AppliedLogId;
use super::response::StateMachineError;
use super::state::{
    CancelTombstone, DecisionRecord, GateState, HoldBatchRecord, HoldConsumeRecord, HoldEntry, HoldRetireRecord,
    LaneState, OperationEntry, PinReceiptRecord, PinRecord, QuotaEntry, RepoEntityKey, RepoRefsSnapshot,
    RootReceiptRecord, RootRecordSm, RootReleaseTombstone, SNAPSHOT_FORMAT_VERSION, SmState, SnapshotRecord,
    StateMachineEvent,
};
use super::wire::WireOperationRecord;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Canonical payload covered by [`RefCasSnapshot::checksum`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBody {
    pub format_version: String,
    pub last_applied: Option<AppliedLogId>,
    pub logical_clock_floor: u64,
    pub next_event_seq: u64,
    pub gates: Vec<GateState>,
    pub refs: Vec<RepoRefsSnapshot>,
    pub lanes: Vec<LaneState>,
    pub operations: Vec<OperationEntry>,
    pub cancellations: Vec<CancelTombstone>,
    pub decisions: Vec<DecisionRecord>,
    pub snapshots: Vec<SnapshotRecord>,
    pub pins: Vec<PinRecord>,
    pub pin_receipts: Vec<PinReceiptRecord>,
    pub roots: Vec<RootRecordSm>,
    pub root_tombstones: Vec<RootReleaseTombstone>,
    pub root_receipts: Vec<RootReceiptRecord>,
    pub holds: Vec<HoldEntry>,
    pub hold_batches: Vec<HoldBatchRecord>,
    pub hold_consumes: Vec<HoldConsumeRecord>,
    pub hold_retires: Vec<HoldRetireRecord>,
    pub repo_quotas: Vec<QuotaEntry>,
    pub tenant_quotas: Vec<QuotaEntry>,
    pub events: Vec<StateMachineEvent>,
}

/// Self-verifying deterministic Raft state-machine snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefCasSnapshot {
    pub body: SnapshotBody,
    pub checksum: String,
}

impl RefCasSnapshot {
    /// Seal a canonical [`SnapshotBody`] with a SHA-256 domain-separated digest.
    pub fn seal(body: SnapshotBody) -> Result<Self, StateMachineError> {
        let checksum = compute_body_checksum(&body)?;
        Ok(Self { body, checksum })
    }

    /// Verify format version and cryptographic digest before restoring any snapshot.
    pub fn verify_integrity(&self) -> Result<(), StateMachineError> {
        if self.body.format_version != SNAPSHOT_FORMAT_VERSION {
            return Err(StateMachineError::SnapshotCorrupted(format!(
                "unsupported snapshot format version {}",
                self.body.format_version
            )));
        }
        let expected = compute_body_checksum(&self.body)?;
        if expected != self.checksum {
            return Err(StateMachineError::SnapshotCorrupted("snapshot SHA-256 checksum mismatch".into()));
        }
        Ok(())
    }
}

pub(super) fn compute_body_checksum(body: &SnapshotBody) -> Result<String, StateMachineError> {
    let encoded = serde_json::to_vec(body)
        .map_err(|err| StateMachineError::SnapshotCorrupted(format!("snapshot serialize failed: {err}")))?;
    let mut hasher = Sha256::new();
    hasher.update(b"rootyard-refcas-sm-snapshot-checksum-v1\0");
    hasher.update(encoded);
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn export_snapshot_body(state: &SmState) -> SnapshotBody {
    let mut operations: Vec<OperationEntry> = state
        .operations
        .iter()
        .map(|(key, record)| OperationEntry { key: *key, record: WireOperationRecord::from_record(record) })
        .collect();
    operations.sort_by_key(|entry| entry.key);
    let refs = state
        .refs
        .iter()
        .map(|(repository_id, map)| RepoRefsSnapshot { repository_id: *repository_id, refs: map.clone() })
        .collect();
    let repo_quotas = state
        .repo_quotas
        .iter()
        .map(|(scope_id, counters)| QuotaEntry { scope_id: *scope_id, counters: *counters })
        .collect();
    let tenant_quotas = state
        .tenant_quotas
        .iter()
        .map(|(scope_id, counters)| QuotaEntry { scope_id: *scope_id, counters: *counters })
        .collect();
    SnapshotBody {
        format_version: SNAPSHOT_FORMAT_VERSION.to_owned(),
        last_applied: state.last_applied,
        logical_clock_floor: state.logical_clock_floor,
        next_event_seq: state.next_event_seq,
        gates: state.gates.values().cloned().collect(),
        refs,
        lanes: state.lanes.values().cloned().collect(),
        operations,
        cancellations: state.cancellations.values().cloned().collect(),
        decisions: state.decisions.values().cloned().collect(),
        snapshots: state.snapshots.values().cloned().collect(),
        pins: state.pins.values().cloned().collect(),
        pin_receipts: state.pin_receipts.values().cloned().collect(),
        roots: state.roots.values().cloned().collect(),
        root_tombstones: state.root_tombstones.values().cloned().collect(),
        root_receipts: state.root_receipts.values().cloned().collect(),
        holds: state.holds.values().cloned().collect(),
        hold_batches: state.hold_batches.values().cloned().collect(),
        hold_consumes: state.hold_consumes.values().cloned().collect(),
        hold_retires: state.hold_retires.values().cloned().collect(),
        repo_quotas,
        tenant_quotas,
        events: state.events.clone(),
    }
}

pub(super) fn restore_from_snapshot(snapshot: &RefCasSnapshot) -> Result<SmState, StateMachineError> {
    snapshot.verify_integrity()?;
    let body = &snapshot.body;
    let mut state = SmState {
        last_applied: body.last_applied,
        logical_clock_floor: body.logical_clock_floor,
        next_event_seq: body.next_event_seq,
        events: body.events.clone(),
        ..SmState::default()
    };
    for gate in &body.gates {
        gate.version()?;
        insert_unique(&mut state.gates, gate.repository_id, gate.clone(), "gate")?;
    }
    for repo_refs in &body.refs {
        insert_unique(&mut state.refs, repo_refs.repository_id, repo_refs.refs.clone(), "refs map")?;
    }
    for lane in &body.lanes {
        insert_unique(&mut state.lanes, lane.key.clone(), lane.clone(), "lane")?;
    }
    for op in &body.operations {
        let record = op
            .record
            .clone()
            .into_record()
            .map_err(|err| StateMachineError::SnapshotCorrupted(format!("invalid operation record: {err}")))?;
        if record.identity().repository_id() != op.key.repository_id
            || record.identity().operation_id() != op.key.entity_id
        {
            return Err(StateMachineError::SnapshotCorrupted("operation key/identity mismatch".into()));
        }
        insert_unique(&mut state.operations, op.key, record, "operation")?;
    }
    for cancel in &body.cancellations {
        insert_unique(&mut state.cancellations, cancel.key, cancel.clone(), "cancel tombstone")?;
    }
    for decision in &body.decisions {
        let op_key = RepoEntityKey::new(decision.repository_id, decision.operation_id);
        insert_unique(&mut state.decisions, decision.decision_id, decision.clone(), "decision")?;
        insert_unique(&mut state.decisions_by_op, op_key, decision.decision_id, "decision op index")?;
    }
    for snap in &body.snapshots {
        insert_unique(&mut state.snapshots, snap.snapshot_id, snap.clone(), "snapshot header")?;
    }
    for pin in &body.pins {
        insert_unique(&mut state.pins, pin.pin_id, pin.clone(), "pin")?;
    }
    for receipt in &body.pin_receipts {
        insert_unique(&mut state.pin_receipts, receipt.request_id, receipt.clone(), "pin receipt")?;
    }
    for root in &body.roots {
        insert_unique(&mut state.roots, root.root_id, root.clone(), "root")?;
    }
    for tomb in &body.root_tombstones {
        insert_unique(&mut state.root_tombstones, tomb.key, tomb.clone(), "root tombstone")?;
    }
    for receipt in &body.root_receipts {
        insert_unique(&mut state.root_receipts, receipt.request_id, receipt.clone(), "root receipt")?;
    }
    for hold in &body.holds {
        insert_unique(&mut state.holds, hold.hold_id, hold.clone(), "hold")?;
    }
    for batch in &body.hold_batches {
        insert_unique(&mut state.hold_batches, batch.request_id, batch.clone(), "hold batch")?;
    }
    for consume in &body.hold_consumes {
        insert_unique(&mut state.hold_consumes, consume.consume_request_id, consume.clone(), "hold consume")?;
    }
    for retire in &body.hold_retires {
        insert_unique(&mut state.hold_retires, retire.request_id, retire.clone(), "hold retire")?;
    }
    for q in &body.repo_quotas {
        state.repo_quotas.insert(q.scope_id, q.counters);
    }
    for q in &body.tenant_quotas {
        state.tenant_quotas.insert(q.scope_id, q.counters);
    }
    Ok(state)
}

fn insert_unique<K: Ord, V>(map: &mut BTreeMap<K, V>, key: K, value: V, label: &str) -> Result<(), StateMachineError> {
    if map.insert(key, value).is_some() {
        return Err(StateMachineError::SnapshotCorrupted(format!("duplicate {label} in snapshot")));
    }
    Ok(())
}
