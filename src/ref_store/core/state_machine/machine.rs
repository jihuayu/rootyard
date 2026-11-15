//! Deterministic Ref-CAS Raft state machine facade, snapshot recovery, and queries.

use super::apply_commit::commit_refs;
use super::apply_decisions::install_decision;
use super::apply_holds::{acquire_hold_batch, mark_hold_consumed, retire_hold_batch};
use super::apply_pins::{create_snapshot_pin, release_pin, renew_pin};
use super::apply_refs::{
    advance_cancel_cutoff, begin_operation, cancel_operation, initialize_gate, set_repository_lane,
};
use super::apply_roots::{register_root, release_root};
use super::commands::{AppliedLogId, RefCasCommand, ScopeLifecycle};
use super::response::{ApplyResponse, StateMachineError};
use super::snapshot::{RefCasSnapshot, compute_body_checksum, export_snapshot_body, restore_from_snapshot};
use super::state::{
    DecisionRecord, HoldEntry, LaneKey, PinRecord, RepoEntityKey, RootRecordSm, SmState, SnapshotRecord,
    StateMachineEvent,
};
use crate::ref_store::contract::{IssuerLane, OperationLookup, RefStoreError};
use crate::ref_store::core::contract::{CoreGateVersion, VersionCheck};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Deterministic Ref-CAS Raft state machine with zero external I/O and zero wall clocks.
#[derive(Clone, Debug, Default)]
pub struct RefCasStateMachine {
    state: SmState,
}

/// Wire entry wrapper coupling Raft `(term, index)` metadata with serialized command bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefCasLogEntry {
    pub log_id: AppliedLogId,
    pub payload: Vec<u8>,
}

/// Canonical command codec helpers (`Vec<u8>` compatible with `openraft` `D = Vec<u8>`).
pub fn encode_command(command: &RefCasCommand) -> Result<Vec<u8>, StateMachineError> {
    serde_json::to_vec(command).map_err(|err| StateMachineError::InvalidInput(format!("encode command failed: {err}")))
}

/// Decode a serialized [`RefCasCommand`] enforcing strict JSON / `deny_unknown_fields` checks.
pub fn decode_command(payload: &[u8]) -> Result<RefCasCommand, StateMachineError> {
    serde_json::from_slice(payload)
        .map_err(|err| StateMachineError::InvalidInput(format!("decode command failed: {err}")))
}

impl RefCasStateMachine {
    /// Construct an empty state machine at `(last_applied = None, logical_clock_floor = 0)`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Deterministically apply one Raft log entry at strictly increasing `log_id.index`.
    ///
    /// On any [`StateMachineError`], state remains rolled back atomically, preserving exact
    /// replica determinism even when an invalid or conflicting command is proposed.
    pub fn apply(&mut self, log_id: AppliedLogId, command: RefCasCommand) -> Result<ApplyResponse, StateMachineError> {
        if let Some(last) = self.state.last_applied
            && log_id.index <= last.index
        {
            return Err(StateMachineError::NonMonotonicLogIndex { expected_gt: last.index, got: log_id.index });
        }
        let mut staged = self.state.clone();
        let response = apply_inner(&mut staged, log_id, command)?;
        staged.last_applied = Some(log_id);
        self.state = staged;
        Ok(response)
    }

    /// Decode serialized `Vec<u8>` Raft payload and apply it deterministically.
    pub fn apply_bytes(&mut self, log_id: AppliedLogId, payload: &[u8]) -> Result<ApplyResponse, StateMachineError> {
        let command = decode_command(payload)?;
        self.apply(log_id, command)
    }

    /// Recover/replay a sequence of Raft log entries cleanly after snapshot restore.
    ///
    /// Entries whose `log_id.index <= last_applied.index` are skipped deterministically as
    /// [`ApplyResponse::AlreadyApplied`]; strictly higher entries are applied in order.
    pub fn recover_entries<I>(&mut self, entries: I) -> Result<Vec<ApplyResponse>, StateMachineError>
    where
        I: IntoIterator<Item = RefCasLogEntry>,
    {
        let mut out = Vec::new();
        for entry in entries {
            if let Some(last) = self.state.last_applied
                && entry.log_id.index <= last.index
            {
                out.push(ApplyResponse::AlreadyApplied { log_id: entry.log_id });
                continue;
            }
            out.push(self.apply_bytes(entry.log_id, &entry.payload)?);
        }
        Ok(out)
    }

    /// Capture a canonical SHA-256-sealed snapshot covering pins, roots, decisions, holds, and `cancel_cutoff`.
    pub fn snapshot(&self) -> Result<RefCasSnapshot, StateMachineError> {
        RefCasSnapshot::seal(export_snapshot_body(&self.state))
    }

    /// Serialize [`Self::snapshot`] to canonical JSON bytes.
    pub fn snapshot_bytes(&self) -> Result<Vec<u8>, StateMachineError> {
        let snap = self.snapshot()?;
        serde_json::to_vec(&snap)
            .map_err(|err| StateMachineError::SnapshotCorrupted(format!("snapshot encode failed: {err}")))
    }

    /// Restore a state machine from a verified [`RefCasSnapshot`].
    pub fn restore(snapshot: &RefCasSnapshot) -> Result<Self, StateMachineError> {
        let state = restore_from_snapshot(snapshot)?;
        Ok(Self { state })
    }

    /// Decode and verify serialized snapshot bytes before restoring state.
    pub fn restore_bytes(bytes: &[u8]) -> Result<Self, StateMachineError> {
        let snapshot: RefCasSnapshot = serde_json::from_slice(bytes)
            .map_err(|err| StateMachineError::SnapshotCorrupted(format!("snapshot decode failed: {err}")))?;
        Self::restore(&snapshot)
    }

    /// Deterministic SHA-256 digest of the complete materialized state.
    pub fn state_digest(&self) -> Result<String, StateMachineError> {
        compute_body_checksum(&export_snapshot_body(&self.state))
    }

    pub fn last_applied(&self) -> Option<AppliedLogId> {
        self.state.last_applied
    }

    pub fn logical_clock_floor(&self) -> u64 {
        self.state.logical_clock_floor
    }

    /// Linearized gate-version observation matching [`PgRefStoreCore::check_version`].
    pub fn check_version(
        &self,
        repository_id: Uuid,
        tenant_id: Uuid,
        known: Option<&CoreGateVersion>,
    ) -> Result<VersionCheck, StateMachineError> {
        if repository_id.is_nil() || tenant_id.is_nil() {
            return Err(StateMachineError::Store(RefStoreError::InvalidIdentity(
                "repository and tenant ids must be non-nil".into(),
            )));
        }
        let Some(gate) = self.state.gates.get(&repository_id) else {
            return Ok(VersionCheck::Unknown);
        };
        if gate.tenant_id != tenant_id {
            return Err(StateMachineError::Store(RefStoreError::Unsupported(
                "repository belongs to another owner namespace",
            )));
        }
        let current = gate.version()?;
        Ok(match known {
            Some(expected) if expected == &current => VersionCheck::Unchanged(current),
            _ => VersionCheck::Changed(current),
        })
    }

    /// Query durable operation status/terminal (used for Commit reply loss / restart recovery).
    pub fn query_operation(
        &self,
        repository_id: Uuid,
        operation_id: Uuid,
    ) -> Result<OperationLookup, StateMachineError> {
        if repository_id.is_nil() || operation_id.is_nil() {
            return Err(StateMachineError::Store(RefStoreError::InvalidIdentity("lookup ids must be non-nil".into())));
        }
        Ok(match self.state.operations.get(&RepoEntityKey::new(repository_id, operation_id)) {
            Some(record) => OperationLookup::Known(record.clone()),
            None => OperationLookup::Unknown,
        })
    }

    pub fn read_refs(&self, repository_id: Uuid) -> BTreeMap<String, String> {
        self.state.refs.get(&repository_id).cloned().unwrap_or_default()
    }

    pub fn read_head_ref(&self, repository_id: Uuid) -> Option<String> {
        self.state.gates.get(&repository_id).map(|gate| gate.head_ref.clone())
    }

    pub fn read_gate_version(&self, repository_id: Uuid) -> Result<Option<CoreGateVersion>, StateMachineError> {
        self.state.gates.get(&repository_id).map(|gate| gate.version()).transpose()
    }

    pub fn read_scope_lifecycle(&self, repository_id: Uuid) -> Option<(ScopeLifecycle, i64)> {
        self.state.gates.get(&repository_id).map(|gate| (gate.lifecycle, gate.authz_floor))
    }

    pub fn cancel_cutoff(&self, repository_id: Uuid, issuer_id: Uuid, lane: &IssuerLane) -> i64 {
        let key = LaneKey::new(repository_id, issuer_id, lane.as_str());
        self.state.lanes.get(&key).map_or(0, |entry| entry.cancel_cutoff)
    }

    pub fn read_decision(&self, decision_id: Uuid) -> Option<&DecisionRecord> {
        self.state.decisions.get(&decision_id)
    }

    pub fn read_pin(&self, pin_id: Uuid) -> Option<&PinRecord> {
        self.state.pins.get(&pin_id)
    }

    pub fn read_snapshot(&self, snapshot_id: Uuid) -> Option<&SnapshotRecord> {
        self.state.snapshots.get(&snapshot_id)
    }

    pub fn read_root(&self, root_id: Uuid) -> Option<&RootRecordSm> {
        self.state.roots.get(&root_id)
    }

    pub fn read_hold(&self, hold_id: Uuid) -> Option<&HoldEntry> {
        self.state.holds.get(&hold_id)
    }

    pub fn has_cancel_tombstone(&self, repository_id: Uuid, operation_id: Uuid) -> bool {
        self.state.cancellations.contains_key(&RepoEntityKey::new(repository_id, operation_id))
    }

    pub fn read_events_since(&self, after_event_seq: u64, limit: usize) -> Vec<StateMachineEvent> {
        self.state.events.iter().filter(|event| event.event_seq > after_event_seq).take(limit).cloned().collect()
    }
}

fn apply_inner(
    state: &mut SmState,
    log_id: AppliedLogId,
    command: RefCasCommand,
) -> Result<ApplyResponse, StateMachineError> {
    match command {
        RefCasCommand::Noop(noop) => {
            if let Some(tick) = noop.logical_tick {
                state.advance_clock(tick);
            }
            Ok(ApplyResponse::Noop)
        }
        RefCasCommand::InitializeGate(cmd) => initialize_gate(state, cmd),
        RefCasCommand::SetRepositoryLane(cmd) => set_repository_lane(state, cmd),
        RefCasCommand::BeginOperation(cmd) => begin_operation(state, cmd),
        RefCasCommand::CommitRefs(cmd) => commit_refs(state, log_id, cmd),
        RefCasCommand::Cancel(cmd) => cancel_operation(state, cmd),
        RefCasCommand::AdvanceCancelCutoff(cmd) => advance_cancel_cutoff(state, cmd),
        RefCasCommand::InstallDecision(cmd) => install_decision(state, cmd),
        RefCasCommand::CreateSnapshotPin(cmd) => create_snapshot_pin(state, cmd),
        RefCasCommand::RenewPin(cmd) => renew_pin(state, cmd),
        RefCasCommand::ReleasePin(cmd) => release_pin(state, cmd),
        RefCasCommand::RegisterRoot(cmd) => register_root(state, cmd),
        RefCasCommand::ReleaseRoot(cmd) => release_root(state, cmd),
        RefCasCommand::AcquireHoldBatch(cmd) => acquire_hold_batch(state, cmd),
        RefCasCommand::MarkHoldConsumed(cmd) => mark_hold_consumed(state, cmd),
        RefCasCommand::RetireHoldBatch(cmd) => retire_hold_batch(state, cmd),
    }
}
