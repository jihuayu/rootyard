//! Deterministic `InitializeGate`, `SetRepositoryLane`, `BeginOperation`, `Cancel`,
//! and `AdvanceCancelCutoff` transitions plus shared lane/cancellation helpers.

use super::apply_decisions::close_decision;
use super::commands::{
    AdvanceCancelCutoffCommand, BeginOperationCommand, CancelCommand, InitializeGateCommand, ScopeLifecycle,
    SetRepositoryLaneCommand, SmDecisionState,
};
use super::response::{ApplyResponse, StateMachineError};
use super::state::{CancelTombstone, GateState, LaneKey, LaneState, RepoEntityKey, SmState};
use super::wire::WireOperationIdentity;
use crate::ref_store::contract::{
    BeginReceipt, CancelReceipt, IssuerLane, OperationIdentity, OperationRecord, OperationState, RefStoreError,
    TerminalResult,
};
use crate::ref_store::core::contract::CoreGateInit;
use serde_json::json;
use uuid::Uuid;

pub(super) fn initialize_gate(
    state: &mut SmState,
    cmd: InitializeGateCommand,
) -> Result<ApplyResponse, StateMachineError> {
    let init = CoreGateInit::try_from(&cmd.gate)?;
    if cmd.authz_floor < 0 {
        return Err(StateMachineError::InvalidInput("authz_floor must be non-negative".into()));
    }
    let repo_id = init.repository_id();
    if let Some(existing) = state.gates.get(&repo_id) {
        if existing.tenant_id != init.tenant_id()
            || existing.object_format != init.object_format()
            || existing.history_incarnation != init.history_incarnation()
            || existing.authority_epoch != init.authority_epoch()
            || existing.group_epoch != init.group_epoch()
            || existing.head_ref != init.head_ref().as_str()
            || existing.pack_mode != cmd.pack_mode
            || existing.lane != cmd.lane
        {
            return Err(StateMachineError::Store(RefStoreError::GateConflict));
        }
        return Ok(ApplyResponse::GateInitialized { version: existing.version()?, created: false });
    }
    let gate = GateState {
        repository_id: repo_id,
        tenant_id: init.tenant_id(),
        object_format: init.object_format(),
        history_incarnation: init.history_incarnation(),
        authority_epoch: init.authority_epoch(),
        group_epoch: init.group_epoch(),
        revision: 1,
        roots_revision: 1,
        head_ref: init.head_ref().as_str().to_owned(),
        pack_mode: cmd.pack_mode,
        lane: cmd.lane,
        lifecycle: ScopeLifecycle::Open,
        authz_floor: cmd.authz_floor,
    };
    let version = gate.version()?;
    state.gates.insert(repo_id, gate);
    state.refs.entry(repo_id).or_default();
    Ok(ApplyResponse::GateInitialized { version, created: true })
}

pub(super) fn set_repository_lane(
    state: &mut SmState,
    cmd: SetRepositoryLaneCommand,
) -> Result<ApplyResponse, StateMachineError> {
    if cmd.history_incarnation.is_nil() || cmd.authority_epoch <= 0 || cmd.group_epoch <= 0 {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity("gate realm fields invalid".into())));
    }
    let gate =
        state.gates.get_mut(&cmd.repository_id).ok_or(StateMachineError::Store(RefStoreError::RepositoryNotFound))?;
    if gate.tenant_id != cmd.tenant_id {
        return Err(StateMachineError::InvalidInput("set_repository_lane tenant differs from gate".into()));
    }
    if cmd.lifecycle < gate.lifecycle {
        return Err(StateMachineError::LifecycleRegression { current: gate.lifecycle, requested: cmd.lifecycle });
    }
    if cmd.authz_floor < gate.authz_floor {
        return Err(StateMachineError::AuthzFloorRegression {
            current_floor: gate.authz_floor,
            requested_floor: cmd.authz_floor,
        });
    }
    gate.lane = cmd.lane;
    gate.lifecycle = cmd.lifecycle;
    gate.authz_floor = cmd.authz_floor;
    gate.history_incarnation = cmd.history_incarnation;
    gate.authority_epoch = cmd.authority_epoch;
    gate.group_epoch = cmd.group_epoch;
    gate.pack_mode = cmd.pack_mode;
    let version = gate.version()?;
    Ok(ApplyResponse::RepositoryLaneUpdated { version, lifecycle: gate.lifecycle, authz_floor: gate.authz_floor })
}

pub(super) fn begin_operation(
    state: &mut SmState,
    cmd: BeginOperationCommand,
) -> Result<ApplyResponse, StateMachineError> {
    let identity = OperationIdentity::try_from(&cmd.identity)?;
    let repo_id = identity.repository_id();
    let op_key = RepoEntityKey::new(repo_id, identity.operation_id());
    if !state.gates.contains_key(&repo_id) {
        return Err(StateMachineError::Store(RefStoreError::RepositoryNotFound));
    }
    if let Some(stored) = state.operations.get(&op_key) {
        verify_identity(stored.identity(), &identity)?;
        return Ok(ApplyResponse::OperationBegun(BeginReceipt { created: false, record: stored.clone() }));
    }
    let lane = lane_key(&identity);
    check_lane_conflicts(state, &lane, &identity)?;
    if let Some(tombstone) = find_cancellation_for_key(state, &lane, identity.sequence()) {
        verify_cancellation(tombstone, &identity)?;
        let result = TerminalResult::json(json!({"state": "cancelled", "reason": "cancel_before_register"}))?;
        let record = OperationRecord::new(identity.clone(), OperationState::Cancelled, Some(result))?;
        state.advance_clock(cmd.logical_tick);
        record_operation_and_lane(state, op_key, &lane, identity.sequence(), identity.operation_id(), record.clone());
        return Ok(ApplyResponse::OperationBegun(BeginReceipt { created: true, record }));
    }
    if state.cancellations.contains_key(&op_key) {
        return Err(StateMachineError::Store(RefStoreError::CancellationConflict));
    }
    if let Some(cutoff) = lane_cutoff(state, &lane)
        && identity.sequence() <= cutoff
    {
        return Err(StateMachineError::BelowCancelCutoff {
            operation_id: identity.operation_id(),
            sequence: identity.sequence(),
            cutoff,
        });
    }
    if let Some(gate) = state.gates.get(&repo_id)
        && gate.lifecycle != ScopeLifecycle::Open
    {
        return Err(StateMachineError::ScopeClosingOrClosed { repository_id: repo_id, lifecycle: gate.lifecycle });
    }
    let record = OperationRecord::new(identity.clone(), OperationState::Pending, None)?;
    state.advance_clock(cmd.logical_tick);
    record_operation_and_lane(state, op_key, &lane, identity.sequence(), identity.operation_id(), record.clone());
    Ok(ApplyResponse::OperationBegun(BeginReceipt { created: true, record }))
}

pub(super) fn cancel_operation(state: &mut SmState, cmd: CancelCommand) -> Result<ApplyResponse, StateMachineError> {
    let identity = OperationIdentity::try_from(&cmd.identity)?;
    let repo_id = identity.repository_id();
    let op_id = identity.operation_id();
    let op_key = RepoEntityKey::new(repo_id, op_id);
    if !state.gates.contains_key(&repo_id) {
        return Err(StateMachineError::Store(RefStoreError::RepositoryNotFound));
    }
    let lane = lane_key(&identity);
    let existing = match state.operations.get(&op_key) {
        Some(stored) => {
            verify_identity(stored.identity(), &identity)?;
            Some(stored.clone())
        }
        None => {
            check_lane_conflicts(state, &lane, &identity)?;
            None
        }
    };
    let effective_tick = state.logical_clock_floor.max(cmd.logical_tick);
    let tombstone_created = if let Some(tomb) = find_cancellation_for_key(state, &lane, identity.sequence()) {
        verify_cancellation(tomb, &identity)?;
        false
    } else if state.cancellations.contains_key(&op_key) {
        return Err(StateMachineError::Store(RefStoreError::CancellationConflict));
    } else if existing.is_none()
        && let Some(cutoff) = lane_cutoff(state, &lane)
        && identity.sequence() <= cutoff
    {
        state.advance_clock(effective_tick);
        return Ok(ApplyResponse::OperationCancelled {
            receipt: CancelReceipt { record: None, tombstone_created: false },
            decision_cancelled: None,
        });
    } else {
        state.cancellations.insert(
            op_key,
            CancelTombstone {
                key: op_key,
                identity: WireOperationIdentity::from(&identity),
                reason: cmd.reason.clone(),
                cancelled_at_tick: effective_tick,
            },
        );
        state.lanes.entry(lane.clone()).or_insert_with(|| LaneState::new(lane.clone()));
        true
    };
    state.advance_clock(effective_tick);

    let final_record = match existing {
        Some(stored) if stored.state() == OperationState::Pending => {
            let result = TerminalResult::json(json!({"state": "cancelled", "reason": "cancel_requested"}))?;
            let updated = OperationRecord::new(identity, OperationState::Cancelled, Some(result))?;
            state.operations.insert(op_key, updated.clone());
            Some(updated)
        }
        other => other,
    };

    let mut decision_cancelled = None;
    if let Some(decision_id) = state.decisions_by_op.get(&op_key).copied()
        && let Some(dec) = state.decisions.get(&decision_id)
        && dec.state == SmDecisionState::Open
    {
        close_decision(state, decision_id, SmDecisionState::Cancelled, Some("cancelled"), None);
        decision_cancelled = Some(decision_id);
    }

    Ok(ApplyResponse::OperationCancelled {
        receipt: CancelReceipt { record: final_record, tombstone_created },
        decision_cancelled,
    })
}

pub(super) fn advance_cancel_cutoff(
    state: &mut SmState,
    cmd: AdvanceCancelCutoffCommand,
) -> Result<ApplyResponse, StateMachineError> {
    if cmd.repository_id.is_nil() || cmd.issuer_id.is_nil() || cmd.cutoff_sequence < 0 {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity(
            "invalid cancel cutoff parameters".into(),
        )));
    }
    let lane = IssuerLane::new(cmd.lane.as_str())?;
    let key = LaneKey::new(cmd.repository_id, cmd.issuer_id, lane.as_str());
    let lane_state = state.lanes.entry(key.clone()).or_insert_with(|| LaneState::new(key.clone()));
    if cmd.cutoff_sequence > lane_state.cancel_cutoff {
        lane_state.cancel_cutoff = cmd.cutoff_sequence;
    }
    let cutoff = lane_state.cancel_cutoff;
    let mut pruned = 0usize;
    if cmd.prune_tombstones_up_to_cutoff {
        let mut to_remove = Vec::new();
        for (op_key, tomb) in &state.cancellations {
            let tomb_key =
                LaneKey::new(tomb.identity.repository_id, tomb.identity.issuer_id, tomb.identity.lane.as_str());
            if tomb_key == key && tomb.identity.sequence <= cutoff && !state.operations.contains_key(op_key) {
                to_remove.push(*op_key);
            }
        }
        pruned = to_remove.len();
        for op_key in to_remove {
            state.cancellations.remove(&op_key);
        }
    }
    Ok(ApplyResponse::CancelCutoffAdvanced { cutoff_sequence: cutoff, pruned_tombstones: pruned })
}

pub(super) fn lane_key(identity: &OperationIdentity) -> LaneKey {
    LaneKey::new(identity.repository_id(), identity.issuer_id(), identity.lane().as_str())
}

pub(super) fn lane_cutoff(state: &SmState, lane_key: &LaneKey) -> Option<i64> {
    state.lanes.get(lane_key).map(|lane| lane.cancel_cutoff)
}

pub(super) fn check_lane_conflicts(
    state: &SmState,
    lane_key: &LaneKey,
    identity: &OperationIdentity,
) -> Result<(), StateMachineError> {
    if let Some(lane_state) = state.lanes.get(lane_key)
        && let Some(bound_op) = lane_state.operation_for_sequence(identity.sequence())
        && bound_op != identity.operation_id()
    {
        return Err(StateMachineError::Store(RefStoreError::IdentityConflict));
    }
    Ok(())
}

pub(super) fn find_cancellation_for_key<'a>(
    state: &'a SmState,
    lane_key: &LaneKey,
    sequence: i64,
) -> Option<&'a CancelTombstone> {
    state.cancellations.values().find(|tomb| {
        tomb.identity.repository_id == lane_key.repository_id
            && tomb.identity.issuer_id == lane_key.issuer_id
            && tomb.identity.lane == lane_key.lane
            && tomb.identity.sequence == sequence
    })
}

pub(super) fn verify_cancellation(
    tomb: &CancelTombstone,
    expected: &OperationIdentity,
) -> Result<(), StateMachineError> {
    if tomb.identity.operation_id == expected.operation_id() && tomb.identity.digest == expected.digest().as_hex() {
        Ok(())
    } else {
        Err(StateMachineError::Store(RefStoreError::CancellationConflict))
    }
}

pub(super) fn verify_identity(
    stored: &OperationIdentity,
    expected: &OperationIdentity,
) -> Result<(), StateMachineError> {
    if stored == expected {
        return Ok(());
    }
    if stored.digest() != expected.digest() {
        return Err(StateMachineError::Store(RefStoreError::DigestConflict));
    }
    Err(StateMachineError::Store(RefStoreError::IdentityConflict))
}

pub(super) fn record_operation_and_lane(
    state: &mut SmState,
    op_key: RepoEntityKey,
    lane_key: &LaneKey,
    sequence: i64,
    operation_id: Uuid,
    record: OperationRecord,
) {
    state.operations.insert(op_key, record);
    let lane = state.lanes.entry(lane_key.clone()).or_insert_with(|| LaneState::new(lane_key.clone()));
    lane.record_sequence(sequence, operation_id);
}
