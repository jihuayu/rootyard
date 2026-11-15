//! Deterministic `CommitRefs` execution for both `CommitMode::Atomic` and
//! `CommitMode::AcceptedSubset` with bit-for-bit PostgreSQL Core parity.

use super::apply_decisions::{close_decision, verify_decision_for_commit};
use super::apply_refs::{
    check_lane_conflicts, find_cancellation_for_key, lane_cutoff, lane_key, record_operation_and_lane,
    verify_cancellation, verify_identity,
};
use super::commands::{AppliedLogId, CommitRefsCommand, ScopeLifecycle, SmDecisionState};
use super::response::{ApplyResponse, StateMachineError};
use super::state::{GateState, RepoEntityKey, SmState};
use crate::ref_store::contract::{OperationRecord, OperationState, RefStoreError, TerminalResult};
use crate::ref_store::core::command::CommitRefsRequest;
use crate::ref_store::core::contract::CommitMode;
use crate::ref_store::core::metadata_subset::{self, MetadataSelection};
use crate::ref_store::core::pack_commit::PackMode;
use crate::ref_store::core::terminal::{
    CommitRefsReceipt, CommitRejectCode, CommitRejection, CommitTerminal, RefCommitResult,
    ensure_exact_terminal_budget, ensure_terminal_budget,
};
use crate::ref_store::core::types::{RefPrecondition, RefTarget, RefUpdate, is_strict_prefix, resolve_head};
use std::collections::BTreeMap;
use uuid::Uuid;

pub(super) fn commit_refs(
    state: &mut SmState,
    log_id: AppliedLogId,
    cmd: CommitRefsCommand,
) -> Result<ApplyResponse, StateMachineError> {
    let request = CommitRefsRequest::try_from(&cmd.request)?;
    request.validate()?;
    let repo_id = request.repository_id();
    let op_id = request.identity().operation_id();
    let op_key = RepoEntityKey::new(repo_id, op_id);

    // 1. Existing operation identity / terminal replay resolves BEFORE gate or lifecycle changes.
    let existing_pending = if let Some(stored) = state.operations.get(&op_key) {
        verify_identity(stored.identity(), request.identity())?;
        match stored.state() {
            OperationState::Committed | OperationState::Rejected => {
                let result = stored
                    .terminal_result()
                    .ok_or_else(|| StateMachineError::SnapshotCorrupted("terminal record missing body".into()))?;
                let terminal = CommitTerminal::from_terminal_result(result)?;
                return Ok(ApplyResponse::RefsCommitted(CommitRefsReceipt {
                    record: stored.clone(),
                    replayed: true,
                    terminal,
                }));
            }
            OperationState::Cancelled => {
                return Err(StateMachineError::Store(RefStoreError::Cancelled { operation_id: op_id }));
            }
            OperationState::Pending => true,
        }
    } else {
        false
    };

    if request.mode() == CommitMode::Atomic {
        ensure_terminal_budget(repo_id, request.refs())?;
    }

    let lane = lane_key(request.identity());
    if !existing_pending {
        check_lane_conflicts(state, &lane, request.identity())?;
        if let Some(tomb) = find_cancellation_for_key(state, &lane, request.identity().sequence()) {
            verify_cancellation(tomb, request.identity())?;
            return Err(StateMachineError::Store(RefStoreError::Cancelled { operation_id: op_id }));
        }
        if state.cancellations.contains_key(&op_key) {
            return Err(StateMachineError::Store(RefStoreError::CancellationConflict));
        }
        if let Some(cutoff) = lane_cutoff(state, &lane)
            && request.identity().sequence() <= cutoff
        {
            return Err(StateMachineError::BelowCancelCutoff {
                operation_id: op_id,
                sequence: request.identity().sequence(),
                cutoff,
            });
        }
    }

    let effective_tick = state.logical_clock_floor.max(cmd.logical_tick);
    let Some(gate) = state.gates.get(&repo_id).cloned() else {
        if let Some(decision_id) = cmd.decision_id {
            return Err(StateMachineError::DecisionNotFound { decision_id });
        }
        return reject_commit(
            state,
            log_id,
            &request,
            None,
            None,
            CommitRejectCode::GateNotFound,
            None,
            None,
            None,
            effective_tick,
        );
    };

    if gate.lifecycle != ScopeLifecycle::Open {
        return Err(StateMachineError::ScopeClosingOrClosed { repository_id: repo_id, lifecycle: gate.lifecycle });
    }
    if gate.tenant_id != request.tenant_id() && cmd.decision_id.is_none() {
        return reject_commit(
            state,
            log_id,
            &request,
            None,
            None,
            CommitRejectCode::TenantMismatch,
            None,
            None,
            None,
            effective_tick,
        );
    }
    if let Some(decision_id) = cmd.decision_id {
        verify_decision_for_commit(state, decision_id, &request, &gate, effective_tick, &cmd.required_holds)?;
    } else if gate.pack_mode == PackMode::PackVerified {
        return Err(StateMachineError::Store(RefStoreError::Unsupported(
            "pack_verified repository requires authorized pack decision",
        )));
    }

    // Realm and gate version checks match PG Core (`pg.rs:338-403`).
    if let Some((code, expected, actual)) = check_gate_mismatch(&gate, &request) {
        return reject_commit(
            state,
            log_id,
            &request,
            Some(&gate),
            cmd.decision_id,
            code,
            None,
            expected,
            actual,
            effective_tick,
        );
    }

    let existing_refs = state.refs.get(&repo_id).cloned().unwrap_or_default();
    if request.mode() == CommitMode::AcceptedSubset {
        return apply_accepted_subset(state, log_id, &request, &gate, &existing_refs, &cmd, effective_tick);
    }

    if let Err((code, name, expected, actual)) = check_cas_atomic(&request, &existing_refs) {
        return reject_commit(
            state,
            log_id,
            &request,
            Some(&gate),
            cmd.decision_id,
            code,
            Some(name),
            expected,
            actual,
            effective_tick,
        );
    }
    if let Err((name, conflict)) = check_existing_prefixes_atomic(&request, &existing_refs) {
        return reject_commit(
            state,
            log_id,
            &request,
            Some(&gate),
            cmd.decision_id,
            CommitRejectCode::PrefixConflict,
            Some(name),
            None,
            Some(conflict),
            effective_tick,
        );
    }
    let new_head = match resolve_head(&gate.head_ref, &existing_refs, request.refs(), request.head()) {
        Ok(head) => head,
        Err((code, name)) => {
            return reject_commit(
                state,
                log_id,
                &request,
                Some(&gate),
                cmd.decision_id,
                code,
                name,
                None,
                None,
                effective_tick,
            );
        }
    };

    let new_revision = gate.revision + 1;
    let results: Vec<RefCommitResult> = request
        .refs()
        .iter()
        .map(|update| RefCommitResult::Applied {
            name: update.name().as_str().to_owned(),
            old_oid: existing_refs.get(update.name().as_str()).cloned(),
            new_oid: update.target().oid().map(|oid| oid.as_hex()),
        })
        .collect();
    let terminal = CommitTerminal::committed(repo_id, new_revision, new_head.clone(), results);
    ensure_exact_terminal_budget(&terminal)?;
    let result = terminal.to_terminal_result()?;
    let record = OperationRecord::new(request.identity().clone(), OperationState::Committed, Some(result.clone()))?;

    let mut updated_refs = existing_refs;
    for update in request.refs() {
        apply_update_to_map(&mut updated_refs, update);
    }
    finalize_committed_state(
        state,
        log_id,
        &request,
        updated_refs,
        new_head,
        new_revision,
        cmd.decision_id,
        record.clone(),
        result,
        effective_tick,
    );
    Ok(ApplyResponse::RefsCommitted(CommitRefsReceipt { record, replayed: false, terminal }))
}

fn check_gate_mismatch(
    gate: &GateState,
    request: &CommitRefsRequest,
) -> Option<(CommitRejectCode, Option<String>, Option<String>)> {
    if gate.tenant_id != request.tenant_id() {
        return Some((CommitRejectCode::TenantMismatch, None, None));
    }
    if gate.object_format != request.object_format() {
        return Some((
            CommitRejectCode::ObjectFormatMismatch,
            Some(request.object_format().to_string()),
            Some(gate.object_format.to_string()),
        ));
    }
    if gate.history_incarnation != request.history_incarnation() {
        return Some((
            CommitRejectCode::HistoryIncarnationMismatch,
            Some(request.history_incarnation().to_string()),
            Some(gate.history_incarnation.to_string()),
        ));
    }
    if gate.authority_epoch != request.authority_epoch() {
        return Some((
            CommitRejectCode::AuthorityEpochMismatch,
            Some(request.authority_epoch().to_string()),
            Some(gate.authority_epoch.to_string()),
        ));
    }
    if gate.group_epoch != request.group_epoch() {
        return Some((
            CommitRejectCode::GroupEpochMismatch,
            Some(request.group_epoch().to_string()),
            Some(gate.group_epoch.to_string()),
        ));
    }
    if gate.revision != request.expected_revision() {
        return Some((
            CommitRejectCode::RevisionMismatch,
            Some(request.expected_revision().to_string()),
            Some(gate.revision.to_string()),
        ));
    }
    None
}

fn apply_accepted_subset(
    state: &mut SmState,
    log_id: AppliedLogId,
    request: &CommitRefsRequest,
    gate: &GateState,
    existing_refs: &BTreeMap<String, String>,
    cmd: &CommitRefsCommand,
    effective_tick: u64,
) -> Result<ApplyResponse, StateMachineError> {
    let repo_id = request.repository_id();
    match metadata_subset::select(request, &gate.head_ref, existing_refs, &cmd.policy_rejects) {
        MetadataSelection::Commit { results, accepted, head } => {
            let new_revision = gate.revision + 1;
            let terminal = CommitTerminal::committed(repo_id, new_revision, head.clone(), results);
            ensure_exact_terminal_budget(&terminal)?;
            let result = terminal.to_terminal_result()?;
            let record =
                OperationRecord::new(request.identity().clone(), OperationState::Committed, Some(result.clone()))?;

            let mut updated_refs = existing_refs.clone();
            for idx in accepted {
                apply_update_to_map(&mut updated_refs, &request.refs()[idx]);
            }
            finalize_committed_state(
                state,
                log_id,
                request,
                updated_refs,
                head,
                new_revision,
                cmd.decision_id,
                record.clone(),
                result,
                effective_tick,
            );
            Ok(ApplyResponse::RefsCommitted(CommitRefsReceipt { record, replayed: false, terminal }))
        }
        MetadataSelection::Reject { results, rejection } => {
            let terminal =
                CommitTerminal::rejected(repo_id, gate.revision, Some(gate.head_ref.clone()), results, rejection);
            ensure_exact_terminal_budget(&terminal)?;
            let result = terminal.to_terminal_result()?;
            let record =
                OperationRecord::new(request.identity().clone(), OperationState::Rejected, Some(result.clone()))?;
            finalize_rejected_state(
                state,
                log_id,
                request,
                gate.revision,
                cmd.decision_id,
                record.clone(),
                result,
                effective_tick,
            );
            Ok(ApplyResponse::RefsCommitted(CommitRefsReceipt { record, replayed: false, terminal }))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn finalize_committed_state(
    state: &mut SmState,
    log_id: AppliedLogId,
    request: &CommitRefsRequest,
    updated_refs: BTreeMap<String, String>,
    head: String,
    new_revision: i64,
    decision_id: Option<Uuid>,
    record: OperationRecord,
    result: TerminalResult,
    effective_tick: u64,
) {
    let repo_id = request.repository_id();
    let op_id = request.identity().operation_id();
    let op_key = RepoEntityKey::new(repo_id, op_id);
    let lane = lane_key(request.identity());
    state.advance_clock(effective_tick);
    state.refs.insert(repo_id, updated_refs);
    if let Some(gate_mut) = state.gates.get_mut(&repo_id) {
        gate_mut.revision = new_revision;
        gate_mut.head_ref = head;
    }
    record_operation_and_lane(state, op_key, &lane, request.identity().sequence(), op_id, record);
    state.push_event(log_id, repo_id, new_revision, op_id, "committed", result.value().clone());
    if let Some(id) = decision_id {
        close_decision(state, id, SmDecisionState::Consumed, None, Some(op_id));
    }
}

#[allow(clippy::too_many_arguments)]
fn finalize_rejected_state(
    state: &mut SmState,
    log_id: AppliedLogId,
    request: &CommitRefsRequest,
    revision: i64,
    decision_id: Option<Uuid>,
    record: OperationRecord,
    result: TerminalResult,
    effective_tick: u64,
) {
    let repo_id = request.repository_id();
    let op_id = request.identity().operation_id();
    let op_key = RepoEntityKey::new(repo_id, op_id);
    let lane = lane_key(request.identity());
    state.advance_clock(effective_tick);
    record_operation_and_lane(state, op_key, &lane, request.identity().sequence(), op_id, record);
    state.push_event(log_id, repo_id, revision, op_id, "rejected", result.value().clone());
    if let Some(id) = decision_id {
        close_decision(state, id, SmDecisionState::Rejected, Some("rejected_batch"), None);
    }
}

#[allow(clippy::too_many_arguments)]
fn reject_commit(
    state: &mut SmState,
    log_id: AppliedLogId,
    request: &CommitRefsRequest,
    gate: Option<&GateState>,
    decision_id: Option<Uuid>,
    code: CommitRejectCode,
    ref_name: Option<String>,
    expected: Option<String>,
    actual: Option<String>,
    effective_tick: u64,
) -> Result<ApplyResponse, StateMachineError> {
    let revision = gate.map_or(0, |g| g.revision);
    let head_ref = gate.map(|g| g.head_ref.clone());
    let results = request
        .refs()
        .iter()
        .map(|update| RefCommitResult::NotApplied { name: update.name().as_str().to_owned(), reason: code })
        .collect();
    let rejection = CommitRejection { code, ref_name, expected, actual };
    let terminal = CommitTerminal::rejected(request.repository_id(), revision, head_ref, results, rejection);
    ensure_exact_terminal_budget(&terminal)?;
    let result = terminal.to_terminal_result()?;
    let record = OperationRecord::new(request.identity().clone(), OperationState::Rejected, Some(result.clone()))?;
    finalize_rejected_state(state, log_id, request, revision, decision_id, record.clone(), result, effective_tick);
    Ok(ApplyResponse::RefsCommitted(CommitRefsReceipt { record, replayed: false, terminal }))
}

fn apply_update_to_map(map: &mut BTreeMap<String, String>, update: &RefUpdate) {
    let name = update.name().as_str();
    match update.target() {
        RefTarget::Oid(oid) => {
            map.insert(name.to_owned(), oid.as_hex());
        }
        RefTarget::Delete => {
            map.remove(name);
        }
    }
}

fn check_cas_atomic(
    request: &CommitRefsRequest,
    existing: &BTreeMap<String, String>,
) -> Result<(), (CommitRejectCode, String, Option<String>, Option<String>)> {
    for update in request.refs() {
        let name = update.name().as_str();
        let actual = existing.get(name).cloned();
        match update.precondition() {
            RefPrecondition::Absent => {
                if let Some(actual) = actual {
                    return Err((
                        CommitRejectCode::OldOidMismatch,
                        name.to_owned(),
                        Some("absent".into()),
                        Some(actual),
                    ));
                }
            }
            RefPrecondition::Present(expected) => {
                let expected_hex = expected.as_hex();
                if actual.as_deref() != Some(expected_hex.as_str()) {
                    return Err((CommitRejectCode::OldOidMismatch, name.to_owned(), Some(expected_hex), actual));
                }
            }
        }
    }
    Ok(())
}

fn check_existing_prefixes_atomic(
    request: &CommitRefsRequest,
    existing: &BTreeMap<String, String>,
) -> Result<(), (String, String)> {
    for update in request.refs() {
        let name = update.name().as_str();
        for current in existing.keys() {
            if current.as_str() == name {
                continue;
            }
            if is_strict_prefix(name, current) || is_strict_prefix(current, name) {
                return Err((name.to_owned(), current.clone()));
            }
        }
    }
    Ok(())
}
