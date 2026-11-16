//! Deterministic publication-decision state transitions.
//!
//! Decisions are single-use capability bindings checked before commit without
//! running Blob I/O, PG queries, or system wall clocks inside `apply`.

use super::commands::{
    InstallDecisionCommand, ScopeLifecycle, SmDecisionState, SmHoldState, WireDecisionKind, WireDecisionVerdict,
};
use super::response::{ApplyResponse, StateMachineError};
use super::state::{DecisionRecord, GateState, RepoEntityKey, SmState};
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::command::CommitRefsRequest;
use crate::ref_store::core::contract::CommitMode;
use crate::ref_store::core::publication_decision::contract::{REPO_MAX_DECISIONS, TENANT_MAX_DECISIONS};
use crate::ref_store::core::terminal::CommitRejectCode;
use crate::ref_store::core::types::RefName;
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use uuid::Uuid;

pub(super) fn install_decision(
    state: &mut SmState,
    cmd: InstallDecisionCommand,
) -> Result<ApplyResponse, StateMachineError> {
    if cmd.decision_id.is_nil()
        || cmd.repository_id.is_nil()
        || cmd.tenant_id.is_nil()
        || cmd.actor_id.is_nil()
        || cmd.operation_id.is_nil()
    {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity("decision ids must be non-nil".into())));
    }
    if cmd.verdicts.is_empty() || cmd.base_revision <= 0 || cmd.authz_epoch <= 0 {
        return Err(StateMachineError::InvalidInput("decision verdicts/revision/epoch out of bounds".into()));
    }
    let mut seen_verdict_refs = BTreeSet::new();
    for verdict in &cmd.verdicts {
        RefName::new(&verdict.ref_name)?;
        if !seen_verdict_refs.insert(verdict.ref_name.as_str()) {
            return Err(StateMachineError::InvalidInput("duplicate ref_name in decision verdicts".into()));
        }
        if verdict.accepted != verdict.reject_code.is_none() {
            return Err(StateMachineError::InvalidInput(
                "decision verdict accepted flag disagrees with reject_code".into(),
            ));
        }
    }
    for digest_hex in [
        &cmd.command_digest,
        &cmd.selection_digest,
        &cmd.policy_digest,
        &cmd.facts_digest,
        &cmd.authz_digest,
        &cmd.dependencies_digest,
    ] {
        RequestDigest::from_str(digest_hex)?;
    }

    let effective_tick = state.logical_clock_floor.max(cmd.logical_tick);
    let op_key = RepoEntityKey::new(cmd.repository_id, cmd.operation_id);

    if let Some(existing_id) = state.decisions_by_op.get(&op_key).copied() {
        let existing = state
            .decisions
            .get(&existing_id)
            .ok_or(StateMachineError::DecisionNotFound { decision_id: existing_id })?;
        if existing.decision_id != cmd.decision_id
            || existing.repository_id != cmd.repository_id
            || existing.tenant_id != cmd.tenant_id
            || existing.actor_id != cmd.actor_id
            || existing.kind != cmd.kind
            || existing.base_revision != cmd.base_revision
            || existing.authz_epoch != cmd.authz_epoch
            || existing.not_after_tick != cmd.not_after_tick
            || existing.command_digest != cmd.command_digest
            || existing.selection_digest != cmd.selection_digest
            || existing.policy_digest != cmd.policy_digest
            || existing.facts_digest != cmd.facts_digest
            || existing.authz_digest != cmd.authz_digest
            || existing.dependencies_digest != cmd.dependencies_digest
            || existing.verdicts != cmd.verdicts
        {
            return Err(StateMachineError::DecisionConflict {
                decision_id: existing.decision_id,
                state: existing.state,
            });
        }
        if existing.state != SmDecisionState::Open {
            return Err(StateMachineError::DecisionConflict {
                decision_id: existing.decision_id,
                state: existing.state,
            });
        }
        let existing_decision_id = existing.decision_id;
        state.advance_clock(effective_tick);
        return Ok(ApplyResponse::DecisionInstalled { decision_id: existing_decision_id, replayed: true });
    }

    if state.decisions.contains_key(&cmd.decision_id) {
        return Err(StateMachineError::DecisionConflict {
            decision_id: cmd.decision_id,
            state: state.decisions[&cmd.decision_id].state,
        });
    }
    if state.cancellations.contains_key(&op_key) {
        return Err(StateMachineError::Store(RefStoreError::Cancelled { operation_id: cmd.operation_id }));
    }

    let gate =
        state.gates.get(&cmd.repository_id).ok_or(StateMachineError::Store(RefStoreError::RepositoryNotFound))?;
    if gate.tenant_id != cmd.tenant_id {
        return Err(StateMachineError::InvalidInput("decision tenant does not match gate tenant".into()));
    }
    if gate.lifecycle != ScopeLifecycle::Open {
        return Err(StateMachineError::ScopeClosingOrClosed {
            repository_id: cmd.repository_id,
            lifecycle: gate.lifecycle,
        });
    }
    if cmd.authz_epoch < gate.authz_floor {
        return Err(StateMachineError::AuthzFloorViolation { authz_epoch: cmd.authz_epoch, floor: gate.authz_floor });
    }
    if gate.revision != cmd.base_revision {
        return Err(StateMachineError::DecisionDigestMismatch {
            decision_id: cmd.decision_id,
            reason: "base_revision differs from current gate revision",
        });
    }
    if cmd.not_after_tick <= effective_tick {
        return Err(StateMachineError::DecisionExpired {
            decision_id: cmd.decision_id,
            not_after_tick: cmd.not_after_tick,
            current_tick: effective_tick,
        });
    }

    charge_decision_quota(state, cmd.repository_id, cmd.tenant_id)?;
    state.advance_clock(effective_tick);
    state.decisions_by_op.insert(op_key, cmd.decision_id);
    state.decisions.insert(
        cmd.decision_id,
        DecisionRecord {
            decision_id: cmd.decision_id,
            repository_id: cmd.repository_id,
            tenant_id: cmd.tenant_id,
            actor_id: cmd.actor_id,
            operation_id: cmd.operation_id,
            kind: cmd.kind,
            state: SmDecisionState::Open,
            base_revision: cmd.base_revision,
            command_digest: cmd.command_digest,
            selection_digest: cmd.selection_digest,
            policy_digest: cmd.policy_digest,
            facts_digest: cmd.facts_digest,
            authz_digest: cmd.authz_digest,
            dependencies_digest: cmd.dependencies_digest,
            verdicts: cmd.verdicts,
            authz_epoch: cmd.authz_epoch,
            installed_at_tick: effective_tick,
            not_after_tick: cmd.not_after_tick,
            closed_code: None,
            consume_receipt_id: None,
        },
    );
    Ok(ApplyResponse::DecisionInstalled { decision_id: cmd.decision_id, replayed: false })
}

pub(super) fn verify_decision_for_commit(
    state: &SmState,
    decision_id: Uuid,
    request: &CommitRefsRequest,
    gate: &GateState,
    current_tick: u64,
    required_holds: &[Uuid],
    policy_rejects: &BTreeMap<String, CommitRejectCode>,
) -> Result<(), StateMachineError> {
    let decision = state.decisions.get(&decision_id).ok_or(StateMachineError::DecisionNotFound { decision_id })?;
    if decision.repository_id != request.repository_id()
        || decision.tenant_id != request.tenant_id()
        || decision.operation_id != request.identity().operation_id()
        || decision.actor_id != request.identity().issuer_id()
    {
        return Err(StateMachineError::DecisionDigestMismatch {
            decision_id,
            reason: "decision scope/actor/operation differs from CommitRefsRequest",
        });
    }
    let expected_kind = match request.mode() {
        CommitMode::Atomic => WireDecisionKind::Atomic,
        CommitMode::AcceptedSubset => WireDecisionKind::AcceptedSubset,
    };
    if decision.kind != expected_kind {
        return Err(StateMachineError::DecisionDigestMismatch { decision_id, reason: "decision mode mismatch" });
    }
    if decision.state != SmDecisionState::Open {
        return Err(StateMachineError::DecisionConflict { decision_id, state: decision.state });
    }
    if decision.authz_epoch < gate.authz_floor {
        return Err(StateMachineError::AuthzFloorViolation {
            authz_epoch: decision.authz_epoch,
            floor: gate.authz_floor,
        });
    }
    super::apply_scopes::verify_decision_scopes_open(state, decision_id, decision.authz_epoch)?;
    if let Some(scoped) = state.decision_scope_deps.get(&decision_id) {
        if scoped.grant_commitment.base_gate_digest != gate.version()?.digest().as_hex() {
            return Err(StateMachineError::DecisionDigestMismatch {
                decision_id,
                reason: "signed grant base_gate_digest disagrees with repository gate",
            });
        }
        let expected_holds: BTreeSet<Uuid> = scoped.grant_commitment.required_holds.iter().copied().collect();
        let supplied_holds: BTreeSet<Uuid> = required_holds.iter().copied().collect();
        if supplied_holds.len() != required_holds.len() || supplied_holds != expected_holds {
            return Err(StateMachineError::DecisionDigestMismatch {
                decision_id,
                reason: "commit required_holds disagree with installed signed decision grant",
            });
        }
    }
    if current_tick > decision.not_after_tick {
        return Err(StateMachineError::DecisionExpired {
            decision_id,
            not_after_tick: decision.not_after_tick,
            current_tick,
        });
    }
    if decision.base_revision != gate.revision {
        return Err(StateMachineError::DecisionDigestMismatch { decision_id, reason: "gate revision superseded" });
    }
    if decision.command_digest != request.digest().as_hex() {
        return Err(StateMachineError::DecisionDigestMismatch { decision_id, reason: "command digest mismatch" });
    }

    let mut verdict_map: BTreeMap<&str, &WireDecisionVerdict> = BTreeMap::new();
    for verdict in &decision.verdicts {
        if verdict.accepted != verdict.reject_code.is_none()
            || verdict_map.insert(verdict.ref_name.as_str(), verdict).is_some()
        {
            return Err(StateMachineError::DecisionDigestMismatch {
                decision_id,
                reason: "installed decision contains inconsistent verdicts",
            });
        }
    }
    if verdict_map.len() != request.refs().len() {
        return Err(StateMachineError::DecisionDigestMismatch {
            decision_id,
            reason: "decision verdicts length disagrees with request refs",
        });
    }
    let mut expected_policy_rejects: BTreeMap<String, CommitRejectCode> = BTreeMap::new();
    for update in request.refs() {
        let name = update.name().as_str();
        let Some(verdict) = verdict_map.get(name) else {
            return Err(StateMachineError::DecisionDigestMismatch {
                decision_id,
                reason: "request ref missing from installed decision verdicts",
            });
        };
        if let Some(code) = verdict.reject_code {
            expected_policy_rejects.insert(name.to_owned(), code);
        }
    }
    if policy_rejects != &expected_policy_rejects {
        return Err(StateMachineError::DecisionDigestMismatch {
            decision_id,
            reason: "commit policy_rejects disagree with installed decision verdicts",
        });
    }
    if request.mode() == CommitMode::Atomic && !expected_policy_rejects.is_empty() {
        return Err(StateMachineError::DecisionDigestMismatch {
            decision_id,
            reason: "atomic commit refused because installed decision rejected ref(s)",
        });
    }

    for hold_id in required_holds {
        let hold = state.holds.get(hold_id).ok_or(StateMachineError::HoldNotFound { hold_id: *hold_id })?;
        if hold.repository_id != request.repository_id()
            || hold.tenant_id != request.tenant_id()
            || hold.operation_id != request.identity().operation_id()
        {
            return Err(StateMachineError::HoldScopeMismatch { hold_id: *hold_id });
        }
        if matches!(hold.state, SmHoldState::Retired) {
            return Err(StateMachineError::HoldNotActive { hold_id: *hold_id, state: hold.state });
        }
    }
    Ok(())
}

pub(super) fn close_decision(
    state: &mut SmState,
    decision_id: Uuid,
    target_state: SmDecisionState,
    closed_code: Option<&str>,
    receipt_id: Option<Uuid>,
) {
    if let Some(record) = state.decisions.get_mut(&decision_id)
        && record.state == SmDecisionState::Open
    {
        record.state = target_state;
        record.closed_code = closed_code.map(str::to_owned);
        record.consume_receipt_id = receipt_id;
    }
}

fn charge_decision_quota(state: &mut SmState, repo_id: Uuid, tenant_id: Uuid) -> Result<(), StateMachineError> {
    let repo_next = state.repo_quotas.get(&repo_id).copied().unwrap_or_default().decisions + 1;
    let tenant_next = state.tenant_quotas.get(&tenant_id).copied().unwrap_or_default().decisions + 1;
    if repo_next > REPO_MAX_DECISIONS || tenant_next > TENANT_MAX_DECISIONS {
        return Err(StateMachineError::QuotaExceeded("publication decision quota exceeded"));
    }
    state.repo_quotas.entry(repo_id).or_default().decisions = repo_next;
    state.tenant_quotas.entry(tenant_id).or_default().decisions = tenant_next;
    Ok(())
}
