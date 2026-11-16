//! Deterministic `CloseAuthScope`, indexed scope dependency checks, and drain queries (#152).
//!
//! Tracks `OPEN -> CLOSING -> CLOSED` lifecycles and monotonic `authz_floor` barriers per
//! `(scope_kind, scope_id)` across Raft log entries and canonical snapshots with zero wall clocks.

use super::apply_decisions::install_decision;
use super::commands::{CloseAuthScopeCommand, InstallScopedDecisionCommand, ScopeLifecycle, SmDecisionState};
use super::response::{ApplyResponse, StateMachineError};
use super::state::SmState;
use crate::ref_store::contract::{OperationState, RefStoreError, RequestDigest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use uuid::Uuid;

/// Exact set of scope kinds permitted by PostgreSQL `migrations/144_ref_store_core_roots_decisions.sql`.
pub const SUPPORTED_DECISION_SCOPE_KINDS: &[&str] = &[
    "token",
    "parent_token",
    "session",
    "user",
    "org_membership",
    "org_team",
    "repo_access",
    "repo_lifecycle",
    "branch_rules",
    "pull",
    "checks",
    "reviews",
    "lfs_locks",
    "authority",
];

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeKey {
    pub scope_kind: String,
    pub scope_id: Uuid,
}

impl ScopeKey {
    pub fn new(scope_kind: impl Into<String>, scope_id: Uuid) -> Self {
        Self { scope_kind: scope_kind.into(), scope_id }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeFloorRecord {
    pub key: ScopeKey,
    pub repository_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub lifecycle: ScopeLifecycle,
    pub authz_floor: i64,
    pub last_change_id: Uuid,
    pub closed_at_tick: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionScopeIndexRecord {
    pub decision_id: Uuid,
    pub dependencies: Vec<super::commands::WireDecisionScopeDep>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeDrainSnapshot {
    pub scope: Option<ScopeFloorRecord>,
    pub pending_operation_ids: Vec<Uuid>,
    pub open_decision_ids: Vec<Uuid>,
    pub settled_terminal_operations: BTreeMap<Uuid, OperationState>,
}

pub fn validate_scope_kind(kind: &str) -> Result<(), StateMachineError> {
    if !SUPPORTED_DECISION_SCOPE_KINDS.contains(&kind) {
        return Err(StateMachineError::InvalidInput(format!("unsupported decision scope_kind {kind:?}")));
    }
    Ok(())
}

pub(super) fn close_auth_scope(
    state: &mut SmState,
    cmd: CloseAuthScopeCommand,
) -> Result<ApplyResponse, StateMachineError> {
    validate_scope_kind(&cmd.scope_kind)?;
    if cmd.scope_id.is_nil() || cmd.change_id.is_nil() {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity(
            "scope_id and change_id must be non-nil".into(),
        )));
    }
    if cmd.lifecycle == ScopeLifecycle::Open || cmd.authz_floor <= 0 {
        return Err(StateMachineError::InvalidInput(
            "close_auth_scope requires Closing/Closed lifecycle and positive authz_floor".into(),
        ));
    }
    if let Some(repo_id) = cmd.repository_id
        && repo_id.is_nil()
    {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity("repository_id must be non-nil".into())));
    }
    if let Some(tenant_id) = cmd.tenant_id
        && tenant_id.is_nil()
    {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity("tenant_id must be non-nil".into())));
    }

    let key = ScopeKey::new(&cmd.scope_kind, cmd.scope_id);
    let effective_tick = state.logical_clock_floor.max(cmd.logical_tick);
    let replayed = if let Some(existing) = state.scope_floors.get(&key) {
        if cmd.lifecycle < existing.lifecycle {
            return Err(StateMachineError::LifecycleRegression {
                current: existing.lifecycle,
                requested: cmd.lifecycle,
            });
        }
        if cmd.authz_floor < existing.authz_floor {
            return Err(StateMachineError::AuthzFloorRegression {
                current_floor: existing.authz_floor,
                requested_floor: cmd.authz_floor,
            });
        }
        existing.lifecycle == cmd.lifecycle
            && existing.authz_floor == cmd.authz_floor
            && existing.last_change_id == cmd.change_id
            && existing.repository_id == cmd.repository_id
            && existing.tenant_id == cmd.tenant_id
    } else {
        false
    };

    if let Some(repo_id) = cmd.repository_id
        && let Some(gate) = state.gates.get_mut(&repo_id)
    {
        if let Some(tid) = cmd.tenant_id
            && gate.tenant_id != tid
        {
            return Err(StateMachineError::InvalidInput("close_auth_scope tenant disagrees with gate".into()));
        }
        if !replayed {
            if cmd.authz_floor > gate.authz_floor {
                gate.authz_floor = cmd.authz_floor;
            }
            if matches!(cmd.scope_kind.as_str(), "repo_lifecycle" | "authority") && cmd.lifecycle > gate.lifecycle {
                gate.lifecycle = cmd.lifecycle;
            }
        }
    }

    if !replayed {
        state.advance_clock(effective_tick);
        state.scope_floors.insert(
            key.clone(),
            ScopeFloorRecord {
                key: key.clone(),
                repository_id: cmd.repository_id,
                tenant_id: cmd.tenant_id,
                lifecycle: cmd.lifecycle,
                authz_floor: cmd.authz_floor,
                last_change_id: cmd.change_id,
                closed_at_tick: effective_tick,
            },
        );
    }

    let drain = inspect_scope_drain_inner(state, &key);
    Ok(ApplyResponse::AuthScopeClosed {
        scope_kind: cmd.scope_kind,
        scope_id: cmd.scope_id,
        lifecycle: cmd.lifecycle,
        authz_floor: cmd.authz_floor,
        replayed,
        open_decision_ids: drain.open_decision_ids,
        pending_operation_ids: drain.pending_operation_ids,
    })
}

pub(super) fn install_scoped_decision(
    state: &mut SmState,
    cmd: InstallScopedDecisionCommand,
) -> Result<ApplyResponse, StateMachineError> {
    if cmd.scope_dependencies.is_empty() {
        return Err(StateMachineError::InvalidInput(
            "install_scoped_decision requires at least one indexed scope dependency".into(),
        ));
    }
    let mut seen_scopes = BTreeSet::new();
    for dep in &cmd.scope_dependencies {
        validate_scope_kind(&dep.scope_kind)?;
        if dep.scope_id.is_nil() || dep.observed_version < 0 {
            return Err(StateMachineError::InvalidInput("invalid decision dependency scope_id or version".into()));
        }
        RequestDigest::from_str(&dep.observed_digest)?;
        let skey = ScopeKey::new(&dep.scope_kind, dep.scope_id);
        if !seen_scopes.insert(skey) {
            return Err(StateMachineError::InvalidInput("duplicate scope dependency in scoped decision".into()));
        }
    }

    let op_key = super::state::RepoEntityKey::new(cmd.decision.repository_id, cmd.decision.operation_id);
    let already_installed = state.decisions_by_op.contains_key(&op_key);
    if !already_installed {
        for dep in &cmd.scope_dependencies {
            let skey = ScopeKey::new(&dep.scope_kind, dep.scope_id);
            if let Some(floor) = state.scope_floors.get(&skey) {
                if floor.lifecycle != ScopeLifecycle::Open {
                    return Err(StateMachineError::ScopeClosingOrClosed {
                        repository_id: cmd.decision.repository_id,
                        lifecycle: floor.lifecycle,
                    });
                }
                if cmd.decision.authz_epoch < floor.authz_floor {
                    return Err(StateMachineError::AuthzFloorViolation {
                        authz_epoch: cmd.decision.authz_epoch,
                        floor: floor.authz_floor,
                    });
                }
            }
        }
    }

    let decision_id = cmd.decision.decision_id;
    let resp = install_decision(state, cmd.decision)?;
    if let Some(existing_rec) = state.decision_scope_deps.get(&decision_id) {
        if existing_rec.dependencies != cmd.scope_dependencies {
            return Err(StateMachineError::DecisionConflict { decision_id, state: SmDecisionState::Open });
        }
    } else {
        for dep in &cmd.scope_dependencies {
            let skey = ScopeKey::new(&dep.scope_kind, dep.scope_id);
            state.scope_decision_index.entry(skey).or_default().insert(decision_id);
        }
        state
            .decision_scope_deps
            .insert(decision_id, DecisionScopeIndexRecord { decision_id, dependencies: cmd.scope_dependencies });
    }
    Ok(resp)
}

pub(super) fn verify_decision_scopes_open(
    state: &SmState,
    decision_id: Uuid,
    decision_authz_epoch: i64,
) -> Result<(), StateMachineError> {
    let Some(indexed) = state.decision_scope_deps.get(&decision_id) else {
        return Ok(());
    };
    let repo_id = state.decisions.get(&decision_id).map_or_else(Uuid::nil, |d| d.repository_id);
    for dep in &indexed.dependencies {
        let skey = ScopeKey::new(&dep.scope_kind, dep.scope_id);
        if let Some(floor) = state.scope_floors.get(&skey) {
            if floor.lifecycle != ScopeLifecycle::Open {
                return Err(StateMachineError::ScopeClosingOrClosed {
                    repository_id: repo_id,
                    lifecycle: floor.lifecycle,
                });
            }
            if decision_authz_epoch < floor.authz_floor {
                return Err(StateMachineError::AuthzFloorViolation {
                    authz_epoch: decision_authz_epoch,
                    floor: floor.authz_floor,
                });
            }
        }
    }
    Ok(())
}

pub(super) fn inspect_scope_drain(
    state: &SmState,
    scope_kind: &str,
    scope_id: Uuid,
) -> Result<ScopeDrainSnapshot, StateMachineError> {
    validate_scope_kind(scope_kind)?;
    if scope_id.is_nil() {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity("scope_id must be non-nil".into())));
    }
    Ok(inspect_scope_drain_inner(state, &ScopeKey::new(scope_kind, scope_id)))
}

fn inspect_scope_drain_inner(state: &SmState, key: &ScopeKey) -> ScopeDrainSnapshot {
    let scope = state.scope_floors.get(key).cloned();
    let mut pending_operation_ids = Vec::new();
    let mut open_decision_ids = Vec::new();
    let mut settled_terminal_operations = BTreeMap::new();

    if let Some(decision_ids) = state.scope_decision_index.get(key) {
        for &decision_id in decision_ids {
            let Some(decision) = state.decisions.get(&decision_id) else {
                continue;
            };
            if decision.state == SmDecisionState::Open {
                open_decision_ids.push(decision_id);
            }
            let op_key = super::state::RepoEntityKey::new(decision.repository_id, decision.operation_id);
            if let Some(op) = state.operations.get(&op_key) {
                match op.state() {
                    OperationState::Pending => pending_operation_ids.push(decision.operation_id),
                    settled => {
                        settled_terminal_operations.insert(decision.operation_id, settled);
                    }
                }
            } else if state.cancellations.contains_key(&op_key) {
                settled_terminal_operations.insert(decision.operation_id, OperationState::Cancelled);
            } else if decision.state == SmDecisionState::Open {
                pending_operation_ids.push(decision.operation_id);
            }
        }
    }

    ScopeDrainSnapshot { scope, pending_operation_ids, open_decision_ids, settled_terminal_operations }
}
