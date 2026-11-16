//! PG `OPEN -> CLOSING` projection bridge and linearizable Raft `ReadIndex` drain barrier (`#152`).
//!
//! Enforces strict fail-closed revocation ordering:
//! 1. PG `ref_store_decision_scopes` (`state = 'CLOSING'`) transitions project monotonically into
//!    `CloseAuthScopeCommand` in the ordered Raft log, never trusting PG wall clocks.
//! 2. Before acknowledging revocation / closing completion, the bridge runs a linearizable
//!    Raft `ReadIndex` barrier and confirms every dependent operation has settled terminal state.
//! 3. Network partitions, quorum loss, or missing terminals stay `Unknown` and NEVER fall back to PG.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::GenericClient;
use uuid::Uuid;

use super::session_fence::{AuthoritySourceKind, assert_authoritative_source};
use crate::ref_store::contract::{IssuerLane, OperationState, RequestDigest};
use crate::ref_store::core::state_machine::{
    CancelCommand, CloseAuthScopeCommand, ScopeDrainSnapshot, ScopeLifecycle, WireOperationIdentity,
    validate_scope_kind,
};
use std::str::FromStr;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PgClosingScopeRow {
    pub scope_kind: String,
    pub scope_id: Uuid,
    pub version: i64,
    pub change_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PgDecisionCancellationRow {
    pub repository_id: Uuid,
    pub operation_id: Uuid,
    pub decision_id: Option<Uuid>,
    pub request_digest: String,
    pub actor_id: Uuid,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DrainedOperationTerminal {
    pub operation_id: Uuid,
    pub state: OperationState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum RevocationDrainStatus {
    DrainedAndConfirmed {
        scope_kind: String,
        scope_id: Uuid,
        authz_floor: i64,
        read_log_index: u64,
        confirmed_operations: Vec<DrainedOperationTerminal>,
    },
    DrainInProgress {
        pending_operation_ids: Vec<Uuid>,
        open_decision_ids: Vec<Uuid>,
        reason: String,
    },
    UnknownQuorumLoss {
        reason: String,
    },
}

impl RevocationDrainStatus {
    /// Returns true ONLY when linearizable Raft `ReadIndex` confirms closed floor + drained terminals.
    pub fn can_ack_revocation(&self) -> bool {
        matches!(self, Self::DrainedAndConfirmed { .. })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinearizableScopeProbe {
    pub source: AuthoritySourceKind,
    pub read_log_index: Option<u64>,
    pub applied_log_index: u64,
    pub drain: ScopeDrainSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteAuthzBridgeError {
    PgDatabase(String),
    InvalidInput(String),
    AuthorityViolation(String),
}

impl std::fmt::Display for RemoteAuthzBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PgDatabase(msg) => write!(f, "remote authz bridge PG error: {msg}"),
            Self::InvalidInput(msg) => write!(f, "remote authz bridge invalid input: {msg}"),
            Self::AuthorityViolation(msg) => write!(f, "remote authz bridge authority violation: {msg}"),
        }
    }
}

impl std::error::Error for RemoteAuthzBridgeError {}

/// Queries committed PostgreSQL `ref_store_decision_scopes` rows in `CLOSING` state ordered deterministically.
pub async fn load_closing_scopes_from_pg<C: GenericClient + Sync>(
    client: &C,
) -> Result<Vec<PgClosingScopeRow>, RemoteAuthzBridgeError> {
    let rows = client
        .query(
            "SELECT scope_kind, scope_id, version, change_id
             FROM ref_store_decision_scopes
             WHERE state = 'CLOSING'
             ORDER BY scope_kind ASC, scope_id ASC",
            &[],
        )
        .await
        .map_err(|e| RemoteAuthzBridgeError::PgDatabase(e.to_string()))?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let scope_kind: String = row.get(0);
        validate_scope_kind(&scope_kind).map_err(|e| RemoteAuthzBridgeError::InvalidInput(e.to_string()))?;
        let scope_id: Uuid = row.get(1);
        let version: i64 = row.get(2);
        let change_opt: Option<Uuid> = row.get(3);
        let change_id = change_opt.unwrap_or(scope_id);
        out.push(PgClosingScopeRow { scope_kind, scope_id, version, change_id });
    }
    Ok(out)
}

/// Projects PG `CLOSING` scope rows into monotonic `CloseAuthScopeCommand` entries independent of PG wall clocks.
pub fn plan_close_scope_commands(
    rows: &[PgClosingScopeRow],
    repository_id: Option<Uuid>,
    tenant_id: Option<Uuid>,
    min_authz_floor: i64,
    logical_tick: u64,
) -> Result<Vec<CloseAuthScopeCommand>, RemoteAuthzBridgeError> {
    if min_authz_floor <= 0 {
        return Err(RemoteAuthzBridgeError::InvalidInput("min_authz_floor must be positive".into()));
    }
    let mut cmds = Vec::with_capacity(rows.len());
    for row in rows {
        validate_scope_kind(&row.scope_kind).map_err(|e| RemoteAuthzBridgeError::InvalidInput(e.to_string()))?;
        let authz_floor = min_authz_floor.max(row.version).max(1);
        cmds.push(CloseAuthScopeCommand {
            scope_kind: row.scope_kind.clone(),
            scope_id: row.scope_id,
            repository_id,
            tenant_id,
            lifecycle: ScopeLifecycle::Closing,
            authz_floor,
            change_id: row.change_id,
            logical_tick,
        });
    }
    Ok(cmds)
}

/// Queries PG decision cancellations so pending/open operations can be deterministically cancelled via Raft log.
pub async fn load_decision_cancellations_from_pg<C: GenericClient + Sync>(
    client: &C,
    repository_id: Uuid,
) -> Result<Vec<PgDecisionCancellationRow>, RemoteAuthzBridgeError> {
    let rows = client
        .query(
            "SELECT repository_id, operation_id, decision_id, request_digest, actor_id, reason
             FROM ref_store_decision_cancellations
             WHERE repository_id = $1
             ORDER BY operation_id ASC",
            &[&repository_id],
        )
        .await
        .map_err(|e| RemoteAuthzBridgeError::PgDatabase(e.to_string()))?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(PgDecisionCancellationRow {
            repository_id: r.get(0),
            operation_id: r.get(1),
            decision_id: r.get(2),
            request_digest: r.get(3),
            actor_id: r.get(4),
            reason: r.get(5),
        });
    }
    Ok(out)
}

/// Converts a PG cancellation tombstone row into a deterministic same-log Raft `CancelCommand`.
pub fn build_cancel_command_from_pg(
    row: &PgDecisionCancellationRow,
    lane: &str,
    sequence: i64,
    logical_tick: u64,
) -> Result<CancelCommand, RemoteAuthzBridgeError> {
    let lane_parsed = IssuerLane::new(lane).map_err(|e| RemoteAuthzBridgeError::InvalidInput(e.to_string()))?;
    let digest = RequestDigest::from_str(&row.request_digest)
        .map_err(|e| RemoteAuthzBridgeError::InvalidInput(e.to_string()))?;
    let id = crate::ref_store::contract::OperationIdentity::new(
        row.repository_id,
        row.actor_id,
        lane_parsed,
        sequence,
        row.operation_id,
        digest,
    )
    .map_err(|e| RemoteAuthzBridgeError::InvalidInput(e.to_string()))?;
    Ok(CancelCommand { identity: (&id).into(), reason: Some(row.reason.clone()), logical_tick })
}

/// Evaluates whether a `CLOSING` scope can be safely acknowledged as drained using ONLY a
/// linearizable Raft `ReadIndex` barrier observation (`assert_authoritative_source` refuses PG/Redis).
pub fn evaluate_revocation_drain_barrier(
    probe: &LinearizableScopeProbe,
    scope_kind: &str,
    scope_id: Uuid,
    required_authz_floor: i64,
    required_close_log_index: u64,
) -> Result<RevocationDrainStatus, RemoteAuthzBridgeError> {
    validate_scope_kind(scope_kind).map_err(|e| RemoteAuthzBridgeError::InvalidInput(e.to_string()))?;
    if let Err(err) = assert_authoritative_source(probe.source) {
        return Err(RemoteAuthzBridgeError::AuthorityViolation(err.to_string()));
    }
    let Some(read_idx) = probe.read_log_index else {
        return Ok(RevocationDrainStatus::UnknownQuorumLoss {
            reason: "missing linearizable ReadIndex log index".into(),
        });
    };
    if probe.applied_log_index < read_idx || probe.applied_log_index < required_close_log_index {
        return Ok(RevocationDrainStatus::DrainInProgress {
            pending_operation_ids: probe.drain.pending_operation_ids.clone(),
            open_decision_ids: probe.drain.open_decision_ids.clone(),
            reason: format!(
                "replica applied_log_index {} behind required (read={}, close={})",
                probe.applied_log_index, read_idx, required_close_log_index
            ),
        });
    }
    let Some(floor) = &probe.drain.scope else {
        return Ok(RevocationDrainStatus::DrainInProgress {
            pending_operation_ids: probe.drain.pending_operation_ids.clone(),
            open_decision_ids: probe.drain.open_decision_ids.clone(),
            reason: format!("scope ({scope_kind}, {scope_id}) closure not yet applied"),
        });
    };
    if floor.lifecycle == ScopeLifecycle::Open || floor.authz_floor < required_authz_floor {
        return Ok(RevocationDrainStatus::DrainInProgress {
            pending_operation_ids: probe.drain.pending_operation_ids.clone(),
            open_decision_ids: probe.drain.open_decision_ids.clone(),
            reason: format!(
                "scope ({scope_kind}, {scope_id}) lifecycle={:?} floor={} behind required {required_authz_floor}",
                floor.lifecycle, floor.authz_floor
            ),
        });
    }
    if !probe.drain.open_decision_ids.is_empty() || !probe.drain.pending_operation_ids.is_empty() {
        return Ok(RevocationDrainStatus::DrainInProgress {
            pending_operation_ids: probe.drain.pending_operation_ids.clone(),
            open_decision_ids: probe.drain.open_decision_ids.clone(),
            reason: "indexed open decisions or pending operations have not reached terminal".into(),
        });
    }

    let confirmed_operations = collect_terminals(&probe.drain.settled_terminal_operations);
    Ok(RevocationDrainStatus::DrainedAndConfirmed {
        scope_kind: scope_kind.to_owned(),
        scope_id,
        authz_floor: floor.authz_floor,
        read_log_index: read_idx,
        confirmed_operations,
    })
}

/// Polls linearizable `ReadIndex` scope probes up to `budget`, never falling back to PG or ACKing
/// revocation when quorum/terminal state remains unknown or draining.
pub async fn await_drain_before_revocation_ack<F, Fut>(
    scope_kind: &str,
    scope_id: Uuid,
    required_authz_floor: i64,
    required_close_log_index: u64,
    budget: Duration,
    poll_interval: Duration,
    mut probe_fn: F,
) -> Result<RevocationDrainStatus, RemoteAuthzBridgeError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<LinearizableScopeProbe, String>>,
{
    let deadline = Instant::now() + budget;
    let mut last_status = RevocationDrainStatus::UnknownQuorumLoss { reason: "no drain probe completed".into() };

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(last_status);
        }
        match timeout_at(deadline, probe_fn()).await {
            Ok(Ok(probe)) => {
                let status = evaluate_revocation_drain_barrier(
                    &probe,
                    scope_kind,
                    scope_id,
                    required_authz_floor,
                    required_close_log_index,
                )?;
                if status.can_ack_revocation() {
                    return Ok(status);
                }
                last_status = status;
            }
            Ok(Err(reason)) => {
                last_status = RevocationDrainStatus::UnknownQuorumLoss { reason };
            }
            Err(_) => {
                return Ok(last_status);
            }
        }
        let rem = deadline.saturating_duration_since(Instant::now());
        if rem.is_zero() {
            return Ok(last_status);
        }
        tokio::time::sleep(poll_interval.min(rem)).await;
    }
}

fn collect_terminals(map: &BTreeMap<Uuid, OperationState>) -> Vec<DrainedOperationTerminal> {
    map.iter().map(|(&operation_id, &state)| DrainedOperationTerminal { operation_id, state }).collect()
}
