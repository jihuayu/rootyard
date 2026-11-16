//! Multi-group shared artifact-hold retirement coordinator and PostgreSQL
//! projection cursor reconciler (`ref_cas_projection_cursors`, #151).

pub use super::bridge_contract::{
    GroupHoldBinding, PgArtifactHoldReconciliationView, PgCrossRepoSiblingHold, PgHoldRowSummary, RetentionBridgeError,
    SharedHoldReference, SharedHoldRetirementStatus,
};
pub use super::retention_bridge::apply_retire_hold_batch_idempotent;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::state_machine::{RefCasStateMachine, ScopeLifecycle, SmHoldState, SmRootState};
use crate::ref_store::pg::{self as ref_pg, db_error};
use crate::ref_store::projector::{ProjectionCursor, ProjectionStreamState, load_cursor};
use crate::ref_store::tx::begin_bounded;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use tokio::time::Instant;
use tokio_postgres::Client;
use uuid::Uuid;

/// Irreversible per-group retirement receipt emitted from `RefCasStateMachine`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRetirementReceipt {
    pub group_id: i64,
    pub history_incarnation: Uuid,
    pub group_epoch: i64,
    pub authority_epoch: i64,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub scope_lifecycle: ScopeLifecycle,
    pub retire_request_id: Uuid,
    pub retired_hold_ids: Vec<Uuid>,
    pub active_root_count: usize,
    pub retirement_log_index: u64,
    pub applied_log_index: u64,
    pub snapshot_digest: String,
    pub receipt_digest: String,
}

impl GroupRetirementReceipt {
    pub fn compute_digest(&self) -> RequestDigest {
        let tag: &[u8] = match self.scope_lifecycle {
            ScopeLifecycle::Open => b"open",
            ScopeLifecycle::Closing => b"closing",
            ScopeLifecycle::Closed => b"closed",
        };
        let mut sorted = self.retired_hold_ids.clone();
        sorted.sort();
        let (gid, ge, ae) =
            (self.group_id.to_be_bytes(), self.group_epoch.to_be_bytes(), self.authority_epoch.to_be_bytes());
        let (ar, rl, al) = (
            (self.active_root_count as u64).to_be_bytes(),
            self.retirement_log_index.to_be_bytes(),
            self.applied_log_index.to_be_bytes(),
        );
        let head: [&[u8]; 12] = [
            &gid,
            self.history_incarnation.as_bytes(),
            &ge,
            &ae,
            self.repository_id.as_bytes(),
            self.tenant_id.as_bytes(),
            tag,
            self.retire_request_id.as_bytes(),
            &ar,
            &rl,
            &al,
            self.snapshot_digest.as_bytes(),
        ];
        let mut slices: Vec<&[u8]> = head.to_vec();
        slices.extend(sorted.iter().map(|id| id.as_bytes().as_slice()));
        RequestDigest::of("refcas-group-retirement-receipt-v1", &slices)
    }

    pub fn verify_integrity(&self) -> Result<(), RetentionBridgeError> {
        RequestDigest::from_str(&self.snapshot_digest)?;
        RequestDigest::from_str(&self.receipt_digest)?;
        if self.compute_digest().as_hex() != self.receipt_digest {
            return Err(RetentionBridgeError::RetirementRefused("group retirement receipt checksum mismatch".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupObservationStatus {
    Retired,
    Active,
    Unreachable,
    UnknownOutcome,
    StaleSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRetirementObservation {
    pub group_id: i64,
    pub repository_id: Uuid,
    pub status: GroupObservationStatus,
    pub receipt: Option<GroupRetirementReceipt>,
    pub observed_log_index: Option<u64>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementBlockReason {
    GroupMissingObservation { group_id: i64, repository_id: Uuid },
    GroupDuplicateObservation { group_id: i64, repository_id: Uuid },
    GroupUnreachable { group_id: i64, repository_id: Uuid },
    GroupUnknownOutcome { group_id: i64, repository_id: Uuid },
    GroupStillActive { group_id: i64, repository_id: Uuid },
    ClosingBarrierNotReached { group_id: i64, repository_id: Uuid },
    ActiveRootStillProtecting { group_id: i64, repository_id: Uuid, active_roots: usize },
    HoldNotRetiredInGroup { group_id: i64, repository_id: Uuid },
    StaleSnapshot { group_id: i64, repository_id: Uuid, observed_log_index: u64, required_log_index: u64 },
    InvalidReceipt { group_id: i64, repository_id: Uuid },
    MissingProjectionCursor { group_id: i64, history_incarnation: Uuid },
    CursorResyncRequired { group_id: i64, history_incarnation: Uuid },
    CursorEpochMismatch { group_id: i64, expected_epoch: i64, actual_epoch: i64 },
    CursorBehindRetirement { group_id: i64, applied_log_index: u64, retirement_log_index: u64 },
    MissingPgHoldRow { repository_id: Uuid, hold_id: Uuid },
    PgHoldIdentityMismatch { repository_id: Uuid, hold_id: Uuid },
    UnreconciledCrossRepoHold { repository_id: Uuid, hold_id: Uuid },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SharedHoldReconciliationOutcome {
    pub shared_hold_key: Uuid,
    pub artifact_digest: String,
    pub backend_identity: String,
    pub status: SharedHoldRetirementStatus,
    pub reconciled_groups: usize,
    pub reasons: Vec<RetirementBlockReason>,
}

/// Inspect one group's deterministic `RefCasStateMachine` and emit either a
/// cryptographically sealed `GroupRetirementReceipt` or a typed blocking status.
pub fn observe_group_retirement_from_sm(
    sm: &RefCasStateMachine,
    binding: &GroupHoldBinding,
    expected_artifact_digest: &str,
    expected_backend_identity: &str,
    retirement_log_index: u64,
) -> Result<GroupRetirementObservation, RetentionBridgeError> {
    binding.validate()?;
    RequestDigest::from_str(expected_artifact_digest)?;
    RequestDigest::from_str(expected_backend_identity)?;
    if retirement_log_index == 0 {
        return Err(RetentionBridgeError::InvalidBinding("retirement_log_index must be >= 1".into()));
    }
    let snap = sm.snapshot()?;
    snap.verify_integrity()?;
    let applied_idx = snap.body.last_applied.map_or(0, |id| id.index);
    let blk = |status, detail: String| {
        Ok(GroupRetirementObservation {
            group_id: binding.group_id,
            repository_id: binding.repository_id,
            status,
            receipt: None,
            observed_log_index: Some(applied_idx),
            detail: Some(detail),
        })
    };
    let Some(gate) = sm.read_gate_version(binding.repository_id)? else {
        return blk(GroupObservationStatus::UnknownOutcome, "missing gate".into());
    };
    if (gate.tenant_id(), gate.history_incarnation(), gate.group_epoch())
        != (binding.tenant_id, binding.history_incarnation, binding.expected_group_epoch)
    {
        return blk(GroupObservationStatus::StaleSnapshot, "realm mismatch".into());
    }
    if applied_idx < retirement_log_index {
        return blk(GroupObservationStatus::StaleSnapshot, format!("applied {applied_idx} < {retirement_log_index}"));
    }
    let Some((lifecycle, _)) = sm.read_scope_lifecycle(binding.repository_id) else {
        return blk(GroupObservationStatus::UnknownOutcome, "no lifecycle".into());
    };
    if lifecycle == ScopeLifecycle::Open {
        return blk(GroupObservationStatus::Active, "closing barrier open".into());
    }
    let active_roots = snap
        .body
        .roots
        .iter()
        .filter(|r| {
            r.state == SmRootState::Active
                && (r.repository_id == binding.repository_id
                    || r.bound_hold_ids.iter().any(|id| binding.hold_ids.contains(id)))
        })
        .count();
    if active_roots > 0 {
        return blk(GroupObservationStatus::Active, format!("{active_roots} active root(s) remain"));
    }
    let Some(retire_rec) = snap.body.hold_retires.iter().find(|r| {
        (r.request_id, r.repository_id, r.tenant_id)
            == (binding.retire_request_id, binding.repository_id, binding.tenant_id)
    }) else {
        return blk(GroupObservationStatus::Active, "no retire receipt".into());
    };
    for &hold_id in &binding.hold_ids {
        if !retire_rec.hold_ids.contains(&hold_id) {
            return blk(GroupObservationStatus::Active, "hold omitted from retire receipt".into());
        }
        let Some(e) = sm.read_hold(hold_id) else {
            return blk(GroupObservationStatus::UnknownOutcome, "missing hold".into());
        };
        if (e.repository_id, e.tenant_id) != (binding.repository_id, binding.tenant_id)
            || e.artifact_digest != expected_artifact_digest
            || e.backend_identity != expected_backend_identity
            || e.state != SmHoldState::Retired
        {
            return blk(GroupObservationStatus::Active, "hold not retired".into());
        }
    }
    let mut receipt = GroupRetirementReceipt {
        group_id: binding.group_id,
        history_incarnation: binding.history_incarnation,
        group_epoch: gate.group_epoch(),
        authority_epoch: gate.authority_epoch(),
        repository_id: binding.repository_id,
        tenant_id: binding.tenant_id,
        scope_lifecycle: lifecycle,
        retire_request_id: binding.retire_request_id,
        retired_hold_ids: binding.hold_ids.clone(),
        active_root_count: active_roots,
        retirement_log_index,
        applied_log_index: applied_idx,
        snapshot_digest: sm.state_digest()?,
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = receipt.compute_digest().as_hex();
    let (group_id, repository_id, receipt) = (binding.group_id, binding.repository_id, Some(receipt));
    Ok(GroupRetirementObservation {
        group_id,
        repository_id,
        status: GroupObservationStatus::Retired,
        receipt,
        observed_log_index: Some(applied_idx),
        detail: None,
    })
}

fn verify_group_cursor(
    binding: &GroupHoldBinding,
    receipt: Option<&GroupRetirementReceipt>,
    cursor: Option<&ProjectionCursor>,
    reasons: &mut Vec<RetirementBlockReason>,
) {
    let (group_id, history_incarnation) = (binding.group_id, binding.history_incarnation);
    let Some(cursor) = cursor else {
        reasons.push(RetirementBlockReason::MissingProjectionCursor { group_id, history_incarnation });
        return;
    };
    let cutoff_behind = cursor.truncation_cutoff.as_ref().is_some_and(|c| cursor.applied_log_index < c.log_index);
    if cursor.stream_state != ProjectionStreamState::Active || cutoff_behind {
        reasons.push(RetirementBlockReason::CursorResyncRequired { group_id, history_incarnation });
    }
    let (expected_epoch, actual_epoch) = (binding.expected_group_epoch, cursor.realm.group_epoch);
    if actual_epoch != expected_epoch {
        reasons.push(RetirementBlockReason::CursorEpochMismatch { group_id, expected_epoch, actual_epoch });
    }
    if let Some(receipt) = receipt
        && cursor.applied_log_index < receipt.retirement_log_index
    {
        let (applied_log_index, retirement_log_index) = (cursor.applied_log_index, receipt.retirement_log_index);
        reasons.push(RetirementBlockReason::CursorBehindRetirement {
            group_id,
            applied_log_index,
            retirement_log_index,
        });
    }
}

fn validate_retired_receipt(
    binding: &GroupHoldBinding,
    obs: &GroupRetirementObservation,
    reasons: &mut Vec<RetirementBlockReason>,
) -> Option<GroupRetirementReceipt> {
    let (group_id, repository_id) = (binding.group_id, binding.repository_id);
    let Some(r) = &obs.receipt else {
        reasons.push(RetirementBlockReason::InvalidReceipt { group_id, repository_id });
        return None;
    };
    if r.verify_integrity().is_err()
        || r.group_id != group_id
        || r.repository_id != repository_id
        || r.tenant_id != binding.tenant_id
        || r.history_incarnation != binding.history_incarnation
        || r.group_epoch != binding.expected_group_epoch
        || r.retire_request_id != binding.retire_request_id
    {
        reasons.push(RetirementBlockReason::InvalidReceipt { group_id, repository_id });
        return None;
    }
    if r.scope_lifecycle == ScopeLifecycle::Open {
        reasons.push(RetirementBlockReason::ClosingBarrierNotReached { group_id, repository_id });
    }
    if r.active_root_count > 0 {
        let active_roots = r.active_root_count;
        reasons.push(RetirementBlockReason::ActiveRootStillProtecting { group_id, repository_id, active_roots });
    }
    if r.retirement_log_index == 0 || r.applied_log_index < r.retirement_log_index {
        reasons.push(RetirementBlockReason::StaleSnapshot {
            group_id,
            repository_id,
            observed_log_index: r.applied_log_index,
            required_log_index: r.retirement_log_index,
        });
    }
    let retired_set: BTreeSet<Uuid> = r.retired_hold_ids.iter().copied().collect();
    if !binding.hold_ids.iter().all(|id| retired_set.contains(id)) {
        reasons.push(RetirementBlockReason::HoldNotRetiredInGroup { group_id, repository_id });
    }
    Some(r.clone())
}

fn check_group_observation(
    g: &GroupHoldBinding,
    obs: Option<&GroupRetirementObservation>,
    reasons: &mut Vec<RetirementBlockReason>,
) -> Option<GroupRetirementReceipt> {
    let (group_id, repository_id) = (g.group_id, g.repository_id);
    let Some(obs) = obs else {
        reasons.push(RetirementBlockReason::GroupMissingObservation { group_id, repository_id });
        return None;
    };
    let reason = match obs.status {
        GroupObservationStatus::Unreachable => RetirementBlockReason::GroupUnreachable { group_id, repository_id },
        GroupObservationStatus::UnknownOutcome => {
            RetirementBlockReason::GroupUnknownOutcome { group_id, repository_id }
        }
        GroupObservationStatus::Active => RetirementBlockReason::GroupStillActive { group_id, repository_id },
        GroupObservationStatus::StaleSnapshot => RetirementBlockReason::StaleSnapshot {
            group_id,
            repository_id,
            observed_log_index: obs.observed_log_index.unwrap_or(0),
            required_log_index: 1,
        },
        GroupObservationStatus::Retired => return validate_retired_receipt(g, obs, reasons),
    };
    reasons.push(reason);
    None
}

fn check_group_pg_holds(
    g: &GroupHoldBinding,
    shared: &SharedHoldReference,
    hold_map: &BTreeMap<Uuid, &PgHoldRowSummary>,
    reasons: &mut Vec<RetirementBlockReason>,
) {
    let repository_id = g.repository_id;
    for &hold_id in &g.hold_ids {
        match hold_map.get(&hold_id) {
            None => reasons.push(RetirementBlockReason::MissingPgHoldRow { repository_id, hold_id }),
            Some(r)
                if r.repository_id != repository_id
                    || r.tenant_id != g.tenant_id
                    || r.sha256 != shared.artifact_digest
                    || r.backend_identity != shared.backend_identity
                    || r.state != "active" =>
            {
                reasons.push(RetirementBlockReason::PgHoldIdentityMismatch { repository_id, hold_id });
            }
            Some(_) => {}
        }
    }
}

/// Fail-closed multi-group evaluator combining group retirement receipts,
/// Migration-149 PG projection cursors, and PG cross-repo `artifact_holds`.
pub fn evaluate_shared_hold_retirement(
    shared: &SharedHoldReference,
    observations: &[GroupRetirementObservation],
    cursors: &[ProjectionCursor],
    pg_holds: Option<&PgArtifactHoldReconciliationView>,
) -> Result<SharedHoldReconciliationOutcome, RetentionBridgeError> {
    shared.validate()?;
    let (mut obs_map, mut reasons) = (BTreeMap::new(), Vec::new());
    for obs in observations {
        if obs_map.insert((obs.group_id, obs.repository_id), obs).is_some() {
            let (group_id, repository_id) = (obs.group_id, obs.repository_id);
            reasons.push(RetirementBlockReason::GroupDuplicateObservation { group_id, repository_id });
        }
    }
    let cursor_map: BTreeMap<(i64, Uuid), &ProjectionCursor> =
        cursors.iter().map(|c| ((c.realm.group_id, c.realm.history_incarnation), c)).collect();
    let hold_map: BTreeMap<Uuid, &PgHoldRowSummary> =
        pg_holds.map(|v| v.found_holds.iter().map(|r| (r.hold_id, r)).collect()).unwrap_or_default();

    let mut reconciled_groups = 0usize;
    for g in &shared.groups {
        let valid_receipt =
            check_group_observation(g, obs_map.get(&(g.group_id, g.repository_id)).copied(), &mut reasons);
        let before = reasons.len();
        verify_group_cursor(
            g,
            valid_receipt.as_ref(),
            cursor_map.get(&(g.group_id, g.history_incarnation)).copied(),
            &mut reasons,
        );
        if pg_holds.is_some() {
            check_group_pg_holds(g, shared, &hold_map, &mut reasons);
        }
        if valid_receipt.is_some() && reasons.len() == before {
            reconciled_groups += 1;
        }
    }
    if let Some(view) = pg_holds {
        reasons.extend(view.unreconciled_sibling_holds.iter().map(|sib| {
            RetirementBlockReason::UnreconciledCrossRepoHold { repository_id: sib.repository_id, hold_id: sib.hold_id }
        }));
    }
    let status = if reasons.is_empty() {
        SharedHoldRetirementStatus::RetiredToSafeReclaim
    } else {
        SharedHoldRetirementStatus::Protected
    };
    let (shared_hold_key, artifact_digest, backend_identity) =
        (shared.shared_hold_key, shared.artifact_digest.clone(), shared.backend_identity.clone());
    Ok(SharedHoldReconciliationOutcome {
        shared_hold_key,
        artifact_digest,
        backend_identity,
        status,
        reconciled_groups,
        reasons,
    })
}

/// Live PG multi-group reconciliation reading `ref_cas_projection_cursors` and
/// cross-repo `artifact_holds` in one bounded read-only transaction.
pub async fn reconcile_shared_hold_retirement_with_pg(
    client: &mut Client,
    shared: &SharedHoldReference,
    observations: &[GroupRetirementObservation],
    deadline: Instant,
) -> Result<SharedHoldReconciliationOutcome, RetentionBridgeError> {
    shared.validate()?;
    let hold_ids = shared.all_hold_ids();
    let tx = begin_bounded(client, deadline).await?;
    let loaded: Result<(Vec<ProjectionCursor>, PgArtifactHoldReconciliationView), RetentionBridgeError> = async {
        ref_pg::bound(&tx, deadline).await?;
        let mut cursors = Vec::new();
        for g in &shared.groups {
            if let Some(c) =
                load_cursor(&tx, g.group_id, g.history_incarnation).await.map_err(|e| RetentionBridgeError::Database(e.to_string()))?
            {
                cursors.push(c);
            }
        }
        let found_holds = tx
            .query("SELECT hold_id, repository_id, tenant_id, sha256, backend_identity, state FROM artifact_holds WHERE hold_id = ANY($1) ORDER BY hold_id ASC", &[&hold_ids])
            .await
            .map_err(db_error)?
            .into_iter()
            .map(|r| PgHoldRowSummary { hold_id: r.get(0), repository_id: r.get(1), tenant_id: r.get(2), sha256: r.get(3), backend_identity: r.get(4), state: r.get(5) })
            .collect();
        let unreconciled_sibling_holds = tx
            .query("SELECT repository_id, hold_id FROM artifact_holds WHERE backend_identity=$1 AND sha256=$2 AND NOT (hold_id = ANY($3)) ORDER BY repository_id ASC, hold_id ASC LIMIT 16", &[&shared.backend_identity, &shared.artifact_digest, &hold_ids])
            .await
            .map_err(db_error)?
            .into_iter()
            .map(|r| PgCrossRepoSiblingHold { repository_id: r.get(0), hold_id: r.get(1) })
            .collect();
        Ok((cursors, PgArtifactHoldReconciliationView { found_holds, unreconciled_sibling_holds }))
    }
    .await;
    let _ = tx.rollback().await;
    let (cursors, pg_view) = loaded?;
    evaluate_shared_hold_retirement(shared, observations, &cursors, Some(&pg_view))
}
