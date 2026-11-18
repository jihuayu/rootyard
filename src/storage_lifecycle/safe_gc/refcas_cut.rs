//! Authoritative Ref-CAS reconciled cut verification across `RefCasStateMachine` & PG17 (#122).
//!
//! A PostgreSQL `ref_store_core_refs.revision` sequence number NEVER proves a
//! Ref-CAS reconciled cut. `DistributedRefCas` (and any repository with active
//! migration-149 Ref-CAS streams) requires a cryptographically verified
//! [`RefCasReconciledCut`] proving `RefCasSnapshot::verify_integrity()`,
//! exact `(applied_event_seq, log_term, log_index)` equality with
//! `ref_cas_projection_cursors`, and zero unresolved `ref_cas_projection_jobs`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::ref_store::{
    core::state_machine::{RefCasStateMachine, SmDecisionState, SmHoldState, SmPinState, WireDecisionKind},
    projector::{ProjectionStreamState, pg::load_cursor},
};

use super::{
    SafeGcError,
    model::{
        DecisionKind, DecisionState, GlobalHoldEntry, GlobalHoldState, InFlightDecisionRecord, LiveRefRoot,
        encode_len_bytes, validate_sha256_hex,
    },
    store::DurableSafeGcAuthority,
};

/// Verified cutpoint proving zero unprojected Ref-CAS commits exist past PostgreSQL's cursor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefCasReconciledCut {
    pub group_id: i64,
    pub group_epoch: u64,
    pub history_id: Uuid,
    pub sm_applied_log_term: u64,
    pub sm_applied_log_index: u64,
    pub sm_applied_event_seq: u64,
    pub sm_last_event_log_term: u64,
    pub sm_last_event_log_index: u64,
    pub sm_snapshot_checksum: String,
    pub pg_projected_log_term: u64,
    pub pg_projected_log_index: u64,
    pub pg_projected_event_seq: u64,
    pub unprojected_jobs_count: u64,
}

impl RefCasReconciledCut {
    pub fn verify_reconciled(
        &self,
        expected_history_id: Uuid,
        min_raft_commit_index: u64,
        expected_quorum_epoch: u64,
    ) -> Result<(), SafeGcError> {
        if self.group_id < 0 || self.history_id.is_nil() || self.history_id != expected_history_id {
            return Err(SafeGcError::IncompleteProof("Ref-CAS reconciled cut history_id or group_id mismatch"));
        }
        if self.group_epoch == 0 || self.group_epoch != expected_quorum_epoch {
            return Err(SafeGcError::IncompleteProof("Ref-CAS reconciled cut group_epoch != quorum_epoch"));
        }
        if self.sm_applied_log_term == 0 || self.sm_applied_log_index < min_raft_commit_index.max(1) {
            return Err(SafeGcError::IncompleteProof(
                "Ref-CAS reconciled cut log_index has not reached required raft_commit_index",
            ));
        }
        validate_sha256_hex(&self.sm_snapshot_checksum)?;
        if self.unprojected_jobs_count > 0 {
            return Err(SafeGcError::IncompleteProof("unresolved PG ref_cas_projection_jobs exist at cutpoint"));
        }
        if self.pg_projected_event_seq != self.sm_applied_event_seq {
            return Err(SafeGcError::IncompleteProof(
                "unprojected Ref-CAS commits exist past PostgreSQL ref_cas_projection_cursors",
            ));
        }
        if self.sm_applied_event_seq == 0 {
            if self.pg_projected_log_index != 0 || self.pg_projected_log_term != 0 {
                return Err(SafeGcError::IncompleteProof(
                    "non-zero PG projected log cursor disagrees with zero Ref-CAS event frontier",
                ));
            }
        } else if self.pg_projected_log_index != self.sm_last_event_log_index
            || self.pg_projected_log_term != self.sm_last_event_log_term
            || self.sm_last_event_log_index > self.sm_applied_log_index
        {
            return Err(SafeGcError::IncompleteProof(
                "PG ref_cas_projection_cursors log (term, index) disagrees with Ref-CAS event frontier",
            ));
        }
        Ok(())
    }

    pub(crate) fn encode_canonical(&self, h: &mut Sha256) {
        h.update(b"refcas-cut-v1|");
        h.update(self.group_id.to_be_bytes());
        h.update(self.group_epoch.to_be_bytes());
        h.update(self.history_id.as_bytes());
        h.update(self.sm_applied_log_term.to_be_bytes());
        h.update(self.sm_applied_log_index.to_be_bytes());
        h.update(self.sm_applied_event_seq.to_be_bytes());
        h.update(self.sm_last_event_log_term.to_be_bytes());
        h.update(self.sm_last_event_log_index.to_be_bytes());
        encode_len_bytes(h, self.sm_snapshot_checksum.as_bytes());
        h.update(self.pg_projected_log_term.to_be_bytes());
        h.update(self.pg_projected_log_index.to_be_bytes());
        h.update(self.pg_projected_event_seq.to_be_bytes());
        h.update(self.unprojected_jobs_count.to_be_bytes());
    }
}

/// Reconcile an authoritative `RefCasStateMachine` snapshot against PostgreSQL
/// migration-149 `ref_cas_projection_cursors` and `ref_cas_projection_jobs`.
pub async fn reconcile_refcas_cut_with_pg<C: GenericClient + Sync>(
    client: &C,
    sm: &RefCasStateMachine,
    repo_id: Uuid,
    group_id: i64,
    authority: &DurableSafeGcAuthority,
) -> Result<RefCasReconciledCut, SafeGcError> {
    let sm_snap = sm.snapshot().map_err(|_| SafeGcError::IncompleteProof("refcas snapshot seal failed"))?;
    sm_snap.verify_integrity().map_err(|_| SafeGcError::IncompleteProof("refcas snapshot integrity failed"))?;

    let snap_before = authority.snapshot();
    let gate = sm_snap
        .body
        .gates
        .iter()
        .find(|g| g.repository_id == repo_id)
        .ok_or(SafeGcError::IncompleteProof("refcas repository gate not initialized"))?;
    if gate.tenant_id != snap_before.authority.tenant_id
        || gate.history_incarnation != snap_before.authority.history_id
        || gate.authority_epoch <= 0
        || gate.authority_epoch as u64 != snap_before.authority.incarnation_epoch
        || gate.group_epoch <= 0
    {
        return Err(SafeGcError::IncompleteProof("refcas gate realm/epoch disagrees with safe_gc authority"));
    }
    let last_applied =
        sm_snap.body.last_applied.ok_or(SafeGcError::IncompleteProof("refcas has no applied log entries"))?;
    let last_event_seq = sm_snap.body.events.last().map(|ev| ev.event_seq).unwrap_or(0);
    let sm_applied_event_seq = last_event_seq.max(sm_snap.body.next_event_seq);
    let (sm_last_event_log_term, sm_last_event_log_index) =
        sm_snap.body.events.last().map_or((0, 0), |ev| (ev.log_term, ev.log_index));

    let cursor = load_cursor(client, group_id, gate.history_incarnation)
        .await
        .map_err(|_| SafeGcError::IncompleteProof("failed reading ref_cas_projection_cursors"))?
        .ok_or(SafeGcError::IncompleteProof(
            "ref_cas_projection_cursors row missing; PG ref sequence cannot prove Ref-CAS cut",
        ))?;
    if cursor.stream_state != ProjectionStreamState::Active {
        return Err(SafeGcError::IncompleteProof("ref_cas_projection_cursors stream requires resync"));
    }
    if cursor.realm.group_epoch != gate.group_epoch {
        return Err(SafeGcError::IncompleteProof("ref_cas_projection_cursors group_epoch != Ref-CAS gate"));
    }

    let unresolved_jobs_i64: i64 = client
        .query_one(
            "SELECT count(*) FROM ref_cas_projection_jobs \
             WHERE repository_id = $1 AND state IN ('queued','running','unknown_hold','failed')",
            &[&repo_id],
        )
        .await
        .map_err(|e| SafeGcError::Io(format!("read ref_cas_projection_jobs failed: {e}")))?
        .get(0);

    let group_epoch_u64 = gate.group_epoch as u64;
    let cut = RefCasReconciledCut {
        group_id,
        group_epoch: group_epoch_u64,
        history_id: gate.history_incarnation,
        sm_applied_log_term: last_applied.term,
        sm_applied_log_index: last_applied.index,
        sm_applied_event_seq,
        sm_last_event_log_term,
        sm_last_event_log_index,
        sm_snapshot_checksum: sm_snap.checksum,
        pg_projected_log_term: cursor.applied_log_term,
        pg_projected_log_index: cursor.applied_log_index,
        pg_projected_event_seq: cursor.applied_event_seq,
        unprojected_jobs_count: unresolved_jobs_i64.max(0) as u64,
    };
    cut.verify_reconciled(gate.history_incarnation, last_applied.index, group_epoch_u64)?;

    let live_refs: Vec<LiveRefRoot> = sm
        .read_refs(repo_id)
        .into_iter()
        .map(|(ref_name, target_oid)| LiveRefRoot { ref_name, target_oid, version_seq: last_applied.index.max(1) })
        .collect();

    let active_snap_ids: BTreeSet<Uuid> = sm_snap
        .body
        .pins
        .iter()
        .filter(|p| p.repository_id == repo_id && p.state == SmPinState::Active)
        .map(|p| p.snapshot_id)
        .collect();
    let mut sm_pin_oids = BTreeSet::new();
    for srec in &sm_snap.body.snapshots {
        if srec.repository_id == repo_id && active_snap_ids.contains(&srec.snapshot_id) {
            if let Some(ref h) = srec.head_oid {
                sm_pin_oids.insert(h.clone());
            }
            sm_pin_oids.extend(srec.refs.values().cloned());
        }
    }

    let sm_holds: Vec<GlobalHoldEntry> = sm_snap
        .body
        .holds
        .iter()
        .filter(|h| h.repository_id == repo_id && h.state == SmHoldState::Active)
        .map(|h| GlobalHoldEntry {
            hold_id: h.hold_id,
            tenant_id: h.tenant_id,
            repo_id,
            incarnation_epoch: snap_before.authority.incarnation_epoch,
            registered_seq: last_applied.index.max(1),
            state: GlobalHoldState::Active,
            protected_pack_ids: Vec::new(),
            protected_oids: Vec::new(),
            protected_physical_keys: Vec::new(),
        })
        .collect();

    let sm_decisions: Vec<InFlightDecisionRecord> = sm_snap
        .body
        .decisions
        .iter()
        .filter(|d| d.repository_id == repo_id && d.state == SmDecisionState::Open)
        .map(|d| InFlightDecisionRecord {
            decision_id: d.decision_id,
            kind: match d.kind {
                WireDecisionKind::Atomic => DecisionKind::Push,
                WireDecisionKind::AcceptedSubset => DecisionKind::Push,
            },
            state: DecisionState::Pending,
            snapshot_seq: last_applied.index.max(1),
            protected_pack_ids: Vec::new(),
            protected_oids: Vec::new(),
        })
        .collect();

    authority.apply_refcas_reconciled_cut(
        live_refs,
        sm_pin_oids.into_iter().collect(),
        sm_holds,
        sm_decisions,
        cut.clone(),
    )?;
    Ok(cut)
}
