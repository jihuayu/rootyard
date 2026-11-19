//! Reconciliation helpers binding PostgreSQL 17 and Ref-CAS state into `DurableSafeGcAuthority`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    SafeGcError,
    model::{
        AuthorityLane, GcMode, GlobalHoldEntry, InFlightDecisionRecord, LiveRefRoot, PairedCursorReconciliation,
        ProducerReconciliationEntry, RetentionProducer, SafeGcArmReceipt, SourceFreshness,
    },
    proof::verify_deletion_proof,
    proof_digest::compute_proof_digest,
    quiescence::ActiveReaderLease,
    refcas_cut::RefCasReconciledCut,
    store::DurableSafeGcAuthority,
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciledSourceTracker {
    #[serde(default)]
    pub sql_hold_ids: BTreeSet<Uuid>,
    #[serde(default)]
    pub sql_decision_ids: BTreeSet<Uuid>,
    #[serde(default)]
    pub sm_hold_ids: BTreeSet<Uuid>,
    #[serde(default)]
    pub sm_decision_ids: BTreeSet<Uuid>,
    #[serde(default)]
    pub sm_pin_oids: BTreeSet<String>,
}

fn replace_reconciled_holds(
    target: &mut Vec<GlobalHoldEntry>,
    prev_source_ids: &mut BTreeSet<Uuid>,
    other_source_ids: &BTreeSet<Uuid>,
    incoming: Vec<GlobalHoldEntry>,
) {
    let next_ids: BTreeSet<Uuid> = incoming.iter().map(|h| h.hold_id).collect();
    target.retain(|h| {
        !prev_source_ids.contains(&h.hold_id) || next_ids.contains(&h.hold_id) || other_source_ids.contains(&h.hold_id)
    });
    for hold in incoming {
        if let Some(slot) = target.iter_mut().find(|h| h.hold_id == hold.hold_id) {
            *slot = hold;
        } else {
            target.push(hold);
        }
    }
    *prev_source_ids = next_ids;
}

fn replace_reconciled_decisions(
    target: &mut Vec<InFlightDecisionRecord>,
    prev_source_ids: &mut BTreeSet<Uuid>,
    other_source_ids: &BTreeSet<Uuid>,
    incoming: Vec<InFlightDecisionRecord>,
) {
    let next_ids: BTreeSet<Uuid> = incoming.iter().map(|d| d.decision_id).collect();
    let mut map: BTreeMap<Uuid, InFlightDecisionRecord> = target
        .drain(..)
        .filter(|d| {
            !prev_source_ids.contains(&d.decision_id)
                || next_ids.contains(&d.decision_id)
                || other_source_ids.contains(&d.decision_id)
        })
        .map(|d| (d.decision_id, d))
        .collect();
    for dec in incoming {
        map.insert(dec.decision_id, dec);
    }
    *target = map.into_values().collect();
    *prev_source_ids = next_ids;
}

impl DurableSafeGcAuthority {
    pub(super) fn apply_refcas_quorum_refs(
        &self,
        live_refs: Vec<LiveRefRoot>,
        raft_commit_index: u64,
    ) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            s.live_refs = live_refs;
            s.authority.live_ref_seq = s.authority.live_ref_seq.max(raft_commit_index);
            s.paired_cursors.refcas_freshness = SourceFreshness::Reconciled;
            s.paired_cursors.refcas_applied_index = s.paired_cursors.refcas_applied_index.max(raft_commit_index);
            s.paired_cursors.refcas_required_index = s.paired_cursors.refcas_required_index.max(raft_commit_index);
            s.push_audit("reconcile_refcas_quorum", &raft_commit_index.to_string());
            Ok(())
        })
    }

    pub(super) fn apply_refcas_reconciled_cut(
        &self,
        live_refs: Vec<LiveRefRoot>,
        sm_pin_oids: Vec<String>,
        sm_holds: Vec<GlobalHoldEntry>,
        sm_decisions: Vec<InFlightDecisionRecord>,
        cut: RefCasReconciledCut,
    ) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            s.live_refs = live_refs;
            s.authority.live_ref_seq = cut.sm_applied_log_index.max(1);
            s.paired_cursors.pg_applied_seq = s.paired_cursors.pg_applied_seq.max(cut.sm_applied_log_index.max(1));
            let next_pins: BTreeSet<String> = sm_pin_oids.into_iter().collect();
            for prod in &mut s.producers {
                if prod.producer == RetentionProducer::Workspace {
                    let mut merged: BTreeSet<String> = prod
                        .root_oids
                        .iter()
                        .filter(|o| !s.reconciled_sources.sm_pin_oids.contains(*o))
                        .cloned()
                        .collect();
                    merged.extend(next_pins.iter().cloned());
                    prod.root_oids = merged.into_iter().collect();
                }
            }
            s.reconciled_sources.sm_pin_oids = next_pins;
            let other_holds = s.reconciled_sources.sql_hold_ids.clone();
            replace_reconciled_holds(
                &mut s.global_holds,
                &mut s.reconciled_sources.sm_hold_ids,
                &other_holds,
                sm_holds,
            );
            let other_decs = s.reconciled_sources.sql_decision_ids.clone();
            replace_reconciled_decisions(
                &mut s.in_flight_decisions,
                &mut s.reconciled_sources.sm_decision_ids,
                &other_decs,
                sm_decisions,
            );
            s.paired_cursors.refcas_freshness = SourceFreshness::Reconciled;
            s.paired_cursors.refcas_applied_index = cut.sm_applied_log_index;
            s.paired_cursors.refcas_required_index = cut.sm_applied_log_index;
            s.paired_cursors.refcas_cut = Some(cut.clone());
            s.push_audit("reconcile_refcas_cut", &cut.sm_applied_log_index.to_string());
            Ok(())
        })
    }

    pub(super) fn apply_pg_reconciled_bundle(&self, bundle: PgReconciledBundle) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            s.live_refs = bundle.live_refs;
            s.authority.live_ref_seq = bundle.max_ref_seq.max(s.authority.live_ref_seq);
            s.producers = bundle.producers;
            s.paired_cursors = bundle.cursors;
            let other_holds = s.reconciled_sources.sm_hold_ids.clone();
            replace_reconciled_holds(
                &mut s.global_holds,
                &mut s.reconciled_sources.sql_hold_ids,
                &other_holds,
                bundle.sql_holds,
            );
            let other_decs = s.reconciled_sources.sm_decision_ids.clone();
            replace_reconciled_decisions(
                &mut s.in_flight_decisions,
                &mut s.reconciled_sources.sql_decision_ids,
                &other_decs,
                bundle.sql_decisions,
            );

            s.reader_leases.active_leases.retain(|_, l| l.reader_label != "pg_serving_read_pin");
            for lease in bundle.transient_reads {
                s.reader_leases.active_leases.insert(lease.lease_id, lease);
            }
            if let Some(epoch) = bundle.pg_gc_fence_epoch {
                s.reader_leases.set_pg_exclusive_barrier_epoch(Some(epoch));
            }
            s.reader_leases.refresh_drain_watermark(s.authority.membership_generation);
            s.refresh_group_receipts_quiescence()?;
            s.push_audit("reconcile_pg_refstore", &s.authority.live_ref_seq.to_string());
            Ok(())
        })
    }

    /// Re-bind an in-flight pending delete batch (SingleNodePg or DistributedRefCas)
    /// to a freshly acquired live PostgreSQL `gc_epoch` fence after restart ONLY if
    /// incarnation, lease_epoch, lane kind, and all live retention/quiescence
    /// invariants still hold.
    pub fn rebind_pending_delete_live_pg_fence(
        &self,
        fence_epoch: u64,
        live_arm: SafeGcArmReceipt,
    ) -> Result<(), SafeGcError> {
        live_arm.validate()?;
        self.update_persisted(|s| {
            if fence_epoch == 0 {
                return Err(SafeGcError::StaleDeleterFenced("SingleNodePg recovery requires non-zero fence_epoch"));
            }
            if live_arm.arm_pubkey_hex != s.authority.trusted_arm_pubkey_hex {
                return Err(SafeGcError::ArmingRejected(
                    "arm receipt Ed25519 public key not trusted by repository authority",
                ));
            }
            s.reader_leases.set_pg_exclusive_barrier_epoch(Some(fence_epoch));
            s.refresh_group_receipts_quiescence()?;
            s.gc_mode = GcMode::ArmedDestructive(live_arm.clone());
            let Some(ref batch_existing) = s.pending_delete else {
                return Ok(());
            };
            if batch_existing.incarnation_epoch != s.authority.incarnation_epoch
                || batch_existing.incarnation_id != s.authority.incarnation_id
            {
                // Stale-incarnation batch: keep it unmodified so restart reconciliation aborts & rolls it back.
                return Ok(());
            }
            if batch_existing.lease_epoch != s.authority.lease_epoch {
                return Err(SafeGcError::StaleDeleterFenced(
                    "pending delete batch lease_epoch != live authority lease_epoch on PG recovery",
                ));
            }
            let mut updated_proof = batch_existing.proof.clone();
            let same_lane_kind = matches!(
                (&updated_proof.lane, &live_arm.lane),
                (AuthorityLane::SingleNodePg { .. }, AuthorityLane::SingleNodePg { .. })
                    | (AuthorityLane::DistributedRefCas { .. }, AuthorityLane::DistributedRefCas { .. })
            );
            if !same_lane_kind {
                return Err(SafeGcError::IncompleteProof(
                    "pending delete batch authority lane kind changed across restart",
                ));
            }
            updated_proof.lane = live_arm.lane;
            updated_proof.live_ref_seq = s.authority.live_ref_seq;
            updated_proof.live_refs = s.live_refs.clone();
            updated_proof.producers = s.producers.clone();
            updated_proof.global_holds = s.global_holds.clone();
            updated_proof.in_flight_decisions = s.in_flight_decisions.clone();
            updated_proof.reader_quiescence.pg_exclusive_reader_barrier_epoch = Some(fence_epoch);
            updated_proof.group_receipts = s.group_receipts.clone();
            updated_proof.paired_cursors = s.paired_cursors.clone();
            updated_proof.proof_digest = compute_proof_digest(&updated_proof);
            verify_deletion_proof(&updated_proof)?;
            s.require_live_barrier(
                s.authority.incarnation_id,
                s.authority.incarnation_epoch,
                s.authority.lease_epoch,
                &updated_proof,
            )?;
            if let Some(batch_mut) = s.pending_delete.as_mut() {
                batch_mut.proof = updated_proof;
            }
            s.push_audit("rebind_pending_delete_pg_fence", &fence_epoch.to_string());
            Ok(())
        })
    }
}

pub(super) struct PgReconciledBundle {
    pub live_refs: Vec<LiveRefRoot>,
    pub max_ref_seq: u64,
    pub producers: Vec<ProducerReconciliationEntry>,
    pub cursors: PairedCursorReconciliation,
    pub sql_holds: Vec<GlobalHoldEntry>,
    pub sql_decisions: Vec<InFlightDecisionRecord>,
    pub transient_reads: Vec<ActiveReaderLease>,
    pub pg_gc_fence_epoch: Option<u64>,
}
