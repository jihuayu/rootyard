//! Reconciliation helpers binding PostgreSQL 17 and Ref-CAS state into `DurableSafeGcAuthority`.

use std::collections::BTreeMap;

use uuid::Uuid;

use super::{
    SafeGcError,
    model::{
        GlobalHoldEntry, InFlightDecisionRecord, LiveRefRoot, PairedCursorReconciliation, ProducerReconciliationEntry,
        SourceFreshness,
    },
    quiescence::ActiveReaderLease,
    store::DurableSafeGcAuthority,
};

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

    pub(super) fn apply_pg_reconciled_bundle(&self, bundle: PgReconciledBundle) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            s.live_refs = bundle.live_refs;
            s.authority.live_ref_seq = bundle.max_ref_seq.max(s.authority.live_ref_seq);
            s.producers = bundle.producers;
            s.paired_cursors = bundle.cursors;
            for hold in bundle.sql_holds {
                if let Some(slot) = s.global_holds.iter_mut().find(|h| h.hold_id == hold.hold_id) {
                    *slot = hold;
                } else {
                    s.global_holds.push(hold);
                }
            }
            let mut merged_decisions: BTreeMap<Uuid, InFlightDecisionRecord> =
                s.in_flight_decisions.iter().cloned().map(|d| (d.decision_id, d)).collect();
            for dec in bundle.sql_decisions {
                merged_decisions.insert(dec.decision_id, dec);
            }
            s.in_flight_decisions = merged_decisions.into_values().collect();

            // Replace transient PG serving-read pin leases while keeping explicit in-process reader leases.
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
