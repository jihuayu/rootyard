//! Bridge from Safe-GC inputs to `#184` (`PR #288`) `RetentionClassificationIndex` (#122).
//!
//! Ensures every destructive `DeletionProof` candidate is independently evaluated
//! through `crate::ref_store::ref_version::pack_cover::RetentionClassificationIndex`
//! and achieves `PackRetentionState::GcEligible` (`gc_eligible == true`,
//! `active_protectors.is_empty()`), while non-authoritative TTL, cache-eviction,
//! and async-projection hints remain strictly ignored.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::{ref_version::VersionId, types::RefName};
use crate::ref_store::ref_version::pack_cover::{
    CoverRetentionHold, NonAuthoritativeHint, PackRetentionClassification, PackRetentionState, PhysicalBlobStatus,
    RetentionClassificationIndex,
};

use super::{
    SafeGcError,
    model::{
        AuthorityLane, DecisionState, GlobalHoldEntry, GlobalHoldState, GroupClosureReceipt, InFlightDecisionRecord,
        LiveRefRoot, PairedCursorReconciliation, ProducerReconciliationEntry, RetentionProducer, SourceFreshness,
    },
    quiescence::{ActiveReaderLease, ReaderQuiescenceObservation},
};

pub struct PackCoverBridgeInputs<'a> {
    pub incarnation_epoch: u64,
    pub lane: &'a AuthorityLane,
    pub live_refs: &'a [LiveRefRoot],
    pub producers: &'a [ProducerReconciliationEntry],
    pub global_holds: &'a [GlobalHoldEntry],
    pub in_flight_decisions: &'a [InFlightDecisionRecord],
    pub paired_cursors: &'a PairedCursorReconciliation,
    pub group_receipts: &'a [GroupClosureReceipt],
    pub reader_quiescence: &'a ReaderQuiescenceObservation,
    pub active_reader_leases: &'a [ActiveReaderLease],
    pub tombstoned_pack_ids: &'a BTreeSet<Uuid>,
}

fn oid_version_id(oid: &str) -> VersionId {
    let digest = Sha256::digest(oid.as_bytes());
    let mut raw = [0_u8; 8];
    raw.copy_from_slice(&digest[..8]);
    let seq = i64::from_be_bytes(raw).unsigned_abs().max(1) as i64;
    VersionId::new(seq.min(i64::MAX - 1).max(1)).expect("positive VersionId")
}

pub fn build_pack_cover_retention_index(inputs: &PackCoverBridgeInputs<'_>) -> RetentionClassificationIndex {
    let mut index = RetentionClassificationIndex::new();
    // Explicitly attach non-authoritative hints to prove #288 ignores TTL/cache/async lag.
    index.add_non_authoritative_hint(NonAuthoritativeHint::TtlExpired { age_seconds: 86_400 });
    index.add_non_authoritative_hint(NonAuthoritativeHint::CacheEvicted { cache_key: "local-pack-cache".into() });
    index.add_non_authoritative_hint(NonAuthoritativeHint::AsyncProjectionMissingOrStale { projection_lag: 0 });

    for &gone in inputs.tombstoned_pack_ids {
        index.set_physical_status(gone, PhysicalBlobStatus::PhysicallyDeletedByGc { gc_issue: "#122" });
    }

    for r in inputs.live_refs {
        if let Ok(ref_name) = RefName::new(r.ref_name.clone()) {
            index.add_hold(CoverRetentionHold::ActiveRefHead {
                ref_name,
                version_id: oid_version_id(&r.target_oid),
                cover_ids: Vec::new(),
            });
        }
    }

    for p in inputs.producers {
        let versions: Vec<VersionId> = p.root_oids.iter().map(|o| oid_version_id(o)).collect();
        let covers = p.pinned_pack_ids.clone();
        if versions.is_empty() && covers.is_empty() {
            continue;
        }
        let id = Uuid::from_u128(0x1220_0000_u128 + (p.producer as u128));
        match p.producer {
            RetentionProducer::Backup => index.add_hold(CoverRetentionHold::BackupManifest {
                manifest_id: id,
                version_ids: versions,
                cover_ids: covers,
                retained: true,
            }),
            RetentionProducer::CiPin => index.add_hold(CoverRetentionHold::CiCloneKitPin {
                job_id: id,
                version_ids: versions,
                cover_ids: covers,
                revoked: false,
            }),
            RetentionProducer::Workspace => index.add_hold(CoverRetentionHold::SnapshotPin {
                pin_id: id,
                version_ids: versions,
                cover_ids: covers,
                released: false,
            }),
            RetentionProducer::PullRequest | RetentionProducer::Namespace | RetentionProducer::Lfs => {
                index.add_hold(CoverRetentionHold::RetentionRoot {
                    root_id: id,
                    version_ids: versions,
                    cover_ids: covers,
                    released: false,
                });
            }
        }
    }

    for h in inputs.global_holds {
        match h.state {
            GlobalHoldState::Active => {
                index.add_hold(CoverRetentionHold::RetentionRoot {
                    root_id: h.hold_id,
                    version_ids: h.protected_oids.iter().map(|o| oid_version_id(o)).collect(),
                    cover_ids: h.protected_pack_ids.clone(),
                    released: false,
                });
            }
            GlobalHoldState::Unknown => {
                index.add_hold(CoverRetentionHold::QuarantineHold {
                    incident_id: h.hold_id,
                    pack_ids: h.protected_pack_ids.clone(),
                    cover_ids: h.protected_pack_ids.clone(),
                    cleared: false,
                });
            }
            GlobalHoldState::Released { .. } => {}
        }
    }

    for d in inputs.in_flight_decisions {
        if matches!(d.state, DecisionState::Pending | DecisionState::Unknown) {
            index.add_hold(CoverRetentionHold::PendingOrUnknownOperation {
                operation_id: d.decision_id,
                target_versions: d.protected_oids.iter().map(|o| oid_version_id(o)).collect(),
                staged_pack_ids: d.protected_pack_ids.clone(),
                protected_cover_ids: d.protected_pack_ids.clone(),
                age_seconds: 3_600,
                resolved: false,
            });
        }
    }

    for lease in inputs.active_reader_leases {
        if !lease.pinned_pack_ids.is_empty() {
            index.add_hold(CoverRetentionHold::HistoricalCoverHold {
                hold_id: lease.lease_id,
                cover_ids: lease.pinned_pack_ids.clone(),
                version_ids: Vec::new(),
                active_readers: 1,
                released: false,
            });
        }
    }

    let require_pg_barrier = matches!(inputs.lane, AuthorityLane::SingleNodePg { .. });
    let mut retired_covers = BTreeSet::new();
    for (idx, gr) in inputs.group_receipts.iter().enumerate() {
        let drained = gr.reader_quiescence.is_quiesced(require_pg_barrier);
        index.add_hold(CoverRetentionHold::CompactionInputHold {
            repack_operation_id: Uuid::from_u128(0x9900_0000_u128 + idx as u128),
            input_cover_ids: gr.retired_pack_ids.clone(),
            compacted_committed: gr.replacement_closure_verified && !gr.replacement_pack_ids.is_empty(),
            readers_drained: drained,
        });
        if gr.replacement_closure_verified && !gr.replacement_pack_ids.is_empty() && drained {
            retired_covers.extend(gr.retired_pack_ids.iter().copied());
        }
    }

    let producers_complete = inputs.producers.len() == RetentionProducer::ALL.len()
        && inputs.producers.iter().all(|p| {
            p.freshness == SourceFreshness::Reconciled
                && p.observed_cursor_seq >= p.required_cursor_seq
                && p.authority_epoch == p.expected_authority_epoch
                && p.expected_authority_epoch >= inputs.incarnation_epoch
        });
    let cursors_complete = inputs.paired_cursors.pg_freshness == SourceFreshness::Reconciled
        && inputs.paired_cursors.pg_applied_seq >= inputs.paired_cursors.pg_required_seq
        && inputs.paired_cursors.refcas_freshness == SourceFreshness::Reconciled
        && inputs.paired_cursors.refcas_applied_index >= inputs.paired_cursors.refcas_required_index;
    let quiescence_complete = inputs.reader_quiescence.is_quiesced(require_pg_barrier);

    index.set_authority_snapshot(
        inputs.incarnation_epoch,
        producers_complete && cursors_complete && quiescence_complete,
        retired_covers,
    );
    index
}

pub fn require_pack_cover_gc_eligible(
    index: &RetentionClassificationIndex,
    pack_id: Uuid,
    contained_oids: &[String],
) -> Result<PackRetentionClassification, SafeGcError> {
    let covered_versions: Vec<VersionId> = contained_oids.iter().map(|o| oid_version_id(o)).collect();
    // Each pack acts as its own cover unit (`cover_id == pack_id`) in #122 safe_gc.
    let verdict = index.classify_pack(pack_id, pack_id, &covered_versions);
    if verdict.state != Some(PackRetentionState::GcEligible)
        || !verdict.gc_eligible
        || !verdict.active_protectors.is_empty()
    {
        return Err(SafeGcError::ProtectionOverlap(format!(
            "#184 pack_cover retention refused GC for pack {pack_id} (state={:?}, protectors={:?})",
            verdict.state, verdict.active_protectors
        )));
    }
    Ok(verdict)
}
