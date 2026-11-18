//! Unit tests for Safe GC default-off gates, unified DeletionProof, #288 retention & anti-ABA (#122).

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::ref_version::pack_cover::PackRetentionState;

use super::{
    SafeGcError,
    anti_aba::{AntiAbaKeyRegistry, KeyLifecycleState, PhysicalBlobKey},
    domain::{
        ActiveDeleteFence, AuthorityRecord, BlobLocatorRecord, DeleteAuthorizationTicket, ProviderDeleteOutcome,
        RemotePresence, SafeGcDeleteBackend, SafeGcFuture,
    },
    executor::{DeleteFaultHook, SafeGcSweepRequest, execute_safe_gc_sweep},
    model::{
        AuthorityLane, CandidatePackTarget, GcMode, GroupClosureReceipt, LiveRefRoot, PairedCursorReconciliation,
        ProducerReconciliationEntry, RetentionProducer, SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT, SAFE_GC_SCHEMA_VERSION,
        SafeGcArmReceipt, SafeGcObjectFormat, SourceFreshness,
    },
    proof::{DeletionProofInputs, build_and_verify_deletion_proof, seal_group_receipt, verify_deletion_proof},
    quiescence::{ReaderLeaseRegistry, ReaderQuiescenceObservation},
    refcas_cut::RefCasReconciledCut,
    store::{DurableSafeGcAuthority, SafeGcRepoSnapshot, ServingPackRecord},
};

#[derive(Default)]
pub(super) struct RecordingDeleteBackend {
    pub(super) deleted: Mutex<Vec<String>>,
    pub(super) fail_key: Mutex<Option<String>>,
    pub(super) unknown_key: Mutex<Option<String>>,
    pub(super) already_absent: Mutex<BTreeSet<String>>,
}

impl SafeGcDeleteBackend for RecordingDeleteBackend {
    fn delete_authorized<'a>(
        &'a self,
        fence: &'a ActiveDeleteFence<'a>,
        ticket: &'a DeleteAuthorizationTicket,
        _deadline: Instant,
    ) -> SafeGcFuture<'a, ProviderDeleteOutcome> {
        Box::pin(async move {
            fence.verify_active_for_ticket(ticket)?;
            let path = ticket.physical_key().to_owned();
            if self.already_absent.lock().unwrap().contains(&path) {
                return Ok(ProviderDeleteOutcome::AlreadyAbsent);
            }
            if self.unknown_key.lock().unwrap().as_deref() == Some(path.as_str()) {
                return Ok(ProviderDeleteOutcome::OutcomeUnknown { reason: "simulated 503 timeout".into() });
            }
            if self.fail_key.lock().unwrap().as_deref() == Some(path.as_str()) {
                return Err(SafeGcError::Io("injected backend delete failure".into()));
            }
            self.deleted.lock().unwrap().push(path);
            Ok(ProviderDeleteOutcome::ConfirmedDeleted)
        })
    }

    fn probe_presence<'a>(
        &'a self,
        locator: &'a BlobLocatorRecord,
        _deadline: Instant,
    ) -> SafeGcFuture<'a, RemotePresence> {
        Box::pin(async move {
            let absent = self.already_absent.lock().unwrap().iter().any(|k| k.ends_with(&locator.sha256));
            if absent {
                Ok(RemotePresence::Absent)
            } else {
                Ok(RemotePresence::Present { content_length: locator.length })
            }
        })
    }
}

pub(super) fn oid(fmt: SafeGcObjectFormat, tag: u8) -> String {
    let mut raw = [0_u8; 32];
    raw[0] = tag.max(1);
    raw[19] = tag.wrapping_add(0x41);
    let hexed = hex::encode(raw);
    hexed[..fmt.oid_hex_len()].to_owned()
}

pub(super) fn sha(tag: &str) -> String {
    hex::encode(Sha256::digest(tag.as_bytes()))
}

pub(super) fn make_pack_record(
    auth: &AuthorityRecord,
    seq: u64,
    group_id: &str,
    tag: &str,
    state: KeyLifecycleState,
    contained_oids: Vec<String>,
) -> (ServingPackRecord, Vec<CandidatePackTarget>) {
    let psha = sha(&format!("pack-{tag}"));
    let isha = sha(&format!("idx-{tag}"));
    let (p_nonce, i_nonce) = (Uuid::new_v4(), Uuid::new_v4());
    let scope = (auth.tenant_id, auth.repo_id, auth.history_id, auth.incarnation_epoch);
    let p_path = PhysicalBlobKey::canonical_path(scope, seq, p_nonce, "pack", &psha);
    let i_path = PhysicalBlobKey::canonical_path(scope, seq + 1, i_nonce, "idx", &isha);
    let pack_key = PhysicalBlobKey {
        schema_version: SAFE_GC_SCHEMA_VERSION,
        tenant_id: auth.tenant_id,
        repo_id: auth.repo_id,
        history_id: auth.history_id,
        incarnation_epoch: auth.incarnation_epoch,
        allocation_seq: seq,
        nonce: p_nonce,
        role: "pack".into(),
        object_sha256: psha.clone(),
        object_path: p_path.clone(),
        state,
    };
    let idx_key = PhysicalBlobKey {
        schema_version: SAFE_GC_SCHEMA_VERSION,
        tenant_id: auth.tenant_id,
        repo_id: auth.repo_id,
        history_id: auth.history_id,
        incarnation_epoch: auth.incarnation_epoch,
        allocation_seq: seq + 1,
        nonce: i_nonce,
        role: "idx".into(),
        object_sha256: isha.clone(),
        object_path: i_path.clone(),
        state,
    };
    let pack_id = Uuid::new_v4();
    let blob_gen = auth.membership_generation as i64;
    let p_etag = format!("\"{}\"", &psha[..32]);
    let i_etag = format!("\"{}\"", &isha[..32]);
    let p_vid = Some(format!("v1-{seq}"));
    let i_vid = Some(format!("v1-{}", seq + 1));
    let pack_loc = BlobLocatorRecord {
        tenant_id: auth.tenant_id,
        authority_id: auth.repo_id,
        generation: blob_gen,
        attempt_id: Uuid::new_v4(),
        namespace: "packs".into(),
        sha256: psha.clone(),
        length: 512,
        remote_etag: p_etag.clone(),
        remote_version_id: p_vid.clone(),
    };
    let idx_loc = BlobLocatorRecord {
        sha256: isha.clone(),
        attempt_id: Uuid::new_v4(),
        remote_etag: i_etag.clone(),
        remote_version_id: i_vid.clone(),
        ..pack_loc.clone()
    };
    let rec = ServingPackRecord {
        pack_id,
        group_id: group_id.into(),
        pack_key,
        idx_key,
        pack_locator: pack_loc,
        idx_locator: idx_loc,
        contained_oids: contained_oids.clone(),
    };
    let cands = vec![
        CandidatePackTarget {
            pack_id,
            key_role: "pack".into(),
            group_id: group_id.into(),
            physical_key: p_path,
            object_sha256: psha,
            remote_etag: p_etag,
            remote_version_id: p_vid,
            provider_generation: blob_gen,
            key_epoch: auth.incarnation_epoch,
            retention_state: PackRetentionState::GcEligible,
            contained_oids: contained_oids.clone(),
        },
        CandidatePackTarget {
            pack_id,
            key_role: "idx".into(),
            group_id: group_id.into(),
            physical_key: i_path,
            object_sha256: isha,
            remote_etag: i_etag,
            remote_version_id: i_vid,
            provider_generation: blob_gen,
            key_epoch: auth.incarnation_epoch,
            retention_state: PackRetentionState::GcEligible,
            contained_oids,
        },
    ];
    (rec, cands)
}

pub(super) fn reconciled_producers(epoch: u64, seq: u64, ci_pin_oid: String) -> Vec<ProducerReconciliationEntry> {
    RetentionProducer::ALL
        .iter()
        .map(|&producer| ProducerReconciliationEntry {
            producer,
            freshness: SourceFreshness::Reconciled,
            observed_cursor_seq: seq,
            required_cursor_seq: seq,
            authority_epoch: epoch,
            expected_authority_epoch: epoch,
            root_oids: if producer == RetentionProducer::CiPin { vec![ci_pin_oid.clone()] } else { vec![] },
            pinned_pack_ids: vec![],
        })
        .collect()
}

pub(super) fn seed_fixture(
    fmt: SafeGcObjectFormat,
    distributed: bool,
) -> (SafeGcRepoSnapshot, SafeGcArmReceipt, super::proof::DeletionProof) {
    let auth = AuthorityRecord {
        tenant_id: Uuid::new_v4(),
        repo_id: Uuid::new_v4(),
        history_id: Uuid::new_v4(),
        incarnation_id: Uuid::new_v4(),
        incarnation_epoch: 1,
        membership_generation: 2,
        live_ref_seq: 10,
        lease_epoch: 1,
    };
    let (live_oid, pin_oid, dead_oid) = (oid(fmt, 1), oid(fmt, 2), oid(fmt, 9));
    let (active_rec, _) = make_pack_record(
        &auth,
        1,
        "g1",
        "active",
        KeyLifecycleState::ActiveServing,
        vec![live_oid.clone(), pin_oid.clone()],
    );
    let (retired_rec, cands) =
        make_pack_record(&auth, 3, "g1", "old", KeyLifecycleState::RetiredPendingProof, vec![dead_oid]);
    let mut reader_leases = ReaderLeaseRegistry::new();
    if !distributed {
        reader_leases.set_pg_exclusive_barrier_epoch(Some(1));
    }
    reader_leases.refresh_drain_watermark(2);
    let rq: ReaderQuiescenceObservation = reader_leases.observe_for_retirement(&[retired_rec.pack_id], 2, 2).unwrap();
    let gr = seal_group_receipt(GroupClosureReceipt {
        group_id: "g1".into(),
        epoch: 1,
        retired_at_generation: 2,
        retired_pack_ids: vec![retired_rec.pack_id],
        replacement_pack_ids: vec![active_rec.pack_id],
        replacement_oids: active_rec.contained_oids.clone(),
        replacement_closure_verified: true,
        reader_quiescence: rq.clone(),
        receipt_digest: String::new(),
    })
    .unwrap();
    let lane = if distributed {
        AuthorityLane::DistributedRefCas {
            ref_cas_authority_id: Uuid::new_v4(),
            quorum_epoch: 1,
            raft_commit_index: 10,
            quorum_verified: true,
            global_hold_bridge_verified: true,
            global_hold_bridge_seq: 10,
            remote_backup_root_verified: true,
            remote_backup_root_epoch: 1,
            async_projection_only: false,
        }
    } else {
        AuthorityLane::SingleNodePg {
            pg_authority_id: auth.repo_id,
            pg_tx_seq: 10,
            pg_gc_fence_epoch: 1,
            reader_barrier_epoch: 1,
        }
    };
    let arm = SafeGcArmReceipt::seal(
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        auth.incarnation_id,
        auth.incarnation_epoch,
        true,
        lane,
    )
    .unwrap();
    let live_refs = vec![LiveRefRoot { ref_name: "refs/heads/main".into(), target_oid: live_oid, version_seq: 10 }];
    let producers = reconciled_producers(1, 10, pin_oid);
    let refcas_cut = if distributed {
        Some(RefCasReconciledCut {
            group_id: 0,
            group_epoch: 1,
            history_id: auth.history_id,
            sm_applied_log_term: 1,
            sm_applied_log_index: 10,
            sm_applied_event_seq: 3,
            sm_last_event_log_term: 1,
            sm_last_event_log_index: 10,
            sm_snapshot_checksum: sha("sm-snapshot"),
            pg_projected_log_term: 1,
            pg_projected_log_index: 10,
            pg_projected_event_seq: 3,
            unprojected_jobs_count: 0,
        })
    } else {
        None
    };
    let paired_cursors = PairedCursorReconciliation {
        pg_freshness: SourceFreshness::Reconciled,
        pg_applied_seq: 10,
        pg_required_seq: 10,
        refcas_freshness: SourceFreshness::Reconciled,
        refcas_applied_index: if distributed { 10 } else { 0 },
        refcas_required_index: if distributed { 10 } else { 0 },
        refcas_cut,
    };
    let snap = SafeGcRepoSnapshot {
        authority: auth.clone(),
        object_format: fmt,
        gc_mode: GcMode::DisabledByDefault,
        live_refs: live_refs.clone(),
        active_packs: vec![active_rec],
        retired_packs: vec![retired_rec],
        group_receipts: vec![gr.clone()],
        producers: producers.clone(),
        global_holds: vec![],
        in_flight_decisions: vec![],
        paired_cursors: paired_cursors.clone(),
        reader_leases,
        staged_uploads: vec![],
        key_registry: AntiAbaKeyRegistry::new(),
        pending_delete: None,
        completed_batches: BTreeMap::new(),
        aborted_batches: BTreeMap::new(),
        reconciled_sources: Default::default(),
        audit_log: vec![],
    };
    let proof = build_and_verify_deletion_proof(DeletionProofInputs {
        tenant_id: auth.tenant_id,
        repo_id: auth.repo_id,
        history_id: auth.history_id,
        object_format: fmt,
        incarnation_id: auth.incarnation_id,
        incarnation_epoch: 1,
        membership_generation: 2,
        membership_digest: snap.compute_membership_digest(),
        live_ref_seq: 10,
        arm_receipt: arm.clone(),
        reader_quiescence: rq,
        live_refs,
        producers,
        global_holds: vec![],
        in_flight_decisions: vec![],
        paired_cursors,
        group_receipts: vec![gr],
        candidates: cands,
    })
    .unwrap();
    (snap, arm, proof)
}

#[tokio::test]
async fn default_off_gate_and_ttl_or_tampered_arming_fail_closed() {
    assert!(!std::hint::black_box(SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT));
    let (snap, mut arm, proof) = seed_fixture(SafeGcObjectFormat::Sha1, false);
    assert!(matches!(snap.gc_mode, GcMode::DisabledByDefault));
    let authority = DurableSafeGcAuthority::in_memory(snap).unwrap();
    let backend = Arc::new(RecordingDeleteBackend::default());
    let res = execute_safe_gc_sweep(
        &authority,
        backend.as_ref(),
        SafeGcSweepRequest {
            batch_id: Uuid::new_v4(),
            deleter_incarnation_id: authority.snapshot().authority.incarnation_id,
            deleter_incarnation_epoch: 1,
            deleter_lease_epoch: 1,
            proof,
            deadline: Instant::now() + Duration::from_secs(5),
            fault: DeleteFaultHook::None,
        },
    )
    .await;
    assert!(matches!(res, Err(SafeGcError::DestructiveGcDisabledByDefault)));
    assert!(backend.deleted.lock().unwrap().is_empty());

    arm.armed_from_cache_or_ttl_only = true;
    assert!(matches!(authority.set_gc_mode(GcMode::ArmedDestructive(arm)), Err(SafeGcError::ArmingRejected(_))));
}

#[test]
fn distributed_refcas_lane_refuses_async_projection_and_missing_151_153() {
    let (snap, _, _) = seed_fixture(SafeGcObjectFormat::Sha256, true);
    let auth = &snap.authority;
    let base_lane = |bridge: bool, backup: bool, async_only: bool| AuthorityLane::DistributedRefCas {
        ref_cas_authority_id: Uuid::new_v4(),
        quorum_epoch: 1,
        raft_commit_index: 10,
        quorum_verified: true,
        global_hold_bridge_verified: bridge,
        global_hold_bridge_seq: 10,
        remote_backup_root_verified: backup,
        remote_backup_root_epoch: 1,
        async_projection_only: async_only,
    };
    for (b, k, a) in [(false, true, false), (true, false, false), (true, true, true)] {
        let err = SafeGcArmReceipt::seal(
            auth.tenant_id,
            auth.repo_id,
            auth.history_id,
            auth.incarnation_id,
            1,
            true,
            base_lane(b, k, a),
        );
        assert!(matches!(err, Err(SafeGcError::DistributedPrereqsMissing(_))));
    }
}

#[tokio::test]
async fn proof_and_live_barrier_reject_forged_header_oids_lane_cursor_and_active_readers() {
    let (snap, arm, mut base_proof) = seed_fixture(SafeGcObjectFormat::Sha256, true);
    verify_deletion_proof(&base_proof).unwrap();

    // 1. Authoritative Ref-CAS cut: PG ref sequence alone (`pg_applied_seq=999`, `refcas_cut=None`) or unprojected commits MUST fail!
    let mut p_no_cut = base_proof.clone();
    p_no_cut.paired_cursors.pg_applied_seq = 999;
    p_no_cut.paired_cursors.refcas_cut = None;
    p_no_cut.proof_digest = super::proof_digest::compute_proof_digest(&p_no_cut);
    assert!(matches!(verify_deletion_proof(&p_no_cut), Err(SafeGcError::IncompleteProof(_))));

    let mut p_unproj = base_proof.clone();
    p_unproj.paired_cursors.refcas_cut.as_mut().unwrap().pg_projected_event_seq = 2;
    p_unproj.proof_digest = super::proof_digest::compute_proof_digest(&p_unproj);
    assert!(matches!(verify_deletion_proof(&p_unproj), Err(SafeGcError::IncompleteProof(_))));

    // 2. Forged contained_oids: vec![] passes stateless syntax if unreferenced, MUST fail authoritative barrier!
    let authority = DurableSafeGcAuthority::in_memory(snap.clone()).unwrap();
    authority.set_gc_mode(GcMode::ArmedDestructive(arm.clone())).unwrap();
    let mut p_forged_oids = base_proof.clone();
    p_forged_oids.candidates[0].contained_oids.clear();
    p_forged_oids.proof_digest = super::proof_digest::compute_proof_digest(&p_forged_oids);
    assert!(matches!(
        authority.begin_delete_batch(Uuid::new_v4(), snap.authority.incarnation_id, 1, 1, p_forged_oids),
        Err(SafeGcError::IncompleteProof(_))
    ));

    // 3. Cross-repo proof header paired with current deleter args MUST fail closed!
    let other_repo = Uuid::new_v4();
    let other_arm = SafeGcArmReceipt::seal(
        snap.authority.tenant_id,
        other_repo,
        snap.authority.history_id,
        snap.authority.incarnation_id,
        1,
        true,
        arm.lane.clone(),
    )
    .unwrap();
    let mut p_wrong_repo = base_proof.clone();
    p_wrong_repo.repo_id = other_repo;
    p_wrong_repo.lane = other_arm.lane;
    p_wrong_repo.proof_digest = super::proof_digest::compute_proof_digest(&p_wrong_repo);
    assert!(matches!(
        authority.begin_delete_batch(Uuid::new_v4(), snap.authority.incarnation_id, 1, 1, p_wrong_repo),
        Err(SafeGcError::IncompleteProof(_))
    ));

    // 4. Live active reader lease pinning retired pack blocks proof build & delete barrier until released!
    let retired_id = snap.retired_packs[0].pack_id;
    let lease = authority.acquire_reader_lease("clone-reader", vec![retired_id]).unwrap();
    assert!(matches!(
        authority.build_authoritative_deletion_proof(arm.clone(), &[]),
        Err(SafeGcError::ReaderQuiescenceUnverified(_))
    ));
    authority.release_reader_lease(lease.lease_id).unwrap();
    let fresh_proof = authority.build_authoritative_deletion_proof(arm, &[]).unwrap();
    assert_eq!(fresh_proof.candidates.len(), 2);

    // 5. Tampered proof digest rejected.
    base_proof.live_ref_seq = 999;
    assert!(matches!(verify_deletion_proof(&base_proof), Err(SafeGcError::ProofDigestMismatch)));
}
