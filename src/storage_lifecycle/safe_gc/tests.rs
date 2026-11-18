//! Unit tests for Safe GC default-off gates, unified DeletionProof, and anti-ABA keys (#122).

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    SafeGcError,
    anti_aba::{AntiAbaKeyRegistry, KeyLifecycleState, PhysicalBlobKey},
    domain::{AuthorityRecord, BlobLocatorRecord, DeleteAuthorizationTicket, SafeGcDeleteBackend, SafeGcFuture},
    executor::{DeleteFaultHook, SafeGcSweepRequest, execute_safe_gc_sweep},
    model::{
        AuthorityLane, CandidatePackTarget, GcMode, GroupClosureReceipt, LiveRefRoot, PairedCursorReconciliation,
        ProducerReconciliationEntry, RetentionProducer, SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT, SafeGcArmReceipt,
        SafeGcObjectFormat, SourceFreshness,
    },
    proof::{DeletionProofInputs, build_and_verify_deletion_proof, seal_group_receipt, verify_deletion_proof},
    store::{DurableSafeGcAuthority, SafeGcRepoSnapshot, ServingPackRecord},
};

#[derive(Default)]
pub(super) struct RecordingDeleteBackend {
    pub(super) deleted: Mutex<Vec<String>>,
    pub(super) fail_key: Mutex<Option<String>>,
}

impl SafeGcDeleteBackend for RecordingDeleteBackend {
    fn delete_authorized<'a>(
        &'a self,
        ticket: &'a DeleteAuthorizationTicket,
        _deadline: Instant,
    ) -> SafeGcFuture<'a, ()> {
        Box::pin(async move {
            let path = ticket.physical_key().to_owned();
            if self.fail_key.lock().unwrap().as_deref() == Some(path.as_str()) {
                return Err(SafeGcError::Io("injected backend delete failure".into()));
            }
            self.deleted.lock().unwrap().push(path);
            Ok(())
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
) -> (ServingPackRecord, CandidatePackTarget) {
    let psha = sha(&format!("pack-{tag}"));
    let isha = sha(&format!("idx-{tag}"));
    let p_nonce = Uuid::new_v4();
    let i_nonce = Uuid::new_v4();
    let scope = (auth.tenant_id, auth.repo_id, auth.history_id, auth.incarnation_epoch);
    let p_path = PhysicalBlobKey::canonical_path(scope, seq, p_nonce, "pack", &psha);
    let i_path = PhysicalBlobKey::canonical_path(scope, seq + 1, i_nonce, "idx", &isha);
    let pack_key = PhysicalBlobKey {
        schema_version: 1,
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
        schema_version: 1,
        tenant_id: auth.tenant_id,
        repo_id: auth.repo_id,
        history_id: auth.history_id,
        incarnation_epoch: auth.incarnation_epoch,
        allocation_seq: seq + 1,
        nonce: i_nonce,
        role: "idx".into(),
        object_sha256: isha.clone(),
        object_path: i_path,
        state,
    };
    let pack_id = Uuid::new_v4();
    let pack_loc = BlobLocatorRecord {
        tenant_id: auth.tenant_id,
        authority_id: auth.repo_id,
        generation: auth.membership_generation as i64,
        attempt_id: Uuid::new_v4(),
        namespace: "packs".into(),
        sha256: psha.clone(),
        length: 512,
    };
    let idx_loc = BlobLocatorRecord { sha256: isha, attempt_id: Uuid::new_v4(), ..pack_loc.clone() };
    let rec = ServingPackRecord {
        pack_id,
        group_id: group_id.into(),
        pack_key,
        idx_key,
        pack_locator: pack_loc,
        idx_locator: idx_loc,
        contained_oids: contained_oids.clone(),
    };
    let cand = CandidatePackTarget {
        pack_id,
        group_id: group_id.into(),
        physical_key: p_path,
        object_sha256: psha,
        key_epoch: auth.incarnation_epoch,
        contained_oids,
    };
    (rec, cand)
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
    let live_oid = oid(fmt, 1);
    let pin_oid = oid(fmt, 2);
    let dead_oid = oid(fmt, 9);
    let (active_rec, _) = make_pack_record(
        &auth,
        1,
        "g1",
        "active",
        KeyLifecycleState::ActiveServing,
        vec![live_oid.clone(), pin_oid.clone()],
    );
    let (retired_rec, cand) =
        make_pack_record(&auth, 3, "g1", "old", KeyLifecycleState::RetiredPendingProof, vec![dead_oid]);
    let gr = seal_group_receipt(GroupClosureReceipt {
        group_id: "g1".into(),
        epoch: 1,
        retired_pack_ids: vec![retired_rec.pack_id],
        replacement_pack_ids: vec![active_rec.pack_id],
        replacement_closure_verified: true,
        quiesced: true,
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
        AuthorityLane::SingleNodePg { pg_authority_id: auth.repo_id, pg_tx_seq: 10, local_quiesced: true }
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
    let paired_cursors = PairedCursorReconciliation {
        pg_freshness: SourceFreshness::Reconciled,
        pg_applied_seq: 10,
        pg_required_seq: 10,
        refcas_freshness: SourceFreshness::Reconciled,
        refcas_applied_index: 10,
        refcas_required_index: 10,
    };
    let proof = build_and_verify_deletion_proof(DeletionProofInputs {
        tenant_id: auth.tenant_id,
        repo_id: auth.repo_id,
        history_id: auth.history_id,
        object_format: fmt,
        incarnation_id: auth.incarnation_id,
        incarnation_epoch: 1,
        live_ref_seq: 10,
        arm_receipt: arm.clone(),
        live_refs: live_refs.clone(),
        producers: producers.clone(),
        global_holds: vec![],
        in_flight_decisions: vec![],
        paired_cursors: paired_cursors.clone(),
        group_receipts: vec![gr.clone()],
        candidates: vec![cand],
    })
    .unwrap();
    let snap = SafeGcRepoSnapshot {
        authority: auth,
        object_format: fmt,
        gc_mode: GcMode::DisabledByDefault,
        live_refs,
        active_packs: vec![active_rec],
        retired_packs: vec![retired_rec],
        group_receipts: vec![gr],
        producers,
        global_holds: vec![],
        in_flight_decisions: vec![],
        paired_cursors,
        key_registry: AntiAbaKeyRegistry::new(),
        pending_delete: None,
        completed_batches: BTreeMap::new(),
        audit_log: vec![],
    };
    (snap, arm, proof)
}

#[tokio::test]
async fn default_off_gate_and_ttl_or_tampered_arming_fail_closed() {
    assert!(!SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT);
    let (snap, mut arm, proof) = seed_fixture(SafeGcObjectFormat::Sha1, false);
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
            proof: proof.clone(),
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

#[test]
fn unified_deletion_proof_rejects_every_missing_lagging_and_overlapping_source() {
    let (_, _, mut base_proof) = seed_fixture(SafeGcObjectFormat::Sha256, true);
    verify_deletion_proof(&base_proof).unwrap();

    // Missing producer (#6 backup dropped).
    let mut p_missing = base_proof.clone();
    p_missing.producers.pop();
    p_missing.proof_digest = super::proof_digest::compute_proof_digest(&p_missing);
    assert!(matches!(verify_deletion_proof(&p_missing), Err(SafeGcError::IncompleteProof(_))));

    // Lagging producer cursor.
    let mut p_lag = base_proof.clone();
    p_lag.producers[0].observed_cursor_seq = 9;
    p_lag.proof_digest = super::proof_digest::compute_proof_digest(&p_lag);
    assert!(matches!(verify_deletion_proof(&p_lag), Err(SafeGcError::IncompleteProof(_))));

    // Lagging Ref-CAS paired cursor.
    let mut p_cur = base_proof.clone();
    p_cur.paired_cursors.refcas_applied_index = 9;
    p_cur.proof_digest = super::proof_digest::compute_proof_digest(&p_cur);
    assert!(matches!(verify_deletion_proof(&p_cur), Err(SafeGcError::IncompleteProof(_))));

    // Tampered proof digest.
    base_proof.live_ref_seq = 999;
    assert!(matches!(verify_deletion_proof(&base_proof), Err(SafeGcError::ProofDigestMismatch)));
}

#[test]
fn anti_aba_registry_forbids_reuse_even_after_deletion_and_same_sha_reupload() {
    let (t, r, h) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let same_sha = sha("identical-pack");
    let mut reg = AntiAbaKeyRegistry::new();
    let k1 = reg.mint_immutable_key((t, r, h, 1), "pack", &same_sha, KeyLifecycleState::ActiveServing).unwrap();
    reg.transition_state(&k1.object_path, KeyLifecycleState::ActiveServing, KeyLifecycleState::RetiredPendingProof)
        .unwrap();
    reg.transition_state(
        &k1.object_path,
        KeyLifecycleState::RetiredPendingProof,
        KeyLifecycleState::DeletePendingBarrier,
    )
    .unwrap();
    reg.transition_state(
        &k1.object_path,
        KeyLifecycleState::DeletePendingBarrier,
        KeyLifecycleState::PhysicallyDeletedTombstone,
    )
    .unwrap();

    // Classic A -> delete -> A re-upload must produce a strictly distinct physical key!
    let k2 = reg.mint_immutable_key((t, r, h, 1), "pack", &same_sha, KeyLifecycleState::ActiveServing).unwrap();
    assert_ne!(k1.object_path, k2.object_path);
    assert!(k2.allocation_seq > k1.allocation_seq);
    assert!(matches!(reg.register_verified_key(k1.clone()), Err(SafeGcError::AbaKeyReuseDetected(_))));
    assert!(matches!(reg.assert_late_put_allowed(&k1.object_path, 1), Err(SafeGcError::AbaKeyReuseDetected(_))));

    reg.advance_incarnation_epoch(2).unwrap();
    assert!(matches!(reg.assert_late_put_allowed(&k2.object_path, 1), Err(SafeGcError::StaleIncarnation(_))));
    assert!(matches!(reg.assert_delete_allowed(&k2.object_path, 1), Err(SafeGcError::StaleDeleterFenced(_))));
    let unique: BTreeSet<_> = [k1.object_path, k2.object_path].into_iter().collect();
    assert_eq!(unique.len(), 2);
}
