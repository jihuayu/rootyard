//! Concurrency, incarnation fencing, partial failure & crash-restart unit tests (#122).

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tempfile::tempdir;
use uuid::Uuid;

use super::{
    SafeGcError,
    anti_aba::KeyLifecycleState,
    domain::UploadedCompactionPair,
    executor::{DeleteFaultHook, SafeGcSweepRequest, execute_safe_gc_sweep, reconcile_pending_delete_after_restart},
    model::{GcMode, GlobalHoldEntry, GlobalHoldState, LiveRefRoot, SafeGcArmReceipt, SafeGcObjectFormat},
    proof::{DeletionProofInputs, build_and_verify_deletion_proof},
    store::DurableSafeGcAuthority,
    tests::{RecordingDeleteBackend, make_pack_record, oid, seed_fixture, sha},
};

#[tokio::test]
async fn concurrent_new_ref_hold_and_release_before_register_abort_deletion() {
    for make_fault in [
        || {
            DeleteFaultHook::ConcurrentNewRefAfterBarrier(LiveRefRoot {
                ref_name: "refs/heads/feature".into(),
                target_oid: oid(SafeGcObjectFormat::Sha1, 9),
                version_seq: 11,
            })
        },
        || {
            DeleteFaultHook::AttachHoldAfterBarrier(GlobalHoldEntry {
                hold_id: Uuid::new_v4(),
                tenant_id: Uuid::nil(), // replaced below
                repo_id: Uuid::nil(),
                incarnation_epoch: 1,
                registered_seq: 11,
                state: GlobalHoldState::Active,
                protected_pack_ids: vec![],
                protected_oids: vec![oid(SafeGcObjectFormat::Sha1, 9)],
                protected_physical_keys: vec![],
            })
        },
    ] {
        let (snap, arm, proof) = seed_fixture(SafeGcObjectFormat::Sha1, false);
        let auth = snap.authority.clone();
        let authority = DurableSafeGcAuthority::in_memory(snap).unwrap();
        authority.set_gc_mode(GcMode::ArmedDestructive(arm)).unwrap();
        let mut fault = make_fault();
        if let DeleteFaultHook::AttachHoldAfterBarrier(ref mut h) = fault {
            h.tenant_id = auth.tenant_id;
            h.repo_id = auth.repo_id;
        }
        let backend = Arc::new(RecordingDeleteBackend::default());
        let res = execute_safe_gc_sweep(
            &authority,
            backend.as_ref(),
            SafeGcSweepRequest {
                batch_id: Uuid::new_v4(),
                deleter_incarnation_id: auth.incarnation_id,
                deleter_incarnation_epoch: 1,
                deleter_lease_epoch: 1,
                proof,
                deadline: Instant::now() + Duration::from_secs(5),
                fault,
            },
        )
        .await;
        assert!(matches!(res, Err(SafeGcError::ConcurrentRetentionRace(_))));
        assert!(backend.deleted.lock().unwrap().is_empty());
    }

    // Release-before-register: hold release sequence ahead of paired cursors refuses deletion!
    let (mut snap, arm, _) = seed_fixture(SafeGcObjectFormat::Sha1, false);
    let hold_id = Uuid::new_v4();
    snap.global_holds.push(GlobalHoldEntry {
        hold_id,
        tenant_id: snap.authority.tenant_id,
        repo_id: snap.authority.repo_id,
        incarnation_epoch: 1,
        registered_seq: 9,
        state: GlobalHoldState::Released { released_at_seq: 10 },
        protected_pack_ids: vec![],
        protected_oids: vec![],
        protected_physical_keys: vec![],
    });
    let auth = snap.authority.clone();
    let cand_rec = snap.retired_packs[0].clone();
    let proof = build_and_verify_deletion_proof(DeletionProofInputs {
        tenant_id: auth.tenant_id,
        repo_id: auth.repo_id,
        history_id: auth.history_id,
        object_format: SafeGcObjectFormat::Sha1,
        incarnation_id: auth.incarnation_id,
        incarnation_epoch: 1,
        live_ref_seq: 10,
        arm_receipt: arm.clone(),
        live_refs: snap.live_refs.clone(),
        producers: snap.producers.clone(),
        global_holds: snap.global_holds.clone(),
        in_flight_decisions: vec![],
        paired_cursors: snap.paired_cursors.clone(),
        group_receipts: snap.group_receipts.clone(),
        candidates: vec![super::model::CandidatePackTarget {
            pack_id: cand_rec.pack_id,
            group_id: cand_rec.group_id.clone(),
            physical_key: cand_rec.pack_key.object_path.clone(),
            object_sha256: cand_rec.pack_key.object_sha256.clone(),
            key_epoch: 1,
            contained_oids: cand_rec.contained_oids.clone(),
        }],
    })
    .unwrap();
    let authority = DurableSafeGcAuthority::in_memory(snap).unwrap();
    authority.set_gc_mode(GcMode::ArmedDestructive(arm)).unwrap();
    let backend = Arc::new(RecordingDeleteBackend::default());
    let res = execute_safe_gc_sweep(
        &authority,
        backend.as_ref(),
        SafeGcSweepRequest {
            batch_id: Uuid::new_v4(),
            deleter_incarnation_id: auth.incarnation_id,
            deleter_incarnation_epoch: 1,
            deleter_lease_epoch: 1,
            proof,
            deadline: Instant::now() + Duration::from_secs(5),
            fault: DeleteFaultHook::ReleaseHoldWithoutCursorAdvance(hold_id, 15),
        },
    )
    .await;
    assert!(matches!(res, Err(SafeGcError::ConcurrentRetentionRace(_))));
    assert!(backend.deleted.lock().unwrap().is_empty());
}

#[tokio::test]
async fn stale_incarnation_fenced_and_partial_failure_reconciles_across_restart() {
    let dir = tempdir().unwrap();
    let journal = dir.path().join("safe-gc.json");
    let (mut snap, arm, _) = seed_fixture(SafeGcObjectFormat::Sha256, true);
    let auth = snap.authority.clone();
    let (ret2, cand2) = make_pack_record(
        &auth,
        5,
        "g1",
        "old2",
        KeyLifecycleState::RetiredPendingProof,
        vec![oid(SafeGcObjectFormat::Sha256, 10)],
    );
    snap.retired_packs.push(ret2.clone());
    snap.group_receipts[0].retired_pack_ids.push(ret2.pack_id);
    snap.group_receipts[0].receipt_digest = super::proof_digest::compute_group_receipt_digest(&snap.group_receipts[0]);

    let ret1 = snap.retired_packs[0].clone();
    let cand1 = super::model::CandidatePackTarget {
        pack_id: ret1.pack_id,
        group_id: "g1".into(),
        physical_key: ret1.pack_key.object_path.clone(),
        object_sha256: ret1.pack_key.object_sha256.clone(),
        key_epoch: 1,
        contained_oids: ret1.contained_oids.clone(),
    };
    let proof = build_and_verify_deletion_proof(DeletionProofInputs {
        tenant_id: auth.tenant_id,
        repo_id: auth.repo_id,
        history_id: auth.history_id,
        object_format: SafeGcObjectFormat::Sha256,
        incarnation_id: auth.incarnation_id,
        incarnation_epoch: 1,
        live_ref_seq: 10,
        arm_receipt: arm.clone(),
        live_refs: snap.live_refs.clone(),
        producers: snap.producers.clone(),
        global_holds: vec![],
        in_flight_decisions: vec![],
        paired_cursors: snap.paired_cursors.clone(),
        group_receipts: snap.group_receipts.clone(),
        candidates: vec![cand1.clone(), cand2.clone()],
    })
    .unwrap();

    let authority = DurableSafeGcAuthority::open_with_journal(&journal, Some(snap)).unwrap();
    authority.set_gc_mode(GcMode::ArmedDestructive(arm)).unwrap();

    // Fail on second key -> first key deleted, second stays checkpointed in journal.
    let backend = Arc::new(RecordingDeleteBackend::default());
    *backend.fail_key.lock().unwrap() = Some(cand2.physical_key.clone());
    let err = execute_safe_gc_sweep(
        &authority,
        backend.as_ref(),
        SafeGcSweepRequest {
            batch_id: Uuid::new_v4(),
            deleter_incarnation_id: auth.incarnation_id,
            deleter_incarnation_epoch: 1,
            deleter_lease_epoch: 1,
            proof: proof.clone(),
            deadline: Instant::now() + Duration::from_secs(5),
            fault: DeleteFaultHook::None,
        },
    )
    .await;
    assert!(matches!(err, Err(SafeGcError::PartialDeleteFailure(_))));
    assert_eq!(backend.deleted.lock().unwrap().len(), 1);

    // Simulate process restart by reopening journal from disk and clearing failure!
    let reopened = DurableSafeGcAuthority::open_with_journal(&journal, None).unwrap();
    *backend.fail_key.lock().unwrap() = None;
    let rec = reconcile_pending_delete_after_restart(
        &reopened,
        backend.as_ref(),
        auth.incarnation_id,
        1,
        1,
        Instant::now() + Duration::from_secs(5),
    )
    .await
    .unwrap()
    .expect("pending delete batch recovered");
    assert!(rec.reconciled_from_checkpoint);
    assert_eq!(backend.deleted.lock().unwrap().len(), 2);

    // Incarnation rotation resets GC to DisabledByDefault and fences stale proof!
    let next_epoch = reopened.rotate_incarnation().unwrap();
    assert_eq!(next_epoch, 2);
    assert!(matches!(reopened.snapshot().gc_mode, GcMode::DisabledByDefault));
    let arm2 = SafeGcArmReceipt::seal(
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        reopened.snapshot().authority.incarnation_id,
        2,
        true,
        proof.lane.clone(),
    )
    .unwrap();
    reopened.set_gc_mode(GcMode::ArmedDestructive(arm2)).unwrap();
    let stale_attempt = execute_safe_gc_sweep(
        &reopened,
        backend.as_ref(),
        SafeGcSweepRequest {
            batch_id: Uuid::new_v4(),
            deleter_incarnation_id: auth.incarnation_id,
            deleter_incarnation_epoch: 1,
            deleter_lease_epoch: 1,
            proof,
            deadline: Instant::now() + Duration::from_secs(5),
            fault: DeleteFaultHook::None,
        },
    )
    .await;
    assert!(matches!(stale_attempt, Err(SafeGcError::StaleIncarnation(_))));
}

#[test]
fn compaction_cas_drift_keeps_prior_closure_intact() {
    let (snap, _, _) = seed_fixture(SafeGcObjectFormat::Sha1, false);
    let auth = snap.authority.clone();
    let old_id = snap.active_packs[0].pack_id;
    let authority = DurableSafeGcAuthority::in_memory(snap).unwrap();
    let (pk, ik) = authority.mint_compaction_keys(1, &sha("np"), &sha("ni")).unwrap();
    let pair = UploadedCompactionPair {
        pack_locator: authority.snapshot().active_packs[0].pack_locator.clone(),
        idx_locator: authority.snapshot().active_packs[0].idx_locator.clone(),
        pack_key: pk,
        idx_key: ik,
    };
    let drift = authority.cas_publish_compaction(
        Uuid::new_v4(),
        "g1",
        auth.incarnation_id,
        1,
        auth.membership_generation + 99,
        &[old_id],
        pair,
        vec![],
        sha("eq"),
    );
    assert!(matches!(drift, Err(SafeGcError::MembershipOrRootDrift(_))));
    assert_eq!(authority.snapshot().active_packs.len(), 1);
    assert_eq!(authority.snapshot().active_packs[0].pack_id, old_id);
}
