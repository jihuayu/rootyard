//! Concurrency, post-ticket drift fencing, provider outcomes & restart unit tests (#122).

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tempfile::tempdir;
use uuid::Uuid;

use super::{
    SafeGcError,
    anti_aba::KeyLifecycleState,
    domain::{CasCompactionPublish, UploadedCompactionPair},
    executor::{
        DeleteFaultHook, PostTicketDriftFault, SafeGcSweepRequest, execute_safe_gc_sweep,
        reclaim_abandoned_compaction_staging, reconcile_pending_delete_after_restart,
    },
    model::{GcMode, GlobalHoldEntry, GlobalHoldState, LiveRefRoot, SafeGcArmReceipt, SafeGcObjectFormat},
    store::DurableSafeGcAuthority,
    tests::{RecordingDeleteBackend, make_pack_record, oid, seed_fixture, sha},
};

#[tokio::test]
async fn concurrent_races_and_post_ticket_drift_abort_before_provider_delete() {
    for post_fault in [
        PostTicketDriftFault::ConcurrentNewRef(LiveRefRoot {
            ref_name: "refs/heads/post-ticket".into(),
            target_oid: oid(SafeGcObjectFormat::Sha1, 9),
            version_seq: 11,
        }),
        PostTicketDriftFault::BumpLeaseEpoch,
        PostTicketDriftFault::RotateIncarnation,
    ] {
        let (snap, arm, proof) = seed_fixture(SafeGcObjectFormat::Sha1, false);
        let auth = snap.authority.clone();
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
                fault: DeleteFaultHook::MutateAfterTicketBeforeProviderDelete(post_fault),
            },
        )
        .await;
        assert!(res.is_err(), "post-ticket state drift must fail closed inside ActiveDeleteFence");
        assert!(backend.deleted.lock().unwrap().is_empty(), "provider must not delete after post-ticket drift");
    }

    // Release-before-register cursor gap aborts deletion!
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
    let authority = DurableSafeGcAuthority::in_memory(snap).unwrap();
    authority.set_gc_mode(GcMode::ArmedDestructive(arm.clone())).unwrap();
    let proof = authority.build_authoritative_deletion_proof(arm, &[]).unwrap();
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
async fn dual_pack_idx_lifecycle_outcome_unknown_and_post_rotation_restart_unwedge() {
    let dir = tempdir().unwrap();
    let journal = dir.path().join("safe-gc.json");
    let (mut snap, arm, _) = seed_fixture(SafeGcObjectFormat::Sha256, true);
    let auth = snap.authority.clone();
    let (ret2, _) = make_pack_record(
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

    let authority = DurableSafeGcAuthority::open_with_journal(&journal, Some(snap)).unwrap();
    authority.set_gc_mode(GcMode::ArmedDestructive(arm.clone())).unwrap();
    let proof = authority.build_authoritative_deletion_proof(arm.clone(), &[]).unwrap();
    // 2 retired packs -> 4 physical keys (pack + idx each)!
    assert_eq!(proof.candidates.len(), 4);

    let backend = Arc::new(RecordingDeleteBackend::default());
    // Mark ret2's idx_key as OutcomeUnknown and ret1's idx_key as AlreadyAbsent!
    let ret1 = authority.snapshot().retired_packs[0].clone();
    backend.already_absent.lock().unwrap().insert(ret1.idx_key.object_path.clone());
    *backend.unknown_key.lock().unwrap() = Some(ret2.idx_key.object_path.clone());

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
    assert!(matches!(err, Err(SafeGcError::DeleteOutcomeUnknown(_))));

    // ret1 had both .pack (ConfirmedDeleted) and .idx (AlreadyAbsent) tombstoned -> removed from retired_packs!
    // ret2 had .pack deleted, .idx OutcomeUnknown -> ret2 MUST remain in retired_packs and pending_delete!
    let mid_snap = authority.snapshot();
    assert_eq!(mid_snap.retired_packs.len(), 1);
    assert_eq!(mid_snap.retired_packs[0].pack_id, ret2.pack_id);
    assert!(mid_snap.pending_delete.is_some());

    // Starting a second sweep before reconciling pending_delete MUST fail closed!
    assert!(matches!(
        authority.begin_delete_batch(Uuid::new_v4(), auth.incarnation_id, 1, 1, proof),
        Err(SafeGcError::ConcurrentRetentionRace(_))
    ));

    // Rotate incarnation while pending_delete is open, then reopen journal after restart:
    // reconcile_pending_delete_after_restart must roll ret2.idx_key back to RetiredPendingProof and unwedge!
    let epoch2 = authority.rotate_incarnation().unwrap();
    assert_eq!(epoch2, 2);
    let reopened = DurableSafeGcAuthority::open_with_journal(&journal, None).unwrap();
    *backend.unknown_key.lock().unwrap() = None;
    let aborted = reconcile_pending_delete_after_restart(
        &reopened,
        backend.as_ref(),
        reopened.snapshot().authority.incarnation_id,
        epoch2,
        reopened.snapshot().authority.lease_epoch,
        Instant::now() + Duration::from_secs(5),
    )
    .await
    .unwrap()
    .expect("aborted stale batch");
    assert!(aborted.aborted_stale_incarnation);
    let post_unwedge = reopened.snapshot();
    assert!(post_unwedge.pending_delete.is_none());
    assert_eq!(
        post_unwedge.key_registry.keys_by_path.get(&ret2.idx_key.object_path).map(|k| k.state),
        Some(KeyLifecycleState::RetiredPendingProof)
    );

    // Now re-arm under epoch 2 (advancing producer epochs to 2) and complete the remaining .idx sweep cleanly!
    let mut prods2 = post_unwedge.producers.clone();
    for p in &mut prods2 {
        p.authority_epoch = 2;
        p.expected_authority_epoch = 2;
    }
    reopened.set_producers_and_cursors(prods2, post_unwedge.paired_cursors.clone()).unwrap();
    let arm2 = SafeGcArmReceipt::seal(
        auth.tenant_id,
        auth.repo_id,
        auth.history_id,
        reopened.snapshot().authority.incarnation_id,
        2,
        true,
        arm.lane,
    )
    .unwrap();
    reopened.set_gc_mode(GcMode::ArmedDestructive(arm2.clone())).unwrap();
    let proof2 = reopened.build_authoritative_deletion_proof(arm2, &[]).unwrap();
    assert_eq!(proof2.candidates.len(), 1);
    assert_eq!(proof2.candidates[0].physical_key, ret2.idx_key.object_path);
    let final_rep = execute_safe_gc_sweep(
        &reopened,
        backend.as_ref(),
        SafeGcSweepRequest {
            batch_id: Uuid::new_v4(),
            deleter_incarnation_id: reopened.snapshot().authority.incarnation_id,
            deleter_incarnation_epoch: 2,
            deleter_lease_epoch: reopened.snapshot().authority.lease_epoch,
            proof: proof2,
            deadline: Instant::now() + Duration::from_secs(5),
            fault: DeleteFaultHook::None,
        },
    )
    .await
    .unwrap();
    assert_eq!(final_rep.deleted_keys, vec![ret2.idx_key.object_path]);
    assert!(reopened.snapshot().retired_packs.is_empty());
}

#[tokio::test]
async fn compaction_cas_drift_preserves_prior_closure_and_cleans_abandoned_staging() {
    let (snap, _, _) = seed_fixture(SafeGcObjectFormat::Sha1, false);
    let auth = snap.authority.clone();
    let old_id = snap.active_packs[0].pack_id;
    let authority = DurableSafeGcAuthority::in_memory(snap).unwrap();
    let (pk, ik) = authority.mint_compaction_keys(1, &sha("np"), &sha("ni")).unwrap();
    let op_id = Uuid::new_v4();
    let mut pack_loc = authority.snapshot().active_packs[0].pack_locator.clone();
    pack_loc.sha256 = sha("np");
    let mut idx_loc = authority.snapshot().active_packs[0].idx_locator.clone();
    idx_loc.sha256 = sha("ni");
    let pair = UploadedCompactionPair {
        pack_locator: pack_loc,
        idx_locator: idx_loc,
        pack_key: pk.clone(),
        idx_key: ik.clone(),
    };
    authority.record_staged_upload(op_id, &pair).unwrap();
    let drift = authority.cas_publish_compaction(CasCompactionPublish {
        op_id,
        group_id: "g1".into(),
        expected_incarnation_id: auth.incarnation_id,
        expected_incarnation_epoch: 1,
        expected_generation: auth.membership_generation + 99,
        expected_membership_digest: authority.snapshot().compute_membership_digest(),
        retired_pack_ids: vec![old_id],
        uploaded: pair,
        replacement_oids: vec![],
        equivalence_digest: sha("eq"),
    });
    assert!(matches!(drift, Err(SafeGcError::MembershipOrRootDrift(_))));
    authority.mark_staged_upload_abandoned(op_id).unwrap();
    assert_eq!(authority.snapshot().active_packs.len(), 1);
    assert_eq!(authority.snapshot().active_packs[0].pack_id, old_id);

    let backend = RecordingDeleteBackend::default();
    let cleaned =
        reclaim_abandoned_compaction_staging(&authority, &backend, None, Instant::now() + Duration::from_secs(5))
            .await
            .unwrap();
    assert_eq!(cleaned.deleted_keys.len(), 2);
    let after = authority.snapshot();
    assert!(after.key_registry.deleted_tombstones.contains(&pk.object_path));
    assert!(after.key_registry.deleted_tombstones.contains(&ik.object_path));
}
