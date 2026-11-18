//! Concurrency, default-off staging, PG restart fence, exact epoch & restart unit tests (#122).

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tempfile::tempdir;
use uuid::Uuid;

use super::{
    SafeGcError,
    anti_aba::KeyLifecycleState,
    executor::{
        DeleteFaultHook, PostTicketDriftFault, SafeGcSweepRequest, execute_safe_gc_sweep,
        execute_safe_gc_sweep_with_external_fence, reconcile_pending_delete_after_restart,
        reconcile_pending_delete_after_restart_fenced,
    },
    model::{GcMode, GlobalHoldEntry, GlobalHoldState, LiveRefRoot, SafeGcArmReceipt, SafeGcObjectFormat},
    store::DurableSafeGcAuthority,
    tests::{RecordingDeleteBackend, make_pack_record, oid, seed_fixture},
};

#[tokio::test]
async fn concurrent_races_exact_epoch_equality_and_post_ticket_drift_abort_delete() {
    let live_fence = || -> Result<(), SafeGcError> { Ok(()) };
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
        let unfenced = execute_safe_gc_sweep(
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
        assert!(matches!(unfenced, Err(SafeGcError::StaleDeleterFenced(_))));

        let res = execute_safe_gc_sweep_with_external_fence(
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
            Some(&live_fence),
        )
        .await;
        assert!(res.is_err(), "post-ticket state drift must fail closed inside ActiveDeleteFence");
        assert!(backend.deleted.lock().unwrap().is_empty(), "provider must not delete after post-ticket drift");
    }

    // Strict exact lease_epoch equality (`==`, NEVER `<=` or `>=`): BOTH lower (0) AND higher (2) fail closed!
    let (snap_eq, arm_eq, proof_eq) = seed_fixture(SafeGcObjectFormat::Sha1, false);
    let auth_eq = snap_eq.authority.clone();
    let authority_eq = DurableSafeGcAuthority::in_memory(snap_eq).unwrap();
    let _ = authority_eq.bump_lease_epoch().unwrap(); // live lease_epoch is now 2
    authority_eq.set_gc_mode(GcMode::ArmedDestructive(arm_eq)).unwrap();
    let backend_eq = Arc::new(RecordingDeleteBackend::default());
    for bad_lease in [1_u64, 3_u64] {
        let err = execute_safe_gc_sweep_with_external_fence(
            &authority_eq,
            backend_eq.as_ref(),
            SafeGcSweepRequest {
                batch_id: Uuid::new_v4(),
                deleter_incarnation_id: auth_eq.incarnation_id,
                deleter_incarnation_epoch: 1,
                deleter_lease_epoch: bad_lease,
                proof: proof_eq.clone(),
                deadline: Instant::now() + Duration::from_secs(5),
                fault: DeleteFaultHook::None,
            },
            Some(&live_fence),
        )
        .await;
        assert!(matches!(err, Err(SafeGcError::StaleDeleterFenced(_))), "lease {bad_lease} != 2 must fail");
        assert!(backend_eq.deleted.lock().unwrap().is_empty());
    }

    // Post-delete lease_epoch drift before tombstone commit MUST fail closed!
    let post_del_err = execute_safe_gc_sweep_with_external_fence(
        &authority_eq,
        backend_eq.as_ref(),
        SafeGcSweepRequest {
            batch_id: Uuid::new_v4(),
            deleter_incarnation_id: auth_eq.incarnation_id,
            deleter_incarnation_epoch: 1,
            deleter_lease_epoch: 2,
            proof: proof_eq,
            deadline: Instant::now() + Duration::from_secs(5),
            fault: DeleteFaultHook::BumpLeaseEpochAfterProviderDeleteBeforeCommit,
        },
        Some(&live_fence),
    )
    .await;
    assert!(matches!(post_del_err, Err(SafeGcError::StaleDeleterFenced(_))));

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
    let res = execute_safe_gc_sweep_with_external_fence(
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
        Some(&live_fence),
    )
    .await;
    assert!(matches!(res, Err(SafeGcError::ConcurrentRetentionRace(_))));
    assert!(backend.deleted.lock().unwrap().is_empty());
}

#[tokio::test]
async fn dual_pack_idx_lifecycle_live_pg_restart_fence_and_post_rotation_unwedge() {
    let dir = tempdir().unwrap();
    let journal = dir.path().join("safe-gc.json");
    let (mut snap, arm, _) = seed_fixture(SafeGcObjectFormat::Sha1, false);
    let auth = snap.authority.clone();
    let (ret2, _) = make_pack_record(
        &auth,
        5,
        "g1",
        "old2",
        KeyLifecycleState::RetiredPendingProof,
        vec![oid(SafeGcObjectFormat::Sha1, 10)],
    );
    snap.retired_packs.push(ret2.clone());
    snap.group_receipts[0].retired_pack_ids.push(ret2.pack_id);
    snap.group_receipts[0].receipt_digest = super::proof_digest::compute_group_receipt_digest(&snap.group_receipts[0]);

    let authority = DurableSafeGcAuthority::open_with_journal(&journal, Some(snap)).unwrap();
    authority.set_gc_mode(GcMode::ArmedDestructive(arm.clone())).unwrap();
    let proof = authority.build_authoritative_deletion_proof(arm.clone(), &[]).unwrap();
    assert_eq!(proof.candidates.len(), 4);

    let backend = Arc::new(RecordingDeleteBackend::default());
    let ret1 = authority.snapshot().retired_packs[0].clone();
    backend.already_absent.lock().unwrap().insert(ret1.idx_key.object_path.clone());
    *backend.unknown_key.lock().unwrap() = Some(ret2.idx_key.object_path.clone());

    let live_fence = || -> Result<(), SafeGcError> { Ok(()) };
    let err = execute_safe_gc_sweep_with_external_fence(
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
        Some(&live_fence),
    )
    .await;
    assert!(matches!(err, Err(SafeGcError::DeleteOutcomeUnknown(_))));

    let mid_snap = authority.snapshot();
    assert_eq!(mid_snap.retired_packs.len(), 1);
    assert_eq!(mid_snap.retired_packs[0].pack_id, ret2.pack_id);
    assert!(mid_snap.pending_delete.is_some());

    // Starting a second sweep before reconciling pending_delete MUST fail closed!
    assert!(matches!(
        authority.begin_delete_batch(Uuid::new_v4(), auth.incarnation_id, 1, 1, proof),
        Err(SafeGcError::ConcurrentRetentionRace(_))
    ));

    // SingleNodePg restart recovery WITHOUT live PG lease/fence (`None` or dead fence) MUST fail closed!
    let dl = Instant::now() + Duration::from_secs(5);
    assert!(matches!(
        reconcile_pending_delete_after_restart(&authority, backend.as_ref(), auth.incarnation_id, 1, 1, dl).await,
        Err(SafeGcError::StaleDeleterFenced(_))
    ));
    let dead_fence = || -> Result<(), SafeGcError> { Err(SafeGcError::StaleDeleterFenced("lost PG lease")) };
    assert!(matches!(
        reconcile_pending_delete_after_restart_fenced(
            &authority,
            backend.as_ref(),
            auth.incarnation_id,
            1,
            1,
            Some(&dead_fence),
            dl,
        )
        .await,
        Err(SafeGcError::StaleDeleterFenced(_))
    ));

    // Rotate incarnation while pending_delete is open, reopen journal:
    // default-off blocks reconciliation until armed AND live PG fence is held!
    let epoch2 = authority.rotate_incarnation().unwrap();
    assert_eq!(epoch2, 2);
    let reopened = DurableSafeGcAuthority::open_with_journal(&journal, None).unwrap();
    *backend.unknown_key.lock().unwrap() = None;
    assert!(matches!(
        reconcile_pending_delete_after_restart_fenced(
            &reopened,
            backend.as_ref(),
            reopened.snapshot().authority.incarnation_id,
            2,
            reopened.snapshot().authority.lease_epoch,
            Some(&live_fence),
            dl,
        )
        .await,
        Err(SafeGcError::DestructiveGcDisabledByDefault)
    ));

    let mut prods2 = reopened.snapshot().producers;
    for p in &mut prods2 {
        p.authority_epoch = 2;
        p.expected_authority_epoch = 2;
    }
    let curs2 = reopened.snapshot().paired_cursors;
    reopened.set_producers_and_cursors(prods2, curs2).unwrap();
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

    let aborted = reconcile_pending_delete_after_restart_fenced(
        &reopened,
        backend.as_ref(),
        reopened.snapshot().authority.incarnation_id,
        2,
        reopened.snapshot().authority.lease_epoch,
        Some(&live_fence),
        dl,
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

    let proof2 = reopened.build_authoritative_deletion_proof(arm2, &[]).unwrap();
    assert_eq!(proof2.candidates.len(), 1);
    assert_eq!(proof2.candidates[0].physical_key, ret2.idx_key.object_path);
    let final_rep = execute_safe_gc_sweep_with_external_fence(
        &reopened,
        backend.as_ref(),
        SafeGcSweepRequest {
            batch_id: Uuid::new_v4(),
            deleter_incarnation_id: reopened.snapshot().authority.incarnation_id,
            deleter_incarnation_epoch: 2,
            deleter_lease_epoch: reopened.snapshot().authority.lease_epoch,
            proof: proof2,
            deadline: dl,
            fault: DeleteFaultHook::None,
        },
        Some(&live_fence),
    )
    .await
    .unwrap();
    assert_eq!(final_rep.deleted_keys, vec![ret2.idx_key.object_path]);
    assert!(reopened.snapshot().retired_packs.is_empty());
}
