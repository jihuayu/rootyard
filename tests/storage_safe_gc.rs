//! Real OpenDAL S3 + BlobStore + stock Git (SHA-1 & SHA-256) Safe GC integration tests (#122).

#[path = "storage_safe_gc_support/dist_auth_harness.rs"]
pub mod dist_auth_harness;
#[path = "storage_safe_gc_support/s3_harness.rs"]
pub mod s3_harness;

use std::{
    collections::BTreeSet,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use anyhow::Result;
use dist_auth_harness::{provision_single_node_trust, seal_test_lane_arm, test_arm_signer, test_dist_lane};
use rootyard::{
    blob_store::{BlobError, disposable_view::DisposableViewRoot},
    storage_lifecycle::safe_gc::{
        SafeGcError,
        anti_aba::AntiAbaKeyRegistry,
        compaction::{CompactionFault, SafeGcCompactionRequest, execute_two_phase_compaction},
        domain::{AuthorityRecord, BlobStoreReadbackBackend, ExternalFenceCheck, StagedUploadState},
        executor::{
            DeleteFaultHook, PostTicketDriftFault, SafeGcSweepRequest, execute_safe_gc_sweep,
            execute_safe_gc_sweep_with_external_fence, quarantine_abandoned_staging_without_delete,
            reclaim_abandoned_compaction_staging, reconcile_pending_delete_after_restart,
            reconcile_pending_delete_after_restart_fenced,
        },
        model::{AuthorityLane, GcMode, SafeGcObjectFormat},
        refcas_cut::RefCasReconciledCut,
        store::DurableSafeGcAuthority,
    },
};
use s3_harness::{LoopbackS3, build_pack_via_opendal, build_snapshot, git_cmd, make_serving_record};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

fn build_sweep_req(
    auth: &AuthorityRecord,
    proof: rootyard::storage_lifecycle::safe_gc::DeletionProof,
    fault: DeleteFaultHook,
    deadline: Instant,
) -> SafeGcSweepRequest {
    SafeGcSweepRequest {
        batch_id: Uuid::new_v4(),
        deleter_incarnation_id: auth.incarnation_id,
        deleter_incarnation_epoch: auth.incarnation_epoch,
        deleter_lease_epoch: auth.lease_epoch,
        proof,
        deadline,
        fault,
    }
}

#[tokio::test]
async fn real_opendal_s3_git_default_off_staging_versioned_delete_exact_epoch_and_dual_key_gc() -> Result<()> {
    let s3 = LoopbackS3::shared();
    let (store, provider) = s3.open_store_and_provider()?;
    let dl = Instant::now() + Duration::from_secs(60);
    let live_pg_fence = || -> std::result::Result<(), SafeGcError> { Ok(()) };

    for (fmt, distributed) in [(SafeGcObjectFormat::Sha1, false), (SafeGcObjectFormat::Sha256, true)] {
        let dir = TempDir::new()?;
        let views = DisposableViewRoot::open(&dir.path().join("views"), 8, 64 * 1024 * 1024, Duration::from_secs(120))?;
        let git_repo = dir.path().join("src.git");
        std::fs::create_dir_all(&git_repo)?;
        git_cmd(&git_repo, &["init", "--object-format", fmt.as_str(), "--initial-branch=main"], None)?;

        let auth = AuthorityRecord {
            tenant_id: Uuid::new_v4(),
            repo_id: Uuid::new_v4(),
            history_id: Uuid::new_v4(),
            trusted_arm_pubkey_hex: test_arm_signer().pubkey_hex().to_owned(),
            incarnation_id: Uuid::new_v4(),
            incarnation_epoch: 1,
            membership_generation: 1,
            live_ref_seq: 1,
            lease_epoch: 1,
        };
        provision_single_node_trust(dir.path(), auth.tenant_id, auth.repo_id, auth.history_id)?;
        let ext: Option<ExternalFenceCheck<'_>> = if distributed { None } else { Some(&live_pg_fence) };

        std::fs::write(git_repo.join("app.txt"), b"v1")?;
        git_cmd(&git_repo, &["add", "."], None)?;
        git_cmd(&git_repo, &["commit", "-m", "live-1"], None)?;
        let (_, p1_rec, _, i1_rec, _c1_oid, p1_oids) = build_pack_via_opendal(
            &provider,
            &git_repo,
            &dir.path().join("s1"),
            "HEAD",
            (auth.tenant_id, auth.repo_id, 1),
            dl,
        )
        .await?;

        std::fs::write(git_repo.join("app2.txt"), b"v2")?;
        git_cmd(&git_repo, &["add", "."], None)?;
        git_cmd(&git_repo, &["commit", "-m", "live-2"], None)?;
        let (_, p3_rec, _, i3_rec, main_oid, p3_oids) = build_pack_via_opendal(
            &provider,
            &git_repo,
            &dir.path().join("s3"),
            "HEAD",
            (auth.tenant_id, auth.repo_id, 1),
            dl,
        )
        .await?;

        git_cmd(&git_repo, &["checkout", "--orphan", "temp_orphan"], None)?;
        git_cmd(&git_repo, &["read-tree", "--empty"], None)?;
        std::fs::remove_file(git_repo.join("app.txt"))?;
        std::fs::remove_file(git_repo.join("app2.txt"))?;
        std::fs::write(git_repo.join("orphan.txt"), b"ephemeral")?;
        git_cmd(&git_repo, &["add", "."], None)?;
        git_cmd(&git_repo, &["commit", "-m", "orphan"], None)?;
        let (p2_loc, p2_rec, i2_loc, i2_rec, _orphan_oid, p2_oids) = build_pack_via_opendal(
            &provider,
            &git_repo,
            &dir.path().join("s2"),
            "HEAD",
            (auth.tenant_id, auth.repo_id, 1),
            dl,
        )
        .await?;

        let mut reg = AntiAbaKeyRegistry::new();
        let srv1 = make_serving_record(&mut reg, &auth, p1_rec, i1_rec, p1_oids.clone());
        let srv3 = make_serving_record(&mut reg, &auth, p3_rec, i3_rec, p3_oids.clone());
        let srv2 = make_serving_record(&mut reg, &auth, p2_rec, i2_rec, p2_oids.clone());
        let refcas_cut = if distributed {
            Some(RefCasReconciledCut {
                group_id: 0,
                group_epoch: 1,
                history_id: auth.history_id,
                sm_applied_log_term: 1,
                sm_applied_log_index: 1,
                sm_applied_event_seq: 1,
                sm_last_event_log_term: 1,
                sm_last_event_log_index: 1,
                sm_snapshot_checksum: hex::encode(Sha256::digest(b"s3-it-sm-snap")),
                pg_projected_log_term: 1,
                pg_projected_log_index: 1,
                pg_projected_event_seq: 1,
                unprojected_jobs_count: 0,
            })
        } else {
            None
        };
        let snap = build_snapshot(
            auth.clone(),
            fmt,
            main_oid.clone(),
            vec![srv1.clone(), srv3.clone(), srv2.clone()],
            reg,
            refcas_cut,
        );
        let journal = dir.path().join("journal.json");
        let authority = DurableSafeGcAuthority::open_with_journal(&journal, Some(snap))?;

        // 1. Corrupted wire S3 PUT creates AbandonedPendingCleanup staging; DEFAULT-OFF MUST DO 0 S3 DELETES!
        let pre_staging_deletes = s3.state.delete_requests.load(Ordering::SeqCst);
        s3.state.corrupt_next_put.store(true, Ordering::SeqCst);
        let bad_op = Uuid::new_v4();
        let bad_res = execute_two_phase_compaction(
            &authority,
            &store,
            &provider,
            SafeGcCompactionRequest {
                op_id: bad_op,
                group_id: "g-main",
                blob_generation: 1,
                target_pack_ids: Vec::new(),
                view_root: &views,
                deadline: dl,
                fault: CompactionFault::None,
            },
        )
        .await;
        assert!(bad_res.is_err());
        assert_eq!(authority.snapshot().active_packs.len(), 3);
        let staged_rec = authority.snapshot().staged_uploads.into_iter().find(|u| u.op_id == bad_op).unwrap();
        assert_eq!(staged_rec.state, StagedUploadState::AbandonedPendingCleanup);
        let staged_pk_loc = staged_rec.pack_locator.to_locator()?;
        assert!(s3.has_key(&staged_pk_loc));

        let disabled_staging_err = reclaim_abandoned_compaction_staging(&authority, &provider, ext, dl).await;
        assert!(matches!(disabled_staging_err, Err(SafeGcError::DestructiveGcDisabledByDefault)));
        assert_eq!(quarantine_abandoned_staging_without_delete(&authority)?, 1);
        assert_eq!(s3.state.delete_requests.load(Ordering::SeqCst), pre_staging_deletes);
        assert!(s3.has_key(&staged_pk_loc), "default-off must never delete abandoned remote staging");

        // 2. Pack-pinned subset compaction + full compaction!
        let r_lease = authority.acquire_reader_lease("pin-srv1", vec![srv1.pack_id])?;
        let sub_compact = execute_two_phase_compaction(
            &authority,
            &store,
            &provider,
            SafeGcCompactionRequest {
                op_id: Uuid::new_v4(),
                group_id: "g-main",
                blob_generation: 1,
                target_pack_ids: Vec::new(),
                view_root: &views,
                deadline: dl,
                fault: CompactionFault::None,
            },
        )
        .await?;
        assert_eq!(sub_compact.publish.retired_pack_ids.len(), 2);
        authority.release_reader_lease(r_lease.lease_id)?;

        let ok_compact = execute_two_phase_compaction(
            &authority,
            &store,
            &provider,
            SafeGcCompactionRequest {
                op_id: Uuid::new_v4(),
                group_id: "g-main",
                blob_generation: 1,
                target_pack_ids: Vec::new(),
                view_root: &views,
                deadline: dl,
                fault: CompactionFault::None,
            },
        )
        .await?;
        assert!(s3.has_key(&p2_loc) && s3.has_key(&i2_loc));
        let new_pk_loc = ok_compact.publish.replacement_pack.to_locator()?;
        let new_ix_loc = ok_compact.publish.replacement_idx.to_locator()?;

        assert!(matches!(store.delete(&p2_loc, dl).await, Err(BlobError::DeleteDisabled)));
        let ro_backend = BlobStoreReadbackBackend { store: &store };

        let live_snap = authority.snapshot();
        let cur_seq = live_snap.authority.live_ref_seq;
        let lane = if distributed {
            test_dist_lane(auth.tenant_id, auth.repo_id, auth.history_id, 1, cur_seq, &live_snap.global_holds, fmt)
        } else {
            AuthorityLane::SingleNodePg {
                pg_authority_id: auth.repo_id,
                pg_tx_seq: cur_seq,
                pg_gc_fence_epoch: 1,
                reader_barrier_epoch: 1,
            }
        };
        let arm = seal_test_lane_arm(auth.tenant_id, auth.repo_id, auth.history_id, auth.incarnation_id, 1, lane)?;

        let overlap_set: BTreeSet<_> = p3_oids.iter().cloned().collect();
        assert!(p2_oids.iter().all(|o| !overlap_set.contains(o)));
        if !distributed {
            authority.set_pg_reader_barrier_epoch(Some(1))?;
        }
        let proof = authority.build_authoritative_deletion_proof(arm.clone(), &[srv2.pack_id])?;
        assert_eq!(proof.candidates.len(), 2);
        assert!(proof.candidates.iter().all(|c| !c.remote_etag.is_empty() && c.remote_version_id.is_some()));

        assert!(matches!(
            execute_safe_gc_sweep(
                &authority,
                &ro_backend,
                build_sweep_req(&live_snap.authority, proof.clone(), DeleteFaultHook::None, dl)
            )
            .await,
            Err(SafeGcError::DestructiveGcDisabledByDefault)
        ));

        // 3. Arm destructive GC -> staging cleanup now executes version-conditioned S3 DELETE!
        authority.set_gc_mode(GcMode::ArmedDestructive(Box::new(arm.clone())))?;
        let cleaned = reclaim_abandoned_compaction_staging(&authority, &provider, ext, dl).await?;
        assert_eq!(cleaned.deleted_keys.len(), 2);
        assert!(!s3.has_key(&staged_pk_loc));

        // 4. Version-conditioned S3 delete regressions (Item 5):
        // 4a. Pre-HEAD replacement with IDENTICAL byte length -> refused BEFORE issuing DELETE!
        let saved_p2 = s3.get_stored(&p2_loc).expect("p2 present");
        let replaced_pre_head = s3.overwrite_same_length(&p2_loc, 0x3c);
        assert_eq!(replaced_pre_head.bytes.len(), saved_p2.bytes.len());
        let pre_ver_deletes = s3.state.delete_requests.load(Ordering::SeqCst);
        let ver_err1 = execute_safe_gc_sweep_with_external_fence(
            &authority,
            &provider,
            build_sweep_req(&authority.snapshot().authority, proof.clone(), DeleteFaultHook::None, dl),
            ext,
        )
        .await;
        assert!(matches!(ver_err1, Err(SafeGcError::CompactionVerificationFailed(_))));
        assert_eq!(s3.state.delete_requests.load(Ordering::SeqCst), pre_ver_deletes, "0 DELETEs on stat mismatch");
        assert_eq!(s3.get_stored(&p2_loc).unwrap().version_id, replaced_pre_head.version_id);
        s3.restore_stored(&p2_loc, saved_p2.clone());

        // Clear pending batch from ver_err1 via incarnation rotation & re-arm under epoch 2!
        let _ = authority.rotate_incarnation()?;
        let mut prods2 = authority.snapshot().producers;
        for p in &mut prods2 {
            p.authority_epoch = 2;
            p.expected_authority_epoch = 2;
        }
        let curs2 = authority.snapshot().paired_cursors;
        authority.set_producers_and_cursors(prods2, curs2)?;
        let arm2 = seal_test_lane_arm(
            auth.tenant_id,
            auth.repo_id,
            auth.history_id,
            authority.snapshot().authority.incarnation_id,
            2,
            arm.lane.clone(),
        )?;
        authority.set_gc_mode(GcMode::ArmedDestructive(Box::new(arm2.clone())))?;
        let _ = reconcile_pending_delete_after_restart_fenced(
            &authority,
            &provider,
            authority.snapshot().authority.incarnation_id,
            2,
            authority.snapshot().authority.lease_epoch,
            ext,
            dl,
        )
        .await?;
        let proof2 = authority.build_authoritative_deletion_proof(arm2.clone(), &[srv2.pack_id])?;

        // 4b. Post-HEAD-before-DELETE TOCTOU replacement with IDENTICAL byte length -> conditional DELETE (?versionId + If-Match) rejected (412) & object preserved!
        *s3.state.replace_same_len_on_head_substring.lock().unwrap() = Some(p2_loc.sha256().to_owned());
        let ver_err2 = execute_safe_gc_sweep_with_external_fence(
            &authority,
            &provider,
            build_sweep_req(&authority.snapshot().authority, proof2, DeleteFaultHook::None, dl),
            ext,
        )
        .await;
        assert!(matches!(ver_err2, Err(SafeGcError::CompactionVerificationFailed(_))));
        let surviving_after_412 = s3.get_stored(&p2_loc).expect("replaced same-length object MUST NOT be deleted");
        assert_eq!(surviving_after_412.bytes.len(), saved_p2.bytes.len());
        assert_ne!(surviving_after_412.version_id, saved_p2.version_id);
        s3.restore_stored(&p2_loc, saved_p2);

        // Rotate to epoch 3, unwedge, and test post-ticket BumpLeaseEpoch + HTTP 503 + restart reconciliation!
        let _ = authority.rotate_incarnation()?;
        let mut prods3 = authority.snapshot().producers;
        for p in &mut prods3 {
            p.authority_epoch = 3;
            p.expected_authority_epoch = 3;
        }
        let curs3 = authority.snapshot().paired_cursors;
        authority.set_producers_and_cursors(prods3, curs3)?;
        let arm3 = seal_test_lane_arm(
            auth.tenant_id,
            auth.repo_id,
            auth.history_id,
            authority.snapshot().authority.incarnation_id,
            3,
            arm.lane.clone(),
        )?;
        authority.set_gc_mode(GcMode::ArmedDestructive(Box::new(arm3.clone())))?;
        let _ = reconcile_pending_delete_after_restart_fenced(
            &authority,
            &provider,
            authority.snapshot().authority.incarnation_id,
            3,
            authority.snapshot().authority.lease_epoch,
            ext,
            dl,
        )
        .await?;
        let proof3 = authority.build_authoritative_deletion_proof(arm3, &[srv2.pack_id])?;

        // 5. Post-ticket BumpLeaseEpoch aborts BEFORE wire DELETE!
        let pre_deletes = s3.state.delete_requests.load(Ordering::SeqCst);
        let drift_err = execute_safe_gc_sweep_with_external_fence(
            &authority,
            &provider,
            build_sweep_req(
                &authority.snapshot().authority,
                proof3,
                DeleteFaultHook::MutateAfterTicketBeforeProviderDelete(PostTicketDriftFault::BumpLeaseEpoch),
                dl,
            ),
            ext,
        )
        .await;
        assert!(matches!(drift_err, Err(SafeGcError::StaleDeleterFenced(_))));
        assert_eq!(s3.state.delete_requests.load(Ordering::SeqCst), pre_deletes);

        // Rotate to epoch 4, unwedge, then inject HTTP 503 on i2_loc DELETE and recover after restart!
        let _ = authority.rotate_incarnation()?;
        let mut prods4 = authority.snapshot().producers;
        for p in &mut prods4 {
            p.authority_epoch = 4;
            p.expected_authority_epoch = 4;
        }
        let curs4 = authority.snapshot().paired_cursors;
        authority.set_producers_and_cursors(prods4, curs4)?;
        let arm4 = seal_test_lane_arm(
            auth.tenant_id,
            auth.repo_id,
            auth.history_id,
            authority.snapshot().authority.incarnation_id,
            4,
            arm.lane,
        )?;
        authority.set_gc_mode(GcMode::ArmedDestructive(Box::new(arm4.clone())))?;
        let _ = reconcile_pending_delete_after_restart_fenced(
            &authority,
            &provider,
            authority.snapshot().authority.incarnation_id,
            4,
            authority.snapshot().authority.lease_epoch,
            ext,
            dl,
        )
        .await?;
        let proof4 = authority.build_authoritative_deletion_proof(arm4, &[srv2.pack_id])?;

        *s3.state.fail_delete_substring.lock().unwrap() = Some(i2_loc.sha256().to_owned());
        let unk_err = execute_safe_gc_sweep_with_external_fence(
            &authority,
            &provider,
            build_sweep_req(&authority.snapshot().authority, proof4, DeleteFaultHook::None, dl),
            ext,
        )
        .await;
        assert!(matches!(unk_err, Err(SafeGcError::DeleteOutcomeUnknown(_))));
        assert!(!s3.has_key(&p2_loc));
        assert!(s3.has_key(&i2_loc));

        *s3.state.fail_delete_substring.lock().unwrap() = None;
        let reopened = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
        let cur_auth = reopened.snapshot().authority;
        if !distributed {
            // SingleNodePg restart without live PG fence (`None`) MUST fail closed!
            assert!(matches!(
                reconcile_pending_delete_after_restart(
                    &reopened,
                    &provider,
                    cur_auth.incarnation_id,
                    cur_auth.incarnation_epoch,
                    cur_auth.lease_epoch,
                    dl,
                )
                .await,
                Err(SafeGcError::StaleDeleterFenced(_))
            ));
            reopened.set_pg_reader_barrier_epoch(Some(1))?;
        }
        let rec_rep = reconcile_pending_delete_after_restart_fenced(
            &reopened,
            &provider,
            cur_auth.incarnation_id,
            cur_auth.incarnation_epoch,
            cur_auth.lease_epoch,
            ext,
            dl,
        )
        .await?
        .expect("reconciled batch");
        assert!(rec_rep.deleted_keys.contains(&srv2.idx_key.object_path));
        assert!(!s3.has_key(&p2_loc) && !s3.has_key(&i2_loc));
        assert!(!reopened.snapshot().retired_packs.iter().any(|p| p.pack_id == srv2.pack_id));
        assert_eq!(s3.state.unconditional_delete_rejections.load(Ordering::SeqCst), 0);
        assert!(s3.state.conditional_delete_requests.load(Ordering::SeqCst) >= 4);

        let verify_dir = dir.path().join("verify-surviving");
        let (pk_dst, ix_dst) = (verify_dir.join("objects/pack/surv.pack"), verify_dir.join("objects/pack/surv.idx"));
        std::fs::create_dir_all(pk_dst.parent().unwrap())?;
        git_cmd(&verify_dir, &["init", "--bare", "--object-format", fmt.as_str()], None)?;
        store.get_to_file(&new_pk_loc, &pk_dst, dl).await?;
        store.get_to_file(&new_ix_loc, &ix_dst, dl).await?;
        git_cmd(&verify_dir, &["update-ref", "refs/heads/main", &main_oid], None)?;
        git_cmd(&verify_dir, &["fsck", "--full", "--strict"], None)?;
    }
    Ok(())
}
