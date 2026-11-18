//! Real OpenDAL S3 + BlobStore + stock Git (SHA-1 & SHA-256) Safe GC integration tests (#122).

#[path = "storage_safe_gc_support/s3_harness.rs"]
mod s3_harness;

use std::{
    collections::BTreeSet,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use anyhow::Result;
use rootyard::{
    blob_store::{BlobError, disposable_view::DisposableViewRoot},
    storage_lifecycle::safe_gc::{
        SafeGcError,
        anti_aba::AntiAbaKeyRegistry,
        compaction::{CompactionFault, SafeGcCompactionRequest, execute_two_phase_compaction},
        domain::{AuthorityRecord, BlobStoreReadbackBackend, StagedUploadState},
        executor::{
            DeleteFaultHook, PostTicketDriftFault, SafeGcSweepRequest, execute_safe_gc_sweep,
            reclaim_abandoned_compaction_staging, reconcile_pending_delete_after_restart,
        },
        model::{AuthorityLane, GcMode, LiveRefRoot, SafeGcArmReceipt, SafeGcObjectFormat},
        store::DurableSafeGcAuthority,
    },
};
use s3_harness::{LoopbackS3, build_pack_via_opendal, build_snapshot, git_cmd, make_serving_record};
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
async fn real_opendal_s3_git_compaction_staging_cleanup_post_ticket_fence_and_dual_key_gc() -> Result<()> {
    let s3 = LoopbackS3::shared();
    let (store, provider) = s3.open_store_and_provider()?;
    let dl = Instant::now() + Duration::from_secs(60);

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
            incarnation_id: Uuid::new_v4(),
            incarnation_epoch: 1,
            membership_generation: 1,
            live_ref_seq: 1,
            lease_epoch: 1,
        };

        std::fs::write(git_repo.join("app.txt"), b"v1")?;
        git_cmd(&git_repo, &["add", "."], None)?;
        git_cmd(&git_repo, &["commit", "-m", "live-1"], None)?;
        let (p1_loc, i1_loc, c1_oid, p1_oids) = build_pack_via_opendal(
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
        let (p3_loc, i3_loc, main_oid, p3_oids) = build_pack_via_opendal(
            &provider,
            &git_repo,
            &dir.path().join("s3"),
            "HEAD",
            (auth.tenant_id, auth.repo_id, 1),
            dl,
        )
        .await?;

        // Disjoint orphan branch NOT referenced by any live ref or producer pin!
        git_cmd(&git_repo, &["checkout", "--orphan", "temp_orphan"], None)?;
        git_cmd(&git_repo, &["read-tree", "--empty"], None)?;
        std::fs::remove_file(git_repo.join("app.txt"))?;
        std::fs::remove_file(git_repo.join("app2.txt"))?;
        std::fs::write(git_repo.join("orphan.txt"), b"ephemeral")?;
        git_cmd(&git_repo, &["add", "."], None)?;
        git_cmd(&git_repo, &["commit", "-m", "orphan"], None)?;
        let (p2_loc, i2_loc, orphan_oid, p2_oids) = build_pack_via_opendal(
            &provider,
            &git_repo,
            &dir.path().join("s2"),
            "HEAD",
            (auth.tenant_id, auth.repo_id, 1),
            dl,
        )
        .await?;

        let mut reg = AntiAbaKeyRegistry::new();
        let srv1 = make_serving_record(&mut reg, &auth, &p1_loc, &i1_loc, p1_oids.clone());
        let srv3 = make_serving_record(&mut reg, &auth, &p3_loc, &i3_loc, p3_oids.clone());
        let srv2 = make_serving_record(&mut reg, &auth, &p2_loc, &i2_loc, p2_oids.clone());
        let _ = c1_oid;
        let snap =
            build_snapshot(auth.clone(), fmt, main_oid.clone(), vec![srv1.clone(), srv3.clone(), srv2.clone()], reg);
        let journal = dir.path().join("journal.json");
        let authority = DurableSafeGcAuthority::open_with_journal(&journal, Some(snap))?;

        // 1. Corrupted wire S3 PUT fails Phase 1b readback, preserves active closure, and queues staging cleanup!
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
        let cleaned = reclaim_abandoned_compaction_staging(&authority, &provider, None, dl).await?;
        assert_eq!(cleaned.deleted_keys.len(), 2);
        assert!(!s3.has_key(&staged_pk_loc));

        // 2. Pack-pinned subset compaction: pin srv1 via ReaderLease -> srv1 stays active while srv3+srv2 compact!
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
        assert!(authority.snapshot().active_packs.iter().any(|p| p.pack_id == srv1.pack_id));
        authority.release_reader_lease(r_lease.lease_id)?;

        // Full compaction across remaining active packs!
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
        assert!(s3.has_key(&new_pk_loc) && s3.has_key(&new_ix_loc));

        // 3. BlobStore::delete remains permanently DeleteDisabled!
        assert!(matches!(store.delete(&p2_loc, dl).await, Err(BlobError::DeleteDisabled)));
        let ro_backend = BlobStoreReadbackBackend { store: &store };

        let live_snap = authority.snapshot();
        let cur_seq = live_snap.authority.live_ref_seq;
        let lane = if distributed {
            AuthorityLane::DistributedRefCas {
                ref_cas_authority_id: auth.repo_id,
                quorum_epoch: 1,
                raft_commit_index: cur_seq,
                quorum_verified: true,
                global_hold_bridge_verified: true,
                global_hold_bridge_seq: cur_seq,
                remote_backup_root_verified: true,
                remote_backup_root_epoch: 1,
                async_projection_only: false,
            }
        } else {
            AuthorityLane::SingleNodePg {
                pg_authority_id: auth.repo_id,
                pg_tx_seq: cur_seq,
                pg_gc_fence_epoch: 1,
                reader_barrier_epoch: 1,
            }
        };
        let arm =
            SafeGcArmReceipt::seal(auth.tenant_id, auth.repo_id, auth.history_id, auth.incarnation_id, 1, true, lane)?;

        // Sweep ONLY srv2 (disjoint orphan pack; both .pack and .idx must be in proof.candidates!).
        let overlap_set: BTreeSet<_> = p3_oids.iter().cloned().collect();
        assert!(p2_oids.iter().all(|o| !overlap_set.contains(o)));
        if !distributed {
            authority.set_pg_reader_barrier_epoch(Some(1))?;
        }
        let proof = authority.build_authoritative_deletion_proof(arm.clone(), &[srv2.pack_id])?;
        assert_eq!(proof.candidates.len(), 2);

        // Default-off check.
        assert!(matches!(
            execute_safe_gc_sweep(
                &authority,
                &ro_backend,
                build_sweep_req(&live_snap.authority, proof.clone(), DeleteFaultHook::None, dl)
            )
            .await,
            Err(SafeGcError::DestructiveGcDisabledByDefault)
        ));

        authority.set_gc_mode(GcMode::ArmedDestructive(arm.clone()))?;

        // 4. Post-ticket state drift regression (#237 Gate 2): bump lease_epoch AFTER ticket mint, BEFORE wire DELETE!
        let pre_deletes = s3.state.delete_requests.load(Ordering::SeqCst);
        let drift_err = execute_safe_gc_sweep(
            &authority,
            &provider,
            build_sweep_req(
                &authority.snapshot().authority,
                proof.clone(),
                DeleteFaultHook::MutateAfterTicketBeforeProviderDelete(PostTicketDriftFault::BumpLeaseEpoch),
                dl,
            ),
        )
        .await;
        assert!(matches!(drift_err, Err(SafeGcError::StaleDeleterFenced(_))));
        assert_eq!(s3.state.delete_requests.load(Ordering::SeqCst), pre_deletes);
        assert!(s3.has_key(&p2_loc) && s3.has_key(&i2_loc));

        // Reconcile / clear aborted batch after lease bump by rotating & unwedging cleanly, then re-arm!
        let _ = orphan_oid;
        let _ = LiveRefRoot { ref_name: String::new(), target_oid: String::new(), version_seq: 0 };
        let _ = authority.rotate_incarnation()?;
        let _ = reconcile_pending_delete_after_restart(
            &authority,
            &provider,
            authority.snapshot().authority.incarnation_id,
            2,
            authority.snapshot().authority.lease_epoch,
            dl,
        )
        .await?;
        let mut prods2 = authority.snapshot().producers;
        for p in &mut prods2 {
            p.authority_epoch = 2;
            p.expected_authority_epoch = 2;
        }
        let curs2 = authority.snapshot().paired_cursors;
        authority.set_producers_and_cursors(prods2, curs2)?;
        let snap2 = authority.snapshot();
        let arm2 = SafeGcArmReceipt::seal(
            auth.tenant_id,
            auth.repo_id,
            auth.history_id,
            snap2.authority.incarnation_id,
            2,
            true,
            arm.lane,
        )?;
        authority.set_gc_mode(GcMode::ArmedDestructive(arm2.clone()))?;
        let proof2 = authority.build_authoritative_deletion_proof(arm2, &[srv2.pack_id])?;

        // 5. Inject HTTP 503 on i2_loc DELETE -> p2_loc ConfirmedDeleted, i2_loc OutcomeUnknown!
        *s3.state.fail_delete_substring.lock().unwrap() = Some(i2_loc.sha256().to_owned());
        let unk_err = execute_safe_gc_sweep(
            &authority,
            &provider,
            build_sweep_req(&authority.snapshot().authority, proof2, DeleteFaultHook::None, dl),
        )
        .await;
        assert!(matches!(unk_err, Err(SafeGcError::DeleteOutcomeUnknown(_))));
        assert!(!s3.has_key(&p2_loc));
        assert!(s3.has_key(&i2_loc), "failed .idx must stay tracked until reconciled");
        assert!(authority.snapshot().retired_packs.iter().any(|p| p.pack_id == srv2.pack_id));

        // Clear HTTP 503, reopen journal from disk (simulated restart), and finish reconciling i2_loc!
        *s3.state.fail_delete_substring.lock().unwrap() = None;
        let reopened = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
        let cur_auth = reopened.snapshot().authority;
        let rec_rep = reconcile_pending_delete_after_restart(
            &reopened,
            &provider,
            cur_auth.incarnation_id,
            cur_auth.incarnation_epoch,
            cur_auth.lease_epoch,
            dl,
        )
        .await?
        .expect("reconciled batch");
        assert!(rec_rep.deleted_keys.contains(&srv2.idx_key.object_path));
        // BOTH .pack and .idx of srv2 are now physically deleted in S3 and retired_packs cleaned up!
        assert!(!s3.has_key(&p2_loc) && !s3.has_key(&i2_loc));
        assert!(!reopened.snapshot().retired_packs.iter().any(|p| p.pack_id == srv2.pack_id));
        let (puts, heads, deletes) = s3.request_totals();
        assert!(puts > 0 && heads > 0 && deletes > pre_deletes);

        // 6. Verify surviving active pack on LoopbackS3 passes stock git fsck cleanly!
        let verify_dir = dir.path().join("verify-surviving");
        let (pk_dst, ix_dst) = (verify_dir.join("objects/pack/surv.pack"), verify_dir.join("objects/pack/surv.idx"));
        std::fs::create_dir_all(pk_dst.parent().unwrap())?;
        git_cmd(&verify_dir, &["init", "--bare", "--object-format", fmt.as_str()], None)?;
        store.get_to_file(&new_pk_loc, &pk_dst, dl).await?;
        store.get_to_file(&new_ix_loc, &ix_dst, dl).await?;
        git_cmd(&verify_dir, &["update-ref", "refs/heads/main", &main_oid], None)?;
        git_cmd(&verify_dir, &["fsck", "--full", "--strict"], None)?;

        let (re_pk, re_ik) = reopened.mint_compaction_keys(2, p2_loc.sha256(), i2_loc.sha256())?;
        assert_ne!(re_pk.object_path, srv2.pack_key.object_path);
        assert_ne!(re_ik.object_path, srv2.idx_key.object_path);
    }
    Ok(())
}
