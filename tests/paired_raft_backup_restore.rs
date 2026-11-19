//! OpenDAL S3 + real stock Git (`SHA-1`/`SHA-256`) + live PG 17 integration tests (#153).

#[path = "paired_raft_backup_support/fixture.rs"]
pub mod fixture;
#[path = "paired_raft_backup_support/format30_delta10_gates.rs"]
pub mod format30_delta10_gates;
#[path = "paired_raft_backup_support/format30_delta15_gates.rs"]
pub mod format30_delta15_gates;
#[path = "paired_raft_backup_support/format30_delta8_gates.rs"]
pub mod format30_delta8_gates;
#[path = "paired_raft_backup_support/format30_e2e.rs"]
pub mod format30_e2e;
#[path = "paired_raft_backup_support/format30_helpers.rs"]
pub mod format30_helpers;
#[path = "paired_raft_backup_support/format30_ledger_gates.rs"]
pub mod format30_ledger_gates;
#[path = "paired_raft_backup_support/format30_luna_fence_hold_gates.rs"]
pub mod format30_luna_fence_hold_gates;
#[path = "paired_raft_backup_support/format30_luna_gates.rs"]
pub mod format30_luna_gates;
#[path = "paired_raft_backup_support/format30_luna_startup_gates.rs"]
pub mod format30_luna_startup_gates;
#[path = "paired_raft_backup_support/mtls_cluster.rs"]
pub mod mtls_cluster;

use std::fs;

use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use fixture::{
    LoopbackS3, build_fixture, build_peer_group_fixture, dl, dticket, mk_req, setup_pg, try_backup, wticket,
};
use rootyard::db;
use rootyard::maintenance::paired_raft_backup::{
    BlobClosureManifest, DecisionExecutionTicket, DurableRaftBackend, PairedBackupError, PairedBackupManifest,
    PgProjectionCursorCut, RestoreTargetScope, capture_live_pg_backup, create_paired_backup, freeze_pg_deleter,
    restore_new_incarnation, restore_new_incarnation_with_pg, verify_backup_archive, verify_pg_live_incarnation,
};
use rootyard::ref_store::GitObjectFormat;
use rootyard::ref_store::core::state_machine::ScopeLifecycle;

#[tokio::test]
async fn end_to_end_paired_backup_and_new_incarnation_restore_sha1_and_sha256() -> Result<()> {
    let s3 = LoopbackS3::new();
    let store = s3.open_store("paired-primary")?;
    for fmt in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let dir = TempDir::new()?;
        let mut fix = build_fixture(&store, &dir.path().join("seed"), fmt).await?;
        let archive_dir = dir.path().join("archive");
        let (manifest, seal_receipt) =
            try_backup(&fix, &store, dir.path(), "archive", fix.artifacts.clone(), Some(&fix.pg_proof)).await?;
        assert_eq!(manifest.blob_closure.total_artifacts, 4);
        fix.coord.unfreeze_after_backup(&fix.raft, &archive_dir, &seal_receipt)?;
        assert!(!fix.coord.status().app_paused && fix.coord.active_barrier().is_none());
        assert!(fix.coord.admit_deleter(7).is_err());

        let scope = RestoreTargetScope {
            expected_tenant_id: Some(fix.tenant),
            expected_repository_id: Some(fix.repo),
            expected_backend_identity: Some(store.backend_identity().as_hex().into()),
        };
        let (out, new_sm, guard) =
            restore_new_incarnation(&archive_dir, &dir.path().join("rw"), &store, &scope, dl()).await?;
        let inc = &out.incarnation;
        assert_ne!(inc.new_cluster_incarnation, fix.cluster_inc);
        assert_ne!(inc.new_storage_authority_id, fix.authority);
        assert_ne!(inc.new_history_incarnation, fix.history);
        assert_eq!((out.restored_blobs, out.git_verified_refs), (4, 1));
        assert!(inc.new_authz_floor >= 30);
        assert_eq!(new_sm.read_refs(fix.repo).get("refs/heads/main").map(String::as_str), Some(fix.commit.as_str()));
        assert!(
            new_sm
                .read_scope_lifecycle(fix.repo)
                .is_some_and(|(lc, fl)| lc == ScopeLifecycle::Open && fl >= inc.new_authz_floor)
        );

        assert!(matches!(
            guard.verify_writer_grant(&wticket(fix.cluster_inc, fix.history, 2, 3, 10)),
            Err(PairedBackupError::StaleIncarnation { .. })
        ));
        assert!(matches!(
            guard.verify_deleter_lease(&dticket(fix.cluster_inc, fix.authority, 1, 7)),
            Err(PairedBackupError::StaleDeleterRefused(_))
        ));
        guard.verify_writer_grant(&wticket(
            inc.new_cluster_incarnation,
            inc.new_history_incarnation,
            inc.new_authority_epoch,
            inc.new_group_epoch,
            inc.new_authz_floor,
        ))?;
        assert!(s3.state.objects.lock().unwrap().keys().any(|k| k.contains(&inc.new_storage_authority_id.to_string())));
    }
    Ok(())
}

#[tokio::test]
async fn missing_whole_pack_pair_and_single_side_closure_regressions() -> Result<()> {
    let s3 = LoopbackS3::new();
    let store = s3.open_store("paired-whole-pair")?;
    let dir = TempDir::new()?;
    let fix = build_fixture(&store, &dir.path().join("seed"), GitObjectFormat::Sha256).await?;
    assert_ne!(fix.pack_1_id, fix.pack_2_id);

    let only_pack_1: Vec<_> = fix.artifacts.iter().filter(|a| a.pack_id == fix.pack_1_id).cloned().collect();
    assert_eq!(only_pack_1.len(), 2);
    assert!(matches!(
        try_backup(&fix, &store, dir.path(), "missing-whole-pair", only_pack_1, Some(&fix.pg_proof)).await.unwrap_err(),
        PairedBackupError::BlobClosureIncomplete(_)
    ));

    let missing_one_idx = fix.artifacts[..3].to_vec();
    assert!(matches!(
        try_backup(&fix, &store, dir.path(), "missing-one-side", missing_one_idx, Some(&fix.pg_proof))
            .await
            .unwrap_err(),
        PairedBackupError::BlobClosureIncomplete(_)
    ));

    let archive_dir = dir.path().join("resealed-missing-pair");
    let (mut manifest, _) =
        try_backup(&fix, &store, dir.path(), "resealed-missing-pair", fix.artifacts.clone(), Some(&fix.pg_proof))
            .await?;
    let kept_entries: Vec<_> =
        manifest.blob_closure.entries.iter().filter(|e| e.pack_id == fix.pack_1_id).cloned().collect();
    let kept_bytes: u64 = kept_entries.iter().map(|e| e.length).sum();
    manifest.blob_closure = BlobClosureManifest {
        backend_identity: manifest.blob_closure.backend_identity.clone(),
        provider: manifest.blob_closure.provider.clone(),
        total_artifacts: kept_entries.len(),
        total_bytes: kept_bytes,
        entries: kept_entries,
        closure_digest: String::new(),
    }
    .seal()?;
    let resealed: PairedBackupManifest = manifest.seal()?;
    let m_bytes = serde_json::to_vec_pretty(&resealed)?;
    fs::write(archive_dir.join("manifest.json"), &m_bytes)?;
    fs::write(archive_dir.join("COMPLETE"), hex::encode(Sha256::digest(&m_bytes)))?;

    assert!(matches!(
        verify_backup_archive(&archive_dir, None).unwrap_err(),
        PairedBackupError::BlobClosureIncomplete(_)
    ));
    assert!(matches!(
        restore_new_incarnation(&archive_dir, &dir.path().join("rw"), &store, &RestoreTargetScope::default(), dl())
            .await
            .unwrap_err(),
        PairedBackupError::BlobClosureIncomplete(_)
    ));
    Ok(())
}

#[tokio::test]
async fn durable_wal_barrier_and_sealing_receipt_freeze_thaw_regressions() -> Result<()> {
    let s3 = LoopbackS3::new();
    let store = s3.open_store("paired-thaw-gate")?;
    let dir = TempDir::new()?;
    let mut fix = build_fixture(&store, &dir.path().join("seed"), GitObjectFormat::Sha256).await?;
    let archive_dir = dir.path().join("good-archive");
    let (_, seal_receipt) =
        try_backup(&fix, &store, dir.path(), "good-archive", fix.artifacts.clone(), Some(&fix.pg_proof)).await?;

    let mut wrong_barrier = seal_receipt.clone();
    wrong_barrier.barrier_id = Uuid::new_v4();
    assert!(fix.coord.unfreeze_after_backup(&fix.raft, &archive_dir, &wrong_barrier).is_err());
    assert!(fix.coord.status().app_paused);

    let complete_path = archive_dir.join("COMPLETE");
    let orig_complete = fs::read(&complete_path)?;
    fs::remove_file(&complete_path)?;
    assert!(matches!(
        fix.coord.unfreeze_after_backup(&fix.raft, &archive_dir, &seal_receipt).unwrap_err(),
        PairedBackupError::IncompleteCut(_)
    ));
    assert!(fix.coord.status().app_paused);
    fs::write(&complete_path, &orig_complete)?;

    // Truncating local voter 0 WAL behind durable `quorum_commit_index` simulates 2/3 remote quorum
    // committed while local node WAL/apply lags -> both backup and thaw fail closed!
    let wal_bytes = fs::read_to_string(fix.raft.wal_path())?;
    let lines: Vec<&str> = wal_bytes.lines().collect();
    let lagged_wal = format!("{}\n", lines[..lines.len() - 1].join("\n"));
    fs::write(fix.raft.wal_path(), lagged_wal)?;

    assert!(matches!(
        try_backup(&fix, &store, dir.path(), "lagged-backup", fix.artifacts.clone(), Some(&fix.pg_proof))
            .await
            .unwrap_err(),
        PairedBackupError::FreezeNotHeld(_)
    ));
    assert!(matches!(
        fix.coord.unfreeze_after_backup(&fix.raft, &archive_dir, &seal_receipt).unwrap_err(),
        PairedBackupError::FreezeNotHeld(_)
    ));
    assert!(fix.coord.status().app_paused);

    fs::write(fix.raft.wal_path(), &wal_bytes)?;
    fix.coord.unfreeze_after_backup(&fix.raft, &archive_dir, &seal_receipt)?;
    assert!(!fix.coord.status().app_paused && fix.coord.active_barrier().is_none());
    Ok(())
}

#[tokio::test]
async fn negative_fail_closed_fault_matrix() -> Result<()> {
    let s3 = LoopbackS3::new();
    let (store, other) = (s3.open_store("paired-neg")?, s3.open_store("paired-wrong-bucket")?);
    let dir = TempDir::new()?;
    let fix = build_fixture(&store, &dir.path().join("seed"), GitObjectFormat::Sha256).await?;
    let peer = build_peer_group_fixture(&dir.path().join("peer"), 2, 5, fix.authority)?;

    let mut skewed_idx = fix.pg_proof.clone();
    skewed_idx.projection_cursors[0].applied_log_index -= 1;
    skewed_idx = skewed_idx.seal()?;

    let mut skewed_grp_epoch = fix.pg_proof.clone();
    skewed_grp_epoch.projection_cursors[0].group_epoch += 1;
    skewed_grp_epoch = skewed_grp_epoch.seal()?;

    let mut multi_pg_skewed_peer = fix.pg_proof.clone();
    multi_pg_skewed_peer.projection_cursors.push(PgProjectionCursorCut {
        group_id: 2,
        history_incarnation: peer.cut.history_incarnation,
        group_epoch: peer.cut.group_epoch + 1,
        applied_event_seq: peer.cut.applied_event_seq as i64,
        applied_log_index: peer.cut.applied_index as i64,
        applied_log_term: peer.cut.applied_term as i64,
        last_event_id: None,
        stream_state: "active".into(),
    });
    multi_pg_skewed_peer = multi_pg_skewed_peer.seal()?;

    assert!(matches!(
        try_backup(&fix, &store, dir.path(), "b1", fix.artifacts.clone(), None).await.unwrap_err(),
        PairedBackupError::IncompleteCut(_)
    ));
    assert!(matches!(
        try_backup(&fix, &store, dir.path(), "b2", fix.artifacts.clone(), Some(&skewed_idx)).await.unwrap_err(),
        PairedBackupError::CutpointSkew(_)
    ));
    assert!(matches!(
        try_backup(&fix, &store, dir.path(), "b3", fix.artifacts.clone(), Some(&skewed_grp_epoch)).await.unwrap_err(),
        PairedBackupError::CutpointSkew(_)
    ));
    assert!(matches!(
        create_paired_backup(
            mk_req(&fix, &store, dir.path(), &dir.path().join("b4"), fix.artifacts.clone(), vec![peer.as_input()]),
            Some(&multi_pg_skewed_peer),
        )
        .await
        .unwrap_err(),
        PairedBackupError::CutpointSkew(_)
    ));

    let good = dir.path().join("good");
    let (manifest, _) =
        try_backup(&fix, &store, dir.path(), "good", fix.artifacts.clone(), Some(&fix.pg_proof)).await?;
    for (sub, st, sc) in [
        ("r1", &other, RestoreTargetScope::default()),
        ("r2", &store, RestoreTargetScope { expected_tenant_id: Some(Uuid::new_v4()), ..Default::default() }),
    ] {
        let e = restore_new_incarnation(&good, &dir.path().join(sub), st, &sc, dl()).await.unwrap_err();
        assert!(matches!(
            e,
            PairedBackupError::BackendIdentityMismatch { .. } | PairedBackupError::TenantOrRepoMismatch(_)
        ));
    }
    let blob_path = good.join(&manifest.blob_closure.entries[0].archive_rel_path);
    let orig = fs::read(&blob_path)?;
    let mut bad = orig.clone();
    bad[0] ^= 0x55;
    for bytes in [bad.as_slice(), &orig[..orig.len().saturating_sub(3)]] {
        fs::write(&blob_path, bytes)?;
        assert!(matches!(verify_backup_archive(&good, None).unwrap_err(), PairedBackupError::CorruptBlobOrDigest(_)));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires live PostgreSQL via ROOTYARD_TEST_DATABASE_URL"]
async fn pg17_live_paired_backup_and_clean_room_new_incarnation_restore() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&url)?;
    let ((src_pool, src_s), (dst_pool, dst_s)) =
        (setup_pg(&admin, &url, "paired_src").await?, setup_pg(&admin, &url, "paired_dst").await?);
    let res: Result<()> = async {
        let (s3, dir) = (LoopbackS3::new(), TempDir::new()?);
        let store = s3.open_store("paired-pg17")?;
        let mut fix = build_fixture(&store, &dir.path().join("seed"), GitObjectFormat::Sha256).await?;
        let peer = build_peer_group_fixture(&dir.path().join("peer-g2"), 2, 4, fix.authority)?;
        let (snap, _) = fix.raft.durable_state()?;
        let (applied, backend, mut src_c) = (
            snap.body.last_applied.unwrap(),
            store.backend_identity().as_hex().to_owned(),
            src_pool.get().await?,
        );
        let (ev_seq, uname) = (
            snap.body.next_event_seq as i64,
            format!("u{}", &fix.tenant.simple().to_string()[..12]),
        );
        src_c.batch_execute(&format!(
            "INSERT INTO users(id,username) VALUES('{t}','{uname}');
             INSERT INTO repositories(id,owner_id,name,state,storage_backend,object_format,transition_state) VALUES('{r}','{t}','paired-demo','provisioning','pg_refstore','sha256','stable');
             INSERT INTO ref_store_core_gates(repository_id,tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,head_ref,revision,pack_mode) VALUES('{r}','{t}','sha256','{h}',2,3,'refs/heads/main',2,'metadata_only');
             INSERT INTO ref_store_core_protocol_repos(repository_id,tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,decision_required,roots_revision) VALUES('{r}','{t}','sha256','{h}',2,3,TRUE,0);
             INSERT INTO ref_store_serving_repositories(repository_id,owner_id,name,object_format,history_incarnation,authority_epoch,group_epoch,backend_identity,state) VALUES('{r}','{t}','paired-demo','sha256','{h}',2,3,'{backend}','pending');
             UPDATE ref_store_serving_repositories SET state='ready' WHERE repository_id='{r}';
             UPDATE repositories SET state='ready' WHERE id='{r}';
             INSERT INTO ref_store_core_refs(repository_id,ref_name,oid,revision) VALUES('{r}','refs/heads/main','{c}',2);
             INSERT INTO ref_store_decision_scopes(scope_kind,scope_id,version,state) VALUES('repo_access','{r}',22,'OPEN');
             INSERT INTO ref_cas_projection_cursors(group_id,history_incarnation,group_epoch,applied_event_seq,applied_log_index,applied_log_term,stream_state) VALUES
               (1,'{h}',2,{ev_seq},{idx},{term},'active'),
               (2,'{ph}',3,{pseq},{pidx},{pterm},'active');",
            t = fix.tenant,
            r = fix.repo,
            h = fix.history,
            c = fix.commit,
            idx = applied.index,
            term = applied.term,
            ph = peer.cut.history_incarnation,
            pseq = peer.cut.applied_event_seq,
            pidx = peer.cut.applied_index,
            pterm = peer.cut.applied_term,
        )).await?;

        assert!(matches!(
            capture_live_pg_backup(&mut src_c, mk_req(&fix, &store, dir.path(), &dir.path().join("p0"), fix.artifacts.clone(), vec![peer.as_input()])).await.unwrap_err(),
            PairedBackupError::DeleterNotFenced(_)
        ));
        freeze_pg_deleter(&**src_c, "paired-backup-it").await?;

        // Active group_id=1 skewed group_epoch (2 != 3) -> CutpointSkew!
        assert!(matches!(
            capture_live_pg_backup(&mut src_c, mk_req(&fix, &store, dir.path(), &dir.path().join("p1"), fix.artifacts.clone(), vec![peer.as_input()])).await.unwrap_err(),
            PairedBackupError::CutpointSkew(_)
        ));
        src_c.execute("UPDATE ref_cas_projection_cursors SET group_epoch=3 WHERE group_id=1", &[]).await?;

        // Peer group_id=2 skewed group_epoch (3 != durable peer Raft epoch 4) -> CutpointSkew!
        assert!(matches!(
            capture_live_pg_backup(&mut src_c, mk_req(&fix, &store, dir.path(), &dir.path().join("p2"), fix.artifacts.clone(), vec![peer.as_input()])).await.unwrap_err(),
            PairedBackupError::CutpointSkew(_)
        ));
        src_c.execute("UPDATE ref_cas_projection_cursors SET group_epoch=4 WHERE group_id=2", &[]).await?;

        let dest = dir.path().join("pg-archive");
        let (manifest, seal_receipt) =
            capture_live_pg_backup(&mut src_c, mk_req(&fix, &store, dir.path(), &dest, fix.artifacts.clone(), vec![peer.as_input()])).await?;
        fix.coord.unfreeze_after_backup(&fix.raft, &dest, &seal_receipt)?;
        assert_eq!(manifest.raft_cutpoint.peer_groups.len(), 1);

        let (mut dst_c, scope) = (
            dst_pool.get().await?,
            RestoreTargetScope {
                expected_tenant_id: Some(fix.tenant),
                expected_repository_id: Some(fix.repo),
                expected_backend_identity: Some(backend),
            },
        );
        let (out, _, _) =
            restore_new_incarnation_with_pg(&dest, &dir.path().join("dst-work"), &store, &mut dst_c, &scope, dl()).await?;
        let inc = &out.incarnation;
        ensure!(inc.new_authz_floor == 32 && inc.new_group_epoch == 5);

        let peer_cur = dst_c
            .query_one(
                "SELECT history_incarnation, group_epoch, applied_event_seq, applied_log_index, applied_log_term \
                 FROM ref_cas_projection_cursors WHERE group_id = 2",
                &[],
            )
            .await?;
        ensure!(
            peer_cur.get::<_, Uuid>(0) == inc.new_history_incarnation
                && peer_cur.get::<_, i64>(1) == inc.new_group_epoch
                && peer_cur.get::<_, i64>(2) == 1
                && peer_cur.get::<_, i64>(3) == 2
                && peer_cur.get::<_, i64>(4) == 1
        );

        let g_ok = wticket(
            inc.new_cluster_incarnation,
            inc.new_history_incarnation,
            inc.new_authority_epoch,
            inc.new_group_epoch,
            inc.new_authz_floor,
        );
        let dec_ok = DecisionExecutionTicket {
            decision_id: Uuid::new_v4(),
            history_incarnation: inc.new_history_incarnation,
            authority_epoch: inc.new_authority_epoch,
            group_epoch: inc.new_group_epoch,
            authz_epoch: inc.new_authz_floor,
        };
        let d_ok = dticket(
            inc.new_cluster_incarnation,
            inc.new_storage_authority_id,
            inc.new_storage_generation,
            inc.new_deleter_epoch,
        );
        verify_pg_live_incarnation(&dst_c, fix.repo, &g_ok, Some(&dec_ok), Some(&d_ok)).await?;

        let mut g_low_authz = g_ok.clone();
        g_low_authz.authz_epoch = inc.new_authz_floor - 1;
        assert!(matches!(
            verify_pg_live_incarnation(&dst_c, fix.repo, &g_low_authz, None, None).await.unwrap_err(),
            PairedBackupError::StaleGrantRefused(_)
        ));

        let mut dec_low_authz = dec_ok.clone();
        dec_low_authz.authz_epoch = inc.new_authz_floor - 1;
        assert!(matches!(
            verify_pg_live_incarnation(&dst_c, fix.repo, &g_ok, Some(&dec_low_authz), None).await.unwrap_err(),
            PairedBackupError::StaleDecisionRefused(_)
        ));

        // Fresh authority & cluster incarnation, BUT deleter_epoch below restored floor -> StaleDeleterRefused!
        let mut d_low_epoch = d_ok.clone();
        d_low_epoch.deleter_epoch = inc.new_deleter_epoch - 1;
        assert!(matches!(
            verify_pg_live_incarnation(&dst_c, fix.repo, &g_ok, None, Some(&d_low_epoch)).await.unwrap_err(),
            PairedBackupError::StaleDeleterRefused(_)
        ));
        Ok(())
    }
    .await;
    if let Ok(adm) = admin.get().await {
        let _ = adm
            .batch_execute(&format!("DROP SCHEMA IF EXISTS {src_s} CASCADE; DROP SCHEMA IF EXISTS {dst_s} CASCADE"))
            .await;
    }
    res
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires live PostgreSQL 17 + built refcas-log raft-node + pg_dump/pg_restore 17"]
async fn production_mtls_quorum_durable_freeze_format30_and_new_incarnation_boot() -> Result<()> {
    format30_e2e::run_live_mtls_quorum_freeze_format30_and_new_incarnation_boot().await
}
