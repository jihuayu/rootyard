//! Real PG17 `DistributedRefCas` `pending_delete` interruption + live `gc_epoch` restart fence proof (#122).

use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use rootyard::{
    AppState, dispatch, metrics,
    ref_store::projector::{
        ProjectionRealm, RefCasEventEnvelope,
        pg::{load_or_init_cursor_for_update, project_event_in_tx},
    },
    storage,
    storage_lifecycle::{
        models::Policy,
        safe_gc::{
            ENV_BLOB_SAFE_GC_DESTRUCTIVE, SafeGcArmReceipt, SafeGcError,
            anti_aba::AntiAbaKeyRegistry,
            domain::AuthorityRecord,
            executor::DeleteFaultHook,
            model::{AuthorityLane, GcMode, SafeGcObjectFormat},
            pg_maintenance::{run_claimed_safe_gc_once_with_fault, safe_gc_journal_path},
            reconcile_pending_delete_after_restart_fenced,
            store::DurableSafeGcAuthority,
        },
        scheduler, worker,
    },
};
use tempfile::TempDir;
use tokio::sync::Semaphore;
use uuid::Uuid;

use super::{
    PG_SAFE_GC_TEST_LOCK, app_config, isolated_pg_pool,
    pg_refcas_merge_fixture::{force_scan_and_schedule, production_refcas_pr_merge},
    provision_pg_refstore_repo,
    s3_harness::{LoopbackS3, build_pack_via_opendal, build_snapshot, git_cmd, make_serving_record},
    test_policy,
};

async fn project_all_refcas_events(
    pool: &deadpool_postgres::Pool,
    tenant_id: Uuid,
    repo_id: Uuid,
    realm: ProjectionRealm,
    sm: &rootyard::ref_store::core::state_machine::RefCasStateMachine,
) -> Result<()> {
    let mut conn = pool.get().await?;
    let tx = conn.transaction().await?;
    let _ = load_or_init_cursor_for_update(&tx, realm).await?;
    for ev in &sm.snapshot()?.body.events {
        let env = RefCasEventEnvelope::from_state_machine_event(realm, Some(tenant_id), None, None, ev)?;
        let _ = project_event_in_tx(&tx, &env, None).await?;
    }
    tx.commit().await?;
    drop(conn);
    pool.get()
        .await?
        .execute(
            "UPDATE ref_cas_projection_jobs SET state='succeeded', completed_at=clock_timestamp() WHERE repository_id=$1",
            &[&repo_id],
        )
        .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg17_distributed_refcas_pending_delete_interruption_requires_new_pg_fence_and_resumes() -> Result<()> {
    let _serial = PG_SAFE_GC_TEST_LOCK.lock().await;
    let Some(db_url) = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok() else {
        ensure!(
            std::env::var_os("ROOTYARD_SAFE_GC_REQUIRE_PG").is_none(),
            "ROOTYARD_SAFE_GC_REQUIRE_PG=1 but ROOTYARD_TEST_DATABASE_URL is missing"
        );
        return Ok(());
    };

    let s3 = LoopbackS3::shared();
    let (blob_store, provider) = s3.open_store_and_provider()?;
    let pool = isolated_pg_pool(&db_url).await?;
    let (tenant_id, repo_id, history_id) = provision_pg_refstore_repo(&pool, &blob_store).await?;
    let dir = TempDir::new()?;
    let cfg = app_config(dir.path(), db_url);
    let state = Arc::new(AppState {
        mirror_primary: None,
        dispatch: dispatch::Signals::default(),
        storage: storage::Storage::open(&cfg)?,
        config: cfg,
        pool: pool.clone(),
        hooks: None,
        transfer_metrics: Arc::new(metrics::TransferCounters::default()),
        git_slots: Arc::new(Semaphore::new(2)),
    });
    let journal = safe_gc_journal_path(&state.storage.root, repo_id);
    let dl = Instant::now() + Duration::from_secs(60);

    let git_repo = dir.path().join("src.git");
    std::fs::create_dir_all(&git_repo)?;
    git_cmd(&git_repo, &["init", "--object-format=sha1", "--initial-branch=main"], None)?;
    std::fs::write(git_repo.join("main.txt"), b"refcas-base")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "base"], None)?;
    let base_oid = git_cmd(&git_repo, &["rev-parse", "refs/heads/main"], None)?;
    std::fs::write(git_repo.join("main.txt"), b"refcas-main")?;
    git_cmd(&git_repo, &["commit", "-am", "main"], None)?;
    let (p_main, p_main_rec, i_main, i_main_rec, main_oid, oids_main) =
        build_pack_via_opendal(&provider, &git_repo, &dir.path().join("sm"), "HEAD", (tenant_id, repo_id, 1), dl)
            .await?;
    ensure!(main_oid != base_oid, "fast-forward feature commit must advance main");

    git_cmd(&git_repo, &["checkout", "--orphan", "orphan"], None)?;
    git_cmd(&git_repo, &["read-tree", "--empty"], None)?;
    std::fs::remove_file(git_repo.join("main.txt"))?;
    std::fs::write(git_repo.join("orphan.txt"), b"refcas-orphan")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "orphan"], None)?;
    let (p_orph, p_orph_rec, i_orph, i_orph_rec, _orph_oid, oids_orph) =
        build_pack_via_opendal(&provider, &git_repo, &dir.path().join("so"), "HEAD", (tenant_id, repo_id, 1), dl)
            .await?;

    let auth_rec = AuthorityRecord {
        tenant_id,
        repo_id,
        history_id,
        incarnation_id: Uuid::new_v4(),
        incarnation_epoch: 1,
        membership_generation: 1,
        live_ref_seq: 1,
        lease_epoch: 1,
    };
    let mut reg = AntiAbaKeyRegistry::new();
    let srv_main = make_serving_record(&mut reg, &auth_rec, p_main_rec, i_main_rec, oids_main);
    let srv_orph = make_serving_record(&mut reg, &auth_rec, p_orph_rec, i_orph_rec, oids_orph);
    let seeded = build_snapshot(
        auth_rec.clone(),
        SafeGcObjectFormat::Sha1,
        main_oid.clone(),
        vec![srv_main, srv_orph],
        reg,
        None,
    );
    DurableSafeGcAuthority::open_with_journal(&journal, Some(seeded))?;
    pool.get()
        .await?
        .execute(
            "INSERT INTO ref_store_core_refs(repository_id,ref_name,oid,revision) VALUES($1,'refs/heads/main',$2,1)",
            &[&repo_id, &main_oid],
        )
        .await?;

    let policy = test_policy();
    let pre_default_off_deletes = s3.state.delete_requests.load(Ordering::SeqCst);
    unsafe {
        for (k, v) in s3.env_pairs() {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        std::env::set_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "false");
    }

    // Default-off repack: 1 replacement pack active, 2 packs (4 physical keys) retired, 0 deletes.
    assert_eq!(scheduler::schedule_once(&state, &policy).await?, 1);
    let off_out = worker::run_once(&state, &policy, Uuid::new_v4()).await?.context("default-off repack")?;
    assert_eq!(off_out.kind, "pando_repack");
    assert_eq!(off_out.state, "succeeded");
    assert_eq!(s3.state.delete_requests.load(Ordering::SeqCst), pre_default_off_deletes, "0 deletes when default-off");
    assert!(s3.has_key(&p_main) && s3.has_key(&i_main) && s3.has_key(&p_orph) && s3.has_key(&i_orph));

    let reloaded = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let snap_off = reloaded.snapshot();
    assert_eq!(snap_off.active_packs.len(), 1);
    assert_eq!(snap_off.retired_packs.len(), 2);
    let rep_pack_loc = snap_off.active_packs[0].pack_locator.to_locator()?;
    let rep_idx_loc = snap_off.active_packs[0].idx_locator.to_locator()?;
    drop(reloaded);

    // The production PR-merge Ref-CAS commit path publishes the sealed cutpoint snapshot.
    let sm = production_refcas_pr_merge(&state, tenant_id, repo_id, history_id, &base_oid, &main_oid).await?;
    project_all_refcas_events(&pool, tenant_id, repo_id, ProjectionRealm::new(history_id, 0, 1)?, &sm).await?;

    let armed = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    armed.set_gc_mode(GcMode::ArmedDestructive(SafeGcArmReceipt::seal(
        tenant_id,
        repo_id,
        history_id,
        auth_rec.incarnation_id,
        1,
        true,
        AuthorityLane::DistributedRefCas {
            ref_cas_authority_id: repo_id,
            quorum_epoch: 1,
            raft_commit_index: 4,
            quorum_verified: true,
            global_hold_bridge_verified: true,
            global_hold_bridge_seq: 4,
            remote_backup_root_verified: true,
            remote_backup_root_epoch: 1,
            async_projection_only: false,
        },
    )?))?;
    drop(armed);
    unsafe {
        std::env::set_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "true");
    }

    // Pass #1: interrupt the DistributedRefCas pending batch after exactly one provider delete.
    force_scan_and_schedule(&state, &pool, &policy, repo_id).await?;
    let pass1 = run_claimed_safe_gc_once_with_fault(
        &state,
        &policy,
        Uuid::new_v4(),
        None,
        DeleteFaultHook::SimulateCrashAfterDeletes(1),
    )
    .await?
    .context("pass1 interrupted sweep")?;
    assert_eq!(pass1.state, "failed");
    let retired = [p_main.clone(), i_main.clone(), p_orph.clone(), i_orph.clone()];
    assert_eq!(retired.iter().filter(|l| !s3.has_key(l)).count(), 1, "exactly one retired locator deleted");
    assert_eq!(retired.iter().filter(|l| s3.has_key(l)).count(), 3, "three retired locators remain on S3");

    let inspected = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let batch1 = inspected.snapshot().pending_delete.clone().context("pass1 pending_delete batch")?;
    assert_eq!(batch1.deleted_keys.len(), 1);
    assert_eq!(batch1.pending_keys.len(), 3);
    let epoch_1 = batch1.proof.reader_quiescence.pg_exclusive_reader_barrier_epoch.context("pass1 PG fence epoch")?;
    assert!(epoch_1 >= 1);
    drop(inspected);

    // Cold restart clears the unheld historical PG barrier epoch in memory and refuses an un-rebound batch.
    let cold_reopened = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let cold_auth = cold_reopened.snapshot().authority;
    assert!(cold_reopened.snapshot().reader_leases.pg_exclusive_barrier_epoch.is_none());
    let unfenced = reconcile_pending_delete_after_restart_fenced(
        &cold_reopened,
        &provider,
        cold_auth.incarnation_id,
        cold_auth.incarnation_epoch,
        cold_auth.lease_epoch,
        Some(&|| Ok(())),
        dl,
    )
    .await;
    assert!(matches!(unfenced, Err(SafeGcError::StaleDeleterFenced(_))));
    assert_eq!(retired.iter().filter(|l| s3.has_key(l)).count(), 3, "un-rebound restart must not delete");
    drop(cold_reopened);

    // Pass #2: the real scheduled worker acquires a fresh PG gc_epoch fence, rebinds, and finishes the batch.
    force_scan_and_schedule(&state, &pool, &policy, repo_id).await?;
    let pass2 = worker::run_once(&state, &policy, Uuid::new_v4()).await?.context("pass2 restart resumption")?;
    unsafe {
        std::env::remove_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE);
    }
    assert_eq!(pass2.kind, "pando_tombstone_delete");
    assert_eq!(pass2.state, "succeeded");
    let pgc = pool.get().await?;
    let res_json: serde_json::Value =
        pgc.query_one("SELECT result FROM storage_maintenance_jobs WHERE id = $1", &[&pass2.job_id]).await?.get(0);
    assert_eq!(res_json["authority_lane"], "distributed_refcas");
    let epoch_2 = res_json["gc_epoch"].as_u64().context("pass2 gc_epoch")?;
    assert!(epoch_2 > epoch_1, "restart must acquire a strictly newer PG gc_epoch fence");
    assert_eq!(res_json["deleted_keys"].as_array().unwrap().len(), 3);
    drop(pgc);

    let final_auth = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let final_snap = final_auth.snapshot();
    assert!(final_snap.pending_delete.is_none());
    assert!(final_snap.retired_packs.is_empty());
    assert!(final_snap.completed_batches.get(&batch1.batch_id).is_some());
    assert!(
        final_snap
            .audit_log
            .iter()
            .any(|e| e.action == "rebind_pending_delete_pg_fence" && e.target == epoch_2.to_string()),
        "restart must audit rebind_pending_delete_pg_fence with the fresh epoch"
    );

    for loc in &retired {
        assert!(!s3.has_key(loc), "retired locator must be deleted");
    }
    assert!(s3.has_key(&rep_pack_loc) && s3.has_key(&rep_idx_loc));
    let verify_dir = dir.path().join("verify-pg-restart");
    let (pk_dst, ix_dst) = (verify_dir.join("objects/pack/surv.pack"), verify_dir.join("objects/pack/surv.idx"));
    std::fs::create_dir_all(pk_dst.parent().unwrap())?;
    git_cmd(&verify_dir, &["init", "--bare", "--object-format=sha1"], None)?;
    blob_store.get_to_file(&rep_pack_loc, &pk_dst, dl).await?;
    blob_store.get_to_file(&rep_idx_loc, &ix_dst, dl).await?;
    git_cmd(&verify_dir, &["update-ref", "refs/heads/main", &main_oid], None)?;
    git_cmd(&verify_dir, &["fsck", "--full", "--strict"], None)?;
    Ok(())
}
