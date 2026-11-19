//! Real PG17 + live Raft hard-`SIGKILL` migration of a legacy `DistributedRefCas` journal to deployed
//! voter re-arm on the production committed writer (#122).

use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use rootyard::{
    AppState, dispatch, metrics,
    ref_store::projector::ProjectionRealm,
    storage,
    storage_lifecycle::{
        safe_gc::{
            ENV_BLOB_SAFE_GC_DESTRUCTIVE, SafeGcError, SafeGcRepoTrustConfig,
            anti_aba::AntiAbaKeyRegistry,
            domain::AuthorityRecord,
            executor::DeleteFaultHook,
            model::{AuthorityLane, GcMode, SafeGcObjectFormat},
            pg_maintenance::{run_claimed_safe_gc_once_with_fault, safe_gc_journal_path},
            store::DurableSafeGcAuthority,
        },
        scheduler, worker,
    },
};
use tempfile::TempDir;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use uuid::Uuid;

use super::super::{
    PG_SAFE_GC_TEST_LOCK, app_config,
    dist_auth_harness::{
        assert_worker_volume_has_no_external_signing_keys, provision_distributed_trust,
        rewrite_legacy_distributed_bundle, seal_test_lane_arm, test_arm_signer, test_dist_lane,
    },
    isolated_pg_pool_with_schema, pg_child_worker,
    pg_refcas_merge_fixture::{build_refcas_merge_rig, force_scan_and_schedule, production_refcas_pr_merge},
    provision_pg_refstore_repo,
    raft_voter_cluster::{LiveRaftVoterCluster, resolve_raft_node_bin, resolve_voter_bin},
    s3_harness::{LoopbackS3, build_pack_via_opendal, build_snapshot, git_cmd, make_serving_record},
    test_policy,
};
use super::project_all_refcas_events;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg17_legacy_distributed_journal_migration_and_deployed_voter_rearm_resumes_pending_delete() -> Result<()> {
    let _serial = PG_SAFE_GC_TEST_LOCK.lock().await;
    let Some(db_url) = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok() else {
        ensure!(
            std::env::var_os("ROOTYARD_SAFE_GC_REQUIRE_PG").is_none(),
            "ROOTYARD_SAFE_GC_REQUIRE_PG=1 but ROOTYARD_TEST_DATABASE_URL is missing"
        );
        return Ok(());
    };
    let db = db_url.as_str();
    let Some(node_bin) = resolve_raft_node_bin()? else { return Ok(()) };
    let Some(_voter_bin) = resolve_voter_bin()? else { return Ok(()) };

    let s3 = LoopbackS3::shared();
    let envs = s3.env_pairs();
    let (blob_store, provider) = s3.open_store_and_provider()?;
    let (pool, schema) = isolated_pg_pool_with_schema(db).await?;
    let (tenant_id, repo_id, history_id) = provision_pg_refstore_repo(&pool, &blob_store).await?;
    let dir = TempDir::new()?;
    let root = dir.path();
    let cfg = app_config(root, db.to_owned());
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
    let cluster = Arc::new(AsyncMutex::new(LiveRaftVoterCluster::start(node_bin).await?));
    let trusted_voters = cluster.lock().await.trusted_voters();
    provision_distributed_trust(&state.storage.root, tenant_id, repo_id, history_id, 2, trusted_voters.clone())?;
    cluster.lock().await.set_voter_enabled(1, true);
    cluster.lock().await.set_voter_enabled(2, true);
    let journal = safe_gc_journal_path(&state.storage.root, repo_id);
    let dl = Instant::now() + Duration::from_secs(60);

    let git_repo = root.join("src.git");
    std::fs::create_dir_all(&git_repo)?;
    git_cmd(&git_repo, &["init", "--object-format=sha1", "--initial-branch=main"], None)?;
    std::fs::write(git_repo.join("main.txt"), b"refcas-base")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "base"], None)?;
    let base_oid = git_cmd(&git_repo, &["rev-parse", "refs/heads/main"], None)?;
    std::fs::write(git_repo.join("main.txt"), b"refcas-main")?;
    git_cmd(&git_repo, &["commit", "-am", "main"], None)?;
    let (p_main, p_main_rec, i_main, i_main_rec, main_oid, oids_main) =
        build_pack_via_opendal(&provider, &git_repo, &root.join("sm"), "HEAD", (tenant_id, repo_id, 1), dl).await?;
    ensure!(main_oid != base_oid, "fast-forward feature commit must advance main");
    git_cmd(&git_repo, &["checkout", "--orphan", "orphan"], None)?;
    git_cmd(&git_repo, &["read-tree", "--empty"], None)?;
    std::fs::remove_file(git_repo.join("main.txt"))?;
    std::fs::write(git_repo.join("orphan.txt"), b"refcas-orphan")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "orphan"], None)?;
    let (p_orph, p_orph_rec, i_orph, i_orph_rec, _orph_oid, oids_orph) =
        build_pack_via_opendal(&provider, &git_repo, &root.join("so"), "HEAD", (tenant_id, repo_id, 1), dl).await?;

    let rig = build_refcas_merge_rig(Arc::clone(&cluster), tenant_id, repo_id, history_id, &base_oid).await?;
    let auth_rec = AuthorityRecord {
        tenant_id,
        repo_id,
        history_id,
        trusted_arm_pubkey_hex: test_arm_signer().pubkey_hex().to_owned(),
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
    unsafe {
        for (key, value) in &envs {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        std::env::set_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "false");
    }
    assert_eq!(scheduler::schedule_once(&state, &policy).await?, 1);
    let off_out = worker::run_once(&state, &policy, Uuid::new_v4()).await?.context("default-off repack")?;
    assert_eq!((off_out.kind.as_str(), off_out.state.as_str()), ("pando_repack", "succeeded"));
    let reloaded = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let snap_off = reloaded.snapshot();
    assert_eq!((snap_off.active_packs.len(), snap_off.retired_packs.len()), (1, 2));
    let rep_pack_loc = snap_off.active_packs[0].pack_locator.to_locator()?;
    let rep_idx_loc = snap_off.active_packs[0].idx_locator.to_locator()?;
    drop(reloaded);

    let sm = production_refcas_pr_merge(&rig, &base_oid, &main_oid).await?;
    project_all_refcas_events(&pool, tenant_id, repo_id, ProjectionRealm::new(history_id, 0, 1)?, &sm).await?;
    let armed = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let holds = armed.snapshot().global_holds.clone();
    let lane = test_dist_lane(tenant_id, repo_id, history_id, 1, 1, &holds, SafeGcObjectFormat::Sha1);
    armed.set_gc_mode(GcMode::ArmedDestructive(Box::new(seal_test_lane_arm(
        tenant_id,
        repo_id,
        history_id,
        auth_rec.incarnation_id,
        1,
        lane,
    )?)))?;
    drop(armed);
    unsafe {
        std::env::set_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "true");
    }

    // Step 1: crash after the durable `begin_delete_batch` checkpoint but before the first delete.
    force_scan_and_schedule(&state, &pool, &policy, repo_id).await?;
    let crashed = run_claimed_safe_gc_once_with_fault(
        &state,
        &policy,
        Uuid::new_v4(),
        None,
        DeleteFaultHook::SimulateCrashAfterDeletes(0),
    )
    .await?
    .context("zero-delete simulated crash")?;
    ensure!(
        crashed.kind == "pando_tombstone_delete" && crashed.state == "failed",
        "the zero-delete pass must persist the batch and fail closed"
    );
    let inspected = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let batch = inspected.snapshot().pending_delete.clone().context("crash pending_delete batch")?;
    assert!(batch.deleted_keys.is_empty(), "the zero-delete crash must not delete a locator");
    assert_eq!(batch.pending_keys.len(), 4);
    drop(inspected);
    let retired = [p_main.clone(), i_main.clone(), p_orph.clone(), i_orph.clone()];
    assert!(
        retired.iter().all(|locator| s3.has_key(locator)),
        "the zero-delete crash must keep every retired locator in the provider"
    );

    // Step 2: rotate the deployed trust doc and journal back to the exact legacy shape.
    rewrite_legacy_distributed_bundle(&state.storage.root, repo_id, &journal)?;
    let err = DurableSafeGcAuthority::open_with_journal(&journal, None).unwrap_err();
    assert!(matches!(
        err,
        SafeGcError::ArmingRejected(
            "legacy DistributedRefCas journal snapshot requires explicit migration and safe re-arm"
        )
    ));

    // Step 3: the legacy volume is released, then a cold runtime must delete nothing at all.
    drop(state);
    pool.get()
        .await?
        .execute("UPDATE storage_maintenance_repo_state SET last_scan_at = NULL WHERE repository_id = $1", &[&repo_id])
        .await?;
    let deletes_before_cold = s3.state.delete_requests.load(Ordering::SeqCst);
    let cold = pg_child_worker::spawn_cold_runtime_no_delete_child(root, db, &schema, repo_id, &envs).await?;
    assert_ne!(cold, std::process::id(), "the cold probe must run in a separate OS process");
    assert_eq!(
        s3.state.delete_requests.load(Ordering::SeqCst),
        deletes_before_cold,
        "a legacy-volume cold runtime must not delete without a voter quorum"
    );
    assert!(retired.iter().all(|locator| s3.has_key(locator)), "the legacy cold runtime must keep every locator");

    // Step 4: migrate trust + journal under the deployed voters and bind the mTLS Bearer boundary.
    let (mut trust, report) =
        SafeGcRepoTrustConfig::migrate_legacy_trust_and_journal(root, &journal, repo_id, 2, trusted_voters)?;
    let auth = cluster.lock().await.voter_client_auth();
    trust.bind_voter_client_auth(root, auth)?;
    assert!(report.journal_migrated && report.disarmed_for_voter_rearm);
    assert_eq!(report.preserved_pending_batch_id, Some(batch.batch_id));
    assert!(report.preserved_deleted_keys.is_empty());
    assert_eq!(report.preserved_pending_keys, batch.pending_keys);
    assert_worker_volume_has_no_external_signing_keys(root, repo_id);

    // Step 5: a migrated but still disarmed volume must keep refusing every delete.
    pool.get()
        .await?
        .execute("UPDATE storage_maintenance_repo_state SET last_scan_at = NULL WHERE repository_id = $1", &[&repo_id])
        .await?;
    let deletes_after_migration = s3.state.delete_requests.load(Ordering::SeqCst);
    let pid2 = pg_child_worker::spawn_cold_runtime_no_delete_child(root, db, &schema, repo_id, &envs).await?;
    assert_ne!(pid2, cold, "each cold probe must run in its own OS process");
    assert_eq!(
        s3.state.delete_requests.load(Ordering::SeqCst),
        deletes_after_migration,
        "a migrated but disarmed volume must not delete"
    );

    // Step 6: a 1-of-3 voter quorum must fail closed; a 2-of-3 quorum re-arms and preserves the batch.
    cluster.lock().await.set_voter_enabled(2, false);
    let failed = SafeGcRepoTrustConfig::rearm_distributed_from_voters(root, &journal, repo_id, None).await;
    assert!(matches!(failed, Err(SafeGcError::DistributedPrereqsMissing(_))));
    cluster.lock().await.set_voter_enabled(2, true);
    let arm = SafeGcRepoTrustConfig::rearm_distributed_from_voters(root, &journal, repo_id, None).await?;
    assert!(matches!(&arm.lane, AuthorityLane::DistributedRefCas { .. }));
    let rearmed = DurableSafeGcAuthority::open_with_journal(&journal, None)?.snapshot();
    assert!(matches!(&rearmed.gc_mode, GcMode::ArmedDestructive(_)));
    let preserved = rearmed.pending_delete.as_ref().context("re-arm must preserve pending delete")?;
    assert_eq!(preserved.batch_id, batch.batch_id);
    assert!(preserved.deleted_keys.is_empty());
    assert_eq!(preserved.pending_keys, batch.pending_keys);

    // Step 7: the deployed voter process is hard-killed after exactly one delete.
    let c1 = pg_child_worker::spawn_pass1_sigkill_child(root, db, &schema, repo_id, &envs, &pool).await?;
    assert_ne!(c1.pid, std::process::id(), "the SIGKILLed pass must run in a separate OS process");
    assert_eq!(retired.iter().filter(|locator| !s3.has_key(locator)).count(), 1, "exactly one delete before SIGKILL");
    assert_eq!(retired.iter().filter(|locator| s3.has_key(locator)).count(), 3, "three locators must survive SIGKILL");
    let interrupted = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let killed = interrupted.snapshot().pending_delete.clone().context("SIGKILL pending_delete batch")?;
    assert_eq!((killed.deleted_keys.len(), killed.pending_keys.len()), (1, 3));
    drop(interrupted);

    // Step 8: a fresh OS process reaps the stale lease and finishes the preserved batch.
    let skip = c1.job_id;
    let c2 = pg_child_worker::spawn_pass2_scheduled_runtime_child(root, db, &schema, repo_id, skip, &envs).await?;
    assert_ne!(c2.pid, c1.pid, "each pass must run in its own OS process");
    assert_ne!(c2.job_id, c1.job_id, "the recovery pass must claim a brand-new maintenance job");
    assert_eq!(c2.result["authority_lane"], "distributed_refcas");
    assert_eq!(c2.result["deleted_keys"].as_array().unwrap().len(), 3);
    let final_snap = DurableSafeGcAuthority::open_with_journal(&journal, None)?.snapshot();
    assert!(final_snap.pending_delete.is_none() && final_snap.retired_packs.is_empty());
    assert!(final_snap.completed_batches.contains_key(&batch.batch_id));
    for locator in &retired {
        assert!(!s3.has_key(locator), "retired locator must be deleted");
    }
    assert!(s3.has_key(&rep_pack_loc) && s3.has_key(&rep_idx_loc), "replacement pack must survive");

    let verify_dir = root.join("verify-pg-migration");
    let (pk_dst, ix_dst) = (verify_dir.join("objects/pack/surv.pack"), verify_dir.join("objects/pack/surv.idx"));
    std::fs::create_dir_all(pk_dst.parent().unwrap())?;
    git_cmd(&verify_dir, &["init", "--bare", "--object-format=sha1"], None)?;
    let dl_final = Instant::now() + Duration::from_secs(30);
    blob_store.get_to_file(&rep_pack_loc, &pk_dst, dl_final).await?;
    blob_store.get_to_file(&rep_idx_loc, &ix_dst, dl_final).await?;
    git_cmd(&verify_dir, &["update-ref", "refs/heads/main", main_oid.as_str()], None)?;
    git_cmd(&verify_dir, &["fsck", "--full", "--strict"], None)?;
    unsafe {
        std::env::remove_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE);
    }
    Ok(())
}
