//! Real PG17 scheduled-worker Ref-CAS lifecycle: install→commit, revoke/cancel, OldOidMismatch (#122).

use std::{
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use rootyard::{
    AppState, dispatch, metrics,
    pulls::remote_merge_finalizer::{
        MergeAttemptOutcome, MergeAuthorityBackend, MergeFaultInjection, PgMergeStore, PullRemoteMergeProducer,
        RemoteMergeError, init_remote_merge_tables, verify_pull_remote_authz_grant,
    },
    ref_store::{
        core::state_machine::{CancelCommand, CloseAuthScopeCommand, RefCasCommand, ScopeLifecycle},
        projector::ProjectionRealm,
    },
    storage,
    storage_lifecycle::{
        models::Policy,
        safe_gc::{
            ENV_BLOB_SAFE_GC_DESTRUCTIVE,
            anti_aba::AntiAbaKeyRegistry,
            domain::AuthorityRecord,
            model::{GcMode, SafeGcObjectFormat},
            pg_maintenance::safe_gc_journal_path,
            store::DurableSafeGcAuthority,
        },
        scheduler, worker,
    },
};
use tempfile::TempDir;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use uuid::Uuid;

use super::{
    PG_SAFE_GC_TEST_LOCK, app_config,
    dist_auth_harness::{provision_distributed_trust, seal_test_lane_arm, test_arm_signer, test_dist_lane},
    isolated_pg_pool_with_schema,
    pg_refcas_merge_fixture::{build_refcas_merge_attempt, build_refcas_merge_rig, force_scan_and_schedule},
    pg_refcas_restart_cases::project_all_refcas_events,
    provision_pg_refstore_repo,
    raft_voter_cluster::{LiveRaftVoterCluster, resolve_raft_node_bin, resolve_voter_bin},
    s3_harness::{LoopbackS3, build_pack_via_opendal, build_snapshot, git_cmd, make_serving_record},
    test_policy,
};

async fn worker_pass(
    state: &Arc<AppState>,
    pool: &deadpool_postgres::Pool,
    policy: &Policy,
    repo_id: Uuid,
) -> Result<String> {
    Ok(worker_pass_with_error(state, pool, policy, repo_id).await?.0)
}

async fn worker_pass_with_error(
    state: &Arc<AppState>,
    pool: &deadpool_postgres::Pool,
    policy: &Policy,
    repo_id: Uuid,
) -> Result<(String, String)> {
    force_scan_and_schedule(state, pool, policy, repo_id).await?;
    let out = worker::run_once(state, policy, Uuid::new_v4()).await?.context("scheduled worker pass")?;
    let row = pool
        .get()
        .await?
        .query_one("SELECT last_error FROM storage_maintenance_jobs WHERE id = $1", &[&out.job_id])
        .await?;
    let last_error: Option<String> = row.get(0);
    Ok((out.state, last_error.unwrap_or_default()))
}

async fn attempt_state(pool: &deadpool_postgres::Pool, repo_id: Uuid, operation_id: Uuid) -> Result<String> {
    Ok(pool
        .get()
        .await?
        .query_one(
            "SELECT state FROM pull_remote_merge_attempts WHERE repository_id=$1 AND operation_id=$2",
            &[&repo_id, &operation_id],
        )
        .await?
        .get(0))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pg17_scheduled_worker_refcas_install_commit_revocation_and_old_oid_rejection() -> Result<()> {
    let _serial = PG_SAFE_GC_TEST_LOCK.lock().await;
    let Some(db_url) = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok() else {
        ensure!(
            std::env::var_os("ROOTYARD_SAFE_GC_REQUIRE_PG").is_none(),
            "ROOTYARD_SAFE_GC_REQUIRE_PG=1 but ROOTYARD_TEST_DATABASE_URL is missing"
        );
        return Ok(());
    };
    let Some(node_bin) = resolve_raft_node_bin()? else { return Ok(()) };
    let Some(_voter_bin) = resolve_voter_bin()? else { return Ok(()) };

    let s3 = LoopbackS3::shared();
    let (blob_store, provider) = s3.open_store_and_provider()?;
    let (pool, _schema) = isolated_pg_pool_with_schema(&db_url).await?;
    let (tenant_id, repo_id, history_id) = provision_pg_refstore_repo(&pool, &blob_store).await?;
    init_remote_merge_tables(&pool).await?;
    let pg_store = PgMergeStore::new(pool.clone());
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
    let cluster = Arc::new(AsyncMutex::new(LiveRaftVoterCluster::start(node_bin).await?));
    let trusted_voters = cluster.lock().await.trusted_voters();
    provision_distributed_trust(&state.storage.root, tenant_id, repo_id, history_id, 2, trusted_voters)?;
    cluster.lock().await.set_voter_enabled(1, true);
    cluster.lock().await.set_voter_enabled(2, true);

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

    git_cmd(&git_repo, &["checkout", "-b", "cand", &base_oid], None)?;
    std::fs::write(git_repo.join("cand.txt"), b"refcas-cand")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "cand"], None)?;
    let (_p_cand, _p_cand_rec, _i_cand, _i_cand_rec, cand_oid, _oids_cand) =
        build_pack_via_opendal(&provider, &git_repo, &dir.path().join("sc"), "HEAD", (tenant_id, repo_id, 1), dl)
            .await?;
    ensure!(cand_oid != main_oid, "candidate commit must differ from main");

    git_cmd(&git_repo, &["checkout", "--orphan", "orphan"], None)?;
    git_cmd(&git_repo, &["read-tree", "--empty"], None)?;
    std::fs::remove_file(git_repo.join("main.txt"))?;
    std::fs::remove_file(git_repo.join("cand.txt"))?;
    std::fs::write(git_repo.join("orphan.txt"), b"refcas-orphan")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "orphan"], None)?;
    let (p_orph, p_orph_rec, i_orph, i_orph_rec, _orph_oid, oids_orph) =
        build_pack_via_opendal(&provider, &git_repo, &dir.path().join("so"), "HEAD", (tenant_id, repo_id, 1), dl)
            .await?;

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
    let pre_deletes = s3.state.delete_requests.load(Ordering::SeqCst);
    unsafe {
        for (k, v) in s3.env_pairs() {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        std::env::set_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "false");
    }
    // Default-off compaction: one replacement pack active, both old packs retired.
    assert_eq!(scheduler::schedule_once(&state, &policy).await?, 1);
    let repacked = worker::run_once(&state, &policy, Uuid::new_v4()).await?.context("default-off repack")?;
    assert_eq!(repacked.kind, "pando_repack");
    assert_eq!(repacked.state, "succeeded");
    assert_eq!(s3.state.delete_requests.load(Ordering::SeqCst), pre_deletes, "0 deletes when default-off");
    let snap_off = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    assert_eq!(snap_off.snapshot().active_packs.len(), 1);
    let rep_pack_loc = snap_off.snapshot().active_packs[0].pack_locator.to_locator()?;
    let rep_idx_loc = snap_off.snapshot().active_packs[0].idx_locator.to_locator()?;
    drop(snap_off);

    let producer = PullRemoteMergeProducer::new(&rig.backend, &pg_store, &rig.keyring);
    let (happy_spec, happy_pull) =
        build_refcas_merge_attempt(&rig, &base_oid, &main_oid, &main_oid, 1, 1, rig.token_scope_id).await?;
    let committed = producer.execute_merge(&happy_spec, &happy_pull, false, MergeFaultInjection::None).await?;
    ensure!(matches!(committed, MergeAttemptOutcome::Committed(_)), "install→commit must commit");
    assert_eq!(rig.backend.read_ref_oid(repo_id, "refs/heads/main").await?, Some(main_oid.clone()));

    let (spec_a, pull_a) =
        build_refcas_merge_attempt(&rig, &main_oid, &cand_oid, &cand_oid, 2, 2, rig.token_scope_id).await?;
    let validated_a = verify_pull_remote_authz_grant(&spec_a, &pull_a, &rig.keyring)?;
    let cancel_identity = validated_a.commit_cmd.commit.request.identity.clone();
    rig.backend.set_abort_after_install_once(true);
    let aborted = producer.execute_merge(&spec_a, &pull_a, false, MergeFaultInjection::None).await.unwrap_err();
    ensure!(matches!(aborted, RemoteMergeError::UnknownOutcome(_)), "install abort must surface UnknownOutcome");
    assert_eq!(attempt_state(&pool, repo_id, spec_a.operation_id).await?, "pending_merge");
    // Project commit + install so the PG cursor is current while the decision stays open.
    let sm_installed = rig.backend.state_machine().await?;
    project_all_refcas_events(&pool, tenant_id, repo_id, ProjectionRealm::new(history_id, 0, 1)?, &sm_installed)
        .await?;

    let armed = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    let armed_snap = armed.snapshot();
    let lane_arm = seal_test_lane_arm(
        tenant_id,
        repo_id,
        history_id,
        auth_rec.incarnation_id,
        1,
        test_dist_lane(tenant_id, repo_id, history_id, 1, 1, &armed_snap.global_holds, SafeGcObjectFormat::Sha1),
    )?;
    armed.set_gc_mode(GcMode::ArmedDestructive(Box::new(lane_arm)))?;
    drop(armed);
    unsafe {
        std::env::set_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "true");
    }

    let (failed, err) = worker_pass_with_error(&state, &pool, &policy, repo_id).await?;
    assert_eq!(failed, "failed", "open in-flight decision must fail closed");
    ensure!(err.contains("in-flight decision"), "expected in-flight decision barrier, got {err}");
    assert_eq!(s3.state.delete_requests.load(Ordering::SeqCst), pre_deletes);
    assert_eq!(rig.backend.read_ref_oid(repo_id, "refs/heads/main").await?, Some(main_oid.clone()));

    // Revoke the attempt's token scope, then replay the installed decision; commit is refused.
    rig.backend
        .apply_repo_command(RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
            scope_kind: "token".into(),
            scope_id: rig.token_scope_id,
            repository_id: None,
            tenant_id: Some(tenant_id),
            lifecycle: ScopeLifecycle::Closing,
            authz_floor: 9,
            change_id: Uuid::new_v4(),
            logical_tick: 20,
        }))
        .await
        .map_err(|err| anyhow::anyhow!("close auth scope through Raft: {err}"))?;
    let revoked = producer.execute_merge(&spec_a, &pull_a, false, MergeFaultInjection::None).await.unwrap_err();
    ensure!(matches!(revoked, RemoteMergeError::RevokedAuthorization(_)), "replay must be revoked, got {revoked:?}");
    assert_eq!(attempt_state(&pool, repo_id, spec_a.operation_id).await?, "rejected_merge");
    let (failed, err) = worker_pass_with_error(&state, &pool, &policy, repo_id).await?;
    assert_eq!(failed, "failed");
    ensure!(
        err.contains("in-flight decision") || err.contains("unprojected Ref-CAS commits"),
        "expected a fail-closed Ref-CAS barrier, got {err}"
    );
    assert_eq!(s3.state.delete_requests.load(Ordering::SeqCst), pre_deletes);
    assert_eq!(rig.backend.read_ref_oid(repo_id, "refs/heads/main").await?, Some(main_oid.clone()));

    rig.backend
        .apply_repo_command(RefCasCommand::Cancel(CancelCommand {
            identity: cancel_identity,
            reason: Some("lifecycle cancellation".into()),
            logical_tick: 21,
        }))
        .await
        .map_err(|err| anyhow::anyhow!("cancel operation through Raft: {err}"))?;
    let cancelled = rig.backend.query_operation_outcome(repo_id, spec_a.operation_id, "refs/heads/main").await?;
    ensure!(
        matches!(cancelled, Some(rootyard::pulls::remote_merge_finalizer::AuthorityCommitOutcome::Cancelled { .. })),
        "cancelled operation must resolve as Cancelled"
    );

    let (spec_b, pull_b) =
        build_refcas_merge_attempt(&rig, &base_oid, &cand_oid, &cand_oid, 2, 3, Uuid::new_v4()).await?;
    let rejected = producer.execute_merge(&spec_b, &pull_b, false, MergeFaultInjection::None).await.unwrap_err();
    ensure!(matches!(rejected, RemoteMergeError::TargetRefMoved { .. }), "stale base must be OldOidMismatch");
    assert_eq!(attempt_state(&pool, repo_id, spec_b.operation_id).await?, "rejected_merge");
    // The cancelled decision no longer blocks: project every terminal and sweep both retired packs.
    let sm_final = rig.backend.state_machine().await?;
    project_all_refcas_events(&pool, tenant_id, repo_id, ProjectionRealm::new(history_id, 0, 1)?, &sm_final).await?;
    assert_eq!(worker_pass(&state, &pool, &policy, repo_id).await?, "succeeded");

    assert!(!s3.has_key(&p_main) && !s3.has_key(&i_main));
    assert!(!s3.has_key(&p_orph) && !s3.has_key(&i_orph));
    assert!(s3.has_key(&rep_pack_loc) && s3.has_key(&rep_idx_loc));
    let verify_dir = dir.path().join("verify-pg-lifecycle");
    let (pk_dst, ix_dst) = (verify_dir.join("objects/pack/surv.pack"), verify_dir.join("objects/pack/surv.idx"));
    std::fs::create_dir_all(pk_dst.parent().unwrap())?;
    git_cmd(&verify_dir, &["init", "--bare", "--object-format=sha1"], None)?;
    blob_store.get_to_file(&rep_pack_loc, &pk_dst, dl).await?;
    blob_store.get_to_file(&rep_idx_loc, &ix_dst, dl).await?;
    git_cmd(&verify_dir, &["update-ref", "refs/heads/main", &main_oid], None)?;
    git_cmd(&verify_dir, &["fsck", "--full", "--strict"], None)?;
    unsafe {
        std::env::remove_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE);
    }
    Ok(())
}
