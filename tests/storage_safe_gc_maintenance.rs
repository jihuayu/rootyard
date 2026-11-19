//! Real PG17 + `storage_lifecycle` scheduler/worker + OpenDAL S3 Safe GC acceptance (#122).

#[path = "storage_safe_gc_support/dist_auth_harness.rs"]
pub mod dist_auth_harness;
#[path = "storage_safe_gc_support/pg_child_worker.rs"]
mod pg_child_worker;
#[path = "storage_safe_gc_support/pg_refcas_cases.rs"]
mod pg_refcas_cases;
#[path = "storage_safe_gc_support/pg_refcas_lifecycle_cases.rs"]
mod pg_refcas_lifecycle_cases;
#[path = "storage_safe_gc_support/pg_refcas_merge_fixture.rs"]
mod pg_refcas_merge_fixture;
#[path = "storage_safe_gc_support/pg_refcas_restart_cases.rs"]
mod pg_refcas_restart_cases;
#[path = "storage_safe_gc_support/raft_voter_cluster.rs"]
mod raft_voter_cluster;
#[path = "storage_safe_gc_support/s3_harness.rs"]
pub mod s3_harness;

use std::{
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, ensure};
use base64::Engine as _;
use deadpool_postgres::{Manager, Pool};
use rootyard::{
    AppState, auth,
    blob_store::disposable_view::DisposableViewRoot,
    config::Config,
    db, dispatch, metrics,
    ref_store::{
        core::types::GitObjectFormat,
        serving::{ProvisionRequest, provision},
    },
    storage::{self, read_leases},
    storage_lifecycle::{
        models::Policy,
        safe_gc::{
            ENV_BLOB_SAFE_GC_DESTRUCTIVE, SafeGcError,
            anti_aba::AntiAbaKeyRegistry,
            compaction::{CompactionFault, SafeGcCompactionRequest, execute_two_phase_compaction},
            domain::{AuthorityRecord, StagedUploadState},
            executor::reconcile_pending_delete_after_restart,
            model::{AuthorityLane, GcMode, SafeGcObjectFormat},
            pg_maintenance::safe_gc_journal_path,
            store::DurableSafeGcAuthority,
        },
        scheduler, worker,
    },
};
use s3_harness::{LoopbackS3, build_pack_via_opendal, build_snapshot, git_cmd, make_serving_record};
use tempfile::TempDir;
use tokio::sync::Semaphore;
use uuid::Uuid;

pub(crate) static PG_SAFE_GC_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) fn test_policy() -> Policy {
    Policy {
        enabled: true,
        poll: Duration::from_secs(1),
        lease_seconds: 15,
        loose_threshold: 1,
        pack_threshold: 2,
        stage_age_seconds: 1,
        cache_max_age_seconds: 60,
        tombstone_grace_seconds: 1,
        scan_period_seconds: 1,
        quiescence_seconds: 2,
        max_attempts: 3,
    }
}

pub(crate) fn app_config(root: &Path, db_url: String) -> Config {
    let git_bin = std::env::var("ROOTYARD_GIT")
        .or_else(|_| std::env::var("ROOTYARD_GIT_PATH"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let usr = PathBuf::from("/usr/bin/git");
            if usr.exists() { usr } else { PathBuf::from("git") }
        });
    Config {
        database_url: db_url,
        data_dir: root.join("server-data"),
        bind: "127.0.0.1:0".parse().unwrap(),
        git: git_bin,
        max_request_bytes: 64 * 1024 * 1024,
        max_output_bytes: 64 * 1024 * 1024,
        max_concurrent_git: 2,
        git_timeout: Duration::from_secs(60),
        git_memory_bytes: 512 * 1024 * 1024,
        max_repo_bytes: 512 * 1024 * 1024,
        max_pending_deliveries: 1_000,
        outbox_worker: false,
        metrics_bind: None,
    }
}

pub(crate) async fn open_pg_pool_for_schema(url: &str, schema: &str) -> Result<Pool> {
    let mut cfg: tokio_postgres::Config = url.parse()?;
    cfg.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=5000 -c lock_timeout=3000"));
    Ok(Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(8)
        .build()?)
}

pub(crate) async fn isolated_pg_pool_with_schema(url: &str) -> Result<(Pool, String)> {
    let admin = db::pool(url)?;
    let schema = format!("safegc122_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let pool = open_pg_pool_for_schema(url, &schema).await?;
    db::migrate(&pool).await?;
    Ok((pool, schema))
}

pub(crate) async fn isolated_pg_pool(url: &str) -> Result<Pool> {
    Ok(isolated_pg_pool_with_schema(url).await?.0)
}

pub(crate) async fn provision_pg_refstore_repo(
    pool: &Pool,
    store: &rootyard::blob_store::opendal::BlobStore,
) -> Result<(Uuid, Uuid, Uuid)> {
    let username = format!("sgc{}", &Uuid::new_v4().simple().to_string()[..12]);
    let issued = db::issue_token(pool, &username, true, false).await?;
    let user_id: Uuid = issued["user_id"].as_str().context("user_id")?.parse()?;
    let secret = issued["token"].as_str().context("token")?;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{secret}"));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(axum::http::header::AUTHORIZATION, format!("Basic {basic}").parse()?);
    let actor = auth::authenticate(pool, &headers).await.map_err(|e| anyhow!("auth failed: {}", e.1))?;

    let receipt = provision(
        pool,
        &actor,
        ProvisionRequest { owner: None, name: "safe-gc-repo".into(), object_format: GitObjectFormat::Sha1 },
        store.backend_identity(),
        tokio::time::Instant::now() + Duration::from_secs(30),
    )
    .await
    .map_err(|e| anyhow!("provision failed: {}", e.1))?;
    let repo_id = receipt.repository.id;
    let row = pool
        .get()
        .await?
        .query_one("SELECT history_incarnation FROM ref_store_serving_repositories WHERE repository_id=$1", &[&repo_id])
        .await?;
    Ok((user_id, repo_id, row.get(0)))
}

async fn insert_transient_serving_read_pin(
    pool: &Pool,
    repo_id: Uuid,
    tenant_id: Uuid,
    history_id: Uuid,
    backend_hex: &str,
    head_oid: &str,
    pack_id: Uuid,
) -> Result<Uuid> {
    let pin_id = Uuid::new_v4();
    let snap_id = Uuid::new_v4();
    let d = |ch: char| -> String { std::iter::repeat_n(ch, 64).collect() };
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO ref_store_core_serving_reads( \
               pin_id,snapshot_id,generation,repository_id,tenant_id,owner_id,purpose,object_format, \
               history_incarnation,authority_epoch,group_epoch,backend_identity,gate_revision,gate_digest, \
               head_ref,head_oid,ref_count,refs_digest,pack_count,membership_digest,snapshot_digest, \
               logical_bytes,lease_seconds,expires_at) \
             VALUES($1,$2,1,$3,$4,$4,'verification','sha1',$5,1,1,$6,1,$7, \
               'refs/heads/main',$8,1,$9,1,$10,$11,1024,60,clock_timestamp()+interval '60 seconds')",
            &[
                &pin_id,
                &snap_id,
                &repo_id,
                &tenant_id,
                &history_id,
                &backend_hex,
                &d('a'),
                &head_oid,
                &d('b'),
                &d('c'),
                &d('d'),
            ],
        )
        .await?;
    client
        .execute(
            "INSERT INTO ref_store_core_serving_read_packs( \
               pin_id,pack_id,registration_id,artifact_set_digest,joined_revision) \
             VALUES($1,$2,$3,$4,1)",
            &[&pin_id, &pack_id, &Uuid::new_v4(), &d('e')],
        )
        .await?;
    Ok(pin_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_pg17_scheduler_worker_default_off_staging_restart_fence_and_opendal_s3_safe_gc() -> Result<()> {
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

    let (tenant_id, repo_id, history_id) = provision_pg_refstore_repo(&pool, &blob_store).await?;
    let dl = Instant::now() + Duration::from_secs(60);

    let git_repo = dir.path().join("src.git");
    std::fs::create_dir_all(&git_repo)?;
    git_cmd(&git_repo, &["init", "--object-format=sha1", "--initial-branch=main"], None)?;
    std::fs::write(git_repo.join("main.txt"), b"main-v1")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "main"], None)?;
    let (p_main, p_main_rec, i_main, i_main_rec, main_oid, oids_main) =
        build_pack_via_opendal(&provider, &git_repo, &dir.path().join("sm"), "HEAD", (tenant_id, repo_id, 1), dl)
            .await?;

    git_cmd(&git_repo, &["checkout", "-b", "pr-branch"], None)?;
    std::fs::write(git_repo.join("pr.txt"), b"pr-feature")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "pr"], None)?;
    let (p_pr, p_pr_rec, i_pr, i_pr_rec, pr_oid, oids_pr) =
        build_pack_via_opendal(&provider, &git_repo, &dir.path().join("sp"), "HEAD", (tenant_id, repo_id, 1), dl)
            .await?;

    git_cmd(&git_repo, &["checkout", "--orphan", "dead_orphan"], None)?;
    git_cmd(&git_repo, &["read-tree", "--empty"], None)?;
    std::fs::remove_file(git_repo.join("main.txt"))?;
    std::fs::remove_file(git_repo.join("pr.txt"))?;
    std::fs::write(git_repo.join("orphan.txt"), b"unreferenced")?;
    git_cmd(&git_repo, &["add", "."], None)?;
    git_cmd(&git_repo, &["commit", "-m", "orphan"], None)?;
    let (p_orph, p_orph_rec, i_orph, i_orph_rec, _orphan_oid, oids_orph) =
        build_pack_via_opendal(&provider, &git_repo, &dir.path().join("so"), "HEAD", (tenant_id, repo_id, 1), dl)
            .await?;

    let pgc = pool.get().await?;
    pgc.execute(
        "INSERT INTO ref_store_core_refs(repository_id,ref_name,oid,revision) VALUES($1,'refs/heads/main',$2,1)",
        &[&repo_id, &main_oid],
    )
    .await?;
    pgc.execute(
        "INSERT INTO forge_pulls(tenant_id,repository_id,number,author_id,title,head_ref,base_ref,head_oid,base_oid) \
         VALUES($1,$2,1,$1,'keep-pr','refs/heads/pr-branch','refs/heads/main',$3,$4)",
        &[&tenant_id, &repo_id, &pr_oid, &main_oid],
    )
    .await?;
    drop(pgc);

    let auth_rec = AuthorityRecord {
        tenant_id,
        repo_id,
        history_id,
        trusted_arm_pubkey_hex: dist_auth_harness::test_arm_signer().pubkey_hex().to_owned(),
        incarnation_id: Uuid::new_v4(),
        incarnation_epoch: 1,
        membership_generation: 1,
        live_ref_seq: 1,
        lease_epoch: 1,
    };
    dist_auth_harness::provision_single_node_trust(&state.storage.root, tenant_id, repo_id, history_id)?;
    let mut reg = AntiAbaKeyRegistry::new();
    let srv_main = make_serving_record(&mut reg, &auth_rec, p_main_rec, i_main_rec, oids_main);
    let srv_pr = make_serving_record(&mut reg, &auth_rec, p_pr_rec, i_pr_rec, oids_pr);
    let srv_orph = make_serving_record(&mut reg, &auth_rec, p_orph_rec, i_orph_rec, oids_orph);
    let journal = safe_gc_journal_path(&state.storage.root, repo_id);
    let snap = build_snapshot(
        auth_rec.clone(),
        SafeGcObjectFormat::Sha1,
        main_oid.clone(),
        vec![srv_main, srv_pr, srv_orph.clone()],
        reg,
        None,
    );
    let authority = DurableSafeGcAuthority::open_with_journal(&journal, Some(snap))?;

    // Seed an AbandonedPendingCleanup staging upload via corrupted PUT before default-off worker run!
    let tmp_views = DisposableViewRoot::open(&dir.path().join("tmp-views"), 4, 64 << 20, Duration::from_secs(60))?;
    s3.state.corrupt_next_put.store(true, Ordering::SeqCst);
    let bad_op = Uuid::new_v4();
    assert!(
        execute_two_phase_compaction(
            &authority,
            &blob_store,
            &provider,
            SafeGcCompactionRequest {
                op_id: bad_op,
                group_id: "g-main",
                blob_generation: 1,
                target_pack_ids: Vec::new(),
                view_root: &tmp_views,
                deadline: dl,
                fault: CompactionFault::None,
            },
        )
        .await
        .is_err()
    );
    let staged_entry = authority.snapshot().staged_uploads.into_iter().find(|u| u.op_id == bad_op).unwrap();
    assert_eq!(staged_entry.state, StagedUploadState::AbandonedPendingCleanup);
    let staged_pk_loc = staged_entry.pack_locator.to_locator()?;
    assert!(s3.has_key(&staged_pk_loc));
    drop(authority);

    let policy = test_policy();
    let worker_owner = Uuid::new_v4();

    // 1. Default-off maintenance run: compacts 3 -> 1, quarantines staging, and performs ZERO S3 deletes!
    let pre_default_off_deletes = s3.state.delete_requests.load(Ordering::SeqCst);
    let env_off = s3.env_pairs();
    unsafe {
        for (k, v) in env_off {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        std::env::set_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "false");
    }
    assert_eq!(scheduler::schedule_once(&state, &policy).await?, 1);
    let out1 = worker::run_once(&state, &policy, worker_owner).await?.context("worker repack job")?;
    assert_eq!(out1.kind, "pando_repack");
    assert_eq!(out1.state, "succeeded");
    assert_eq!(s3.state.delete_requests.load(Ordering::SeqCst), pre_default_off_deletes, "0 deletes when default-off");
    assert!(s3.has_key(&staged_pk_loc), "default-off worker must NOT delete abandoned remote staging");
    assert!(s3.has_key(&p_main) && s3.has_key(&p_pr) && s3.has_key(&p_orph));

    let reloaded = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    assert_eq!(reloaded.snapshot().active_packs.len(), 1);
    assert_eq!(reloaded.snapshot().retired_packs.len(), 3);
    assert!(reloaded.snapshot().audit_log.iter().any(|e| e.action == "quarantined_staging_delete_disabled"));
    let rep_pack_loc = reloaded.snapshot().active_packs[0].pack_locator.to_locator()?;
    let rep_idx_loc = reloaded.snapshot().active_packs[0].idx_locator.to_locator()?;

    // 2. Arm SingleNodePg destructive GC + enable ROOTYARD_BLOB_SAFE_GC_DESTRUCTIVE=true!
    let arm = dist_auth_harness::seal_test_lane_arm(
        tenant_id,
        repo_id,
        history_id,
        auth_rec.incarnation_id,
        1,
        AuthorityLane::SingleNodePg {
            pg_authority_id: repo_id,
            pg_tx_seq: 1,
            pg_gc_fence_epoch: 1,
            reader_barrier_epoch: 1,
        },
    )?;
    reloaded.set_gc_mode(GcMode::ArmedDestructive(Box::new(arm)))?;
    drop(reloaded);
    unsafe {
        std::env::set_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "true");
    }

    // 2a. Active transient serving-read pin in PostgreSQL blocks deletion!
    let pin_id = insert_transient_serving_read_pin(
        &pool,
        repo_id,
        tenant_id,
        history_id,
        blob_store.backend_identity().as_hex(),
        &main_oid,
        srv_orph.pack_id,
    )
    .await?;
    pool.get()
        .await?
        .execute("UPDATE storage_maintenance_repo_state SET last_scan_at = NULL WHERE repository_id = $1", &[&repo_id])
        .await?;
    assert_eq!(scheduler::schedule_once(&state, &policy).await?, 1);
    let blocked_read = worker::run_once(&state, &policy, worker_owner).await?.context("blocked by serving read")?;
    assert_eq!(blocked_read.state, "failed");
    assert!(s3.has_key(&p_orph) && s3.has_key(&i_orph));
    pool.get().await?.execute("DELETE FROM ref_store_core_serving_reads WHERE pin_id = $1", &[&pin_id]).await?;

    // 2b. Pending LFS upload blocks deletion!
    let lfs_sha: String = std::iter::repeat_n('7', 64).collect();
    pool.get()
        .await?
        .execute(
            "INSERT INTO lfs_objects(tenant_id,repository_id,oid,size,state) VALUES($1,$2,$3,128,'pending')",
            &[&tenant_id, &repo_id, &lfs_sha],
        )
        .await?;
    pool.get()
        .await?
        .execute("UPDATE storage_maintenance_repo_state SET last_scan_at = NULL WHERE repository_id = $1", &[&repo_id])
        .await?;
    assert_eq!(scheduler::schedule_once(&state, &policy).await?, 1);
    let blocked_lfs = worker::run_once(&state, &policy, worker_owner).await?.context("blocked by pending LFS")?;
    assert_eq!(blocked_lfs.state, "failed");
    assert!(s3.has_key(&p_orph));
    pool.get()
        .await?
        .execute("UPDATE lfs_objects SET state='ready' WHERE repository_id=$1 AND oid=$2", &[&repo_id, &lfs_sha])
        .await?;

    // 2c. Shared PG reader lease fences concurrent exclusive GC acquisition!
    let shared_pg_read =
        read_leases::shared(&pool, repo_id, tokio::time::Instant::now() + Duration::from_secs(5)).await.unwrap();
    shared_pg_read.ensure_active().unwrap();
    assert!(
        read_leases::exclusive(&pool, repo_id, tokio::time::Instant::now() + Duration::from_millis(200)).await.is_err()
    );
    drop(shared_pg_read);

    // 3. Armed sweep with injected HTTP 503 on i_orph -> leaves pending_delete OutcomeUnknown for restart recovery!
    *s3.state.fail_delete_substring.lock().unwrap() = Some(i_orph.sha256().to_owned());
    pool.get()
        .await?
        .execute("UPDATE storage_maintenance_repo_state SET last_scan_at = NULL WHERE repository_id = $1", &[&repo_id])
        .await?;
    assert_eq!(scheduler::schedule_once(&state, &policy).await?, 1);
    let partial_out = worker::run_once(&state, &policy, worker_owner).await?.context("partial sweep with 503")?;
    assert_eq!(partial_out.state, "failed");
    assert!(!s3.has_key(&staged_pk_loc), "armed run cleaned abandoned staging");
    assert!(!s3.has_key(&p_orph) && s3.has_key(&i_orph), "i_orph OutcomeUnknown must remain on S3");

    // 3a. Simulated restart: recovery WITHOUT live PG Lease + Fence (`None`) MUST fail closed!
    *s3.state.fail_delete_substring.lock().unwrap() = None;
    let restarted = DurableSafeGcAuthority::open_with_journal(&journal, None)?;
    assert!(restarted.snapshot().pending_delete.is_some());
    let cur = restarted.snapshot().authority;
    let unfenced_err = reconcile_pending_delete_after_restart(
        &restarted,
        &provider,
        cur.incarnation_id,
        cur.incarnation_epoch,
        cur.lease_epoch,
        dl,
    )
    .await;
    assert!(matches!(unfenced_err, Err(SafeGcError::StaleDeleterFenced(_))));
    assert!(s3.has_key(&i_orph), "unfenced restart call must NOT delete i_orph");
    drop(restarted);

    // 3b. Run scheduler::schedule_once + worker::run_once -> acquires live PG Lease + Fence & finishes i_orph!
    pool.get()
        .await?
        .execute("UPDATE storage_maintenance_repo_state SET last_scan_at = NULL WHERE repository_id = $1", &[&repo_id])
        .await?;
    assert_eq!(scheduler::schedule_once(&state, &policy).await?, 1);
    let sweep_out = worker::run_once(&state, &policy, worker_owner).await?.context("fenced restart recovery")?;
    assert_eq!(sweep_out.kind, "pando_tombstone_delete");
    assert_eq!(sweep_out.state, "succeeded");
    unsafe {
        std::env::remove_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE);
    }

    assert_eq!(s3.state.unconditional_delete_rejections.load(Ordering::SeqCst), 0);
    assert!(!s3.has_key(&p_main) && !s3.has_key(&i_main));
    assert!(!s3.has_key(&p_pr) && !s3.has_key(&i_pr));
    assert!(!s3.has_key(&p_orph) && !s3.has_key(&i_orph));
    assert!(s3.has_key(&rep_pack_loc) && s3.has_key(&rep_idx_loc));

    let verify_dir = dir.path().join("verify-pg-surviving");
    let (pk_dst, ix_dst) = (verify_dir.join("objects/pack/surv.pack"), verify_dir.join("objects/pack/surv.idx"));
    std::fs::create_dir_all(pk_dst.parent().unwrap())?;
    git_cmd(&verify_dir, &["init", "--bare", "--object-format=sha1"], None)?;
    blob_store.get_to_file(&rep_pack_loc, &pk_dst, dl).await?;
    blob_store.get_to_file(&rep_idx_loc, &ix_dst, dl).await?;
    git_cmd(&verify_dir, &["update-ref", "refs/heads/main", &main_oid], None)?;
    git_cmd(&verify_dir, &["update-ref", "refs/pull/1/head", &pr_oid], None)?;
    git_cmd(&verify_dir, &["fsck", "--full", "--strict"], None)?;
    Ok(())
}
