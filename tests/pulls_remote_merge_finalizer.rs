//! Stock-Git (`SHA-1`/`SHA-256`) + Ref-CAS + PG17 + 3-node mTLS Raft integration tests (`Refs #156`).

#[path = "pulls_remote_merge_support/mod.rs"]
mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use deadpool_postgres::{Manager, Pool};
use rootyard::db;
use rootyard::pulls::remote_merge_finalizer::{
    AuthorityCommitOutcome, InMemoryMergeStore, InProcessRefCasBackend, MergeAttemptOutcome, MergeAuthorityBackend,
    MergeFaultInjection, MergeReceiptStore, MergeStrategy, PgMergeStore, PrepareMergeInput, ProjectedPullRecord,
    ProjectionOutcome, PullMergeReceiptProjector, PullMergeState, PullRemoteMergeProducer,
    RecoverablePullMergeFinalizer, RemoteMergeError, init_remote_merge_tables, prepare_merge_candidate,
    verify_pull_remote_authz_grant,
};
use rootyard::ref_store::core::state_machine::{
    AppliedLogId, CloseAuthScopeCommand, RefCasCommand, RefCasStateMachine, ScopeLifecycle,
};
use rootyard::ref_store::core::types::GitObjectFormat;
use support::ctx::{BuildArgs, TestCtx, git_ok, setup_git_repo};
use support::raft::{LiveRaft3, LiveRaft3Backend};
use tempfile::TempDir;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

fn seed_pull_rec(store: &InMemoryMergeStore, ctx: &TestCtx, n: i64, h: &str, b: &str) {
    store.seed_pull(ProjectedPullRecord {
        tenant_id: ctx.tenant,
        repository_id: ctx.repo,
        pull_number: n,
        state: "open".into(),
        head_oid: h.into(),
        base_oid: b.into(),
        merge_commit_oid: None,
        merged_storage_generation: None,
        version: 1,
    });
}

#[tokio::test]
async fn stock_git_sha1_and_sha256_merge_pack_refcas_sole_commit_and_idempotent_projection() -> Result<()> {
    let dl = Instant::now() + Duration::from_secs(30);
    for fmt in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let dir = TempDir::new()?;
        let (base, h1, h2) = setup_git_repo(dir.path(), fmt)?;
        let c1 = prepare_merge_candidate(
            dir.path(),
            &PrepareMergeInput {
                format: fmt,
                strategy: MergeStrategy::FastForward,
                base_oid: &base,
                head_oid: &h1,
                author_name: "a",
                commit_message: "pr1",
            },
            dl,
        )
        .await?;
        let c2 = prepare_merge_candidate(
            dir.path(),
            &PrepareMergeInput {
                format: fmt,
                strategy: MergeStrategy::MergeCommit,
                base_oid: &h1,
                head_oid: &h2,
                author_name: "a",
                commit_message: "pr2",
            },
            dl,
        )
        .await?;
        assert!(c1.target_oid == h1 && c2.target_oid != h2 && !c1.pack_bytes.is_empty());
        assert_eq!(git_ok(dir.path(), &["rev-parse", "refs/heads/main"])?, base);

        let ctx = TestCtx::new(fmt);
        let (sc1, sc2) = ctx.seed_cmds(&base);
        let mut sm = RefCasStateMachine::new();
        sm.apply(AppliedLogId { term: 1, index: 1 }, sc1).unwrap();
        sm.apply(AppliedLogId { term: 1, index: 2 }, sc2).unwrap();
        let gv1 = sm.read_gate_version(ctx.repo).unwrap().unwrap();
        let backend = InProcessRefCasBackend::new(sm);
        let store = InMemoryMergeStore::new();
        seed_pull_rec(&store, &ctx, 1, &h1, &base);
        seed_pull_rec(&store, &ctx, 2, &h2, &h1);

        let prod = PullRemoteMergeProducer::new(&backend, &store, &ctx.keyring);
        let (s1, p1) = ctx.build(BuildArgs {
            num: 1,
            seq: 1,
            base: &base,
            head: &h1,
            target: &c1.target_oid,
            strat: MergeStrategy::FastForward,
            rev: gv1.revision(),
            gd: &gv1.digest().as_hex(),
            psha: &c1.pack_sha256,
        });
        let MergeAttemptOutcome::Committed(rec1) =
            prod.execute_merge(&s1, &p1, true, MergeFaultInjection::None).await?
        else {
            bail!("commit 1");
        };
        assert_eq!(
            PullMergeReceiptProjector::new(&store).project_committed(&rec1, 1, 1, true).await?,
            ProjectionOutcome::ProjectedCommitted { replayed: true }
        );
        let gv2 = backend.state_machine().read_gate_version(ctx.repo).unwrap().unwrap();
        let (s2, p2) = ctx.build(BuildArgs {
            num: 2,
            seq: 2,
            base: &h1,
            head: &h2,
            target: &c2.target_oid,
            strat: MergeStrategy::MergeCommit,
            rev: gv2.revision(),
            gd: &gv2.digest().as_hex(),
            psha: &c2.pack_sha256,
        });
        let MergeAttemptOutcome::Committed(rec2) =
            prod.execute_merge(&s2, &p2, true, MergeFaultInjection::None).await?
        else {
            bail!("commit 2");
        };
        assert_eq!(backend.read_ref_oid(ctx.repo, "refs/heads/main").await?, Some(c2.target_oid));
        assert_eq!(store.get_pull(ctx.repo, 2).unwrap().merge_commit_oid, Some(rec2.merged_oid));
    }
    Ok(())
}

#[tokio::test]
async fn concurrent_same_ref_pr_stream_and_crash_timeout_reconciler() -> Result<()> {
    let dl = Instant::now() + Duration::from_secs(30);
    let dir = TempDir::new()?;
    let (base, h1, h2) = setup_git_repo(dir.path(), GitObjectFormat::Sha256)?;
    let c1 = prepare_merge_candidate(
        dir.path(),
        &PrepareMergeInput {
            format: GitObjectFormat::Sha256,
            strategy: MergeStrategy::FastForward,
            base_oid: &base,
            head_oid: &h1,
            author_name: "a",
            commit_message: "p1",
        },
        dl,
    )
    .await?;
    let c2 = prepare_merge_candidate(
        dir.path(),
        &PrepareMergeInput {
            format: GitObjectFormat::Sha256,
            strategy: MergeStrategy::MergeCommit,
            base_oid: &base,
            head_oid: &h2,
            author_name: "b",
            commit_message: "p2",
        },
        dl,
    )
    .await?;

    let ctx = TestCtx::new(GitObjectFormat::Sha256);
    let (sc1, sc2) = ctx.seed_cmds(&base);
    let mut sm = RefCasStateMachine::new();
    sm.apply(AppliedLogId { term: 1, index: 1 }, sc1).unwrap();
    sm.apply(AppliedLogId { term: 1, index: 2 }, sc2).unwrap();
    let gv = sm.read_gate_version(ctx.repo).unwrap().unwrap();
    let backend = InProcessRefCasBackend::new(sm);
    let store = InMemoryMergeStore::new();
    seed_pull_rec(&store, &ctx, 1, &h1, &base);
    seed_pull_rec(&store, &ctx, 2, &h2, &base);

    let (s1, p1) = ctx.build(BuildArgs {
        num: 1,
        seq: 1,
        base: &base,
        head: &h1,
        target: &c1.target_oid,
        strat: MergeStrategy::FastForward,
        rev: gv.revision(),
        gd: &gv.digest().as_hex(),
        psha: &c1.pack_sha256,
    });
    let (s2, p2) = ctx.build(BuildArgs {
        num: 2,
        seq: 2,
        base: &base,
        head: &h2,
        target: &c2.target_oid,
        strat: MergeStrategy::MergeCommit,
        rev: gv.revision(),
        gd: &gv.digest().as_hex(),
        psha: &c2.pack_sha256,
    });
    let prod = PullRemoteMergeProducer::new(&backend, &store, &ctx.keyring);
    let (r1, r2) = tokio::join!(
        prod.execute_merge(&s1, &p1, true, MergeFaultInjection::CoordinatorTimeoutAfterCasBeforeProjection),
        prod.execute_merge(&s2, &p2, true, MergeFaultInjection::None),
    );
    assert!(r1.is_err() || r2.is_err());
    let _ = RecoverablePullMergeFinalizer::new(&backend, &store).reconcile_pending(ctx.repo, true).await?;
    let merged: Vec<_> =
        [1, 2].into_iter().filter_map(|n| store.get_pull(ctx.repo, n)).filter(|p| p.state == "merged").collect();
    assert_eq!(merged.len(), 1);
    assert_eq!(backend.read_ref_oid(ctx.repo, "refs/heads/main").await?, merged[0].merge_commit_oid);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires multi-process raft-node binary, openssl, and PostgreSQL 17"]
async fn e2e_pg17_mtls_raft3_stock_git_merge_crash_recovery_and_concurrent_race() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL").context("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&url)?;
    let schema = format!("pulls156_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut cfg: tokio_postgres::Config = url.parse()?;
    cfg.options(format!("-c search_path={schema} -c timezone=UTC"));
    let pool = Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(8)
        .build()?;
    db::migrate(&pool).await?;
    init_remote_merge_tables(&pool).await?;

    let ctx = TestCtx::new(GitObjectFormat::Sha256);
    let pgc = pool.get().await?;
    pgc.execute(
        "INSERT INTO users(id,username) VALUES($1,$2)",
        &[&ctx.tenant, &format!("u{}", &ctx.tenant.simple().to_string()[..8])],
    )
    .await?;
    pgc.execute(
        "INSERT INTO repositories(id,owner_id,name,state,object_format) VALUES($1,$2,'r156','ready','sha256')",
        &[&ctx.repo, &ctx.tenant],
    )
    .await?;

    let dir = TempDir::new()?;
    let (base, h1, h2) = setup_git_repo(dir.path(), GitObjectFormat::Sha256)?;
    let dl = Instant::now() + Duration::from_secs(30);
    let c1 = prepare_merge_candidate(
        dir.path(),
        &PrepareMergeInput {
            format: GitObjectFormat::Sha256,
            strategy: MergeStrategy::FastForward,
            base_oid: &base,
            head_oid: &h1,
            author_name: "u",
            commit_message: "pr1",
        },
        dl,
    )
    .await?;
    let c2 = prepare_merge_candidate(
        dir.path(),
        &PrepareMergeInput {
            format: GitObjectFormat::Sha256,
            strategy: MergeStrategy::MergeCommit,
            base_oid: &base,
            head_oid: &h2,
            author_name: "u",
            commit_message: "pr2",
        },
        dl,
    )
    .await?;
    for (num, hr, ho) in [(1i64, "refs/heads/pr-1", &h1), (2i64, "refs/heads/pr-2", &h2)] {
        pgc.execute("INSERT INTO forge_pulls(tenant_id,repository_id,number,author_id,title,head_ref,base_ref,head_oid,base_oid) VALUES($1,$2,$3,$1,'p',$4,'refs/heads/main',$5,$6)", &[&ctx.tenant, &ctx.repo, &num, &hr, ho, &base]).await?;
    }

    let mut raft = LiveRaft3::start().await?;
    let (sc1, sc2) = ctx.seed_cmds(&base);
    raft.append(&sc1).await?;
    let (_, sm_seed, _) = raft.append(&sc2).await?;
    let gv = sm_seed.read_gate_version(ctx.repo).unwrap().unwrap();
    let shared = Arc::new(AsyncMutex::new(raft));
    let backend = LiveRaft3Backend(Arc::clone(&shared));
    let pg_store = PgMergeStore::new(pool.clone());
    let prod = PullRemoteMergeProducer::new(&backend, &pg_store, &ctx.keyring);

    let (s1, p1) = ctx.build(BuildArgs {
        num: 1,
        seq: 1,
        base: &base,
        head: &h1,
        target: &c1.target_oid,
        strat: MergeStrategy::FastForward,
        rev: gv.revision(),
        gd: &gv.digest().as_hex(),
        psha: &c1.pack_sha256,
    });
    assert!(matches!(
        prod.execute_merge(&s1, &p1, true, MergeFaultInjection::CoordinatorTimeoutAfterCasBeforeProjection).await,
        Err(RemoteMergeError::UnknownOutcome(_))
    ));
    shared.lock().await.restart_leader().await?;
    let rep = RecoverablePullMergeFinalizer::new(&backend, &pg_store).reconcile_pending(ctx.repo, true).await?;
    assert_eq!(rep.committed, 1);
    let a1 = pg_store.load_attempt(ctx.repo, s1.operation_id).await?.context("a1")?;
    let orig_idx1 = a1.commit_log_index.context("orig_idx1")?;
    let r1 = pgc
        .query_one("SELECT state, merge_commit_oid FROM forge_pulls WHERE repository_id=$1 AND number=1", &[&ctx.repo])
        .await?;
    assert_eq!(
        (r1.get::<_, String>(0).as_str(), r1.get::<_, Option<String>>(1).as_deref()),
        ("merged", Some(c1.target_oid.as_str()))
    );

    let (s2, p2) = ctx.build(BuildArgs {
        num: 2,
        seq: 2,
        base: &base,
        head: &h2,
        target: &c2.target_oid,
        strat: MergeStrategy::MergeCommit,
        rev: gv.revision(),
        gd: &gv.digest().as_hex(),
        psha: &c2.pack_sha256,
    });
    assert!(matches!(
        prod.execute_merge(&s2, &p2, true, MergeFaultInjection::None).await,
        Err(RemoteMergeError::TargetRefMoved { .. })
    ));
    let r2 = pgc
        .query_one("SELECT state, merge_commit_oid FROM forge_pulls WHERE repository_id=$1 AND number=2", &[&ctx.repo])
        .await?;
    assert_eq!((r2.get::<_, String>(0).as_str(), r2.get::<_, Option<String>>(1)), ("open", None));
    assert_eq!(backend.read_ref_oid(ctx.repo, "refs/heads/main").await?, Some(c1.target_oid.clone()));

    let close_cmd = RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
        scope_kind: "token".into(),
        scope_id: ctx.scope_id,
        repository_id: Some(ctx.repo),
        tenant_id: Some(ctx.tenant),
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 99,
        change_id: Uuid::new_v4(),
        logical_tick: 50,
    });
    let (_, sm_closed, _) = shared.lock().await.append(&close_cmd).await?;
    assert_eq!(sm_closed.read_scope_floor("token", ctx.scope_id).unwrap().authz_floor, 99);

    let v1 = verify_pull_remote_authz_grant(&s1, &p1, &ctx.keyring)?;
    assert!(matches!(
        backend.install_and_commit_scoped(ctx.repo, &s1.base_ref, v1.install_cmd, v1.commit_cmd).await?,
        AuthorityCommitOutcome::Committed { ref merged_oid, log_index, replayed: true, .. }
            if merged_oid == &c1.target_oid && log_index == orig_idx1
    ));
    assert!(matches!(
        backend.query_operation_outcome(ctx.repo, s1.operation_id, "refs/heads/main").await?,
        Some(AuthorityCommitOutcome::Committed { ref merged_oid, log_index, replayed: true, .. })
            if merged_oid == &c1.target_oid && log_index == orig_idx1
    ));

    let mut bad_committed = a1.into_committed_receipt(
        c1.target_oid.clone(),
        orig_idx1,
        a1.commit_log_term.context("orig_term1")?,
        gv.revision() + 1,
        a1.terminal_digest.clone().context("td1")?,
        true,
    );
    bad_committed.binding_digest = "ff".repeat(32);
    assert!(matches!(
        pg_store.project_committed(&bad_committed, 1, 1, true).await,
        Err(RemoteMergeError::Equivocation(_))
    ));

    let mut pending_rec = a1.clone();
    pending_rec.operation_id = Uuid::new_v4();
    pending_rec.attempt_id = Uuid::new_v4();
    pending_rec.pull_number = 2;
    pending_rec.state = PullMergeState::PendingMerge;
    pending_rec.commit_log_index = None;
    pending_rec.commit_log_term = None;
    pending_rec.merged_oid = None;
    pending_rec.terminal_digest = None;
    pending_rec.reject_reason = None;
    pg_store.insert_pending(&pending_rec).await?;
    let mut bad_pending_comm = pending_rec.into_committed_receipt(
        pending_rec.candidate_target_oid.clone(),
        orig_idx1,
        1,
        gv.revision() + 1,
        "aa".repeat(32),
        false,
    );
    bad_pending_comm.attempt_id = Uuid::new_v4();
    assert!(matches!(
        pg_store.project_committed(&bad_pending_comm, 1, 1, true).await,
        Err(RemoteMergeError::Equivocation(_))
    ));
    drop(pgc);
    let _ = admin.get().await?.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE")).await;
    Ok(())
}
