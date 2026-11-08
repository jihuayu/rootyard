//! Real-PostgreSQL contract tests for the isolated RefStore metadata core.
//!
//! Run explicitly by the root runner:
//! `ROOTYARD_TEST_DATABASE_URL=... cargo test --test ref_store_core -- --ignored`.
//! Selecting this suite without a database panics instead of silently passing.
//! The suite creates random task-owned schemas; it does not use an in-memory
//! fake, Vault, object storage or a long-lived request transaction.
use anyhow::{Context, Result};
use deadpool_postgres::{Manager, Pool};
use rootyard::db;
use rootyard::ref_store::{
    CancelReceipt, CommitMode, CommitRefsReceipt, CommitRefsRequest, CommitRejectCode, CoreGate, CoreGateInit,
    CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, OperationIdentity, OperationLookup,
    OperationState, PgRefStoreCore, RefName, RefPrecondition, RefStoreError, RefTarget, RefUpdate, TerminalKind,
    VersionCheck,
};
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set when running the ignored ref_store_core suite")
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(15)
}

fn lane() -> IssuerLane {
    IssuerLane::new("core-test").unwrap()
}

fn oid(format: GitObjectFormat, byte: u8) -> GitOid {
    match format {
        GitObjectFormat::Sha1 => GitOid::Sha1([byte; 20]),
        GitObjectFormat::Sha256 => GitOid::Sha256([byte; 32]),
    }
}

fn ref_name(value: &str) -> RefName {
    RefName::new(value).unwrap()
}

fn update(name: &str, old: Option<GitOid>, new: Option<GitOid>) -> RefUpdate {
    let precondition = match old {
        Some(old) => RefPrecondition::Present(old),
        None => RefPrecondition::Absent,
    };
    let target = match new {
        Some(new) => RefTarget::Oid(new),
        None => RefTarget::Delete,
    };
    RefUpdate::new(ref_name(name), precondition, target)
}

fn gate(repo: Uuid, tenant: Uuid, format: GitObjectFormat, history: Uuid, head: &str) -> CoreGateInit {
    CoreGateInit::new(repo, tenant, format, history, 1, 1, RefName::branch(head).unwrap()).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn request(
    repo: Uuid,
    tenant: Uuid,
    issuer: Uuid,
    sequence: i64,
    operation: Uuid,
    format: GitObjectFormat,
    history: Uuid,
    expected_revision: i64,
    head: HeadUpdate,
    refs: Vec<RefUpdate>,
) -> CommitRefsRequest {
    CommitRefsRequest::new(
        repo,
        tenant,
        issuer,
        lane(),
        sequence,
        operation,
        format,
        history,
        1,
        1,
        expected_revision,
        head,
        CommitMode::Atomic,
        refs,
    )
    .unwrap()
}

async fn setup() -> Result<(Pool, Pool, String, Uuid, Uuid)> {
    let url = database_url();
    let admin = db::pool(&url)?;
    let schema = format!("ref_store_core_test_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!(
        "-c search_path={schema} -c timezone=UTC -c statement_timeout=15000 -c lock_timeout=10000"
    ));
    let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(12)
        .build()?;
    db::migrate(&pool).await?;
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let username = format!("core{}", &tenant.simple().to_string()[..12]);
    let client = pool.get().await?;
    client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&tenant, &username]).await?;
    // The A1 bootstrap only accepts an explicitly unserved repository.
    client
        .execute(
            "INSERT INTO repositories(id,owner_id,name,state,object_format) VALUES($1,$2,'core','provisioning','sha1')",
            &[&repo, &tenant],
        )
        .await?;
    drop(client);
    Ok((admin, pool, schema, tenant, repo))
}

async fn teardown(admin: &Pool, schema: &str) -> Result<()> {
    admin.get().await?.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await?;
    Ok(())
}

fn pool_error(error: deadpool_postgres::PoolError) -> RefStoreError {
    RefStoreError::Database(error.to_string())
}

async fn initialize(pool: &Pool, init: &CoreGateInit) -> Result<CoreGate, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.initialize(&mut client, init, deadline()).await
}

async fn commit(pool: &Pool, request: &CommitRefsRequest) -> Result<CommitRefsReceipt, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.commit_refs(&mut client, request, deadline()).await
}

async fn check_version(
    pool: &Pool,
    repo: Uuid,
    tenant: Uuid,
    known: Option<&CoreGateVersion>,
) -> Result<VersionCheck, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.check_version(&mut client, repo, tenant, known, deadline()).await
}

async fn cancel(pool: &Pool, identity: &OperationIdentity) -> Result<CancelReceipt, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgRefStoreCore.cancel(&mut client, identity, deadline()).await
}

async fn operation_state(pool: &Pool, repo: Uuid, operation: Uuid) -> Result<Option<OperationState>> {
    let mut client = pool.get().await?;
    let lookup = PgRefStoreCore.query_operation(&mut client, repo, operation, deadline()).await?;
    Ok(match lookup {
        OperationLookup::Known(record) => Some(record.state()),
        OperationLookup::Unknown => None,
    })
}

async fn count(pool: &Pool, sql: &str, repo: Uuid) -> Result<i64> {
    Ok(pool.get().await?.query_one(sql, &[&repo]).await?.get(0))
}

async fn insert_repository(pool: &Pool, tenant: Uuid, state: &str, backend: &str) -> Result<Uuid> {
    let repo = Uuid::new_v4();
    let name = format!("core{}", &repo.simple().to_string()[..12]);
    pool.get()
        .await?
        .execute(
            "INSERT INTO repositories(id,owner_id,name,state,storage_backend) VALUES($1,$2,$3,$4,$5)",
            &[&repo, &tenant, &name, &state, &backend],
        )
        .await?;
    Ok(repo)
}

async fn seed_legacy_projection(pool: &Pool, tenant: Uuid, repo: Uuid) -> Result<()> {
    let client = pool.get().await?;
    let token = Uuid::new_v4();
    let digest = vec![0u8; 32];
    client
        .execute("INSERT INTO tokens(id,user_id,digest) VALUES($1,$2,$3)", &[&token, &tenant, &digest])
        .await?;
    let operation = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,storage_generation,evidence,outcome)
             VALUES($1,$2,$3,$4,'core',1,1,'{}'::jsonb,'recorded')",
            &[&operation, &repo, &tenant, &token],
        )
        .await?;
    let event = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let oid = "1".repeat(40);
    client
        .execute(
            "INSERT INTO outbox_events(event_id,operation_id,repository_id,storage_generation,operation_sequence,transaction_sequence,ref_name,old_oid,new_oid)
             VALUES($1,$2,$3,1,1,1,'refs/heads/main',$4,$4)",
            &[&event, &operation, &repo, &oid],
        )
        .await?;
    client
        .execute(
            "INSERT INTO repository_ref_projection(repository_id,ref_name,oid,deleted,storage_generation,operation_sequence,transaction_sequence,event_id)
             VALUES($1,'refs/heads/main',$2,false,1,1,1,$3)",
            &[&repo, &oid, &event],
        )
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn bootstrap_requires_unserved_provisioning_repository() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let history = Uuid::new_v4();
        let init = gate(repo, tenant, GitObjectFormat::Sha1, history, "refs/heads/main");
        let created = initialize(&pool, &init).await?;
        assert_eq!(created.revision(), 1);
        assert_eq!(created.head_ref().as_str(), "refs/heads/main");
        assert_eq!(created.history_incarnation(), history);
        let replayed = initialize(&pool, &init).await?;
        assert_eq!(replayed, created);
        assert!(matches!(
            initialize(&pool, &gate(repo, tenant, GitObjectFormat::Sha1, Uuid::new_v4(), "refs/heads/main")).await,
            Err(RefStoreError::GateConflict)
        ));
        assert!(matches!(
            initialize(&pool, &gate(repo, Uuid::new_v4(), GitObjectFormat::Sha1, history, "refs/heads/main")).await,
            Err(RefStoreError::RepositoryNotFound)
        ));
        assert!(matches!(
            initialize(&pool, &gate(repo, tenant, GitObjectFormat::Sha256, history, "refs/heads/main")).await,
            Err(RefStoreError::InvalidIdentity(_))
        ));

        // Initialization never switches serving authority or legacy state.
        let client = pool.get().await?;
        let row = client
            .query_one("SELECT storage_backend,state,transition_state FROM repositories WHERE id=$1", &[&repo])
            .await?;
        assert_eq!(row.get::<_, String>(0), "gitfs");
        assert_eq!(row.get::<_, String>(1), "provisioning");
        assert_eq!(row.get::<_, String>(2), "stable");
        assert_eq!(client.query_one("SELECT count(*) FROM pando_repository_states WHERE repository_id=$1", &[&repo]).await?.get::<_, i64>(0), 0);

        // A ready (served) repository cannot be bootstrapped.
        let ready = insert_repository(&pool, tenant, "ready", "gitfs").await?;
        let error = initialize(&pool, &gate(ready, tenant, GitObjectFormat::Sha1, Uuid::new_v4(), "refs/heads/main"))
            .await
            .expect_err("ready repository was accepted for core bootstrap");
        assert!(matches!(error, RefStoreError::Unsupported(_)), "unexpected {error}");

        // A draining transition cannot be bootstrapped.
        let draining = insert_repository(&pool, tenant, "provisioning", "gitfs").await?;
        client
            .execute(
                "UPDATE repositories SET transition_state='draining',transition_id=$2,transition_started_at=clock_timestamp() WHERE id=$1",
                &[&draining, &Uuid::new_v4()],
            )
            .await?;
        let error = initialize(&pool, &gate(draining, tenant, GitObjectFormat::Sha1, Uuid::new_v4(), "refs/heads/main"))
            .await
            .expect_err("draining repository was accepted for core bootstrap");
        assert!(matches!(error, RefStoreError::Unsupported(_)), "unexpected {error}");

        // A non-gitfs backend with live Pando authority and refs is rejected.
        let pando = insert_repository(&pool, tenant, "provisioning", "pando").await?;
        client
            .execute(
                "INSERT INTO pando_repository_states(repository_id,tenant_id,storage_generation,object_format,state)
                 VALUES($1,$2,1,'sha1','serving')",
                &[&pando, &tenant],
            )
            .await?;
        client
            .execute(
                "INSERT INTO pando_refs(repository_id,ref_name,oid,updated_generation) VALUES($1,'refs/heads/main',$2,1)",
                &[&pando, &"a".repeat(40)],
            )
            .await?;
        let error = initialize(&pool, &gate(pando, tenant, GitObjectFormat::Sha1, Uuid::new_v4(), "refs/heads/main"))
            .await
            .expect_err("pando repository was accepted for core bootstrap");
        assert!(matches!(error, RefStoreError::Unsupported(_)), "unexpected {error}");

        // A gitfs repository with a legacy Pando authority row is rejected too.
        let shadow = insert_repository(&pool, tenant, "provisioning", "gitfs").await?;
        client
            .execute(
                "INSERT INTO pando_repository_states(repository_id,tenant_id,storage_generation,object_format,state)
                 VALUES($1,$2,1,'sha1','serving')",
                &[&shadow, &tenant],
            )
            .await?;
        let error = initialize(&pool, &gate(shadow, tenant, GitObjectFormat::Sha1, Uuid::new_v4(), "refs/heads/main"))
            .await
            .expect_err("repository with pando authority was accepted");
        assert!(matches!(error, RefStoreError::Unsupported(_)), "unexpected {error}");

        // A repository that already has legacy projected refs is not empty.
        let legacy = insert_repository(&pool, tenant, "provisioning", "gitfs").await?;
        seed_legacy_projection(&pool, tenant, legacy).await?;
        let error = initialize(&pool, &gate(legacy, tenant, GitObjectFormat::Sha1, Uuid::new_v4(), "refs/heads/main"))
            .await
            .expect_err("repository with legacy refs was accepted");
        assert!(matches!(error, RefStoreError::Unsupported(_)), "unexpected {error}");
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_gates WHERE repository_id=$1", legacy).await?, 0);
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("bootstrap fence test panicked")?;
    teardown(&admin, &schema).await?;
    outcome?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn commit_replays_exact_terminal_and_digest_conflicts_do_not_mutate() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let format = GitObjectFormat::Sha1;
        let history = Uuid::new_v4();
        initialize(&pool, &gate(repo, tenant, format, history, "refs/heads/main")).await?;

        let operation = Uuid::new_v4();
        let first = request(
            repo,
            tenant,
            tenant,
            1,
            operation,
            format,
            history,
            1,
            HeadUpdate::Keep,
            vec![update("refs/heads/main", None, Some(oid(format, 1)))],
        );
        let committed = commit(&pool, &first).await?;
        assert!(committed.is_committed());
        assert_eq!(committed.terminal.kind, TerminalKind::Committed);
        assert_eq!(committed.terminal.revision, 2);
        let exact = committed.record.terminal_result().cloned().expect("committed terminal result");
        let gate_version = match check_version(&pool, repo, tenant, None).await? {
            VersionCheck::Changed(version) => version,
            other => panic!("unexpected version after commit: {other:?}"),
        };
        assert_eq!(gate_version.revision(), 2);
        assert!(matches!(
            check_version(&pool, repo, tenant, Some(&gate_version)).await?,
            VersionCheck::Unchanged(_)
        ));

        // Same identity and digest: exact saved terminal, no second mutation.
        let replay = commit(&pool, &first).await?;
        assert!(replay.replayed);
        assert_eq!(replay.record.terminal_result(), Some(&exact));
        assert_eq!(replay.terminal, committed.terminal);
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", repo).await?, 1);
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1", repo).await?, 1);
        assert!(matches!(
            check_version(&pool, repo, tenant, None).await?,
            VersionCheck::Changed(version) if version.revision() == 2
        ));

        // Same operation id, different canonical digest is a conflict, never a replay.
        let different = request(
            repo,
            tenant,
            tenant,
            1,
            operation,
            format,
            history,
            1,
            HeadUpdate::Keep,
            vec![update("refs/heads/other", None, Some(oid(format, 2)))],
        );
        assert!(matches!(commit(&pool, &different).await, Err(RefStoreError::DigestConflict)));
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", repo).await?, 1);
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1", repo).await?, 1);
        assert_eq!(operation_state(&pool, repo, operation).await?, Some(OperationState::Committed));
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("commit replay test panicked")?;
    teardown(&admin, &schema).await?;
    outcome?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn cancel_before_register_prevents_ref_changes() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let format = GitObjectFormat::Sha1;
        let history = Uuid::new_v4();
        initialize(&pool, &gate(repo, tenant, format, history, "refs/heads/main")).await?;

        let operation = Uuid::new_v4();
        let attempt = request(
            repo,
            tenant,
            tenant,
            1,
            operation,
            format,
            history,
            1,
            HeadUpdate::Keep,
            vec![update("refs/heads/main", None, Some(oid(format, 3)))],
        );
        let cancelled = cancel(&pool, attempt.identity()).await?;
        assert!(cancelled.tombstone_created);
        assert!(cancelled.record.is_none());

        let error = commit(&pool, &attempt).await.expect_err("cancel tombstone was ignored");
        assert!(matches!(error, RefStoreError::Cancelled { .. }), "unexpected {error}");
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", repo).await?, 0);
        assert_eq!(
            count(&pool, "SELECT count(*) FROM ref_store_core_cancellations WHERE repository_id=$1", repo).await?,
            1
        );
        assert!(matches!(
            check_version(&pool, repo, tenant, None).await?,
            VersionCheck::Changed(version) if version.revision() == 1
        ));
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("cancel-before-register test panicked")?;
    teardown(&admin, &schema).await?;
    outcome?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn two_connections_same_old_oid_have_one_committer_and_one_terminal_rejection() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let format = GitObjectFormat::Sha1;
        let history = Uuid::new_v4();
        initialize(&pool, &gate(repo, tenant, format, history, "refs/heads/main")).await?;
        let seed = request(
            repo,
            tenant,
            tenant,
            1,
            Uuid::new_v4(),
            format,
            history,
            1,
            HeadUpdate::Keep,
            vec![update("refs/heads/main", None, Some(oid(format, 1)))],
        );
        assert!(commit(&pool, &seed).await?.is_committed());

        let mut blocker = pool.get().await?;
        let blocker_tx = blocker.transaction().await?;
        blocker_tx
            .query_one("SELECT revision FROM ref_store_core_gates WHERE repository_id=$1 FOR UPDATE", &[&repo])
            .await?;

        // Both admitted requests observe the same old OID and expected
        // revision. The gate row serializes them, so exactly one applies.
        let left = request(
            repo,
            tenant,
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            format,
            history,
            2,
            HeadUpdate::Keep,
            vec![update("refs/heads/main", Some(oid(format, 1)), Some(oid(format, 2)))],
        );
        let right = request(
            repo,
            tenant,
            Uuid::new_v4(),
            1,
            Uuid::new_v4(),
            format,
            history,
            2,
            HeadUpdate::Keep,
            vec![update("refs/heads/main", Some(oid(format, 1)), Some(oid(format, 3)))],
        );
        let left_pool = pool.clone();
        let left_task = tokio::spawn(async move { commit(&left_pool, &left).await });
        let right_pool = pool.clone();
        let right_task = tokio::spawn(async move { commit(&right_pool, &right).await });

        // Real PostgreSQL barrier: both commits reached the gate row lock and
        // are waiting. No sleep-only synchronization decides success.
        let observer = pool.get().await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: i64 = observer
                    .query_one(
                        "SELECT count(*) FROM pg_stat_activity
                         WHERE datname=current_database() AND state='active'
                           AND wait_event_type='Lock' AND query LIKE '%ref_store_core_gates%'",
                        &[],
                    )
                    .await?
                    .get(0);
                if waiting >= 2 {
                    break Ok::<(), anyhow::Error>(());
                }
                assert!(!left_task.is_finished() && !right_task.is_finished(), "a commit escaped the gate barrier");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("commits never reached the PostgreSQL gate-lock barrier")??;
        drop(observer);
        blocker_tx.rollback().await?;
        drop(blocker);

        let left_result = tokio::time::timeout(Duration::from_secs(10), left_task)
            .await
            .context("left commit deadlocked")??;
        let right_result = tokio::time::timeout(Duration::from_secs(10), right_task)
            .await
            .context("right commit deadlocked")??;
        let receipts = [left_result, right_result];
        let committed = receipts.iter().filter(|receipt| receipt.is_committed()).count();
        let rejected = receipts.iter().filter(|receipt| !receipt.is_committed()).count();
        assert_eq!((committed, rejected), (1, 1), "old-OID CAS must have exactly one winner");
        for receipt in &receipts {
            if !receipt.is_committed() {
                // The winner advanced the gate revision while holding the row
                // lock, so the second admission is a durable revision
                // rejection; it can never apply the same old OID twice.
                assert_eq!(
                    receipt.terminal.rejection.as_ref().map(|rejection| rejection.code),
                    Some(CommitRejectCode::RevisionMismatch)
                );
                assert_eq!(receipt.terminal.kind, TerminalKind::Rejected);
                assert!(receipt
                    .terminal
                    .refs
                    .iter()
                    .all(|result| matches!(result, rootyard::ref_store::RefCommitResult::NotApplied { .. })));
            }
        }
        assert!(matches!(
            check_version(&pool, repo, tenant, None).await?,
            VersionCheck::Changed(version) if version.revision() == 3
        ));
        let final_oid: String = pool
            .get()
            .await?
            .query_one(
                "SELECT oid FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name='refs/heads/main'",
                &[&repo],
            )
            .await?
            .get(0);
        let winner_oid = receipts
            .iter()
            .find(|receipt| receipt.is_committed())
            .and_then(|receipt| receipt.terminal.refs.first())
            .and_then(|result| match result {
                rootyard::ref_store::RefCommitResult::Applied { new_oid, .. } => new_oid.clone(),
                rootyard::ref_store::RefCommitResult::NotApplied { .. } => None,
            })
            .expect("winner result");
        assert_eq!(final_oid, winner_oid);
        assert_eq!(
            count(&pool, "SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1", repo).await?,
            3,
            "seed commit, winner and durable loser rejection each have one event"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("same-old-OID race test panicked")?;
    teardown(&admin, &schema).await?;
    outcome?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn atomic_rejection_writes_no_partial_refs_and_epochs_history_tenant_prefix_are_checked() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let format = GitObjectFormat::Sha1;
        let history = Uuid::new_v4();
        initialize(&pool, &gate(repo, tenant, format, history, "refs/heads/main")).await?;
        let seed = request(
            repo,
            tenant,
            tenant,
            1,
            Uuid::new_v4(),
            format,
            history,
            1,
            HeadUpdate::Keep,
            vec![
                update("refs/heads/a", None, Some(oid(format, 1))),
                update("refs/heads/topic", None, Some(oid(format, 2))),
            ],
        );
        assert!(commit(&pool, &seed).await?.is_committed());

        // One CAS failure makes the whole atomic batch not applied.
        let failing_operation = Uuid::new_v4();
        let failing = request(
            repo,
            tenant,
            tenant,
            2,
            failing_operation,
            format,
            history,
            2,
            HeadUpdate::Keep,
            vec![
                update("refs/heads/new", None, Some(oid(format, 3))),
                update("refs/heads/a", Some(oid(format, 9)), Some(oid(format, 4))),
            ],
        );
        let rejected = commit(&pool, &failing).await?;
        assert!(!rejected.is_committed());
        assert_eq!(
            rejected.terminal.rejection.as_ref().map(|rejection| rejection.code),
            Some(CommitRejectCode::OldOidMismatch)
        );
        assert!(rejected.terminal.refs.iter().all(|result| matches!(
            result,
            rootyard::ref_store::RefCommitResult::NotApplied { reason: CommitRejectCode::OldOidMismatch, .. }
        )));
        assert_eq!(
            count(&pool, "SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", repo).await?,
            2,
            "the rejected batch must not create its first ref"
        );
        assert!(matches!(
            check_version(&pool, repo, tenant, None).await?,
            VersionCheck::Changed(version) if version.revision() == 2
        ));

        // Prefix conflict against a current row.
        let prefix = request(
            repo,
            tenant,
            tenant,
            3,
            Uuid::new_v4(),
            format,
            history,
            2,
            HeadUpdate::Keep,
            vec![update("refs/heads/topic/sub", None, Some(oid(format, 3)))],
        );
        let rejected = commit(&pool, &prefix).await?;
        assert_eq!(
            rejected.terminal.rejection.as_ref().map(|rejection| rejection.code),
            Some(CommitRejectCode::PrefixConflict)
        );
        assert_eq!(
            count(
                &pool,
                "SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name='refs/heads/topic/sub'",
                repo
            )
            .await?,
            0
        );

        // Prefix conflict inside one batch is fail-closed before the registry.
        let batch_operation = Uuid::new_v4();
        let batch_prefix = request(
            repo,
            tenant,
            tenant,
            4,
            batch_operation,
            format,
            history,
            2,
            HeadUpdate::Keep,
            vec![
                update("refs/heads/x", None, Some(oid(format, 3))),
                update("refs/heads/x/y", None, Some(oid(format, 4))),
            ],
        );
        assert!(matches!(commit(&pool, &batch_prefix).await, Err(RefStoreError::InvalidIdentity(_))));
        assert_eq!(operation_state(&pool, repo, batch_operation).await?, None);
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1", repo).await?, 2);

        // Epoch/history/tenant/revision mismatches are durable rejections and
        // never mutate refs.
        let cases: Vec<(CommitRefsRequest, CommitRejectCode)> = vec![
            (
                CommitRefsRequest::new(
                    repo,
                    tenant,
                    tenant,
                    lane(),
                    5,
                    Uuid::new_v4(),
                    format,
                    Uuid::new_v4(),
                    1,
                    1,
                    2,
                    HeadUpdate::Keep,
                    CommitMode::Atomic,
                    vec![update("refs/heads/history", None, Some(oid(format, 3)))],
                )
                .unwrap(),
                CommitRejectCode::HistoryIncarnationMismatch,
            ),
            (
                CommitRefsRequest::new(
                    repo,
                    tenant,
                    tenant,
                    lane(),
                    6,
                    Uuid::new_v4(),
                    format,
                    history,
                    2,
                    1,
                    2,
                    HeadUpdate::Keep,
                    CommitMode::Atomic,
                    vec![update("refs/heads/authority", None, Some(oid(format, 3)))],
                )
                .unwrap(),
                CommitRejectCode::AuthorityEpochMismatch,
            ),
            (
                CommitRefsRequest::new(
                    repo,
                    tenant,
                    tenant,
                    lane(),
                    7,
                    Uuid::new_v4(),
                    format,
                    history,
                    1,
                    2,
                    2,
                    HeadUpdate::Keep,
                    CommitMode::Atomic,
                    vec![update("refs/heads/group", None, Some(oid(format, 3)))],
                )
                .unwrap(),
                CommitRejectCode::GroupEpochMismatch,
            ),
            (
                request(
                    repo,
                    Uuid::new_v4(),
                    tenant,
                    8,
                    Uuid::new_v4(),
                    format,
                    history,
                    2,
                    HeadUpdate::Keep,
                    vec![update("refs/heads/tenant", None, Some(oid(format, 3)))],
                ),
                CommitRejectCode::TenantMismatch,
            ),
            (
                request(
                    repo,
                    tenant,
                    tenant,
                    9,
                    Uuid::new_v4(),
                    format,
                    history,
                    1,
                    HeadUpdate::Keep,
                    vec![update("refs/heads/revision", None, Some(oid(format, 3)))],
                ),
                CommitRejectCode::RevisionMismatch,
            ),
            (
                CommitRefsRequest::new(
                    repo,
                    tenant,
                    tenant,
                    lane(),
                    10,
                    Uuid::new_v4(),
                    GitObjectFormat::Sha256,
                    history,
                    1,
                    1,
                    2,
                    HeadUpdate::Keep,
                    CommitMode::Atomic,
                    vec![update("refs/heads/format", None, Some(oid(GitObjectFormat::Sha256, 3)))],
                )
                .unwrap(),
                CommitRejectCode::ObjectFormatMismatch,
            ),
        ];
        for (case, code) in cases {
            let receipt = commit(&pool, &case).await?;
            assert!(!receipt.is_committed(), "unexpected committed {code:?}");
            assert_eq!(receipt.terminal.rejection.as_ref().map(|rejection| rejection.code), Some(code));
        }
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", repo).await?, 2);
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("atomic rejection test panicked")?;
    teardown(&admin, &schema).await?;
    outcome?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn head_retarget_and_deletion_policy_is_atomic() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let format = GitObjectFormat::Sha1;
        let history = Uuid::new_v4();
        initialize(&pool, &gate(repo, tenant, format, history, "refs/heads/main")).await?;
        let create = request(
            repo,
            tenant,
            tenant,
            1,
            Uuid::new_v4(),
            format,
            history,
            1,
            HeadUpdate::Keep,
            vec![
                update("refs/heads/main", None, Some(oid(format, 1))),
                update("refs/heads/next", None, Some(oid(format, 2))),
                update("refs/heads/feature", None, Some(oid(format, 3))),
            ],
        );
        assert!(commit(&pool, &create).await?.is_committed());

        let retarget = request(
            repo,
            tenant,
            tenant,
            2,
            Uuid::new_v4(),
            format,
            history,
            2,
            HeadUpdate::retarget("refs/heads/next")?,
            vec![update("refs/heads/next", Some(oid(format, 2)), Some(oid(format, 4)))],
        );
        let receipt = commit(&pool, &retarget).await?;
        assert!(receipt.is_committed());
        assert_eq!(receipt.terminal.head_ref.as_deref(), Some("refs/heads/next"));

        let delete_without_retarget = request(
            repo,
            tenant,
            tenant,
            3,
            Uuid::new_v4(),
            format,
            history,
            3,
            HeadUpdate::Keep,
            vec![update("refs/heads/next", Some(oid(format, 4)), None)],
        );
        let rejected = commit(&pool, &delete_without_retarget).await?;
        assert_eq!(
            rejected.terminal.rejection.as_ref().map(|rejection| rejection.code),
            Some(CommitRejectCode::HeadDeletedWithoutRetarget)
        );
        assert_eq!(
            count(
                &pool,
                "SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name='refs/heads/next'",
                repo
            )
            .await?,
            1
        );

        let missing_retarget = request(
            repo,
            tenant,
            tenant,
            4,
            Uuid::new_v4(),
            format,
            history,
            3,
            HeadUpdate::retarget("refs/heads/feature")?,
            vec![
                update("refs/heads/next", Some(oid(format, 4)), None),
                update("refs/heads/feature", Some(oid(format, 3)), None),
            ],
        );
        let rejected = commit(&pool, &missing_retarget).await?;
        assert_eq!(
            rejected.terminal.rejection.as_ref().map(|rejection| rejection.code),
            Some(CommitRejectCode::HeadTargetMissing)
        );

        // HEAD can only be a branch, never a tag, and this fails before the
        // registry is touched.
        assert!(HeadUpdate::retarget("refs/tags/v1").is_err());

        let delete_and_retarget = request(
            repo,
            tenant,
            tenant,
            5,
            Uuid::new_v4(),
            format,
            history,
            3,
            HeadUpdate::retarget("refs/heads/main")?,
            vec![update("refs/heads/next", Some(oid(format, 4)), None)],
        );
        let receipt = commit(&pool, &delete_and_retarget).await?;
        assert!(receipt.is_committed());
        assert_eq!(receipt.terminal.head_ref.as_deref(), Some("refs/heads/main"));
        assert_eq!(
            count(
                &pool,
                "SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name='refs/heads/next'",
                repo
            )
            .await?,
            0
        );

        let delete_non_head = request(
            repo,
            tenant,
            tenant,
            6,
            Uuid::new_v4(),
            format,
            history,
            4,
            HeadUpdate::Keep,
            vec![update("refs/heads/feature", Some(oid(format, 3)), None)],
        );
        let receipt = commit(&pool, &delete_non_head).await?;
        assert!(receipt.is_committed());
        assert_eq!(receipt.terminal.head_ref.as_deref(), Some("refs/heads/main"));
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("HEAD policy test panicked")?;
    teardown(&admin, &schema).await?;
    outcome?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn core_error_rolls_back_partial_writes_and_a_client_commit_cannot_publish_them() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let format = GitObjectFormat::Sha1;
        let history = Uuid::new_v4();
        initialize(&pool, &gate(repo, tenant, format, history, "refs/heads/main")).await?;

        // Inject a failure after the ref rows, gate revision and operation
        // terminal were already written inside the short transaction.
        let client = pool.get().await?;
        client
            .batch_execute(
                "CREATE FUNCTION core_event_boom() RETURNS trigger LANGUAGE plpgsql AS $$
                 BEGIN RAISE EXCEPTION 'injected core event failure'; END $$;
                 CREATE TRIGGER core_event_boom BEFORE INSERT ON ref_store_core_events
                 FOR EACH ROW EXECUTE FUNCTION core_event_boom();",
            )
            .await?;

        let operation = Uuid::new_v4();
        let attempt = request(
            repo,
            tenant,
            tenant,
            1,
            operation,
            format,
            history,
            1,
            HeadUpdate::Keep,
            vec![update("refs/heads/main", None, Some(oid(format, 1)))],
        );
        let mut failing_client = pool.get().await?;
        let error = PgRefStoreCore
            .commit_refs(&mut failing_client, &attempt, deadline())
            .await
            .expect_err("injected event failure was not reported");
        assert!(matches!(error, RefStoreError::Database(_)), "unexpected {error}");

        // A client that (incorrectly) tries to commit this session after the
        // core error cannot publish the rolled-back partial writes.
        failing_client.batch_execute("COMMIT").await?;

        client
            .batch_execute(
                "DROP TRIGGER core_event_boom ON ref_store_core_events; DROP FUNCTION core_event_boom();",
            )
            .await?;

        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", repo).await?, 0);
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1", repo).await?, 0);
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_issuer_lanes WHERE repository_id=$1", repo).await?, 0);
        assert_eq!(operation_state(&pool, repo, operation).await?, None);
        assert!(matches!(
            check_version(&pool, repo, tenant, None).await?,
            VersionCheck::Changed(version) if version.revision() == 1
        ));

        // The rollback also released the lane sequence, so a clean retry with
        // the same lane/sequence commits exactly once.
        let retry = request(
            repo,
            tenant,
            tenant,
            1,
            Uuid::new_v4(),
            format,
            history,
            1,
            HeadUpdate::Keep,
            vec![update("refs/heads/main", None, Some(oid(format, 1)))],
        );
        assert!(commit(&pool, &retry).await?.is_committed());
        assert!(matches!(
            check_version(&pool, repo, tenant, None).await?,
            VersionCheck::Changed(version) if version.revision() == 2
        ));
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("core error rollback test panicked")?;
    teardown(&admin, &schema).await?;
    outcome?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn oversized_aggregate_terminal_is_rejected_before_any_write() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let format = GitObjectFormat::Sha1;
        let history = Uuid::new_v4();
        initialize(&pool, &gate(repo, tenant, format, history, "refs/heads/main")).await?;

        let long_name = |index: usize| {
            format!("refs/heads/{index:03}{}", "a".repeat(1024 - "refs/heads/".len() - 3))
        };
        let oversized_operation = Uuid::new_v4();
        let oversized = request(
            repo,
            tenant,
            tenant,
            1,
            oversized_operation,
            format,
            history,
            1,
            HeadUpdate::Keep,
            (0..128).map(|index| update(&long_name(index), None, Some(oid(format, 1)))).collect(),
        );
        // The request itself is legal (128 refs, each name 1024 bytes); only
        // the aggregate terminal body is impossible.
        let error = commit(&pool, &oversized).await.expect_err("oversized terminal was accepted");
        assert!(
            matches!(error, RefStoreError::InvalidIdentity(ref message) if message.contains("64 KiB")),
            "unexpected {error}"
        );
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", repo).await?, 0);
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1", repo).await?, 0);
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_issuer_lanes WHERE repository_id=$1", repo).await?, 0);
        assert_eq!(operation_state(&pool, repo, oversized_operation).await?, None);
        assert!(matches!(
            check_version(&pool, repo, tenant, None).await?,
            VersionCheck::Changed(version) if version.revision() == 1
        ));

        // One maximum-length name is allowed.
        let single = request(
            repo,
            tenant,
            tenant,
            1,
            Uuid::new_v4(),
            format,
            history,
            1,
            HeadUpdate::Keep,
            vec![update(&long_name(7), None, Some(oid(format, 2)))],
        );
        assert!(commit(&pool, &single).await?.is_committed());

        // The full 128-ref batch envelope still works with bounded names.
        let short_name = |index: usize| format!("refs/heads/batch-{index:03}");
        let batch = request(
            repo,
            tenant,
            tenant,
            2,
            Uuid::new_v4(),
            format,
            history,
            2,
            HeadUpdate::Keep,
            (0..128).map(|index| update(&short_name(index), None, Some(oid(format, 3)))).collect(),
        );
        let receipt = commit(&pool, &batch).await?;
        assert!(receipt.is_committed());
        assert_eq!(receipt.terminal.revision, 3);
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", repo).await?, 129);
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("oversized terminal test panicked")?;
    teardown(&admin, &schema).await?;
    outcome?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn repository_authority_change_rejects_new_mutations_but_replays_old_terminal() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let format = GitObjectFormat::Sha1;
        let history = Uuid::new_v4();
        initialize(&pool, &gate(repo, tenant, format, history, "refs/heads/main")).await?;
        let seed = request(
            repo,
            tenant,
            tenant,
            1,
            Uuid::new_v4(),
            format,
            history,
            1,
            HeadUpdate::Keep,
            vec![update("refs/heads/main", None, Some(oid(format, 1)))],
        );
        let committed = commit(&pool, &seed).await?;
        assert!(committed.is_committed());
        let exact = committed.record.terminal_result().cloned().expect("committed terminal");
        assert!(commit(&pool, &seed).await?.replayed);

        let client = pool.get().await?;
        let mutation = |sequence: i64, expected_revision: i64| {
            request(
                repo,
                tenant,
                tenant,
                sequence,
                Uuid::new_v4(),
                format,
                history,
                expected_revision,
                HeadUpdate::Keep,
                vec![update("refs/heads/main", Some(oid(format, 1)), Some(oid(format, 2)))],
            )
        };

        // The repository becomes served by the legacy GitFS path.
        client.execute("UPDATE repositories SET state='ready' WHERE id=$1", &[&repo]).await?;
        let stale = mutation(2, 2);
        let error = commit(&pool, &stale).await.expect_err("ready repository accepted a core mutation");
        assert!(matches!(error, RefStoreError::Unsupported(_)), "unexpected {error}");
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", repo).await?, 1);
        assert_eq!(count(&pool, "SELECT count(*) FROM ref_store_core_events WHERE repository_id=$1", repo).await?, 1);
        assert_eq!(operation_state(&pool, repo, stale.identity().operation_id()).await?, None);
        // Immutable proof of the older operation is still available.
        let replay = commit(&pool, &seed).await?;
        assert!(replay.replayed);
        assert!(replay.is_committed());
        assert_eq!(replay.terminal, committed.terminal);
        assert_eq!(replay.record.terminal_result(), Some(&exact));
        assert_eq!(
            operation_state(&pool, repo, seed.identity().operation_id()).await?,
            Some(OperationState::Committed)
        );

        // A Pando backend cannot carry new core mutations.
        client
            .execute("UPDATE repositories SET state='provisioning',storage_backend='pando' WHERE id=$1", &[&repo])
            .await?;
        let error = commit(&pool, &mutation(3, 2)).await.expect_err("pando backend accepted a core mutation");
        assert!(matches!(error, RefStoreError::Unsupported(_)), "unexpected {error}");

        // A live Pando authority row is rejected even with a gitfs row.
        client.execute("UPDATE repositories SET storage_backend='gitfs' WHERE id=$1", &[&repo]).await?;
        client
            .execute(
                "INSERT INTO pando_repository_states(repository_id,tenant_id,storage_generation,object_format,state)
                 VALUES($1,$2,1,'sha1','serving')",
                &[&repo, &tenant],
            )
            .await?;
        let error = commit(&pool, &mutation(4, 2)).await.expect_err("pando authority accepted a core mutation");
        assert!(matches!(error, RefStoreError::Unsupported(_)), "unexpected {error}");
        client.execute("DELETE FROM pando_repository_states WHERE repository_id=$1", &[&repo]).await?;

        // A draining transition blocks new mutations.
        client
            .execute(
                "UPDATE repositories SET transition_state='draining',transition_id=$2,transition_started_at=clock_timestamp() WHERE id=$1",
                &[&repo, &Uuid::new_v4()],
            )
            .await?;
        let error = commit(&pool, &mutation(5, 2)).await.expect_err("draining repository accepted a core mutation");
        assert!(matches!(error, RefStoreError::Unsupported(_)), "unexpected {error}");
        assert!(commit(&pool, &seed).await?.replayed);
        assert!(matches!(
            check_version(&pool, repo, tenant, None).await?,
            VersionCheck::Changed(version) if version.revision() == 2
        ));

        // Restoring an explicitly unserved stable state lets a new mutation
        // proceed from the unchanged gate revision.
        client
            .execute(
                "UPDATE repositories SET transition_state='stable',transition_id=NULL,transition_started_at=NULL WHERE id=$1",
                &[&repo],
            )
            .await?;
        let resumed = mutation(6, 2);
        let receipt = commit(&pool, &resumed).await?;
        assert!(receipt.is_committed());
        assert_eq!(receipt.terminal.revision, 3);
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("repository authority fence test panicked")?;
    teardown(&admin, &schema).await?;
    outcome?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn check_version_is_unknown_before_initialization() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        assert_eq!(check_version(&pool, repo, tenant, None).await?, VersionCheck::Unknown);
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("unknown gate test panicked")?;
    teardown(&admin, &schema).await?;
    outcome?;
    Ok(())
}
