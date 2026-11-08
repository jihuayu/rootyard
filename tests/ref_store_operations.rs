//! Focused PostgreSQL tests for the transitional RefStore operation registry.
//! Run with `ROOTYARD_TEST_DATABASE_URL=... cargo test --test ref_store_operations -- --ignored`.
use anyhow::{Context, Result, anyhow};
use deadpool_postgres::{Manager, Pool};
use rootyard::db;
use rootyard::ref_store::{
    IssuerLane, OperationIdentity, OperationLookup, OperationState, PgRefStore, RefStoreError, RequestDigest,
    TerminalOutcome, TerminalResult,
};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;
use uuid::Uuid;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(15)
}

fn identity(repo: Uuid, issuer: Uuid, sequence: i64, operation: Uuid, digest: u8) -> OperationIdentity {
    OperationIdentity::new(
        repo,
        issuer,
        IssuerLane::new("test-lane").unwrap(),
        sequence,
        operation,
        RequestDigest::from_bytes([digest; 32]),
    )
    .unwrap()
}

fn result(marker: i64) -> TerminalResult {
    TerminalResult::json(serde_json::json!({"state": "committed", "marker": marker})).unwrap()
}

fn assert_immutable_trigger(error: tokio_postgres::Error) {
    let database = error.as_db_error().expect("expected a PostgreSQL trigger/check error");
    let code = database.code().code();
    assert!(code == "23514" || code == "P0001", "unexpected SQLSTATE {code}: {}", database.message());
    assert!(database.message().contains("immutable"), "unexpected trigger message: {}", database.message());
}

async fn setup(url: &str) -> Result<(Pool, Pool, String, Uuid, Uuid)> {
    let admin = db::pool(url)?;
    let schema = format!("ref_store_test_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=15000 -c lock_timeout=10000"));
    let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(8)
        .build()?;
    db::migrate(&pool).await?;
    let actor = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let username = format!("refstore{}", &actor.simple().to_string()[..12]);
    let client = pool.get().await?;
    client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&actor, &username]).await?;
    client
        .execute("INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'refstore','ready')", &[&repo, &actor])
        .await?;
    drop(client);
    Ok((admin, pool, schema, actor, repo))
}

async fn teardown(admin: &Pool, schema: &str) -> Result<()> {
    admin.get().await?.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn same_digest_replays_and_different_digest_conflicts() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let (admin, pool, schema, actor, repo) = setup(&url).await?;
    let result = tokio::spawn(async move {
        let store = PgRefStore;
        let operation = Uuid::new_v4();
        let original = identity(repo, actor, 1, operation, 7);
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        let begun = store.begin(&tx, &original, deadline()).await?;
        assert!(begun.created);
        assert_eq!(begun.record.state(), OperationState::Pending);
        tx.commit().await?;

        let tx = client.transaction().await?;
        let committed =
            store.record_terminal(&tx, &original, TerminalOutcome::Committed, &result(1), deadline()).await?;
        assert!(!committed.replayed);
        tx.commit().await?;

        let tx = client.transaction().await?;
        let replay = store.begin(&tx, &original, deadline()).await?;
        assert!(!replay.created);
        assert_eq!(replay.record.state(), OperationState::Committed);
        assert_eq!(replay.record.terminal_result(), Some(&result(1)));
        let same = store.record_terminal(&tx, &original, TerminalOutcome::Committed, &result(1), deadline()).await?;
        assert!(same.replayed);
        tx.commit().await?;

        // Same operation id, different digest is a conflict, not a replay.
        let different = identity(repo, actor, 1, operation, 8);
        let tx = client.transaction().await?;
        assert!(matches!(store.begin(&tx, &different, deadline()).await, Err(RefStoreError::DigestConflict)));
        tx.rollback().await?;

        // Same lane sequence, different operation id is also a conflict.
        let duplicate_lane = identity(repo, actor, 1, Uuid::new_v4(), 7);
        let tx = client.transaction().await?;
        assert!(matches!(store.begin(&tx, &duplicate_lane, deadline()).await, Err(RefStoreError::IdentityConflict)));
        tx.rollback().await?;

        let tx = client.transaction().await?;
        assert_eq!(store.get(&tx, repo, operation, deadline()).await?, OperationLookup::Known(replay.record));
        assert_eq!(store.get(&tx, Uuid::new_v4(), operation, deadline()).await?, OperationLookup::Unknown);
        tx.rollback().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("replay test panicked");
    teardown(&admin, &schema).await?;
    result??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn cancel_before_register_is_persistent_across_connections() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let (admin, pool, schema, actor, repo) = setup(&url).await?;
    let result = tokio::spawn(async move {
        let store = PgRefStore;
        let operation = Uuid::new_v4();
        let original = identity(repo, actor, 1, operation, 3);
        let mut first = pool.get().await?;
        let tx = first.transaction().await?;
        let cancelled = store.cancel(&tx, &original, deadline()).await?;
        assert!(cancelled.tombstone_created);
        assert!(cancelled.record.is_none());
        tx.commit().await?;
        drop(first);

        // A fresh pool connection sees the durable tombstone before registration.
        let mut second = pool.get().await?;
        let tx = second.transaction().await?;
        let begun = store.begin(&tx, &original, deadline()).await?;
        assert!(begun.created);
        assert_eq!(begun.record.state(), OperationState::Cancelled);
        assert!(matches!(
            store.record_terminal(&tx, &original, TerminalOutcome::Committed, &result(1), deadline()).await,
            Err(RefStoreError::Cancelled { .. })
        ));
        tx.commit().await?;

        let mut third = pool.get().await?;
        let tx = third.transaction().await?;
        match store.get(&tx, repo, operation, deadline()).await? {
            OperationLookup::Known(record) => assert_eq!(record.state(), OperationState::Cancelled),
            OperationLookup::Unknown => panic!("cancel tombstone did not produce a terminal record"),
        }
        tx.rollback().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("cancel test panicked");
    teardown(&admin, &schema).await?;
    result??;
    Ok(())
}
#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn cancel_races_and_terminal_results_are_immutable() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let (admin, pool, schema, actor, repo) = setup(&url).await?;
    let result = tokio::spawn(async move {
        let store = PgRefStore;
        let mut client = pool.get().await?;

        // Pending -> cancel wins; a late commit cannot turn it into committed.
        let pending = identity(repo, actor, 2, Uuid::new_v4(), 4);
        let tx = client.transaction().await?;
        store.begin(&tx, &pending, deadline()).await?;
        tx.commit().await?;
        let tx = client.transaction().await?;
        let cancelled = store.cancel(&tx, &pending, deadline()).await?;
        assert!(cancelled.tombstone_created);
        assert_eq!(cancelled.record.as_ref().map(|record| record.state()), Some(OperationState::Cancelled));
        assert!(matches!(
            store.record_terminal(&tx, &pending, TerminalOutcome::Committed, &result(2), deadline()).await,
            Err(RefStoreError::Cancelled { .. })
        ));
        tx.commit().await?;

        // A committed result can be replayed but never replaced.
        let committed_identity = identity(repo, actor, 3, Uuid::new_v4(), 5);
        let tx = client.transaction().await?;
        store.begin(&tx, &committed_identity, deadline()).await?;
        let committed = store
            .record_terminal(&tx, &committed_identity, TerminalOutcome::Committed, &result(10), deadline())
            .await?;
        let operation = committed.record.identity().operation_id();
        assert!(!committed.replayed);
        assert!(store
            .record_terminal(&tx, &committed_identity, TerminalOutcome::Committed, &result(10), deadline())
            .await?
            .replayed);
        assert!(matches!(
            store.record_terminal(&tx, &committed_identity, TerminalOutcome::Rejected, &result(10), deadline()).await,
            Err(RefStoreError::TerminalImmutable)
        ));
        assert!(matches!(
            store.record_terminal(&tx, &committed_identity, TerminalOutcome::Committed, &result(11), deadline()).await,
            Err(RefStoreError::TerminalImmutable)
        ));
        tx.commit().await?;

        // A later cancel records a tombstone but preserves the terminal result.
        let tx = client.transaction().await?;
        let after = store.cancel(&tx, &committed_identity, deadline()).await?;
        assert!(after.tombstone_created);
        assert_eq!(after.record.as_ref().map(|record| record.state()), Some(OperationState::Committed));
        tx.commit().await?;
        let tx = client.transaction().await?;
        let replay = store.begin(&tx, &committed_identity, deadline()).await?;
        assert!(!replay.created);
        assert_eq!(replay.record.state(), OperationState::Committed);
        assert_eq!(replay.record.terminal_result(), Some(&result(10)));
        tx.rollback().await?;

        // Database triggers reject a terminal rewrite even if a caller bypasses
        // the adapter's checks. These transactions are expected to abort.
        let tx = client.transaction().await?;
        let error = tx
            .execute(
                "UPDATE ref_store_operations SET terminal_result='{\"tampered\":true}' WHERE repository_id=$1 AND operation_id=$2",
                &[&repo, &operation],
            )
            .await
            .expect_err("terminal result rewrite must be rejected by the database");
        assert_immutable_trigger(error);
        tx.rollback().await?;

        let tx = client.transaction().await?;
        let error = tx
            .execute(
                "UPDATE ref_store_operations SET sequence=sequence+1 WHERE repository_id=$1 AND operation_id=$2",
                &[&repo, &operation],
            )
            .await
            .expect_err("operation identity rewrite must be rejected by the database");
        assert_immutable_trigger(error);
        tx.rollback().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("immutability test panicked");
    teardown(&admin, &schema).await?;
    result??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn reserved_sequences_are_transactional_and_monotonic() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let (admin, pool, schema, actor, repo) = setup(&url).await?;
    let result = tokio::spawn(async move {
        let store = PgRefStore;
        let lane = IssuerLane::new("reservation").unwrap();
        let mut client = pool.get().await?;

        // Rollback does not consume the sequence.
        let operation = Uuid::new_v4();
        let tx = client.transaction().await?;
        assert_eq!(store.reserve_sequence(&tx, repo, actor, operation, &lane, deadline()).await?.sequence(), 1);
        tx.rollback().await?;

        let tx = client.transaction().await?;
        let first = store.reserve_sequence(&tx, repo, actor, operation, &lane, deadline()).await?;
        assert_eq!(first.sequence(), 1);
        assert_eq!(first.operation_id(), operation);
        let identity = first.identity(RequestDigest::from_bytes([1; 32]))?;
        store.begin(&tx, &identity, deadline()).await?;
        tx.commit().await?;

        let tx = client.transaction().await?;
        assert_eq!(store.reserve_sequence(&tx, repo, actor, Uuid::new_v4(), &lane, deadline()).await?.sequence(), 2);
        tx.rollback().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("reservation test panicked");
    teardown(&admin, &schema).await?;
    result??;
    Ok(())
}

fn identity_with_lane(
    repo: Uuid,
    issuer: Uuid,
    lane: &str,
    sequence: i64,
    operation: Uuid,
    digest: u8,
) -> OperationIdentity {
    OperationIdentity::new(
        repo,
        issuer,
        IssuerLane::new(lane).unwrap(),
        sequence,
        operation,
        RequestDigest::from_bytes([digest; 32]),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn foreign_lane_begin_and_cancel_cannot_both_win() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let (admin, pool, schema, actor, repo) = setup(&url).await?;
    let result = tokio::spawn(async move {
        let operation = Uuid::new_v4();
        let foreign_issuer = Uuid::new_v4();
        let begin_identity = identity_with_lane(repo, actor, "lane-a", 1, operation, 7);
        let cancel_identity = identity_with_lane(repo, foreign_issuer, "lane-b", 1, operation, 9);

        let begin_pool = pool.clone();
        let begin_task = tokio::spawn(async move {
            let store = PgRefStore;
            let mut client = begin_pool.get().await?;
            let tx = client.transaction().await?;
            let won = match store.begin(&tx, &begin_identity, deadline()).await {
                Ok(_) => {
                    tx.commit().await?;
                    true
                }
                Err(_) => {
                    tx.rollback().await?;
                    false
                }
            };
            Ok::<bool, anyhow::Error>(won)
        });
        let cancel_pool = pool.clone();
        let cancel_task = tokio::spawn(async move {
            let store = PgRefStore;
            let mut client = cancel_pool.get().await?;
            let tx = client.transaction().await?;
            let won = match store.cancel(&tx, &cancel_identity, deadline()).await {
                Ok(_) => {
                    tx.commit().await?;
                    true
                }
                Err(_) => {
                    tx.rollback().await?;
                    false
                }
            };
            Ok::<bool, anyhow::Error>(won)
        });
        let begin_won = begin_task.await??;
        let cancel_won = cancel_task.await??;
        assert_ne!(begin_won, cancel_won, "exactly one cross-lane identity must win");

        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        let operations: i64 = tx
            .query_one(
                "SELECT count(*) FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2",
                &[&repo, &operation],
            )
            .await?
            .get(0);
        let cancellations: i64 = tx
            .query_one(
                "SELECT count(*) FROM ref_store_cancellations WHERE repository_id=$1 AND operation_id=$2",
                &[&repo, &operation],
            )
            .await?
            .get(0);
        assert_eq!(operations + cancellations, 1, "ambiguous operation/tombstone identity");
        if operations == 1 {
            let row = tx
                .query_one(
                    "SELECT issuer_id,lane,state FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2",
                    &[&repo, &operation],
                )
                .await?;
            assert_eq!(row.get::<_, Uuid>(0), actor);
            assert_eq!(row.get::<_, String>(1), "lane-a");
            assert_eq!(row.get::<_, String>(2), "pending");
        } else {
            let row = tx
                .query_one(
                    "SELECT issuer_id,lane FROM ref_store_cancellations WHERE repository_id=$1 AND operation_id=$2",
                    &[&repo, &operation],
                )
                .await?;
            assert_eq!(row.get::<_, Uuid>(0), foreign_issuer);
            assert_eq!(row.get::<_, String>(1), "lane-b");
        }
        tx.rollback().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("cross-lane race test panicked");
    teardown(&admin, &schema).await?;
    result??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn registry_methods_observe_absolute_deadline_while_lock_blocked() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let (admin, pool, schema, actor, repo) = setup(&url).await?;
    let result = tokio::spawn(async move {
        let store = PgRefStore;
        let operation = Uuid::new_v4();
        let original = identity(repo, actor, 1, operation, 11);

        // A pending operation exists first, so the same blocked key can probe
        // begin, cancel and record_terminal.
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        store.begin(&tx, &original, deadline()).await?;
        tx.commit().await?;

        let mut blocker = pool.get().await?;
        let hold = blocker.transaction().await?;
        hold.query_one(
            rootyard::ref_store::pg::OPERATION_LOCK_SQL,
            &[&rootyard::ref_store::pg::OPERATION_LOCK_DOMAIN, &repo, &operation],
        )
        .await?;

        let mut blocked = pool.get().await?;
        let tx = blocked.transaction().await?;
        let started = Instant::now();
        let error = store
            .begin(&tx, &original, Instant::now() + Duration::from_millis(250))
            .await
            .expect_err("blocked begin must hit its absolute deadline");
        assert!(matches!(&error, RefStoreError::Timeout), "unexpected begin error: {error}");
        assert!(started.elapsed() < Duration::from_secs(3), "deadline probe returned too late");
        tx.rollback().await?;

        let tx = blocked.transaction().await?;
        let error = store
            .record_terminal(&tx, &original, TerminalOutcome::Committed, &result(20), Instant::now() + Duration::from_millis(250))
            .await
            .expect_err("blocked terminal record must hit its absolute deadline");
        assert!(matches!(&error, RefStoreError::Timeout), "unexpected terminal error: {error}");
        tx.rollback().await?;

        let tx = blocked.transaction().await?;
        let error = store
            .cancel(&tx, &original, Instant::now() + Duration::from_millis(250))
            .await
            .expect_err("blocked cancel must hit its absolute deadline");
        assert!(matches!(&error, RefStoreError::Timeout), "unexpected cancel error: {error}");
        tx.rollback().await?;

        hold.rollback().await?;
        drop(blocker);

        // Block reserve_sequence's lane row after it has acquired the same
        // operation lock; verify the absolute-deadline wrapper protects it too.
        let lane = IssuerLane::new("reserve-blocked").unwrap();
        let reserve_operation = Uuid::new_v4();
        let mut lane_client = pool.get().await?;
        let tx = lane_client.transaction().await?;
        store.reserve_sequence(&tx, repo, actor, reserve_operation, &lane, deadline()).await?;
        tx.commit().await?;
        let mut lane_blocker = pool.get().await?;
        let lane_hold = lane_blocker.transaction().await?;
        lane_hold
            .query_one(
                "SELECT last_reserved_sequence FROM ref_store_issuer_lanes WHERE repository_id=$1 AND issuer_id=$2 AND lane=$3 FOR UPDATE",
                &[&repo, &actor, &lane.as_str()],
            )
            .await?;
        let tx = blocked.transaction().await?;
        let error = store
            .reserve_sequence(
                &tx,
                repo,
                actor,
                reserve_operation,
                &lane,
                Instant::now() + Duration::from_millis(250),
            )
            .await
            .expect_err("blocked reservation must hit its absolute deadline");
        assert!(matches!(&error, RefStoreError::Timeout), "unexpected reserve error: {error}");
        tx.rollback().await?;
        lane_hold.rollback().await?;
        drop(lane_blocker);
        drop(lane_client);

        let tx = blocked.transaction().await?;
        let replay = store.begin(&tx, &original, deadline()).await?;
        assert_eq!(replay.record.state(), OperationState::Pending);
        let cancelled = store.cancel(&tx, &original, deadline()).await?;
        assert_eq!(cancelled.record.as_ref().map(|record| record.state()), Some(OperationState::Cancelled));
        tx.commit().await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("deadline probe test panicked");
    teardown(&admin, &schema).await?;
    result??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn reservation_begin_and_cancel_share_operation_lock_without_deadlock() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let (admin, pool, schema, actor, repo) = setup(&url).await?;
    let result =
        tokio::spawn(async move {
            let operation = Uuid::new_v4();
            let lane = IssuerLane::new("reservation-race").unwrap();
            let digest = RequestDigest::from_bytes([31; 32]);

            let (reserved_tx, reserved_rx) = oneshot::channel();
            let (proceed_tx, proceed_rx) = oneshot::channel();
            let (begun_tx, begun_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel();
            let owner_pool = pool.clone();
            let owner = tokio::spawn(async move {
                let store = PgRefStore;
                let mut client = owner_pool.get().await?;
                let tx = client.transaction().await?;
                let reservation = store.reserve_sequence(&tx, repo, actor, operation, &lane, deadline()).await?;
                let identity = reservation.identity(digest)?;
                reserved_tx.send(()).map_err(|_| anyhow!("reserved receiver dropped"))?;
                proceed_rx.await?;
                store.begin(&tx, &identity, deadline()).await?;
                begun_tx.send(()).map_err(|_| anyhow!("begun receiver dropped"))?;
                release_rx.await?;
                tx.commit().await?;
                Ok::<(), anyhow::Error>(())
            });
            reserved_rx.await?;

            let (cancel_started_tx, cancel_started_rx) = oneshot::channel();
            let cancel_pool = pool.clone();
            let cancel_identity = identity_with_lane(repo, actor, "reservation-race", 1, operation, 31);
            let cancel_task = tokio::spawn(async move {
                let store = PgRefStore;
                let mut client = cancel_pool.get().await?;
                let tx = client.transaction().await?;
                let backend_pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
                cancel_started_tx.send(backend_pid).map_err(|_| anyhow!("cancel start receiver dropped"))?;
                let outcome = match store.cancel(&tx, &cancel_identity, deadline()).await {
                    Ok(_) => {
                        tx.commit().await?;
                        None
                    }
                    Err(error) => {
                        tx.rollback().await?;
                        Some(error)
                    }
                };
                Ok::<Option<RefStoreError>, anyhow::Error>(outcome)
            });
            let cancel_pid = cancel_started_rx.await?;
            let observer = pool.get().await?;
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let waiting: bool = observer.query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)",
                    &[&cancel_pid],
                ).await?.get(0);
                    if waiting {
                        break Ok::<(), anyhow::Error>(());
                    }
                    assert!(!cancel_task.is_finished(), "cancel finished before reaching the advisory-lock barrier");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .context("cancel never reached the advisory-lock barrier")??;
            drop(observer);

            // The owner can still enter begin while the cancel waits. Without the
            // pre-reservation operation lock this would invert into a lane/operation
            // deadlock. A database deadlock error fails this test below.
            proceed_tx.send(()).map_err(|_| anyhow!("proceed receiver dropped"))?;
            tokio::time::timeout(Duration::from_secs(5), begun_rx)
                .await
                .expect("begin deadlocked against reservation/cancel")?;
            release_tx.send(()).map_err(|_| anyhow!("release receiver dropped"))?;
            owner.await??;

            let cancel_outcome = tokio::time::timeout(Duration::from_secs(5), cancel_task)
                .await
                .expect("cancel deadlocked after owner commit")??;
            assert!(cancel_outcome.is_none(), "unexpected serialized cancel error: {cancel_outcome:?}");

            let mut client = pool.get().await?;
            let tx = client.transaction().await?;
            let row = tx
                .query_one(
                    "SELECT issuer_id,lane,state FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2",
                    &[&repo, &operation],
                )
                .await?;
            assert_eq!(row.get::<_, Uuid>(0), actor);
            assert_eq!(row.get::<_, String>(1), "reservation-race");
            assert_eq!(row.get::<_, String>(2), "cancelled");
            let tombstones: i64 = tx
                .query_one(
                    "SELECT count(*) FROM ref_store_cancellations WHERE repository_id=$1 AND operation_id=$2",
                    &[&repo, &operation],
                )
                .await?
                .get(0);
            assert_eq!(tombstones, 1);
            tx.rollback().await?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("reservation/begin/cancel race test panicked");
    teardown(&admin, &schema).await?;
    result??;
    Ok(())
}
