//! Run with ROOTYARD_TEST_DATABASE_URL=postgresql://... cargo test --test outbox -- --ignored.
//! Uses a unique schema and removes it even if an assertion panics.
use anyhow::{Context, Result};
use deadpool_postgres::{Manager, Pool};
use rootyard::{db, events};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and PostgreSQL schema creation permission"]
async fn durable_outbox_contract() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL").context("set ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&url)?;
    let schema = format!("outbox_test_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let result = run_in_schema(&url, &schema).await;
    admin.get().await?.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await?;
    result
}
async fn run_in_schema(url: &str, schema: &str) -> Result<()> {
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!("-c search_path={schema} -c statement_timeout=5000 -c lock_timeout=3000"));
    let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(8)
        .build()?;
    // Spawn makes assertion panics return here, allowing schema cleanup.
    tokio::spawn(async move {
        db::migrate(&pool).await?;
        pool.get().await?.batch_execute(include_str!("../migrations/002_reliability.sql")).await?;
        pool.get().await?.batch_execute(include_str!("../migrations/002_reliability.sql")).await?;
        verify_contract(&pool).await
    })
    .await
    .context("outbox test panicked")?
}
async fn verify_contract(pool: &Pool) -> Result<()> {
    let token = db::issue_token(pool, "alice", true, false).await?;
    let actor: Uuid = serde_json::from_value(token["user_id"].clone())?;
    let token_id: Uuid = serde_json::from_value(token["token_id"].clone())?;
    let repo = Uuid::new_v4();
    pool.get()
        .await?
        .execute("INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'test','ready')", &[&repo, &actor])
        .await?;
    let mut op = events::OperationRecord {
        id: Uuid::new_v4(),
        repository_id: repo,
        actor_id: actor,
        token_id,
        service_principal_id: None,
        actor_name: "alice".into(),
        sequence: 1,
        storage_generation: 1,
        outcome: "unknown".into(),
        evidence: serde_json::json!({"state":"prepared"}),
    };
    let a = "1".repeat(40);
    let b = "2".repeat(40);
    let zero = "0".repeat(40);
    let changes = vec![
        events::RefEventInput {
            transaction_sequence: 1,
            ref_name: "refs/heads/main".into(),
            old_oid: zero.clone(),
            new_oid: a.clone(),
        },
        events::RefEventInput {
            transaction_sequence: 2,
            ref_name: "refs/heads/main".into(),
            old_oid: a.clone(),
            new_oid: b.clone(),
        },
        events::RefEventInput {
            transaction_sequence: 3,
            ref_name: "refs/heads/main".into(),
            old_oid: b.clone(),
            new_oid: a.clone(),
        },
    ];
    events::publish(pool, &op, &changes[..1]).await?;
    assert!(events::claim(pool, "ref-index", Uuid::new_v4(), 100, 60).await?.is_empty());
    op.outcome = "recorded".into();
    op.evidence = serde_json::json!({"state":"completed", "receipt":["refs/heads/main"]});
    events::publish(pool, &op, &changes).await?;
    events::publish(pool, &op, &changes).await?;
    assert_eq!(events::pending_count(pool).await?, 6);
    let mut altered_evidence = op.clone();
    altered_evidence.evidence = serde_json::json!({"state":"tampered"});
    assert!(events::publish(pool, &altered_evidence, &changes).await.is_err());
    let saved = pool.get().await?.query_one("SELECT evidence FROM git_operations WHERE id=$1", &[&op.id]).await?;
    assert_eq!(saved.get::<_, serde_json::Value>(0), op.evidence);
    assert!(events::publish(pool, &op, &changes[..1]).await.is_err());
    let mut invalid = changes.clone();
    invalid[0].new_oid = b.clone();
    assert!(events::publish(pool, &op, &invalid).await.is_err());
    let owner = Uuid::new_v4();
    let claim = events::claim(pool, "ref-index", owner, 100, 1).await?.remove(0);
    assert_eq!(claim.transaction_sequence, 1);
    assert!(events::claim(pool, "ref-index", Uuid::new_v4(), 100, 60).await?.is_empty());
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(!events::acknowledge(pool, &claim).await?);
    let newer = events::claim(pool, "ref-index", owner, 100, 60).await?.remove(0);
    assert_eq!(newer.generation, claim.generation + 1);
    assert!(!events::fail(pool, &claim, "stale", 0).await?);
    assert!(events::fail(pool, &newer, "retry", 0).await?);
    for _ in 0..3 {
        assert_eq!(events::worker_once(pool, "ref-index", owner, 100).await?, 1);
    }
    for _ in 0..3 {
        assert_eq!(events::worker_once(pool, "audit-log", owner, 100).await?, 1);
    }
    assert_eq!(events::pending_count(pool).await?, 0);
    let row = pool
        .get()
        .await?
        .query_one("SELECT oid,transaction_sequence FROM repository_ref_projection WHERE repository_id=$1", &[&repo])
        .await?;
    assert_eq!(row.get::<_, String>(0), a);
    assert_eq!(row.get::<_, i64>(1), 3);
    // Prepared-only unknown must block even without a known event.
    let mut unknown = op.clone();
    unknown.id = Uuid::new_v4();
    unknown.sequence = 2;
    unknown.outcome = "unknown".into();
    events::publish(pool, &unknown, &[]).await?;
    let mut deletion = op.clone();
    deletion.id = Uuid::new_v4();
    deletion.sequence = 3;
    let deleted = vec![events::RefEventInput {
        transaction_sequence: 1,
        ref_name: "refs/heads/main".into(),
        old_oid: a.clone(),
        new_oid: zero.clone(),
    }];
    events::publish(pool, &deletion, &deleted).await?;
    assert!(events::claim(pool, "ref-index", owner, 100, 60).await?.is_empty());
    unknown.outcome = "no_ref_changes".into();
    events::publish(pool, &unknown, &[]).await?;
    let (one, two) = tokio::join!(
        events::claim(pool, "ref-index", Uuid::new_v4(), 100, 60),
        events::claim(pool, "ref-index", Uuid::new_v4(), 100, 60)
    );
    let mut both = one?;
    both.extend(two?);
    assert_eq!(both.len(), 1);
    let mut forged = both[0].clone();
    forged.repository_id = Uuid::new_v4();
    forged.new_oid = b.clone();
    assert!(events::acknowledge(pool, &forged).await?);
    let row = pool
        .get()
        .await?
        .query_one("SELECT deleted,oid FROM repository_ref_projection WHERE repository_id=$1", &[&repo])
        .await?;
    assert!(row.get::<_, bool>(0));
    assert!(row.get::<_, Option<String>>(1).is_none());
    let mut forged_op = op.clone();
    forged_op.id = Uuid::new_v4();
    forged_op.sequence = 4;
    forged_op.actor_id = Uuid::new_v4();
    assert!(events::publish(pool, &forged_op, &changes).await.is_err());
    assert!(events::claim(pool, "not-supported", owner, 100, 60).await.is_err());
    // A worker may wait on the delivery lock until after its lease expires.
    let mut fourth = op.clone();
    fourth.id = Uuid::new_v4();
    fourth.sequence = 4;
    let final_change = vec![events::RefEventInput {
        transaction_sequence: 1,
        ref_name: "refs/heads/main".into(),
        old_oid: zero.clone(),
        new_oid: b.clone(),
    }];
    events::publish(pool, &fourth, &final_change).await?;
    let delayed_claim = events::claim(pool, "ref-index", owner, 100, 2).await?.remove(0);
    let mut blocking_client = pool.get().await?;
    let blocking_tx = blocking_client.transaction().await?;
    blocking_tx
        .query_one(
            "SELECT event_id FROM event_deliveries WHERE event_id=$1 AND consumer='ref-index' FOR UPDATE",
            &[&delayed_claim.event_id],
        )
        .await?;
    let worker_pool = pool.clone();
    let delayed = tokio::spawn(async move { events::acknowledge(&worker_pool, &delayed_claim).await });
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    blocking_tx.commit().await?;
    assert!(!delayed.await??);

    // Even when the initial fence check passes, waiting on a projection lock
    // must not allow effects or ack to commit after the lease deadline.
    let effect_claim = events::claim(pool, "ref-index", owner, 100, 2).await?.remove(0);
    let blocking_tx = blocking_client.transaction().await?;
    blocking_tx
        .query_one("SELECT repository_id FROM repository_ref_projection WHERE repository_id=$1 FOR UPDATE", &[&repo])
        .await?;
    let worker_pool = pool.clone();
    let delayed = tokio::spawn(async move { events::acknowledge(&worker_pool, &effect_claim).await });
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    blocking_tx.commit().await?;
    assert!(!delayed.await??);
    let row = pool
        .get()
        .await?
        .query_one("SELECT deleted FROM repository_ref_projection WHERE repository_id=$1", &[&repo])
        .await?;
    assert!(row.get::<_, bool>(0), "expired effect must roll back");
    assert_eq!(events::worker_once(pool, "ref-index", owner, 100).await?, 1);
    println!(
        "PASS prepared-only unknown barrier/concurrent claims/deletion/trusted database payload/ownership FK isolation/consumer allowlist"
    );
    println!(
        "PASS migration upgrade/replay/unknown blocking/ABA order/lease expiry/reclaim/fencing/retry/transactional consumers"
    );
    Ok(())
}
