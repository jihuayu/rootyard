//! Focused PostgreSQL concurrency tests. Filesystem/CLI resolution is exercised
//! separately by tests/recovery_ops.py; SQL transitions here model that barrier.
use anyhow::{Context, Result};
use deadpool_postgres::{Manager, Pool};
use rootyard::{db, events};
use std::time::Duration;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn resolution_worker_fences() -> Result<()> {
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")?;
    let admin = db::pool(&url)?;
    let schema = format!("resolution_test_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=5000 -c lock_timeout=3000"));
    let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(10)
        .build()?;
    let result = tokio::spawn(async move {
        db::migrate(&pool).await?;
        verify(&pool).await
    })
    .await
    .context("fence test panicked");
    admin.get().await?.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await?;
    result??;
    Ok(())
}
fn change() -> events::RefEventInput {
    events::RefEventInput {
        transaction_sequence: 1,
        ref_name: "refs/heads/main".into(),
        old_oid: "0".repeat(40),
        new_oid: "1".repeat(40),
    }
}
async fn verify(pool: &Pool) -> Result<()> {
    let token = db::issue_token(pool, "alice", true, false).await?;
    let actor: Uuid = serde_json::from_value(token["user_id"].clone())?;
    let token_id: Uuid = serde_json::from_value(token["token_id"].clone())?;
    let repo = Uuid::new_v4();
    pool.get()
        .await?
        .execute("INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'fences','ready')", &[&repo, &actor])
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
        outcome: "recorded".into(),
        evidence: serde_json::json!({"fixture":"known receipt"}),
        admission: None,
    };
    events::publish(pool, &op, &[change()]).await?;
    let first = events::claim(pool, "ref-index", Uuid::new_v4(), 10, 60).await?.remove(0);
    assert!(events::acknowledge(pool, &first).await?);
    op.id = Uuid::new_v4();
    op.sequence = 2;
    events::publish(pool, &op, &[change()]).await?;
    let second = events::claim(pool, "ref-index", Uuid::new_v4(), 10, 60).await?.remove(0);
    // Hold a projection row. The worker must retain its shared repository fence
    // while waiting here, preventing a concurrent resolution from moving epochs.
    let mut blocker = pool.get().await?;
    let lock = blocker.transaction().await?;
    lock.query_one("SELECT repository_id FROM repository_ref_projection WHERE repository_id=$1 FOR UPDATE", &[&repo])
        .await?;
    let worker_pool = pool.clone();
    let task = tokio::spawn(async move { events::acknowledge(&worker_pool, &second).await });
    let mut observed_block = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut resolver = pool.get().await?;
        let tx = resolver.transaction().await?;
        tx.batch_execute("SET LOCAL lock_timeout='100ms'").await?;
        if tx.query_one("SELECT id FROM repositories WHERE id=$1 FOR UPDATE", &[&repo]).await.is_err() {
            observed_block = true;
            break;
        }
        tx.rollback().await?;
    }
    assert!(observed_block, "in-flight effect did not hold shared repository fence");
    lock.commit().await?;
    assert!(task.await??);
    // Reverse order: resolution acquires its fence first. A previously claimed
    // old event must wait, then observe the new generation, not recreate a missing row.
    op.id = Uuid::new_v4();
    op.sequence = 3;
    events::publish(pool, &op, &[change()]).await?;
    let stale = events::claim(pool, "ref-index", Uuid::new_v4(), 10, 60).await?.remove(0);
    let stale_id = stale.event_id.clone();
    let mut resolver = pool.get().await?;
    let tx = resolver.transaction().await?;
    tx.query_one("SELECT id FROM repositories WHERE id=$1 FOR UPDATE", &[&repo]).await?;
    let worker_pool = pool.clone();
    let task = tokio::spawn(async move { events::acknowledge(&worker_pool, &stale).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!task.is_finished());
    tx.execute("UPDATE repositories SET storage_generation=2 WHERE id=$1", &[&repo]).await?;
    tx.execute("DELETE FROM repository_ref_projection WHERE repository_id=$1", &[&repo]).await?;
    tx.commit().await?;
    assert!(task.await??);
    assert_eq!(
        pool.get()
            .await?
            .query_one("SELECT count(*) FROM repository_ref_projection WHERE repository_id=$1", &[&repo])
            .await?
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        pool.get()
            .await?
            .query_one("SELECT effect FROM event_deliveries WHERE event_id=$1 AND consumer='ref-index'", &[&stale_id])
            .await?
            .get::<_, String>(0),
        "superseded_generation"
    );
    // A lease can expire while waiting on the repository lock. Epoch validity does
    // not renew the claim; an expired owner cannot acknowledge the effect.
    op.id = Uuid::new_v4();
    op.sequence = 4;
    op.storage_generation = 2;
    events::publish(pool, &op, &[change()]).await?;
    let expired = events::claim(pool, "ref-index", Uuid::new_v4(), 10, 1).await?.remove(0);
    let saved = expired.clone();
    let mut resolver = pool.get().await?;
    let tx = resolver.transaction().await?;
    tx.query_one("SELECT id FROM repositories WHERE id=$1 FOR UPDATE", &[&repo]).await?;
    let worker_pool = pool.clone();
    let task = tokio::spawn(async move { events::acknowledge(&worker_pool, &expired).await });
    tokio::time::sleep(Duration::from_millis(1200)).await;
    tx.commit().await?;
    assert!(!task.await??);
    let current = events::claim(pool, "ref-index", Uuid::new_v4(), 10, 60).await?.remove(0);
    assert!(current.generation > saved.generation);
    assert!(!events::acknowledge(pool, &saved).await?);
    assert!(events::acknowledge(pool, &current).await?);
    // Defensively recheck predecessor barriers at acknowledgment time, even if a
    // publisher violated normal operation order by inserting earlier evidence late.
    let repo2 = Uuid::new_v4();
    pool.get()
        .await?
        .execute("INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'barrier','ready')", &[&repo2, &actor])
        .await?;
    op.id = Uuid::new_v4();
    op.repository_id = repo2;
    op.sequence = 2;
    op.storage_generation = 1;
    events::publish(pool, &op, &[change()]).await?;
    let claims = events::claim(pool, "ref-index", Uuid::new_v4(), 10, 60).await?;
    let claim = claims.into_iter().find(|c| c.repository_id == repo2).unwrap();
    let mut unknown = op.clone();
    unknown.id = Uuid::new_v4();
    unknown.sequence = 1;
    unknown.outcome = "unknown".into();
    unknown.evidence = serde_json::json!({"fixture":"unknown"});
    events::publish(pool, &unknown, &[]).await?;
    assert!(!events::acknowledge(pool, &claim).await?);
    // Model the durable SQL part of resolution. History stays unknown, and only
    // the explicitly covered operation loses its ordering barrier.
    let id = Uuid::new_v4();
    let volume = Uuid::new_v4();
    let hash = "a".repeat(64);
    let mut resolver = pool.get().await?;
    let tx = resolver.transaction().await?;
    tx.query_one("SELECT id FROM repositories WHERE id=$1 FOR UPDATE", &[&repo2]).await?;
    tx.execute("INSERT INTO recovery_resolutions(id,repository_id,old_generation,new_generation,incident_revision,inspected_fingerprint,volume_id,snapshot,reason) VALUES($1,$2,1,2,0,$3,$4,'{}','test modeled barrier')",&[&id,&repo2,&hash,&volume]).await?;
    tx.execute("INSERT INTO operation_resolutions(operation_id,repository_id,resolution_id,operation_digest) VALUES($1,$2,$3,$4)",&[&unknown.id,&repo2,&id,&hash]).await?;
    tx.execute("UPDATE repositories SET storage_generation=2 WHERE id=$1", &[&repo2]).await?;
    tx.commit().await?;
    assert!(events::acknowledge(pool, &claim).await?);
    assert_eq!(
        pool.get()
            .await?
            .query_one("SELECT count(*) FROM repository_ref_projection WHERE repository_id=$1", &[&repo2])
            .await?
            .get::<_, i64>(0),
        0
    );
    assert!(events::publish(pool, &unknown, &[]).await.is_err());
    assert!(
        pool.get()
            .await?
            .execute("UPDATE git_operations SET outcome='recorded' WHERE id=$1", &[&unknown.id])
            .await
            .is_err()
    );
    assert!(
        pool.get().await?.execute("UPDATE git_operations SET evidence='{}' WHERE id=$1", &[&unknown.id]).await.is_err()
    );
    assert!(
        pool.get()
            .await?
            .execute("DELETE FROM operation_resolutions WHERE operation_id=$1", &[&unknown.id])
            .await
            .is_err()
    );
    assert_eq!(
        pool.get()
            .await?
            .query_one("SELECT outcome FROM git_operations WHERE id=$1", &[&unknown.id])
            .await?
            .get::<_, String>(0),
        "unknown"
    );
    Ok(())
}
