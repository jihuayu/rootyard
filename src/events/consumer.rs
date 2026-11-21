//! Bounded consumer leases and delivery acknowledgment for the event outbox.
use anyhow::{Context, Result, bail, ensure};
use deadpool_postgres::Pool;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use super::{CONSUMERS, Claim};

fn valid_consumer(consumer: &str) -> Result<()> {
    ensure!(CONSUMERS.contains(&consumer), "unknown consumer");
    Ok(())
}

fn claim_from_row(row: &Row, consumer: &str, owner: Uuid, generation: i64) -> Claim {
    Claim {
        event_id: row.get("event_id"),
        consumer: consumer.into(),
        lease_owner: owner,
        generation,
        repository_id: row.get("repository_id"),
        operation_id: row.get("operation_id"),
        storage_generation: row.get("storage_generation"),
        operation_sequence: row.get("operation_sequence"),
        transaction_sequence: row.get("transaction_sequence"),
        ref_name: row.get("ref_name"),
        old_oid: row.get("old_oid"),
        new_oid: row.get("new_oid"),
    }
}

pub async fn claim(pool: &Pool, consumer: &str, owner: Uuid, limit: i64, lease_seconds: i64) -> Result<Vec<Claim>> {
    claim_scoped(pool, consumer, None, owner, limit, lease_seconds).await
}

/// Claim one exact consumer scope. `target_kind` is `None` for the shared
/// legacy/default queue or `Some(TARGET_AUDIT_KIND)` for the dedicated
/// standalone audit queue. The filter is part of the lease query, so a target
/// worker can never lease a legacy `audit-log` row.
async fn claim_scoped(
    pool: &Pool,
    consumer: &str,
    target_kind: Option<&str>,
    owner: Uuid,
    limit: i64,
    lease_seconds: i64,
) -> Result<Vec<Claim>> {
    valid_consumer(consumer)?;
    ensure!((1..=1000).contains(&limit) && (1..=3600).contains(&lease_seconds), "invalid claim bounds");
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let rows=tx.query("SELECT e.* FROM event_deliveries d JOIN outbox_events e USING(event_id) JOIN git_operations o ON o.id=e.operation_id WHERE d.consumer=$1 AND o.outcome <> 'unknown' AND ($3::text IS NULL OR (o.evidence->>'kind'=$3 AND o.evidence->>'authority'='pg_refstore' AND o.evidence->>'delivery'='audit-log' AND o.evidence->>'source'='ref_store_core_events' AND o.evidence->>'repository_id'=e.repository_id::text AND o.evidence->>'storage_generation'=e.storage_generation::text AND o.evidence->>'core_operation_id'=e.operation_id::text AND o.evidence->>'core_revision'=e.operation_sequence::text AND o.evidence->>'core_outcome'='committed')) AND d.state <> 'delivered' AND d.next_attempt_at <= clock_timestamp() AND (d.state='pending' OR d.lease_until <= clock_timestamp()) AND NOT EXISTS (SELECT 1 FROM outbox_events prior JOIN event_deliveries pd USING(event_id) WHERE pd.consumer=d.consumer AND pd.state <> 'delivered' AND prior.repository_id=e.repository_id AND prior.ref_name=e.ref_name AND (prior.storage_generation,prior.operation_sequence,prior.transaction_sequence)<(e.storage_generation,e.operation_sequence,e.transaction_sequence)) AND NOT EXISTS (SELECT 1 FROM git_operations unknown_op WHERE unknown_op.repository_id=e.repository_id AND unknown_op.outcome='unknown' AND NOT EXISTS(SELECT 1 FROM operation_resolutions resolved WHERE resolved.operation_id=unknown_op.id) AND (unknown_op.storage_generation,unknown_op.sequence)<(e.storage_generation,e.operation_sequence)) ORDER BY e.storage_generation,e.operation_sequence,e.transaction_sequence,e.event_id LIMIT $2 FOR UPDATE OF d SKIP LOCKED", &[&consumer,&limit,&target_kind]).await?;
    let mut claims = Vec::new();
    for row in rows {
        let id: String = row.get("event_id");
        // Recheck the clock only after obtaining the delivery row lock.
        if let Some(lease)=tx.query_opt("UPDATE event_deliveries SET state='leased',lease_owner=$3,lease_generation=lease_generation+1,lease_until=clock_timestamp()+($4::bigint * interval '1 second'),attempts=attempts+1 WHERE event_id=$1 AND consumer=$2 AND state <> 'delivered' AND next_attempt_at<=clock_timestamp() AND (state='pending' OR lease_until<=clock_timestamp()) RETURNING lease_generation", &[&id,&consumer,&owner,&lease_seconds]).await? {
            claims.push(claim_from_row(&row,consumer,owner,lease.get(0)));
        }
    }
    tx.commit().await?;
    Ok(claims)
}

async fn lock_valid_lease(tx: &Transaction<'_>, claim: &Claim) -> Result<bool> {
    valid_consumer(&claim.consumer)?;
    let exists = tx
        .query_opt(
            "SELECT event_id FROM event_deliveries WHERE event_id=$1 AND consumer=$2 FOR UPDATE",
            &[&claim.event_id, &claim.consumer],
        )
        .await?;
    if exists.is_none() {
        return Ok(false);
    }
    Ok(tx.query_one("SELECT state='leased' AND lease_owner=$3 AND lease_generation=$4 AND lease_until>clock_timestamp() FROM event_deliveries WHERE event_id=$1 AND consumer=$2", &[&claim.event_id,&claim.consumer,&claim.lease_owner,&claim.generation]).await?.get::<_,Option<bool>>(0).unwrap_or(false))
}

/// Apply the local database effect and delivery acknowledgment in one transaction.
/// No exactly-once promise is made for external side effects.
pub async fn acknowledge(pool: &Pool, claim: &Claim) -> Result<bool> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    // Canonical event metadata, never the caller's Claim payload, chooses the
    // repository. Repository -> delivery -> projection is the global lock order.
    let Some(event)=tx.query_opt("SELECT repository_id,storage_generation,operation_sequence,transaction_sequence,ref_name,operation_id FROM outbox_events WHERE event_id=$1",&[&claim.event_id]).await? else {return Ok(false);};
    let repository_id: Uuid = event.get(0);
    let current: i64 = tx
        .query_one("SELECT rootyard_worker_repository_generation($1, current_schema())", &[&repository_id])
        .await?
        .get(0);
    if !lock_valid_lease(&tx, claim).await? {
        return Ok(false);
    }
    let generation: i64 = event.get(1);
    let sequence: i64 = event.get(2);
    let ordinal: i64 = event.get(3);
    let ref_name: String = event.get(4);
    let operation_id: Uuid = event.get(5);
    let blocked:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM git_operations o WHERE o.repository_id=$1 AND o.outcome='unknown' AND NOT EXISTS(SELECT 1 FROM operation_resolutions r WHERE r.operation_id=o.id) AND (o.storage_generation,o.sequence)<=($2,$3)) OR EXISTS(SELECT 1 FROM outbox_events p JOIN event_deliveries d USING(event_id) WHERE p.repository_id=$1 AND p.ref_name=$4 AND d.consumer=$5 AND d.state<>'delivered' AND (p.storage_generation,p.operation_sequence,p.transaction_sequence)<($2,$3,$6)) OR EXISTS(SELECT 1 FROM git_operations o WHERE o.id=$7 AND o.outcome='unknown')",&[&repository_id,&generation,&sequence,&ref_name,&claim.consumer,&ordinal,&operation_id]).await?.get(0);
    if blocked {
        return Ok(false);
    }
    ensure!(generation <= current, "event generation exceeds repository generation");
    let superseded = claim.consumer == "ref-index" && generation < current;
    // CI maintenance has exact root-observation evidence, not a native push
    // receipt. Keep its outbox/audit trail, but never label it push_receipt in
    // the user ref projection. Explicit recovery snapshots remain independent.
    let ci_maintenance: bool = tx
        .query_one(
            "SELECT COALESCE(evidence->>'kind'='observed_immutable_ci_root',false) FROM git_operations WHERE id=$1",
            &[&operation_id],
        )
        .await?
        .get(0);
    // A repository with a durable `pg_refstore` serving binding is the single
    // ref authority: keep its outbox/audit trail, but never mirror it into the
    // legacy rebuildable projection (migration 145 refuses that second write).
    let pg_refstore_served: bool = if tx
        .query_one("SELECT to_regclass(format('%I.ref_store_serving_repositories', current_schema())) IS NOT NULL", &[])
        .await?
        .get(0)
    {
        tx.query_one(
            "SELECT EXISTS (SELECT 1 FROM ref_store_serving_repositories WHERE repository_id=$1)",
            &[&repository_id],
        )
        .await?
        .get(0)
    } else {
        false
    };
    match claim.consumer.as_str() {
        "audit-log" => {
            tx.execute("INSERT INTO audit_events(event_id) VALUES($1) ON CONFLICT DO NOTHING", &[&claim.event_id])
                .await?;
        }
        "ref-index" if !superseded && !ci_maintenance && !pg_refstore_served => {
            tx.execute("INSERT INTO repository_ref_projection(repository_id,ref_name,oid,deleted,storage_generation,operation_sequence,transaction_sequence,event_id) SELECT repository_id,ref_name,CASE WHEN new_oid ~ '^0+$' THEN NULL ELSE new_oid END,new_oid ~ '^0+$',storage_generation,operation_sequence,transaction_sequence,event_id FROM outbox_events WHERE event_id=$1 ON CONFLICT(repository_id,ref_name) DO UPDATE SET oid=EXCLUDED.oid,deleted=EXCLUDED.deleted,storage_generation=EXCLUDED.storage_generation,operation_sequence=EXCLUDED.operation_sequence,transaction_sequence=EXCLUDED.transaction_sequence,event_id=EXCLUDED.event_id,source_kind='push_receipt',resolution_id=NULL,updated_at=clock_timestamp() WHERE (repository_ref_projection.storage_generation,repository_ref_projection.operation_sequence,repository_ref_projection.transaction_sequence)<(EXCLUDED.storage_generation,EXCLUDED.operation_sequence,EXCLUDED.transaction_sequence)", &[&claim.event_id]).await?;
        }
        "ref-index" => {}
        _ => bail!("unknown consumer"),
    }
    // Effects may wait on another lock. Expiry is checked again before commit;
    // an expired fence rolls back the entire local effect.
    let effect = if superseded { "superseded_generation" } else { "applied" };
    let count=tx.execute("UPDATE event_deliveries SET state='delivered',lease_owner=NULL,lease_until=NULL,delivered_at=clock_timestamp(),last_error_code=NULL,effect=$5 WHERE event_id=$1 AND consumer=$2 AND state='leased' AND lease_owner=$3 AND lease_generation=$4 AND lease_until>clock_timestamp()", &[&claim.event_id,&claim.consumer,&claim.lease_owner,&claim.generation,&effect]).await?;
    if count == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

pub async fn fail(pool: &Pool, claim: &Claim, error_code: &str, delay_seconds: i64) -> Result<bool> {
    ensure!((0..=86400).contains(&delay_seconds), "invalid retry delay");
    ensure!(
        !error_code.is_empty()
            && error_code.len() <= 64
            && error_code.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "invalid error code"
    );
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    if !lock_valid_lease(&tx, claim).await? {
        return Ok(false);
    }
    let count=tx.execute("UPDATE event_deliveries SET state='pending',lease_owner=NULL,lease_until=NULL,next_attempt_at=clock_timestamp()+($5::bigint * interval '1 second'),last_error_code=$6 WHERE event_id=$1 AND consumer=$2 AND state='leased' AND lease_owner=$3 AND lease_generation=$4 AND lease_until>clock_timestamp()", &[&claim.event_id,&claim.consumer,&claim.lease_owner,&claim.generation,&delay_seconds,&error_code]).await?;
    tx.commit().await?;
    Ok(count == 1)
}

pub async fn worker_once(pool: &Pool, consumer: &str, owner: Uuid, limit: i64) -> Result<usize> {
    worker_once_with_lease(pool, consumer, owner, limit, 60).await
}

pub async fn worker_once_with_lease(
    pool: &Pool,
    consumer: &str,
    owner: Uuid,
    limit: i64,
    lease_seconds: i64,
) -> Result<usize> {
    worker_once_with_lease_scoped(pool, consumer, None, owner, limit, lease_seconds).await
}

/// One bounded scan over an optional evidence-scoped consumer queue. Standalone
/// passes `TARGET_AUDIT_KIND` and the audit-log consumer; the legacy defaults
/// pass `None` and keep their existing full per-consumer scan.
pub async fn worker_once_with_lease_scoped(
    pool: &Pool,
    consumer: &str,
    target_kind: Option<&str>,
    owner: Uuid,
    limit: i64,
    lease_seconds: i64,
) -> Result<usize> {
    let claims = claim_scoped(pool, consumer, target_kind, owner, limit, lease_seconds).await?;
    run_claims(pool, claims).await
}

async fn run_claims(pool: &Pool, claims: Vec<Claim>) -> Result<usize> {
    let mut count = 0;
    for item in claims {
        match acknowledge(pool, &item).await {
            Ok(true) => count += 1,
            Ok(false) => {}
            Err(error) => {
                fail(pool, &item, "local_effect_failed", 5).await.context("reschedule local consumer")?;
                return Err(error);
            }
        }
    }
    Ok(count)
}
