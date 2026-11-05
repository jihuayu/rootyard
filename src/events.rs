//! PostgreSQL outbox and fenced, transactional local consumers.
//! These projections are rebuildable; GitFS is the authoritative ref store.
use anyhow::{Context, Result, bail, ensure};
use deadpool_postgres::Pool;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
pub struct OperationRecord {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub actor_id: Uuid,
    pub token_id: Uuid,
    pub actor_name: String,
    pub sequence: i64,
    pub storage_generation: i64,
    pub outcome: String,
    pub evidence: serde_json::Value,
}
#[derive(Clone, Debug, Serialize)]
pub struct RefEventInput {
    pub transaction_sequence: i64,
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Claim {
    pub event_id: String,
    pub consumer: String,
    pub lease_owner: Uuid,
    pub generation: i64,
    pub repository_id: Uuid,
    pub operation_id: Uuid,
    pub storage_generation: i64,
    pub operation_sequence: i64,
    pub transaction_sequence: i64,
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
}
pub const CONSUMERS: &[&str] = &["audit-log", "ref-index"];
fn valid_consumer(consumer: &str) -> Result<()> {
    ensure!(CONSUMERS.contains(&consumer), "unknown consumer");
    Ok(())
}
pub fn event_id(operation_id: Uuid, transaction_sequence: i64, ref_name: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"rootyard-ref-event-v1\0");
    hash.update(operation_id.as_bytes());
    hash.update(transaction_sequence.to_be_bytes());
    hash.update(ref_name.as_bytes());
    hex::encode(hash.finalize())
}
fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64)
        && oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Replay verifies immutable metadata and events. Unknown evidence may grow;
/// terminal publication must contain the complete, identical transaction set.
pub async fn publish(
    pool: &Pool,
    operation: &OperationRecord,
    changes: &[RefEventInput],
) -> Result<()> {
    ensure!(
        matches!(
            operation.outcome.as_str(),
            "unknown" | "recorded" | "no_ref_changes"
        ),
        "invalid outcome"
    );
    ensure!(
        operation.sequence > 0 && operation.storage_generation > 0,
        "invalid operation sequence"
    );
    ensure!(
        crate::db::valid_name(&operation.actor_name),
        "invalid actor name"
    );
    ensure!(changes.len() <= 100_000, "too many ref events");
    ensure!(
        operation.outcome != "no_ref_changes" || changes.is_empty(),
        "no_ref_changes contains events"
    );
    let mut ids = std::collections::HashSet::new();
    for change in changes {
        ensure!(
            change.transaction_sequence > 0
                && change.ref_name.starts_with("refs/")
                && change.ref_name.len() <= 1024
                && !change.ref_name.bytes().any(|b| b <= 32 || b == 127),
            "invalid ref event"
        );
        ensure!(
            valid_oid(&change.old_oid)
                && valid_oid(&change.new_oid)
                && change.old_oid.len() == change.new_oid.len(),
            "invalid event oid"
        );
        ensure!(
            ids.insert(event_id(
                operation.id,
                change.transaction_sequence,
                &change.ref_name
            )),
            "duplicate ref event"
        );
    }
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    // Shared repository lock orders publication against explicit offline resolution.
    tx.query_one(
        "SELECT id FROM repositories WHERE id=$1 FOR SHARE",
        &[&operation.repository_id],
    )
    .await?;
    ensure!(
        tx.query_opt(
            "SELECT operation_id FROM operation_resolutions WHERE operation_id=$1",
            &[&operation.id]
        )
        .await?
        .is_none(),
        "resolved operation is immutable"
    );
    tx.execute("INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,storage_generation,outcome,evidence) VALUES($1,$2,$3,$4,$5,$6,$7,'unknown',$8) ON CONFLICT(id) DO NOTHING", &[&operation.id,&operation.repository_id,&operation.actor_id,&operation.token_id,&operation.actor_name,&operation.sequence,&operation.storage_generation,&operation.evidence]).await?;
    let row = tx
        .query_one(
            "SELECT * FROM git_operations WHERE id=$1 FOR UPDATE",
            &[&operation.id],
        )
        .await?;
    ensure!(
        row.get::<_, Uuid>("repository_id") == operation.repository_id
            && row.get::<_, Uuid>("actor_id") == operation.actor_id
            && row.get::<_, Uuid>("token_id") == operation.token_id
            && row.get::<_, String>("actor_name") == operation.actor_name
            && row.get::<_, i64>("sequence") == operation.sequence
            && row.get::<_, i64>("storage_generation") == operation.storage_generation,
        "operation replay metadata mismatch"
    );
    let previous: String = row.get("outcome");
    ensure!(
        previous == "unknown" || previous == operation.outcome,
        "terminal operation outcome mismatch"
    );
    let existing = tx
        .query(
            "SELECT event_id FROM outbox_events WHERE operation_id=$1",
            &[&operation.id],
        )
        .await?;
    if operation.outcome != "unknown" || previous != "unknown" {
        ensure!(
            existing
                .iter()
                .all(|row| ids.contains(&row.get::<_, String>(0))),
            "operation replay omitted existing events"
        );
    }
    if previous != "unknown" {
        ensure!(
            row.get::<_, serde_json::Value>("evidence") == operation.evidence,
            "terminal operation evidence mismatch"
        );
        ensure!(
            existing.len() == changes.len(),
            "terminal operation cannot gain events"
        );
    }
    for change in changes {
        let id = event_id(operation.id, change.transaction_sequence, &change.ref_name);
        tx.execute("INSERT INTO outbox_events(event_id,operation_id,repository_id,storage_generation,operation_sequence,transaction_sequence,ref_name,old_oid,new_oid) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(event_id) DO NOTHING", &[&id,&operation.id,&operation.repository_id,&operation.storage_generation,&operation.sequence,&change.transaction_sequence,&change.ref_name,&change.old_oid,&change.new_oid]).await?;
        let old = tx.query_one("SELECT operation_id,transaction_sequence,ref_name,old_oid,new_oid FROM outbox_events WHERE event_id=$1", &[&id]).await?;
        ensure!(
            old.get::<_, Uuid>(0) == operation.id
                && old.get::<_, i64>(1) == change.transaction_sequence
                && old.get::<_, String>(2) == change.ref_name
                && old.get::<_, String>(3) == change.old_oid
                && old.get::<_, String>(4) == change.new_oid,
            "event replay mismatch"
        );
        tx.execute("INSERT INTO event_deliveries(event_id,consumer) VALUES($1,'audit-log'),($1,'ref-index') ON CONFLICT DO NOTHING", &[&id]).await?;
    }
    tx.execute("UPDATE git_operations SET outcome=$2,evidence=$3,settled_at=CASE WHEN $2='unknown' THEN NULL ELSE COALESCE(settled_at,clock_timestamp()) END WHERE id=$1", &[&operation.id,&operation.outcome,&operation.evidence]).await?;
    tx.commit().await?;
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

pub async fn claim(
    pool: &Pool,
    consumer: &str,
    owner: Uuid,
    limit: i64,
    lease_seconds: i64,
) -> Result<Vec<Claim>> {
    valid_consumer(consumer)?;
    ensure!(
        (1..=1000).contains(&limit) && (1..=3600).contains(&lease_seconds),
        "invalid claim bounds"
    );
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let rows=tx.query("SELECT e.* FROM event_deliveries d JOIN outbox_events e USING(event_id) JOIN git_operations o ON o.id=e.operation_id WHERE d.consumer=$1 AND o.outcome <> 'unknown' AND d.state <> 'delivered' AND d.next_attempt_at <= clock_timestamp() AND (d.state='pending' OR d.lease_until <= clock_timestamp()) AND NOT EXISTS (SELECT 1 FROM outbox_events prior JOIN event_deliveries pd USING(event_id) WHERE pd.consumer=d.consumer AND pd.state <> 'delivered' AND prior.repository_id=e.repository_id AND prior.ref_name=e.ref_name AND (prior.storage_generation,prior.operation_sequence,prior.transaction_sequence)<(e.storage_generation,e.operation_sequence,e.transaction_sequence)) AND NOT EXISTS (SELECT 1 FROM git_operations unknown_op WHERE unknown_op.repository_id=e.repository_id AND unknown_op.outcome='unknown' AND NOT EXISTS(SELECT 1 FROM operation_resolutions resolved WHERE resolved.operation_id=unknown_op.id) AND (unknown_op.storage_generation,unknown_op.sequence)<(e.storage_generation,e.operation_sequence)) ORDER BY e.storage_generation,e.operation_sequence,e.transaction_sequence,e.event_id LIMIT $2 FOR UPDATE OF d SKIP LOCKED", &[&consumer,&limit]).await?;
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
        .query_one(
            "SELECT storage_generation FROM repositories WHERE id=$1 FOR SHARE",
            &[&repository_id],
        )
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
    ensure!(
        generation <= current,
        "event generation exceeds repository generation"
    );
    let superseded = claim.consumer == "ref-index" && generation < current;
    // CI maintenance has exact root-observation evidence, not a native push
    // receipt. Keep its outbox/audit trail, but never label it push_receipt in
    // the user ref projection. Explicit recovery snapshots remain independent.
    let ci_maintenance: bool = tx.query_one("SELECT COALESCE(evidence->>'kind'='observed_immutable_ci_root',false) FROM git_operations WHERE id=$1", &[&operation_id]).await?.get(0);
    match claim.consumer.as_str() {
        "audit-log" => {
            tx.execute(
                "INSERT INTO audit_events(event_id) VALUES($1) ON CONFLICT DO NOTHING",
                &[&claim.event_id],
            )
            .await?;
        }
        "ref-index" if !superseded && !ci_maintenance => {
            tx.execute("INSERT INTO repository_ref_projection(repository_id,ref_name,oid,deleted,storage_generation,operation_sequence,transaction_sequence,event_id) SELECT repository_id,ref_name,CASE WHEN new_oid ~ '^0+$' THEN NULL ELSE new_oid END,new_oid ~ '^0+$',storage_generation,operation_sequence,transaction_sequence,event_id FROM outbox_events WHERE event_id=$1 ON CONFLICT(repository_id,ref_name) DO UPDATE SET oid=EXCLUDED.oid,deleted=EXCLUDED.deleted,storage_generation=EXCLUDED.storage_generation,operation_sequence=EXCLUDED.operation_sequence,transaction_sequence=EXCLUDED.transaction_sequence,event_id=EXCLUDED.event_id,source_kind='push_receipt',resolution_id=NULL,updated_at=clock_timestamp() WHERE (repository_ref_projection.storage_generation,repository_ref_projection.operation_sequence,repository_ref_projection.transaction_sequence)<(EXCLUDED.storage_generation,EXCLUDED.operation_sequence,EXCLUDED.transaction_sequence)", &[&claim.event_id]).await?;
        }
        "ref-index" => {}
        _ => bail!("unknown consumer"),
    }
    // Effects may wait on another lock. Expiry is checked again before commit;
    // an expired fence rolls back the entire local effect.
    let effect = if superseded {
        "superseded_generation"
    } else {
        "applied"
    };
    let count=tx.execute("UPDATE event_deliveries SET state='delivered',lease_owner=NULL,lease_until=NULL,delivered_at=clock_timestamp(),last_error_code=NULL,effect=$5 WHERE event_id=$1 AND consumer=$2 AND state='leased' AND lease_owner=$3 AND lease_generation=$4 AND lease_until>clock_timestamp()", &[&claim.event_id,&claim.consumer,&claim.lease_owner,&claim.generation,&effect]).await?;
    if count == 0 {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

pub async fn fail(
    pool: &Pool,
    claim: &Claim,
    error_code: &str,
    delay_seconds: i64,
) -> Result<bool> {
    ensure!((0..=86400).contains(&delay_seconds), "invalid retry delay");
    ensure!(
        !error_code.is_empty()
            && error_code.len() <= 64
            && error_code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
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
    let claims = claim(pool, consumer, owner, limit, lease_seconds).await?;
    let mut count = 0;
    for item in claims {
        match acknowledge(pool, &item).await {
            Ok(true) => count += 1,
            Ok(false) => {}
            Err(error) => {
                fail(pool, &item, "local_effect_failed", 5)
                    .await
                    .context("reschedule local consumer")?;
                return Err(error);
            }
        }
    }
    Ok(count)
}

pub async fn pending_count(pool: &Pool) -> Result<i64> {
    Ok(pool
        .get()
        .await?
        .query_one(
            "SELECT count(*) FROM event_deliveries WHERE state <> 'delivered'",
            &[],
        )
        .await?
        .get(0))
}
