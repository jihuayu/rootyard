//! Reliable Ref-CAS projection business jobs (`ref_cas_projection_jobs`) and
//! transactional / backfill webhook enqueueing (`forge_webhook_deliveries`) (#117).

use super::identity::derive_webhook_event_id;
use super::pg::{from_pg_u64, pg_err, projection_tables_present};
use super::types::{
    ProjectedRefDelta, ProjectionError, ProjectionJobKind, ProjectionJobRecord, ProjectionJobState, ProjectionRealm,
    RefCasEventEnvelope,
};
use crate::webhooks::signing::{build_delivery_headers, signature_header};
use deadpool_postgres::{Pool, Transaction};
use serde_json::{Value, json};
use tokio::time::Instant;
use uuid::Uuid;

pub(crate) async fn insert_jobs_in_tx(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    jobs: &[super::types::ProjectionJobSpec],
) -> Result<usize, ProjectionError> {
    let mut inserted = 0usize;
    for job in jobs {
        let log_index = super::pg::to_pg_i64(job.log_index, "log_index")?;
        let event_seq = super::pg::to_pg_i64(job.event_seq, "event_seq")?;
        let n = tx
            .execute(
                "INSERT INTO ref_cas_projection_jobs \
                 (job_key, repository_id, tenant_id, op_event_id, history_incarnation, group_id, \
                  group_epoch, log_index, event_seq, kind, scope_key, state, payload) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'queued',$12) \
                 ON CONFLICT (job_key) DO NOTHING",
                &[
                    &job.job_key,
                    &job.repository_id,
                    &tenant_id,
                    &job.op_event_id,
                    &job.realm.history_incarnation,
                    &job.realm.group_id,
                    &job.realm.group_epoch,
                    &log_index,
                    &event_seq,
                    &job.kind.as_str(),
                    &job.scope_key,
                    &job.payload,
                ],
            )
            .await
            .map_err(pg_err)?;
        if n == 1 {
            inserted += 1;
        }
    }
    Ok(inserted)
}

/// Inserts signed `push` deliveries for every active push hook on the repository inside the
/// caller's projection PG transaction so ref projection, jobs, webhooks, and cursor commit as one.
pub(crate) async fn enqueue_push_webhooks_in_tx(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    envelope: &RefCasEventEnvelope,
    op_event_id: &str,
    delta: &ProjectedRefDelta,
) -> Result<usize, ProjectionError> {
    if !delta.emit_push_webhook || crate::ci_pins::reserved(&delta.ref_name) {
        return Ok(0);
    }
    let hooks = tx
        .query(
            "SELECT id, secret, max_attempts FROM forge_webhooks \
             WHERE tenant_id = $1 AND repository_id = $2 AND active = true AND events ? 'push' \
             ORDER BY created_at ASC, id ASC FOR UPDATE",
            &[&tenant_id, &envelope.repository_id],
        )
        .await
        .map_err(pg_err)?;

    let payload = json!({
        "event": "push",
        "event_id": delta.event_id,
        "op_event_id": op_event_id,
        "operation_id": envelope.operation_id,
        "repository_id": envelope.repository_id,
        "revision": envelope.revision,
        "history_incarnation": envelope.realm.history_incarnation,
        "group_id": envelope.realm.group_id,
        "group_epoch": envelope.realm.group_epoch,
        "log_index": envelope.log_index,
        "ref_name": delta.ref_name,
        "old_oid": delta.old_oid,
        "new_oid": delta.new_oid,
    });
    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|e| ProjectionError::Decode(format!("encode webhook payload: {e}")))?;

    let mut enqueued = 0usize;
    for hook in &hooks {
        let webhook_id: Uuid = hook.get("id");
        let secret: String = hook.get("secret");
        let max_attempts: i64 = hook.get("max_attempts");
        if insert_single_webhook_delivery_tx(
            tx,
            WebhookDeliverySpec {
                tenant_id,
                repository_id: envelope.repository_id,
                webhook_id,
                secret: &secret,
                max_attempts,
                delivery_event_id: &delta.webhook_event_id,
                payload: &payload,
                payload_bytes: &payload_bytes,
            },
        )
        .await?
        {
            enqueued += 1;
        }
    }
    Ok(enqueued)
}

struct WebhookDeliverySpec<'a> {
    tenant_id: Uuid,
    repository_id: Uuid,
    webhook_id: Uuid,
    secret: &'a str,
    max_attempts: i64,
    delivery_event_id: &'a str,
    payload: &'a Value,
    payload_bytes: &'a [u8],
}

async fn insert_single_webhook_delivery_tx(
    tx: &Transaction<'_>,
    spec: WebhookDeliverySpec<'_>,
) -> Result<bool, ProjectionError> {
    let WebhookDeliverySpec {
        tenant_id,
        repository_id,
        webhook_id,
        secret,
        max_attempts,
        delivery_event_id,
        payload,
        payload_bytes,
    } = spec;
    let exists = tx
        .query_opt(
            "SELECT 1 FROM forge_webhook_deliveries WHERE webhook_id = $1 AND event_id = $2",
            &[&webhook_id, &delivery_event_id],
        )
        .await
        .map_err(pg_err)?;
    if exists.is_some() {
        return Ok(false);
    }

    let last: i64 = tx
        .query_one(
            "SELECT COALESCE((SELECT sequence FROM forge_webhook_deliveries \
             WHERE tenant_id = $1 AND repository_id = $2 AND webhook_id = $3 \
             ORDER BY sequence DESC LIMIT 1), 0)",
            &[&tenant_id, &repository_id, &webhook_id],
        )
        .await
        .map_err(pg_err)?
        .get(0);
    let sequence =
        last.checked_add(1).ok_or_else(|| ProjectionError::Database("webhook delivery sequence overflow".into()))?;
    let delivery_id = Uuid::new_v4();
    let sig = signature_header(secret, payload_bytes);
    let req_headers = build_delivery_headers("push", delivery_id, webhook_id, 1, &sig);

    let inserted = tx
        .execute(
            "INSERT INTO forge_webhook_deliveries \
             (id, webhook_id, tenant_id, repository_id, sequence, event_id, event_type, payload, \
              request_headers, signature_256, state, attempts, max_attempts, next_attempt_unix) \
             VALUES ($1,$2,$3,$4,$5,$6,'push',$7,$8,$9,'pending',0,$10,0) \
             ON CONFLICT (webhook_id, event_id) DO NOTHING",
            &[
                &delivery_id,
                &webhook_id,
                &tenant_id,
                &repository_id,
                &sequence,
                &delivery_event_id,
                payload,
                &req_headers,
                &sig,
                &max_attempts,
            ],
        )
        .await
        .map_err(pg_err)?;
    Ok(inserted == 1)
}

/// Bounded backfill for any `(ref_cas_projected_events, active push webhook)` pairs missed by
/// newly enabled hooks. Stops strictly at `deadline` and never touches standalone `outbox:*` ids.
pub async fn sync_projected_ref_cas_webhooks_bounded(
    pool: &Pool,
    tenant_id: Uuid,
    repository_id: Uuid,
    pair_limit: i64,
    deadline: Instant,
) -> Result<usize, ProjectionError> {
    if Instant::now() >= deadline {
        return Ok(0);
    }
    let mut client = pool.get().await.map_err(|e| ProjectionError::Database(e.to_string()))?;
    if !projection_tables_present(&**client).await? {
        return Ok(0);
    }
    let pairs = client
        .query(
            "SELECT e.event_id, e.op_event_id, e.operation_id, e.history_incarnation, e.group_id, \
                    e.group_epoch, e.log_index, e.revision, e.ref_name, e.old_oid, e.new_oid, \
                    w.id AS webhook_id, w.secret, w.max_attempts \
             FROM ref_cas_projected_events e \
             JOIN ref_cas_projected_operations o ON o.op_event_id = e.op_event_id \
             JOIN forge_webhooks w ON w.repository_id = e.repository_id \
               AND w.tenant_id = $1 AND w.active = true AND w.events ? 'push' \
             WHERE e.repository_id = $2 AND o.outcome = 'committed' \
               AND e.ref_name <> 'refs/rootyard-ci' \
               AND e.ref_name NOT LIKE 'refs/rootyard-ci/%' \
               AND NOT EXISTS (SELECT 1 FROM forge_webhook_deliveries d \
                               WHERE d.webhook_id = w.id AND d.event_id = 'refcas:' || e.event_id) \
             ORDER BY e.group_epoch ASC, e.log_index ASC, e.event_seq ASC, e.ref_sequence ASC, \
                      w.created_at ASC, w.id ASC \
             LIMIT $3",
            &[&tenant_id, &repository_id, &pair_limit.max(1)],
        )
        .await
        .map_err(pg_err)?;

    let mut enqueued = 0usize;
    for row in &pairs {
        if Instant::now() >= deadline {
            break;
        }
        let ref_name: String = row.get("ref_name");
        if crate::ci_pins::reserved(&ref_name) {
            continue;
        }
        let raw_event_id: String = row.get("event_id");
        let delivery_event_id = derive_webhook_event_id(&raw_event_id);
        let payload = json!({
            "event": "push",
            "event_id": raw_event_id,
            "op_event_id": row.get::<_, String>("op_event_id"),
            "operation_id": row.get::<_, Uuid>("operation_id"),
            "repository_id": repository_id,
            "revision": row.get::<_, i64>("revision"),
            "history_incarnation": row.get::<_, Uuid>("history_incarnation"),
            "group_id": row.get::<_, i64>("group_id"),
            "group_epoch": row.get::<_, i64>("group_epoch"),
            "log_index": row.get::<_, i64>("log_index"),
            "ref_name": ref_name,
            "old_oid": row.get::<_, Option<String>>("old_oid"),
            "new_oid": row.get::<_, Option<String>>("new_oid"),
        });
        let payload_bytes = serde_json::to_vec(&payload).map_err(|e| ProjectionError::Decode(e.to_string()))?;
        let webhook_id: Uuid = row.get("webhook_id");
        let secret: String = row.get("secret");
        let max_attempts: i64 = row.get("max_attempts");
        let tx = client.transaction().await.map_err(pg_err)?;
        let locked = tx
            .query_opt(
                "SELECT 1 FROM forge_webhooks \
                 WHERE tenant_id = $1 AND repository_id = $2 AND id = $3 AND active = true FOR UPDATE",
                &[&tenant_id, &repository_id, &webhook_id],
            )
            .await
            .map_err(pg_err)?;
        if locked.is_some()
            && insert_single_webhook_delivery_tx(
                &tx,
                WebhookDeliverySpec {
                    tenant_id,
                    repository_id,
                    webhook_id,
                    secret: &secret,
                    max_attempts,
                    delivery_event_id: &delivery_event_id,
                    payload: &payload,
                    payload_bytes: &payload_bytes,
                },
            )
            .await?
        {
            tx.commit().await.map_err(pg_err)?;
            enqueued += 1;
        }
    }
    Ok(enqueued)
}

/// Claims up to one lease-fenced Ref-CAS projection job (`queued` or expired `running`).
pub async fn claim_next_projection_job(
    pool: &Pool,
    owner: Uuid,
    lease_seconds: i64,
    max_attempts: i64,
) -> Result<Option<ProjectionJobRecord>, ProjectionError> {
    let mut client = pool.get().await.map_err(|e| ProjectionError::Database(e.to_string()))?;
    if !projection_tables_present(&**client).await? {
        return Ok(None);
    }
    let tx = client.transaction().await.map_err(pg_err)?;
    tx.execute(
        "UPDATE ref_cas_projection_jobs \
         SET state = 'failed', lease_owner = NULL, lease_until = NULL, \
             last_error = 'lease expired after maximum attempts', \
             completed_at = clock_timestamp(), updated_at = clock_timestamp() \
         WHERE state = 'running' AND lease_until < clock_timestamp() AND attempt >= $1",
        &[&max_attempts.max(1)],
    )
    .await
    .map_err(pg_err)?;
    let row = tx
        .query_opt(
            "WITH candidate AS ( \
               SELECT job_key FROM ref_cas_projection_jobs \
               WHERE attempt < $3 \
                 AND (state = 'queued' OR (state = 'running' AND lease_until < clock_timestamp())) \
               ORDER BY created_at ASC, job_key ASC LIMIT 1 FOR UPDATE SKIP LOCKED \
             ) UPDATE ref_cas_projection_jobs j SET state = 'running', \
                 attempt = j.attempt + 1, claim_generation = j.claim_generation + 1, \
                 lease_owner = $1, \
                 lease_until = clock_timestamp() + make_interval(secs => ($2::bigint)::double precision), \
                 updated_at = clock_timestamp() \
             FROM candidate WHERE j.job_key = candidate.job_key \
             RETURNING j.job_key, j.repository_id, j.tenant_id, j.op_event_id, j.history_incarnation, \
                       j.group_id, j.group_epoch, j.log_index, j.event_seq, j.kind, j.scope_key, \
                       j.state, j.attempt, j.claim_generation, j.lease_owner, j.last_error, j.payload",
            &[&owner, &lease_seconds.max(1), &max_attempts.max(1)],
        )
        .await
        .map_err(pg_err)?;
    tx.commit().await.map_err(pg_err)?;
    row.as_ref().map(decode_job_row).transpose()
}

pub async fn finish_projection_job(
    pool: &Pool,
    job: &ProjectionJobRecord,
    final_state: ProjectionJobState,
    last_error: Option<&str>,
) -> Result<bool, ProjectionError> {
    if matches!(final_state, ProjectionJobState::Queued | ProjectionJobState::Running) {
        return Err(ProjectionError::InvalidInput("finish_projection_job requires terminal/hold state".into()));
    }
    let client = pool.get().await.map_err(|e| ProjectionError::Database(e.to_string()))?;
    let n = client
        .execute(
            "UPDATE ref_cas_projection_jobs \
             SET state = $4::text, lease_owner = NULL, lease_until = NULL, last_error = $5, \
                 completed_at = CASE WHEN $4::text IN ('succeeded','failed') THEN clock_timestamp() ELSE NULL END, \
                 updated_at = clock_timestamp() \
             WHERE job_key = $1 AND state = 'running' AND lease_owner = $2 AND claim_generation = $3",
            &[&job.job_key, &job.lease_owner, &job.claim_generation, &final_state.as_str(), &last_error],
        )
        .await
        .map_err(pg_err)?;
    Ok(n == 1)
}

/// Processes a bounded batch of reliable Ref-CAS projection jobs safely under lease fencing.
pub async fn process_due_projection_jobs(
    pool: &Pool,
    owner: Uuid,
    batch: usize,
    lease_seconds: i64,
) -> Result<usize, ProjectionError> {
    let mut completed = 0usize;
    for _ in 0..batch.clamp(1, 256) {
        let Some(job) = claim_next_projection_job(pool, owner, lease_seconds, 5).await? else {
            break;
        };
        let client = pool.get().await.map_err(|e| ProjectionError::Database(e.to_string()))?;
        let verified = super::pg::verify_projected_operation_non_authorizing(&**client, &job.op_event_id).await;
        match verified {
            Ok(true) => {
                if finish_projection_job(pool, &job, ProjectionJobState::Succeeded, None).await? {
                    completed += 1;
                }
            }
            Ok(false) => {
                let _ = finish_projection_job(
                    pool,
                    &job,
                    ProjectionJobState::UnknownHold,
                    Some("projected operation receipt missing or integrity check failed"),
                )
                .await?;
            }
            Err(err) => {
                let msg = err.to_string();
                let clipped: String = msg.chars().take(1024).collect();
                let _ = finish_projection_job(pool, &job, ProjectionJobState::Failed, Some(&clipped)).await?;
            }
        }
    }
    Ok(completed)
}

fn decode_job_row(row: &tokio_postgres::Row) -> Result<ProjectionJobRecord, ProjectionError> {
    let realm = ProjectionRealm::new(row.get("history_incarnation"), row.get("group_id"), row.get("group_epoch"))?;
    let log_index = from_pg_u64(row.get("log_index"), "log_index")?;
    let event_seq = from_pg_u64(row.get("event_seq"), "event_seq")?;
    let kind = ProjectionJobKind::parse(row.get("kind"))?;
    let state = ProjectionJobState::parse(row.get("state"))?;
    Ok(ProjectionJobRecord {
        job_key: row.get("job_key"),
        repository_id: row.get("repository_id"),
        tenant_id: row.get("tenant_id"),
        op_event_id: row.get("op_event_id"),
        realm,
        log_index,
        event_seq,
        kind,
        scope_key: row.get("scope_key"),
        state,
        attempt: row.get("attempt"),
        claim_generation: row.get("claim_generation"),
        lease_owner: row.get("lease_owner"),
        last_error: row.get("last_error"),
        payload: row.get("payload"),
    })
}
