//! Inbound event ingestion: a per-hook serialized delivery allocator, bounded
//! outbox scans, and the CI callback transaction. The allocator uses one short
//! `READ COMMITTED` transaction; no transaction spans an HTTP or Git operation.
use crate::{
    AppState, Error, ci_pins, db,
    pulls::models::{
        PULL_FIELDS, PullRequest, body_valid, context_valid, valid_check_status_and_conclusion, valid_format,
        valid_oid_for_format, verify_commit_exists,
    },
    webhooks::{
        delivery::{PullCiOrchestration, on_pull_synchronized},
        models::{CiCallbackInput, DELIVERY_FIELDS, WebhookDelivery, ensure_schema},
        signing::{
            HEADER_SIGNATURE_256, build_delivery_headers, resolve_callback_identity, signature_header,
            upsert_callback_check_run, verify_signature_header,
        },
    },
};
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

/// Serializes `sequence` allocation per webhook. The parent hook row is locked
/// `FOR UPDATE` before the separate index-backed maximum lookup, so a waiter
/// re-reads the previous child row under `READ COMMITTED` after the owner
/// commits. A missing (or concurrently deleted) hook is `NotFound`, never a
/// misleading duplicate fallback. History is append-only for a retained hook,
/// so the sequence is monotonic until operator pruning or a restore removes
/// rows; this is not a cross-prune or cross-PITR-rollback guarantee.
#[rustfmt::skip]
pub async fn enqueue_webhook_delivery(
    client: &mut tokio_postgres::Client,
    tenant_id: Uuid,
    repository_id: Uuid,
    webhook_id: Uuid,
    secret: &str,
    max_attempts: i64,
    event_id: &str,
    event_type: &str,
    payload: &Value,
) -> Result<Option<WebhookDelivery>, Error> {
    let mut tx = client
        .build_transaction()
        .isolation_level(IsolationLevel::ReadCommitted)
        .start()
        .await
        .map_err(Error::internal)?;
    let hook = tx
        .query_opt(
            "SELECT 1 FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND id=$3 FOR UPDATE",
            &[&tenant_id, &repository_id, &webhook_id],
        )
        .await
        .map_err(Error::internal)?;
    if hook.is_none() {
        tx.rollback().await.map_err(Error::internal)?;
        return Err(Error::not_found());
    }
    // Idempotency is checked before allocation while the parent row is locked,
    // preserving UNIQUE (webhook_id, event_id) without consuming a sequence.
    let existing_sql =
        "SELECT 1 FROM forge_webhook_deliveries WHERE webhook_id=$1 AND event_id=$2";
    if tx
        .query_opt(existing_sql, &[&webhook_id, &event_id])
        .await
        .map_err(Error::internal)?
        .is_some()
    {
        tx.commit().await.map_err(Error::internal)?;
        return Ok(None);
    }
    // This is a separate statement after the lock wait, so READ COMMITTED sees
    // the previous owner's committed child row. Using the existing
    // (tenant_id, repository_id, webhook_id, sequence) index keeps the lookup
    // bounded to this hook.
    let max_sql = "SELECT COALESCE((SELECT sequence FROM forge_webhook_deliveries \
                   WHERE tenant_id=$1 AND repository_id=$2 AND webhook_id=$3 \
                   ORDER BY sequence DESC LIMIT 1), 0)";
    let last: i64 = tx
        .query_one(max_sql, &[&tenant_id, &repository_id, &webhook_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    let sequence = last
        .checked_add(1)
        .ok_or_else(|| Error::internal("webhook delivery sequence exhausted"))?;
    let delivery_id = Uuid::new_v4();
    let payload_bytes = serde_json::to_vec(payload).map_err(Error::internal)?;
    let sig = signature_header(secret, &payload_bytes);
    let req_headers = build_delivery_headers(event_type, delivery_id, webhook_id, 1, &sig);
    let insert_sql = format!(
        "INSERT INTO forge_webhook_deliveries \
         (id,webhook_id,tenant_id,repository_id,sequence,event_id,event_type,payload,request_headers,signature_256,state,attempts,max_attempts,next_attempt_unix) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending',0,$11,0) \
         ON CONFLICT (webhook_id, event_id) DO NOTHING RETURNING {DELIVERY_FIELDS}"
    );
    let row = tx
        .query_opt(
            &insert_sql,
            &[
                &delivery_id, &webhook_id, &tenant_id, &repository_id, &sequence, &event_id,
                &event_type, payload, &req_headers, &sig, &max_attempts,
            ],
        )
        .await
        .map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(row.as_ref().map(WebhookDelivery::row))
}

/// Scans `outbox_events` (excluding `refs/rootyard-ci/*`) and enqueues signed `push` deliveries.
#[rustfmt::skip]
pub async fn sync_outbox_events(
    state: &AppState,
    tenant_id: Uuid,
    repository_id: Uuid,
) -> Result<usize, Error> {
    ensure_schema(&state.pool).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let hooks = client
        .query("SELECT id, secret, max_attempts, events FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND active=true ORDER BY created_at ASC, id ASC", &[&tenant_id, &repository_id])
        .await
        .map_err(Error::internal)?;
    if hooks.is_empty() {
        return Ok(0);
    }

    let outbox_rows = client
        .query(
            "SELECT e.event_id, e.operation_id, e.storage_generation, e.ref_name, e.old_oid, e.new_oid \
             FROM outbox_events e JOIN git_operations o ON o.id = e.operation_id \
             WHERE e.repository_id=$1 AND o.outcome <> 'unknown' AND e.ref_name NOT LIKE 'refs/rootyard-ci/%' \
               AND EXISTS ( \
                 SELECT 1 FROM forge_webhooks w \
                 WHERE w.repository_id=e.repository_id AND w.active=true AND w.events ? 'push' \
                   AND NOT EXISTS (SELECT 1 FROM forge_webhook_deliveries d \
                                   WHERE d.webhook_id=w.id AND d.event_id='outbox:' || e.event_id) \
               ) \
             ORDER BY e.operation_sequence ASC, e.transaction_sequence ASC LIMIT 200",
            &[&repository_id],
        )
        .await
        .map_err(Error::internal)?;

    let mut enqueued = 0usize;
    for ev in &outbox_rows {
        let raw_event_id: String = ev.get("event_id");
        let ref_name: String = ev.get("ref_name");
        if ci_pins::reserved(&ref_name) {
            continue;
        }
        let delivery_event_id = format!("outbox:{raw_event_id}");
        let payload = json!({
            "event": "push", "event_id": raw_event_id,
            "operation_id": ev.get::<_, Uuid>("operation_id"), "repository_id": repository_id,
            "storage_generation": ev.get::<_, i64>("storage_generation"), "ref_name": ref_name,
            "old_oid": ev.get::<_, String>("old_oid"), "new_oid": ev.get::<_, String>("new_oid"),
        });
        for hook in &hooks {
            let subscribed = hook.get::<_, Value>("events").as_array().is_some_and(|arr| arr.iter().any(|v| v.as_str() == Some("push")));
            if subscribed
                && enqueue_webhook_delivery(&mut client, tenant_id, repository_id, hook.get("id"), &hook.get::<_, String>("secret"), hook.get("max_attempts"), &delivery_event_id, "push", &payload)
                    .await?
                    .is_some()
            {
                enqueued += 1;
            }
        }
    }
    Ok(enqueued)
}

/// Bounded background backfill for missing `(outbox event, active push hook)`
/// pairs. Unlike the manual `LIMIT 200` event scan above, this selects pairs in
/// one anti-join, so memory follows `pair_limit` instead of the number of active
/// hooks. Each call inserts at most one page; inserted pairs disappear from the
/// next anti-join, so durable replay advances through a backlog. The pool's
/// 5 s statement timeout bounds the SELECT and each INSERT, while `deadline`
/// stops the loop between pairs.
#[rustfmt::skip]
pub(crate) async fn sync_outbox_events_bounded(
    state: &AppState,
    tenant_id: Uuid,
    repository_id: Uuid,
    pair_limit: i64,
    deadline: tokio::time::Instant,
) -> Result<usize, Error> {
    if tokio::time::Instant::now() >= deadline {
        return Ok(0);
    }
    ensure_schema(&state.pool).await?;
    if tokio::time::Instant::now() >= deadline {
        return Ok(0);
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let pairs = client
        .query(
            "SELECT e.event_id, e.operation_id, e.storage_generation, e.ref_name, e.old_oid, e.new_oid, \
                    w.id AS webhook_id, w.secret, w.max_attempts \
             FROM outbox_events e \
             JOIN git_operations o ON o.id = e.operation_id \
             JOIN forge_webhooks w ON w.repository_id = e.repository_id \
               AND w.tenant_id = $1 AND w.active = true AND w.events ? 'push' \
             WHERE e.repository_id = $2 AND o.outcome <> 'unknown' \
               AND e.ref_name <> 'refs/rootyard-ci' \
               AND e.ref_name NOT LIKE 'refs/rootyard-ci/%' \
               AND NOT EXISTS (SELECT 1 FROM forge_webhook_deliveries d \
                               WHERE d.webhook_id = w.id AND d.event_id = 'outbox:' || e.event_id) \
             ORDER BY e.operation_sequence ASC, e.transaction_sequence ASC, w.created_at ASC, w.id ASC \
             LIMIT $3",
            &[&tenant_id, &repository_id, &pair_limit],
        )
        .await
        .map_err(Error::internal)?;

    let mut enqueued = 0usize;
    let mut first_error: Option<Error> = None;
    for ev in &pairs {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        let raw_event_id: String = ev.get("event_id");
        let ref_name: String = ev.get("ref_name");
        if ci_pins::reserved(&ref_name) {
            continue;
        }
        let delivery_event_id = format!("outbox:{raw_event_id}");
        let payload = json!({
            "event": "push", "event_id": raw_event_id,
            "operation_id": ev.get::<_, Uuid>("operation_id"), "repository_id": repository_id,
            "storage_generation": ev.get::<_, i64>("storage_generation"), "ref_name": ref_name,
            "old_oid": ev.get::<_, String>("old_oid"), "new_oid": ev.get::<_, String>("new_oid"),
        });
        match enqueue_webhook_delivery(
            &mut client, tenant_id, repository_id, ev.get("webhook_id"),
            &ev.get::<_, String>("secret"), ev.get("max_attempts"),
            &delivery_event_id, "push", &payload,
        )
        .await
        {
            Ok(Some(_)) => enqueued += 1,
            Ok(None) => {}
            // One bad pair must not discard the rest of the bounded page. It
            // stays selected for a later round, while successful pairs advance.
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(enqueued),
    }
}

/// HMAC-authenticated, idempotent CI callback ingestion. The HTTP admission and
/// signature checks happen before the short callback transaction.
#[rustfmt::skip]
pub(crate) async fn ci_callback(
    state: &AppState,
    owner: String,
    name: String,
    hook_id: Uuid,
    headers: HeaderMap,
    body: Bytes,
) -> Result<axum::response::Response, Error> {
    ensure_schema(&state.pool).await?;
    if !db::valid_name(&owner) || !db::valid_name(&name) {
        return Err(Error::not_found());
    }
    let sig_header = headers
        .get(HEADER_SIGNATURE_256)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(Error::unauthorized)?;

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let hook_row = client
        .query_opt(
            "SELECT r.id AS repo_id, r.owner_id AS tenant_id, r.state AS repo_state, \
             r.object_format AS repo_object_format, w.secret, w.active, w.ci_contexts \
             FROM repositories r JOIN namespaces u ON u.id = r.owner_id \
             JOIN forge_webhooks w ON w.repository_id = r.id AND w.tenant_id = r.owner_id \
             WHERE u.slug=$1 AND r.name=$2 AND w.id=$3",
            &[&owner, &name, &hook_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;

    let (repo_id, tenant_id, secret): (Uuid, Uuid, String) = (hook_row.get("repo_id"), hook_row.get("tenant_id"), hook_row.get("secret"));
    let object_format: String = hook_row.get("repo_object_format");
    if !verify_signature_header(&secret, &body, sig_header) {
        return Err(Error::unauthorized());
    }
    if !hook_row.get::<_, bool>("active") {
        return Err(Error(StatusCode::CONFLICT, "webhook is inactive"));
    }
    if hook_row.get::<_, String>("repo_state") != "ready" {
        return Err(Error(StatusCode::CONFLICT, "repository is not ready"));
    }

    let input: CiCallbackInput = serde_json::from_slice(&body).map_err(|_| Error::bad_request())?;
    let default_ctx = hook_row
        .get::<_, Value>("ci_contexts")
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(Value::as_str)
        .unwrap_or("ci/default")
        .to_owned();
    let context = input.context.clone().unwrap_or(default_ctx);
    let output = input.output.clone().unwrap_or_default();

    if !valid_format(&object_format)
        || !valid_oid_for_format(&input.commit_oid, &object_format)
        || input.base_oid.as_ref().is_some_and(|oid| !valid_oid_for_format(oid, &object_format))
        || !context_valid(&context)
        || !valid_check_status_and_conclusion(&input.status, input.conclusion.as_deref())
        || !body_valid(&output, false)
        || input.attempt.is_some_and(|a| a <= 0)
        || input.sequence.is_some_and(|s| s <= 0)
    {
        return Err(Error::bad_request());
    }

    let (event_id, req_sha256) = resolve_callback_identity(&headers, hook_id, &input, &context, &output)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    crate::webhooks::trust::lock_policy_tx(&tx,repo_id).await?;
    let current_hook=tx.query_opt(
        "SELECT secret,active,ci_contexts FROM forge_webhooks WHERE id=$1 AND repository_id=$2 FOR SHARE",
        &[&hook_id,&repo_id]).await.map_err(Error::internal)?
        .ok_or_else(Error::unauthorized)?;
    if !current_hook.get::<_,bool>("active") ||
        current_hook.get::<_,String>("secret")!=secret ||
        current_hook.get::<_,Value>("ci_contexts")!=hook_row.get::<_,Value>("ci_contexts") {
        return Err(Error::unauthorized());
    }
    if let Some(cb_row) = tx
        .query_opt("SELECT request_sha256, response FROM forge_webhook_callbacks WHERE repository_id=$1 AND event_id=$2 FOR UPDATE", &[&repo_id, &event_id])
        .await
        .map_err(Error::internal)?
    {
        if cb_row.get::<_, String>("request_sha256") != req_sha256 {
            return Err(Error(StatusCode::CONFLICT, "callback idempotency key conflict"));
        }
        let saved_resp: Value = cb_row.get("response");
        tx.commit().await.map_err(Error::internal)?;
        return Ok(crate::webhooks::models::json(StatusCode::OK, saved_resp));
    }

    let trusted_binding: Option<(Option<Uuid>,bool)> = tx.query_opt(
        "SELECT webhook_id,active FROM forge_trusted_check_contexts WHERE repository_id=$1 AND context=$2",
        &[&repo_id,&context],
    ).await.map_err(Error::internal)?.map(|r| (r.get(0),r.get(1)));
    if let Some((expected_hook,active)) = trusted_binding {
        if !active || expected_hook != Some(hook_id) || !hook_row.get::<_, Value>("ci_contexts")
            .as_array().is_some_and(|a| a.iter().any(|v| v.as_str() == Some(context.as_str()))) {
            return Err(Error(StatusCode::FORBIDDEN, "integration does not own this CI context"));
        }
        let (Some(run_id),Some(job_id),Some(base_oid),Some(generation),Some(pull_number),Some(attempt)) =
            (input.ci_run_id,input.ci_job_id,input.base_oid.as_ref(),input.lease_generation,input.pull_number,input.attempt)
            else { return Err(Error::bad_request()); };
        let valid: bool = tx.query_one(
            "SELECT EXISTS(SELECT 1 FROM ci_runs c JOIN forge_pulls p \
             ON p.repository_id=c.repository_id AND p.number=c.pull_number \
             WHERE c.id=$1 AND c.repository_id=$2 AND c.context=$3 AND c.job_id=$4 \
               AND c.head_oid=$5 AND c.base_oid=$6 AND c.pull_number=$7 \
               AND c.state='leased' AND c.attempt=$8 AND c.lease_generation=$9 \
               AND c.lease_expires_unix>extract(epoch FROM clock_timestamp()) \
               AND p.state='open' AND p.head_oid=c.head_oid AND p.base_oid=c.base_oid \
               AND p.version=c.pull_version)",
            &[&run_id,&repo_id,&context,&job_id,&input.commit_oid,base_oid,&pull_number,&attempt,&generation],
        ).await.map_err(Error::internal)?.get(0);
        if !valid { return Err(Error(StatusCode::CONFLICT, "CI run attempt or candidate changed")); }
    }

    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later")
    })?;
    let exists = verify_commit_exists(&state, repo_id, &input.commit_oid).await?;
    drop(_slot);
    if !exists {
        return Err(Error(StatusCode::CONFLICT, "commit object not found"));
    }

    let check_run = upsert_callback_check_run(
        &tx, tenant_id, repo_id, &input.commit_oid, &context, &input.status,
        input.conclusion.as_ref(), input.attempt, input.sequence, &output,
    ).await?;
    if trusted_binding.is_some() {
        tx.execute(
            "UPDATE forge_check_runs SET issuer_webhook_id=$5,ci_run_id=$6,ci_base_oid=$7,ci_lease_generation=$8 \
             WHERE tenant_id=$1 AND repository_id=$2 AND commit_oid=$3 AND context=$4",
            &[&tenant_id,&repo_id,&input.commit_oid,&context,&hook_id,&input.ci_run_id,
              &input.base_oid,&input.lease_generation],
        ).await.map_err(Error::internal)?;
        if input.status == "completed" {
            tx.execute(
                "UPDATE ci_runs SET state='completed',conclusion=$2,lease_expires_unix=0,updated_at=clock_timestamp() WHERE id=$1",
                &[&input.ci_run_id,&input.conclusion],
            ).await.map_err(Error::internal)?;
        }
    }

    let resp_val = serde_json::to_value(&check_run).map_err(Error::internal)?;
    tx.execute(
        "INSERT INTO forge_webhook_callbacks (tenant_id,repository_id,webhook_id,event_id,request_sha256,response) VALUES ($1,$2,$3,$4,$5,$6)",
        &[&tenant_id, &repo_id, &hook_id, &event_id, &req_sha256, &resp_val],
    )
    .await
    .map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(crate::webhooks::models::json(StatusCode::OK, resp_val))
}

/// Enqueues signed `pull_request` deliveries for every open Pull Request and
/// returns one orchestration summary per pull. Kept in the ingestion module
/// with the outbox scans and allocator so `delivery.rs` remains a facade.
#[rustfmt::skip]
pub async fn sync_pull_events(
    state: &AppState,
    tenant_id: Uuid,
    repository_id: Uuid,
) -> Result<Vec<PullCiOrchestration>, Error> {
    ensure_schema(&state.pool).await?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let pull_rows = client
        .query(&format!("SELECT {PULL_FIELDS} FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND state='open' ORDER BY number ASC"), &[&tenant_id, &repository_id])
        .await
        .map_err(Error::internal)?;
    drop(client);

    let mut results = Vec::with_capacity(pull_rows.len());
    for row in &pull_rows {
        let pull = PullRequest::row(row);
        let action = if pull.version <= 1 { "opened" } else { "synchronize" };
        results.push(on_pull_synchronized(state, repository_id, &pull, action).await?);
    }
    Ok(results)
}
