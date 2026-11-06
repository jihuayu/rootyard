//! HTTP handlers for Track A (`webhooks`): webhook CRUD, manual/automated event dispatch,
//! ping, delivery inspection, manual retry, and HMAC-verified idempotent CI check-run callbacks.
use crate::{
    AppState, Error,
    auth::{self, authorize_repo as authorize, finish_tx as finish, idempotency_key},
    db,
    pulls::models::{
        body_valid, context_valid, creation_replay, positive, record_creation,
        valid_check_status_and_conclusion, valid_oid, verify_commit_exists,
    },
    webhooks::{
        delivery::{
            DispatchSummary, current_unix_seconds, deliver_single, dispatch_due_deliveries,
            enqueue_webhook_delivery, sync_outbox_events, sync_pull_events,
        },
        models::{
            CiCallbackInput, DELIVERY_FIELDS, DeliveriesQuery, DispatchInput, NewWebhook,
            PingInput, RetryInput, WEBHOOK_FIELDS, Webhook, WebhookDelivery, WebhookPatch,
            WebhooksQuery, ensure_schema, json, validate_attempts_and_timeout,
            validate_ci_contexts, validate_events, validate_secret, validate_webhook_url,
        },
        signing::{
            HEADER_SIGNATURE_256, resolve_callback_identity, upsert_callback_check_run,
            verify_signature_header,
        },
    },
};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json as sjson};
use std::sync::Arc;
use uuid::Uuid;

fn parse_opt_body<T: Default + DeserializeOwned>(body: &Bytes) -> Result<T, Error> {
    if body.is_empty() {
        Ok(T::default())
    } else {
        serde_json::from_slice(body).map_err(|_| Error::bad_request())
    }
}

pub async fn list_webhooks(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<WebhooksQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let (after, limit) = query.bounds()?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, false).await?;
    let sql = format!("SELECT {WEBHOOK_FIELDS} FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND ($3::bool IS NULL OR active=$3) ORDER BY created_at ASC, id ASC OFFSET $4 LIMIT $5");
    let rows = tx.query(&sql, &[&actor.id, &repo, &query.active, &after, &(limit + 1)]).await.map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let mut items = Vec::with_capacity(rows.len().min(limit as usize));
    for row in rows.iter().take(limit as usize) {
        items.push(Webhook::row(row)?);
    }
    let next_after = if more { Some(after + limit) } else { None };
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "items": items, "next_after": next_after })))
}

pub async fn create_webhook(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<NewWebhook>,
) -> Result<Response, Error> {
    tokio::spawn(async move {
        ensure_schema(&state.pool).await?;
        let actor = auth::authenticate(&state.pool, &headers).await?;
        validate_webhook_url(&input.url)?;
        let secret_sha256 = validate_secret(&input.secret)?;
        let events = match input.events {
            Some(ref ev) => validate_events(ev)?,
            None => vec!["push".to_owned(), "pull_request".to_owned()],
        };
        let ci_contexts = match input.ci_contexts {
            Some(ref ctxs) => validate_ci_contexts(ctxs)?,
            None => vec!["ci/default".to_owned()],
        };
        let auto_ci_pin = input.auto_ci_pin.unwrap_or(true);
        let active = input.active.unwrap_or(true);
        let max_attempts = input.max_attempts.unwrap_or(5);
        let timeout_ms = input.timeout_ms.unwrap_or(5000);
        validate_attempts_and_timeout(max_attempts, timeout_ms)?;

        let key = idempotency_key(&headers)?.map(str::to_owned);
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let repo = authorize(&tx, &actor, &owner, &name, true).await?;

        if let Some(ref k) = key {
            let req_val = sjson!({
                "operation": "create_webhook", "url": input.url, "secret_sha256": secret_sha256,
                "events": events, "ci_contexts": ci_contexts, "auto_ci_pin": auto_ci_pin,
                "active": active, "max_attempts": max_attempts, "timeout_ms": timeout_ms,
            });
            if let Some(saved) = creation_replay(&tx, actor.id, repo, k, &req_val).await? {
                finish(tx, &actor, true).await?;
                return Ok(json(StatusCode::OK, saved));
            }
        }

        let hook_id = Uuid::new_v4();
        let events_json = serde_json::to_value(&events).map_err(Error::internal)?;
        let contexts_json = serde_json::to_value(&ci_contexts).map_err(Error::internal)?;
        let sql = format!(
            "INSERT INTO forge_webhooks (id,tenant_id,repository_id,url,secret,secret_sha256,events,ci_contexts,auto_ci_pin,active,max_attempts,timeout_ms,version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1) RETURNING {WEBHOOK_FIELDS}"
        );
        let row = tx
            .query_one(&sql, &[&hook_id, &actor.id, &repo, &input.url, &input.secret, &secret_sha256, &events_json, &contexts_json, &auto_ci_pin, &active, &max_attempts, &timeout_ms])
            .await
            .map_err(Error::internal)?;

        let webhook = Webhook::row(&row)?;
        let val = serde_json::to_value(&webhook).map_err(Error::internal)?;
        record_creation(&tx, actor.id, repo, key.as_deref(), &val).await?;
        finish(tx, &actor, true).await?;
        Ok(json(StatusCode::CREATED, val))
    })
    .await
    .map_err(Error::internal)?
}

pub async fn get_webhook(
    State(state): State<Arc<AppState>>,
    Path((owner, name, hook_id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, false).await?;
    let row = tx
        .query_opt(&format!("SELECT {WEBHOOK_FIELDS} FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND id=$3"), &[&actor.id, &repo, &hook_id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let webhook = Webhook::row(&row)?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, webhook))
}

pub async fn update_webhook(
    State(state): State<Arc<AppState>>,
    Path((owner, name, hook_id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
    Json(patch): Json<WebhookPatch>,
) -> Result<Response, Error> {
    tokio::spawn(async move {
        ensure_schema(&state.pool).await?;
        let actor = auth::authenticate(&state.pool, &headers).await?;
        if let Some(v) = patch.expected_version {
            positive(v)?;
        }
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let repo = authorize(&tx, &actor, &owner, &name, true).await?;

        let existing = tx
            .query_opt(&format!("SELECT {WEBHOOK_FIELDS}, secret FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND id=$3 FOR UPDATE"), &[&actor.id, &repo, &hook_id])
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
        let cur = Webhook::row(&existing)?;
        if patch.expected_version.is_some_and(|exp| cur.version != exp) {
            return Err(Error(StatusCode::CONFLICT, "webhook version conflict"));
        }

        let next_url = match patch.url {
            Some(ref u) => { validate_webhook_url(u)?; u.clone() }
            None => cur.url,
        };
        let (next_secret, next_secret_sha256) = match patch.secret {
            Some(ref s) => (s.clone(), validate_secret(s)?),
            None => (existing.get::<_, String>("secret"), cur.secret_sha256),
        };
        let next_events = match patch.events {
            Some(ref ev) => validate_events(ev)?,
            None => cur.events,
        };
        let next_contexts = match patch.ci_contexts {
            Some(ref ctxs) => validate_ci_contexts(ctxs)?,
            None => cur.ci_contexts,
        };
        let next_auto_pin = patch.auto_ci_pin.unwrap_or(cur.auto_ci_pin);
        let next_active = patch.active.unwrap_or(cur.active);
        let next_max_attempts = patch.max_attempts.unwrap_or(cur.max_attempts);
        let next_timeout_ms = patch.timeout_ms.unwrap_or(cur.timeout_ms);
        validate_attempts_and_timeout(next_max_attempts, next_timeout_ms)?;

        let events_json = serde_json::to_value(&next_events).map_err(Error::internal)?;
        let contexts_json = serde_json::to_value(&next_contexts).map_err(Error::internal)?;
        let sql = format!(
            "UPDATE forge_webhooks SET url=$4, secret=$5, secret_sha256=$6, events=$7, ci_contexts=$8, auto_ci_pin=$9, active=$10, max_attempts=$11, timeout_ms=$12, version=version+1, updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND id=$3 RETURNING {WEBHOOK_FIELDS}"
        );
        let updated = tx
            .query_one(&sql, &[&actor.id, &repo, &hook_id, &next_url, &next_secret, &next_secret_sha256, &events_json, &contexts_json, &next_auto_pin, &next_active, &next_max_attempts, &next_timeout_ms])
            .await
            .map_err(Error::internal)?;
        let webhook = Webhook::row(&updated)?;
        finish(tx, &actor, true).await?;
        Ok(json(StatusCode::OK, webhook))
    })
    .await
    .map_err(Error::internal)?
}

pub async fn delete_webhook(
    State(state): State<Arc<AppState>>,
    Path((owner, name, hook_id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    tokio::spawn(async move {
        ensure_schema(&state.pool).await?;
        let actor = auth::authenticate(&state.pool, &headers).await?;
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let repo = authorize(&tx, &actor, &owner, &name, true).await?;
        let deleted = tx
            .execute("DELETE FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND id=$3", &[&actor.id, &repo, &hook_id])
            .await
            .map_err(Error::internal)?;
        if deleted == 0 {
            return Err(Error::not_found());
        }
        finish(tx, &actor, true).await?;
        Ok(json(StatusCode::OK, sjson!({ "deleted": true, "id": hook_id })))
    })
    .await
    .map_err(Error::internal)?
}

pub async fn ping_webhook(
    State(state): State<Arc<AppState>>,
    Path((owner, name, hook_id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    tokio::spawn(async move {
        ensure_schema(&state.pool).await?;
        let actor = auth::authenticate(&state.pool, &headers).await?;
        let input: PingInput = parse_opt_body(&body)?;
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let repo = authorize(&tx, &actor, &owner, &name, true).await?;
        let row = tx
            .query_opt("SELECT secret, max_attempts FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND id=$3", &[&actor.id, &repo, &hook_id])
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
        let (secret, max_attempts): (String, i64) = (row.get("secret"), row.get("max_attempts"));
        finish(tx, &actor, true).await?;
        drop(client);

        let event_id = input.event_id.unwrap_or_else(|| format!("ping:{}", Uuid::new_v4()));
        if event_id.is_empty() || event_id.len() > 128 {
            return Err(Error::bad_request());
        }
        let zen = input.zen.unwrap_or_else(|| "Deterministic Git and Forge pipelines.".to_owned());
        let payload = sjson!({ "event": "ping", "zen": zen, "hook_id": hook_id, "repository_id": repo });

        let pool_client = state.pool.get().await.map_err(Error::internal)?;
        let delivery = match enqueue_webhook_delivery(&pool_client, actor.id, repo, hook_id, &secret, max_attempts, &event_id, "ping", &payload).await? {
            Some(d) => d,
            None => {
                let existing = pool_client
                    .query_one(&format!("SELECT {DELIVERY_FIELDS} FROM forge_webhook_deliveries WHERE webhook_id=$1 AND event_id=$2"), &[&hook_id, &event_id])
                    .await
                    .map_err(Error::internal)?;
                WebhookDelivery::row(&existing)
            }
        };
        drop(pool_client);

        let final_delivery = if input.deliver_now.unwrap_or(true) && delivery.state != "delivered" {
            deliver_single(&state, actor.id, repo, delivery.id, current_unix_seconds()).await?
        } else {
            delivery
        };
        Ok(json(StatusCode::OK, final_delivery))
    })
    .await
    .map_err(Error::internal)?
}

pub async fn dispatch_webhooks(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    tokio::spawn(async move {
        ensure_schema(&state.pool).await?;
        let actor = auth::authenticate(&state.pool, &headers).await?;
        let input: DispatchInput = parse_opt_body(&body)?;
        let (limit, now_unix) = (input.limit.unwrap_or(50), input.now_unix.unwrap_or_else(current_unix_seconds));
        if !(1..=200).contains(&limit) || now_unix < 0 {
            return Err(Error::bad_request());
        }

        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let repo = authorize(&tx, &actor, &owner, &name, true).await?;
        finish(tx, &actor, true).await?;
        drop(client);

        let orchestrated_pulls = if input.sync_pulls.unwrap_or(true) {
            sync_pull_events(&state, actor.id, repo).await?.len()
        } else {
            0
        };
        let synced_outbox_deliveries = if input.sync_outbox.unwrap_or(true) {
            sync_outbox_events(&state, actor.id, repo).await?
        } else {
            0
        };
        let deliveries = dispatch_due_deliveries(&state, actor.id, repo, limit, now_unix).await?;
        let delivered_count = deliveries.iter().filter(|d| d.state == "delivered").count();
        let failed_count = deliveries.iter().filter(|d| d.state == "failed").count();
        let dead_letter_count = deliveries.iter().filter(|d| d.state == "dead_letter").count();

        Ok(json(
            StatusCode::OK,
            DispatchSummary {
                synced_outbox_deliveries, orchestrated_pulls, attempted_deliveries: deliveries.len(),
                delivered_count, failed_count, dead_letter_count, deliveries,
            },
        ))
    })
    .await
    .map_err(Error::internal)?
}

pub async fn list_deliveries(
    State(state): State<Arc<AppState>>,
    Path((owner, name, hook_id)): Path<(String, String, Uuid)>,
    Query(query): Query<DeliveriesQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let (after, limit) = query.bounds()?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, false).await?;

    tx.query_opt("SELECT id FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND id=$3", &[&actor.id, &repo, &hook_id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;

    let sql = format!(
        "SELECT {DELIVERY_FIELDS} FROM forge_webhook_deliveries WHERE tenant_id=$1 AND repository_id=$2 AND webhook_id=$3 AND sequence > $4 AND ($5::text IS NULL OR state = $5) AND ($6::text IS NULL OR event_type = $6) ORDER BY sequence ASC LIMIT $7"
    );
    let rows = tx
        .query(&sql, &[&actor.id, &repo, &hook_id, &after, &query.state, &query.event_type, &(limit + 1)])
        .await
        .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<_> = rows.iter().take(limit as usize).map(WebhookDelivery::row).collect();
    let next_after = if more { items.last().map(|d| d.sequence) } else { None };
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "webhook_id": hook_id, "items": items, "next_after": next_after })))
}

pub async fn get_delivery(
    State(state): State<Arc<AppState>>,
    Path((owner, name, hook_id, delivery_id)): Path<(String, String, Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, false).await?;
    let row = tx
        .query_opt(&format!("SELECT {DELIVERY_FIELDS} FROM forge_webhook_deliveries WHERE tenant_id=$1 AND repository_id=$2 AND webhook_id=$3 AND id=$4"), &[&actor.id, &repo, &hook_id, &delivery_id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let delivery = WebhookDelivery::row(&row);
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, delivery))
}

pub async fn retry_delivery(
    State(state): State<Arc<AppState>>,
    Path((owner, name, hook_id, delivery_id)): Path<(String, String, Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    tokio::spawn(async move {
        ensure_schema(&state.pool).await?;
        let actor = auth::authenticate(&state.pool, &headers).await?;
        let input: RetryInput = parse_opt_body(&body)?;
        let (now_unix, reset_attempts) = (input.now_unix.unwrap_or_else(current_unix_seconds), input.reset_attempts.unwrap_or(true));

        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let repo = authorize(&tx, &actor, &owner, &name, true).await?;
        let row = tx
            .query_opt(
                &format!(
                    "UPDATE forge_webhook_deliveries SET state='pending', attempts = CASE WHEN $5 OR state='dead_letter' OR attempts >= max_attempts THEN 0 ELSE attempts END, lease_generation=lease_generation+1, next_attempt_unix=0, updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND webhook_id=$3 AND id=$4 AND (state <> 'leased' OR next_attempt_unix <= extract(epoch FROM clock_timestamp())) RETURNING {DELIVERY_FIELDS}"
                ),
                &[&actor.id, &repo, &hook_id, &delivery_id, &reset_attempts],
            )
            .await
            .map_err(Error::internal)?
            .ok_or(Error(StatusCode::CONFLICT, "delivery is being sent or does not exist"))?;
        let pending_delivery = WebhookDelivery::row(&row);
        finish(tx, &actor, true).await?;
        drop(client);

        let result = if input.deliver_now.unwrap_or(true) {
            deliver_single(&state, actor.id, repo, delivery_id, now_unix).await?
        } else {
            pending_delivery
        };
        Ok(json(StatusCode::OK, result))
    })
    .await
    .map_err(Error::internal)?
}

pub async fn ci_callback(
    State(state): State<Arc<AppState>>,
    Path((owner, name, hook_id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    tokio::spawn(async move {
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
                "SELECT r.id AS repo_id, r.owner_id AS tenant_id, r.state AS repo_state, w.secret, w.active, w.ci_contexts \
                 FROM repositories r JOIN users u ON u.id = r.owner_id \
                 JOIN forge_webhooks w ON w.repository_id = r.id AND w.tenant_id = r.owner_id \
                 WHERE u.username=$1 AND r.name=$2 AND w.id=$3",
                &[&owner, &name, &hook_id],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;

        let (repo_id, tenant_id, secret): (Uuid, Uuid, String) = (hook_row.get("repo_id"), hook_row.get("tenant_id"), hook_row.get("secret"));
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

        if !valid_oid(&input.commit_oid)
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
            return Ok(json(StatusCode::OK, saved_resp));
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
        Ok(json(StatusCode::OK, resp_val))
    })
    .await
    .map_err(Error::internal)?
}
