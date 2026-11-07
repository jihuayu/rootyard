//! HTTP handlers for Track A (`webhooks`): webhook CRUD, manual/automated event dispatch,
//! ping, delivery inspection, manual retry, and HMAC-verified idempotent CI check-run callbacks.
use crate::{
    AppState, Error,
    auth::{self, authorize_repo_with_role, finish_tx as finish, idempotency_key},
    pulls::models::{creation_replay, positive, record_creation},
    webhooks::{
        delivery::{
            DispatchSummary, current_unix_seconds, deliver_single, dispatch_due_deliveries, enqueue_webhook_delivery,
            sync_outbox_events, sync_pull_events,
        },
        models::{
            DELIVERY_FIELDS, DeliveriesQuery, DeliveryCursor, DispatchInput, NewWebhook, PingInput, RetryInput,
            WEBHOOK_FIELDS, Webhook, WebhookDelivery, WebhookPatch, WebhooksQuery, ensure_schema, json,
            validate_attempts_and_timeout, validate_ci_contexts, validate_events, validate_secret,
            validate_webhook_url,
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
    if body.is_empty() { Ok(T::default()) } else { serde_json::from_slice(body).map_err(|_| Error::bad_request()) }
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
    // The tenant column is the repository owner, never the acting user, so
    // collaborators and organization administrators read the owner's rows.
    let access = authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Read).await?;
    let sql = format!(
        "SELECT {WEBHOOK_FIELDS} FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND ($3::bool IS NULL OR active=$3) ORDER BY created_at ASC, id ASC OFFSET $4 LIMIT $5"
    );
    let rows = tx
        .query(&sql, &[&access.owner_id, &access.repo_id, &query.active, &after, &(limit + 1)])
        .await
        .map_err(Error::internal)?;
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
        let access = authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Write).await?;

        if let Some(ref k) = key {
            let req_val = sjson!({
                "operation": "create_webhook", "url": input.url, "secret_sha256": secret_sha256,
                "events": events, "ci_contexts": ci_contexts, "auto_ci_pin": auto_ci_pin,
                "active": active, "max_attempts": max_attempts, "timeout_ms": timeout_ms,
            });
            if let Some(saved) = creation_replay(&tx, access.owner_id, access.repo_id, k, &req_val).await? {
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
            .query_one(&sql, &[&hook_id, &access.owner_id, &access.repo_id, &input.url, &input.secret, &secret_sha256, &events_json, &contexts_json, &auto_ci_pin, &active, &max_attempts, &timeout_ms])
            .await
            .map_err(Error::internal)?;

        let webhook = Webhook::row(&row)?;
        let val = serde_json::to_value(&webhook).map_err(Error::internal)?;
        record_creation(&tx, access.owner_id, access.repo_id, key.as_deref(), &val).await?;
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
    let access = authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Read).await?;
    let row = tx
        .query_opt(
            &format!("SELECT {WEBHOOK_FIELDS} FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND id=$3"),
            &[&access.owner_id, &access.repo_id, &hook_id],
        )
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
        let policy_repo=crate::webhooks::trust::policy_repo_id(&state,&owner,&name).await?;
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        crate::webhooks::trust::lock_policy_tx(&tx,policy_repo).await?;
        let access = authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Write).await?;
        if access.repo_id!=policy_repo{return Err(Error(StatusCode::CONFLICT,"repository changed"));}

        let existing = tx
            .query_opt(&format!("SELECT {WEBHOOK_FIELDS}, secret FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND id=$3 FOR UPDATE"), &[&access.owner_id, &access.repo_id, &hook_id])
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
            .query_one(&sql, &[&access.owner_id, &access.repo_id, &hook_id, &next_url, &next_secret, &next_secret_sha256, &events_json, &contexts_json, &next_auto_pin, &next_active, &next_max_attempts, &next_timeout_ms])
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
        let policy_repo = crate::webhooks::trust::policy_repo_id(&state, &owner, &name).await?;
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        crate::webhooks::trust::lock_policy_tx(&tx, policy_repo).await?;
        let access = authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Write).await?;
        if access.repo_id != policy_repo {
            return Err(Error(StatusCode::CONFLICT, "repository changed"));
        }
        let deleted = tx
            .execute(
                "DELETE FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND id=$3",
                &[&access.owner_id, &access.repo_id, &hook_id],
            )
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
        let access = authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Write).await?;
        let row = tx
            .query_opt(
                "SELECT secret, max_attempts FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND id=$3",
                &[&access.owner_id, &access.repo_id, &hook_id],
            )
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
        let payload = sjson!({ "event": "ping", "zen": zen, "hook_id": hook_id, "repository_id": access.repo_id });

        let mut pool_client = state.pool.get().await.map_err(Error::internal)?;
        let delivery = match enqueue_webhook_delivery(
            &mut pool_client,
            access.owner_id,
            access.repo_id,
            hook_id,
            &secret,
            max_attempts,
            &event_id,
            "ping",
            &payload,
        )
        .await?
        {
            Some(d) => d,
            None => {
                let existing = pool_client
                    .query_one(
                        &format!(
                            "SELECT {DELIVERY_FIELDS} FROM forge_webhook_deliveries WHERE webhook_id=$1 AND event_id=$2"
                        ),
                        &[&hook_id, &event_id],
                    )
                    .await
                    .map_err(Error::internal)?;
                WebhookDelivery::row(&existing)
            }
        };
        drop(pool_client);

        let final_delivery = if input.deliver_now.unwrap_or(true) && delivery.state != "delivered" {
            deliver_single(&state, access.owner_id, access.repo_id, delivery.id, current_unix_seconds()).await?
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
        let access = authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Write).await?;
        finish(tx, &actor, true).await?;
        drop(client);

        let orchestrated_pulls = if input.sync_pulls.unwrap_or(true) {
            sync_pull_events(&state, access.owner_id, access.repo_id).await?.len()
        } else {
            0
        };
        let synced_outbox_deliveries = if input.sync_outbox.unwrap_or(true) {
            sync_outbox_events(&state, access.owner_id, access.repo_id).await?
        } else {
            0
        };
        let deliveries = dispatch_due_deliveries(&state, access.owner_id, access.repo_id, limit, now_unix).await?;
        let delivered_count = deliveries.iter().filter(|d| d.state == "delivered").count();
        let failed_count = deliveries.iter().filter(|d| d.state == "failed").count();
        let dead_letter_count = deliveries.iter().filter(|d| d.state == "dead_letter").count();

        Ok(json(
            StatusCode::OK,
            DispatchSummary {
                synced_outbox_deliveries,
                orchestrated_pulls,
                attempted_deliveries: deliveries.len(),
                delivered_count,
                failed_count,
                dead_letter_count,
                deliveries,
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
    let cursor = query.cursor(hook_id)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Read).await?;

    tx.query_opt(
        "SELECT id FROM forge_webhooks WHERE tenant_id=$1 AND repository_id=$2 AND id=$3",
        &[&access.owner_id, &access.repo_id, &hook_id],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::not_found)?;

    // The lossless cursor compares the composite key. Legacy `after=N` uses
    // `sequence > N` by placing the maximum UUID in the second component; that
    // intentionally skips historic ties and stays documented as lossy.
    let (start_sequence, start_id) = match cursor {
        Some(cursor) => (cursor.sequence, cursor.id),
        None if query.after.is_some() => (after, Uuid::from_bytes([u8::MAX; 16])),
        None => (after, Uuid::nil()),
    };
    let sql = format!(
        "SELECT {DELIVERY_FIELDS} FROM forge_webhook_deliveries WHERE tenant_id=$1 AND repository_id=$2 AND webhook_id=$3 AND (sequence, id) > ($4, $5) AND ($6::text IS NULL OR state = $6) AND ($7::text IS NULL OR event_type = $7) ORDER BY sequence ASC, id ASC LIMIT $8"
    );
    let rows = tx
        .query(
            &sql,
            &[
                &access.owner_id,
                &access.repo_id,
                &hook_id,
                &start_sequence,
                &start_id,
                &query.state,
                &query.event_type,
                &(limit + 1),
            ],
        )
        .await
        .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<_> = rows.iter().take(limit as usize).map(WebhookDelivery::row).collect();
    // Take the cursor from the last returned item, never the limit+1 probe row.
    let next_after = if more { items.last().map(|d| d.sequence) } else { None };
    let next_cursor = if more {
        items.last().map(|d| DeliveryCursor { hook_id, sequence: d.sequence, id: d.id }.encode())
    } else {
        None
    };
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({
            "webhook_id": hook_id, "items": items, "next_after": next_after, "next_cursor": next_cursor
        }),
    ))
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
    let access = authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Read).await?;
    let row = tx
        .query_opt(&format!("SELECT {DELIVERY_FIELDS} FROM forge_webhook_deliveries WHERE tenant_id=$1 AND repository_id=$2 AND webhook_id=$3 AND id=$4"), &[&access.owner_id, &access.repo_id, &hook_id, &delivery_id])
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
        let access = authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Write).await?;
        let row = tx
            .query_opt(
                &format!(
                    "UPDATE forge_webhook_deliveries SET state='pending', attempts = CASE WHEN $5 OR state='dead_letter' OR attempts >= max_attempts THEN 0 ELSE attempts END, lease_generation=lease_generation+1, next_attempt_unix=0, updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND webhook_id=$3 AND id=$4 AND (state <> 'leased' OR next_attempt_unix <= extract(epoch FROM clock_timestamp())) RETURNING {DELIVERY_FIELDS}"
                ),
                &[&access.owner_id, &access.repo_id, &hook_id, &delivery_id, &reset_attempts],
            )
            .await
            .map_err(Error::internal)?
            .ok_or(Error(StatusCode::CONFLICT, "delivery is being sent or does not exist"))?;
        let pending_delivery = WebhookDelivery::row(&row);
        finish(tx, &actor, true).await?;
        drop(client);

        let result = if input.deliver_now.unwrap_or(true) {
            deliver_single(&state, access.owner_id, access.repo_id, delivery_id, now_unix).await?
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
    tokio::spawn(
        async move { crate::webhooks::ingestion::ci_callback(state, owner, name, hook_id, headers, body).await },
    )
    .await
    .map_err(Error::internal)?
}
