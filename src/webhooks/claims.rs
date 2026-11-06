//! Short PostgreSQL claims fence network delivery outcomes without holding a transaction open.
use crate::{Error, webhooks::models::{DELIVERY_FIELDS, WebhookDelivery}};
use serde_json::Value;
use uuid::Uuid;

pub struct Claimed {
    pub webhook_id: Uuid,
    pub event_type: String,
    pub payload: Value,
    pub attempt: i64,
    pub generation: i64,
    pub max_attempts: i64,
    pub url: String,
    pub secret: String,
    pub timeout_ms: i64,
}

/// UPDATE obtains the row lock and advances the generation atomically. A crashed sender
/// becomes eligible again after its bounded transport deadline plus five seconds.
pub async fn claim(
    client: &tokio_postgres::Client,
    tenant_id: Uuid,
    repository_id: Uuid,
    delivery_id: Uuid,
    now_unix: i64,
) -> Result<Option<Claimed>, Error> {
    let row = client.query_opt(
        "UPDATE forge_webhook_deliveries d SET state='leased', attempts=d.attempts+1, \
         lease_generation=d.lease_generation+1, next_attempt_unix=$4 + \
         ((w.timeout_ms + 999) / 1000) + 5, updated_at=clock_timestamp() \
         FROM forge_webhooks w WHERE d.webhook_id=w.id AND w.active=true \
         AND d.tenant_id=$1 AND d.repository_id=$2 AND d.id=$3 \
         AND (d.state='pending' OR (d.state IN ('failed','leased') \
              AND d.next_attempt_unix <= $4)) \
         RETURNING d.webhook_id,d.event_type,d.payload,d.attempts,d.lease_generation, \
                   d.max_attempts,w.url,w.secret,w.timeout_ms",
        &[&tenant_id, &repository_id, &delivery_id, &now_unix],
    ).await.map_err(Error::internal)?;
    Ok(row.map(|r| Claimed {
        webhook_id: r.get("webhook_id"), event_type: r.get("event_type"),
        payload: r.get("payload"), attempt: r.get("attempts"),
        generation: r.get("lease_generation"), max_attempts: r.get("max_attempts"),
        url: r.get("url"), secret: r.get("secret"), timeout_ms: r.get("timeout_ms"),
    }))
}

#[allow(clippy::too_many_arguments)]
pub async fn complete(
    client: &tokio_postgres::Client,
    tenant_id: Uuid,
    repository_id: Uuid,
    delivery_id: Uuid,
    generation: i64,
    next_state: &str,
    headers: &Value,
    signature: &str,
    status: Option<i32>,
    error: Option<String>,
    next_unix: i64,
    delivered: bool,
) -> Result<WebhookDelivery, Error> {
    let sql = format!(
        "UPDATE forge_webhook_deliveries SET state=$5,request_headers=$6,signature_256=$7, \
         response_status=$8,last_error=$9,next_attempt_unix=$10, \
         delivered_at=CASE WHEN $11 THEN clock_timestamp() ELSE delivered_at END, \
         updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND id=$3 \
         AND state='leased' AND lease_generation=$4 RETURNING {DELIVERY_FIELDS}"
    );
    let row = client.query_opt(&sql, &[&tenant_id,&repository_id,&delivery_id,&generation,
        &next_state,&headers,&signature,&status,&error,&next_unix,&delivered])
        .await.map_err(Error::internal)?;
    match row {
        Some(row) => Ok(WebhookDelivery::row(&row)),
        None => current(client, tenant_id, repository_id, delivery_id).await,
    }
}

pub async fn current(
    client: &tokio_postgres::Client,
    tenant_id: Uuid,
    repository_id: Uuid,
    delivery_id: Uuid,
) -> Result<WebhookDelivery, Error> {
    let sql = format!("SELECT {DELIVERY_FIELDS} FROM forge_webhook_deliveries WHERE tenant_id=$1 AND repository_id=$2 AND id=$3");
    client.query_opt(&sql, &[&tenant_id,&repository_id,&delivery_id]).await
        .map_err(Error::internal)?.as_ref().map(WebhookDelivery::row)
        .ok_or_else(Error::not_found)
}
