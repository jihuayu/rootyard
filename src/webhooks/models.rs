//! Data models, SSRF-safe webhook URL validation, event/context validators,
//! and idempotent runtime schema initialization for Track A (`webhooks`).
use crate::{
    Error,
    pulls::models::context_valid,
    webhooks::{policy, signing::sha256_hex},
};
use axum::{
    Json,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use tokio_postgres::Row;
use uuid::Uuid;

pub const WEBHOOK_FIELDS: &str = "id,tenant_id,repository_id,url,secret_sha256,events,ci_contexts,auto_ci_pin,active,max_attempts,timeout_ms,version,created_at::text,updated_at::text";
pub const DELIVERY_FIELDS: &str = "id,webhook_id,tenant_id,repository_id,sequence,event_id,event_type,payload,request_headers,signature_256,state,attempts,max_attempts,response_status,last_error,next_attempt_unix,delivered_at::text,created_at::text,updated_at::text";
pub const SUPPORTED_EVENTS: &[&str] = &["push", "pull_request", "check_run", "ping"];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Webhook {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub url: String,
    pub secret_sha256: String,
    pub secret_configured: bool,
    pub events: Vec<String>,
    pub ci_contexts: Vec<String>,
    pub auto_ci_pin: bool,
    pub active: bool,
    pub max_attempts: i64,
    pub timeout_ms: i64,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl Webhook {
    pub fn row(row: &Row) -> Result<Self, Error> {
        let events: Vec<String> = serde_json::from_value(row.get("events")).map_err(Error::internal)?;
        let ci_contexts: Vec<String> = serde_json::from_value(row.get("ci_contexts")).map_err(Error::internal)?;
        Ok(Self {
            id: row.get("id"),
            repository_id: row.get("repository_id"),
            url: row.get("url"),
            secret_sha256: row.get("secret_sha256"),
            secret_configured: true,
            events,
            ci_contexts,
            auto_ci_pin: row.get("auto_ci_pin"),
            active: row.get("active"),
            max_attempts: row.get("max_attempts"),
            timeout_ms: row.get("timeout_ms"),
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub repository_id: Uuid,
    pub sequence: i64,
    pub event_id: String,
    pub event_type: String,
    pub payload: Value,
    pub request_headers: Value,
    pub signature_256: String,
    pub state: String,
    pub attempts: i64,
    pub max_attempts: i64,
    pub response_status: Option<i32>,
    pub last_error: Option<String>,
    pub next_attempt_unix: i64,
    pub delivered_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl WebhookDelivery {
    pub fn row(row: &Row) -> Self {
        Self {
            id: row.get("id"),
            webhook_id: row.get("webhook_id"),
            repository_id: row.get("repository_id"),
            sequence: row.get("sequence"),
            event_id: row.get("event_id"),
            event_type: row.get("event_type"),
            payload: row.get("payload"),
            request_headers: row.get("request_headers"),
            signature_256: row.get("signature_256"),
            state: row.get("state"),
            attempts: row.get("attempts"),
            max_attempts: row.get("max_attempts"),
            response_status: row.get("response_status"),
            last_error: row.get("last_error"),
            next_attempt_unix: row.get("next_attempt_unix"),
            delivered_at: row.get("delivered_at"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewWebhook {
    pub url: String,
    pub secret: String,
    #[serde(default)]
    pub events: Option<Vec<String>>,
    #[serde(default)]
    pub ci_contexts: Option<Vec<String>>,
    #[serde(default)]
    pub auto_ci_pin: Option<bool>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub max_attempts: Option<i64>,
    #[serde(default)]
    pub timeout_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookPatch {
    #[serde(default)]
    pub expected_version: Option<i64>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub events: Option<Vec<String>>,
    #[serde(default)]
    pub ci_contexts: Option<Vec<String>>,
    #[serde(default)]
    pub auto_ci_pin: Option<bool>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default)]
    pub max_attempts: Option<i64>,
    #[serde(default)]
    pub timeout_ms: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PingInput {
    #[serde(default)]
    pub zen: Option<String>,
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub deliver_now: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchInput {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub now_unix: Option<i64>,
    #[serde(default)]
    pub sync_outbox: Option<bool>,
    #[serde(default)]
    pub sync_pulls: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryInput {
    #[serde(default)]
    pub now_unix: Option<i64>,
    #[serde(default)]
    pub deliver_now: Option<bool>,
    #[serde(default)]
    pub reset_attempts: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiCallbackInput {
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub delivery_id: Option<Uuid>,
    pub commit_oid: String,
    #[serde(default)]
    pub context: Option<String>,
    pub status: String,
    #[serde(default)]
    pub conclusion: Option<String>,
    #[serde(default)]
    pub attempt: Option<i64>,
    #[serde(default)]
    pub sequence: Option<i64>,
    #[serde(default)]
    pub output: Option<String>,
    #[serde(default)]
    pub pull_number: Option<i64>,
    #[serde(default)]
    pub ci_run_id: Option<Uuid>,
    #[serde(default)]
    pub ci_job_id: Option<Uuid>,
    #[serde(default)]
    pub base_oid: Option<String>,
    #[serde(default)]
    pub lease_generation: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveriesQuery {
    #[serde(default)]
    pub after: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub event_type: Option<String>,
}

impl DeliveriesQuery {
    pub fn bounds(&self) -> Result<(i64, i64), Error> {
        let after = self.after.unwrap_or(0);
        let limit = self.limit.unwrap_or(50);
        if after < 0 || !(1..=100).contains(&limit) {
            return Err(Error::bad_request());
        }
        if let Some(ref st) = self.state
            && !matches!(st.as_str(), "pending" | "leased" | "delivered" | "failed" | "dead_letter")
        {
            return Err(Error::bad_request());
        }
        if let Some(ref et) = self.event_type
            && !SUPPORTED_EVENTS.contains(&et.as_str())
        {
            return Err(Error::bad_request());
        }
        Ok((after, limit))
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhooksQuery {
    #[serde(default)]
    pub after: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub active: Option<bool>,
}

impl WebhooksQuery {
    pub fn bounds(&self) -> Result<(i64, i64), Error> {
        let after = self.after.unwrap_or(0);
        let limit = self.limit.unwrap_or(50);
        if after < 0 || !(1..=100).contains(&limit) {
            return Err(Error::bad_request());
        }
        Ok((after, limit))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedWebhookTarget {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub host_header: String,
    pub is_loopback: bool,
}

pub fn json(status: StatusCode, value: impl Serialize) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}

/// Validates a webhook target URL against SSRF rules under the current operator policy.
pub fn validate_webhook_url(raw: &str) -> Result<ParsedWebhookTarget, Error> {
    validate_webhook_url_with_policy(raw, policy::loopback_targets_allowed())
}

/// Validates a webhook target URL against the SSRF rules. `loopback_allowed` is the
/// explicit operator opt-in; loopback targets are rejected when it is false.
pub fn validate_webhook_url_with_policy(raw: &str, loopback_allowed: bool) -> Result<ParsedWebhookTarget, Error> {
    if !(8..=1024).contains(&raw.len()) || raw.contains('#') || raw.bytes().any(|b| b <= 32 || b == 127) {
        return Err(Error::bad_request());
    }
    let uri: Uri = raw.parse().map_err(|_| Error::bad_request())?;
    let scheme = uri.scheme_str().ok_or_else(Error::bad_request)?;
    if !matches!(scheme, "http" | "https") {
        return Err(Error::bad_request());
    }
    let authority = uri.authority().ok_or_else(Error::bad_request)?;
    if authority.as_str().contains('@') {
        return Err(Error::bad_request());
    }
    let raw_host = authority.host().trim();
    if raw_host.is_empty() {
        return Err(Error::bad_request());
    }
    let unbracketed =
        raw_host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(raw_host).to_ascii_lowercase();

    let port = match authority.port_u16() {
        Some(0) => return Err(Error::bad_request()),
        Some(p) => p,
        None => {
            if scheme == "https" {
                443
            } else {
                80
            }
        }
    };

    let is_loopback = policy::host_is_loopback(&unbracketed);
    if scheme == "http" && !is_loopback {
        return Err(Error::bad_request());
    }
    // Loopback egress is denied unless the operator opted in. The decision never
    // comes from the request body, and it is re-evaluated for every delivery.
    if is_loopback && !loopback_allowed {
        return Err(Error::bad_request());
    }

    if !is_loopback {
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            let blocked = match ip {
                IpAddr::V4(v4) => policy::ipv4_is_blocked_non_loopback(v4),
                IpAddr::V6(v6) => policy::ipv6_is_blocked_non_loopback(v6),
            };
            if blocked {
                return Err(Error::bad_request());
            }
        } else if unbracketed == "metadata.google.internal"
            || unbracketed == "metadata"
            || unbracketed == "instance-data"
            || unbracketed.ends_with(".internal")
            || unbracketed.ends_with(".local")
            || !unbracketed.contains('.')
            || unbracketed.bytes().all(|b| b.is_ascii_digit() || b == b'.' || b == b':')
        {
            return Err(Error::bad_request());
        }
    }

    let path_and_query = uri.path_and_query().map(|pq| pq.as_str().to_owned()).unwrap_or_else(|| "/".to_owned());
    let host_for_header = if unbracketed.contains(':') { format!("[{unbracketed}]") } else { unbracketed.clone() };
    let host_header = if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
        host_for_header
    } else {
        format!("{host_for_header}:{port}")
    };

    Ok(ParsedWebhookTarget {
        scheme: scheme.to_owned(),
        host: unbracketed,
        port,
        path_and_query,
        host_header,
        is_loopback,
    })
}

pub fn validate_secret(secret: &str) -> Result<String, Error> {
    if !(8..=256).contains(&secret.len()) || secret.trim().is_empty() || secret.chars().any(char::is_control) {
        return Err(Error::bad_request());
    }
    Ok(sha256_hex(secret.as_bytes()))
}

pub fn validate_events(raw: &[String]) -> Result<Vec<String>, Error> {
    if raw.is_empty() || raw.len() > 16 {
        return Err(Error::bad_request());
    }
    let mut out = Vec::new();
    for item in raw {
        if item == "*" {
            for ev in ["push", "pull_request", "check_run"] {
                if !out.iter().any(|existing| existing == ev) {
                    out.push(ev.to_owned());
                }
            }
            continue;
        }
        if !SUPPORTED_EVENTS.contains(&item.as_str()) {
            return Err(Error::bad_request());
        }
        if !out.contains(item) {
            out.push(item.clone());
        }
    }
    if out.is_empty() || out.len() > 16 {
        return Err(Error::bad_request());
    }
    Ok(out)
}

pub fn validate_ci_contexts(raw: &[String]) -> Result<Vec<String>, Error> {
    if raw.len() > 64 {
        return Err(Error::bad_request());
    }
    let mut out = Vec::new();
    for ctx in raw {
        if !context_valid(ctx) {
            return Err(Error::bad_request());
        }
        if !out.contains(ctx) {
            out.push(ctx.clone());
        }
    }
    Ok(out)
}

pub fn validate_attempts_and_timeout(max_attempts: i64, timeout_ms: i64) -> Result<(), Error> {
    if !(1..=20).contains(&max_attempts) || !(100..=30_000).contains(&timeout_ms) {
        return Err(Error::bad_request());
    }
    Ok(())
}

/// Idempotently initializes the Track A webhook tables under an advisory transaction lock.
pub async fn ensure_schema(pool: &Pool) -> Result<(), Error> {
    let mut client = pool.get().await.map_err(Error::internal)?;
    let exists: bool = client
        .query_one(
            "SELECT to_regclass('forge_webhooks') IS NOT NULL \
             AND to_regclass('forge_webhook_deliveries') IS NOT NULL \
             AND to_regclass('forge_webhook_callbacks') IS NOT NULL",
            &[],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    if exists {
        return Ok(());
    }

    let tx = client.transaction().await.map_err(Error::internal)?;
    tx.execute("SELECT pg_advisory_xact_lock(400402026)", &[]).await.map_err(Error::internal)?;
    let ddl = crate::webhooks::MIGRATION_040_SQL
        .split("INSERT INTO schema_migrations")
        .next()
        .unwrap_or(crate::webhooks::MIGRATION_040_SQL);
    tx.batch_execute(ddl).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_context_and_secret_validators() {
        assert_eq!(validate_secret("whsec_valid_secret_12345").unwrap().len(), 64);
        assert!(validate_secret("short").is_err());
        assert_eq!(
            validate_events(&["push".into(), "pull_request".into(), "push".into()]).unwrap(),
            vec!["push".to_string(), "pull_request".to_string()]
        );
        assert_eq!(validate_events(&["*".into()]).unwrap(), vec!["push", "pull_request", "check_run"]);
        assert_eq!(
            validate_ci_contexts(&["ci/build".into(), "ci/test".into(), "ci/build".into()]).unwrap(),
            vec!["ci/build".to_string(), "ci/test".to_string()]
        );
    }

    #[test]
    fn loopback_is_denied_unless_the_caller_passes_the_explicit_opt_in() {
        assert!(validate_webhook_url_with_policy("http://127.0.0.1:9000/hook", false).is_err());
        assert!(validate_webhook_url_with_policy("https://localhost/hook", false).is_err());
        assert!(validate_webhook_url_with_policy("http://127.0.0.1:9000/hook", true).is_ok());
        assert!(validate_webhook_url_with_policy("https://ci.example.com/hook", false).is_ok());
    }
}
