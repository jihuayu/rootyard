//! Idempotent in-app notifications (`forge_notifications`).
//!
//! Channel & retention contract:
//! - Channel `in_app`: notifications are persisted in PostgreSQL (`forge_notifications`)
//!   with `UNIQUE (recipient_id, delivery_key)` so duplicate dispatch or retries are no-ops.
//! - Retention: notifications carry a 90-day default `expires_at` (`NOTIFICATION_RETENTION_DAYS`);
//!   expired rows are excluded from all queries and purged via `prune_expired_notifications`.
//! - Live authorization: every read/ack re-evaluates repository membership/RBAC and
//!   restricted-PAT grants inside the transaction so revoked access hides private data at once.

use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish},
    db::{self, Identity},
    pagination,
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::Transaction;
use serde::{Deserialize, Serialize};
use serde_json::json as sjson;
use std::sync::Arc;
use uuid::Uuid;

pub const NOTIFICATION_CHANNEL: &str = "in_app";
pub const NOTIFICATION_RETENTION_DAYS: i64 = 90;
const PAGE_DEFAULT: i64 = 50;
const NOTIF_CURSOR_SCOPE: &str = "forge-notifications:v1";

pub(crate) const REPO_VISIBILITY_SQL: &str = concat!(
    "r.state='ready' AND (ns.user_id=$USER",
    " OR EXISTS (SELECT 1 FROM organization_memberships m WHERE m.organization_id=r.owner_id AND m.user_id=$USER)",
    " OR EXISTS (SELECT 1 FROM organization_team_members tm WHERE tm.organization_id=r.owner_id AND tm.user_id=$USER)",
    " OR EXISTS (SELECT 1 FROM repository_collaborators c WHERE c.repository_id=r.id AND c.user_id=$USER)",
    " OR EXISTS (SELECT 1 FROM repository_team_members tm WHERE tm.repository_id=r.id AND tm.user_id=$USER))"
);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Notification {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub owner: String,
    pub repo: String,
    pub recipient_id: Uuid,
    pub actor_id: Option<Uuid>,
    pub channel: String,
    pub target_type: String,
    pub target_number: i64,
    pub event_kind: String,
    pub delivery_key: String,
    pub title: String,
    pub body_excerpt: String,
    pub delivery_count: i64,
    pub unread: bool,
    pub read_at: Option<String>,
    pub expires_at: String,
    pub created_at: String,
    pub updated_at: String,
}

impl Notification {
    pub fn row(row: &tokio_postgres::Row) -> Self {
        Self {
            id: row.get("id"),
            repository_id: row.get("repository_id"),
            owner: row.get("owner"),
            repo: row.get("repo"),
            recipient_id: row.get("recipient_id"),
            actor_id: row.get("actor_id"),
            channel: row.get("channel"),
            target_type: row.get("target_type"),
            target_number: row.get("target_number"),
            event_kind: row.get("event_kind"),
            delivery_key: row.get("delivery_key"),
            title: row.get("title"),
            body_excerpt: row.get("body_excerpt"),
            delivery_count: row.get("delivery_count"),
            unread: row.get("unread"),
            read_at: row.get("read_at"),
            expires_at: row.get("expires_at"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationQuery {
    pub unread_only: Option<bool>,
    pub owner: Option<String>,
    pub repo: Option<String>,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadAllInput {
    pub owner: Option<String>,
    pub repo: Option<String>,
}

pub(crate) struct NotifySpec<'a> {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub actor_id: Uuid,
    pub target_type: &'a str,
    pub target_number: i64,
    pub thread_type: &'a str,
    pub thread_number: i64,
    pub event_kind: &'a str,
    pub delivery_key: &'a str,
    pub title: &'a str,
    pub body_excerpt: &'a str,
    pub extra_recipients: &'a [Uuid],
}

fn json(status: StatusCode, value: impl Serialize) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}

pub(crate) fn sanitize_single_line(raw: &str, max_bytes: usize, fallback: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return fallback.to_owned();
    }
    let mut end = 0;
    for (idx, ch) in trimmed.char_indices() {
        if idx + ch.len_utf8() > max_bytes {
            break;
        }
        end = idx + ch.len_utf8();
    }
    trimmed[..end].to_owned()
}

pub(crate) fn valid_iso_cursor_ts(raw: &str) -> bool {
    let b = raw.as_bytes();
    b.len() == 27
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'.'
        && b[26] == b'Z'
        && b.iter()
            .enumerate()
            .filter(|(i, _)| !matches!(i, 4 | 7 | 10 | 13 | 16 | 19 | 26))
            .all(|(_, c)| c.is_ascii_digit())
}

fn scope_key(actor_id: Uuid, restricted: bool, unread_only: bool, owner: Option<&str>, repo: Option<&str>) -> String {
    format!(
        "{NOTIF_CURSOR_SCOPE}:{actor_id}:{restricted}:{unread_only}:{}:{}",
        owner.unwrap_or("*"),
        repo.unwrap_or("*"),
    )
}

pub(crate) async fn emit_repo_notifications(
    tx: &Transaction<'_>,
    spec: NotifySpec<'_>,
) -> Result<(), Error> {
    let title = sanitize_single_line(spec.title, 256, "Repository activity");
    let excerpt = sanitize_single_line(spec.body_excerpt, 512, "");
    let sql = concat!(
        "WITH live_members AS (",
        " SELECT ns.user_id AS uid FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id WHERE r.id=$2 AND ns.user_id IS NOT NULL",
        " UNION SELECT user_id FROM organization_memberships WHERE organization_id=$1",
        " UNION SELECT user_id FROM organization_team_members WHERE organization_id=$1",
        " UNION SELECT user_id FROM repository_collaborators WHERE repository_id=$2",
        " UNION SELECT user_id FROM repository_team_members WHERE repository_id=$2",
        "), candidates AS (",
        " SELECT s.user_id AS recipient_id FROM forge_subscriptions s",
        " WHERE s.tenant_id=$1 AND s.repository_id=$2 AND s.state='subscribed'",
        " AND ((s.target_type=$4 AND s.target_number=$5) OR (s.target_type='repository' AND s.target_number=0))",
        " UNION SELECT unnest($12::uuid[]) AS recipient_id",
        "), active AS (",
        " SELECT DISTINCT c.recipient_id FROM candidates c JOIN live_members lm ON lm.uid=c.recipient_id",
        " WHERE c.recipient_id <> $3",
        " AND NOT EXISTS (SELECT 1 FROM forge_subscriptions ig WHERE ig.tenant_id=$1 AND ig.repository_id=$2 AND ig.user_id=c.recipient_id AND ig.state='ignored' AND ((ig.target_type=$4 AND ig.target_number=$5) OR (ig.target_type='repository' AND ig.target_number=0)))",
        ") ",
        "INSERT INTO forge_notifications (tenant_id,repository_id,recipient_id,actor_id,channel,target_type,target_number,event_kind,delivery_key,title,body_excerpt) ",
        "SELECT $1,$2,a.recipient_id,$3,'in_app',$6,$7,$8,$9,$10,$11 FROM active a ",
        "ON CONFLICT (recipient_id, delivery_key) DO NOTHING"
    );
    tx.execute(
        sql,
        &[
            &spec.tenant_id,
            &spec.repository_id,
            &spec.actor_id,
            &spec.thread_type,
            &spec.thread_number,
            &spec.target_type,
            &spec.target_number,
            &spec.event_kind,
            &spec.delivery_key,
            &title,
            &excerpt,
            &spec.extra_recipients,
        ],
    )
    .await
    .map_err(Error::internal)?;
    Ok(())
}

pub(crate) fn visibility_and_scope_clause(restricted: bool) -> String {
    let vis = REPO_VISIBILITY_SQL.replace("$USER", "$1");
    let scope = if restricted {
        " AND EXISTS (SELECT 1 FROM token_repository_scopes ts WHERE ts.token_id=$2 AND ts.repository_id=r.id AND ts.action = CASE WHEN n.target_type='issue' THEN 'issues_read' WHEN n.target_type IN ('pull','pull_review','pull_review_comment') THEN 'pulls_read' ELSE 'repo_read' END)"
    } else {
        ""
    };
    format!("{vis}{scope}")
}

pub(crate) async fn load_notifications_page(
    tx: &Transaction<'_>,
    actor: &Identity,
    query: &NotificationQuery,
) -> Result<(Vec<Notification>, Option<String>), Error> {
    let unread_only = query.unread_only.unwrap_or(false);
    let limit = query.limit.unwrap_or(PAGE_DEFAULT);
    if !(1..=100).contains(&limit) {
        return Err(Error::bad_request());
    }
    if query.owner.as_ref().is_some_and(|v| !db::valid_name(v))
        || query.repo.as_ref().is_some_and(|v| !db::valid_name(v))
        || (query.repo.is_some() && query.owner.is_none())
    {
        return Err(Error::bad_request());
    }
    let restricted = auth::token_is_restricted(tx, actor).await?;
    let scope = scope_key(actor.id, restricted, unread_only, query.owner.as_deref(), query.repo.as_deref());
    let (cursor_ts, cursor_id) = match query.cursor.as_deref() {
        Some(raw) => {
            let parts = pagination::decode(raw, &scope, 2)?;
            if !valid_iso_cursor_ts(&parts[0]) {
                return Err(Error(StatusCode::BAD_REQUEST, "invalid pagination cursor"));
            }
            let id = Uuid::parse_str(&parts[1])
                .map_err(|_| Error(StatusCode::BAD_REQUEST, "invalid pagination cursor"))?;
            (Some(parts[0].clone()), Some(id))
        }
        None => (None, None),
    };
    let gate = visibility_and_scope_clause(restricted);
    let sql = format!(
        "SELECT n.id,n.repository_id,ns.slug AS owner,r.name AS repo,n.recipient_id,n.actor_id,n.channel,n.target_type,n.target_number,n.event_kind,n.delivery_key,n.title,n.body_excerpt,n.delivery_count,n.unread,n.read_at::text,n.expires_at::text,n.created_at::text,n.updated_at::text,to_char(n.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS cursor_ts \
         FROM forge_notifications n \
         JOIN repositories r ON r.id=n.repository_id AND r.owner_id=n.tenant_id \
         JOIN namespaces ns ON ns.id=r.owner_id \
         WHERE n.recipient_id=$1 AND NOT n.archived AND n.expires_at > clock_timestamp() \
         AND (NOT $3::bool OR n.unread) \
         AND ($4::text IS NULL OR ns.slug=$4) \
         AND ($5::text IS NULL OR r.name=$5) \
         AND ({gate}) \
         AND ($6::text IS NULL OR (n.created_at, n.id) < ($6::text::timestamptz, $7::uuid)) \
         ORDER BY n.created_at DESC, n.id DESC LIMIT $8"
    );
    let rows = tx
        .query(
            &sql,
            &[
                &actor.id,
                &actor.token_id,
                &unread_only,
                &query.owner,
                &query.repo,
                &cursor_ts,
                &cursor_id,
                &(limit + 1),
            ],
        )
        .await
        .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<Notification> = rows.iter().take(limit as usize).map(Notification::row).collect();
    let next_cursor = if more {
        rows.get(limit as usize - 1).map(|row| {
            let ts: String = row.get("cursor_ts");
            let id: Uuid = row.get("id");
            let id_s = id.to_string();
            pagination::encode(&scope, &[ts.as_str(), id_s.as_str()])
        })
    } else {
        None
    };
    Ok((items, next_cursor))
}

pub(crate) async fn mark_notification_read_tx(
    tx: &Transaction<'_>,
    actor: &Identity,
    id: Uuid,
) -> Result<(Notification, bool), Error> {
    let restricted = auth::token_is_restricted(tx, actor).await?;
    let gate = visibility_and_scope_clause(restricted);
    let check_sql = format!(
        "SELECT n.unread FROM forge_notifications n \
         JOIN repositories r ON r.id=n.repository_id AND r.owner_id=n.tenant_id \
         JOIN namespaces ns ON ns.id=r.owner_id \
         WHERE n.id=$3 AND n.recipient_id=$1 AND NOT n.archived AND n.expires_at > clock_timestamp() AND ({gate}) \
         FOR UPDATE OF n"
    );
    let was_unread: bool = tx
        .query_opt(&check_sql, &[&actor.id, &actor.token_id, &id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0);
    let upd_sql = concat!(
        "UPDATE forge_notifications SET unread=false,read_at=COALESCE(read_at,clock_timestamp()),",
        "updated_at=CASE WHEN unread THEN clock_timestamp() ELSE updated_at END ",
        "WHERE id=$1 AND recipient_id=$2 ",
        "RETURNING id,repository_id,(SELECT slug FROM namespaces WHERE id=tenant_id) AS owner,(SELECT name FROM repositories WHERE id=repository_id) AS repo,recipient_id,actor_id,channel,target_type,target_number,event_kind,delivery_key,title,body_excerpt,delivery_count,unread,read_at::text,expires_at::text,created_at::text,updated_at::text"
    );
    let row = tx.query_one(upd_sql, &[&id, &actor.id]).await.map_err(Error::internal)?;
    Ok((Notification::row(&row), !was_unread))
}

pub(crate) async fn mark_all_notifications_read_tx(
    tx: &Transaction<'_>,
    actor: &Identity,
    input: &ReadAllInput,
) -> Result<u64, Error> {
    if input.owner.as_ref().is_some_and(|v| !db::valid_name(v))
        || input.repo.as_ref().is_some_and(|v| !db::valid_name(v))
        || (input.repo.is_some() && input.owner.is_none())
    {
        return Err(Error::bad_request());
    }
    let restricted = auth::token_is_restricted(tx, actor).await?;
    let gate = visibility_and_scope_clause(restricted);
    let sql = format!(
        "UPDATE forge_notifications n SET unread=false,read_at=clock_timestamp(),updated_at=clock_timestamp() \
         FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id \
         WHERE n.repository_id=r.id AND n.tenant_id=r.owner_id \
         AND n.recipient_id=$1 AND n.unread AND NOT n.archived AND n.expires_at > clock_timestamp() \
         AND ($3::text IS NULL OR ns.slug=$3) AND ($4::text IS NULL OR r.name=$4) \
         AND ({gate})"
    );
    tx.execute(&sql, &[&actor.id, &actor.token_id, &input.owner, &input.repo])
        .await
        .map_err(Error::internal)
}

pub async fn list_notifications(
    State(state): State<Arc<AppState>>,
    Query(query): Query<NotificationQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, false).await?;
    let (items, next_cursor) = load_notifications_page(&tx, &actor, &query).await?;
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({
            "items": items,
            "next_cursor": next_cursor,
            "channel": NOTIFICATION_CHANNEL,
            "retention_days": NOTIFICATION_RETENTION_DAYS,
        }),
    ))
}

pub async fn mark_notification_read(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    let (notification, already_read) = mark_notification_read_tx(&tx, &actor, id).await?;
    finish(tx, &actor, true).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "notification": notification, "already_read": already_read }),
    ))
}

pub async fn mark_all_notifications_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    input: Option<Json<ReadAllInput>>,
) -> Result<Response, Error> {
    let input = input.map(|Json(v)| v).unwrap_or_default();
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    let updated_count = mark_all_notifications_read_tx(&tx, &actor, &input).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, sjson!({ "updated_count": updated_count })))
}

pub async fn prune_expired_notifications(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    let deleted = tx
        .execute(
            "DELETE FROM forge_notifications WHERE recipient_id=$1 AND expires_at <= clock_timestamp()",
            &[&actor.id],
        )
        .await
        .map_err(Error::internal)?;
    finish(tx, &actor, true).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "pruned_count": deleted, "retention_days": NOTIFICATION_RETENTION_DAYS }),
    ))
}
