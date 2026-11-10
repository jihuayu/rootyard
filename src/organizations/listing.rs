//! Bounded, scope-bound keyset pagination for organization member and team
//! listings.
//!
//! Both lists keep the historical `{"items":[...],"truncated":bool}` envelope
//! and add `next_cursor`. The cursor is an ordering position, never a
//! capability: every page re-authenticates the caller, resolves the
//! organization by slug and re-runs the membership/role check before any row
//! is read. Each cursor is bound to `(actor, organization, list kind)` by the
//! codec scope, so replaying it as another actor, organization or list is a
//! 400 rather than an authorization shortcut.
use crate::{AppState, Error, auth, db, members::models::Role, pagination, token_scopes::NamespaceAction};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json as sjson};
use std::sync::Arc;
use uuid::Uuid;

use super::{Res, org_id, require_member};

const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 1000;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgListQuery {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Serialize)]
struct OrgPage {
    items: Vec<Value>,
    truncated: bool,
    next_cursor: Option<String>,
}

fn bad_cursor() -> Error {
    Error(StatusCode::BAD_REQUEST, "invalid pagination cursor")
}

fn member_scope(actor: Uuid, org: Uuid) -> String {
    format!("organization-members:{actor}:{org}")
}

fn team_scope(actor: Uuid, org: Uuid) -> String {
    format!("organization-teams:{actor}:{org}")
}

fn decode_member_cursor(raw: &str, actor: Uuid, org: Uuid) -> Result<(String, Uuid), Error> {
    let fields = pagination::decode(raw, &member_scope(actor, org), 2)?;
    let [username, user_id] = fields.as_slice() else {
        return Err(bad_cursor());
    };
    let user_id = Uuid::parse_str(user_id).map_err(|_| bad_cursor())?;
    if user_id.is_nil() || !db::valid_name(username) {
        return Err(bad_cursor());
    }
    Ok((username.clone(), user_id))
}

fn decode_team_cursor(raw: &str, actor: Uuid, org: Uuid) -> Result<(String, Uuid), Error> {
    let fields = pagination::decode(raw, &team_scope(actor, org), 2)?;
    let [slug, id] = fields.as_slice() else {
        return Err(bad_cursor());
    };
    let id = Uuid::parse_str(id).map_err(|_| bad_cursor())?;
    if id.is_nil() || !db::valid_name(slug) {
        return Err(bad_cursor());
    }
    Ok((slug.clone(), id))
}

fn limit_of(query: &OrgListQuery) -> Result<i64, Error> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(Error::bad_request());
    }
    Ok(limit)
}

fn page_response(
    items: Vec<Value>,
    more: bool,
    next_cursor: Option<String>,
    uri: &Uri,
    limit: i64,
) -> Result<Response, Error> {
    let mut response = (
        [(header::CACHE_CONTROL, "no-store")],
        Json(OrgPage { items, truncated: more, next_cursor: next_cursor.clone() }),
    )
        .into_response();
    if let Some(cursor) = next_cursor {
        response.headers_mut().insert(
            header::HeaderName::from_static("x-next-cursor"),
            header::HeaderValue::from_str(&cursor).map_err(Error::internal)?,
        );
        let link =
            format!("<{}?cursor={}&limit={}>; rel=\"next\"", uri.path(), pagination::query_value(&cursor), limit);
        response.headers_mut().insert(header::LINK, header::HeaderValue::from_str(&link).map_err(Error::internal)?);
    }
    Ok(response)
}

pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Query(query): Query<OrgListQuery>,
    uri: Uri,
    headers: HeaderMap,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let limit = limit_of(&query)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let org = org_id(&tx, &slug).await?;
    auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgRead).await?;
    // Authorization precedes cursor decoding: an unauthorized caller keeps the
    // historical 404/403 even when the supplied cursor is malformed.
    require_member(&tx, org, actor.id, Role::Read).await?;
    let cursor = match query.cursor.as_deref() {
        Some(raw) => Some(decode_member_cursor(raw, actor.id, org)?),
        None => None,
    };
    let rows = match &cursor {
        // First page: organization predicate only, so no unreachable
        // `cursor IS NULL OR ...` disjunction can force a prefix scan.
        None => {
            tx.query(
                "SELECT u.username,m.user_id,m.role,m.version FROM organization_memberships m \
                 JOIN users u ON u.id=m.user_id WHERE m.organization_id=$1 \
                 ORDER BY u.username,m.user_id LIMIT $2",
                &[&org, &(limit + 1)],
            )
            .await
        }
        // Continuation: the organization scope stays first; the keyset tuple
        // is a parameterized predicate over the last returned row.
        Some((username, user_id)) => {
            tx.query(
                "SELECT u.username,m.user_id,m.role,m.version FROM organization_memberships m \
                 JOIN users u ON u.id=m.user_id \
                 WHERE m.organization_id=$1 AND (u.username,m.user_id) > ($2,$3) \
                 ORDER BY u.username,m.user_id LIMIT $4",
                &[&org, username, user_id, &(limit + 1)],
            )
            .await
        }
    }
    .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let kept: Vec<_> = rows.iter().take(limit as usize).collect();
    let next_cursor = if more {
        kept.last().map(|r| {
            let user_id = r.get::<_, Uuid>(1).to_string();
            pagination::encode(&member_scope(actor.id, org), &[r.get::<_, &str>(0), user_id.as_str()])
        })
    } else {
        None
    };
    let items: Vec<_> = kept
        .iter()
        .map(|r| {
            sjson!({
                "username":r.get::<_,&str>(0),
                "role":r.get::<_,&str>(2),
                "version":r.get::<_,i64>(3)
            })
        })
        .collect();
    auth::finish_tx(tx, &actor, false).await?;
    page_response(items, more, next_cursor, &uri, limit)
}

pub async fn list_teams(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
    Query(query): Query<OrgListQuery>,
    uri: Uri,
    headers: HeaderMap,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let limit = limit_of(&query)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let org = org_id(&tx, &slug).await?;
    auth::authorize_namespace_action(&tx, &actor, org, NamespaceAction::OrgRead).await?;
    require_member(&tx, org, actor.id, Role::Read).await?;
    let cursor = match query.cursor.as_deref() {
        Some(raw) => Some(decode_team_cursor(raw, actor.id, org)?),
        None => None,
    };
    let rows = match &cursor {
        None => {
            tx.query(
                "SELECT id,slug,name,role,version FROM organization_teams \
                 WHERE organization_id=$1 ORDER BY slug,id LIMIT $2",
                &[&org, &(limit + 1)],
            )
            .await
        }
        Some((slug, id)) => {
            tx.query(
                "SELECT id,slug,name,role,version FROM organization_teams \
                 WHERE organization_id=$1 AND (slug,id) > ($2,$3) ORDER BY slug,id LIMIT $4",
                &[&org, slug, id, &(limit + 1)],
            )
            .await
        }
    }
    .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let kept: Vec<_> = rows.iter().take(limit as usize).collect();
    let next_cursor = if more {
        kept.last().map(|r| {
            let id = r.get::<_, Uuid>(0).to_string();
            pagination::encode(&team_scope(actor.id, org), &[r.get::<_, &str>(1), id.as_str()])
        })
    } else {
        None
    };
    let items: Vec<_> = kept
        .iter()
        .map(|r| {
            sjson!({
                "id":r.get::<_,Uuid>(0),
                "slug":r.get::<_,&str>(1),
                "name":r.get::<_,&str>(2),
                "role":r.get::<_,&str>(3),
                "version":r.get::<_,i64>(4)
            })
        })
        .collect();
    auth::finish_tx(tx, &actor, false).await?;
    page_response(items, more, next_cursor, &uri, limit)
}
