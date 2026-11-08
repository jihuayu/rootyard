//! Organization administration pages under `/web/organizations`.
//!
//! This is the first vertical slice of issue #87 (organization/member/team web
//! UI). It is deliberately a thin renderer over the existing organization API:
//!
//! - reads resolve the slug, call `authorize_namespace_action(OrgRead)` and read
//!   the direct membership role, exactly like the JSON listing handlers;
//! - every write calls the existing `organizations::handlers` function
//!   (`put_member_atomic`, `delete_member`, `create_team`, `put_team_member`,
//!   `delete_team_member`) with the browser credential normalized by the shared
//!   web helper. There is no HTTP self-call, no duplicated authorization and no
//!   second source of truth for the business rules;
//! - cookie authentication, Origin checks and the CSRF token are enforced by the
//!   existing `/web` middleware before these handlers run. Bearer API callers
//!   keep the documented non-browser contract of the other `/web` routes.
//!
//! Lists use bounded keyset pagination with a cursor bound to
//! `(actor, organization[, team], list kind)`. A cursor is an ordering position,
//! never a capability: every page re-authenticates and re-checks membership.
//! `can_members` / `can_teams` only decide whether actionable HTML is rendered;
//! the API handlers re-authorize the mutation regardless of what was shown.
//!
//! `usage`, `recovery` and `integration` administration UI are not part of this
//! slice; see `docs/organization-web-ui.md` for the explicit partial status.

use crate::{
    AppState, Error, auth,
    db::{self, Identity},
    members::models::Role,
    organizations::handlers as org_handlers,
    pagination,
    token_scopes::{NamespaceAction, ScopeDenial},
    web::handlers::authenticate_web,
    web::org_admin_actions as actions,
    web::org_admin_views as views,
    web::templates::html_response,
};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{get, post},
};
use deadpool_postgres::Transaction;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

type App = State<Arc<AppState>>;
type Res = Result<Response, Error>;

/// Browser-friendly page size. Bounded so a page is always readable and one
/// request can never ask the server to materialize an unbounded list.
const DEFAULT_LIMIT: i64 = 25;
const MAX_LIMIT: i64 = 100;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

fn bad_cursor() -> Error {
    Error(StatusCode::BAD_REQUEST, "invalid pagination cursor")
}

fn org_list_scope(actor: Uuid) -> String {
    format!("web-organizations:{actor}")
}

fn member_scope(actor: Uuid, org: Uuid) -> String {
    format!("web-organization-members:{actor}:{org}")
}

fn team_scope(actor: Uuid, org: Uuid) -> String {
    format!("web-organization-teams:{actor}:{org}")
}

fn team_member_scope(actor: Uuid, org: Uuid, team: Uuid) -> String {
    format!("web-organization-team-members:{actor}:{org}:{team}")
}

fn limit_of(query: &PageQuery) -> Result<i64, Error> {
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(Error::bad_request());
    }
    Ok(limit)
}

fn decode_org_cursor(raw: &str, actor: Uuid) -> Result<(String, Uuid), Error> {
    let fields = pagination::decode(raw, &org_list_scope(actor), 2)?;
    let [slug, id] = fields.as_slice() else {
        return Err(bad_cursor());
    };
    let id = Uuid::parse_str(id).map_err(|_| bad_cursor())?;
    if id.is_nil() || !db::valid_name(slug) {
        return Err(bad_cursor());
    }
    Ok((slug.clone(), id))
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

fn decode_team_member_cursor(
    raw: &str,
    actor: Uuid,
    org: Uuid,
    team: Uuid,
) -> Result<(String, Uuid), Error> {
    let fields = pagination::decode(raw, &team_member_scope(actor, org, team), 2)?;
    let [username, user_id] = fields.as_slice() else {
        return Err(bad_cursor());
    };
    let user_id = Uuid::parse_str(user_id).map_err(|_| bad_cursor())?;
    if user_id.is_nil() || !db::valid_name(username) {
        return Err(bad_cursor());
    }
    Ok((username.clone(), user_id))
}

/// View-only authorization result. The role is the caller's direct membership
/// role; the capability flags additionally require the token scope gate to
/// allow the matching write action (read-only tokens and restricted tokens
/// without the grant are therefore `false`).
struct ReadCtx {
    org: Uuid,
    role: Role,
    can_members: bool,
    can_teams: bool,
}

async fn scope_allows(
    tx: &Transaction<'_>,
    actor: &Identity,
    org: Uuid,
    action: NamespaceAction,
) -> Result<bool, Error> {
    match crate::token_scopes::authorize_namespace_for_request(
        tx,
        actor.token_id,
        actor.id,
        org,
        action,
        auth::web_scope_enabled(),
    )
    .await
    {
        Ok(()) => Ok(true),
        Err(ScopeDenial::Forbidden) => Ok(false),
        Err(ScopeDenial::InvalidToken) => Err(Error::unauthorized()),
        Err(ScopeDenial::Unavailable) => Err(Error::internal("token scope store unavailable")),
    }
}

async fn read_ctx(tx: &Transaction<'_>, actor: &Identity, slug: &str) -> Result<ReadCtx, Error> {
    let org = org_handlers::org_id(tx, slug).await?;
    auth::authorize_namespace_action(tx, actor, org, NamespaceAction::OrgRead).await?;
    let role = org_handlers::member_role(tx, org, actor.id).await?;
    let (mut can_members, mut can_teams) = (false, false);
    if role >= Role::Admin {
        can_members = scope_allows(tx, actor, org, NamespaceAction::OrgMembersWrite).await?;
        can_teams = scope_allows(tx, actor, org, NamespaceAction::OrgTeamsWrite).await?;
    }
    Ok(ReadCtx { org, role, can_members, can_teams })
}

fn page_ctx(slug: &str, actor: &Identity, ctx: &ReadCtx) -> views::PageCtx {
    views::PageCtx {
        slug: slug.to_owned(),
        role: ctx.role.as_str().to_owned(),
        actor: actor.username.clone(),
        can_members: ctx.can_members,
        can_teams: ctx.can_teams,
    }
}

pub async fn organizations_page(
    State(state): App,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Res {
    let actor = authenticate_web(&state.pool, &headers).await?;
    let limit = limit_of(&query)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let cursor = match query.cursor.as_deref() {
        Some(raw) => Some(decode_org_cursor(raw, actor.id)?),
        None => None,
    };
    // A restricted token sees only organizations for which it holds org:read;
    // an unrestricted token keeps the historical account-wide membership list.
    let restricted = auth::token_is_restricted(&tx, &actor).await?;
    let rows = match &cursor {
        None => {
            tx.query(
                "SELECT o.id, ns.slug, m.role FROM organization_memberships m \
                 JOIN organizations o ON o.id=m.organization_id \
                 JOIN namespaces ns ON ns.organization_id=o.id AND ns.kind='organization' \
                 WHERE m.user_id=$1 AND (NOT $2 OR EXISTS (\
                     SELECT 1 FROM token_namespace_scopes s \
                      WHERE s.token_id=$3 AND s.organization_id=o.id AND s.action='org:read')) \
                 ORDER BY ns.slug, o.id LIMIT $4",
                &[&actor.id, &restricted, &actor.token_id, &(limit + 1)],
            )
            .await
        }
        Some((slug, id)) => {
            tx.query(
                "SELECT o.id, ns.slug, m.role FROM organization_memberships m \
                 JOIN organizations o ON o.id=m.organization_id \
                 JOIN namespaces ns ON ns.organization_id=o.id AND ns.kind='organization' \
                 WHERE m.user_id=$1 AND (NOT $2 OR EXISTS (\
                     SELECT 1 FROM token_namespace_scopes s \
                      WHERE s.token_id=$3 AND s.organization_id=o.id AND s.action='org:read')) \
                   AND (ns.slug, o.id) > ($4, $5) \
                 ORDER BY ns.slug, o.id LIMIT $6",
                &[&actor.id, &restricted, &actor.token_id, slug, id, &(limit + 1)],
            )
            .await
        }
    }
    .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let kept: Vec<_> = rows.iter().take(limit as usize).collect();
    let next_cursor = if more {
        kept.last().map(|row| {
            let id = row.get::<_, Uuid>(0).to_string();
            pagination::encode(&org_list_scope(actor.id), &[row.get::<_, &str>(1), id.as_str()])
        })
    } else {
        None
    };
    let items: Vec<_> = kept
        .iter()
        .map(|row| views::OrgRow {
            slug: row.get::<_, &str>(1).to_owned(),
            role: row.get::<_, &str>(2).to_owned(),
        })
        .collect();
    auth::finish_tx(tx, &actor, false).await?;
    let ctx = views::PageCtx {
        slug: String::new(),
        role: "member".to_owned(),
        actor: actor.username.clone(),
        can_members: false,
        can_teams: false,
    };
    Ok(html_response(
        StatusCode::OK,
        views::render_organizations(&ctx, &items, limit, next_cursor.as_deref()),
    ))
}

pub async fn organization_overview(
    State(state): App,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Res {
    let actor = authenticate_web(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let ctx = read_ctx(&tx, &actor, &slug).await?;
    let row = tx
        .query_one("SELECT version, created_at::text FROM organizations WHERE id=$1", &[&ctx.org])
        .await
        .map_err(Error::internal)?;
    let counts = tx
        .query_one(
            "SELECT (SELECT count(*) FROM organization_memberships WHERE organization_id=$1), \
                    (SELECT count(*) FROM organization_teams WHERE organization_id=$1), \
                    (SELECT count(*) FROM organization_audit_log WHERE organization_id=$1)",
            &[&ctx.org],
        )
        .await
        .map_err(Error::internal)?;
    auth::finish_tx(tx, &actor, false).await?;
    let overview = views::Overview {
        version: row.get(0),
        created_at: row.get(1),
        members: counts.get(0),
        teams: counts.get(1),
        audit_entries: counts.get(2),
    };
    let page = page_ctx(&slug, &actor, &ctx);
    Ok(html_response(StatusCode::OK, views::render_overview(&page, &overview)))
}

pub async fn members_page(
    State(state): App,
    Path(slug): Path<String>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Res {
    let actor = authenticate_web(&state.pool, &headers).await?;
    let limit = limit_of(&query)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let ctx = read_ctx(&tx, &actor, &slug).await?;
    let cursor = match query.cursor.as_deref() {
        Some(raw) => Some(decode_member_cursor(raw, actor.id, ctx.org)?),
        None => None,
    };
    let rows = match &cursor {
        None => {
            tx.query(
                "SELECT u.username, m.user_id, m.role, m.version \
                 FROM organization_memberships m JOIN users u ON u.id=m.user_id \
                 WHERE m.organization_id=$1 ORDER BY u.username, m.user_id LIMIT $2",
                &[&ctx.org, &(limit + 1)],
            )
            .await
        }
        Some((username, user_id)) => {
            tx.query(
                "SELECT u.username, m.user_id, m.role, m.version \
                 FROM organization_memberships m JOIN users u ON u.id=m.user_id \
                 WHERE m.organization_id=$1 AND (u.username, m.user_id) > ($2, $3) \
                 ORDER BY u.username, m.user_id LIMIT $4",
                &[&ctx.org, username, user_id, &(limit + 1)],
            )
            .await
        }
    }
    .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let kept: Vec<_> = rows.iter().take(limit as usize).collect();
    let next_cursor = if more {
        kept.last().map(|row| {
            let user_id = row.get::<_, Uuid>(1).to_string();
            pagination::encode(
                &member_scope(actor.id, ctx.org),
                &[row.get::<_, &str>(0), user_id.as_str()],
            )
        })
    } else {
        None
    };
    let items: Vec<_> = kept
        .iter()
        .map(|row| views::MemberRow {
            username: row.get::<_, &str>(0).to_owned(),
            role: row.get::<_, &str>(2).to_owned(),
            version: row.get(3),
        })
        .collect();
    let page = page_ctx(&slug, &actor, &ctx);
    auth::finish_tx(tx, &actor, false).await?;
    Ok(html_response(
        StatusCode::OK,
        views::render_members(&page, &items, limit, next_cursor.as_deref()),
    ))
}

pub async fn teams_page(
    State(state): App,
    Path(slug): Path<String>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Res {
    let actor = authenticate_web(&state.pool, &headers).await?;
    let limit = limit_of(&query)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let ctx = read_ctx(&tx, &actor, &slug).await?;
    let cursor = match query.cursor.as_deref() {
        Some(raw) => Some(decode_team_cursor(raw, actor.id, ctx.org)?),
        None => None,
    };
    let rows = match &cursor {
        None => {
            tx.query(
                "SELECT t.id, t.slug, t.name, t.role, t.version, \
                        (SELECT count(*) FROM organization_team_members tm WHERE tm.team_id=t.id) \
                 FROM organization_teams t WHERE t.organization_id=$1 \
                 ORDER BY t.slug, t.id LIMIT $2",
                &[&ctx.org, &(limit + 1)],
            )
            .await
        }
        Some((team_slug, team_id)) => {
            tx.query(
                "SELECT t.id, t.slug, t.name, t.role, t.version, \
                        (SELECT count(*) FROM organization_team_members tm WHERE tm.team_id=t.id) \
                 FROM organization_teams t WHERE t.organization_id=$1 AND (t.slug, t.id) > ($2, $3) \
                 ORDER BY t.slug, t.id LIMIT $4",
                &[&ctx.org, team_slug, team_id, &(limit + 1)],
            )
            .await
        }
    }
    .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let kept: Vec<_> = rows.iter().take(limit as usize).collect();
    let next_cursor = if more {
        kept.last().map(|row| {
            let id = row.get::<_, Uuid>(0).to_string();
            pagination::encode(&team_scope(actor.id, ctx.org), &[row.get::<_, &str>(1), id.as_str()])
        })
    } else {
        None
    };
    let items: Vec<_> = kept
        .iter()
        .map(|row| views::TeamRow {
            slug: row.get::<_, &str>(1).to_owned(),
            name: row.get::<_, &str>(2).to_owned(),
            role: row.get::<_, &str>(3).to_owned(),
            version: row.get(4),
            members: row.get(5),
        })
        .collect();
    let page = page_ctx(&slug, &actor, &ctx);
    auth::finish_tx(tx, &actor, false).await?;
    Ok(html_response(
        StatusCode::OK,
        views::render_teams(&page, &items, limit, next_cursor.as_deref()),
    ))
}

pub async fn team_page(
    State(state): App,
    Path((slug, team_slug)): Path<(String, String)>,
    Query(query): Query<PageQuery>,
    headers: HeaderMap,
) -> Res {
    let actor = authenticate_web(&state.pool, &headers).await?;
    let limit = limit_of(&query)?;
    if !db::valid_name(&team_slug) {
        return Err(Error::not_found());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let ctx = read_ctx(&tx, &actor, &slug).await?;
    let row = tx
        .query_opt(
            "SELECT id, name, role, version FROM organization_teams \
             WHERE organization_id=$1 AND slug=$2",
            &[&ctx.org, &team_slug],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let team = views::TeamRow {
        slug: team_slug.clone(),
        name: row.get(1),
        role: row.get(2),
        version: row.get(3),
        members: 0,
    };
    let team_id: Uuid = row.get(0);
    let cursor = match query.cursor.as_deref() {
        Some(raw) => Some(decode_team_member_cursor(raw, actor.id, ctx.org, team_id)?),
        None => None,
    };
    let rows = match &cursor {
        None => {
            tx.query(
                "SELECT u.username, tm.user_id, m.role \
                 FROM organization_team_members tm \
                 JOIN users u ON u.id=tm.user_id \
                 LEFT JOIN organization_memberships m \
                   ON m.organization_id=tm.organization_id AND m.user_id=tm.user_id \
                 WHERE tm.team_id=$1 AND tm.organization_id=$2 \
                 ORDER BY u.username, tm.user_id LIMIT $3",
                &[&team_id, &ctx.org, &(limit + 1)],
            )
            .await
        }
        Some((username, user_id)) => {
            tx.query(
                "SELECT u.username, tm.user_id, m.role \
                 FROM organization_team_members tm \
                 JOIN users u ON u.id=tm.user_id \
                 LEFT JOIN organization_memberships m \
                   ON m.organization_id=tm.organization_id AND m.user_id=tm.user_id \
                 WHERE tm.team_id=$1 AND tm.organization_id=$2 \
                   AND (u.username, tm.user_id) > ($3, $4) \
                 ORDER BY u.username, tm.user_id LIMIT $5",
                &[&team_id, &ctx.org, username, user_id, &(limit + 1)],
            )
            .await
        }
    }
    .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let kept: Vec<_> = rows.iter().take(limit as usize).collect();
    let next_cursor = if more {
        kept.last().map(|row| {
            let user_id = row.get::<_, Uuid>(1).to_string();
            pagination::encode(
                &team_member_scope(actor.id, ctx.org, team_id),
                &[row.get::<_, &str>(0), user_id.as_str()],
            )
        })
    } else {
        None
    };
    let items: Vec<_> = kept
        .iter()
        .map(|row| views::TeamMemberRow {
            username: row.get::<_, &str>(0).to_owned(),
            role: row.get::<_, Option<String>>(2),
        })
        .collect();
    let page = page_ctx(&slug, &actor, &ctx);
    auth::finish_tx(tx, &actor, false).await?;
    Ok(html_response(
        StatusCode::OK,
        views::render_team(&page, &team, &items, limit, next_cursor.as_deref()),
    ))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/web/organizations", get(organizations_page))
        .route("/web/organizations/{slug}", get(organization_overview))
        .route(
            "/web/organizations/{slug}/members",
            get(members_page).post(actions::member_set),
        )
        .route(
            "/web/organizations/{slug}/members/{username}/remove",
            post(actions::member_remove),
        )
        .route("/web/organizations/{slug}/teams", get(teams_page).post(actions::team_create))
        .route("/web/organizations/{slug}/teams/{team}", get(team_page))
        .route("/web/organizations/{slug}/teams/{team}/members", post(actions::team_member_add))
        .route(
            "/web/organizations/{slug}/teams/{team}/members/{username}/remove",
            post(actions::team_member_remove),
        )
}
