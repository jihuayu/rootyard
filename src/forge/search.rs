//! Authorized cross-repository and repository-scoped Forge search (`/api/search`).
//!
//! Enforces live RBAC visibility and restricted-PAT action grants per item kind inside
//! a single PostgreSQL transaction, excludes soft-deleted/moderated comments, and binds
//! deterministic total ordering to opaque scoped keyset cursors.

use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish},
    db::{self, Identity},
    forge::notifications::{REPO_VISIBILITY_SQL, sanitize_single_line},
    members::models::Role,
    pagination,
    token_scopes::RepoAction,
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

const SEARCH_CURSOR_SCOPE: &str = "forge-search:v1";
const DEFAULT_LIMIT: i64 = 25;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchScope {
    All,
    Repositories,
    Issues,
    Pulls,
    Comments,
}

impl SearchScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Repositories => "repositories",
            Self::Issues => "issues",
            Self::Pulls => "pulls",
            Self::Comments => "comments",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchSort {
    Updated,
    Number,
}

impl SearchSort {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Updated => "updated",
            Self::Number => "number",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchQuery {
    pub q: String,
    pub scope: Option<SearchScope>,
    pub sort: Option<SearchSort>,
    pub cursor: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SearchHit {
    pub kind: String,
    pub repository_id: Uuid,
    pub owner: String,
    pub repo: String,
    pub number: i64,
    pub comment_number: i64,
    pub state: Option<String>,
    pub title: String,
    pub excerpt: String,
    pub updated_at: String,
}

fn json(status: StatusCode, value: impl Serialize) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}

pub(crate) fn validate_search_query(query: &SearchQuery) -> Result<(String, SearchScope, SearchSort, i64), Error> {
    let trimmed = query.q.trim();
    if trimmed.is_empty() || trimmed.len() > 128 || trimmed.chars().any(char::is_control) {
        return Err(Error::bad_request());
    }
    let scope = query.scope.unwrap_or(SearchScope::All);
    let sort = query.sort.unwrap_or(SearchSort::Updated);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=100).contains(&limit) {
        return Err(Error::bad_request());
    }
    Ok((trimmed.to_owned(), scope, sort, limit))
}

fn valid_cursor_ts(raw: &str) -> bool {
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

fn cursor_scope(
    actor_id: Uuid,
    restricted: bool,
    repo_id: Option<Uuid>,
    q: &str,
    scope: SearchScope,
    sort: SearchSort,
) -> String {
    let target = repo_id.map_or_else(|| "global".to_owned(), |id| id.to_string());
    format!(
        "{SEARCH_CURSOR_SCOPE}:{actor_id}:{restricted}:{target}:{}:{}:{}",
        scope.as_str(),
        sort.as_str(),
        hex::encode(q.as_bytes()),
    )
}

pub(crate) async fn execute_search(
    tx: &Transaction<'_>,
    actor: &Identity,
    target_repo_id: Option<Uuid>,
    query: &SearchQuery,
) -> Result<(Vec<SearchHit>, Option<String>), Error> {
    let (needle, scope, sort, limit) = validate_search_query(query)?;
    let restricted = auth::token_is_restricted(tx, actor).await?;
    let c_scope = cursor_scope(actor.id, restricted, target_repo_id, &needle, scope, sort);
    let (c_ts, c_owner, c_repo, c_kind, c_num, c_sub) = match query.cursor.as_deref() {
        Some(raw) => {
            let parts = pagination::decode(raw, &c_scope, 6)?;
            if !valid_cursor_ts(&parts[0]) || !db::valid_name(&parts[1]) || !db::valid_name(&parts[2]) {
                return Err(Error(StatusCode::BAD_REQUEST, "invalid pagination cursor"));
            }
            let num: i64 = parts[4].parse().map_err(|_| Error(StatusCode::BAD_REQUEST, "invalid pagination cursor"))?;
            let sub: i64 = parts[5].parse().map_err(|_| Error(StatusCode::BAD_REQUEST, "invalid pagination cursor"))?;
            (
                Some(parts[0].clone()),
                Some(parts[1].clone()),
                Some(parts[2].clone()),
                Some(parts[3].clone()),
                Some(num),
                Some(sub),
            )
        }
        None => (None, None, None, None, None, None),
    };

    let vis = REPO_VISIBILITY_SQL.replace("$USER", "$1");
    let scope_cond = |action: &'static str| -> String {
        if restricted {
            format!("AND EXISTS (SELECT 1 FROM token_repository_scopes ts WHERE ts.token_id=$2 AND ts.repository_id=r.id AND ts.action='{action}')")
        } else {
            String::new()
        }
    };
    let s_repo = scope_cond("repo_read");
    let s_issue = scope_cond("issues_read");
    let s_pull = scope_cond("pulls_read");

    let mut branches = Vec::new();
    if matches!(scope, SearchScope::All | SearchScope::Repositories) {
        branches.push(format!(
            "SELECT 'repository'::text AS kind, r.id AS repository_id, ns.slug AS owner, r.name AS repo, 0::bigint AS number, 0::bigint AS comment_number, r.state AS state, (ns.slug || '/' || r.name) AS title, r.state AS raw_excerpt, r.created_at AS sort_ts, r.created_at::text AS updated_at \
             FROM auth_repos ar JOIN repositories r ON r.id=ar.id JOIN namespaces ns ON ns.id=r.owner_id \
             WHERE strpos(lower(ns.slug || '/' || r.name), lower($4)) > 0 {s_repo}"
        ));
    }
    if matches!(scope, SearchScope::All | SearchScope::Issues) {
        branches.push(format!(
            "SELECT 'issue'::text AS kind, r.id AS repository_id, ns.slug AS owner, r.name AS repo, i.number, 0::bigint AS comment_number, i.state, i.title, i.body AS raw_excerpt, i.updated_at AS sort_ts, i.updated_at::text AS updated_at \
             FROM auth_repos ar JOIN repositories r ON r.id=ar.id JOIN namespaces ns ON ns.id=r.owner_id \
             JOIN forge_issues i ON i.tenant_id=r.owner_id AND i.repository_id=r.id \
             WHERE (strpos(lower(i.title), lower($4)) > 0 OR strpos(lower(i.body), lower($4)) > 0) {s_issue}"
        ));
    }
    if matches!(scope, SearchScope::All | SearchScope::Pulls) {
        branches.push(format!(
            "SELECT 'pull'::text AS kind, r.id AS repository_id, ns.slug AS owner, r.name AS repo, p.number, 0::bigint AS comment_number, p.state, p.title, p.body AS raw_excerpt, p.updated_at AS sort_ts, p.updated_at::text AS updated_at \
             FROM auth_repos ar JOIN repositories r ON r.id=ar.id JOIN namespaces ns ON ns.id=r.owner_id \
             JOIN forge_pulls p ON p.tenant_id=r.owner_id AND p.repository_id=r.id \
             WHERE (strpos(lower(p.title), lower($4)) > 0 OR strpos(lower(p.body), lower($4)) > 0) {s_pull}"
        ));
    }
    if matches!(scope, SearchScope::All | SearchScope::Comments) {
        branches.push(format!(
            "SELECT 'issue_comment'::text AS kind, r.id AS repository_id, ns.slug AS owner, r.name AS repo, c.issue_number AS number, c.number AS comment_number, c.moderation_state AS state, ('#' || c.issue_number::text || ' comment #' || c.number::text) AS title, c.body AS raw_excerpt, c.updated_at AS sort_ts, c.updated_at::text AS updated_at \
             FROM auth_repos ar JOIN repositories r ON r.id=ar.id JOIN namespaces ns ON ns.id=r.owner_id \
             JOIN forge_issue_comments c ON c.tenant_id=r.owner_id AND c.repository_id=r.id \
             WHERE c.moderation_state='visible' AND c.deleted_at IS NULL AND strpos(lower(c.body), lower($4)) > 0 {s_issue}"
        ));
        branches.push(format!(
            "SELECT 'pull_review_comment'::text AS kind, r.id AS repository_id, ns.slug AS owner, r.name AS repo, rc.pull_number AS number, rc.number AS comment_number, (CASE WHEN rc.commit_oid=p.head_oid AND rc.base_oid=p.base_oid THEN 'active' ELSE 'outdated' END) AS state, (rc.path || ':' || rc.line::text) AS title, rc.body AS raw_excerpt, rc.updated_at AS sort_ts, rc.updated_at::text AS updated_at \
             FROM auth_repos ar JOIN repositories r ON r.id=ar.id JOIN namespaces ns ON ns.id=r.owner_id \
             JOIN forge_pull_review_comments rc ON rc.tenant_id=r.owner_id AND rc.repository_id=r.id \
             JOIN forge_pulls p ON p.tenant_id=rc.tenant_id AND p.repository_id=rc.repository_id AND p.number=rc.pull_number \
             WHERE rc.moderation_state='visible' AND rc.deleted_at IS NULL AND (strpos(lower(rc.body), lower($4)) > 0 OR strpos(lower(rc.path), lower($4)) > 0) {s_pull}"
        ));
    }

    let union_sql = branches.join(" UNION ALL ");
    let (cursor_pred, order_by) = match sort {
        SearchSort::Updated => (
            "($5::text IS NULL OR ((u.sort_ts < $5::text::timestamptz) OR (u.sort_ts = $5::text::timestamptz AND (u.owner,u.repo,u.kind,u.number,u.comment_number) > ($6::text,$7::text,$8::text,$9::bigint,$10::bigint))))",
            "u.sort_ts DESC, u.owner ASC, u.repo ASC, u.kind ASC, u.number ASC, u.comment_number ASC",
        ),
        SearchSort::Number => (
            "($5::text IS NULL OR ((u.number < $9::bigint) OR (u.number = $9::bigint AND (u.owner,u.repo,u.kind,u.comment_number) > ($6::text,$7::text,$8::text,$10::bigint))))",
            "u.number DESC, u.owner ASC, u.repo ASC, u.kind ASC, u.comment_number ASC",
        ),
    };

    let sql = format!(
        "WITH auth_repos AS (SELECT r.id FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id WHERE ({vis}) AND $2::uuid IS NOT NULL AND ($3::uuid IS NULL OR r.id=$3)), \
         unioned AS ({union_sql}) \
         SELECT u.kind,u.repository_id,u.owner,u.repo,u.number,u.comment_number,u.state,u.title,u.raw_excerpt,u.updated_at,to_char(u.sort_ts AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS cursor_ts \
         FROM unioned u WHERE {cursor_pred} ORDER BY {order_by} LIMIT $11"
    );
    let rows = tx
        .query(
            &sql,
            &[
                &actor.id,
                // Browser children read the live grants stored under their parent API token.
                &actor.scope_token_id(),
                &target_repo_id,
                &needle,
                &c_ts,
                &c_owner,
                &c_repo,
                &c_kind,
                &c_num,
                &c_sub,
                &(limit + 1),
            ],
        )
        .await
        .map_err(Error::internal)?;

    let more = rows.len() > limit as usize;
    let items: Vec<SearchHit> = rows
        .iter()
        .take(limit as usize)
        .map(|row| SearchHit {
            kind: row.get("kind"),
            repository_id: row.get("repository_id"),
            owner: row.get("owner"),
            repo: row.get("repo"),
            number: row.get("number"),
            comment_number: row.get("comment_number"),
            state: row.get("state"),
            title: row.get("title"),
            excerpt: sanitize_single_line(row.get::<_, &str>("raw_excerpt"), 200, ""),
            updated_at: row.get("updated_at"),
        })
        .collect();
    let next_cursor = if more {
        rows.get(limit as usize - 1).map(|row| {
            let ts: String = row.get("cursor_ts");
            let owner: String = row.get("owner");
            let repo: String = row.get("repo");
            let kind: String = row.get("kind");
            let num = row.get::<_, i64>("number").to_string();
            let sub = row.get::<_, i64>("comment_number").to_string();
            pagination::encode(
                &c_scope,
                &[ts.as_str(), owner.as_str(), repo.as_str(), kind.as_str(), num.as_str(), sub.as_str()],
            )
        })
    } else {
        None
    };
    Ok((items, next_cursor))
}

pub async fn search_global(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SearchQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let (_, scope, sort, _) = validate_search_query(&query)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, false).await?;
    let (items, next_cursor) = execute_search(&tx, &actor, None, &query).await?;
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "scope": scope.as_str(), "sort": sort.as_str(), "items": items, "next_cursor": next_cursor }),
    ))
}

pub async fn search_repo(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<SearchQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let (_, scope, sort, _) = validate_search_query(&query)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = match scope {
        SearchScope::Issues => auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, RepoAction::IssuesRead).await?,
        SearchScope::Pulls => auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, RepoAction::PullsRead).await?,
        SearchScope::Comments => {
            match auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, RepoAction::IssuesRead).await {
                Ok(a) => a,
                Err(_) => auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, RepoAction::PullsRead).await?,
            }
        }
        SearchScope::Repositories | SearchScope::All => {
            auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, RepoAction::RepoRead).await?
        }
    };
    let (items, next_cursor) = execute_search(&tx, &actor, Some(access.repo_id), &query).await?;
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "scope": scope.as_str(), "sort": sort.as_str(), "items": items, "next_cursor": next_cursor }),
    ))
}
