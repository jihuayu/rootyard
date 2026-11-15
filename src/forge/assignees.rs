//! Optimistic-versioned Issue and Pull Request assignee management with live RBAC verification.

use super::{
    handlers::{creation_replay, json, positive, record_creation},
    notifications::{NotifySpec, emit_repo_notifications},
};
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish, idempotency_key},
    db::{self, Identity},
    members::{audit, models::Role, rbac},
    pulls::models::repo_tenant_id,
    token_scopes::RepoAction,
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use deadpool_postgres::Transaction;
use serde::{Deserialize, Serialize};
use serde_json::json as sjson;
use std::{collections::HashSet, sync::Arc};
use tokio_postgres::Row;
use uuid::Uuid;

const MAX_ASSIGNEES: usize = 20;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssigneeEntry {
    pub user_id: Uuid,
    pub username: String,
    pub created_at: String,
}

impl AssigneeEntry {
    pub(crate) fn row(row: &Row) -> Self {
        Self {
            user_id: row.get("user_id"),
            username: row.get("username"),
            created_at: row.get("created_at"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssigneeSetInput {
    pub expected_version: i64,
    pub assignees: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssigneeVersionQuery {
    pub expected_version: i64,
}

pub(crate) async fn load_target_assignees(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    target_kind: &str,
    number: i64,
) -> Result<Vec<AssigneeEntry>, Error> {
    let sql = match target_kind {
        "issue" => concat!(
            "SELECT a.assignee_id AS user_id, u.username, a.created_at::text ",
            "FROM forge_issue_assignees a JOIN users u ON u.id=a.assignee_id ",
            "WHERE a.tenant_id=$1 AND a.repository_id=$2 AND a.issue_number=$3 ORDER BY u.username ASC"
        ),
        "pull" => concat!(
            "SELECT a.assignee_id AS user_id, u.username, a.created_at::text ",
            "FROM forge_pull_assignees a JOIN users u ON u.id=a.assignee_id ",
            "WHERE a.tenant_id=$1 AND a.repository_id=$2 AND a.pull_number=$3 ORDER BY u.username ASC"
        ),
        _ => return Err(Error::bad_request()),
    };
    let rows = tx
        .query(sql, &[&tenant_id, &repo_id, &number])
        .await
        .map_err(Error::internal)?;
    Ok(rows.iter().map(AssigneeEntry::row).collect())
}

async fn resolve_member_assignee(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    raw_username: &str,
) -> Result<(Uuid, String), Error> {
    let trimmed = raw_username.trim();
    if !db::valid_name(trimmed) {
        return Err(Error::bad_request());
    }
    let user_row = tx
        .query_opt("SELECT id, username FROM users WHERE lower(username)=lower($1)", &[&trimmed])
        .await
        .map_err(Error::internal)?
        .ok_or(Error(StatusCode::NOT_FOUND, "assignee user not found"))?;
    let uid: Uuid = user_row.get("id");
    let username: String = user_row.get("username");
    if rbac::resolve_effective_role_by_id(tx, repo_id, tenant_id, uid)
        .await?
        .is_none()
    {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "assignee does not hold repository membership or access",
        ));
    }
    Ok((uid, username))
}

pub(crate) async fn apply_target_assignees_tx(
    tx: &Transaction<'_>,
    ids: (Uuid, Uuid),
    actor: &Identity,
    target: (&str, i64),
    replace: bool,
    expected_version: i64,
    raw_usernames: &[String],
) -> Result<(i64, Vec<AssigneeEntry>), Error> {
    let (tenant_id, repo_id) = ids;
    let (target_kind, number) = target;
    positive(number)?;
    positive(expected_version)?;
    if raw_usernames.len() > MAX_ASSIGNEES || (!replace && raw_usernames.is_empty()) {
        return Err(Error::bad_request());
    }
    let (lock_sql, clear_sql, insert_sql, bump_sql, event_kind) = match target_kind {
        "issue" => (
            "SELECT title, assignee_version FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE",
            "DELETE FROM forge_issue_assignees WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3",
            "INSERT INTO forge_issue_assignees (tenant_id,repository_id,issue_number,assignee_id,assigned_by) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            "UPDATE forge_issues SET assignee_version=assignee_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING assignee_version",
            "issue_assigned",
        ),
        "pull" => (
            "SELECT title, assignee_version FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE",
            "DELETE FROM forge_pull_assignees WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3",
            "INSERT INTO forge_pull_assignees (tenant_id,repository_id,pull_number,assignee_id,assigned_by) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            "UPDATE forge_pulls SET assignee_version=assignee_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING assignee_version",
            "pull_assigned",
        ),
        _ => return Err(Error::bad_request()),
    };
    let locked = tx
        .query_opt(lock_sql, &[&tenant_id, &repo_id, &number])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let title: String = locked.get("title");
    let cur_ver: i64 = locked.get("assignee_version");
    if cur_ver != expected_version {
        return Err(Error(StatusCode::CONFLICT, "assignee version conflict"));
    }

    let existing: HashSet<Uuid> = load_target_assignees(tx, tenant_id, repo_id, target_kind, number)
        .await?
        .into_iter()
        .map(|a| a.user_id)
        .collect();

    let mut seen = HashSet::new();
    let mut resolved = Vec::with_capacity(raw_usernames.len());
    let mut added = Vec::new();
    for uname in raw_usernames {
        let (uid, canonical) = resolve_member_assignee(tx, tenant_id, repo_id, uname).await?;
        if seen.insert(uid) {
            if !existing.contains(&uid) {
                added.push(uid);
            }
            resolved.push((uid, canonical));
        }
    }
    if replace {
        tx.execute(clear_sql, &[&tenant_id, &repo_id, &number])
            .await
            .map_err(Error::internal)?;
    }
    for (uid, _) in &resolved {
        tx.execute(insert_sql, &[&tenant_id, &repo_id, &number, uid, &actor.id])
            .await
            .map_err(Error::internal)?;
    }
    let new_ver: i64 = tx
        .query_one(bump_sql, &[&tenant_id, &repo_id, &number])
        .await
        .map_err(Error::internal)?
        .get(0);
    let items = load_target_assignees(tx, tenant_id, repo_id, target_kind, number).await?;
    let names: Vec<&str> = resolved.iter().map(|(_, n)| n.as_str()).collect();
    audit::record_audit_event(
        tx,
        tenant_id,
        repo_id,
        actor,
        &format!("{target_kind}.assignees_updated"),
        target_kind,
        &number.to_string(),
        sjson!({ "replace": replace, "assignees": names, "assignee_version": new_ver }),
    )
    .await?;
    if !added.is_empty() {
        let dkey = format!("{target_kind}:{repo_id}:{number}:assign:v{new_ver}");
        emit_repo_notifications(
            tx,
            NotifySpec {
                tenant_id,
                repository_id: repo_id,
                actor_id: actor.id,
                target_type: target_kind,
                target_number: number,
                thread_type: target_kind,
                thread_number: number,
                event_kind,
                delivery_key: &dkey,
                title: &format!("Assigned {target_kind} #{number}: {title}"),
                body_excerpt: "",
                extra_recipients: &added,
            },
        )
        .await?;
    }
    Ok((new_ver, items))
}

pub(crate) async fn remove_target_assignee_tx(
    tx: &Transaction<'_>,
    ids: (Uuid, Uuid),
    actor: &Identity,
    target: (&str, i64),
    username: &str,
    expected_version: i64,
) -> Result<i64, Error> {
    let (tenant_id, repo_id) = ids;
    let (target_kind, number) = target;
    positive(number)?;
    positive(expected_version)?;
    let trimmed = username.trim();
    if !db::valid_name(trimmed) {
        return Err(Error::bad_request());
    }
    let uid: Uuid = tx
        .query_opt("SELECT id FROM users WHERE lower(username)=lower($1)", &[&trimmed])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0);
    let (lock_sql, del_sql, bump_sql) = match target_kind {
        "issue" => (
            "SELECT assignee_version FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE",
            "DELETE FROM forge_issue_assignees WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND assignee_id=$4",
            "UPDATE forge_issues SET assignee_version=assignee_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING assignee_version",
        ),
        "pull" => (
            "SELECT assignee_version FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE",
            "DELETE FROM forge_pull_assignees WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND assignee_id=$4",
            "UPDATE forge_pulls SET assignee_version=assignee_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING assignee_version",
        ),
        _ => return Err(Error::bad_request()),
    };
    let cur_ver: i64 = tx
        .query_opt(lock_sql, &[&tenant_id, &repo_id, &number])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0);
    if cur_ver != expected_version {
        return Err(Error(StatusCode::CONFLICT, "assignee version conflict"));
    }
    let deleted = tx
        .execute(del_sql, &[&tenant_id, &repo_id, &number, &uid])
        .await
        .map_err(Error::internal)?;
    if deleted == 0 {
        return Err(Error::not_found());
    }
    let new_ver: i64 = tx
        .query_one(bump_sql, &[&tenant_id, &repo_id, &number])
        .await
        .map_err(Error::internal)?
        .get(0);
    audit::record_audit_event(
        tx,
        tenant_id,
        repo_id,
        actor,
        &format!("{target_kind}.assignee_removed"),
        target_kind,
        &number.to_string(),
        sjson!({ "username": trimmed, "assignee_version": new_ver }),
    )
    .await?;
    Ok(new_ver)
}

async fn target_assignees_list(
    state: Arc<AppState>,
    headers: HeaderMap,
    owner: String,
    name: String,
    target_kind: &'static str,
    number: i64,
    action: RepoAction,
) -> Result<Response, Error> {
    positive(number)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, action).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let tbl = if target_kind == "issue" { "forge_issues" } else { "forge_pulls" };
    let assignee_version: i64 = tx
        .query_opt(&format!("SELECT assignee_version FROM {tbl} WHERE tenant_id=$1 AND repository_id=$2 AND number=$3"), &[&tenant_id, &access.repo_id, &number])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0);
    let items = load_target_assignees(&tx, tenant_id, access.repo_id, target_kind, number).await?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "assignee_version": assignee_version, "items": items })))
}

async fn target_assignees_mutate(
    state: Arc<AppState>,
    headers: HeaderMap,
    repo: (String, String),
    target: (&'static str, i64),
    action: RepoAction,
    replace: bool,
    input: AssigneeSetInput,
) -> Result<Response, Error> {
    let (owner, name) = repo;
    let (target_kind, number) = target;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let key = if replace { None } else { idempotency_key(&headers)? };
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Triage, action).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    if let Some(k) = key {
        let req = sjson!({ "operation": format!("{target_kind}_assignees"), "number": number, "expected_version": input.expected_version, "assignees": input.assignees });
        if let Some(saved) = creation_replay(&tx, tenant_id, access.repo_id, k, &req).await? {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::OK, saved));
        }
    }
    let (assignee_version, items) = apply_target_assignees_tx(&tx, (tenant_id, access.repo_id), &actor, (target_kind, number), replace, input.expected_version, &input.assignees).await?;
    let payload = sjson!({ "assignee_version": assignee_version, "items": items });
    record_creation(&tx, tenant_id, access.repo_id, key, &payload).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, payload))
}

async fn target_assignee_remove(
    state: Arc<AppState>,
    headers: HeaderMap,
    repo: (String, String),
    target: (&'static str, i64),
    username: String,
    action: RepoAction,
    expected_version: i64,
) -> Result<Response, Error> {
    let (owner, name) = repo;
    let (target_kind, number) = target;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Triage, action).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let assignee_version = remove_target_assignee_tx(&tx, (tenant_id, access.repo_id), &actor, (target_kind, number), &username, expected_version).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, sjson!({ "deleted": true, "assignee_version": assignee_version })))
}

pub async fn list_issue_assignees(State(s): State<Arc<AppState>>, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap) -> Result<Response, Error> {
    target_assignees_list(s, h, o, n, "issue", num, RepoAction::IssuesRead).await
}
pub async fn set_issue_assignees(State(s): State<Arc<AppState>>, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<AssigneeSetInput>) -> Result<Response, Error> {
    target_assignees_mutate(s, h, (o, n), ("issue", num), RepoAction::IssuesWrite, true, i).await
}
pub async fn add_issue_assignees(State(s): State<Arc<AppState>>, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<AssigneeSetInput>) -> Result<Response, Error> {
    target_assignees_mutate(s, h, (o, n), ("issue", num), RepoAction::IssuesWrite, false, i).await
}
pub async fn remove_issue_assignee(State(s): State<Arc<AppState>>, Path((o, n, num, u)): Path<(String, String, i64, String)>, Query(q): Query<AssigneeVersionQuery>, h: HeaderMap) -> Result<Response, Error> {
    target_assignee_remove(s, h, (o, n), ("issue", num), u, RepoAction::IssuesWrite, q.expected_version).await
}
pub async fn list_pull_assignees(State(s): State<Arc<AppState>>, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap) -> Result<Response, Error> {
    target_assignees_list(s, h, o, n, "pull", num, RepoAction::PullsRead).await
}
pub async fn set_pull_assignees(State(s): State<Arc<AppState>>, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<AssigneeSetInput>) -> Result<Response, Error> {
    target_assignees_mutate(s, h, (o, n), ("pull", num), RepoAction::PullsWrite, true, i).await
}
pub async fn add_pull_assignees(State(s): State<Arc<AppState>>, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<AssigneeSetInput>) -> Result<Response, Error> {
    target_assignees_mutate(s, h, (o, n), ("pull", num), RepoAction::PullsWrite, false, i).await
}
pub async fn remove_pull_assignee(State(s): State<Arc<AppState>>, Path((o, n, num, u)): Path<(String, String, i64, String)>, Query(q): Query<AssigneeVersionQuery>, h: HeaderMap) -> Result<Response, Error> {
    target_assignee_remove(s, h, (o, n), ("pull", num), u, RepoAction::PullsWrite, q.expected_version).await
}
