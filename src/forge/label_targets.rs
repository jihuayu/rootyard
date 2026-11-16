//! Issue and Pull Request label attachment handlers with optimistic concurrency (`label_version`).

use super::{
    handlers::{creation_replay, json, positive, record_creation},
    labels::{
        LabelAttachmentInput, LabelVersionQuery, RepoLabel, dedupe_labels, load_target_labels,
        normalize_label_name,
    },
};
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish, idempotency_key},
    db::Identity,
    members::{audit, models::Role},
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
use serde_json::json as sjson;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) async fn apply_target_labels_tx(
    tx: &Transaction<'_>,
    ids: (Uuid, Uuid),
    actor: &Identity,
    target: (&str, i64),
    replace: bool,
    expected_version: i64,
    raw_labels: &[String],
) -> Result<(i64, Vec<RepoLabel>), Error> {
    let (tenant_id, repo_id) = ids;
    let (target_kind, number) = target;
    positive(number)?;
    positive(expected_version)?;
    let labels = dedupe_labels(raw_labels)?;
    if !replace && labels.is_empty() {
        return Err(Error::bad_request());
    }
    let (lock_sql, clear_sql, insert_sql, bump_sql) = match target_kind {
        "issue" => (
            "SELECT label_version FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE",
            "DELETE FROM forge_issue_labels WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3",
            "INSERT INTO forge_issue_labels (tenant_id,repository_id,issue_number,label_name,added_by) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            "UPDATE forge_issues SET label_version=label_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING label_version",
        ),
        "pull" => (
            "SELECT label_version FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE",
            "DELETE FROM forge_pull_labels WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3",
            "INSERT INTO forge_pull_labels (tenant_id,repository_id,pull_number,label_name,added_by) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
            "UPDATE forge_pulls SET label_version=label_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING label_version",
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
        return Err(Error(StatusCode::CONFLICT, "label version conflict"));
    }
    for lname in &labels {
        tx.query_opt(
            "SELECT 1 FROM forge_labels WHERE tenant_id=$1 AND repository_id=$2 AND name=$3 FOR SHARE",
            &[&tenant_id, &repo_id, lname],
        )
        .await
        .map_err(Error::internal)?
        .ok_or(Error(StatusCode::NOT_FOUND, "label not found"))?;
    }
    if replace {
        tx.execute(clear_sql, &[&tenant_id, &repo_id, &number])
            .await
            .map_err(Error::internal)?;
    }
    for lname in &labels {
        tx.execute(insert_sql, &[&tenant_id, &repo_id, &number, lname, &actor.id])
            .await
            .map_err(Error::internal)?;
    }
    let new_ver: i64 = tx
        .query_one(bump_sql, &[&tenant_id, &repo_id, &number])
        .await
        .map_err(Error::internal)?
        .get(0);
    let attached = load_target_labels(tx, tenant_id, repo_id, target_kind, number).await?;
    audit::record_audit_event(
        tx,
        tenant_id,
        repo_id,
        actor,
        &format!("{target_kind}.labels_updated"),
        target_kind,
        &number.to_string(),
        sjson!({ "replace": replace, "labels": labels, "label_version": new_ver }),
    )
    .await?;
    Ok((new_ver, attached))
}

pub(crate) async fn remove_target_label_tx(
    tx: &Transaction<'_>,
    ids: (Uuid, Uuid),
    actor: &Identity,
    target: (&str, i64),
    raw_label: &str,
    expected_version: i64,
) -> Result<i64, Error> {
    let (tenant_id, repo_id) = ids;
    let (target_kind, number) = target;
    positive(number)?;
    positive(expected_version)?;
    let label = normalize_label_name(raw_label)?;
    let (lock_sql, del_sql, bump_sql) = match target_kind {
        "issue" => (
            "SELECT label_version FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE",
            "DELETE FROM forge_issue_labels WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND label_name=$4",
            "UPDATE forge_issues SET label_version=label_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING label_version",
        ),
        "pull" => (
            "SELECT label_version FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE",
            "DELETE FROM forge_pull_labels WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND label_name=$4",
            "UPDATE forge_pulls SET label_version=label_version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING label_version",
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
        return Err(Error(StatusCode::CONFLICT, "label version conflict"));
    }
    let deleted = tx
        .execute(del_sql, &[&tenant_id, &repo_id, &number, &label])
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
        &format!("{target_kind}.label_removed"),
        target_kind,
        &number.to_string(),
        sjson!({ "label": label, "label_version": new_ver }),
    )
    .await?;
    Ok(new_ver)
}

async fn target_labels_list(
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
    let label_version: i64 = tx
        .query_opt(&format!("SELECT label_version FROM {tbl} WHERE tenant_id=$1 AND repository_id=$2 AND number=$3"), &[&tenant_id, &access.repo_id, &number])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0);
    let items = load_target_labels(&tx, tenant_id, access.repo_id, target_kind, number).await?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "label_version": label_version, "items": items })))
}

async fn target_labels_mutate(
    state: Arc<AppState>,
    headers: HeaderMap,
    repo: (String, String),
    target: (&'static str, i64),
    action: RepoAction,
    replace: bool,
    input: LabelAttachmentInput,
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
        let req = sjson!({ "operation": format!("{target_kind}_labels"), "number": number, "expected_version": input.expected_version, "labels": input.labels });
        if let Some(saved) = creation_replay(&tx, tenant_id, access.repo_id, k, &req).await? {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::OK, saved));
        }
    }
    let (label_version, items) = apply_target_labels_tx(&tx, (tenant_id, access.repo_id), &actor, (target_kind, number), replace, input.expected_version, &input.labels).await?;
    let payload = sjson!({ "label_version": label_version, "items": items });
    record_creation(&tx, tenant_id, access.repo_id, key, &payload).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, payload))
}

async fn target_label_remove(
    state: Arc<AppState>,
    headers: HeaderMap,
    repo: (String, String),
    target: (&'static str, i64),
    label: String,
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
    let label_version = remove_target_label_tx(&tx, (tenant_id, access.repo_id), &actor, (target_kind, number), &label, expected_version).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, sjson!({ "deleted": true, "label_version": label_version })))
}

pub async fn list_issue_labels(State(s): State<Arc<AppState>>, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap) -> Result<Response, Error> {
    target_labels_list(s, h, o, n, "issue", num, RepoAction::IssuesRead).await
}
pub async fn set_issue_labels(State(s): State<Arc<AppState>>, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<LabelAttachmentInput>) -> Result<Response, Error> {
    target_labels_mutate(s, h, (o, n), ("issue", num), RepoAction::IssuesWrite, true, i).await
}
pub async fn add_issue_labels(State(s): State<Arc<AppState>>, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<LabelAttachmentInput>) -> Result<Response, Error> {
    target_labels_mutate(s, h, (o, n), ("issue", num), RepoAction::IssuesWrite, false, i).await
}
pub async fn remove_issue_label(State(s): State<Arc<AppState>>, Path((o, n, num, l)): Path<(String, String, i64, String)>, Query(q): Query<LabelVersionQuery>, h: HeaderMap) -> Result<Response, Error> {
    target_label_remove(s, h, (o, n), ("issue", num), l, RepoAction::IssuesWrite, q.expected_version).await
}
pub async fn list_pull_labels(State(s): State<Arc<AppState>>, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap) -> Result<Response, Error> {
    target_labels_list(s, h, o, n, "pull", num, RepoAction::PullsRead).await
}
pub async fn set_pull_labels(State(s): State<Arc<AppState>>, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<LabelAttachmentInput>) -> Result<Response, Error> {
    target_labels_mutate(s, h, (o, n), ("pull", num), RepoAction::PullsWrite, true, i).await
}
pub async fn add_pull_labels(State(s): State<Arc<AppState>>, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<LabelAttachmentInput>) -> Result<Response, Error> {
    target_labels_mutate(s, h, (o, n), ("pull", num), RepoAction::PullsWrite, false, i).await
}
pub async fn remove_pull_label(State(s): State<Arc<AppState>>, Path((o, n, num, l)): Path<(String, String, i64, String)>, Query(q): Query<LabelVersionQuery>, h: HeaderMap) -> Result<Response, Error> {
    target_label_remove(s, h, (o, n), ("pull", num), l, RepoAction::PullsWrite, q.expected_version).await
}
