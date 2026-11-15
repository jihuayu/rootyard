//! Repository label definitions and optimistic-versioned Issue/PR label attachments.

use super::handlers::{creation_replay, json, positive, record_creation};
use crate::{
    AppState, Error,
    auth::{self, RepoAccess, finish_tx as finish, idempotency_key},
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
use serde::{Deserialize, Serialize};
use serde_json::json as sjson;
use std::{collections::HashSet, sync::Arc};
use tokio_postgres::Row;
use uuid::Uuid;

const LABEL_FIELDS: &str = "repository_id,name,color,description,version,created_at::text,updated_at::text";
const MAX_ATTACHED_LABELS: usize = 50;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoLabel {
    pub repository_id: Uuid,
    pub name: String,
    pub color: String,
    pub description: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl RepoLabel {
    pub(crate) fn row(row: &Row) -> Self {
        Self {
            repository_id: row.get("repository_id"),
            name: row.get("name"),
            color: row.get("color"),
            description: row.get("description"),
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewLabel {
    pub name: String,
    pub color: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchLabel {
    pub expected_version: i64,
    pub name: Option<String>,
    pub color: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelVersionQuery {
    pub expected_version: i64,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelListQuery {
    pub after: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelAttachmentInput {
    pub expected_version: i64,
    pub labels: Vec<String>,
}

pub(crate) fn normalize_label_name(raw: &str) -> Result<String, Error> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed != raw
        || raw.len() > 64
        || raw.chars().any(char::is_control)
    {
        return Err(Error::bad_request());
    }
    Ok(trimmed.to_owned())
}

pub(crate) fn normalize_label_color(raw: &str) -> Result<String, Error> {
    let stripped = raw.strip_prefix('#').unwrap_or(raw).trim();
    if stripped.len() != 6 || !stripped.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::bad_request());
    }
    Ok(stripped.to_ascii_lowercase())
}

pub(crate) fn validate_label_description(raw: &str) -> Result<(), Error> {
    if raw.len() > 256 || raw.chars().any(char::is_control) {
        return Err(Error::bad_request());
    }
    Ok(())
}

pub(super) fn dedupe_labels(raw: &[String]) -> Result<Vec<String>, Error> {
    if raw.len() > MAX_ATTACHED_LABELS {
        return Err(Error::bad_request());
    }
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(raw.len());
    for item in raw {
        let name = normalize_label_name(item)?;
        if seen.insert(name.clone()) {
            out.push(name);
        }
    }
    Ok(out)
}

async fn authorize_label_read(tx: &Transaction<'_>, actor: &Identity, owner: &str, name: &str) -> Result<RepoAccess, Error> {
    match auth::authorize_repo_with_role(tx, actor, owner, name, Role::Read, RepoAction::RepoRead).await {
        Ok(a) => Ok(a),
        Err(e) if e.0 == StatusCode::FORBIDDEN => {
            match auth::authorize_repo_with_role(tx, actor, owner, name, Role::Read, RepoAction::IssuesRead).await {
                Ok(a) => Ok(a),
                Err(_) => auth::authorize_repo_with_role(tx, actor, owner, name, Role::Read, RepoAction::PullsRead).await,
            }
        }
        Err(e) => Err(e),
    }
}

async fn authorize_label_write(tx: &Transaction<'_>, actor: &Identity, owner: &str, name: &str) -> Result<RepoAccess, Error> {
    match auth::authorize_repo_with_role(tx, actor, owner, name, Role::Triage, RepoAction::IssuesWrite).await {
        Ok(a) => Ok(a),
        Err(e) if e.0 == StatusCode::FORBIDDEN => {
            auth::authorize_repo_with_role(tx, actor, owner, name, Role::Triage, RepoAction::PullsWrite).await
        }
        Err(e) => Err(e),
    }
}

pub(crate) async fn load_repo_labels(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    after: &str,
    limit: i64,
) -> Result<(Vec<RepoLabel>, Option<String>), Error> {
    let sql = format!(
        "SELECT {LABEL_FIELDS} FROM forge_labels WHERE tenant_id=$1 AND repository_id=$2 AND name>$3 ORDER BY name ASC LIMIT $4"
    );
    let rows = tx
        .query(&sql, &[&tenant_id, &repo_id, &after, &(limit + 1)])
        .await
        .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<RepoLabel> = rows.iter().take(limit as usize).map(RepoLabel::row).collect();
    let next_after = if more { items.last().map(|l| l.name.clone()) } else { None };
    Ok((items, next_after))
}

pub(crate) async fn load_target_labels(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    target_kind: &str,
    number: i64,
) -> Result<Vec<RepoLabel>, Error> {
    let sql = match target_kind {
        "issue" => concat!(
            "SELECT l.repository_id,l.name,l.color,l.description,l.version,l.created_at::text,l.updated_at::text ",
            "FROM forge_issue_labels il JOIN forge_labels l ON l.tenant_id=il.tenant_id AND l.repository_id=il.repository_id AND l.name=il.label_name ",
            "WHERE il.tenant_id=$1 AND il.repository_id=$2 AND il.issue_number=$3 ORDER BY l.name ASC"
        ),
        "pull" => concat!(
            "SELECT l.repository_id,l.name,l.color,l.description,l.version,l.created_at::text,l.updated_at::text ",
            "FROM forge_pull_labels pl JOIN forge_labels l ON l.tenant_id=pl.tenant_id AND l.repository_id=pl.repository_id AND l.name=pl.label_name ",
            "WHERE pl.tenant_id=$1 AND pl.repository_id=$2 AND pl.pull_number=$3 ORDER BY l.name ASC"
        ),
        _ => return Err(Error::bad_request()),
    };
    let rows = tx
        .query(sql, &[&tenant_id, &repo_id, &number])
        .await
        .map_err(Error::internal)?;
    Ok(rows.iter().map(RepoLabel::row).collect())
}

pub(crate) async fn create_label_tx(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    actor: &Identity,
    input: &NewLabel,
) -> Result<RepoLabel, Error> {
    let name = normalize_label_name(&input.name)?;
    let color = normalize_label_color(&input.color)?;
    validate_label_description(&input.description)?;
    let dup = tx
        .query_opt(
            "SELECT 1 FROM forge_labels WHERE tenant_id=$1 AND repository_id=$2 AND name=$3",
            &[&tenant_id, &repo_id, &name],
        )
        .await
        .map_err(Error::internal)?;
    if dup.is_some() {
        return Err(Error(StatusCode::CONFLICT, "label already exists"));
    }
    let sql = format!(
        "INSERT INTO forge_labels (tenant_id,repository_id,name,color,description) VALUES ($1,$2,$3,$4,$5) RETURNING {LABEL_FIELDS}"
    );
    let row = tx
        .query_one(&sql, &[&tenant_id, &repo_id, &name, &color, &input.description])
        .await
        .map_err(Error::internal)?;
    audit::record_audit_event(
        tx,
        tenant_id,
        repo_id,
        actor,
        "label.created",
        "label",
        &name,
        sjson!({ "color": color }),
    )
    .await?;
    Ok(RepoLabel::row(&row))
}

pub async fn list_labels(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<LabelListQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) {
        return Err(Error::bad_request());
    }
    let after = query.after.as_deref().unwrap_or("");
    if after.len() > 64 || after.chars().any(char::is_control) {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize_label_read(&tx, &actor, &owner, &name).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let (items, next_after) = load_repo_labels(&tx, tenant_id, access.repo_id, after, limit).await?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "items": items, "next_after": next_after })))
}

pub async fn create_label(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<NewLabel>,
) -> Result<Response, Error> {
    let label_name = normalize_label_name(&input.name)?;
    let color = normalize_label_color(&input.color)?;
    validate_label_description(&input.description)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let key = idempotency_key(&headers)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize_label_write(&tx, &actor, &owner, &name).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    if let Some(key) = key {
        let req = sjson!({ "operation": "label", "name": label_name, "color": color, "description": input.description });
        if let Some(saved) = creation_replay(&tx, tenant_id, access.repo_id, key, &req).await? {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::CREATED, saved));
        }
    }
    let label = create_label_tx(&tx, tenant_id, access.repo_id, &actor, &input).await?;
    let val = serde_json::to_value(&label).map_err(Error::internal)?;
    record_creation(&tx, tenant_id, access.repo_id, key, &val).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::CREATED, val))
}

pub async fn get_label(
    State(state): State<Arc<AppState>>,
    Path((owner, name, label)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let label = normalize_label_name(&label)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize_label_read(&tx, &actor, &owner, &name).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let sql = format!("SELECT {LABEL_FIELDS} FROM forge_labels WHERE tenant_id=$1 AND repository_id=$2 AND name=$3");
    let row = tx
        .query_opt(&sql, &[&tenant_id, &access.repo_id, &label])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let res = RepoLabel::row(&row);
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, res))
}

pub async fn update_label(
    State(state): State<Arc<AppState>>,
    Path((owner, name, label)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(input): Json<PatchLabel>,
) -> Result<Response, Error> {
    let cur_name = normalize_label_name(&label)?;
    positive(input.expected_version)?;
    let new_name = input.name.as_deref().map(normalize_label_name).transpose()?;
    let new_color = input.color.as_deref().map(normalize_label_color).transpose()?;
    if let Some(ref desc) = input.description {
        validate_label_description(desc)?;
    }
    if new_name.is_none() && new_color.is_none() && input.description.is_none() {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize_label_write(&tx, &actor, &owner, &name).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let cur_ver: i64 = tx
        .query_opt(
            "SELECT version FROM forge_labels WHERE tenant_id=$1 AND repository_id=$2 AND name=$3 FOR UPDATE",
            &[&tenant_id, &access.repo_id, &cur_name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0);
    if cur_ver != input.expected_version {
        return Err(Error(StatusCode::CONFLICT, "label version conflict"));
    }
    if let Some(ref target) = new_name
        && target != &cur_name
        && tx
            .query_opt(
                "SELECT 1 FROM forge_labels WHERE tenant_id=$1 AND repository_id=$2 AND name=$3",
                &[&tenant_id, &access.repo_id, target],
            )
            .await
            .map_err(Error::internal)?
            .is_some()
    {
        return Err(Error(StatusCode::CONFLICT, "target label name already exists"));
    }
    let sql = format!(
        "UPDATE forge_labels SET name=COALESCE($5,name),color=COALESCE($6,color),description=COALESCE($7,description),version=version+1,updated_at=clock_timestamp() \
         WHERE tenant_id=$1 AND repository_id=$2 AND name=$3 AND version=$4 RETURNING {LABEL_FIELDS}"
    );
    let row = tx
        .query_one(
            &sql,
            &[&tenant_id, &access.repo_id, &cur_name, &input.expected_version, &new_name, &new_color, &input.description],
        )
        .await
        .map_err(Error::internal)?;
    let updated = RepoLabel::row(&row);
    audit::record_audit_event(
        &tx,
        tenant_id,
        access.repo_id,
        &actor,
        "label.updated",
        "label",
        &updated.name,
        sjson!({ "previous_name": cur_name, "version": updated.version }),
    )
    .await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, updated))
}

pub async fn delete_label(
    State(state): State<Arc<AppState>>,
    Path((owner, name, label)): Path<(String, String, String)>,
    Query(query): Query<LabelVersionQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let label = normalize_label_name(&label)?;
    positive(query.expected_version)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize_label_write(&tx, &actor, &owner, &name).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let cur_ver: i64 = tx
        .query_opt(
            "SELECT version FROM forge_labels WHERE tenant_id=$1 AND repository_id=$2 AND name=$3 FOR UPDATE",
            &[&tenant_id, &access.repo_id, &label],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0);
    if cur_ver != query.expected_version {
        return Err(Error(StatusCode::CONFLICT, "label version conflict"));
    }
    tx.execute(
        "DELETE FROM forge_labels WHERE tenant_id=$1 AND repository_id=$2 AND name=$3 AND version=$4",
        &[&tenant_id, &access.repo_id, &label, &query.expected_version],
    )
    .await
    .map_err(Error::internal)?;
    audit::record_audit_event(&tx, tenant_id, access.repo_id, &actor, "label.deleted", "label", &label, sjson!({})).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, sjson!({ "deleted": true, "name": label })))
}
