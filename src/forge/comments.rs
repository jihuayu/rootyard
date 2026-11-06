//! Tenant-scoped Issue comment handlers.
use super::handlers::{Comment, CommentPatch, NewComment, Page, COMMENT_FIELDS, body_valid, creation_replay, issue_exists, json, positive, record_creation};
use crate::{AppState, Error, auth::{self, Role, authorize_repo_with_role as authorize, finish_tx as finish, idempotency_key}};
use axum::{Json, extract::{Path, Query, State}, http::{HeaderMap, StatusCode}, response::Response};
use std::sync::Arc;

pub async fn create_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    headers: HeaderMap,
    Json(input): Json<NewComment>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    if !body_valid(&input.body, true) {
        return Err(Error::bad_request());
    }
    let key = idempotency_key(&headers)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Triage).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    if let Some(key) = key {
        let request =
            serde_json::json!({"operation":"comment", "issue_number":number, "body":input.body});
        if let Some(response) = creation_replay(&tx, tenant_id, repo, key, &request).await? {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::CREATED, response));
        }
    }
    let comment_number: i64 = tx.query_opt("UPDATE forge_issues SET next_comment_number=next_comment_number+1 WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING next_comment_number-1", &[&tenant_id,&repo,&number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?.get(0);
    let row = tx.query_one(&format!("INSERT INTO forge_issue_comments (tenant_id,repository_id,issue_number,number,author_id,body) VALUES($1,$2,$3,$4,$5,$6) RETURNING {COMMENT_FIELDS}"), &[&tenant_id,&repo,&number,&comment_number,&actor.id,&input.body]).await.map_err(Error::internal)?;
    let comment = serde_json::to_value(Comment::row(&row)).map_err(Error::internal)?;
    record_creation(&tx, tenant_id, repo, key, &comment).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::CREATED, comment))
}

pub async fn list_comments(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Query(page): Query<Page>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    let (after, limit) = page.bounds()?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Read).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    issue_exists(&tx, tenant_id, repo, number).await?;
    let rows = tx.query(&format!("SELECT {COMMENT_FIELDS} FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number>$4 ORDER BY number LIMIT $5"), &[&tenant_id,&repo,&number,&after,&(limit+1)]).await.map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<_> = rows.iter().take(limit as usize).map(Comment::row).collect();
    let next_after = if more {
        items.last().map(|i| i.number)
    } else {
        None
    };
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        serde_json::json!({"items":items,"next_after":next_after}),
    ))
}

pub async fn get_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    positive(comment_number)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Read).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    let row = tx.query_opt(&format!("SELECT {COMMENT_FIELDS} FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4"), &[&tenant_id,&repo,&number,&comment_number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let comment = Comment::row(&row);
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, comment))
}

pub async fn update_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>,
    headers: HeaderMap,
    Json(input): Json<CommentPatch>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    positive(comment_number)?;
    positive(input.expected_version)?;
    if !body_valid(&input.body, true) {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Triage).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    tx.query_opt("SELECT number FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4", &[&tenant_id,&repo,&number,&comment_number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let row = tx.query_opt(&format!("UPDATE forge_issue_comments SET body=$6,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4 AND version=$5 RETURNING {COMMENT_FIELDS}"), &[&tenant_id,&repo,&number,&comment_number,&input.expected_version,&input.body]).await.map_err(Error::internal)?.ok_or(Error(StatusCode::CONFLICT,"comment version conflict"))?;
    let comment = Comment::row(&row);
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, comment))
}

