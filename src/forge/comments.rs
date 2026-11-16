//! Tenant-scoped Issue comment handlers with revision audit history and notifications.
use super::handlers::{
    COMMENT_FIELDS, Comment, CommentPatch, NewComment, Page, body_valid, creation_replay,
    issue_exists, json, positive, record_creation,
};
use super::moderation::{RevisionSpec, record_comment_revision};
use super::notifications::{NotifySpec, emit_repo_notifications};
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish, idempotency_key},
    db::Identity,
    members::{audit, models::Role},
    token_scopes::RepoAction,
};
use deadpool_postgres::Transaction;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json as sjson;
use std::sync::Arc;
use uuid::Uuid;

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
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Triage, RepoAction::IssuesWrite).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    if let Some(key) = key {
        let request = sjson!({"operation":"comment", "issue_number":number, "body":input.body});
        if let Some(response) = creation_replay(&tx, tenant_id, repo, key, &request).await? {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::CREATED, response));
        }
    }
    let comment_number: i64 = tx
        .query_opt(
            "UPDATE forge_issues SET next_comment_number=next_comment_number+1 WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING next_comment_number-1",
            &[&tenant_id, &repo, &number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?
        .get(0);
    let row = tx
        .query_one(
            &format!("INSERT INTO forge_issue_comments (tenant_id,repository_id,issue_number,number,author_id,body) VALUES($1,$2,$3,$4,$5,$6) RETURNING {COMMENT_FIELDS}"),
            &[&tenant_id, &repo, &number, &comment_number, &actor.id, &input.body],
        )
        .await
        .map_err(Error::internal)?;
    let comment = serde_json::to_value(Comment::row(&row)).map_err(Error::internal)?;
    record_creation(&tx, tenant_id, repo, key, &comment).await?;
    emit_repo_notifications(
        &tx,
        NotifySpec {
            tenant_id,
            repository_id: repo,
            actor_id: actor.id,
            target_type: "issue",
            target_number: number,
            thread_type: "issue",
            thread_number: number,
            event_kind: "issue_commented",
            delivery_key: &format!("issue:{repo}:{number}:comment:{comment_number}"),
            title: &format!("Comment #{comment_number} on issue #{number}"),
            body_excerpt: &input.body,
            extra_recipients: &[],
        },
    )
    .await?;
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
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, RepoAction::IssuesRead).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    issue_exists(&tx, tenant_id, repo, number).await?;
    let rows = tx
        .query(
            &format!("SELECT {COMMENT_FIELDS} FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number>$4 ORDER BY number LIMIT $5"),
            &[&tenant_id, &repo, &number, &after, &(limit + 1)],
        )
        .await
        .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<_> = rows.iter().take(limit as usize).map(Comment::row).collect();
    let next_after = if more { items.last().map(|i| i.number) } else { None };
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({"items": items, "next_after": next_after})))
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
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, RepoAction::IssuesRead).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    let row = tx
        .query_opt(
            &format!("SELECT {COMMENT_FIELDS} FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4"),
            &[&tenant_id, &repo, &number, &comment_number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let comment = Comment::row(&row);
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, comment))
}

pub(crate) async fn update_issue_comment_tx(
    tx: &Transaction<'_>,
    ids: (Uuid, Uuid),
    actor: &Identity,
    role: Role,
    target: (i64, i64),
    update: (i64, &str),
) -> Result<Comment, Error> {
    let (tenant_id, repo) = ids;
    let (number, comment_number) = target;
    let (expected_version, body) = update;
    let current = tx
        .query_opt(
            "SELECT author_id,body,version,moderation_state FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4 FOR UPDATE",
            &[&tenant_id, &repo, &number, &comment_number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let author_id: Uuid = current.get("author_id");
    let prev_body: String = current.get("body");
    let cur_version: i64 = current.get("version");
    let mod_state: String = current.get("moderation_state");
    if author_id != actor.id && role < Role::Maintain {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient permission to edit comment"));
    }
    if mod_state == "deleted" {
        return Err(Error(StatusCode::CONFLICT, "deleted comment cannot be edited"));
    }
    if cur_version != expected_version {
        return Err(Error(StatusCode::CONFLICT, "comment version conflict"));
    }
    record_comment_revision(
        tx,
        RevisionSpec {
            tenant_id,
            repository_id: repo,
            target_type: "issue_comment",
            parent_number: number,
            comment_number,
            action: "edited",
            actor_id: actor.id,
            previous_body: &prev_body,
            new_body: body,
            reason: "",
        },
    )
    .await?;
    let row = tx
        .query_one(
            &format!("UPDATE forge_issue_comments SET body=$5,edited_at=clock_timestamp(),version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4 RETURNING {COMMENT_FIELDS}"),
            &[&tenant_id, &repo, &number, &comment_number, &body],
        )
        .await
        .map_err(Error::internal)?;
    audit::record_audit_event(
        tx,
        tenant_id,
        repo,
        actor,
        "issue_comment.edited",
        "issue_comment",
        &format!("{number}:{comment_number}"),
        sjson!({ "expected_version": expected_version }),
    )
    .await?;
    Ok(Comment::row(&row))
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
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Triage, RepoAction::IssuesWrite).await?;
    let comment = update_issue_comment_tx(
        &tx,
        (access.owner_id, access.repo_id),
        &actor,
        access.role,
        (number, comment_number),
        (input.expected_version, &input.body),
    )
    .await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, comment))
}
