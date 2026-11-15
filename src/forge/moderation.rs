//! Issue comment delete, moderation (`hide`/`unhide`/`delete`), and revision history.

use super::handlers::{COMMENT_FIELDS, Comment, json, positive};
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish},
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
use std::sync::Arc;
use tokio_postgres::Row;
use uuid::Uuid;

pub(crate) const HIDDEN_COMMENT_BODY: &str = "[hidden by moderator]";
pub(crate) const DELETED_COMMENT_BODY: &str = "[deleted]";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedVersionQuery {
    pub expected_version: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModerateCommentInput {
    pub expected_version: i64,
    pub action: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionPageQuery {
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CommentRevision {
    pub repository_id: Uuid,
    pub target_type: String,
    pub parent_number: i64,
    pub comment_number: i64,
    pub revision: i64,
    pub action: String,
    pub actor_id: Uuid,
    pub previous_body: String,
    pub new_body: String,
    pub reason: String,
    pub created_at: String,
}

impl CommentRevision {
    pub(crate) fn row(row: &Row) -> Self {
        Self {
            repository_id: row.get("repository_id"),
            target_type: row.get("target_type"),
            parent_number: row.get("parent_number"),
            comment_number: row.get("comment_number"),
            revision: row.get("revision"),
            action: row.get("action"),
            actor_id: row.get("actor_id"),
            previous_body: row.get("previous_body"),
            new_body: row.get("new_body"),
            reason: row.get("reason"),
            created_at: row.get("created_at"),
        }
    }
}

pub(crate) struct RevisionSpec<'a> {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub target_type: &'a str,
    pub parent_number: i64,
    pub comment_number: i64,
    pub action: &'a str,
    pub actor_id: Uuid,
    pub previous_body: &'a str,
    pub new_body: &'a str,
    pub reason: &'a str,
}

pub(crate) fn display_comment_body(body: &str, moderation_state: &str) -> String {
    match moderation_state {
        "hidden" => HIDDEN_COMMENT_BODY.to_owned(),
        "deleted" => DELETED_COMMENT_BODY.to_owned(),
        _ => body.to_owned(),
    }
}

pub(crate) fn sanitize_reason(raw: &str) -> Result<String, Error> {
    if raw.len() > 512 || raw.chars().any(char::is_control) {
        return Err(Error::bad_request());
    }
    Ok(raw.to_owned())
}

pub(crate) async fn record_comment_revision(
    tx: &Transaction<'_>,
    spec: RevisionSpec<'_>,
) -> Result<i64, Error> {
    let next_rev: i64 = tx
        .query_one(
            "SELECT COALESCE(MAX(revision), 0) + 1 FROM forge_comment_revisions WHERE tenant_id=$1 AND repository_id=$2 AND target_type=$3 AND parent_number=$4 AND comment_number=$5",
            &[
                &spec.tenant_id,
                &spec.repository_id,
                &spec.target_type,
                &spec.parent_number,
                &spec.comment_number,
            ],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    tx.execute(
        "INSERT INTO forge_comment_revisions (tenant_id,repository_id,target_type,parent_number,comment_number,revision,action,actor_id,previous_body,new_body,reason) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
        &[
            &spec.tenant_id,
            &spec.repository_id,
            &spec.target_type,
            &spec.parent_number,
            &spec.comment_number,
            &next_rev,
            &spec.action,
            &spec.actor_id,
            &spec.previous_body,
            &spec.new_body,
            &spec.reason,
        ],
    )
    .await
    .map_err(Error::internal)?;
    Ok(next_rev)
}

pub(crate) async fn list_comment_revisions_tx(
    tx: &Transaction<'_>,
    ids: (Uuid, Uuid),
    target: (&str, i64, i64),
    after: i64,
    limit: i64,
) -> Result<(Vec<CommentRevision>, Option<i64>), Error> {
    let (tenant_id, repo_id) = ids;
    let (target_type, parent_number, comment_number) = target;
    let rows = tx
        .query(
            "SELECT repository_id,target_type,parent_number,comment_number,revision,action,actor_id,previous_body,new_body,reason,created_at::text \
             FROM forge_comment_revisions \
             WHERE tenant_id=$1 AND repository_id=$2 AND target_type=$3 AND parent_number=$4 AND comment_number=$5 AND revision>$6 \
             ORDER BY revision ASC LIMIT $7",
            &[&tenant_id, &repo_id, &target_type, &parent_number, &comment_number, &after, &(limit + 1)],
        )
        .await
        .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<CommentRevision> = rows.iter().take(limit as usize).map(CommentRevision::row).collect();
    let next_after = if more { items.last().map(|r| r.revision) } else { None };
    Ok((items, next_after))
}

pub(crate) async fn delete_issue_comment_tx(
    tx: &Transaction<'_>,
    ids: (Uuid, Uuid),
    actor: &Identity,
    role: Role,
    target: (i64, i64),
    expected_version: i64,
) -> Result<Comment, Error> {
    let (tenant_id, repo_id) = ids;
    let (issue_number, comment_number) = target;
    positive(issue_number)?;
    positive(comment_number)?;
    positive(expected_version)?;
    let current = tx
        .query_opt(
            "SELECT author_id,body,version,moderation_state FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4 FOR UPDATE",
            &[&tenant_id, &repo_id, &issue_number, &comment_number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let author_id: Uuid = current.get("author_id");
    let prev_body: String = current.get("body");
    let cur_version: i64 = current.get("version");
    let mod_state: String = current.get("moderation_state");
    if author_id != actor.id && role < Role::Maintain {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient permission to delete comment"));
    }
    if mod_state == "deleted" {
        return Err(Error(StatusCode::CONFLICT, "comment already deleted"));
    }
    if cur_version != expected_version {
        return Err(Error(StatusCode::CONFLICT, "comment version conflict"));
    }
    record_comment_revision(
        tx,
        RevisionSpec {
            tenant_id,
            repository_id: repo_id,
            target_type: "issue_comment",
            parent_number: issue_number,
            comment_number,
            action: "deleted",
            actor_id: actor.id,
            previous_body: &prev_body,
            new_body: DELETED_COMMENT_BODY,
            reason: "",
        },
    )
    .await?;
    let sql = format!(
        "UPDATE forge_issue_comments SET body=$6,deleted_at=clock_timestamp(),deleted_by=$5,moderation_state='deleted',moderated_by=NULL,moderated_at=NULL,moderation_reason='',version=version+1,updated_at=clock_timestamp() \
         WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4 AND version=$7 RETURNING {COMMENT_FIELDS}"
    );
    let row = tx
        .query_one(
            &sql,
            &[
                &tenant_id,
                &repo_id,
                &issue_number,
                &comment_number,
                &actor.id,
                &DELETED_COMMENT_BODY,
                &expected_version,
            ],
        )
        .await
        .map_err(Error::internal)?;
    audit::record_audit_event(
        tx,
        tenant_id,
        repo_id,
        actor,
        "issue_comment.deleted",
        "issue_comment",
        &format!("{issue_number}:{comment_number}"),
        sjson!({ "expected_version": expected_version }),
    )
    .await?;
    Ok(Comment::row(&row))
}

pub(crate) async fn moderate_issue_comment_tx(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    actor: &Identity,
    issue_number: i64,
    comment_number: i64,
    input: &ModerateCommentInput,
) -> Result<Comment, Error> {
    positive(issue_number)?;
    positive(comment_number)?;
    positive(input.expected_version)?;
    let reason = sanitize_reason(&input.reason)?;
    if !matches!(input.action.as_str(), "hide" | "unhide" | "delete") {
        return Err(Error::bad_request());
    }
    let current = tx
        .query_opt(
            "SELECT body,version,moderation_state FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4 FOR UPDATE",
            &[&tenant_id, &repo_id, &issue_number, &comment_number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let prev_body: String = current.get("body");
    let cur_version: i64 = current.get("version");
    let mod_state: String = current.get("moderation_state");
    if mod_state == "deleted" {
        return Err(Error(StatusCode::CONFLICT, "deleted comment cannot be moderated"));
    }
    if cur_version != input.expected_version {
        return Err(Error(StatusCode::CONFLICT, "comment version conflict"));
    }
    let (rev_action, rev_prev, rev_new, sql) = match input.action.as_str() {
        "hide" => (
            "hidden",
            display_comment_body(&prev_body, &mod_state),
            HIDDEN_COMMENT_BODY.to_owned(),
            format!(
                "UPDATE forge_issue_comments SET moderation_state='hidden',moderated_by=$5,moderated_at=clock_timestamp(),moderation_reason=$6,version=version+1,updated_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4 RETURNING {COMMENT_FIELDS}"
            ),
        ),
        "unhide" => {
            if mod_state != "hidden" {
                return Err(Error(StatusCode::CONFLICT, "comment is not hidden"));
            }
            (
                "unhidden",
                HIDDEN_COMMENT_BODY.to_owned(),
                prev_body.clone(),
                format!(
                    "UPDATE forge_issue_comments SET moderation_state='visible',moderated_by=NULL,moderated_at=NULL,moderation_reason='',version=version+1,updated_at=clock_timestamp() \
                     WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4 RETURNING {COMMENT_FIELDS}"
                ),
            )
        }
        "delete" => (
            "deleted",
            display_comment_body(&prev_body, &mod_state),
            DELETED_COMMENT_BODY.to_owned(),
            format!(
                "UPDATE forge_issue_comments SET body='{DELETED_COMMENT_BODY}',deleted_at=clock_timestamp(),deleted_by=$5,moderation_state='deleted',moderated_by=$5,moderated_at=clock_timestamp(),moderation_reason=$6,version=version+1,updated_at=clock_timestamp() \
                 WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4 RETURNING {COMMENT_FIELDS}"
            ),
        ),
        _ => return Err(Error::bad_request()),
    };
    record_comment_revision(
        tx,
        RevisionSpec {
            tenant_id,
            repository_id: repo_id,
            target_type: "issue_comment",
            parent_number: issue_number,
            comment_number,
            action: rev_action,
            actor_id: actor.id,
            previous_body: &rev_prev,
            new_body: &rev_new,
            reason: &reason,
        },
    )
    .await?;
    let row = match input.action.as_str() {
        "unhide" => {
            tx.query_one(&sql, &[&tenant_id, &repo_id, &issue_number, &comment_number])
                .await
                .map_err(Error::internal)?
        }
        _ => {
            tx.query_one(
                &sql,
                &[&tenant_id, &repo_id, &issue_number, &comment_number, &actor.id, &reason],
            )
            .await
            .map_err(Error::internal)?
        }
    };
    audit::record_audit_event(
        tx,
        tenant_id,
        repo_id,
        actor,
        &format!("issue_comment.moderated.{}", input.action),
        "issue_comment",
        &format!("{issue_number}:{comment_number}"),
        sjson!({ "action": input.action, "reason": reason }),
    )
    .await?;
    Ok(Comment::row(&row))
}

pub async fn delete_issue_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>,
    Query(query): Query<ExpectedVersionQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Triage, RepoAction::IssuesWrite).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let comment = delete_issue_comment_tx(
        &tx,
        (tenant_id, access.repo_id),
        &actor,
        access.role,
        (number, comment_number),
        query.expected_version,
    )
    .await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, comment))
}

pub async fn moderate_issue_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>,
    headers: HeaderMap,
    Json(input): Json<ModerateCommentInput>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Maintain, RepoAction::IssuesWrite).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let comment = moderate_issue_comment_tx(&tx, tenant_id, access.repo_id, &actor, number, comment_number, &input).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, comment))
}

pub async fn list_issue_comment_revisions(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>,
    Query(page): Query<RevisionPageQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    positive(number)?;
    positive(comment_number)?;
    let after = page.after.unwrap_or(0);
    let limit = page.limit.unwrap_or(50);
    if after < 0 || !(1..=100).contains(&limit) {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Maintain, RepoAction::IssuesRead).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    tx.query_opt(
        "SELECT 1 FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4",
        &[&tenant_id, &access.repo_id, &number, &comment_number],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::not_found)?;
    let (items, next_after) = list_comment_revisions_tx(
        &tx,
        (tenant_id, access.repo_id),
        ("issue_comment", number, comment_number),
        after,
        limit,
    )
    .await?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "items": items, "next_after": next_after })))
}
