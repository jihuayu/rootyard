//! Edit, soft-delete, moderation (`hide`/`unhide`/`delete`), and revision history for PR inline review comments.

use super::{
    models::{body_valid, json, positive, repo_tenant_id},
    review_comments::{PullReviewComment, REVIEW_COMMENT_FIELDS, load_pull_head_base},
};
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish},
    forge::moderation::{
        DELETED_COMMENT_BODY, ExpectedVersionQuery, HIDDEN_COMMENT_BODY, ModerateCommentInput,
        RevisionPageQuery, RevisionSpec, display_comment_body, list_comment_revisions_tx,
        record_comment_revision, sanitize_reason,
    },
    members::{audit, models::Role},
    token_scopes::RepoAction,
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;
use serde_json::json as sjson;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchPullReviewComment {
    pub expected_version: i64,
    pub body: String,
}

pub async fn update_review_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>,
    headers: HeaderMap,
    Json(input): Json<PatchPullReviewComment>,
) -> Result<Response, Error> {
    positive(number)?;
    positive(comment_number)?;
    positive(input.expected_version)?;
    if !body_valid(&input.body, true) {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Triage, RepoAction::PullsWrite).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let pull = load_pull_head_base(&tx, tenant_id, access.repo_id, number).await?;
    let current = tx
        .query_opt(
            "SELECT author_id,body,version,moderation_state FROM forge_pull_review_comments WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number=$4 FOR UPDATE",
            &[&tenant_id, &access.repo_id, &number, &comment_number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let author_id: Uuid = current.get("author_id");
    let prev_body: String = current.get("body");
    let cur_ver: i64 = current.get("version");
    let mod_state: String = current.get("moderation_state");
    if author_id != actor.id && access.role < Role::Maintain {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient permission to edit review comment"));
    }
    if mod_state == "deleted" {
        return Err(Error(StatusCode::CONFLICT, "deleted review comment cannot be edited"));
    }
    if cur_ver != input.expected_version {
        return Err(Error(StatusCode::CONFLICT, "review comment version conflict"));
    }
    record_comment_revision(
        &tx,
        RevisionSpec {
            tenant_id,
            repository_id: access.repo_id,
            target_type: "pull_review_comment",
            parent_number: number,
            comment_number,
            action: "edited",
            actor_id: actor.id,
            previous_body: &prev_body,
            new_body: &input.body,
            reason: "",
        },
    )
    .await?;
    let row = tx
        .query_one(
            &format!("UPDATE forge_pull_review_comments SET body=$5,edited_at=clock_timestamp(),version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number=$4 RETURNING {REVIEW_COMMENT_FIELDS}"),
            &[&tenant_id, &access.repo_id, &number, &comment_number, &input.body],
        )
        .await
        .map_err(Error::internal)?;
    audit::record_audit_event(
        &tx,
        tenant_id,
        access.repo_id,
        &actor,
        "pull_review_comment.edited",
        "pull_review_comment",
        &format!("{number}:{comment_number}"),
        sjson!({ "expected_version": input.expected_version }),
    )
    .await?;
    let updated = PullReviewComment::row_for_pull(&row, &pull.head_oid, &pull.base_oid);
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, updated))
}

pub async fn delete_review_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>,
    Query(query): Query<ExpectedVersionQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    positive(number)?;
    positive(comment_number)?;
    positive(query.expected_version)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Triage, RepoAction::PullsWrite).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let pull = load_pull_head_base(&tx, tenant_id, access.repo_id, number).await?;
    let current = tx
        .query_opt(
            "SELECT author_id,body,version,moderation_state FROM forge_pull_review_comments WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number=$4 FOR UPDATE",
            &[&tenant_id, &access.repo_id, &number, &comment_number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let author_id: Uuid = current.get("author_id");
    let prev_body: String = current.get("body");
    let cur_ver: i64 = current.get("version");
    let mod_state: String = current.get("moderation_state");
    if author_id != actor.id && access.role < Role::Maintain {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient permission to delete review comment"));
    }
    if mod_state == "deleted" {
        return Err(Error(StatusCode::CONFLICT, "review comment already deleted"));
    }
    if cur_ver != query.expected_version {
        return Err(Error(StatusCode::CONFLICT, "review comment version conflict"));
    }
    record_comment_revision(
        &tx,
        RevisionSpec {
            tenant_id,
            repository_id: access.repo_id,
            target_type: "pull_review_comment",
            parent_number: number,
            comment_number,
            action: "deleted",
            actor_id: actor.id,
            previous_body: &prev_body,
            new_body: DELETED_COMMENT_BODY,
            reason: "",
        },
    )
    .await?;
    let row = tx
        .query_one(
            &format!("UPDATE forge_pull_review_comments SET body=$6,deleted_at=clock_timestamp(),deleted_by=$5,moderation_state='deleted',moderated_by=NULL,moderated_at=NULL,moderation_reason='',version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number=$4 RETURNING {REVIEW_COMMENT_FIELDS}"),
            &[&tenant_id, &access.repo_id, &number, &comment_number, &actor.id, &DELETED_COMMENT_BODY],
        )
        .await
        .map_err(Error::internal)?;
    audit::record_audit_event(
        &tx,
        tenant_id,
        access.repo_id,
        &actor,
        "pull_review_comment.deleted",
        "pull_review_comment",
        &format!("{number}:{comment_number}"),
        sjson!({ "expected_version": query.expected_version }),
    )
    .await?;
    let deleted = PullReviewComment::row_for_pull(&row, &pull.head_oid, &pull.base_oid);
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, deleted))
}

pub async fn moderate_review_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>,
    headers: HeaderMap,
    Json(input): Json<ModerateCommentInput>,
) -> Result<Response, Error> {
    positive(number)?;
    positive(comment_number)?;
    positive(input.expected_version)?;
    let reason = sanitize_reason(&input.reason)?;
    if !matches!(input.action.as_str(), "hide" | "unhide" | "delete") {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Maintain, RepoAction::PullsWrite).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let pull = load_pull_head_base(&tx, tenant_id, access.repo_id, number).await?;
    let current = tx
        .query_opt(
            "SELECT body,version,moderation_state FROM forge_pull_review_comments WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number=$4 FOR UPDATE",
            &[&tenant_id, &access.repo_id, &number, &comment_number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let prev_body: String = current.get("body");
    let cur_ver: i64 = current.get("version");
    let mod_state: String = current.get("moderation_state");
    if mod_state == "deleted" {
        return Err(Error(StatusCode::CONFLICT, "deleted review comment cannot be moderated"));
    }
    if cur_ver != input.expected_version {
        return Err(Error(StatusCode::CONFLICT, "review comment version conflict"));
    }
    let (rev_action, rev_prev, rev_new, row) = match input.action.as_str() {
        "hide" => {
            let row = tx
                .query_one(
                    &format!("UPDATE forge_pull_review_comments SET moderation_state='hidden',moderated_by=$5,moderated_at=clock_timestamp(),moderation_reason=$6,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number=$4 RETURNING {REVIEW_COMMENT_FIELDS}"),
                    &[&tenant_id, &access.repo_id, &number, &comment_number, &actor.id, &reason],
                )
                .await
                .map_err(Error::internal)?;
            ("hidden", display_comment_body(&prev_body, &mod_state), HIDDEN_COMMENT_BODY.to_owned(), row)
        }
        "unhide" => {
            if mod_state != "hidden" {
                return Err(Error(StatusCode::CONFLICT, "review comment is not hidden"));
            }
            let row = tx
                .query_one(
                    &format!("UPDATE forge_pull_review_comments SET moderation_state='visible',moderated_by=NULL,moderated_at=NULL,moderation_reason='',version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number=$4 RETURNING {REVIEW_COMMENT_FIELDS}"),
                    &[&tenant_id, &access.repo_id, &number, &comment_number],
                )
                .await
                .map_err(Error::internal)?;
            ("unhidden", HIDDEN_COMMENT_BODY.to_owned(), prev_body.clone(), row)
        }
        _ => {
            let row = tx
                .query_one(
                    &format!("UPDATE forge_pull_review_comments SET body=$6,deleted_at=clock_timestamp(),deleted_by=$5,moderation_state='deleted',moderated_by=$5,moderated_at=clock_timestamp(),moderation_reason=$7,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number=$4 RETURNING {REVIEW_COMMENT_FIELDS}"),
                    &[&tenant_id, &access.repo_id, &number, &comment_number, &actor.id, &DELETED_COMMENT_BODY, &reason],
                )
                .await
                .map_err(Error::internal)?;
            ("deleted", display_comment_body(&prev_body, &mod_state), DELETED_COMMENT_BODY.to_owned(), row)
        }
    };
    record_comment_revision(
        &tx,
        RevisionSpec {
            tenant_id,
            repository_id: access.repo_id,
            target_type: "pull_review_comment",
            parent_number: number,
            comment_number,
            action: rev_action,
            actor_id: actor.id,
            previous_body: &rev_prev,
            new_body: &rev_new,
            reason: &reason,
        },
    )
    .await?;
    audit::record_audit_event(
        &tx,
        tenant_id,
        access.repo_id,
        &actor,
        &format!("pull_review_comment.moderated.{}", input.action),
        "pull_review_comment",
        &format!("{number}:{comment_number}"),
        sjson!({ "action": input.action, "reason": reason }),
    )
    .await?;
    let moderated = PullReviewComment::row_for_pull(&row, &pull.head_oid, &pull.base_oid);
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, moderated))
}

pub async fn list_review_comment_revisions(
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
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Maintain, RepoAction::PullsRead).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    tx.query_opt(
        "SELECT 1 FROM forge_pull_review_comments WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number=$4",
        &[&tenant_id, &access.repo_id, &number, &comment_number],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::not_found)?;
    let (items, next_after) = list_comment_revisions_tx(
        &tx,
        (tenant_id, access.repo_id),
        ("pull_review_comment", number, comment_number),
        after,
        limit,
    )
    .await?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "items": items, "next_after": next_after })))
}
