//! Inline diff-line PR review comments anchored to commit/base/path/side/line.
//!
//! Advancing PR `head_oid` or `base_oid` preserves historical coordinates while
//! computing `outdated = true` on read; moderation (`hide`/`unhide`/`delete`) and
//! edits append immutable `forge_comment_revisions` + `repository_audit_log` entries.

use super::models::{
    PULL_FIELDS, PullRequest, body_valid, creation_replay, git_cmd, json, positive,
    record_creation, repo_tenant_id, valid_oid,
};
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish, idempotency_key},
    browse::models::normalize_rel_path,
    db::Identity,
    forge::{
        moderation::display_comment_body,
        notifications::{NotifySpec, emit_repo_notifications},
    },
    git_http,
    members::{audit, models::Role},
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

pub(crate) const REVIEW_COMMENT_FIELDS: &str = concat!(
    "repository_id,pull_number,number,review_number,in_reply_to_number,author_id,",
    "commit_oid,base_oid,pull_version,path,side,line,body,version,",
    "moderation_state,edited_at::text,deleted_at::text,moderation_reason,",
    "created_at::text,updated_at::text"
);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PullReviewComment {
    pub repository_id: Uuid,
    pub pull_number: i64,
    pub number: i64,
    pub review_number: Option<i64>,
    pub in_reply_to_number: Option<i64>,
    pub author_id: Uuid,
    pub commit_oid: String,
    pub base_oid: String,
    pub pull_version: i64,
    pub outdated: bool,
    pub path: String,
    pub side: String,
    pub line: i64,
    pub body: String,
    pub version: i64,
    pub moderation_state: String,
    pub edited_at: Option<String>,
    pub deleted_at: Option<String>,
    pub moderation_reason: String,
    pub created_at: String,
    pub updated_at: String,
}

impl PullReviewComment {
    pub(crate) fn row_for_pull(row: &Row, current_head_oid: &str, current_base_oid: &str) -> Self {
        let moderation_state: String = row.get("moderation_state");
        let raw_body: String = row.get("body");
        let commit_oid: String = row.get("commit_oid");
        let base_oid: String = row.get("base_oid");
        let outdated = commit_oid != current_head_oid || base_oid != current_base_oid;
        Self {
            repository_id: row.get("repository_id"),
            pull_number: row.get("pull_number"),
            number: row.get("number"),
            review_number: row.get("review_number"),
            in_reply_to_number: row.get("in_reply_to_number"),
            author_id: row.get("author_id"),
            commit_oid,
            base_oid,
            pull_version: row.get("pull_version"),
            outdated,
            path: row.get("path"),
            side: row.get("side"),
            line: row.get("line"),
            body: display_comment_body(&raw_body, &moderation_state),
            version: row.get("version"),
            moderation_state,
            edited_at: row.get("edited_at"),
            deleted_at: row.get("deleted_at"),
            moderation_reason: row.get("moderation_reason"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewPullReviewComment {
    pub path: String,
    pub side: String,
    pub line: i64,
    pub body: String,
    pub commit_oid: Option<String>,
    pub base_oid: Option<String>,
    pub review_number: Option<i64>,
    pub in_reply_to_number: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCommentListQuery {
    pub after: Option<i64>,
    pub limit: Option<i64>,
    pub outdated: Option<bool>,
}

pub(crate) fn normalize_diff_anchor(
    path: &str,
    side: &str,
    line: i64,
) -> Result<(String, &'static str, i64), Error> {
    let clean_path = normalize_rel_path(Some(path))?;
    if clean_path.is_empty() || clean_path.len() > 1024 {
        return Err(Error::bad_request());
    }
    let norm_side = match side {
        "left" => "left",
        "right" => "right",
        _ => return Err(Error::bad_request()),
    };
    if !(1..=10_000_000).contains(&line) {
        return Err(Error::bad_request());
    }
    Ok((clean_path, norm_side, line))
}

async fn validate_git_diff_line_anchor(
    state: &Arc<AppState>,
    actor: &Identity,
    repo_id: Uuid,
    oids: (&str, &str),
    anchor: (&str, &str, i64),
) -> Result<(), Error> {
    let (base_oid, head_oid) = oids;
    let (path, side, line) = anchor;
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later")
    })?;
    let lease = crate::storage::read_leases::shared(
        &state.pool,
        repo_id,
        tokio::time::Instant::now() + state.config.git_timeout,
    )
    .await?;
    auth::verify_active(&state.pool, actor, repo_id, RepoAction::PullsWrite, Role::Triage).await?;

    let mut names_cmd = git_cmd(state, repo_id)?;
    names_cmd.args(["diff", "--name-only", base_oid, head_oid, "--", path]);
    let changed = lease
        .guard(git_http::collect_git_output(names_cmd, 256 * 1024, state.config.git_timeout))
        .await?
        .map_err(Error::internal)?;
    if String::from_utf8_lossy(&changed).trim().is_empty() {
        return Err(Error(StatusCode::BAD_REQUEST, "path is not part of pull request diff"));
    }

    let side_oid = if side == "left" { base_oid } else { head_oid };
    let spec = format!("{side_oid}:{path}");
    let mut cat_cmd = git_cmd(state, repo_id)?;
    cat_cmd.args(["cat-file", "blob", &spec]);
    let blob_bytes = lease
        .guard(git_http::collect_git_output(cat_cmd, 4 * 1024 * 1024, state.config.git_timeout))
        .await?
        .map_err(|_| Error(StatusCode::BAD_REQUEST, "anchored path missing on selected diff side"))?;
    let total_lines = count_lines(&blob_bytes);
    if line > total_lines {
        return Err(Error(StatusCode::BAD_REQUEST, "line number exceeds file length on diff side"));
    }
    lease.ensure_active()?;
    Ok(())
}

pub(crate) fn count_lines(bytes: &[u8]) -> i64 {
    if bytes.is_empty() {
        return 0;
    }
    let newlines = bytes.iter().filter(|&&b| b == b'\n').count() as i64;
    if bytes.last() == Some(&b'\n') {
        newlines
    } else {
        newlines + 1
    }
}

pub(crate) async fn load_pull_review_comments_all(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    pull: &PullRequest,
    after: i64,
    limit: i64,
    outdated_filter: Option<bool>,
) -> Result<(Vec<PullReviewComment>, Option<i64>), Error> {
    let outdated_pred = match outdated_filter {
        Some(true) => "AND (commit_oid <> $6 OR base_oid <> $7)",
        Some(false) => "AND commit_oid = $6 AND base_oid = $7",
        None => "",
    };
    let sql = format!(
        "SELECT {REVIEW_COMMENT_FIELDS} FROM forge_pull_review_comments \
         WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number>$4 {outdated_pred} \
         ORDER BY number ASC LIMIT $5"
    );
    let rows = match outdated_filter {
        Some(_) => {
            tx.query(
                &sql,
                &[&tenant_id, &repo_id, &pull.number, &after, &(limit + 1), &pull.head_oid, &pull.base_oid],
            )
            .await
        }
        None => tx.query(&sql, &[&tenant_id, &repo_id, &pull.number, &after, &(limit + 1)]).await,
    }
    .map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<PullReviewComment> = rows
        .iter()
        .take(limit as usize)
        .map(|r| PullReviewComment::row_for_pull(r, &pull.head_oid, &pull.base_oid))
        .collect();
    let next_after = if more { items.last().map(|c| c.number) } else { None };
    Ok((items, next_after))
}

pub(super) async fn load_pull_head_base(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    number: i64,
) -> Result<PullRequest, Error> {
    let row = tx
        .query_opt(
            &format!("SELECT {PULL_FIELDS} FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3"),
            &[&tenant_id, &repo_id, &number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    Ok(PullRequest::row(&row))
}

pub async fn create_review_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    headers: HeaderMap,
    Json(input): Json<NewPullReviewComment>,
) -> Result<Response, Error> {
    positive(number)?;
    let (clean_path, norm_side, line) = normalize_diff_anchor(&input.path, &input.side, input.line)?;
    if !body_valid(&input.body, true)
        || input.commit_oid.as_ref().is_some_and(|c| !valid_oid(c))
        || input.base_oid.as_ref().is_some_and(|c| !valid_oid(c))
        || input.review_number.is_some_and(|v| v <= 0)
        || input.in_reply_to_number.is_some_and(|v| v <= 0)
    {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let key = idempotency_key(&headers)?;

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Triage, RepoAction::PullsWrite).await?;
    let (repo_id, tenant_id) = (access.repo_id, access.owner_id);
    if let Some(k) = key {
        let req = sjson!({
            "operation": "pull_review_comment",
            "pull_number": number,
            "path": clean_path,
            "side": norm_side,
            "line": line,
            "body": input.body,
            "commit_oid": input.commit_oid,
            "base_oid": input.base_oid,
            "review_number": input.review_number,
            "in_reply_to_number": input.in_reply_to_number,
        });
        if let Some(saved) = creation_replay(&tx, tenant_id, repo_id, k, &req).await? {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::CREATED, saved));
        }
    }
    let pull = load_pull_head_base(&tx, tenant_id, repo_id, number).await?;
    if pull.state != "open" {
        return Err(Error(StatusCode::CONFLICT, "pull request is not open"));
    }
    if let Some(ref cid) = input.commit_oid
        && cid != &pull.head_oid
    {
        return Err(Error(StatusCode::CONFLICT, "review comment commit_oid does not match pull request head_oid"));
    }
    if let Some(ref bid) = input.base_oid
        && bid != &pull.base_oid
    {
        return Err(Error(StatusCode::CONFLICT, "review comment base_oid does not match pull request base_oid"));
    }
    finish(tx, &actor, false).await?;
    drop(client);

    validate_git_diff_line_anchor(&state, &actor, repo_id, (&pull.base_oid, &pull.head_oid), (&clean_path, norm_side, line)).await?;

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Triage, RepoAction::PullsWrite).await?;
    let pull_row = tx
        .query_opt(
            &format!("UPDATE forge_pulls SET next_review_comment_number=next_review_comment_number+1 WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING {PULL_FIELDS}, next_review_comment_number-1 AS allocated"),
            &[&tenant_id, &repo_id, &number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let locked_pull = PullRequest::row(&pull_row);
    let comment_number: i64 = pull_row.get("allocated");
    if locked_pull.state != "open" {
        return Err(Error(StatusCode::CONFLICT, "pull request is not open"));
    }
    if locked_pull.head_oid != pull.head_oid || locked_pull.base_oid != pull.base_oid {
        return Err(Error(StatusCode::CONFLICT, "pull request head/base changed concurrently; retry"));
    }
    if let Some(rev_num) = input.review_number {
        tx.query_opt(
            "SELECT 1 FROM forge_pull_reviews WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number=$4",
            &[&tenant_id, &repo_id, &number, &rev_num],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    }
    if let Some(parent_num) = input.in_reply_to_number {
        let parent_row = tx
            .query_opt(
                "SELECT path, side, line FROM forge_pull_review_comments WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number=$4",
                &[&tenant_id, &repo_id, &number, &parent_num],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
        let p_path: String = parent_row.get("path");
        let p_side: String = parent_row.get("side");
        let p_line: i64 = parent_row.get("line");
        if p_path != clean_path || p_side != norm_side || p_line != line {
            return Err(Error(
                StatusCode::BAD_REQUEST,
                "reply must share path, side, and line of parent review comment",
            ));
        }
    }

    let ins = format!(
        "INSERT INTO forge_pull_review_comments (tenant_id,repository_id,pull_number,number,review_number,in_reply_to_number,author_id,commit_oid,base_oid,pull_version,path,side,line,body) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING {REVIEW_COMMENT_FIELDS}"
    );
    let row = tx
        .query_one(
            &ins,
            &[
                &tenant_id, &repo_id, &number, &comment_number, &input.review_number, &input.in_reply_to_number,
                &actor.id, &locked_pull.head_oid, &locked_pull.base_oid, &locked_pull.version, &clean_path, &norm_side, &line, &input.body,
            ],
        )
        .await
        .map_err(Error::internal)?;
    let comment = PullReviewComment::row_for_pull(&row, &locked_pull.head_oid, &locked_pull.base_oid);
    let val = serde_json::to_value(&comment).map_err(Error::internal)?;
    record_creation(&tx, tenant_id, repo_id, key, &val).await?;
    audit::record_audit_event(
        &tx,
        tenant_id,
        repo_id,
        &actor,
        "pull_review_comment.created",
        "pull_review_comment",
        &format!("{number}:{comment_number}"),
        sjson!({ "path": clean_path, "side": norm_side, "line": line, "commit_oid": locked_pull.head_oid }),
    )
    .await?;
    emit_repo_notifications(
        &tx,
        NotifySpec {
            tenant_id,
            repository_id: repo_id,
            actor_id: actor.id,
            target_type: "pull_review_comment",
            target_number: number,
            thread_type: "pull",
            thread_number: number,
            event_kind: "pull_review_commented",
            delivery_key: &format!("pull:{repo_id}:{number}:rc:{comment_number}"),
            title: &format!("Inline review comment on PR #{number} ({clean_path}:{line})"),
            body_excerpt: &input.body,
            extra_recipients: &[],
        },
    )
    .await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::CREATED, val))
}

pub async fn list_review_comments(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Query(query): Query<ReviewCommentListQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    positive(number)?;
    let after = query.after.unwrap_or(0);
    let limit = query.limit.unwrap_or(50);
    if after < 0 || !(1..=100).contains(&limit) {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, RepoAction::PullsRead).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let pull = load_pull_head_base(&tx, tenant_id, access.repo_id, number).await?;
    let (items, next_after) = load_pull_review_comments_all(&tx, tenant_id, access.repo_id, &pull, after, limit, query.outdated).await?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "items": items, "next_after": next_after })))
}

pub async fn get_review_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    positive(number)?;
    positive(comment_number)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, RepoAction::PullsRead).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let pull = load_pull_head_base(&tx, tenant_id, access.repo_id, number).await?;
    let row = tx
        .query_opt(
            &format!("SELECT {REVIEW_COMMENT_FIELDS} FROM forge_pull_review_comments WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number=$4"),
            &[&tenant_id, &access.repo_id, &number, &comment_number],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let comment = PullReviewComment::row_for_pull(&row, &pull.head_oid, &pull.base_oid);
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, comment))
}

#[cfg(test)]
#[path = "review_comments_tests.rs"]
mod tests;
