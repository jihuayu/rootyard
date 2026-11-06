//! HTTP handlers for Pull Request CRUD, native Git diff inspection, and Pull Request Reviews.
use crate::{
    AppState, Error,
    auth::{self, authorize_repo as authorize, finish_tx as finish, idempotency_key},
    git_http,
    members::{audit, models::Role, rbac},
    pulls::{
        models::{
            NewPull, NewReview, PULL_FIELDS, Page, PullDiffResponse, PullPage, PullPatch,
            PullRequest, PullReview, PullStateFilter, REVIEW_FIELDS, body_valid, creation_replay,
            git_cmd, json, merge_base, normalize_branch_ref, positive, pull_exists,
            record_creation, repo_tenant_id, repository_object_format, resolve_ref_oid, title_valid,
            valid_oid, valid_oid_for_format, valid_review_state,
        },
        rules,
    },
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json as sjson;
use std::sync::Arc;
use uuid::Uuid;

async fn source_lease(
    state: &AppState, actor: &crate::db::Identity, owner: &str, name: &str, write: bool,
) -> Result<(Uuid, crate::storage::read_leases::Lease), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client.query_opt(
        "SELECT r.id FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id \
         WHERE ns.slug=$1 AND r.name=$2", &[&owner, &name],
    ).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let repo: Uuid = row.get(0);
    drop(client);
    auth::verify_active(&state.pool, actor, repo, write).await?;
    let lease = crate::storage::read_leases::shared(&state.pool, repo,
        tokio::time::Instant::now() + state.config.git_timeout).await?;
    auth::verify_active(&state.pool, actor, repo, write).await?;
    Ok((repo, lease))
}

async fn has_active_webhooks(
    tx: &deadpool_postgres::Transaction<'_>,
    repo_id: Uuid,
) -> Result<bool, Error> {
    let reg: Option<String> = tx
        .query_one("SELECT to_regclass('forge_webhooks')::text", &[])
        .await
        .map_err(Error::internal)?
        .get(0);
    if reg.is_none() {
        return Ok(false);
    }
    tx.query_one(
        "SELECT EXISTS(SELECT 1 FROM forge_webhooks WHERE repository_id=$1 AND active=true)",
        &[&repo_id],
    )
    .await
    .map_err(Error::internal)
    .map(|r| r.get(0))
}

pub async fn create_pull(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<NewPull>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if !title_valid(&input.title) || !body_valid(&input.body, false) {
        return Err(Error::bad_request());
    }
    let head_ref = normalize_branch_ref(&input.head_ref)?;
    let base_ref = normalize_branch_ref(&input.base_ref)?;
    if head_ref == base_ref {
        return Err(Error::bad_request());
    }
    if input.head_oid.as_ref().is_some_and(|h| !valid_oid(h))
        || input.base_oid.as_ref().is_some_and(|b| !valid_oid(b))
    {
        return Err(Error::bad_request());
    }
    let (lease_repo, source_lease) = source_lease(&state, &actor, &owner, &name, true).await?;
    let key = idempotency_key(&headers)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, true).await?;
    if repo != lease_repo { return Err(Error(StatusCode::CONFLICT, "repository route changed")); }
    let tenant_id = repo_tenant_id(&tx, repo).await?;
    let object_format = repository_object_format(&tx, repo).await?;
    if input.head_oid.as_ref().is_some_and(|h| !valid_oid_for_format(h, &object_format))
        || input.base_oid.as_ref().is_some_and(|b| !valid_oid_for_format(b, &object_format))
    {
        return Err(Error::bad_request());
    }
    if let Some(key) = key {
        let request = sjson!({
            "operation": "pull",
            "title": input.title,
            "body": input.body,
            "head_ref": head_ref,
            "base_ref": base_ref,
            "head_oid": input.head_oid,
            "base_oid": input.base_oid,
        });
        if let Some(response) = creation_replay(&tx, tenant_id, repo, key, &request).await? {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::CREATED, response));
        }
    }
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later")
    })?;
    let live_head_oid = source_lease.guard(resolve_ref_oid(&state, repo, &head_ref))
        .await??
        .ok_or(Error(StatusCode::CONFLICT, "head branch ref does not exist"))?;
    let live_base_oid = source_lease.guard(resolve_ref_oid(&state, repo, &base_ref))
        .await??
        .ok_or(Error(StatusCode::CONFLICT, "base branch ref does not exist"))?;
    source_lease.ensure_active()?;
    drop(_slot);
    if !valid_oid_for_format(&live_head_oid, &object_format)
        || !valid_oid_for_format(&live_base_oid, &object_format)
    {
        return Err(Error::internal("live branch OID differs from repository object format"));
    }

    if input.head_oid.as_ref().is_some_and(|expected| expected != &live_head_oid) {
        return Err(Error(StatusCode::CONFLICT, "head_oid does not match live branch ref"));
    }
    if input.base_oid.as_ref().is_some_and(|expected| expected != &live_base_oid) {
        return Err(Error(StatusCode::CONFLICT, "base_oid does not match live branch ref"));
    }

    let cnt_ins = "INSERT INTO forge_pull_counters (tenant_id,repository_id) VALUES ($1,$2) ON CONFLICT DO NOTHING";
    tx.execute(cnt_ins, &[&tenant_id, &repo]).await.map_err(Error::internal)?;
    let cnt_upd = "UPDATE forge_pull_counters SET next_number=next_number+1 WHERE tenant_id=$1 AND repository_id=$2 RETURNING next_number-1";
    let number: i64 = tx.query_one(cnt_upd, &[&tenant_id, &repo]).await.map_err(Error::internal)?.get(0);
    let ins = format!("INSERT INTO forge_pulls (tenant_id,repository_id,number,author_id,title,body,head_ref,base_ref,head_oid,base_oid) VALUES ($1,$2,$3,$10,$4,$5,$6,$7,$8,$9) RETURNING {PULL_FIELDS}");
    let row = tx
        .query_one(
            &ins,
            &[&tenant_id, &repo, &number, &input.title, &input.body, &head_ref, &base_ref, &live_head_oid, &live_base_oid, &actor.id],
        )
        .await
        .map_err(Error::internal)?;
    let pull_model = PullRequest::row(&row);
    let pull = serde_json::to_value(&pull_model).map_err(Error::internal)?;
    record_creation(&tx, tenant_id, repo, key, &pull).await?;
    let det = sjson!({ "head_ref": head_ref, "base_ref": base_ref, "head_oid": live_head_oid });
    audit::record_audit_event(&tx, tenant_id, repo, &actor, "pull.created", "pull", &number.to_string(), det).await?;
    let sync_wh = has_active_webhooks(&tx, repo).await?;
    finish(tx, &actor, true).await?;
    drop(client);
    if sync_wh {
        let _ = crate::webhooks::delivery::on_pull_synchronized(&state, repo, &pull_model, "opened").await;
    }
    Ok(json(StatusCode::CREATED, pull))
}

pub async fn list_pulls(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(page): Query<PullPage>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let (after, limit) = page.bounds()?;
    let filter = page.state.as_ref().map(PullStateFilter::as_str);
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, false).await?;
    let tenant_id = repo_tenant_id(&tx, repo).await?;
    let q = format!("SELECT {PULL_FIELDS} FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number>$3 AND ($5::text IS NULL OR state=$5) ORDER BY number LIMIT $4");
    let rows = tx.query(&q, &[&tenant_id, &repo, &after, &(limit + 1), &filter]).await.map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<_> = rows.iter().take(limit as usize).map(PullRequest::row).collect();
    let next_after = if more { items.last().map(|p| p.number) } else { None };
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "items": items, "next_after": next_after })))
}

pub async fn get_pull(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, false).await?;
    let tenant_id = repo_tenant_id(&tx, repo).await?;
    let q = format!("SELECT {PULL_FIELDS} FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3");
    let row = tx.query_opt(&q, &[&tenant_id, &repo, &number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let pull = PullRequest::row(&row);
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, pull))
}

pub async fn update_pull(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    headers: HeaderMap,
    Json(input): Json<PullPatch>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    positive(input.expected_version)?;
    if input.title.as_ref().is_some_and(|v| !title_valid(v))
        || input.body.as_ref().is_some_and(|v| !body_valid(v, false))
        || input.state.as_ref().is_some_and(|v| !matches!(v.as_str(), "open" | "closed"))
        || input.head_oid.as_ref().is_some_and(|v| !valid_oid(v))
        || input.base_oid.as_ref().is_some_and(|v| !valid_oid(v))
        || (input.title.is_none()
            && input.body.is_none()
            && input.state.is_none()
            && input.head_oid.is_none()
            && input.base_oid.is_none())
    {
        return Err(Error::bad_request());
    }
    let source_lease = if input.head_oid.is_some() || input.base_oid.is_some() {
        Some(source_lease(&state, &actor, &owner, &name, true).await?)
    } else { None };
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, true).await?;
    if source_lease.as_ref().is_some_and(|(id, _)| *id != repo) {
        return Err(Error(StatusCode::CONFLICT, "repository route changed"));
    }
    let tenant_id = repo_tenant_id(&tx, repo).await?;
    let object_format = repository_object_format(&tx, repo).await?;
    if input.head_oid.as_ref().is_some_and(|v| !valid_oid_for_format(v, &object_format))
        || input.base_oid.as_ref().is_some_and(|v| !valid_oid_for_format(v, &object_format))
    {
        return Err(Error::bad_request());
    }
    let lock_q = "SELECT state, version, head_ref, base_ref FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE";
    let existing = tx.query_opt(lock_q, &[&tenant_id, &repo, &number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let current_state: String = existing.get("state");
    let current_version: i64 = existing.get("version");
    let head_ref: String = existing.get("head_ref");
    let base_ref: String = existing.get("base_ref");

    if current_state == "merged" {
        return Err(Error(StatusCode::CONFLICT, "merged pull request is immutable"));
    }
    if current_version != input.expected_version {
        return Err(Error(StatusCode::CONFLICT, "pull request version conflict"));
    }
    let target_state = input.state.as_deref().unwrap_or(&current_state);
    if input.head_oid.is_some() || input.base_oid.is_some() {
        if target_state == "closed" {
            return Err(Error(StatusCode::CONFLICT, "cannot update commits on a closed pull request"));
        }
        let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
            Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later")
        })?;
        let lease = &source_lease.as_ref().ok_or_else(Error::unauthorized)?.1;
        if let Some(ref new_head) = input.head_oid {
            let live_head = lease.guard(resolve_ref_oid(&state, repo, &head_ref))
                .await??
                .ok_or(Error(StatusCode::CONFLICT, "head branch ref does not exist"))?;
            if !valid_oid_for_format(&live_head, &object_format) {
                return Err(Error::internal("head branch OID differs from repository object format"));
            }
            if &live_head != new_head {
                return Err(Error(StatusCode::CONFLICT, "head_oid does not match live branch ref"));
            }
        }
        if let Some(ref new_base) = input.base_oid {
            let live_base = lease.guard(resolve_ref_oid(&state, repo, &base_ref))
                .await??
                .ok_or(Error(StatusCode::CONFLICT, "base branch ref does not exist"))?;
            if !valid_oid_for_format(&live_base, &object_format) {
                return Err(Error::internal("base branch OID differs from repository object format"));
            }
            if &live_base != new_base {
                return Err(Error(StatusCode::CONFLICT, "base_oid does not match live branch ref"));
            }
        }
        if let Some((_, lease)) = &source_lease { lease.ensure_active()?; }
    }

    let upd = format!("UPDATE forge_pulls SET title=COALESCE($5,title),body=COALESCE($6,body),state=COALESCE($7,state),head_oid=COALESCE($8,head_oid),base_oid=COALESCE($9,base_oid),version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 AND version=$4 RETURNING {PULL_FIELDS}");
    let row = tx
        .query_opt(
            &upd,
            &[&tenant_id, &repo, &number, &input.expected_version, &input.title, &input.body, &input.state, &input.head_oid, &input.base_oid],
        )
        .await
        .map_err(Error::internal)?
        .ok_or(Error(StatusCode::CONFLICT, "pull request version conflict"))?;
    let pull = PullRequest::row(&row);
    let det = sjson!({ "state": pull.state, "version": pull.version });
    audit::record_audit_event(&tx, tenant_id, repo, &actor, "pull.updated", "pull", &number.to_string(), det).await?;
    let sync_action = if pull.state == "open" {
        if input.head_oid.is_some() {
            Some("synchronize")
        } else if input.state.as_deref() == Some("open") && current_state != "open" {
            Some("reopened")
        } else {
            None
        }
    } else {
        None
    };
    let sync_wh = if sync_action.is_some() {
        has_active_webhooks(&tx, repo).await?
    } else {
        false
    };
    finish(tx, &actor, true).await?;
    drop(client);
    if let (true, Some(action)) = (sync_wh, sync_action) {
        let _ = crate::webhooks::delivery::on_pull_synchronized(&state, repo, &pull, action).await;
    }
    Ok(json(StatusCode::OK, pull))
}

pub async fn get_pull_diff(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo = authorize(&tx, &actor, &owner, &name, false).await?;
    let tenant_id = repo_tenant_id(&tx, repo).await?;
    let q = format!("SELECT {PULL_FIELDS} FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3");
    let row = tx.query_opt(&q, &[&tenant_id, &repo, &number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let pull = PullRequest::row(&row);
    finish(tx, &actor, false).await?;
    drop(client);

    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later")
    })?;
    let _lease = crate::storage::read_leases::shared(&state.pool, repo,
        tokio::time::Instant::now() + state.config.git_timeout).await?;
    auth::verify_active(&state.pool, &actor, repo, false).await?;
    let merge_base_oid = _lease.guard(merge_base(&state, repo, &pull.base_oid, &pull.head_oid)).await??;
    let fast_forward = merge_base_oid.as_deref() == Some(pull.base_oid.as_str());
    let mut cmd = git_cmd(&state, repo)?;
    cmd.args(["diff", "--no-color", "--no-ext-diff", &pull.base_oid, &pull.head_oid]);
    let diff_bytes = _lease.guard(git_http::collect_git_output(
        cmd, 4 * 1024 * 1024, state.config.git_timeout)).await?
        .map_err(Error::internal)?;
    _lease.ensure_active()?;
    auth::verify_active(&state.pool, &actor, repo, false).await?;
    let diff = String::from_utf8_lossy(&diff_bytes).into_owned();
    Ok(json(
        StatusCode::OK,
        PullDiffResponse {
            pull_number: pull.number,
            base_ref: pull.base_ref,
            head_ref: pull.head_ref,
            base_oid: pull.base_oid,
            head_oid: pull.head_oid,
            merge_base_oid,
            fast_forward,
            diff,
        },
    ))
}

pub async fn create_review(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    headers: HeaderMap,
    Json(input): Json<NewReview>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    if !valid_review_state(&input.state)
        || !valid_oid(&input.commit_oid)
        || !body_valid(&input.body, input.state != "approved")
    {
        return Err(Error::bad_request());
    }
    let key = idempotency_key(&headers)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let min_role = if input.state == "commented" { Role::Triage } else { Role::Write };
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, min_role).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    let object_format = repository_object_format(&tx, repo).await?;
    if !valid_oid_for_format(&input.commit_oid, &object_format) {
        return Err(Error::bad_request());
    }
    if let Some(key) = key {
        let request = sjson!({
            "operation": "pull_review",
            "pull_number": number,
            "state": input.state,
            "commit_oid": input.commit_oid,
            "body": input.body,
        });
        if let Some(response) = creation_replay(&tx, tenant_id, repo, key, &request).await? {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::CREATED, response));
        }
    }
    let lock_q = "SELECT author_id, base_ref, state, head_oid, version FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE";
    let pull_row = tx.query_opt(lock_q, &[&tenant_id, &repo, &number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let pull_author_id: Uuid = pull_row.get("author_id");
    let pull_base_ref: String = pull_row.get("base_ref");
    let pull_state: String = pull_row.get("state");
    let pull_head_oid: String = pull_row.get("head_oid");
    let pull_version: i64 = pull_row.get("version");
    if pull_state != "open" {
        return Err(Error(StatusCode::CONFLICT, "pull request is not open"));
    }
    if input.commit_oid != pull_head_oid {
        return Err(Error(StatusCode::CONFLICT, "review commit_oid does not match pull request head_oid"));
    }
    let disallow_self = rules::is_self_approval_disallowed(&tx, tenant_id, repo, &pull_base_ref, pull_author_id).await?;
    rbac::check_review_permission(&tx, &access, actor.id, pull_author_id, &pull_base_ref, &input.state, disallow_self).await?;

    let rev_upd = "UPDATE forge_pulls SET next_review_number=next_review_number+1 WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING next_review_number-1";
    let review_number: i64 = tx.query_one(rev_upd, &[&tenant_id, &repo, &number]).await.map_err(Error::internal)?.get(0);
    let ins = format!("INSERT INTO forge_pull_reviews (tenant_id,repository_id,pull_number,number,author_id,state,commit_oid,pull_version,body) VALUES ($1,$2,$3,$4,$9,$5,$6,$7,$8) RETURNING {REVIEW_FIELDS}");
    let row = tx
        .query_one(&ins, &[&tenant_id, &repo, &number, &review_number, &input.state, &input.commit_oid, &pull_version, &input.body, &actor.id])
        .await
        .map_err(Error::internal)?;
    let review = serde_json::to_value(PullReview::row(&row)).map_err(Error::internal)?;
    record_creation(&tx, tenant_id, repo, key, &review).await?;
    let det = sjson!({ "pull_number": number, "state": input.state, "commit_oid": input.commit_oid });
    audit::record_audit_event(&tx, tenant_id, repo, &actor, "pull_review.submitted", "pull_review", &format!("{number}:{review_number}"), det).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::CREATED, review))
}

pub async fn list_reviews(
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
    let repo = authorize(&tx, &actor, &owner, &name, false).await?;
    let tenant_id = repo_tenant_id(&tx, repo).await?;
    pull_exists(&tx, tenant_id, repo, number).await?;
    let q = format!("SELECT {REVIEW_FIELDS} FROM forge_pull_reviews WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 AND number>$4 ORDER BY number LIMIT $5");
    let rows = tx.query(&q, &[&tenant_id, &repo, &number, &after, &(limit + 1)]).await.map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<_> = rows.iter().take(limit as usize).map(PullReview::row).collect();
    let next_after = if more { items.last().map(|r| r.number) } else { None };
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "items": items, "next_after": next_after })))
}
