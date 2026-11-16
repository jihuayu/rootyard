//! HTTP handlers for repository soft-delete, grace-window restore, fail-closed purge,
//! and explicit alias removal.
use super::{
    lifecycle::{
        DeleteRepoInput, LifecycleAction, PurgeRepoInput, RestoreRepoInput, enforce_mutating_availability,
        request_sha256, validate_expected_version, validate_grace_period,
    },
    lifecycle_handlers::{Res, load_lifecycle_view, lock_repo_for_lifecycle, store_idempotency},
    lifecycle_ops::{
        AliasDeleteResponse, DeleteRepoResponse, json_no_store, lifecycle_action_audit_name,
        require_idempotency_key_valid,
    },
    purge_db,
};
use crate::{AppState, Error, auth, members::models::Role, token_scopes::RepoAction};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::json;
use std::sync::Arc;

pub async fn delete_repo(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Res {
    if body.is_empty() {
        return Err(Error::bad_request());
    }
    let input: DeleteRepoInput = serde_json::from_slice(&body).map_err(|_| Error::bad_request())?;
    validate_expected_version(input.expected_version)?;
    let grace = validate_grace_period(input.grace_period_seconds)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let idem_key = require_idempotency_key_valid(&headers)?;
    let req_hash = request_sha256(&input)?;

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access =
        auth::authorize_repo_lifecycle(&tx, &actor, &owner, &name, Role::Admin, RepoAction::RepoAdmin, false).await?;

    let locked = match lock_repo_for_lifecycle(
        &tx,
        access.repo_id,
        &actor,
        LifecycleAction::Delete,
        idem_key.as_deref(),
        &req_hash,
        input.expected_version,
    )
    .await?
    {
        Ok(repo) => repo,
        Err((status, resp_body)) => {
            auth::finish_tx(tx, &actor, false).await?;
            return json_no_store(status, &resp_body);
        }
    };
    enforce_mutating_availability(
        locked.deleted,
        false,
        locked.transfer_in_progress || locked.transition_state != "stable" || locked.gc_fenced,
    )?;

    let row = tx
        .query_one(
            "UPDATE repositories SET deleted_at = clock_timestamp(), deleted_by = $2, \
             purge_after = clock_timestamp() + make_interval(secs => $3), version = version + 1 \
             WHERE id = $1 RETURNING deleted_at::text, purge_after::text, version",
            &[&locked.id, &actor.id, &(grace as f64)],
        )
        .await
        .map_err(Error::internal)?;
    let deleted_at: String = row.get(0);
    let purge_after: String = row.get(1);
    let new_version: i64 = row.get(2);

    crate::members::audit::record_audit_event(
        &tx,
        locked.owner_id,
        locked.id,
        &actor,
        lifecycle_action_audit_name(LifecycleAction::Delete),
        "repository",
        &locked.name,
        json!({"grace_period_seconds": grace, "purge_after": purge_after}),
    )
    .await?;

    let resp = DeleteRepoResponse { deleted: true, deleted_at, purge_after, version: new_version };
    store_idempotency(
        &tx,
        locked.id,
        actor.id,
        LifecycleAction::Delete,
        idem_key.as_deref(),
        &req_hash,
        StatusCode::OK,
        &resp,
    )
    .await?;
    auth::finish_tx(tx, &actor, true).await?;
    json_no_store(StatusCode::OK, &resp)
}

pub async fn restore(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<RestoreRepoInput>,
) -> Res {
    validate_expected_version(input.expected_version)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let idem_key = require_idempotency_key_valid(&headers)?;
    let req_hash = request_sha256(&input)?;

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access =
        auth::authorize_repo_lifecycle(&tx, &actor, &owner, &name, Role::Admin, RepoAction::RepoAdmin, true).await?;

    let locked = match lock_repo_for_lifecycle(
        &tx,
        access.repo_id,
        &actor,
        LifecycleAction::Restore,
        idem_key.as_deref(),
        &req_hash,
        input.expected_version,
    )
    .await?
    {
        Ok(repo) => repo,
        Err((status, body)) => {
            auth::finish_tx(tx, &actor, false).await?;
            return json_no_store(status, &body);
        }
    };
    if !locked.deleted {
        return Err(Error(StatusCode::CONFLICT, "repository is not soft-deleted"));
    }
    enforce_mutating_availability(
        false,
        false,
        locked.transfer_in_progress || locked.transition_state != "stable" || locked.gc_fenced,
    )?;

    tx.execute(
        "UPDATE repositories SET deleted_at = NULL, deleted_by = NULL, purge_after = NULL, version = version + 1 WHERE id = $1",
        &[&locked.id],
    )
    .await
    .map_err(Error::internal)?;

    crate::members::audit::record_audit_event(
        &tx,
        locked.owner_id,
        locked.id,
        &actor,
        lifecycle_action_audit_name(LifecycleAction::Restore),
        "repository",
        &locked.name,
        json!({"version": locked.version + 1}),
    )
    .await?;

    let view = load_lifecycle_view(&tx, locked.id).await?;
    store_idempotency(
        &tx,
        locked.id,
        actor.id,
        LifecycleAction::Restore,
        idem_key.as_deref(),
        &req_hash,
        StatusCode::OK,
        &view,
    )
    .await?;
    auth::finish_tx(tx, &actor, true).await?;
    json_no_store(StatusCode::OK, &view)
}

pub async fn purge(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<PurgeRepoInput>,
) -> Res {
    validate_expected_version(input.expected_version)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access =
        auth::authorize_repo_lifecycle(&tx, &actor, &owner, &name, Role::Admin, RepoAction::RepoAdmin, true).await?;
    auth::finish_tx(tx, &actor, false).await?;
    drop(client);
    purge_db::execute_purge(&state, &actor, &owner, &name, access.repo_id, &input).await
}

pub async fn delete_alias(
    State(state): State<Arc<AppState>>,
    Path((owner, name, alias_owner, alias_name)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access =
        auth::authorize_repo_lifecycle(&tx, &actor, &owner, &name, Role::Admin, RepoAction::RepoAdmin, false).await?;
    let archived: bool = tx
        .query_one("SELECT archived_at IS NOT NULL FROM repositories WHERE id = $1 FOR UPDATE", &[&access.repo_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    if archived {
        return Err(Error(StatusCode::FORBIDDEN, "repository is archived and read-only"));
    }
    let deleted = tx
        .query_opt(
            "DELETE FROM repository_aliases a USING namespaces n \
             WHERE a.alias_owner_id = n.id AND a.repository_id = $1 AND n.slug = $2 AND a.alias_name = $3 \
             RETURNING a.id",
            &[&access.repo_id, &alias_owner, &alias_name],
        )
        .await
        .map_err(Error::internal)?;
    if deleted.is_none() {
        return Err(Error::not_found());
    }
    crate::members::audit::record_audit_event(
        &tx,
        access.owner_id,
        access.repo_id,
        &actor,
        "repository.alias_deleted",
        "repository_alias",
        &format!("{alias_owner}/{alias_name}"),
        json!({"alias_owner": alias_owner, "alias_name": alias_name}),
    )
    .await?;
    auth::finish_tx(tx, &actor, true).await?;
    json_no_store(StatusCode::OK, &AliasDeleteResponse { deleted: true, owner: alias_owner, name: alias_name })
}
