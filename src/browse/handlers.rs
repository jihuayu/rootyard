//! Read-only HTTP handlers for Track 2A repository browsing endpoints.
use crate::{
    AppState, Error, auth, db::Identity,
    browse::{
        git_read,
        models::{
            self, BlobByOidQuery, BlobQuery, CommitsQuery, CompareQuery, RefsQuery, RefsResponse,
            StorageRouteQuery, StorageRouteResponse, TreeByOidQuery, TreeQuery,
        },
    },
};
use axum::{
    Json,
    extract::{Extension, Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

pub(crate) fn json_ok(value: impl serde::Serialize) -> Response {
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, "no-store")],
        Json(value),
    )
        .into_response()
}

pub(crate) fn acquire_git_slot(state: &AppState) -> Result<OwnedSemaphorePermit, Error> {
    state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git capacity exhausted; retry later",
        )
    })
}

pub async fn list_refs(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<RefsQuery>,
    Extension(actor): Extension<Identity>,
) -> Result<Response, Error> {
    let (prefix, after, limit) = query.validate()?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id: Uuid = auth::authorize_repo(&tx, &actor, &owner, &name, false).await?;
    let storage_generation: i64 = tx
        .query_one(
            "SELECT storage_generation FROM repositories WHERE id=$1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .get(0);

    auth::finish_tx(tx, &actor, false).await?;
    drop(client);
    let _permit = acquire_git_slot(&state)?;
    let _lease = crate::storage::read_leases::shared(&state.pool, repo_id,
        tokio::time::Instant::now() + state.config.git_timeout).await?;
    let _snapshot = state.storage.read_snapshot_lock(repo_id).await;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    let head = _lease.guard(git_read::read_head(&state, repo_id)).await??;
    let filtered = _lease.guard(git_read::page_refs(&state, repo_id, prefix, after, limit)).await??;
    let more = filtered.len() > limit;
    let items: Vec<_> = filtered.into_iter().take(limit).collect();
    let next_after = if more {
        items.last().map(|r| r.name.clone())
    } else {
        None
    };

    _lease.ensure_active()?;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    Ok(json_ok(RefsResponse {
        repository_id: repo_id,
        storage_generation,
        head,
        items,
        next_after,
    }))
}

pub async fn list_commits(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<CommitsQuery>,
    Extension(actor): Extension<Identity>,
) -> Result<Response, Error> {
    let (spec, after, limit) = query.validate()?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo(&tx, &actor, &owner, &name, false).await?;

    auth::finish_tx(tx, &actor, false).await?;
    drop(client);
    let _permit = acquire_git_slot(&state)?;
    let _lease = crate::storage::read_leases::shared(&state.pool, repo_id,
        tokio::time::Instant::now() + state.config.git_timeout).await?;
    let _snapshot = state.storage.read_snapshot_lock(repo_id).await;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    let payload = _lease.guard(git_read::list_commits(&state, repo_id, spec, after, limit)).await??;

    _lease.ensure_active()?;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    Ok(json_ok(payload))
}

pub async fn get_commit(
    State(state): State<Arc<AppState>>,
    Path((owner, name, oid)): Path<(String, String, String)>,
    Extension(actor): Extension<Identity>,
) -> Result<Response, Error> {
    if !models::valid_non_zero_oid(&oid) {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo(&tx, &actor, &owner, &name, false).await?;

    auth::finish_tx(tx, &actor, false).await?;
    drop(client);
    let _permit = acquire_git_slot(&state)?;
    let _lease = crate::storage::read_leases::shared(&state.pool, repo_id,
        tokio::time::Instant::now() + state.config.git_timeout).await?;
    let _snapshot = state.storage.read_snapshot_lock(repo_id).await;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    let detail = _lease.guard(git_read::get_commit_detail(&state, repo_id, &oid)).await??;

    _lease.ensure_active()?;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    Ok(json_ok(detail))
}

pub async fn get_tree(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<TreeQuery>,
    Extension(actor): Extension<Identity>,
) -> Result<Response, Error> {
    let limit = models::validate_limit(query.limit)?;
    let after = models::validate_tree_after(query.after.as_deref())?;
    let rel_path = models::normalize_rel_path(query.path.as_deref())?;
    if let Some(ref spec) = query.oid {
        if !models::valid_revision_spec(spec) {
            return Err(Error::bad_request());
        }
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo(&tx, &actor, &owner, &name, false).await?;

    auth::finish_tx(tx, &actor, false).await?;
    drop(client);
    let _permit = acquire_git_slot(&state)?;
    let _lease = crate::storage::read_leases::shared(&state.pool, repo_id,
        tokio::time::Instant::now() + state.config.git_timeout).await?;
    let _snapshot = state.storage.read_snapshot_lock(repo_id).await;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    let tree = _lease.guard(git_read::read_tree(
        &state,
        repo_id,
        query.oid.as_deref(),
        &rel_path,
        after,
        limit,
    )).await??;

    _lease.ensure_active()?;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    Ok(json_ok(tree))
}

pub async fn get_tree_by_oid(
    State(state): State<Arc<AppState>>,
    Path((owner, name, oid)): Path<(String, String, String)>,
    Query(query): Query<TreeByOidQuery>,
    Extension(actor): Extension<Identity>,
) -> Result<Response, Error> {
    if !models::valid_revision_spec(&oid) {
        return Err(Error::bad_request());
    }
    let limit = models::validate_limit(query.limit)?;
    let after = models::validate_tree_after(query.after.as_deref())?;
    let rel_path = models::normalize_rel_path(query.path.as_deref())?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo(&tx, &actor, &owner, &name, false).await?;

    auth::finish_tx(tx, &actor, false).await?;
    drop(client);
    let _permit = acquire_git_slot(&state)?;
    let _lease = crate::storage::read_leases::shared(&state.pool, repo_id,
        tokio::time::Instant::now() + state.config.git_timeout).await?;
    let _snapshot = state.storage.read_snapshot_lock(repo_id).await;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    let tree = _lease.guard(git_read::read_tree(&state, repo_id, Some(&oid), &rel_path, after, limit)).await??;

    _lease.ensure_active()?;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    Ok(json_ok(tree))
}

pub async fn get_blob(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<BlobQuery>,
    Extension(actor): Extension<Identity>,
) -> Result<Response, Error> {
    let clean_path = models::normalize_rel_path(query.path.as_deref())?;
    if clean_path.is_empty() {
        let Some(ref oid) = query.oid else {
            return Err(Error::bad_request());
        };
        if !models::valid_non_zero_oid(oid) {
            return Err(Error::bad_request());
        }
    } else if let Some(ref spec) = query.oid {
        if !models::valid_revision_spec(spec) {
            return Err(Error::bad_request());
        }
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo(&tx, &actor, &owner, &name, false).await?;

    auth::finish_tx(tx, &actor, false).await?;
    drop(client);
    let _permit = acquire_git_slot(&state)?;
    let _lease = crate::storage::read_leases::shared(&state.pool, repo_id,
        tokio::time::Instant::now() + state.config.git_timeout).await?;
    let _snapshot = state.storage.read_snapshot_lock(repo_id).await;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    let blob = _lease.guard(git_read::read_blob(
        &state, repo_id, query.oid.as_deref(), query.path.as_deref())).await??;

    _lease.ensure_active()?;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    Ok(json_ok(blob))
}

pub async fn get_blob_by_oid(
    State(state): State<Arc<AppState>>,
    Path((owner, name, oid)): Path<(String, String, String)>,
    Query(query): Query<BlobByOidQuery>,
    Extension(actor): Extension<Identity>,
) -> Result<Response, Error> {
    let clean_path = models::normalize_rel_path(query.path.as_deref())?;
    if clean_path.is_empty() {
        if !models::valid_non_zero_oid(&oid) {
            return Err(Error::bad_request());
        }
    } else if !models::valid_revision_spec(&oid) {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo(&tx, &actor, &owner, &name, false).await?;

    auth::finish_tx(tx, &actor, false).await?;
    drop(client);
    let _permit = acquire_git_slot(&state)?;
    let _lease = crate::storage::read_leases::shared(&state.pool, repo_id,
        tokio::time::Instant::now() + state.config.git_timeout).await?;
    let _snapshot = state.storage.read_snapshot_lock(repo_id).await;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    let blob = _lease.guard(git_read::read_blob(&state, repo_id, Some(&oid), query.path.as_deref())).await??;

    _lease.ensure_active()?;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    Ok(json_ok(blob))
}

pub async fn compare_commits(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<CompareQuery>,
    Extension(actor): Extension<Identity>,
) -> Result<Response, Error> {
    if !models::valid_revision_spec(&query.base) || !models::valid_revision_spec(&query.head) {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo(&tx, &actor, &owner, &name, false).await?;

    auth::finish_tx(tx, &actor, false).await?;
    drop(client);
    let _permit = acquire_git_slot(&state)?;
    let _lease = crate::storage::read_leases::shared(&state.pool, repo_id,
        tokio::time::Instant::now() + state.config.git_timeout).await?;
    let _snapshot = state.storage.read_snapshot_lock(repo_id).await;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    let comparison = _lease.guard(git_read::compare_commits(
        &state, repo_id, &query.base, &query.head)).await??;

    _lease.ensure_active()?;
    auth::verify_active(&state.pool, &actor, repo_id, false).await?;
    Ok(json_ok(comparison))
}

pub async fn get_storage_route(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<StorageRouteQuery>,
    Extension(actor): Extension<Identity>,
) -> Result<Response, Error> {
    let requested_operation = query.validate()?.to_owned();
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id: Uuid = auth::authorize_repo(&tx, &actor, &owner, &name, false).await?;
    let row = tx
        .query_one(
            "SELECT r.name, r.state, r.storage_backend, r.storage_generation, ns.slug AS username \
             FROM repositories r JOIN namespaces ns ON ns.id = r.owner_id WHERE r.id = $1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?;
    let status = crate::forge::build_backend_status(
        &state,
        repo_id,
        row.get("username"),
        row.get("name"),
        row.get("state"),
        row.get::<_, &str>("storage_backend"),
        row.get("storage_generation"),
    );
    auth::finish_tx(tx, &actor, false).await?;
    let selected_backend = if matches!(requested_operation.as_str(), "write" | "git-receive-pack") {
        status.write_backend.clone()
    } else {
        status.read_backend.clone()
    };
    Ok(json_ok(StorageRouteResponse {
        repository_id: status.repository_id,
        owner: status.owner,
        name: status.name,
        storage_backend: status.storage_backend,
        storage_generation: status.storage_generation,
        state: status.state,
        gateway_route: status.gateway_route,
        read_backend: status.read_backend,
        write_backend: status.write_backend,
        requested_operation,
        selected_backend,
        write_paused: status.write_paused,
        pando_ready: status.pando_ready,
        gitfs_ready: status.gitfs_ready,
    }))
}
