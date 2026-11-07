//! Streaming Git LFS upload and admission diagnostics.
use super::handlers::{lfs_json, sanitize_headers};
use crate::{
    AppState, Error, auth,
    lfs::{models, storage},
};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};
use uuid::Uuid;

static UPLOAD_WAITERS: OnceLock<Mutex<HashMap<Uuid, usize>>> = OnceLock::new();
fn waiters() -> &'static Mutex<HashMap<Uuid, usize>> {
    UPLOAD_WAITERS.get_or_init(|| Mutex::new(HashMap::new()))
}
struct UploadWaiter(Uuid);
impl UploadWaiter {
    fn new(id: Uuid) -> Self {
        *waiters().lock().unwrap().entry(id).or_default() += 1;
        Self(id)
    }
}
impl Drop for UploadWaiter {
    fn drop(&mut self) {
        let mut guard = waiters().lock().unwrap();
        if let Some(count) = guard.get_mut(&self.0) {
            *count -= 1;
            if *count == 0 {
                guard.remove(&self.0);
            }
        }
    }
}

/// Read-only diagnostic used to prove a request passed metadata authorization
/// and is queued behind the repository publication lock.
pub async fn upload_waiters(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let name = models::normalize_repo_name(&repo_raw)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, name, auth::Role::Admin, crate::token_scopes::RepoAction::RepoRead).await?;
    let count = *waiters().lock().unwrap().get(&access.repo_id).unwrap_or(&0);
    auth::finish_tx(tx, &actor, false).await?;
    Ok(lfs_json(StatusCode::OK, serde_json::json!({"waiters":count})))
}

pub async fn upload_object(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw, oid)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    tokio::spawn(async move { upload_inner(state, owner, repo_raw, oid, None, headers, body).await })
        .await
        .map_err(Error::internal)?
}

pub async fn upload_object_with_size(
    State(state): State<Arc<AppState>>,
    Path((owner, repo_raw, oid, size)): Path<(String, String, String, i64)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    tokio::spawn(async move { upload_inner(state, owner, repo_raw, oid, Some(size), headers, body).await })
        .await
        .map_err(Error::internal)?
}

async fn upload_inner(
    state: Arc<AppState>,
    owner: String,
    repo_raw: String,
    oid: String,
    size_param: Option<i64>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    let headers = sanitize_headers(&headers);
    let actor = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&actor)?;
    let name = models::normalize_repo_name(&repo_raw)?;
    if !models::valid_lfs_oid(&oid) {
        return Err(Error(StatusCode::UNPROCESSABLE_ENTITY, "invalid LFS oid"));
    }
    if let Some(sz) = size_param {
        if sz < 0 {
            return Err(Error(StatusCode::UNPROCESSABLE_ENTITY, "invalid LFS size"));
        }
        if sz as u64 > state.config.max_request_bytes {
            return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "request size limit exceeded"));
        }
    }
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|cl| cl > state.config.max_request_bytes)
    {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "request size limit exceeded"));
    }

    let (repo_id, tenant_id, expected_size) = {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let access = auth::authorize_repo_with_role(&tx, &actor, &owner, name, auth::Role::Write, crate::token_scopes::RepoAction::ContentsWrite).await?;
        let (repo_id, tenant_id) = (access.repo_id, access.owner_id);
        let row = tx
            .query_opt(
                "SELECT size, state FROM lfs_objects WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3",
                &[&tenant_id, &repo_id, &oid],
            )
            .await
            .map_err(Error::internal)?;
        let expected = if let Some(r) = row {
            let db_size: i64 = r.get(0);
            if size_param.is_some_and(|sz| sz != db_size) {
                return Err(Error(StatusCode::UNPROCESSABLE_ENTITY, "LFS object size mismatch"));
            }
            db_size as u64
        } else if let Some(sz) = size_param {
            tx.execute(
                "INSERT INTO lfs_objects (tenant_id, repository_id, oid, size, state) VALUES ($1, $2, $3, $4, 'pending')",
                &[&tenant_id, &repo_id, &oid, &sz],
            )
            .await
            .map_err(Error::internal)?;
            sz as u64
        } else {
            return Err(Error::not_found());
        };
        auth::finish_tx(tx, &actor, true).await?;
        (repo_id, tenant_id, expected)
    };

    let waiter = UploadWaiter::new(repo_id);
    let _write_guard = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo_id))
        .await
        .map_err(|_| Error::timeout())?;
    drop(waiter);

    // The reservation snapshot predates the lock. A queued upload may now be
    // superseded by a completed upload or lose authorization while waiting.
    {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        auth::authorize_repo_with_role(&tx, &actor, &owner, name, auth::Role::Write, crate::token_scopes::RepoAction::ContentsWrite).await?;
        let row = tx
            .query_opt(
                "SELECT size, state FROM lfs_objects WHERE tenant_id=$1 AND repository_id=$2 AND oid=$3",
                &[&tenant_id, &repo_id, &oid],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
        let size: i64 = row.get("size");
        if size != expected_size as i64 {
            return Err(Error(StatusCode::CONFLICT, "LFS object reservation changed"));
        }
        if row.get::<_, &str>("state") == "ready"
            && storage::ensure_readable(
                &state.storage.root,
                repo_id,
                tenant_id,
                &oid,
                expected_size,
                tokio::time::Instant::now() + state.config.git_timeout,
            )
            .await
            .map_err(Error::internal)?
        {
            storage::schedule_remote_repair(
                state.storage.root.clone(),
                repo_id,
                tenant_id,
                oid.clone(),
                expected_size,
                state.config.git_timeout,
            );
            auth::finish_tx(tx, &actor, true).await?;
            return Ok(lfs_json(
                StatusCode::OK,
                serde_json::json!({ "oid": oid, "size": expected_size, "state": "ready" }),
            ));
        }
        auth::finish_tx(tx, &actor, true).await?;
    }

    storage::check_repo_quota(&state, repo_id, expected_size).await?;
    tokio::time::timeout(
        state.config.git_timeout,
        storage::stream_to_staging_and_publish(&state, repo_id, &oid, expected_size, body),
    )
    .await
    .map_err(|_| Error::timeout())??;
    storage::publish_remote(&state, repo_id, tenant_id, &oid, expected_size).await?;

    let finalize_res: Result<(), Error> = async {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let _ = auth::authorize_repo_with_role(&tx, &actor, &owner, name, auth::Role::Write, crate::token_scopes::RepoAction::ContentsWrite).await?;
        let updated = tx
            .execute(
                "UPDATE lfs_objects SET state = 'ready', updated_at = clock_timestamp() WHERE tenant_id = $1 AND repository_id = $2 AND oid = $3 AND size = $4",
                &[&tenant_id, &repo_id, &oid, &(expected_size as i64)],
            )
            .await
            .map_err(Error::internal)?;
        if updated != 1 {
            return Err(Error(StatusCode::CONFLICT, "LFS object reservation missing or modified"));
        }
        auth::finish_tx(tx, &actor, true).await
    }
    .await;

    if let Err(err) = finalize_res {
        // The OID path is immutable shared content. A request that lost its token
        // after publishing must never remove bytes another request committed.
        state.transfer_metrics.record_failure();
        return Err(err);
    }

    state.transfer_metrics.record_success();
    Ok(lfs_json(StatusCode::OK, serde_json::json!({ "oid": oid, "size": expected_size, "state": "ready" })))
}
