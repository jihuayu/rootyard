//! Standalone Axum LFS v1 Batch, Basic Transfer, Verify, and Locks router (`Refs #145`).

use std::collections::BTreeMap;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::lfs::models::{BatchObjectSpec, BatchRequest, LFS_MEDIA_TYPE};

use super::authz::{AuthorizedRepoAccess, LfsBlobRuntimeGate, LfsPrincipal, extract_credentials_header};
use super::git_smart_http::{
    handle_git_info_refs, handle_git_receive_pack, handle_git_upload_pack, handle_internal_pre_receive,
};
use super::locks_store::CreateLockOutcome;
use super::pg_store::{LfsRepoRealm, PgLfsBlobStore};
use super::transfer::{
    LfsTransferContext, download_lfs_object_from_remote, process_batch_request, upload_lfs_object_to_remote,
    verify_lfs_object_remote,
};
use super::types::{LfsBlobError, LfsProofRejectCode};

pub struct LfsBlobProofService {
    gate: RwLock<LfsBlobRuntimeGate>,
    pg: PgLfsBlobStore,
    scratch_dir: PathBuf,
    base_url: String,
    internal_secret: String,
    timeout: Duration,
}

impl LfsBlobProofService {
    pub fn new(
        gate: LfsBlobRuntimeGate,
        pg: PgLfsBlobStore,
        scratch_dir: PathBuf,
        base_url: String,
        timeout: Duration,
    ) -> Self {
        Self {
            gate: RwLock::new(gate),
            pg,
            scratch_dir,
            base_url,
            internal_secret: Uuid::new_v4().to_string(),
            timeout,
        }
    }

    pub fn set_gate(&self, gate: LfsBlobRuntimeGate) {
        *self.gate.write().unwrap_or_else(|e| e.into_inner()) = gate;
    }

    pub fn current_gate(&self) -> LfsBlobRuntimeGate {
        self.gate.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn pg(&self) -> &PgLfsBlobStore {
        &self.pg
    }

    pub fn scratch_dir(&self) -> &FsPath {
        &self.scratch_dir
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(super) fn internal_secret(&self) -> &str {
        &self.internal_secret
    }

    pub(super) async fn auth_repo(
        &self,
        headers: &HeaderMap,
        owner: &str,
        repo: &str,
        require_write: bool,
    ) -> Result<(LfsBlobRuntimeGate, LfsPrincipal, LfsRepoRealm, AuthorizedRepoAccess, String), LfsBlobError> {
        let gate = self.current_gate();
        let _ = gate.require_store()?;
        let (username, secret) = extract_credentials_header(headers)?;
        let principal = self.pg.authenticate_principal(&username, &secret).await?;
        let realm = self.pg.lookup_repo_by_slug(owner, repo).await?;
        let access = self.pg.authorize_repo_access(&realm, &principal, require_write, false).await?;
        let raw_auth = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        Ok((gate, principal, realm, access, raw_auth))
    }
}

pub(super) fn lfs_json_response(status: StatusCode, payload: impl serde::Serialize) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, LFS_MEDIA_TYPE),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONNECTION, "close"),
        ],
        Json(payload),
    )
        .into_response()
}

pub(super) fn lfs_err_response(err: LfsBlobError) -> Response {
    let status = err.code.http_status();
    let mut res = lfs_json_response(status, json!({ "code": err.code.as_str(), "message": err.message }));
    if status == StatusCode::UNAUTHORIZED {
        let _ = res.headers_mut().insert(header::WWW_AUTHENTICATE, "Basic realm=\"rootyard-lfs\"".parse().unwrap());
    }
    res
}

const MAX_LFS_HTTP_BODY_BYTES: usize = 64 * 1024 * 1024;

pub fn lfs_blob_proof_router(svc: Arc<LfsBlobProofService>) -> Router {
    let uploads = Router::new()
        .route("/{owner}/{repo}/info/lfs/objects/{oid}/{size}", put(handle_put_object_sized))
        .route("/{owner}/{repo}/info/lfs/objects/{oid}", put(handle_put_object_unsized))
        .route("/{owner}/{repo}/git-upload-pack", post(handle_git_upload_pack))
        .route("/{owner}/{repo}/git-receive-pack", post(handle_git_receive_pack))
        .layer(DefaultBodyLimit::max(MAX_LFS_HTTP_BODY_BYTES));

    Router::new()
        .route("/{owner}/{repo}/info/refs", get(handle_git_info_refs))
        .route("/{owner}/{repo}/info/lfs/objects/batch", post(handle_batch))
        .route("/{owner}/{repo}/info/lfs/verify", post(handle_verify))
        .route("/{owner}/{repo}/info/lfs/objects/{oid}", get(handle_get_object).post(handle_post_oid_or_verify))
        .route("/{owner}/{repo}/info/lfs/objects/{oid}/{size}", get(handle_get_object_sized))
        .route("/{owner}/{repo}/info/lfs/locks", get(handle_list_locks).post(handle_create_lock))
        .route("/{owner}/{repo}/info/lfs/locks/verify", post(handle_verify_locks))
        .route("/{owner}/{repo}/info/lfs/locks/{id}/unlock", post(handle_unlock))
        .route("/_internal/lfs-pre-receive", post(handle_internal_pre_receive))
        .merge(uploads)
        .with_state(svc)
}

async fn handle_batch(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Json(req): Json<BatchRequest>,
) -> Response {
    let write = req.operation == "upload";
    let (gate, _, realm, access, raw_auth) = match svc.auth_repo(&headers, &owner, &repo, write).await {
        Ok(t) => t,
        Err(e) => return lfs_err_response(e),
    };
    let ctx = LfsTransferContext {
        gate: &gate,
        pg: &svc.pg,
        realm: &realm,
        access: &access,
        scratch_dir: &svc.scratch_dir,
        timeout: svc.timeout,
    };
    match process_batch_request(&ctx, &svc.base_url, &raw_auth, &req).await {
        Ok(resp) => lfs_json_response(StatusCode::OK, resp),
        Err(e) => lfs_err_response(e),
    }
}

async fn handle_put_object_sized(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo, oid, size)): Path<(String, String, String, i64)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (gate, _, realm, access, _) = match svc.auth_repo(&headers, &owner, &repo, true).await {
        Ok(t) => t,
        Err(e) => return lfs_err_response(e),
    };
    let ctx = LfsTransferContext {
        gate: &gate,
        pg: &svc.pg,
        realm: &realm,
        access: &access,
        scratch_dir: &svc.scratch_dir,
        timeout: svc.timeout,
    };
    match upload_lfs_object_to_remote(&ctx, &oid, size, &body).await {
        Ok(_) => (StatusCode::OK, [(header::CONNECTION, "close")], Body::empty()).into_response(),
        Err(e) => lfs_err_response(e),
    }
}

async fn handle_put_object_unsized(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo, oid)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let size = body.len() as i64;
    handle_put_object_sized(State(svc), Path((owner, repo, oid, size)), headers, body).await
}

async fn handle_verify(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Json(spec): Json<BatchObjectSpec>,
) -> Response {
    let (gate, _, realm, access, _) = match svc.auth_repo(&headers, &owner, &repo, true).await {
        Ok(t) => t,
        Err(e) => return lfs_err_response(e),
    };
    let ctx = LfsTransferContext {
        gate: &gate,
        pg: &svc.pg,
        realm: &realm,
        access: &access,
        scratch_dir: &svc.scratch_dir,
        timeout: svc.timeout,
    };
    match verify_lfs_object_remote(&ctx, &spec.oid, spec.size).await {
        Ok(_) => lfs_json_response(StatusCode::OK, json!({})),
        Err(e) => lfs_err_response(e),
    }
}

async fn handle_post_oid_or_verify(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo, oid)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if oid == "verify" {
        let Ok(spec) = serde_json::from_slice::<BatchObjectSpec>(&body) else {
            return lfs_err_response(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "bad verify body"));
        };
        return handle_verify(State(svc), Path((owner, repo)), headers, Json(spec)).await;
    }
    lfs_err_response(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "unsupported object POST"))
}

async fn handle_get_object(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo, oid)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let (gate, _, realm, access, _) = match svc.auth_repo(&headers, &owner, &repo, false).await {
        Ok(t) => t,
        Err(e) => return lfs_err_response(e),
    };
    let ctx = LfsTransferContext {
        gate: &gate,
        pg: &svc.pg,
        realm: &realm,
        access: &access,
        scratch_dir: &svc.scratch_dir,
        timeout: svc.timeout,
    };
    match download_lfs_object_from_remote(&ctx, &oid).await {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream"), (header::CONNECTION, "close")],
            Body::from(bytes),
        )
            .into_response(),
        Err(e) => lfs_err_response(e),
    }
}

async fn handle_get_object_sized(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo, oid, _size)): Path<(String, String, String, i64)>,
    headers: HeaderMap,
) -> Response {
    handle_get_object(State(svc), Path((owner, repo, oid)), headers).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LockCreateBody {
    path: String,
    #[serde(rename = "ref")]
    _ref: Option<serde_json::Value>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockUnlockBody {
    #[serde(default)]
    force: bool,
    #[serde(rename = "ref")]
    _ref: Option<serde_json::Value>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockVerifyBody {
    cursor: Option<Uuid>,
    limit: Option<i64>,
    #[serde(rename = "ref")]
    _ref: Option<serde_json::Value>,
}

async fn handle_create_lock(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<LockCreateBody>,
) -> Response {
    let (_, _, _, access, _) = match svc.auth_repo(&headers, &owner, &repo, true).await {
        Ok(t) => t,
        Err(e) => return lfs_err_response(e),
    };
    match svc.pg.create_lock(&access, &body.path).await {
        Ok(CreateLockOutcome::Created(lock)) => lfs_json_response(StatusCode::CREATED, json!({ "lock": lock })),
        Ok(CreateLockOutcome::AlreadyLocked(lock)) => {
            lfs_json_response(StatusCode::CONFLICT, json!({ "message": "path is already locked", "lock": lock }))
        }
        Err(e) => lfs_err_response(e),
    }
}

async fn handle_list_locks(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo)): Path<(String, String)>,
    Query(q): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let (_, _, realm, _, _) = match svc.auth_repo(&headers, &owner, &repo, false).await {
        Ok(t) => t,
        Err(e) => return lfs_err_response(e),
    };
    let path_filter = q.get("path").map(String::as_str);
    let id_filter = q.get("id").and_then(|s| Uuid::parse_str(s).ok());
    let cursor = q.get("cursor").and_then(|s| Uuid::parse_str(s).ok());
    let limit = q.get("limit").and_then(|s| s.parse::<i64>().ok()).unwrap_or(100);
    match svc.pg.list_locks(realm.repository_id, path_filter, id_filter, cursor, limit).await {
        Ok((locks, Some(nc))) => lfs_json_response(StatusCode::OK, json!({ "locks": locks, "next_cursor": nc })),
        Ok((locks, None)) => lfs_json_response(StatusCode::OK, json!({ "locks": locks })),
        Err(e) => lfs_err_response(e),
    }
}

async fn handle_verify_locks(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo)): Path<(String, String)>,
    headers: HeaderMap,
    raw: Bytes,
) -> Response {
    let (_, _, _, access, _) = match svc.auth_repo(&headers, &owner, &repo, true).await {
        Ok(t) => t,
        Err(e) => return lfs_err_response(e),
    };
    let input = if raw.is_empty() {
        LockVerifyBody::default()
    } else {
        match serde_json::from_slice::<LockVerifyBody>(&raw) {
            Ok(v) => v,
            Err(_) => return lfs_err_response(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "bad locks verify JSON")),
        }
    };
    match svc.pg.verify_locks(&access, input.cursor, input.limit.unwrap_or(100)).await {
        Ok(report) => lfs_json_response(StatusCode::OK, report),
        Err(e) => lfs_err_response(e),
    }
}

async fn handle_unlock(
    State(svc): State<Arc<LfsBlobProofService>>,
    Path((owner, repo, id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
    raw: Bytes,
) -> Response {
    let (_, _, _, access, _) = match svc.auth_repo(&headers, &owner, &repo, true).await {
        Ok(t) => t,
        Err(e) => return lfs_err_response(e),
    };
    let body = if raw.is_empty() {
        LockUnlockBody::default()
    } else {
        match serde_json::from_slice::<LockUnlockBody>(&raw) {
            Ok(v) => v,
            Err(_) => return lfs_err_response(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "bad unlock JSON")),
        }
    };
    match svc.pg.unlock(&access, id, body.force).await {
        Ok(lock) => lfs_json_response(StatusCode::OK, json!({ "lock": lock })),
        Err(e) => lfs_err_response(e),
    }
}
