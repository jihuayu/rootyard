//! Production `crate::lfs::routes()` (`AppState`) S4 remote-Blob HTTP bridge (`Refs #145`).

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};

use axum::{
    Json,
    body::{Body, Bytes},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState, Error, auth,
    lfs::{
        handlers::{reauthorize_repo, sanitize_headers},
        models::{self, BatchObjectSpec, BatchRequest, LFS_MEDIA_TYPE},
    },
    token_scopes::RepoAction,
};

use super::authz::{LfsBlobRuntimeGate, extract_stable_operation_id};
use super::pg_store::PgLfsBlobStore;
pub(crate) use super::prod_publication::active_push_quarantine_dirs;
use super::prod_publication::ephemeral_scratch_root;
pub use super::prod_publication::{PushAttestationSession, prod_validate_and_attest_push, with_push_attestation_session};
use super::transfer::{
    LfsTransferContext, download_lfs_object_from_remote, process_batch_request, upload_lfs_object_to_remote,
    verify_lfs_object_remote,
};
use super::types::{LfsBlobError, LfsProofRejectCode};

static GATE_OVERRIDE: OnceLock<RwLock<Option<LfsBlobRuntimeGate>>> = OnceLock::new();

fn gate_slot() -> &'static RwLock<Option<LfsBlobRuntimeGate>> {
    GATE_OVERRIDE.get_or_init(|| RwLock::new(None))
}

pub fn set_runtime_gate_override(gate: Option<LfsBlobRuntimeGate>) {
    *gate_slot().write().unwrap_or_else(|e| e.into_inner()) = gate;
}

pub fn active_blob_gate() -> Option<LfsBlobRuntimeGate> {
    if let Some(g) = gate_slot().read().unwrap_or_else(|e| e.into_inner()).clone() {
        return Some(g);
    }
    LfsBlobRuntimeGate::blob_mode_requested().then(LfsBlobRuntimeGate::from_env_gate)
}

pub(crate) fn enforce_blob_gate_if_requested() -> Result<Option<LfsBlobRuntimeGate>, Error> {
    let Some(gate) = active_blob_gate() else {
        return Ok(None);
    };
    let _ = gate.require_store().map_err(to_app_error)?;
    Ok(Some(gate))
}

pub(crate) fn to_app_error(err: LfsBlobError) -> Error {
    Error(err.code.http_status(), err.code.as_str())
}

fn lfs_blob_json(status: StatusCode, payload: impl Serialize) -> Response {
    let mut res = (status, Json(payload)).into_response();
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(LFS_MEDIA_TYPE));
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res.headers_mut().insert(HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff"));
    res.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    if status == StatusCode::UNAUTHORIZED {
        res.headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"Rootyard\", charset=\"UTF-8\""));
    }
    res
}

fn lfs_blob_err_response(err: LfsBlobError) -> Response {
    lfs_blob_json(
        err.code.http_status(),
        json!({ "code": err.code.as_str(), "error": err.code.as_str(), "message": err.message }),
    )
}

fn build_base_url(headers: &HeaderMap) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.eq_ignore_ascii_case("https"))
        .map(|_| "https")
        .unwrap_or("http");
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()).map(str::trim).filter(|h| !h.is_empty())
    else {
        return String::new();
    };
    format!("{scheme}://{host}")
}

fn collect_forwarded_action_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(auth_val) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        out.insert("Authorization".to_owned(), auth_val.to_owned());
    }
    for name in ["X-Rootyard-Operation-Id", "Idempotency-Key"] {
        if let Some(val) = headers.get(name).and_then(|v| v.to_str().ok()) {
            out.insert(name.to_owned(), val.to_owned());
        }
    }
    out
}

async fn auth_and_prepare_prod(
    state: &Arc<AppState>,
    gate: &LfsBlobRuntimeGate,
    headers: &HeaderMap,
    owner: &str,
    repo_raw: &str,
    write: bool,
) -> Result<
    (
        crate::db::Identity,
        String,
        PgLfsBlobStore,
        super::pg_store::LfsRepoRealm,
        super::authz::AuthorizedRepoAccess,
    ),
    Result<Response, Error>,
> {
    if let Err(e) = gate.require_store() {
        return Err(Ok(lfs_blob_err_response(e)));
    }
    let clean_headers = sanitize_headers(headers);
    let actor = auth::authenticate(&state.pool, &clean_headers).await.map_err(Err)?;
    if write {
        auth::writable(&actor).map_err(Err)?;
    }
    let name = models::normalize_repo_name(repo_raw).map_err(Err)?;
    let repo_lookup = state
        .pool
        .get()
        .await
        .map_err(|e| Err(Error::internal(e)))?
        .query_opt(
            "SELECT r.id, r.owner_id FROM repositories r JOIN namespaces ns ON ns.id = r.owner_id
             WHERE ns.slug = $1 AND r.name = $2 AND r.deleted_at IS NULL",
            &[&owner, &name],
        )
        .await
        .map_err(|e| Err(Error::internal(e)))?
        .ok_or_else(|| Err(Error::not_found()))?;
    let lookup_repo_id: Uuid = repo_lookup.get(0);
    let lookup_tenant_id: Uuid = repo_lookup.get(1);

    let pg = PgLfsBlobStore::new(state.pool.clone());
    let realm = match pg.ensure_realm_for_repository(lookup_repo_id, &state.storage.root).await {
        Ok(r) => r,
        Err(e) => return Err(Ok(lfs_blob_err_response(e))),
    };
    let auth_access = match pg.resolve_authoritative_repo_access(&realm, actor.id, &actor.username, write, false).await
    {
        Ok(a) => a,
        Err(e) => return Err(Ok(lfs_blob_err_response(e))),
    };
    let (repo_id, tenant_id) = {
        let mut client = state.pool.get().await.map_err(|e| Err(Error::internal(e)))?;
        let tx = client.transaction().await.map_err(|e| Err(Error::internal(e)))?;
        let access = auth::authorize_repo_with_role(
            &tx,
            &actor,
            owner,
            name,
            if write { auth::Role::Write } else { auth::Role::Read },
            if write { RepoAction::ContentsWrite } else { RepoAction::ContentsRead },
        )
        .await
        .map_err(Err)?;
        auth::finish_tx(tx, &actor, false).await.map_err(Err)?;
        (access.repo_id, access.owner_id)
    };
    if repo_id != lookup_repo_id || tenant_id != lookup_tenant_id || realm.owner_tenant_id != tenant_id {
        return Err(Err(Error(StatusCode::CONFLICT, "repository identity changed")));
    }
    Ok((actor, name.to_owned(), pg, realm, auth_access))
}

pub(crate) async fn prod_delete_refused(gate: LfsBlobRuntimeGate) -> Result<Response, Error> {
    if let Err(e) = gate.require_store() {
        return Ok(lfs_blob_err_response(e));
    }
    Ok(lfs_blob_err_response(LfsBlobError::new(
        LfsProofRejectCode::DeleteDisabledByPolicy,
        "physical LFS object DELETE is disabled until safe GC (#122)",
    )))
}

pub(crate) async fn prod_batch(
    gate: LfsBlobRuntimeGate,
    state: Arc<AppState>,
    owner: String,
    repo_raw: String,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    if let Err(e) = gate.require_store() {
        return Ok(lfs_blob_err_response(e));
    }
    models::check_lfs_json_headers(&headers)?;
    let req: BatchRequest = serde_json::from_slice(&body).map_err(|_| Error::bad_request())?;
    let write = match req.operation.as_str() {
        "upload" => true,
        "download" => false,
        _ => return Err(Error::bad_request()),
    };
    if let Err(e) = extract_stable_operation_id(&headers) {
        return Ok(lfs_blob_err_response(e));
    }
    let (actor, name, pg, realm, access) =
        match auth_and_prepare_prod(&state, &gate, &headers, &owner, &repo_raw, write).await {
            Ok(t) => t,
            Err(early) => return early,
        };
    let scratch = ephemeral_scratch_root();
    let ctx = LfsTransferContext {
        gate: &gate,
        pg: &pg,
        realm: &realm,
        access: &access,
        scratch_dir: &scratch,
        timeout: state.config.git_timeout,
    };
    let base_url = build_base_url(&headers);
    let action_headers = collect_forwarded_action_headers(&sanitize_headers(&headers));
    let batch_resp = match process_batch_request(&ctx, &base_url, &action_headers, &req).await {
        Ok(r) => r,
        Err(e) => return Ok(lfs_blob_err_response(e)),
    };
    reauthorize_repo(
        &state,
        &actor,
        &owner,
        &name,
        realm.repository_id,
        realm.owner_tenant_id,
        if write { auth::Role::Write } else { auth::Role::Read },
        if write { RepoAction::ContentsWrite } else { RepoAction::ContentsRead },
        write,
    )
    .await?;
    Ok(lfs_blob_json(StatusCode::OK, batch_resp))
}

pub(crate) async fn prod_upload(
    gate: LfsBlobRuntimeGate,
    state: Arc<AppState>,
    owner: String,
    repo_raw: String,
    oid: String,
    size_param: Option<i64>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    if let Err(e) = gate.require_store() {
        return Ok(lfs_blob_err_response(e));
    }
    let op_id = match extract_stable_operation_id(&headers) {
        Ok(v) => v,
        Err(e) => return Ok(lfs_blob_err_response(e)),
    };
    let (actor, name, pg, realm, access) =
        match auth_and_prepare_prod(&state, &gate, &headers, &owner, &repo_raw, true).await {
            Ok(t) => t,
            Err(early) => return early,
        };
    if !models::valid_lfs_oid(&oid) {
        return Ok(lfs_blob_err_response(LfsBlobError::new(
            LfsProofRejectCode::MalformedLfsPointer,
            "invalid LFS oid",
        )));
    }
    if let Some(sz) = size_param {
        if sz < 0 {
            return Ok(lfs_blob_err_response(LfsBlobError::new(
                LfsProofRejectCode::SizeOrDigestMismatch,
                "negative LFS size",
            )));
        }
        if sz as u64 > state.config.max_request_bytes {
            return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "request size limit exceeded"));
        }
    }
    let mut payload = Vec::new();
    let mut stream = body.into_data_stream();
    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.map_err(|_| Error::bad_request())?;
        if (payload.len() as u64).saturating_add(chunk.len() as u64) > state.config.max_request_bytes {
            return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "request size limit exceeded"));
        }
        payload.extend_from_slice(&chunk);
    }
    let expected_size = size_param.unwrap_or(payload.len() as i64);
    let scratch = ephemeral_scratch_root();
    let ctx = LfsTransferContext {
        gate: &gate,
        pg: &pg,
        realm: &realm,
        access: &access,
        scratch_dir: &scratch,
        timeout: state.config.git_timeout,
    };
    let committed = match upload_lfs_object_to_remote(&ctx, op_id, &oid, expected_size, &payload).await {
        Ok(c) => c,
        Err(e) => return Ok(lfs_blob_err_response(e)),
    };
    reauthorize_repo(
        &state,
        &actor,
        &owner,
        &name,
        realm.repository_id,
        realm.owner_tenant_id,
        auth::Role::Write,
        RepoAction::ContentsWrite,
        true,
    )
    .await?;
    state.transfer_metrics.record_success();
    Ok(lfs_blob_json(
        StatusCode::OK,
        json!({
            "oid": committed.oid_sha256,
            "size": committed.size_bytes,
            "state": "ready",
            "hold_id": committed.hold_id,
            "locator_attempt_id": committed.locator.attempt_id,
        }),
    ))
}

pub(crate) async fn prod_verify(
    gate: LfsBlobRuntimeGate,
    state: Arc<AppState>,
    owner: String,
    repo_raw: String,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Error> {
    if let Err(e) = gate.require_store() {
        return Ok(lfs_blob_err_response(e));
    }
    models::check_lfs_json_headers(&headers)?;
    let spec: BatchObjectSpec = serde_json::from_slice(&body).map_err(|_| Error::bad_request())?;
    let (actor, name, pg, realm, access) =
        match auth_and_prepare_prod(&state, &gate, &headers, &owner, &repo_raw, true).await {
            Ok(t) => t,
            Err(early) => return early,
        };
    let scratch = ephemeral_scratch_root();
    let ctx = LfsTransferContext {
        gate: &gate,
        pg: &pg,
        realm: &realm,
        access: &access,
        scratch_dir: &scratch,
        timeout: state.config.git_timeout,
    };
    if let Err(e) = verify_lfs_object_remote(&ctx, &spec.oid, spec.size).await {
        return Ok(lfs_blob_err_response(e));
    }
    reauthorize_repo(
        &state,
        &actor,
        &owner,
        &name,
        realm.repository_id,
        realm.owner_tenant_id,
        auth::Role::Write,
        RepoAction::ContentsWrite,
        true,
    )
    .await?;
    Ok(lfs_blob_json(StatusCode::OK, json!({ "oid": spec.oid, "size": spec.size, "verified": true })))
}

pub(crate) async fn prod_download(
    gate: LfsBlobRuntimeGate,
    state: Arc<AppState>,
    owner: String,
    repo_raw: String,
    oid: String,
    size_param: Option<i64>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    if let Err(e) = gate.require_store() {
        return Ok(lfs_blob_err_response(e));
    }
    let (actor, name, pg, realm, access) =
        match auth_and_prepare_prod(&state, &gate, &headers, &owner, &repo_raw, false).await {
            Ok(t) => t,
            Err(early) => return early,
        };
    let scratch = ephemeral_scratch_root();
    let ctx = LfsTransferContext {
        gate: &gate,
        pg: &pg,
        realm: &realm,
        access: &access,
        scratch_dir: &scratch,
        timeout: state.config.git_timeout,
    };
    let bytes = match download_lfs_object_from_remote(&ctx, &oid, size_param).await {
        Ok(b) => b,
        Err(e) => return Ok(lfs_blob_err_response(e)),
    };
    reauthorize_repo(
        &state,
        &actor,
        &owner,
        &name,
        realm.repository_id,
        realm.owner_tenant_id,
        auth::Role::Read,
        RepoAction::ContentsRead,
        false,
    )
    .await?;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("x-lfs-oid", &oid)
        .header(header::CONNECTION, "close")
        .body(Body::from(bytes))
        .map_err(Error::internal)
}
