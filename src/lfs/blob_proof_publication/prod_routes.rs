//! Production `crate::lfs::routes()` (`AppState`) S4 streaming HTTP bridge (`Refs #145`).

use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::{StreamExt, stream};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::{
    AppState, Error, auth,
    lfs::{
        handlers::{reauthorize_repo, sanitize_headers},
        models::{self, BatchObjectSpec, BatchRequest},
    },
    token_scopes::RepoAction,
};

use super::authz::{LfsBlobRuntimeGate, extract_stable_operation_id};
use super::locks_store::InFlightUploadGuard;
use super::pg_store::PgLfsBlobStore;
pub(crate) use super::prod_publication::{active_push_quarantine_dirs, enforce_blob_gate_if_requested, to_app_error};
use super::prod_publication::{
    build_base_url, collect_forwarded_action_headers, ephemeral_scratch_root, lfs_blob_err_response, lfs_blob_json,
};
pub use super::prod_publication::{
    PushAttestationSession, active_blob_gate, prod_validate_and_attest_hook, prod_validate_and_attest_push,
    set_runtime_gate_override, with_push_attestation_session,
};
use super::transfer::{
    LfsTransferContext, PreStreamedScratch, acquire_transfer_permit, open_verified_remote_download_file,
    process_batch_request, upload_streamed_lfs_object_to_remote, verify_lfs_object_remote,
};
use super::types::{LfsBlobError, LfsProofRejectCode};

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
    Box<Response>,
> {
    if let Err(e) = gate.require_store() {
        return Err(Box::new(lfs_blob_err_response(e)));
    }
    let clean_headers = sanitize_headers(headers);
    let actor = auth::authenticate(&state.pool, &clean_headers).await.map_err(|e| Box::new(e.into_response()))?;
    if write {
        auth::writable(&actor).map_err(|e| Box::new(e.into_response()))?;
    }
    let name = models::normalize_repo_name(repo_raw).map_err(|e| Box::new(e.into_response()))?;
    let repo_lookup = state
        .pool
        .get()
        .await
        .map_err(|e| Box::new(Error::internal(e).into_response()))?
        .query_opt(
            "SELECT r.id, r.owner_id FROM repositories r JOIN namespaces ns ON ns.id = r.owner_id
             WHERE ns.slug = $1 AND r.name = $2 AND r.deleted_at IS NULL",
            &[&owner, &name],
        )
        .await
        .map_err(|e| Box::new(Error::internal(e).into_response()))?
        .ok_or_else(|| Box::new(Error::not_found().into_response()))?;
    let lookup_repo_id: Uuid = repo_lookup.get(0);
    let lookup_tenant_id: Uuid = repo_lookup.get(1);

    let pg = PgLfsBlobStore::new(state.pool.clone());
    let realm = match pg.ensure_realm_for_repository(lookup_repo_id, &state.storage.root).await {
        Ok(r) => r,
        Err(e) => return Err(Box::new(lfs_blob_err_response(e))),
    };
    if write {
        let stale_window = state.config.git_timeout.max(std::time::Duration::from_secs(5));
        if let Err(e) = pg.reconcile_stale_pending_uploads(realm.repository_id, stale_window).await {
            return Err(Box::new(lfs_blob_err_response(e)));
        }
    }
    let auth_access = match pg.resolve_authoritative_repo_access(&realm, actor.id, &actor.username, write, false).await
    {
        Ok(a) => a,
        Err(e) => return Err(Box::new(lfs_blob_err_response(e))),
    };
    let (repo_id, tenant_id) = {
        let mut client = state.pool.get().await.map_err(|e| Box::new(Error::internal(e).into_response()))?;
        let tx = client.transaction().await.map_err(|e| Box::new(Error::internal(e).into_response()))?;
        let access = auth::authorize_repo_with_role(
            &tx,
            &actor,
            owner,
            name,
            if write { auth::Role::Write } else { auth::Role::Read },
            if write { RepoAction::ContentsWrite } else { RepoAction::ContentsRead },
        )
        .await
        .map_err(|e| Box::new(e.into_response()))?;
        auth::finish_tx(tx, &actor, false).await.map_err(|e| Box::new(e.into_response()))?;
        (access.repo_id, access.owner_id)
    };
    if repo_id != lookup_repo_id || tenant_id != lookup_tenant_id || realm.owner_tenant_id != tenant_id {
        return Err(Box::new(Error(StatusCode::CONFLICT, "repository identity changed").into_response()));
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
    let _permit = match acquire_transfer_permit(state.config.git_timeout).await {
        Ok(p) => p,
        Err(e) => return Ok(lfs_blob_err_response(e)),
    };
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
            Err(early) => return Ok(*early),
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
    let _permit = match acquire_transfer_permit(state.config.git_timeout).await {
        Ok(p) => p,
        Err(e) => return Ok(lfs_blob_err_response(e)),
    };
    let op_id = match extract_stable_operation_id(&headers) {
        Ok(v) => v,
        Err(e) => return Ok(lfs_blob_err_response(e)),
    };
    let (actor, name, pg, realm, access) =
        match auth_and_prepare_prod(&state, &gate, &headers, &owner, &repo_raw, true).await {
            Ok(t) => t,
            Err(early) => return Ok(*early),
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
    let content_len_opt = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    if content_len_opt.is_some_and(|cl| cl > state.config.max_request_bytes) {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "request size limit exceeded"));
    }
    let declared_size: Option<i64> = size_param.or_else(|| content_len_opt.and_then(|cl| i64::try_from(cl).ok()));

    let repo_id = realm.repository_id;
    let tenant_id = realm.owner_tenant_id;
    if let (Some(explicit_op), Some(decl_sz)) = (op_id, declared_size)
        && let Err(e) = pg
            .begin_or_load_upload_operation(repo_id, explicit_op, tenant_id, actor.id, &oid, decl_sz)
            .await
    {
        return Ok(lfs_blob_err_response(e));
    }
    let attempt_id = Uuid::new_v4();
    let attempt_res = pg
        .record_upload_attempt_start(attempt_id, tenant_id, repo_id, actor.id, &oid, declared_size.unwrap_or(0))
        .await;
    if let Err(e) = attempt_res {
        return Ok(lfs_blob_err_response(e));
    }

    let scratch = ephemeral_scratch_root();
    fs::create_dir_all(&scratch).await.map_err(Error::internal)?;
    let scratch_path = scratch.join(format!(".lfs-stream-up-{}.tmp", Uuid::new_v4()));
    let mut upload_guard = InFlightUploadGuard::new(pg.clone(), repo_id, attempt_id, op_id, scratch_path.clone());
    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    {
        let std_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&scratch_path)
            .map_err(Error::internal)?;
        let mut out_file = fs::File::from_std(std_file);
        let mut data_stream = body.into_data_stream();
        while let Some(chunk_res) = data_stream.next().await {
            let Some(chunk) = chunk_res.ok() else {
                upload_guard.abort_now("upload_stream_error_or_oversize").await;
                return Err(Error::bad_request());
            };
            written = written.saturating_add(chunk.len() as u64);
            if written > state.config.max_request_bytes {
                upload_guard.abort_now("upload_stream_error_or_oversize").await;
                return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "request size limit exceeded"));
            }
            hasher.update(&chunk);
            out_file.write_all(&chunk).await.map_err(Error::internal)?;
        }
        out_file.sync_all().await.map_err(Error::internal)?;
    }

    let expected_size = size_param.unwrap_or(written as i64);
    let streamed = PreStreamedScratch {
        path: scratch_path,
        size_bytes: written as i64,
        sha256_hex: hex::encode(hasher.finalize()),
        pre_attempt_id: Some(attempt_id),
    };
    let ctx = LfsTransferContext {
        gate: &gate,
        pg: &pg,
        realm: &realm,
        access: &access,
        scratch_dir: &scratch,
        timeout: state.config.git_timeout,
    };
    let committed = match upload_streamed_lfs_object_to_remote(&ctx, op_id, &oid, expected_size, &streamed).await {
        Ok(c) => c,
        Err(e) => {
            upload_guard.abort_now(&e.message).await;
            return Ok(lfs_blob_err_response(e));
        }
    };
    upload_guard.mark_committed();
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
    let _permit = match acquire_transfer_permit(state.config.git_timeout).await {
        Ok(p) => p,
        Err(e) => return Ok(lfs_blob_err_response(e)),
    };
    models::check_lfs_json_headers(&headers)?;
    let op_id = match extract_stable_operation_id(&headers) {
        Ok(v) => v,
        Err(e) => return Ok(lfs_blob_err_response(e)),
    };
    let spec: BatchObjectSpec = serde_json::from_slice(&body).map_err(|_| Error::bad_request())?;
    let (actor, name, pg, realm, access) =
        match auth_and_prepare_prod(&state, &gate, &headers, &owner, &repo_raw, true).await {
            Ok(t) => t,
            Err(early) => return Ok(*early),
        };
    if let Some(id) = op_id {
        match pg.load_upload_operation(realm.repository_id, id).await {
            Ok(Some(saved))
                if saved.state != "committed"
                    || saved.tenant_id != realm.owner_tenant_id
                    || saved.actor_id != actor.id
                    || saved.oid_sha256 != spec.oid
                    || saved.size_bytes != spec.size =>
            {
                return Ok(lfs_blob_err_response(LfsBlobError::new(
                    LfsProofRejectCode::AttestationEquivocation,
                    "verify operation_id is uncommitted or conflicts with current tenant or upload operation record",
                )));
            }
            Ok(_) => {}
            Err(e) => return Ok(lfs_blob_err_response(e)),
        }
    }
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
    let permit = match acquire_transfer_permit(state.config.git_timeout).await {
        Ok(p) => p,
        Err(e) => return Ok(lfs_blob_err_response(e)),
    };
    let (actor, name, pg, realm, access) =
        match auth_and_prepare_prod(&state, &gate, &headers, &owner, &repo_raw, false).await {
            Ok(t) => t,
            Err(early) => return Ok(*early),
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
    let (file, guard, expected_len) = match open_verified_remote_download_file(&ctx, &oid, size_param).await {
        Ok(t) => t,
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
    let body_stream = stream::try_unfold((file, guard, permit), |(mut f, g, p)| async move {
        let mut buf = vec![0u8; 64 * 1024];
        let n = f.read(&mut buf).await?;
        if n == 0 {
            return Ok::<_, std::io::Error>(None);
        }
        buf.truncate(n);
        Ok(Some((Bytes::from(buf), (f, g, p))))
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, expected_len.to_string())
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .header("x-lfs-oid", &oid)
        .header(header::CONNECTION, "close")
        .body(Body::from_stream(body_stream))
        .map_err(Error::internal)
}
