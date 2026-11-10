//! Smart-HTTP `info/refs` and `git-upload-pack`.
//!
//! Advertisements come from the real temporary view / sealed snapshot refs.
//! `git-upload-pack` itself runs as one bounded native child against that view
//! and is streamed to the client; the child and the view are killed/removed when
//! the response completes, fails or is cancelled.
//!
//! Authentication at request start is not reused as the final read allow. After
//! Blob materialization (and, for the write advertisement, immediately before
//! the first byte) the current token, RBAC, contents-read scope, ready binding
//! and actually opened Blob backend are checked again. The upload stream carries
//! that same guard so the native worker can re-check it independently of a slow
//! client; an authorization failure aborts the stream while a ref advance under
//! the unchanged realm leaves the older captured view valid.
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::Response,
};

use super::{
    error::GatewayError,
    native,
    serving::lookup,
    session::{authenticate, authority_error, git_protocol, read_authorization, validate_git_protocol},
    snapshot::{self, service_prefix},
    state::BlobGitState,
};
use crate::ref_store::serving::ServingRepository;

pub(super) async fn info_refs(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let name = repository_name(&raw_name)?;
    let service = match uri.query() {
        Some("service=git-upload-pack") => "git-upload-pack",
        Some("service=git-receive-pack") => "git-receive-pack",
        _ => return Err(GatewayError::BadRequest("invalid Git service advertisement request")),
    };
    validate_git_protocol(&headers)?;
    let identity = authenticate(&state, &headers).await?;
    let deadline = state.deadline();
    let _slot = state.slot().await?;
    let writable = service == "git-receive-pack";
    let serving = lookup(state.pool(), &identity, &owner, name, writable, state.store().backend_identity(), deadline)
        .await
        .map_err(authority_error)?;
    let authorization = read_authorization(state.clone(), &identity, &serving);
    let refs = snapshot::load_ref_view(&state, &serving, deadline).await?;
    if service == "git-receive-pack" {
        // A read-only token cannot advertise pushes. Re-run the *writable*
        // lookup against the live token/RBAC/scope/realm/backend immediately
        // before the first advertisement byte; the captured realm must still be
        // the same authority that produced this ref view.
        let fresh =
            lookup(state.pool(), &identity, &owner, name, true, state.store().backend_identity(), deadline).await;
        let fresh = match fresh {
            Ok(fresh) => fresh,
            Err(error) => {
                snapshot::release_view(&state, &refs, deadline).await;
                return Err(authority_error(error));
            }
        };
        if let Err(error) = authorization.ensure_same_realm(&fresh) {
            snapshot::release_view(&state, &refs, deadline).await;
            return Err(error);
        }
        let mut body = service_prefix("git-receive-pack");
        body.extend_from_slice(&super::protocol::advertise_refs(&refs.refs, refs.format));
        snapshot::release_view(&state, &refs, deadline).await;
        return Ok(bytes_response("application/x-git-receive-pack-advertisement", body));
    }
    let view = snapshot::build_view(&state, &refs, deadline).await?;
    // Blob/native preparation may have taken a long time and released every
    // PostgreSQL lease. Re-check the current authority immediately before the
    // native advertisement is produced and its first byte is returned.
    authorization.revalidate(deadline).await?;
    let mut command = view.command_with_protocol(state.git_binary(), git_protocol(&headers));
    command.arg("upload-pack").arg("--stateless-rpc").arg("--advertise-refs").arg(view.repo());
    let captured = native::run_capture(command, None, state.limits().max_response_bytes, deadline).await?;
    if !captured.success {
        return Err(GatewayError::Internal("native upload-pack advertisement was refused"));
    }
    authorization.revalidate(deadline).await?;
    let mut body = service_prefix("git-upload-pack");
    body.extend_from_slice(&captured.stdout);
    Ok(bytes_response("application/x-git-upload-pack-advertisement", body))
}

pub(super) async fn upload_pack(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, GatewayError> {
    let name = repository_name(&raw_name)?;
    require_upload_content_type(&headers)?;
    validate_git_protocol(&headers)?;
    let encoding = super::receive::content_encoding(&headers)?;
    let identity = authenticate(&state, &headers).await?;
    let deadline = state.deadline();
    let _slot = state.slot().await?;
    let serving: ServingRepository =
        lookup(state.pool(), &identity, &owner, name, false, state.store().backend_identity(), deadline)
            .await
            .map_err(authority_error)?;
    let authorization = read_authorization(state.clone(), &identity, &serving);
    let lease = state.reserve_bytes(state.limits().max_request_bytes)?;
    let workspace = state.reserve_workspace(state.limits().max_request_bytes)?;
    let work = state.temp_dir("upload")?;
    let request_path = work.path().join("want.bin");
    native::spool_body_with_encoding(
        body,
        &request_path,
        state.limits().max_request_bytes,
        state.limits().max_request_bytes,
        encoding,
        deadline,
    )
    .await?;
    let refs = snapshot::load_ref_view(&state, &serving, deadline).await?;
    let view = snapshot::build_view(&state, &refs, deadline).await?;
    // The view is now materialized from the captured snapshot and no metadata
    // lease is held. Revalidate the current token/RBAC/scope/realm/backend
    // immediately before the native producer may return its first byte, then
    // hand the same guard to the producer for periodic independent checks.
    authorization.revalidate(deadline).await?;
    let mut command = view.command_with_protocol(state.git_binary(), git_protocol(&headers));
    command.arg("upload-pack").arg("--stateless-rpc").arg(view.repo());
    let stream = native::spawn_stream(
        command,
        Some(request_path),
        state.limits().max_response_bytes,
        deadline,
        (view, work, _slot, lease, workspace),
        authorization,
    )
    .await?;
    let mut response = Response::new(stream);
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/x-git-upload-pack-result"));
    response.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    Ok(response)
}

fn repository_name(raw: &str) -> Result<&str, GatewayError> {
    let name = raw.strip_suffix(".git").ok_or(GatewayError::NotFound)?;
    if !crate::db::valid_name(name) {
        return Err(GatewayError::NotFound);
    }
    Ok(name)
}

fn require_upload_content_type(headers: &HeaderMap) -> Result<(), GatewayError> {
    match headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()) {
        Some("application/x-git-upload-pack-request") => Ok(()),
        _ => Err(GatewayError::BadRequest("invalid Git upload-pack content type")),
    }
}

fn bytes_response(content_type: &'static str, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static(content_type));
    response.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    response
}
