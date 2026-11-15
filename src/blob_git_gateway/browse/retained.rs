//! Snapshot-scoped historical tree/blob reads over an authorized retained
//! materialization. The existing current Browse renderer and captured-ref
//! reachability rules are reused; this module owns only the retained resource
//! context and its post-encoding final authorization fence.
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use base64::Engine;
use serde::Serialize;
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

use super::{
    MAX_CAPTURE_BYTES, bad_input, captured_revision, memory_budget, parse_tree, reachable, require_type, resolve,
    root_oid, run, validate_spec, validate_tree_after,
};
use super::super::{
    api::strip_name,
    error::GatewayError,
    session::authenticate,
    snapshot,
    state::{BlobGitState, ByteLease},
};
use crate::browse::models::{BlobByOidQuery, BlobResponse, TreeQuery, TreeResponse, normalize_rel_path, valid_non_zero_oid, validate_limit};
use crate::ref_store::core::pack_snapshot::PgPackSnapshotMaterializer;
use crate::ref_store::serving::{PgServingSnapshotMetadata, RetainedServingReadContext, ServingSnapshotRead};

pub(super) async fn tree(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name, snapshot)): Path<(String, String, String)>,
    Query(query): Query<TreeQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let snapshot_id = parse_snapshot_id(&snapshot)?;
    let path = normalize_rel_path(query.path.as_deref()).map_err(bad_input)?;
    let limit = validate_limit(query.limit).map_err(bad_input)?;
    let after = validate_tree_after(query.after.as_deref())?.map(str::to_owned);
    let spec = query.oid.as_deref().unwrap_or("HEAD").to_owned();
    validate_spec(&spec)?;

    let identity = authenticate(&state, &headers).await?;
    let input = ServingSnapshotRead { owner, name: name.to_owned(), snapshot_id };
    let deadline = state.deadline();
    let slot = state.slot().await?;
    let memory = memory_budget(&state);
    let lease = state.reserve_bytes(memory)?;
    let materializer = materializer(&state)?;
    let context = PgServingSnapshotMetadata
        .materialize_with_context(state.pool(), &identity, input.clone(), &materializer, deadline)
        .await
        .map_err(serving_error)?;
    let deadline = context.deadline();
    let computed = snapshot::build_retained_view(&state, context.view(), deadline).await?;
    let refs = context
        .view()
        .refs()
        .iter()
        .map(|reference| (reference.name().to_owned(), reference.oid_hex().to_owned()))
        .collect::<Vec<_>>();
    let spec = captured_revision(&refs, &spec)?;
    let root_oid = root_oid(&state, &*computed, &spec, memory, deadline).await?;
    let expression = if path.is_empty() { format!("{root_oid}^{{tree}}") } else { format!("{root_oid}:{path}") };
    let tree_oid = resolve(&state, &*computed, &expression, deadline).await?;
    require_type(&state, &*computed, &tree_oid, "tree", deadline).await?;
    let raw = run(
        &state,
        &*computed,
        &["ls-tree", "-z", "-l", &tree_oid],
        (memory / 8).min(MAX_CAPTURE_BYTES),
        deadline,
    )
    .await?;
    let mut entries = parse_tree(&raw, &path, after.as_deref(), limit)?;
    let more = entries.len() > limit;
    entries.truncate(limit);
    let next_after = if more { entries.last().map(|entry| entry.name.clone()) } else { None };
    let result = TreeResponse { oid: root_oid, tree_oid, path, items: entries, next_after };
    finish_retained(
        &state,
        &identity,
        &input,
        context,
        &materializer,
        slot,
        lease,
        (memory / 12).min(state.limits().max_response_bytes),
        &result,
    )
    .await
}

pub(super) async fn blob(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name, snapshot, oid)): Path<(String, String, String, String)>,
    Query(query): Query<BlobByOidQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let snapshot_id = parse_snapshot_id(&snapshot)?;
    let path = normalize_rel_path(query.path.as_deref()).map_err(bad_input)?;
    validate_spec(&oid)?;
    if path.is_empty() && !valid_non_zero_oid(&oid) {
        return Err(GatewayError::BadRequest("a file path or full blob object identifier is required"));
    }

    let identity = authenticate(&state, &headers).await?;
    let input = ServingSnapshotRead { owner, name: name.to_owned(), snapshot_id };
    let deadline = state.deadline();
    let slot = state.slot().await?;
    let memory = memory_budget(&state);
    let lease = state.reserve_bytes(memory)?;
    let materializer = materializer(&state)?;
    let context = PgServingSnapshotMetadata
        .materialize_with_context(state.pool(), &identity, input.clone(), &materializer, deadline)
        .await
        .map_err(serving_error)?;
    let deadline = context.deadline();
    let computed = snapshot::build_retained_view(&state, context.view(), deadline).await?;
    let refs = context
        .view()
        .refs()
        .iter()
        .map(|reference| (reference.name().to_owned(), reference.oid_hex().to_owned()))
        .collect::<Vec<_>>();
    let spec = captured_revision(&refs, &oid)?;
    let oid = if path.is_empty() {
        reachable(&state, &*computed, &spec, memory, deadline).await?;
        resolve(&state, &*computed, &spec, deadline).await?
    } else {
        let root = root_oid(&state, &*computed, &spec, memory, deadline).await?;
        resolve(&state, &*computed, &format!("{root}:{path}"), deadline).await?
    };
    require_type(&state, &*computed, &oid, "blob", deadline).await?;
    let raw_size = run(&state, &*computed, &["cat-file", "-s", &oid], 64, deadline).await?;
    let size = std::str::from_utf8(&raw_size)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .ok_or(GatewayError::Internal("native blob size is invalid"))?;
    let max_blob = MAX_CAPTURE_BYTES
        .min(memory / 12)
        .min(state.limits().max_response_bytes / 8);
    if size > max_blob {
        return Err(GatewayError::TooLarge);
    }
    let raw = run(&state, &*computed, &["cat-file", "blob", &oid], max_blob, deadline).await?;
    if raw.len() as u64 != size {
        return Err(GatewayError::Internal("native blob length differs from its object size"));
    }
    let is_binary = raw.contains(&0) || std::str::from_utf8(&raw).is_err();
    let content = if is_binary { None } else { std::str::from_utf8(&raw).ok().map(str::to_owned) };
    let content_base64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    let result = BlobResponse { oid, size, is_binary, content, content_base64 };
    finish_retained(
        &state,
        &identity,
        &input,
        context,
        &materializer,
        slot,
        lease,
        (memory / 12).min(state.limits().max_response_bytes),
        &result,
    )
    .await
}

fn serving_error(error: crate::Error) -> GatewayError {
    match error.0 {
        axum::http::StatusCode::BAD_REQUEST => GatewayError::BadRequest("invalid snapshot metadata request"),
        axum::http::StatusCode::UNAUTHORIZED => GatewayError::Unauthorized,
        axum::http::StatusCode::FORBIDDEN => GatewayError::Forbidden("repository authorization is no longer valid"),
        axum::http::StatusCode::NOT_FOUND => GatewayError::NotFound,
        axum::http::StatusCode::CONFLICT => GatewayError::Conflict("repository state changed; retry"),
        axum::http::StatusCode::GATEWAY_TIMEOUT | axum::http::StatusCode::REQUEST_TIMEOUT => GatewayError::Timeout,
        axum::http::StatusCode::SERVICE_UNAVAILABLE => {
            GatewayError::Unavailable("verified pack snapshot is temporarily unavailable")
        }
        _ => GatewayError::Internal("verified pack snapshot could not be materialized"),
    }
}

fn materializer(state: &BlobGitState) -> Result<PgPackSnapshotMaterializer, GatewayError> {
    PgPackSnapshotMaterializer::new(state.store().clone(), state.git_binary().to_path_buf())
        .map_err(snapshot::materialize_error)
}

fn parse_snapshot_id(raw: &str) -> Result<Uuid, GatewayError> {
    let snapshot_id = Uuid::parse_str(raw).map_err(|_| GatewayError::BadRequest("invalid snapshot identifier"))?;
    if snapshot_id.is_nil() {
        return Err(GatewayError::BadRequest("invalid snapshot identifier"));
    }
    Ok(snapshot_id)
}

#[allow(clippy::too_many_arguments)]
async fn finish_retained<T: Serialize>(
    state: &BlobGitState,
    identity: &crate::db::Identity,
    input: &ServingSnapshotRead,
    context: RetainedServingReadContext,
    materializer: &PgPackSnapshotMaterializer,
    slot: OwnedSemaphorePermit,
    lease: ByteLease,
    limit: u64,
    value: &T,
) -> Result<Response, GatewayError> {
    let bytes = super::session::encode_response(value, limit)?;
    PgServingSnapshotMetadata
        .finalize_materialized(state.pool(), identity, input, context, materializer)
        .await
        .map_err(serving_error)?;
    Ok(super::session::body_response(bytes, slot, lease, None))
}
