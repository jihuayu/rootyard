//! Retention-root tree/blob browsing.
//!
//! The coordinator materializes an authorized root and returns an opaque
//! context. This module copies its exact verified pack/index bytes into a
//! disposable private Git view, applies the selected-root ref/HEAD policy, reads
//! bounded browse bytes, fully encodes the JSON, then asks the same retained
//! context to recheck current authority/root/binding/backend/realm/cluster before
//! the body is served. PostgreSQL is never held across pack, native, file or JSON
//! work, and no session/proof/HWM is issued here.
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

use super::super::{
    api::strip_name,
    error::GatewayError,
    retention_roots::root_facade,
    session::authenticate,
    snapshot,
    state::{BlobGitState, ByteLease, WorkspaceLease},
};
use super::{
    MAX_CAPTURE_BYTES, bad_input, blob_read_ceiling, captured_revision, memory_budget, parse_tree, reachable,
    require_type, resolve, root_oid, run, validate_tree_after,
};
use crate::browse::models::{
    self, BlobByOidQuery, BlobResponse, TreeQuery, TreeResponse, normalize_rel_path, validate_limit,
};
use crate::ref_store::serving::{PgServingRetentionRoots, ServingRetainedRootReadContext, ServingRootRead};

pub(crate) async fn tree(
    state: State<Arc<BlobGitState>>,
    path: Path<(String, String, String)>,
    query: Query<TreeQuery>,
    headers: HeaderMap,
) -> Response {
    tree_authorized(state, path, query, headers).await.unwrap_or_else(GatewayError::api)
}

async fn tree_authorized(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name, root)): Path<(String, String, String)>,
    Query(query): Query<TreeQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let root_id = parse_root_id(&root)?;
    let path = normalize_rel_path(query.path.as_deref()).map_err(bad_input)?;
    let limit = validate_limit(query.limit).map_err(bad_input)?;
    let after = validate_tree_after(query.after.as_deref())?.map(str::to_owned);
    let spec = query.oid.as_deref().unwrap_or("HEAD").to_owned();
    validate_root_spec(&spec)?;

    let identity = authenticate(&state, &headers).await?;
    let deadline = state.deadline();
    let slot = state.slot().await?;
    let memory = memory_budget(&state);
    let lease = state.reserve_bytes(memory)?;
    let facade = root_facade(&state)?;
    let input = ServingRootRead { owner, name: name.to_owned(), root_id };
    let context =
        facade.materialize_with_context(state.pool(), &identity, input, deadline).await.map_err(root_serving_error)?;
    let deadline = context.deadline();
    let computed = snapshot::build_retained_root_view(&state, context.view(), deadline).await?;
    let refs = snapshot::retained_root_refs(context.view());
    let spec = captured_revision(&refs, &spec)?;
    let root_oid = root_oid(&state, &*computed, &spec, memory, deadline).await?;
    let expression = if path.is_empty() { format!("{root_oid}^{{tree}}") } else { format!("{root_oid}:{path}") };
    let tree_oid = resolve(&state, &*computed, &expression, deadline).await?;
    require_type(&state, &*computed, &tree_oid, "tree", deadline).await?;
    let raw =
        run(&state, &*computed, &["ls-tree", "-z", "-l", &tree_oid], (memory / 8).min(MAX_CAPTURE_BYTES), deadline)
            .await?;
    let mut entries = parse_tree(&raw, &path, after.as_deref(), limit)?;
    let more = entries.len() > limit;
    entries.truncate(limit);
    let next_after = if more { entries.last().map(|entry| entry.name.clone()) } else { None };
    let result = TreeResponse { oid: root_oid, tree_oid, path, items: entries, next_after };
    let workspace = computed.into_workspace();
    finish_root(
        &state,
        &facade,
        &identity,
        OnRootContext { context },
        slot,
        lease,
        workspace,
        (memory / 12).min(state.limits().max_response_bytes),
        &result,
    )
    .await
}

pub(crate) async fn blob(
    state: State<Arc<BlobGitState>>,
    path: Path<(String, String, String, String)>,
    query: Query<BlobByOidQuery>,
    headers: HeaderMap,
) -> Response {
    blob_authorized(state, path, query, headers).await.unwrap_or_else(GatewayError::api)
}

async fn blob_authorized(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name, root, oid)): Path<(String, String, String, String)>,
    Query(query): Query<BlobByOidQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let root_id = parse_root_id(&root)?;
    let path = normalize_rel_path(query.path.as_deref()).map_err(bad_input)?;
    validate_root_spec(&oid)?;
    direct_blob_guard(&path, &oid)?;

    let identity = authenticate(&state, &headers).await?;
    let deadline = state.deadline();
    let slot = state.slot().await?;
    let memory = memory_budget(&state);
    let lease = state.reserve_bytes(memory)?;
    let facade = root_facade(&state)?;
    let input = ServingRootRead { owner, name: name.to_owned(), root_id };
    let context =
        facade.materialize_with_context(state.pool(), &identity, input, deadline).await.map_err(root_serving_error)?;
    let deadline = context.deadline();
    let computed = snapshot::build_retained_root_view(&state, context.view(), deadline).await?;
    let refs = snapshot::retained_root_refs(context.view());
    let spec = captured_revision(&refs, &oid)?;
    let oid = if path.is_empty() {
        let resolved = resolve(&state, &*computed, &spec, deadline).await?;
        reachable(&state, &*computed, &resolved, memory, deadline).await?;
        resolved
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
    let max_blob = blob_read_ceiling(memory, state.limits().max_response_bytes, memory / 12);
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
    let workspace = computed.into_workspace();
    finish_root(
        &state,
        &facade,
        &identity,
        OnRootContext { context },
        slot,
        lease,
        workspace,
        (memory / 12).min(state.limits().max_response_bytes),
        &result,
    )
    .await
}

struct OnRootContext {
    context: ServingRetainedRootReadContext,
}

#[allow(clippy::too_many_arguments)]
async fn finish_root<T: Serialize>(
    state: &BlobGitState,
    facade: &PgServingRetentionRoots,
    identity: &crate::db::Identity,
    root: OnRootContext,
    slot: OwnedSemaphorePermit,
    lease: ByteLease,
    workspace: WorkspaceLease,
    limit: u64,
    value: &T,
) -> Result<Response, GatewayError> {
    let bytes = super::session::encode_response(value, limit)?;
    facade.finalize_materialized(state.pool(), identity, root.context).await.map_err(root_serving_error)?;
    Ok(super::session::body_response_with_workspace(bytes, slot, lease, workspace, None))
}

/// Root Browse accepts ordinary public revision forms and exactly one private
/// namespace: the literal synthetic selected-OID refs installed by the retained
/// root view. Membership is still checked against the actual retained refs by
/// `captured_revision`; this function only prevents arbitrary private refs,
/// short IDs, zero IDs, uppercase/non-canonical hex and traversal suffixes from
/// reaching native resolution.
fn validate_root_spec(spec: &str) -> Result<(), GatewayError> {
    if models::valid_revision_spec(spec) {
        return Ok(());
    }
    if let Some(oid) = spec.strip_prefix(snapshot::RETAINED_ROOT_OID_REF_PREFIX)
        && models::valid_non_zero_oid(oid)
    {
        return Ok(());
    }
    Err(GatewayError::BadRequest("invalid repository revision"))
}

/// Direct no-path blob reads retain the ordinary Browse contract: the path
/// segment must itself be a full non-zero object id. Synthetic refs are allowed
/// for tree and path-based blob selectors, never as a direct no-path blob.
fn direct_blob_guard(path: &str, oid: &str) -> Result<(), GatewayError> {
    if path.is_empty() && !models::valid_non_zero_oid(oid) {
        return Err(GatewayError::BadRequest("a file path or full blob object identifier is required"));
    }
    Ok(())
}

fn parse_root_id(raw: &str) -> Result<Uuid, GatewayError> {
    let root_id = Uuid::parse_str(raw).map_err(|_| GatewayError::BadRequest("invalid root id"))?;
    if root_id.is_nil() {
        return Err(GatewayError::BadRequest("invalid root id"));
    }
    Ok(root_id)
}

fn root_serving_error(error: crate::Error) -> GatewayError {
    match error.0 {
        axum::http::StatusCode::BAD_REQUEST => GatewayError::BadRequest("invalid retention root browse request"),
        axum::http::StatusCode::UNAUTHORIZED => GatewayError::Unauthorized,
        axum::http::StatusCode::FORBIDDEN => GatewayError::Forbidden("retention root content is not authorized"),
        axum::http::StatusCode::NOT_FOUND => GatewayError::NotFound,
        axum::http::StatusCode::CONFLICT => GatewayError::Conflict("retention root state changed; retry"),
        axum::http::StatusCode::PAYLOAD_TOO_LARGE => GatewayError::TooLarge,
        axum::http::StatusCode::TOO_MANY_REQUESTS => GatewayError::TooManyRequests("retained root quota is exhausted"),
        axum::http::StatusCode::REQUEST_TIMEOUT | axum::http::StatusCode::GATEWAY_TIMEOUT => GatewayError::Timeout,
        axum::http::StatusCode::SERVICE_UNAVAILABLE => {
            GatewayError::Unavailable("retention root content is temporarily unavailable")
        }
        _ => GatewayError::Internal("retention root content could not be materialized"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_spec_accepts_only_public_forms_and_exact_synthetic_oids() {
        for spec in [
            "HEAD".to_owned(),
            "main".to_owned(),
            "refs/heads/main".to_owned(),
            "refs/tags/v1".to_owned(),
            "a".repeat(40),
            "b".repeat(64),
            format!("refs/roots/oid/{}", "c".repeat(40)),
            format!("refs/roots/oid/{}", "d".repeat(64)),
        ] {
            assert!(validate_root_spec(&spec).is_ok(), "root spec rejected: {spec}");
        }
        for spec in [
            "refs/roots/oid/".to_owned(),
            format!("refs/roots/oid/{}", "a".repeat(39)),
            format!("refs/roots/oid/{}", "a".repeat(41)),
            format!("refs/roots/oid/{}", "a".repeat(63)),
            format!("refs/roots/oid/{}", "A".repeat(40)),
            format!("refs/roots/oid/{}", "0".repeat(40)),
            format!("refs/roots/oid/{}", "0".repeat(64)),
            "refs/private/selected".to_owned(),
            format!("refs/roots/oid/{}/child", "a".repeat(40)),
            format!("refs/roots/oid/{}..", "a".repeat(40)),
        ] {
            assert!(validate_root_spec(&spec).is_err(), "root spec accepted: {spec}");
        }
    }

    #[test]
    fn direct_blob_guard_requires_full_oid_without_a_path() {
        let message = "a file path or full blob object identifier is required";
        for spec in [
            "HEAD".to_owned(),
            "main".to_owned(),
            "refs/heads/main".to_owned(),
            format!("refs/roots/oid/{}", "a".repeat(40)),
        ] {
            assert_eq!(
                direct_blob_guard("", &spec),
                Err(GatewayError::BadRequest(message)),
                "direct revision was accepted: {spec}"
            );
            assert!(direct_blob_guard("a.txt", &spec).is_ok(), "path revision was refused: {spec}");
        }
        assert!(direct_blob_guard("", &"a".repeat(40)).is_ok());
        assert!(direct_blob_guard("", &"b".repeat(64)).is_ok());
    }
}
