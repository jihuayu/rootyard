//! Retention-root metadata and intent transport.
//!
//! This module exposes only create, historical metadata, existing-root release
//! and release-by-original-intent. Root tree/blob browsing is separate later
//! work. Every handler builds the serving-root facade from the actual opened
//! `BlobGitState` store and trusted Git binary; no SQL client, ambient backend or
//! caller-supplied authority is accepted here.
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, StatusCode, header},
    response::Response,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    api::strip_name,
    error::GatewayError,
    session::authenticate,
    state::BlobGitState,
};
use crate::{
    browse::models::valid_non_zero_oid,
    ref_store::{
        RootPurpose, RootSelector,
        core::retention_root::{MAX_ROOT_OIDS, PgRetentionRoots},
        serving::{
            PgServingRetentionRoots, ServingRootCreate, ServingRootIntent, ServingRootRead, ServingRootRelease,
            ServingRootReleaseTarget,
        },
    },
};

/// Exact fixed sentinel from `ref_store::serving::commit_unknown_error`.
/// Only this known ambiguous-COMMIT error may carry the retry-key/body message.
const COMMIT_UNKNOWN_SENTINEL: &str =
    "ref-store commit outcome is unknown; retry the same request to resolve it idempotently";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootCreateBody {
    idempotency_key: String,
    source_snapshot_id: Uuid,
    purpose: RootPurposeBody,
    selector: RootSelectorBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRootBody {
    idempotency_key: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseIntentBody {
    create: RootCreateBody,
    idempotency_key: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RootPurposeBody {
    Ci,
    Workspace,
    PullRequest,
    Namespace,
    Backup,
    Export,
    OperatorAudit,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootSelectorBody {
    kind: RootSelectorKindBody,
    #[serde(default)]
    oids: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RootSelectorKindBody {
    Snapshot,
    Oids,
}

#[derive(Serialize)]
struct RootReceiptView {
    action: &'static str,
    root_id: Uuid,
    generation: i64,
    replayed: bool,
    created_at_unix_micros: i64,
    receipt_only: bool,
    /// Historical receipt state, never current live root state.
    receipt_state: String,
}

#[derive(Serialize)]
struct RootMetadataView {
    root_id: Uuid,
    current_state: String,
    generation: i64,
    purpose: String,
    selector_kind: String,
    object_format: String,
    head_ref: String,
    head_oid: Option<String>,
    ref_count: i64,
    pack_count: i64,
    oid_count: i64,
}

pub(super) async fn create_root(
    state: State<Arc<BlobGitState>>,
    path: Path<(String, String)>,
    headers: HeaderMap,
    payload: Result<Json<RootCreateBody>, JsonRejection>,
) -> Response {
    create_root_authorized(state, path, headers, payload).await.unwrap_or_else(GatewayError::api)
}

async fn create_root_authorized(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name)): Path<(String, String)>,
    headers: HeaderMap,
    payload: Result<Json<RootCreateBody>, JsonRejection>,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let intent = json_body(payload)?.into_intent()?;
    let identity = authenticate(&state, &headers).await?;
    let facade = root_facade(&state)?;
    let receipt = facade
        .create(
            state.pool(),
            &identity,
            ServingRootCreate {
                owner,
                name: name.to_owned(),
                intent,
            },
            state.deadline(),
        )
        .await
        .map_err(roots_error)?;
    let status = if receipt.replayed() { StatusCode::OK } else { StatusCode::CREATED };
    json_response(&state, status, &RootReceiptView::new(&receipt))
}

pub(super) async fn read_root(
    state: State<Arc<BlobGitState>>,
    path: Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    read_root_authorized(state, path, headers).await.unwrap_or_else(GatewayError::api)
}

async fn read_root_authorized(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name, root)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let root_id = parse_root_id(&root)?;
    let identity = authenticate(&state, &headers).await?;
    let facade = root_facade(&state)?;
    let record = facade
        .metadata(
            state.pool(),
            &identity,
            ServingRootRead { owner, name: name.to_owned(), root_id },
            state.deadline(),
        )
        .await
        .map_err(roots_error)?
        .ok_or(GatewayError::NotFound)?;
    json_response(&state, StatusCode::OK, &RootMetadataView::from_record(&record))
}

pub(super) async fn release_root(
    state: State<Arc<BlobGitState>>,
    path: Path<(String, String, String)>,
    headers: HeaderMap,
    payload: Result<Json<ReleaseRootBody>, JsonRejection>,
) -> Response {
    release_root_authorized(state, path, headers, payload).await.unwrap_or_else(GatewayError::api)
}

async fn release_root_authorized(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name, root)): Path<(String, String, String)>,
    headers: HeaderMap,
    payload: Result<Json<ReleaseRootBody>, JsonRejection>,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let root_id = parse_root_id(&root)?;
    let body = json_body(payload)?;
    let identity = authenticate(&state, &headers).await?;
    let facade = root_facade(&state)?;
    let receipt = facade
        .release(
            state.pool(),
            &identity,
            ServingRootRelease {
                owner,
                name: name.to_owned(),
                target: ServingRootReleaseTarget::Existing { root_id },
                idempotency_key: body.idempotency_key,
                reason: body.reason,
            },
            state.deadline(),
        )
        .await
        .map_err(roots_error)?;
    json_response(&state, StatusCode::OK, &RootReceiptView::new(&receipt))
}

pub(super) async fn release_root_intent(
    state: State<Arc<BlobGitState>>,
    path: Path<(String, String)>,
    headers: HeaderMap,
    payload: Result<Json<ReleaseIntentBody>, JsonRejection>,
) -> Response {
    release_root_intent_authorized(state, path, headers, payload).await.unwrap_or_else(GatewayError::api)
}

async fn release_root_intent_authorized(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name)): Path<(String, String)>,
    headers: HeaderMap,
    payload: Result<Json<ReleaseIntentBody>, JsonRejection>,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let body = json_body(payload)?;
    let create = body.create.into_intent()?;
    let identity = authenticate(&state, &headers).await?;
    let facade = root_facade(&state)?;
    let receipt = facade
        .release(
            state.pool(),
            &identity,
            ServingRootRelease {
                owner,
                name: name.to_owned(),
                target: ServingRootReleaseTarget::ByIntent { create },
                idempotency_key: body.idempotency_key,
                reason: body.reason,
            },
            state.deadline(),
        )
        .await
        .map_err(roots_error)?;
    json_response(&state, StatusCode::OK, &RootReceiptView::new(&receipt))
}

impl RootCreateBody {
    fn into_intent(self) -> Result<ServingRootIntent, GatewayError> {
        if self.source_snapshot_id.is_nil() {
            return Err(GatewayError::BadRequest("invalid source snapshot id"));
        }
        Ok(ServingRootIntent {
            source_snapshot_id: self.source_snapshot_id,
            selector: self.selector.into_selector()?,
            purpose: self.purpose.into_root_purpose(),
            idempotency_key: self.idempotency_key,
        })
    }
}

impl RootSelectorBody {
    fn into_selector(self) -> Result<RootSelector, GatewayError> {
        match self.kind {
            RootSelectorKindBody::Snapshot => {
                if self.oids.is_some() {
                    return Err(GatewayError::BadRequest("snapshot selector must not carry oids"));
                }
                Ok(RootSelector::Snapshot)
            }
            RootSelectorKindBody::Oids => {
                let oids = self.oids.ok_or(GatewayError::BadRequest("oids selector requires oids"))?;
                if oids.is_empty() || oids.len() > MAX_ROOT_OIDS {
                    return Err(GatewayError::BadRequest("root selector is out of bounds"));
                }
                if !oids.iter().all(|oid| valid_non_zero_oid(oid)) {
                    return Err(GatewayError::BadRequest("invalid root object id"));
                }
                Ok(RootSelector::ObjectIds(oids))
            }
        }
    }
}

impl RootPurposeBody {
    fn into_root_purpose(self) -> RootPurpose {
        match self {
            Self::Ci => RootPurpose::Ci,
            Self::Workspace => RootPurpose::Workspace,
            Self::PullRequest => RootPurpose::PullRequest,
            Self::Namespace => RootPurpose::Namespace,
            Self::Backup => RootPurpose::Backup,
            Self::Export => RootPurpose::Export,
            Self::OperatorAudit => RootPurpose::OperatorAudit,
        }
    }
}

impl RootReceiptView {
    fn new(receipt: &crate::ref_store::core::retention_root::RootReceipt) -> Self {
        Self {
            action: receipt.action().as_str(),
            root_id: receipt.root_id(),
            generation: receipt.generation(),
            replayed: receipt.replayed(),
            created_at_unix_micros: receipt.created_at_unix_micros(),
            receipt_only: true,
            receipt_state: receipt.state().to_owned(),
        }
    }
}

impl RootMetadataView {
    fn from_record(record: &crate::ref_store::core::retention_root::RootRecord) -> Self {
        Self {
            root_id: record.root_id(),
            current_state: record.state().to_owned(),
            generation: record.generation(),
            purpose: record.purpose().as_str().to_owned(),
            selector_kind: record.selector_kind().as_str().to_owned(),
            object_format: record.object_format().as_str().to_owned(),
            head_ref: record.head_ref().to_owned(),
            head_oid: record.head_oid_hex().map(str::to_owned),
            ref_count: record.ref_count(),
            pack_count: record.pack_count(),
            oid_count: record.oid_count(),
        }
    }
}

pub(crate) fn root_facade(state: &BlobGitState) -> Result<PgServingRetentionRoots, GatewayError> {
    let roots = PgRetentionRoots::new(state.store().clone(), state.git_binary().to_path_buf())
        .map_err(|_| GatewayError::Internal("retention root engine unavailable"))?;
    Ok(PgServingRetentionRoots::new(roots))
}

fn parse_root_id(raw: &str) -> Result<Uuid, GatewayError> {
    let root_id = Uuid::parse_str(raw).map_err(|_| GatewayError::BadRequest("invalid root id"))?;
    if root_id.is_nil() {
        return Err(GatewayError::BadRequest("invalid root id"));
    }
    Ok(root_id)
}

fn json_body<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, GatewayError> {
    match payload {
        Ok(Json(value)) => Ok(value),
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => Err(GatewayError::TooLarge),
        Err(_) => Err(GatewayError::BadRequest("invalid retention root request")),
    }
}

fn json_response<T: Serialize>(
    state: &BlobGitState,
    status: StatusCode,
    value: &T,
) -> Result<Response, GatewayError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| GatewayError::Internal("retention root response could not be encoded"))?;
    if bytes.len() as u64 > state.limits().max_response_bytes {
        return Err(GatewayError::TooLarge);
    }
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    Ok(response)
}

fn roots_error(error: crate::Error) -> GatewayError {
    match error.0 {
        StatusCode::BAD_REQUEST => GatewayError::BadRequest("invalid retention root request"),
        StatusCode::UNAUTHORIZED => GatewayError::Unauthorized,
        StatusCode::FORBIDDEN => GatewayError::Forbidden("retention root is not authorized"),
        StatusCode::NOT_FOUND => GatewayError::NotFound,
        StatusCode::CONFLICT => GatewayError::Conflict("retention root state changed; retry the same request"),
        StatusCode::PAYLOAD_TOO_LARGE => GatewayError::TooLarge,
        StatusCode::TOO_MANY_REQUESTS => GatewayError::TooManyRequests("retained root quota is exhausted"),
        StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => GatewayError::Timeout,
        StatusCode::SERVICE_UNAVAILABLE
            if error.1 == COMMIT_UNKNOWN_SENTINEL =>
        {
            GatewayError::Unavailable("retention root outcome is unknown; retry the same key and body")
        }
        StatusCode::SERVICE_UNAVAILABLE => {
            GatewayError::Unavailable("retention root metadata service is unavailable")
        }
        _ => GatewayError::Internal("retention root request was refused"),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_error_distinguishes_unknown_commit_from_generic_unavailable() {
        let unknown = roots_error(crate::Error(
            StatusCode::SERVICE_UNAVAILABLE,
            COMMIT_UNKNOWN_SENTINEL,
        ));
        assert_eq!(
            unknown,
            GatewayError::Unavailable(
                "retention root outcome is unknown; retry the same key and body"
            )
        );

        for error in [
            crate::Error(StatusCode::SERVICE_UNAVAILABLE, "ref-store pool unavailable"),
            crate::Error(StatusCode::SERVICE_UNAVAILABLE, "retention root transaction cleanup failed"),
        ] {
            let mapped = roots_error(error);
            assert_eq!(
                mapped,
                GatewayError::Unavailable("retention root metadata service is unavailable")
            );
            assert!(!mapped.message().to_ascii_lowercase().contains("unknown"));
        }

        assert_eq!(
            roots_error(crate::Error(StatusCode::BAD_REQUEST, "invalid")),
            GatewayError::BadRequest("invalid retention root request")
        );
        assert_eq!(
            roots_error(crate::Error(StatusCode::INTERNAL_SERVER_ERROR, "internal")),
            GatewayError::Internal("retention root request was refused")
        );
    }
}
