//! Bounded HTTP surface for durable A5a snapshot metadata.
//!
//! Routes are `POST /api/repos/{owner}/{name}/snapshots`,
//! `GET|DELETE /api/repos/{owner}/{name}/snapshots/{snapshot}` and
//! `POST /api/repos/{owner}/{name}/snapshots/{snapshot}/renew`. There is no
//! competing POST release route.
//!
//! These handlers are only transport/DTO framing. Authorization, current role
//! and scope, ready binding/backend/realm/cluster fencing and the final commit
//! all stay in `PgServingSnapshotMetadata`; no SQL authority is reimplemented
//! here. Responses are explicit projections of durable receipts or current
//! stored metadata, never serialized internal values.
//!
//! This is an internal checkpoint toward full #107, not issue closure. A5a
//! responses keep `complete_git_read_snapshot=false`; no #174 session token or
//! high-watermark is issued. Materializer, Browse historical view and
//! retention-root HTTP remain separate later work.
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
    session::{authenticate, authorize_write},
    state::BlobGitState,
};
use crate::ref_store::{
    MetadataMutationAction, PinReleaseReason,
    core::{
        MetadataPinReceipt,
        pack_commit::RegisteredPack,
        pack_snapshot::{PackReadSnapshot, PackSnapshotReceipt},
    },
    serving::{
        PgServingSnapshotMetadata, ServingSnapshotCreate, ServingSnapshotRead, ServingSnapshotRelease,
        ServingSnapshotRenew,
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateSnapshotBody {
    idempotency_key: String,
    lease_seconds: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewSnapshotBody {
    idempotency_key: String,
    expected_generation: i64,
    lease_seconds: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseSnapshotBody {
    idempotency_key: String,
    expected_generation: i64,
}

#[derive(Serialize)]
struct SnapshotCreateView {
    action: &'static str,
    snapshot_id: Uuid,
    pin_id: Uuid,
    pin_generation: i64,
    gate_revision: i64,
    gate_digest: String,
    head_ref: String,
    head_oid: Option<String>,
    ref_count: i64,
    refs_digest: String,
    membership_digest: String,
    pack_count: i64,
    pack_mode: &'static str,
    snapshot_digest: String,
    logical_bytes: i64,
    expires_at_unix_micros: i64,
    expires_at_is_historical: bool,
    replayed: bool,
    receipt_only: bool,
    receipt_grants_live_lease: bool,
    complete_registered_pack_membership: bool,
    complete_git_read_snapshot: bool,
}

impl SnapshotCreateView {
    fn new(receipt: &PackSnapshotReceipt, replayed: bool) -> Self {
        Self {
            action: MetadataMutationAction::Create.as_str(),
            snapshot_id: receipt.snapshot_id(),
            pin_id: receipt.pin_id(),
            pin_generation: receipt.pin_generation(),
            gate_revision: receipt.gate_revision(),
            gate_digest: receipt.gate_digest_hex().to_owned(),
            head_ref: receipt.head_ref().to_owned(),
            head_oid: receipt.head_oid_hex().map(str::to_owned),
            ref_count: receipt.ref_count(),
            refs_digest: receipt.refs_digest_hex().to_owned(),
            membership_digest: receipt.membership_digest_hex().to_owned(),
            pack_count: receipt.pack_count(),
            pack_mode: receipt.pack_mode(),
            snapshot_digest: receipt.snapshot_digest_hex().to_owned(),
            logical_bytes: receipt.logical_bytes(),
            expires_at_unix_micros: receipt.expires_at_unix_micros(),
            expires_at_is_historical: replayed,
            replayed,
            receipt_only: true,
            receipt_grants_live_lease: false,
            complete_registered_pack_membership: receipt.complete_registered_pack_membership(),
            complete_git_read_snapshot: receipt.complete_git_read_snapshot(),
        }
    }
}

#[derive(Serialize)]
struct PinMutationView {
    action: &'static str,
    snapshot_id: Uuid,
    pin_id: Uuid,
    pin_generation: i64,
    expires_at_unix_micros: i64,
    released_at_unix_micros: Option<i64>,
    release_reason: Option<&'static str>,
    expires_at_is_historical: bool,
    replayed: bool,
    receipt_only: bool,
    receipt_grants_live_lease: bool,
    complete_git_read_snapshot: bool,
}

impl PinMutationView {
    fn new(receipt: &MetadataPinReceipt, replayed: bool) -> Self {
        let release = receipt.action() == MetadataMutationAction::Release;
        Self {
            action: receipt.action().as_str(),
            snapshot_id: receipt.snapshot_id(),
            pin_id: receipt.pin_id(),
            pin_generation: receipt.pin_generation(),
            expires_at_unix_micros: receipt.expires_at_unix_micros(),
            released_at_unix_micros: receipt.released_at_unix_micros(),
            release_reason: receipt.release_reason().map(PinReleaseReason::as_str),
            expires_at_is_historical: replayed || release,
            replayed,
            receipt_only: true,
            receipt_grants_live_lease: false,
            complete_git_read_snapshot: false,
        }
    }
}

#[derive(Serialize)]
struct SnapshotView {
    snapshot_id: Uuid,
    pin_id: Uuid,
    pin_generation: i64,
    gate_revision: i64,
    gate_digest: String,
    head_ref: String,
    head_oid: Option<String>,
    ref_count: i64,
    refs: Vec<RefView>,
    pack_count: i64,
    pack_mode: &'static str,
    packs: Vec<PackView>,
    membership_digest: String,
    snapshot_digest: String,
    logical_bytes: i64,
    expires_at_unix_micros: i64,
    source_kind: &'static str,
    complete_registered_pack_membership: bool,
    complete_git_read_snapshot: bool,
}

impl SnapshotView {
    fn new(snapshot: &PackReadSnapshot) -> Self {
        Self {
            snapshot_id: snapshot.snapshot_id(),
            pin_id: snapshot.pin_id(),
            pin_generation: snapshot.pin_generation(),
            gate_revision: snapshot.gate_revision(),
            gate_digest: snapshot.gate_digest_hex().to_owned(),
            head_ref: snapshot.head_ref().to_owned(),
            head_oid: snapshot.head_oid_hex().map(str::to_owned),
            ref_count: snapshot.ref_count(),
            refs: snapshot.refs().iter().map(RefView::new).collect(),
            pack_count: snapshot.pack_count(),
            pack_mode: snapshot.pack_mode(),
            packs: snapshot.packs().iter().map(PackView::new).collect(),
            membership_digest: snapshot.membership_digest_hex().to_owned(),
            snapshot_digest: snapshot.snapshot_digest_hex().to_owned(),
            logical_bytes: snapshot.logical_bytes(),
            expires_at_unix_micros: snapshot.expires_at_unix_micros(),
            source_kind: snapshot.source_kind().as_str(),
            complete_registered_pack_membership: snapshot.complete_registered_pack_membership(),
            complete_git_read_snapshot: snapshot.complete_git_read_snapshot(),
        }
    }
}

#[derive(Serialize)]
struct RefView {
    name: String,
    oid: String,
}

impl RefView {
    fn new(reference: &crate::ref_store::core::pack_commit::CapturedRef) -> Self {
        Self { name: reference.name().to_owned(), oid: reference.oid_hex().to_owned() }
    }
}

#[derive(Serialize)]
struct PackView {
    pack_id: Uuid,
    registration_id: Uuid,
    artifact_set_digest: String,
    joined_revision: Option<i64>,
    artifact_count: usize,
    verified_bytes: u64,
    artifacts: Vec<ArtifactView>,
}

impl PackView {
    fn new(pack: &RegisteredPack) -> Self {
        let artifacts = pack.artifacts().iter().map(ArtifactView::new).collect::<Vec<_>>();
        Self {
            pack_id: pack.pack_id(),
            registration_id: pack.registration_id(),
            artifact_set_digest: pack.artifact_set_digest().as_hex(),
            joined_revision: pack.joined_revision(),
            artifact_count: artifacts.len(),
            verified_bytes: artifacts.iter().fold(0u64, |total, artifact| total.saturating_add(artifact.length)),
            artifacts,
        }
    }
}

#[derive(Serialize)]
struct ArtifactView {
    role: &'static str,
    sha256: String,
    length: u64,
}

impl ArtifactView {
    fn new(artifact: &crate::ref_store::core::pack_commit::RegisteredArtifact) -> Self {
        Self {
            role: artifact.role().as_str(),
            sha256: artifact.verified_sha256().as_str().to_owned(),
            length: artifact.verified_length(),
        }
    }
}

pub(super) async fn create_snapshot(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name)): Path<(String, String)>,
    headers: HeaderMap,
    payload: Result<Json<CreateSnapshotBody>, JsonRejection>,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let input = json_body(payload)?;
    let identity = authenticate(&state, &headers).await?;
    authorize_write(&identity)?;
    let deadline = state.deadline();
    let outcome = PgServingSnapshotMetadata
        .create(
            state.pool(),
            &identity,
            ServingSnapshotCreate {
                owner,
                name: name.to_owned(),
                idempotency_key: input.idempotency_key,
                lease_seconds: input.lease_seconds,
            },
            state.store().backend_identity(),
            deadline,
        )
        .await
        .map_err(metadata_error)?;
    let status = if outcome.replayed { StatusCode::OK } else { StatusCode::CREATED };
    json_response(&state, status, &SnapshotCreateView::new(&outcome.receipt, outcome.replayed))
}

pub(super) async fn read_snapshot(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name, snapshot)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let snapshot_id = parse_snapshot_id(&snapshot)?;
    let identity = authenticate(&state, &headers).await?;
    let deadline = state.deadline();
    let snapshot = PgServingSnapshotMetadata
        .read(
            state.pool(),
            &identity,
            ServingSnapshotRead { owner, name: name.to_owned(), snapshot_id },
            state.store().backend_identity(),
            deadline,
        )
        .await
        .map_err(metadata_error)?;
    json_response(&state, StatusCode::OK, &SnapshotView::new(&snapshot))
}

pub(super) async fn renew_snapshot(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name, snapshot)): Path<(String, String, String)>,
    headers: HeaderMap,
    payload: Result<Json<RenewSnapshotBody>, JsonRejection>,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let snapshot_id = parse_snapshot_id(&snapshot)?;
    let input = json_body(payload)?;
    let identity = authenticate(&state, &headers).await?;
    authorize_write(&identity)?;
    let deadline = state.deadline();
    let outcome = PgServingSnapshotMetadata
        .renew(
            state.pool(),
            &identity,
            ServingSnapshotRenew {
                owner,
                name: name.to_owned(),
                snapshot_id,
                idempotency_key: input.idempotency_key,
                expected_generation: input.expected_generation,
                lease_seconds: input.lease_seconds,
            },
            state.store().backend_identity(),
            deadline,
        )
        .await
        .map_err(metadata_error)?;
    json_response(&state, StatusCode::OK, &PinMutationView::new(&outcome.receipt, outcome.replayed))
}

pub(super) async fn release_snapshot(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, raw_name, snapshot)): Path<(String, String, String)>,
    headers: HeaderMap,
    payload: Result<Json<ReleaseSnapshotBody>, JsonRejection>,
) -> Result<Response, GatewayError> {
    let name = strip_name(&raw_name)?;
    let snapshot_id = parse_snapshot_id(&snapshot)?;
    let input = json_body(payload)?;
    let identity = authenticate(&state, &headers).await?;
    authorize_write(&identity)?;
    let deadline = state.deadline();
    let outcome = PgServingSnapshotMetadata
        .release(
            state.pool(),
            &identity,
            ServingSnapshotRelease {
                owner,
                name: name.to_owned(),
                snapshot_id,
                idempotency_key: input.idempotency_key,
                expected_generation: input.expected_generation,
                reason: PinReleaseReason::ClientDone,
            },
            state.store().backend_identity(),
            deadline,
        )
        .await
        .map_err(metadata_error)?;
    json_response(&state, StatusCode::OK, &PinMutationView::new(&outcome.receipt, outcome.replayed))
}

fn json_body<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, GatewayError> {
    match payload {
        Ok(Json(value)) => Ok(value),
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => Err(GatewayError::TooLarge),
        Err(_) => Err(GatewayError::BadRequest("invalid snapshot metadata request")),
    }
}

fn parse_snapshot_id(raw: &str) -> Result<Uuid, GatewayError> {
    let snapshot_id = Uuid::parse_str(raw).map_err(|_| GatewayError::BadRequest("invalid snapshot identifier"))?;
    if snapshot_id.is_nil() {
        return Err(GatewayError::BadRequest("invalid snapshot identifier"));
    }
    Ok(snapshot_id)
}

fn metadata_error(error: crate::Error) -> GatewayError {
    match error.0 {
        StatusCode::BAD_REQUEST => GatewayError::BadRequest("invalid snapshot metadata request"),
        StatusCode::UNAUTHORIZED => GatewayError::Unauthorized,
        StatusCode::FORBIDDEN => GatewayError::Forbidden("snapshot metadata is not authorized"),
        StatusCode::NOT_FOUND => GatewayError::NotFound,
        StatusCode::CONFLICT => GatewayError::Conflict("snapshot metadata state changed; retry the same request"),
        StatusCode::PAYLOAD_TOO_LARGE => GatewayError::TooLarge,
        StatusCode::TOO_MANY_REQUESTS => GatewayError::TooManyRequests("retained snapshot quota is exhausted"),
        StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => GatewayError::Timeout,
        StatusCode::SERVICE_UNAVAILABLE => {
            if error.1 == "metadata commit outcome is unknown; retry the same request" {
                GatewayError::Unavailable(
                    "snapshot metadata commit outcome is unknown; retry the same idempotency key",
                )
            } else {
                GatewayError::Unavailable("snapshot metadata is temporarily unavailable")
            }
        }
        _ => GatewayError::Internal("snapshot metadata request was refused"),
    }
}

fn json_response<T: Serialize>(
    state: &BlobGitState,
    status: StatusCode,
    value: &T,
) -> Result<Response, GatewayError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| GatewayError::Internal("snapshot metadata response could not be encoded"))?;
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
