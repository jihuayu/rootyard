//! Bounded packfile HTTP download client (retry, SHA-256 + trailer checksum,
//! SSRF redirect refusal) and Axum signed packfile server with live auth & pin
//! re-validation before and during chunked streaming.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::{Path as AxumPath, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use bytes::Bytes;
use reqwest::redirect;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use uuid::Uuid;

use super::{
    retention::PackDeliveryLeaseRegistry,
    signing::{LivePackReadAuthorizer, PackUriKeyring, VerifyDownloadParams, verify_signed_download_request},
    ssrf_guard::{redact_uri_for_log, validate_offload_uri},
    types::{FallbackReason, OffloadPolicyConfig, PackObjectFormat, PackfileUriError, SignedPackfileDescriptor},
};

const STREAM_CHUNK_BYTES: usize = 32 * 1024;

/// Verified immutable pack blob stored behind an offload endpoint.
#[derive(Clone)]
pub struct PackStreamMeta {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pack_oid: String,
    pub pack_hash_hex: String,
    pub object_format: PackObjectFormat,
    pub sha256_hex: String,
    pub payload: Bytes,
}

impl PackStreamMeta {
    pub fn validate_bytes(&self) -> Result<(), PackfileUriError> {
        validate_pack_bytes_integrity(
            &self.payload,
            self.payload.len() as u64,
            &self.sha256_hex,
            &self.pack_hash_hex,
            self.object_format,
        )
    }
}

/// Shared state serving signed `https://` packfile requests with live checks.
pub struct PackHttpServerState {
    pub keyring: Arc<PackUriKeyring>,
    pub leases: PackDeliveryLeaseRegistry,
    pub policy: OffloadPolicyConfig,
    pub allowed_resolved_ips: Vec<IpAddr>,
    pub authorizer: Arc<dyn LivePackReadAuthorizer>,
    pub packs: Arc<RwLock<HashMap<String, PackStreamMeta>>>,
    pub inflight_limiter: Arc<Semaphore>,
    pub clock_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub served_requests: AtomicU64,
    pub rejected_requests: AtomicU64,
}

impl PackHttpServerState {
    pub fn insert_pack(&self, meta: PackStreamMeta) -> Result<(), PackfileUriError> {
        meta.validate_bytes()?;
        let key = scoped_pack_key(meta.tenant_id, meta.repository_id, &meta.pack_oid);
        let mut guard = self.packs.write().unwrap_or_else(|p| p.into_inner());
        guard.insert(key, meta);
        Ok(())
    }

    pub fn remove_pack(&self, tenant_id: Uuid, repository_id: Uuid, pack_oid: &str) -> bool {
        let key = scoped_pack_key(tenant_id, repository_id, pack_oid);
        let mut guard = self.packs.write().unwrap_or_else(|p| p.into_inner());
        guard.remove(&key).is_some()
    }
}

fn scoped_pack_key(tenant_id: Uuid, repository_id: Uuid, pack_oid: &str) -> String {
    format!("{tenant_id}/{repository_id}/{pack_oid}")
}

/// Verifies Git `.pack` magic header, version (`2` or `3`), exact byte count,
/// SHA-256 digest, and trailing Git pack hash matching `expected_pack_hash_hex`.
pub fn validate_pack_bytes_integrity(
    bytes: &[u8],
    expected_len: u64,
    expected_sha256_hex: &str,
    expected_pack_hash_hex: &str,
    object_format: PackObjectFormat,
) -> Result<(), PackfileUriError> {
    if bytes.len() as u64 != expected_len {
        return Err(PackfileUriError::IntegrityMismatch(format!(
            "pack byte length {} mismatches expected {expected_len}",
            bytes.len()
        )));
    }
    let trailer_len = object_format.oid_hex_len() / 2;
    if bytes.len() < 12 + trailer_len || &bytes[..4] != b"PACK" {
        return Err(PackfileUriError::IntegrityMismatch("invalid PACK header".to_owned()));
    }
    let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != 2 && version != 3 {
        return Err(PackfileUriError::IntegrityMismatch(format!("unsupported PACK version {version}")));
    }
    let actual_trailer = hex::encode(&bytes[bytes.len() - trailer_len..]);
    if actual_trailer != expected_pack_hash_hex {
        return Err(PackfileUriError::IntegrityMismatch(
            "pack trailing checksum mismatches descriptor".to_owned(),
        ));
    }
    let actual_sha256 = hex::encode(Sha256::digest(bytes));
    if actual_sha256 != expected_sha256_hex {
        return Err(PackfileUriError::IntegrityMismatch(
            "pack sha256 mismatches signed expectation".to_owned(),
        ));
    }
    Ok(())
}

/// Validates signature, live auth, retention pin hold, and streams pack bytes safely.
pub async fn serve_signed_packfile(
    state: &PackHttpServerState,
    raw_uri: &str,
    tenant_id: Uuid,
    repository_id: Uuid,
    pack_oid: &str,
    object_format: PackObjectFormat,
    actor_id: Uuid,
) -> Result<Vec<u8>, PackfileUriError> {
    let _permit = state
        .inflight_limiter
        .try_acquire()
        .map_err(|_| PackfileUriError::CapacityExceeded("inflight offload concurrency limit reached".to_owned()))?;
    let now_unix = (state.clock_unix)();
    let res = verify_signed_download_request(
        &state.keyring,
        state.authorizer.as_ref(),
        &VerifyDownloadParams {
            raw_uri,
            expected_tenant_id: tenant_id,
            expected_repository_id: repository_id,
            expected_pack_oid: pack_oid,
            expected_format: object_format,
            actor_id,
            now_unix,
            policy: &state.policy,
            resolved_ips: &state.allowed_resolved_ips,
        },
    )
    .await;
    let verified = match res {
        Ok(v) => v,
        Err(err) => {
            state.rejected_requests.fetch_add(1, Ordering::Relaxed);
            return Err(err);
        }
    };

    let _hold = state.leases.begin_download_hold(
        verified.claims.pin_id,
        tenant_id,
        repository_id,
        pack_oid,
        now_unix,
    )?;
    let meta = {
        let guard = state.packs.read().unwrap_or_else(|p| p.into_inner());
        guard
            .get(&scoped_pack_key(tenant_id, repository_id, pack_oid))
            .cloned()
    }
    .ok_or_else(|| PackfileUriError::RetentionPinMissing("pack missing from storage".to_owned()))?;

    meta.validate_bytes()?;
    let mut out = Vec::with_capacity(meta.payload.len());
    for chunk in meta.payload.chunks(STREAM_CHUNK_BYTES) {
        if !state.leases.is_hold_still_valid(verified.claims.pin_id) {
            state.rejected_requests.fetch_add(1, Ordering::Relaxed);
            return Err(PackfileUriError::RetentionPinMissing(
                "retention pin revoked during pack stream".to_owned(),
            ));
        }
        out.extend_from_slice(chunk);
    }
    state.served_requests.fetch_add(1, Ordering::Relaxed);
    Ok(out)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPackRouteQuery {
    pub tenant: Uuid,
    pub repo: Uuid,
    pub pack: String,
    pub fmt: String,
    pub exp: u64,
    pub kid: String,
    pub nonce: String,
    pub pin: Uuid,
    pub sig: String,
}

/// Builds an Axum router exposing signed pack downloads with `Connection: close`.
pub fn build_signed_packfile_router(state: Arc<PackHttpServerState>) -> Router {
    let prefix = if state.policy.path_prefix == "/" {
        String::new()
    } else {
        state.policy.path_prefix.clone()
    };
    let route = format!("{prefix}/{{tenant}}/{{repo}}/{{pack_file}}");
    Router::new().route(&route, get(axum_serve_handler)).with_state(state)
}

async fn axum_serve_handler(
    State(state): State<Arc<PackHttpServerState>>,
    AxumPath((tenant, repo, pack_file)): AxumPath<(Uuid, Uuid, String)>,
    Query(query): Query<SignedPackRouteQuery>,
    uri: axum::http::Uri,
) -> Response {
    let Some(pack_oid) = pack_file.strip_suffix(".pack") else {
        return closed_response(StatusCode::BAD_REQUEST, b"invalid pack suffix".to_vec());
    };
    let Some(host) = state.policy.allowed_hosts.first() else {
        return closed_response(StatusCode::SERVICE_UNAVAILABLE, b"no offload host".to_vec());
    };
    let fmt = match query.fmt.as_str() {
        "sha1" => PackObjectFormat::Sha1,
        "sha256" => PackObjectFormat::Sha256,
        _ => return closed_response(StatusCode::BAD_REQUEST, b"invalid object format".to_vec()),
    };
    let full_uri = format!(
        "https://{host}{}?tenant={}&repo={}&pack={}&fmt={}&exp={}&kid={}&nonce={}&pin={}&sig={}",
        uri.path(),
        query.tenant.hyphenated(),
        query.repo.hyphenated(),
        query.pack,
        query.fmt,
        query.exp,
        query.kid,
        query.nonce,
        query.pin.hyphenated(),
        query.sig
    );
    let _ = redact_uri_for_log(&full_uri);
    match serve_signed_packfile(&state, &full_uri, tenant, repo, pack_oid, fmt, Uuid::nil()).await {
        Ok(bytes) => closed_response(StatusCode::OK, bytes),
        Err(PackfileUriError::Unauthorized) => closed_response(StatusCode::FORBIDDEN, b"forbidden".to_vec()),
        Err(PackfileUriError::TokenExpired | PackfileUriError::RetentionPinMissing(_)) => {
            closed_response(StatusCode::GONE, b"expired or unpinned".to_vec())
        }
        Err(PackfileUriError::CapacityExceeded(_)) => {
            closed_response(StatusCode::TOO_MANY_REQUESTS, b"busy".to_vec())
        }
        Err(_) => closed_response(StatusCode::BAD_REQUEST, b"rejected".to_vec()),
    }
}

fn closed_response(status: StatusCode, body: Vec<u8>) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONNECTION, "close")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Bounded HTTP pack download client config enforcing no auto-redirects and strict byte/deadline caps.
#[derive(Clone)]
pub struct PackDownloaderConfig {
    pub client: reqwest::Client,
    pub concurrency_limit: Arc<Semaphore>,
    pub request_deadline: Duration,
    pub max_retries: usize,
    pub max_pack_bytes: u64,
}

impl PackDownloaderConfig {
    pub fn build(policy: &OffloadPolicyConfig) -> Result<Self, PackfileUriError> {
        let client = reqwest::Client::builder()
            .redirect(redirect::Policy::none())
            .timeout(Duration::from_millis(policy.request_deadline_ms))
            .build()
            .map_err(|e| PackfileUriError::Internal(format!("client init failed: {e}")))?;
        Ok(Self {
            client,
            concurrency_limit: Arc::new(Semaphore::new(policy.max_inflight_downloads.max(1))),
            request_deadline: Duration::from_millis(policy.request_deadline_ms),
            max_retries: policy.max_retries_per_pack,
            max_pack_bytes: policy.max_pack_bytes_per_request,
        })
    }
}

/// Outcome of downloading and verifying a signed pack URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchAttemptResult {
    Verified {
        bytes: Vec<u8>,
        attempts: usize,
        retransmitted_bytes: u64,
    },
    NeedsInlineFallback(FallbackReason),
}

/// Downloads a signed offload pack with redirect refusal, bounded retries, deadline,
/// and SHA-256 + trailer checksum verification.
pub async fn fetch_pack_with_integrity_and_retry(
    cfg: &PackDownloaderConfig,
    desc: &SignedPackfileDescriptor,
    object_format: PackObjectFormat,
    policy: &OffloadPolicyConfig,
    resolved_ips: &[IpAddr],
) -> Result<FetchAttemptResult, PackfileUriError> {
    validate_offload_uri(&desc.uri, policy, resolved_ips)?;
    if desc.byte_len > cfg.max_pack_bytes {
        return Err(PackfileUriError::CapacityExceeded("pack exceeds byte cap".to_owned()));
    }
    let _permit = cfg
        .concurrency_limit
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| PackfileUriError::CapacityExceeded("downloader semaphore closed".to_owned()))?;

    let mut retransmitted_bytes = 0u64;
    let total_attempts = cfg.max_retries.saturating_add(1);
    for attempt in 1..=total_attempts {
        let fut = single_fetch_attempt(&cfg.client, &desc.uri, cfg.max_pack_bytes);
        let outcome = tokio::time::timeout(cfg.request_deadline, fut).await;
        let bytes = match outcome {
            Ok(Ok(data)) => data,
            Ok(Err(
                err @ (PackfileUriError::SsrfBlocked(_)
                | PackfileUriError::CapacityExceeded(_)
                | PackfileUriError::Unauthorized
                | PackfileUriError::RetentionPinMissing(_)),
            )) => return Err(err),
            Ok(Err(_)) | Err(_) => {
                if attempt == total_attempts {
                    return Ok(FetchAttemptResult::NeedsInlineFallback(
                        FallbackReason::PreDownloadRetryExhausted,
                    ));
                }
                continue;
            }
        };
        if bytes.len() as u64 != desc.byte_len && attempt < total_attempts {
            retransmitted_bytes = retransmitted_bytes.saturating_add(bytes.len() as u64);
            continue;
        }
        validate_pack_bytes_integrity(&bytes, desc.byte_len, &desc.sha256_hex, &desc.pack_hash_hex, object_format)?;
        return Ok(FetchAttemptResult::Verified { bytes, attempts: attempt, retransmitted_bytes });
    }
    Ok(FetchAttemptResult::NeedsInlineFallback(
        FallbackReason::PreDownloadRetryExhausted,
    ))
}

async fn single_fetch_attempt(
    client: &reqwest::Client,
    uri: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, PackfileUriError> {
    let resp = client
        .get(uri)
        .send()
        .await
        .map_err(|_| PackfileUriError::CdnUnavailable("offload http transport error".to_owned()))?;
    if resp.status().is_redirection() {
        return Err(PackfileUriError::SsrfBlocked(
            "unexpected redirect blocked by SSRF policy".to_owned(),
        ));
    }
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED || resp.status() == reqwest::StatusCode::FORBIDDEN {
        return Err(PackfileUriError::Unauthorized);
    }
    if resp.status() == reqwest::StatusCode::GONE {
        return Err(PackfileUriError::RetentionPinMissing(
            "offload lease revoked or expired".to_owned(),
        ));
    }
    if !resp.status().is_success() {
        return Err(PackfileUriError::CdnUnavailable(format!(
            "offload endpoint returned {}",
            resp.status().as_u16()
        )));
    }
    if let Some(cl) = resp.content_length()
        && cl > max_bytes
    {
        return Err(PackfileUriError::CapacityExceeded("response content-length exceeds cap".to_owned()));
    }
    let body = resp
        .bytes()
        .await
        .map_err(|_| PackfileUriError::CdnUnavailable("interrupted response body".to_owned()))?;
    if body.len() as u64 > max_bytes {
        return Err(PackfileUriError::CapacityExceeded("response body exceeded cap".to_owned()));
    }
    Ok(body.to_vec())
}
