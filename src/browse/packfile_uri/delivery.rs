//! Axum signed `packfile-uris` server with bounded pack storage, inbound `Host`
//! & caller-header validation, and `Body::from_stream` chunked streaming holding
//! concurrency, byte, and retention pin guards until stream completion or drop.

use std::{
    collections::HashMap,
    io,
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
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use bytes::Bytes;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::{sync::Semaphore, time::Instant};
use uuid::Uuid;

use super::{
    retention::PackDeliveryLeaseRegistry,
    signing::{LivePackReadAuthorizer, PackUriKeyring, VerifyDownloadParams, verify_signed_download_request},
    ssrf_guard::{PackUriDnsResolver, redact_uri_for_log, validate_policy_config},
    types::{DownloadSubjectContext, InflightBytesLimiter, OffloadPolicyConfig, PackObjectFormat, PackfileUriError},
};

const STREAM_CHUNK_BYTES: usize = 32 * 1024;
const DEFAULT_MAX_CACHED_PACKS: usize = 256;

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

#[derive(Default)]
struct BoundedPackStore {
    entries: HashMap<String, PackStreamMeta>,
    total_bytes: u64,
}

/// Shared state serving signed `https://` packfile requests with live checks & byte bounds.
pub struct PackHttpServerState {
    pub keyring: Arc<PackUriKeyring>,
    pub leases: PackDeliveryLeaseRegistry,
    policy: RwLock<OffloadPolicyConfig>,
    pub resolver: Arc<dyn PackUriDnsResolver>,
    pub authorizer: Arc<dyn LivePackReadAuthorizer>,
    packs: RwLock<BoundedPackStore>,
    pub max_cached_packs: usize,
    pub max_cached_bytes: u64,
    pub inflight_limiter: Arc<Semaphore>,
    pub inflight_bytes: Arc<InflightBytesLimiter>,
    pub clock_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
    pub served_requests: AtomicU64,
    pub rejected_requests: AtomicU64,
}

impl PackHttpServerState {
    pub fn new(
        keyring: Arc<PackUriKeyring>,
        leases: PackDeliveryLeaseRegistry,
        policy: OffloadPolicyConfig,
        resolver: Arc<dyn PackUriDnsResolver>,
        authorizer: Arc<dyn LivePackReadAuthorizer>,
        clock_unix: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        let inflight_downloads = policy.max_inflight_downloads.max(1);
        let max_bytes = policy.max_inflight_bytes.max(1);
        Self {
            keyring,
            leases,
            policy: RwLock::new(policy),
            resolver,
            authorizer,
            packs: RwLock::new(BoundedPackStore::default()),
            max_cached_packs: DEFAULT_MAX_CACHED_PACKS,
            max_cached_bytes: max_bytes,
            inflight_limiter: Arc::new(Semaphore::new(inflight_downloads)),
            inflight_bytes: Arc::new(InflightBytesLimiter::new(max_bytes)),
            clock_unix,
            served_requests: AtomicU64::new(0),
            rejected_requests: AtomicU64::new(0),
        }
    }

    pub fn current_policy(&self) -> OffloadPolicyConfig {
        self.policy.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    pub fn set_policy(&self, updated: OffloadPolicyConfig) {
        *self.policy.write().unwrap_or_else(|p| p.into_inner()) = updated;
    }

    pub fn insert_pack(&self, meta: PackStreamMeta) -> Result<(), PackfileUriError> {
        meta.validate_bytes()?;
        let new_len = meta.payload.len() as u64;
        let key = scoped_pack_key(meta.tenant_id, meta.repository_id, &meta.pack_oid);
        let mut guard = self.packs.write().unwrap_or_else(|p| p.into_inner());
        let replaced_len = guard.entries.get(&key).map_or(0, |old| old.payload.len() as u64);
        let is_new = !guard.entries.contains_key(&key);
        let projected = guard.total_bytes.saturating_sub(replaced_len).saturating_add(new_len);
        if (is_new && guard.entries.len() >= self.max_cached_packs) || projected > self.max_cached_bytes {
            let now = (self.clock_unix)();
            guard.entries.retain(|_, existing| {
                !self.leases.can_sweep_pack(existing.tenant_id, existing.repository_id, &existing.pack_oid, now)
            });
            guard.total_bytes = guard.entries.values().map(|e| e.payload.len() as u64).sum();
        }
        let replaced_after = guard.entries.get(&key).map_or(0, |old| old.payload.len() as u64);
        let projected_after = guard.total_bytes.saturating_sub(replaced_after).saturating_add(new_len);
        if (!guard.entries.contains_key(&key) && guard.entries.len() >= self.max_cached_packs)
            || projected_after > self.max_cached_bytes
        {
            return Err(PackfileUriError::CapacityExceeded("pack store capacity exceeded".to_owned()));
        }
        guard.total_bytes = projected_after;
        guard.entries.insert(key, meta);
        Ok(())
    }

    pub fn pack_count(&self) -> usize {
        self.packs.read().unwrap_or_else(|p| p.into_inner()).entries.len()
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
        return Err(PackfileUriError::IntegrityMismatch("pack trailing checksum mismatches descriptor".to_owned()));
    }
    let actual_sha256 = hex::encode(Sha256::digest(bytes));
    if actual_sha256 != expected_sha256_hex {
        return Err(PackfileUriError::IntegrityMismatch("pack sha256 mismatches signed expectation".to_owned()));
    }
    Ok(())
}

/// Parameters authenticating and scoping a server-side signed packfile stream.
pub struct ServePackRequest<'a> {
    pub raw_uri: &'a str,
    pub inbound_host: &'a str,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pack_oid: &'a str,
    pub object_format: PackObjectFormat,
    pub presented_subject: Option<DownloadSubjectContext>,
}

/// Prepares a guarded chunked [`Body`] holding concurrency, byte, and pin guards until EOF/drop.
pub async fn serve_signed_packfile_stream(
    state: Arc<PackHttpServerState>,
    req: &ServePackRequest<'_>,
) -> Result<Body, PackfileUriError> {
    let policy = state.current_policy();
    if let Err(err) = validate_policy_config(&policy) {
        state.rejected_requests.fetch_add(1, Ordering::Relaxed);
        return Err(err);
    }
    let permit = state.inflight_limiter.clone().try_acquire_owned().map_err(|_| {
        state.rejected_requests.fetch_add(1, Ordering::Relaxed);
        PackfileUriError::CapacityExceeded("inflight offload concurrency limit reached".to_owned())
    })?;
    let now_unix = (state.clock_unix)();
    let verified = match verify_signed_download_request(
        &state.keyring,
        state.authorizer.as_ref(),
        &VerifyDownloadParams {
            raw_uri: req.raw_uri,
            inbound_host: req.inbound_host,
            expected_tenant_id: req.tenant_id,
            expected_repository_id: req.repository_id,
            expected_pack_oid: req.pack_oid,
            expected_format: req.object_format,
            presented_subject: req.presented_subject,
            now_unix,
            policy: &policy,
            resolver: state.resolver.as_ref(),
        },
    )
    .await
    {
        Ok(v) => v,
        Err(err) => {
            state.rejected_requests.fetch_add(1, Ordering::Relaxed);
            return Err(err);
        }
    };

    let hold = match state.leases.begin_download_hold(
        verified.claims.pin_id,
        req.tenant_id,
        req.repository_id,
        req.pack_oid,
        &verified.claims.subject,
        now_unix,
    ) {
        Ok(h) => h,
        Err(err) => {
            state.rejected_requests.fetch_add(1, Ordering::Relaxed);
            return Err(err);
        }
    };
    let meta = {
        let guard = state.packs.read().unwrap_or_else(|p| p.into_inner());
        guard.entries.get(&scoped_pack_key(req.tenant_id, req.repository_id, req.pack_oid)).cloned()
    }
    .ok_or_else(|| {
        state.rejected_requests.fetch_add(1, Ordering::Relaxed);
        PackfileUriError::RetentionPinMissing("pack missing from storage".to_owned())
    })?;
    meta.validate_bytes()?;
    let bytes_guard = state.inflight_bytes.try_reserve(meta.payload.len() as u64).inspect_err(|_| {
        state.rejected_requests.fetch_add(1, Ordering::Relaxed);
    })?;

    let deadline = Instant::now() + Duration::from_millis(policy.request_deadline_ms);
    let claims = verified.claims;
    let payload = meta.payload;
    let stream = async_stream::stream! {
        let _permit_keep = permit;
        let _bytes_keep = bytes_guard;
        let _hold_keep = hold;
        let mut offset = 0usize;
        while offset < payload.len() {
            if !state.current_policy().enabled
                || Instant::now() > deadline
                || !state.leases.is_hold_still_valid(claims.pin_id)
            {
                state.rejected_requests.fetch_add(1, Ordering::Relaxed);
                yield Err(io::Error::other("packfile stream aborted by policy, deadline, or pin revocation"));
                return;
            }
            if state
                .authorizer
                .authorize_pack_download(
                    claims.tenant_id,
                    claims.repository_id,
                    &claims.subject,
                    &claims.pack_oid,
                    claims.pin_id,
                )
                .await
                .is_err()
            {
                state.rejected_requests.fetch_add(1, Ordering::Relaxed);
                yield Err(io::Error::new(io::ErrorKind::PermissionDenied, "live auth revoked during stream"));
                return;
            }
            let end = (offset + STREAM_CHUNK_BYTES).min(payload.len());
            yield Ok::<Bytes, io::Error>(payload.slice(offset..end));
            offset = end;
        }
        state.served_requests.fetch_add(1, Ordering::Relaxed);
    };
    Ok(Body::from_stream(stream))
}

/// Convenience helper collecting [`serve_signed_packfile_stream`] into a verified byte vector.
pub async fn serve_signed_packfile(
    state: Arc<PackHttpServerState>,
    req: &ServePackRequest<'_>,
) -> Result<Vec<u8>, PackfileUriError> {
    let body = serve_signed_packfile_stream(state, req).await?;
    let mut stream = body.into_data_stream();
    let mut out = Vec::new();
    while let Some(frame) = stream.next().await {
        let chunk = frame.map_err(|e| {
            if e.to_string().contains("live auth") {
                PackfileUriError::Unauthorized
            } else {
                PackfileUriError::RetentionPinMissing(e.to_string())
            }
        })?;
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPackRouteQuery {
    pub tenant: Uuid,
    pub repo: Uuid,
    pub pack: String,
    pub fmt: String,
    pub actor: Uuid,
    pub tok: Uuid,
    pub epoch: u64,
    pub exp: u64,
    pub kid: String,
    pub nonce: String,
    pub pin: Uuid,
    pub sig: String,
}

/// Builds an Axum router exposing chunked signed pack downloads with strict `Host` & policy checks.
pub fn build_signed_packfile_router(state: Arc<PackHttpServerState>) -> Router {
    let prefix = state.current_policy().path_prefix;
    let base = if prefix == "/" { String::new() } else { prefix };
    let route = format!("{base}/{{tenant}}/{{repo}}/{{pack_file}}");
    Router::new().route(&route, get(axum_serve_handler)).with_state(state)
}

async fn axum_serve_handler(
    State(state): State<Arc<PackHttpServerState>>,
    AxumPath((tenant, repo, pack_file)): AxumPath<(Uuid, Uuid, String)>,
    Query(query): Query<SignedPackRouteQuery>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let policy = state.current_policy();
    if !policy.enabled {
        state.rejected_requests.fetch_add(1, Ordering::Relaxed);
        return closed_response(StatusCode::SERVICE_UNAVAILABLE, Body::from("offload disabled"));
    }
    let Some(pack_oid) = pack_file.strip_suffix(".pack") else {
        return closed_response(StatusCode::BAD_REQUEST, Body::from("invalid pack suffix"));
    };
    let Ok((inbound_host, authority)) = extract_inbound_authority(&headers, &uri, &policy) else {
        state.rejected_requests.fetch_add(1, Ordering::Relaxed);
        return closed_response(StatusCode::BAD_REQUEST, Body::from("invalid Host authority"));
    };
    let presented_subject = match extract_optional_subject_headers(&headers) {
        Ok(sub) => sub,
        Err(_) => {
            state.rejected_requests.fetch_add(1, Ordering::Relaxed);
            return closed_response(StatusCode::FORBIDDEN, Body::from("invalid caller identity headers"));
        }
    };
    let fmt = match query.fmt.as_str() {
        "sha1" => PackObjectFormat::Sha1,
        "sha256" => PackObjectFormat::Sha256,
        _ => return closed_response(StatusCode::BAD_REQUEST, Body::from("invalid object format")),
    };
    let raw_q = uri.query().unwrap_or_default();
    let full_uri = format!("https://{authority}{}?{raw_q}", uri.path());
    let _ = redact_uri_for_log(&full_uri);
    let req = ServePackRequest {
        raw_uri: &full_uri,
        inbound_host: &inbound_host,
        tenant_id: tenant,
        repository_id: repo,
        pack_oid,
        object_format: fmt,
        presented_subject,
    };
    match serve_signed_packfile_stream(Arc::clone(&state), &req).await {
        Ok(body) => closed_response(StatusCode::OK, body),
        Err(PackfileUriError::Unauthorized | PackfileUriError::ScopeMismatch(_)) => {
            closed_response(StatusCode::FORBIDDEN, Body::from("forbidden"))
        }
        Err(PackfileUriError::TokenExpired | PackfileUriError::RetentionPinMissing(_)) => {
            closed_response(StatusCode::GONE, Body::from("expired or unpinned"))
        }
        Err(PackfileUriError::CapacityExceeded(_)) => closed_response(StatusCode::TOO_MANY_REQUESTS, Body::from("busy")),
        Err(_) => closed_response(StatusCode::BAD_REQUEST, Body::from("rejected")),
    }
}

fn extract_inbound_authority(
    headers: &HeaderMap,
    uri: &Uri,
    policy: &OffloadPolicyConfig,
) -> Result<(String, String), PackfileUriError> {
    let raw_hdr = headers.get(header::HOST).and_then(|v| v.to_str().ok()).map(str::trim);
    let raw_uri = uri.authority().map(|a| a.as_str());
    let raw = match (raw_hdr, raw_uri) {
        (Some(h), Some(u)) if !h.eq_ignore_ascii_case(u) => {
            return Err(PackfileUriError::ScopeMismatch("Host and URI authority conflict".to_owned()));
        }
        (Some(h), _) if !h.is_empty() => h,
        (_, Some(u)) if !u.is_empty() => u,
        _ => return Err(PackfileUriError::ScopeMismatch("missing Host header".to_owned())),
    };
    let authority: axum::http::uri::Authority = raw
        .parse()
        .map_err(|_| PackfileUriError::ScopeMismatch("malformed Host authority".to_owned()))?;
    let host = authority.host().to_ascii_lowercase();
    let formatted = match (policy.loopback_test_port(), authority.port_u16()) {
        (Some(tp), Some(p)) if p == tp => format!("{host}:{tp}"),
        (None, None | Some(443)) => host.clone(),
        _ => return Err(PackfileUriError::ScopeMismatch("unexpected Host port".to_owned())),
    };
    Ok((host, formatted))
}

fn extract_optional_subject_headers(headers: &HeaderMap) -> Result<Option<DownloadSubjectContext>, PackfileUriError> {
    let a = headers.get("x-rootyard-actor");
    let t = headers.get("x-rootyard-token-id");
    let e = headers.get("x-rootyard-auth-epoch");
    match (a, t, e) {
        (None, None, None) => Ok(None),
        (Some(av), Some(tv), Some(ev)) => {
            let actor = Uuid::parse_str(av.to_str().map_err(|_| PackfileUriError::Unauthorized)?)
                .map_err(|_| PackfileUriError::Unauthorized)?;
            let tok = Uuid::parse_str(tv.to_str().map_err(|_| PackfileUriError::Unauthorized)?)
                .map_err(|_| PackfileUriError::Unauthorized)?;
            let ep = ev
                .to_str()
                .map_err(|_| PackfileUriError::Unauthorized)?
                .parse::<u64>()
                .map_err(|_| PackfileUriError::Unauthorized)?;
            Ok(Some(DownloadSubjectContext::new(actor, tok, ep)?))
        }
        _ => Err(PackfileUriError::Unauthorized),
    }
}

fn closed_response(status: StatusCode, body: Body) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONNECTION, "close")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
