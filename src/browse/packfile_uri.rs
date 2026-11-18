//! Optional Git Protocol v2 `packfile-uris` offload & safe inline fallback
//! delivery (Issue #185).
//!
//! Design boundaries:
//! - Opt-in capability negotiation (`packfile-uris=https` capability + pkt-line)
//!   with deterministic inline fallback when unsupported, disabled, unhealthy,
//!   or when active pack retention pins cannot be guaranteed.
//! - Short-lived HMAC-SHA256 signed `https://` offload URLs scoped strictly to
//!   `(tenant_id, repository_id, pack_oid, object_format, allowed_host, exp,
//!   key_id, scope_nonce, pin_id)`, guarded by strict SSRF + DNS IP checks.
//! - Live per-request authorization and active retention pin holds enforced
//!   before and during streaming; URL/cache hits are never treated as authority.
//! - Bounded inflight downloads, bytes, retries, and request deadlines with
//!   SHA-256 + trailer checksum verification and fail-closed corruption checks.

pub mod delivery;
pub mod planner;
pub mod protocol_v2;
pub mod retention;
pub mod signing;
pub mod ssrf_guard;
pub mod types;

#[cfg(test)]
mod tests;

pub use delivery::{
    FetchAttemptResult, PackDownloaderConfig, PackHttpServerState, PackStreamMeta, build_signed_packfile_router,
    fetch_pack_with_integrity_and_retry, serve_signed_packfile, validate_pack_bytes_integrity,
};
pub use planner::{
    CdnCircuitBreaker, CdnHealthState, DeliveryPlanRequest, DeliveryPlanner, PackClosurePlan, PlannedFetchResponse,
};
pub use protocol_v2::{
    FetchV2Request, ParsedUriProtocolSet, decode_packfile_uris_section, encode_fetch_v2_response,
    fetch_capability_tokens, format_fetch_capability_line, parse_fetch_v2_request, parse_uri_protocol_list,
};
pub use retention::{
    AcquireLeaseParams, InflightDownloadGuard, OffloadPackPinGuard, PackDeliveryLeaseRegistry, RetentionLeaseState,
};
pub use signing::{
    LivePackReadAuthorizer, MintUriRequest, PackUriKeyring, SignedDownloadClaims, SigningKeyMaterial,
    VerifiedDownloadContext, VerifyDownloadParams, mint_signed_offload_uri, verify_signed_download_request,
};
pub use ssrf_guard::{
    ValidatedOffloadUri, redact_uri_for_log, validate_offload_host_pattern, validate_offload_uri,
    validate_path_prefix, validate_policy_config,
};
pub use types::{
    DEFAULT_MAX_INFLIGHT_DOWNLOADS, DEFAULT_MAX_RETRIES_PER_PACK, DEFAULT_MAX_URIS_PER_FETCH, DEFAULT_OFFLOAD_TTL_SECS,
    DEFAULT_RETENTION_GRACE_SECS, DeliveryMode, DeliveryTelemetry, FallbackReason, MAX_OFFLOAD_BYTES_HARD_CAP,
    MAX_OFFLOAD_TTL_SECS, MAX_RETENTION_GRACE_SECS, MAX_URIS_PER_FETCH_CAP, MIN_OFFLOAD_TTL_SECS,
    OffloadPolicyConfig, PackObjectFormat, PackfileClosureMember, PackfileUriError, SignedPackfileDescriptor,
    from_browse_format, to_browse_format, validate_catalog_pack_oid, validate_hex_sha256, validate_pack_oid,
};
