//! Optional Git Protocol v2 `packfile-uris` offload & safe inline fallback
//! delivery (Issue #185).

pub mod cover_builder;
pub mod cover_git;
pub mod delivery;
pub mod downloader;
pub mod gateway_bridge;
pub mod planner;
pub mod protocol_v2;
pub mod retention;
pub mod signing;
pub mod ssrf_guard;
pub mod types;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_audit;

pub use cover_builder::{
    MaterializedCoverBundle, RepoCoverBuildParams, build_residual_pack_bytes, build_verified_cover_proof_from_repo,
};
pub use delivery::{
    PackHttpServerState, PackStreamMeta, ServePackRequest, SignedPackRouteQuery, build_signed_packfile_router,
    serve_signed_packfile, serve_signed_packfile_stream, validate_pack_bytes_integrity,
};
pub use downloader::{FetchAttemptResult, PackDownloaderConfig, fetch_pack_with_integrity_and_retry};
pub use gateway_bridge::{GatewayFetchBridgeInput, GatewayPackfileOffload, LiveRevalidatorFn};
pub use planner::{
    CdnCircuitBreaker, CdnHealthState, DeliveryPlanRequest, DeliveryPlanner, PackWireMeta, PlannedFetchResponse,
    VerifiedPackCoverInput,
};
pub use protocol_v2::{
    FetchV2Request, MAX_FETCH_HAVES, MAX_FETCH_WANTS, ParsedUriProtocolSet, decode_packfile_uris_section,
    encode_fetch_v2_response, encode_fetch_v2_response_with_acks, fetch_capability_tokens, format_fetch_capability_line,
    format_fetch_capability_line_for_policy, inject_packfile_uris_into_v2_advertisement, parse_fetch_v2_request,
    parse_uri_protocol_list, should_advertise_packfile_uris, strip_packfile_uris_from_v2_request,
};
pub use retention::{
    AcquireLeaseParams, InflightDownloadGuard, OffloadPackPinGuard, PackDeliveryLeaseRegistry, RetentionLeaseState,
};
pub use signing::{
    LivePackReadAuthorizer, MintUriRequest, PackUriKeyring, SignedDownloadClaims, SigningKeyMaterial,
    VerifiedDownloadContext, VerifyDownloadParams, mint_signed_offload_uri, verify_signed_download_request,
};
pub use ssrf_guard::{
    PackUriDnsResolver, StaticMapDnsResolver, SystemDnsResolver, ValidatedOffloadUri, redact_uri_for_log,
    validate_offload_host_pattern, validate_offload_uri, validate_offload_uri_and_resolve, validate_path_prefix,
    validate_policy_config,
};
pub use types::{
    DEFAULT_MAX_ACTIVE_LEASES, DEFAULT_MAX_INFLIGHT_BYTES, DEFAULT_MAX_INFLIGHT_DOWNLOADS,
    DEFAULT_MAX_RETRIES_PER_PACK, DEFAULT_MAX_URIS_PER_FETCH, DEFAULT_OFFLOAD_TTL_SECS, DEFAULT_RETENTION_GRACE_SECS,
    DeliveryMode, DeliveryTelemetry, DownloadSubjectContext, FallbackReason, InflightBytesGuard, InflightBytesLimiter,
    MAX_ACTIVE_LEASES_HARD_CAP, MAX_OFFLOAD_BYTES_HARD_CAP, MAX_OFFLOAD_TTL_SECS, MAX_RETENTION_GRACE_SECS,
    MAX_URIS_PER_FETCH_CAP, MIN_OFFLOAD_TTL_SECS, OffloadPolicyConfig, PackObjectFormat, PackfileClosureMember,
    PackfileUriError, SignedPackfileDescriptor, from_browse_format, to_browse_format, validate_catalog_pack_oid,
    validate_hex_sha256, validate_pack_oid,
};
