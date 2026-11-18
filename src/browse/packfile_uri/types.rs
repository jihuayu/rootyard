//! Core domain types, bounds, errors, and redaction helpers for `packfile-uris` delivery.

use std::{fmt, sync::Arc};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    browse::object_format::ObjectFormat,
    cache_wake::replica_cache::{ReplicaObjectFormat, error::is_lower_hex_exact},
    ref_store::ref_version::PackSetEntry,
};

pub use crate::cache_wake::replica_cache::ReplicaObjectFormat as PackObjectFormat;

pub const MIN_OFFLOAD_TTL_SECS: u64 = 15;
pub const MAX_OFFLOAD_TTL_SECS: u64 = 900;
pub const DEFAULT_OFFLOAD_TTL_SECS: u64 = 120;
pub const MAX_RETENTION_GRACE_SECS: u64 = 3_600;
pub const DEFAULT_RETENTION_GRACE_SECS: u64 = 60;
pub const MAX_URIS_PER_FETCH_CAP: usize = 16;
pub const DEFAULT_MAX_URIS_PER_FETCH: usize = 4;
pub const DEFAULT_MAX_INFLIGHT_DOWNLOADS: usize = 4;
pub const DEFAULT_MAX_RETRIES_PER_PACK: usize = 2;
pub const MAX_RETRIES_HARD_CAP: usize = 3;
pub const MAX_OFFLOAD_BYTES_HARD_CAP: u64 = 8 * 1024 * 1024 * 1024;
pub const MIN_DEADLINE_MS: u64 = 100;
pub const MAX_DEADLINE_MS: u64 = 600_000;

/// Converts [`ObjectFormat`] into canonical [`PackObjectFormat`].
pub fn from_browse_format(format: ObjectFormat) -> PackObjectFormat {
    match format {
        ObjectFormat::Sha1 => ReplicaObjectFormat::Sha1,
        ObjectFormat::Sha256 => ReplicaObjectFormat::Sha256,
    }
}

/// Converts [`PackObjectFormat`] back into [`ObjectFormat`].
pub fn to_browse_format(format: PackObjectFormat) -> ObjectFormat {
    match format {
        ReplicaObjectFormat::Sha1 => ObjectFormat::Sha1,
        ReplicaObjectFormat::Sha256 => ObjectFormat::Sha256,
    }
}

/// Typed errors across `packfile-uris` negotiation, signing, SSRF, retention, and delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackfileUriError {
    Unauthorized,
    UnsupportedProtocol(String),
    SsrfBlocked(String),
    InvalidPolicy(String),
    InvalidSignature(String),
    TokenExpired,
    ScopeMismatch(String),
    RetentionPinMissing(String),
    IntegrityMismatch(String),
    ProtocolSyntax(String),
    CapacityExceeded(String),
    CdnUnavailable(String),
    Timeout(String),
    Internal(String),
}

impl fmt::Display for PackfileUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "unauthorized packfile download"),
            Self::UnsupportedProtocol(msg) => write!(f, "unsupported uri protocol: {msg}"),
            Self::SsrfBlocked(msg) => write!(f, "ssrf guard blocked offload uri: {msg}"),
            Self::InvalidPolicy(msg) => write!(f, "invalid offload policy: {msg}"),
            Self::InvalidSignature(msg) => write!(f, "invalid packfile offload signature: {msg}"),
            Self::TokenExpired => write!(f, "offload url token expired"),
            Self::ScopeMismatch(msg) => write!(f, "offload url scope mismatch: {msg}"),
            Self::RetentionPinMissing(msg) => write!(f, "active retention pin missing or revoked: {msg}"),
            Self::IntegrityMismatch(msg) => write!(f, "packfile integrity check failed: {msg}"),
            Self::ProtocolSyntax(msg) => write!(f, "invalid protocol v2 fetch payload: {msg}"),
            Self::CapacityExceeded(msg) => write!(f, "packfile offload capacity exceeded: {msg}"),
            Self::CdnUnavailable(msg) => write!(f, "cdn offload endpoint unavailable: {msg}"),
            Self::Timeout(msg) => write!(f, "packfile offload timed out: {msg}"),
            Self::Internal(msg) => write!(f, "internal packfile offload error: {msg}"),
        }
    }
}

impl std::error::Error for PackfileUriError {}

/// Policy configuration controlling optional HTTPS-only `packfile-uris` offload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OffloadPolicyConfig {
    pub enabled: bool,
    pub advertise_in_capabilities: bool,
    pub allowed_scheme: String,
    pub allowed_hosts: Vec<String>,
    pub path_prefix: String,
    pub key_id: String,
    pub ttl_secs: u64,
    pub retention_grace_secs: u64,
    pub max_uris_per_fetch: usize,
    pub max_pack_bytes_per_request: u64,
    pub max_inflight_downloads: usize,
    pub max_retries_per_pack: usize,
    pub request_deadline_ms: u64,
    pub min_pack_bytes_for_offload: u64,
    pub fallback_on_unhealthy_cdn: bool,
}

impl OffloadPolicyConfig {
    /// Strict production baseline requiring HTTPS, explicit host allowlist, and short TTL.
    pub fn strict_production(allowed_hosts: Vec<String>, key_id: impl Into<String>) -> Self {
        Self {
            enabled: true,
            advertise_in_capabilities: true,
            allowed_scheme: "https".to_owned(),
            allowed_hosts,
            path_prefix: "/v1/packs".to_owned(),
            key_id: key_id.into(),
            ttl_secs: DEFAULT_OFFLOAD_TTL_SECS,
            retention_grace_secs: DEFAULT_RETENTION_GRACE_SECS,
            max_uris_per_fetch: DEFAULT_MAX_URIS_PER_FETCH,
            max_pack_bytes_per_request: 512 * 1024 * 1024,
            max_inflight_downloads: DEFAULT_MAX_INFLIGHT_DOWNLOADS,
            max_retries_per_pack: DEFAULT_MAX_RETRIES_PER_PACK,
            request_deadline_ms: 30_000,
            min_pack_bytes_for_offload: 4 * 1024,
            fallback_on_unhealthy_cdn: true,
        }
    }

    /// Safe baseline configuration with offload disabled so callers use full inline delivery.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            advertise_in_capabilities: false,
            allowed_scheme: "https".to_owned(),
            allowed_hosts: Vec::new(),
            path_prefix: "/v1/packs".to_owned(),
            key_id: "default-disabled".to_owned(),
            ttl_secs: DEFAULT_OFFLOAD_TTL_SECS,
            retention_grace_secs: DEFAULT_RETENTION_GRACE_SECS,
            max_uris_per_fetch: DEFAULT_MAX_URIS_PER_FETCH,
            max_pack_bytes_per_request: 512 * 1024 * 1024,
            max_inflight_downloads: DEFAULT_MAX_INFLIGHT_DOWNLOADS,
            max_retries_per_pack: DEFAULT_MAX_RETRIES_PER_PACK,
            request_deadline_ms: 30_000,
            min_pack_bytes_for_offload: 4 * 1024,
            fallback_on_unhealthy_cdn: true,
        }
    }
}

/// One pre-materialized immutable pack candidate inside a repository closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackfileClosureMember {
    pub pack_oid: String,
    pub pack_hash_hex: String,
    pub sha256_hex: String,
    pub byte_len: u64,
    pub covered_objects: u64,
    pub cache_warm: bool,
}

impl PackfileClosureMember {
    /// Builds a validated candidate descriptor from metadata.
    pub fn validate(&self, object_format: PackObjectFormat) -> Result<(), PackfileUriError> {
        validate_catalog_pack_oid(&self.pack_oid, object_format)?;
        validate_pack_oid(&self.pack_hash_hex, object_format)?;
        validate_hex_sha256(&self.sha256_hex)?;
        if self.byte_len == 0 || self.byte_len > MAX_OFFLOAD_BYTES_HARD_CAP {
            return Err(PackfileUriError::InvalidPolicy(format!(
                "invalid pack byte length: {}",
                self.byte_len
            )));
        }
        Ok(())
    }

    /// Converts from a cataloged [`PackSetEntry`] plus verified pack checksum, byte length, and wire hash.
    pub fn from_pack_set_entry(
        entry: &PackSetEntry,
        pack_hash_hex: String,
        sha256_hex: String,
        byte_len: u64,
        covered_objects: u64,
        cache_warm: bool,
    ) -> Result<Self, PackfileUriError> {
        let pack_oid = hex::encode(entry.artifact_set_digest());
        if byte_len == 0 || byte_len > MAX_OFFLOAD_BYTES_HARD_CAP {
            return Err(PackfileUriError::InvalidPolicy(format!("invalid pack byte length: {byte_len}")));
        }
        validate_hex_sha256(&sha256_hex)?;
        Ok(Self { pack_oid, pack_hash_hex, sha256_hex, byte_len, covered_objects, cache_warm })
    }
}

/// Validates a catalog pack identifier (`40`/`64` hex for repository object format or 64-hex RefStore pack id).
pub fn validate_catalog_pack_oid(value: &str, format: PackObjectFormat) -> Result<(), PackfileUriError> {
    if is_lower_hex_exact(value, format.oid_hex_len()) || is_lower_hex_exact(value, 64) {
        Ok(())
    } else {
        Err(PackfileUriError::InvalidPolicy(
            "catalog pack_oid must be 40 or 64 lowercase hex chars".to_owned(),
        ))
    }
}

/// Validates a lowercase pack identifier or Git pack trailer checksum matching [`PackObjectFormat`].
pub fn validate_pack_oid(value: &str, format: PackObjectFormat) -> Result<(), PackfileUriError> {
    let expected = format.oid_hex_len();
    if is_lower_hex_exact(value, expected) {
        Ok(())
    } else {
        Err(PackfileUriError::InvalidPolicy(format!(
            "pack oid/hash must be {expected} lowercase hex chars"
        )))
    }
}

/// Validates an exact 64-char lowercase SHA-256 hex digest.
pub fn validate_hex_sha256(value: &str) -> Result<(), PackfileUriError> {
    if is_lower_hex_exact(value, 64) {
        Ok(())
    } else {
        Err(PackfileUriError::InvalidPolicy(
            "sha256 digest must be 64 lowercase hex chars".to_owned(),
        ))
    }
}

/// Short-lived signed `packfile-uris` descriptor handed to the Git client.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPackfileDescriptor {
    pub pack_oid: String,
    pub pack_hash_hex: String,
    pub sha256_hex: String,
    pub byte_len: u64,
    pub uri: String,
    pub expires_at_unix: u64,
    pub pin_id: Uuid,
    pub key_id: String,
    pub scope_nonce: String,
}

impl fmt::Debug for SignedPackfileDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedPackfileDescriptor")
            .field("pack_oid", &self.pack_oid)
            .field("pack_hash_hex", &self.pack_hash_hex)
            .field("byte_len", &self.byte_len)
            .field("uri", &super::ssrf_guard::redact_uri_for_log(&self.uri))
            .field("expires_at_unix", &self.expires_at_unix)
            .field("pin_id", &self.pin_id)
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Explains why delivery fell back to the inline Git upload-pack stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    FeatureDisabled,
    ClientOmittedPackfileUris,
    ClientUnsupportedProtocols,
    BelowOffloadThreshold,
    CdnBreakerOpen,
    CdnUnhealthy,
    PinAcquisitionFailed,
    IncompleteClosure,
    OverloadedOrQueueSaturated,
    PreDownloadRetryExhausted,
}

/// Planned fetch delivery mode for one Protocol v2 `fetch` exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryMode {
    OffloadPlusResidual {
        offloaded: Vec<SignedPackfileDescriptor>,
        residual_inline_bytes: u64,
        residual_objects: u64,
        lease_pins: Vec<Arc<super::retention::OffloadPackPinGuard>>,
    },
    InlineFallback {
        reason: FallbackReason,
        total_inline_bytes: u64,
        total_objects: u64,
    },
}

/// Observable per-fetch telemetry without secrets or credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryTelemetry {
    pub offload_used: bool,
    pub fallback_reason: Option<FallbackReason>,
    pub cache_hits: u64,
    pub blob_get_count: u64,
    pub blob_get_bytes: u64,
    pub offloaded_bytes: u64,
    pub inline_bytes: u64,
    pub duplicate_retransmit_bytes: u64,
    pub queue_wait_ms: u64,
}
