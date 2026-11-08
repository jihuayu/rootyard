//! Bounded, typed advisory cache/wake boundary.
//!
//! Nothing in this module is an authority. Cache misses, flushes, Redis
//! outages, evictions, duplicate warmups and lost wake hints may only change
//! latency or cause an origin read. They must never modify refs, tasks,
//! authentication/authorization, roots, holds, hard quotas or durable
//! PostgreSQL/RefStore state. Redis is independently enableable and does not
//! require Raft.
//!
//! This module provides the available boundary; the serving process does not
//! construct cache consumers yet. Dispatch continues to use local `Notify` and
//! an optional mature RedisWake. Redis cache/wake compilation is gated by the
//! optional `state-redis` feature and uses the mature `redis` async client;
//! this module contains no hand-written RESP, TCP or TLS implementation.
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::{fmt, future::Future, pin::Pin, time::Duration};
use uuid::Uuid;

pub mod memory;
pub mod origin;

#[cfg(feature = "state-redis")]
pub mod redis;

pub use memory::{CacheStats, MemoryCache};
pub use origin::{OriginError, OriginGuard, SingleFlight, WarmupOutcome};
#[cfg(feature = "state-redis")]
pub use redis::{RedisCache, RedisWake};

/// Boxed future used by the boundary so no async-trait framework is needed.
pub type CacheTask<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Exact advisory wake payload. It carries no event, repository, user, token,
/// ref, object ID or operation ID.
pub const WAKE_PAYLOAD: &[u8] = b"v1";

/// Validate the advisory Pub/Sub channel name. Channels are installation
/// names, never secrets and never tenant-private data.
pub fn validate_wake_channel(channel: &str) -> Result<()> {
    ensure!(
        (1..=128).contains(&channel.len()) && channel.bytes().all(|c| c.is_ascii_alphanumeric() || b":_-".contains(&c)),
        "invalid wake channel"
    );
    Ok(())
}

/// The only cache value kinds admitted by this boundary.
///
/// There is deliberately no authentication, authorization, token, session,
/// cookie, credential, signed-URL or hard-quota kind. Permission decisions must
/// be resolved from PostgreSQL on every authoritative path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CacheKind {
    GitObjectPreview = 1,
    TreeListing = 2,
    DiffView = 3,
    RefSnapshotHint = 4,
    IssueView = 5,
    PullView = 6,
    RouteDirectory = 7,
    QueryNegative = 8,
    WakeHint = 9,
    WarmupHint = 10,
    AdvisoryRate = 11,
}

impl CacheKind {
    pub const ALL: [Self; 11] = [
        Self::GitObjectPreview,
        Self::TreeListing,
        Self::DiffView,
        Self::RefSnapshotHint,
        Self::IssueView,
        Self::PullView,
        Self::RouteDirectory,
        Self::QueryNegative,
        Self::WakeHint,
        Self::WarmupHint,
        Self::AdvisoryRate,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GitObjectPreview => "git-object-preview",
            Self::TreeListing => "tree-listing",
            Self::DiffView => "diff-view",
            Self::RefSnapshotHint => "ref-snapshot-hint",
            Self::IssueView => "issue-view",
            Self::PullView => "pull-view",
            Self::RouteDirectory => "route-directory",
            Self::QueryNegative => "query-negative",
            Self::WakeHint => "wake-hint",
            Self::WarmupHint => "warmup-hint",
            Self::AdvisoryRate => "advisory-rate",
        }
    }

    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::GitObjectPreview),
            2 => Some(Self::TreeListing),
            3 => Some(Self::DiffView),
            4 => Some(Self::RefSnapshotHint),
            5 => Some(Self::IssueView),
            6 => Some(Self::PullView),
            7 => Some(Self::RouteDirectory),
            8 => Some(Self::QueryNegative),
            9 => Some(Self::WakeHint),
            10 => Some(Self::WarmupHint),
            11 => Some(Self::AdvisoryRate),
            _ => None,
        }
    }
}

/// Explicit, validated key components. A key always carries environment,
/// cache schema, history/authority incarnation, tenant security domain,
/// repository, kind, business/version and a bounded opaque discriminator.
#[derive(Clone, Copy)]
pub struct CacheKeyParts<'a> {
    pub environment: &'a str,
    pub schema: u16,
    pub history_incarnation: Uuid,
    pub tenant: Uuid,
    pub repo: Uuid,
    pub kind: CacheKind,
    pub version: u64,
    pub discriminator: &'a str,
}

/// A versioned typed cache key. The discriminator is SHA-256-digested so raw
/// tokens, cookies, signed URLs or query text are never key material.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    encoded: String,
    kind: CacheKind,
    version: u64,
}

impl CacheKey {
    pub fn new(parts: CacheKeyParts<'_>) -> Result<Self> {
        ensure!(
            (1..=32).contains(&parts.environment.len())
                && parts
                    .environment
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b)),
            "invalid cache environment"
        );
        ensure!(parts.discriminator.len() <= 512, "cache discriminator too long");
        let digest = if parts.discriminator.is_empty() {
            "none".to_owned()
        } else {
            let digest = Sha256::digest(parts.discriminator.as_bytes());
            hex::encode(&digest[..8])
        };
        let encoded = format!(
            "ry:cache:v1:{}:{}:{}:{}:{}:{}:{}:{}",
            parts.environment,
            parts.schema,
            parts.history_incarnation,
            parts.tenant,
            parts.repo,
            parts.kind.as_str(),
            parts.version,
            digest
        );
        ensure!(encoded.len() <= 320, "cache key too long");
        Ok(Self { encoded, kind: parts.kind, version: parts.version })
    }

    pub fn as_str(&self) -> &str {
        &self.encoded
    }

    pub fn kind(&self) -> CacheKind {
        self.kind
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    /// Approximate key bytes charged against the Memory byte budget.
    pub fn len(&self) -> usize {
        self.encoded.len()
    }

    pub fn is_empty(&self) -> bool {
        self.encoded.is_empty()
    }
}

impl fmt::Debug for CacheKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the encoded key, tenant/repo IDs or discriminator.
        formatter
            .debug_struct("CacheKey")
            .field("kind", &self.kind)
            .field("version", &self.version)
            .field("key_bytes", &self.encoded.len())
            .finish()
    }
}

/// A payload bound to its kind and version. Cache users cannot reinterpret a
/// value under another kind or version.
#[derive(Clone, PartialEq, Eq)]
pub struct CacheValue {
    kind: CacheKind,
    version: u64,
    bytes: Vec<u8>,
}

const VALUE_MAGIC: &[u8; 4] = b"RYC1";
const VALUE_HEADER: usize = 13;

impl CacheValue {
    pub fn new(kind: CacheKind, version: u64, bytes: Vec<u8>) -> Self {
        Self { kind, version, bytes }
    }

    pub fn kind(&self) -> CacheKind {
        self.kind
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn encoded_len(&self) -> usize {
        VALUE_HEADER + self.bytes.len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(VALUE_MAGIC);
        out.push(self.kind.code());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Decode and require the value's kind/version to match its key. A stale or
    /// confused value is a cache miss, never a cross-kind authorization signal.
    pub fn decode(key: &CacheKey, raw: &[u8]) -> Result<Self> {
        ensure!(raw.len() >= VALUE_HEADER, "cache value header truncated");
        ensure!(raw.starts_with(VALUE_MAGIC), "unknown cache value format");
        let kind = CacheKind::from_code(raw[4]).ok_or_else(|| anyhow::anyhow!("unknown cache value kind"))?;
        ensure!(kind == key.kind, "cache value kind does not match key");
        let version = u64::from_be_bytes(raw[5..13].try_into().expect("fixed value header"));
        ensure!(version == key.version, "cache value version does not match key");
        Ok(Self { kind, version, bytes: raw[VALUE_HEADER..].to_vec() })
    }
}

impl fmt::Debug for CacheValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Values may contain tenant-private display data. Print bounds only.
        formatter
            .debug_struct("CacheValue")
            .field("kind", &self.kind)
            .field("version", &self.version)
            .field("value_bytes", &self.bytes.len())
            .finish()
    }
}

/// Memory and origin bounds. Redis uses `RedisCacheLimits` plus a validated
/// server maxmemory/eviction contract; Memory entry/byte caps are not applied
/// to Redis.
#[derive(Clone, Copy, Debug)]
pub struct CacheLimits {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub max_value_bytes: usize,
    pub default_ttl: Duration,
    pub max_ttl: Duration,
    pub request_timeout: Duration,
    pub max_inflight: usize,
    pub origin_permits: usize,
    pub origin_wait: Duration,
    pub origin_deadline: Duration,
    pub breaker_failures: u32,
    pub breaker_cooldown: Duration,
}

impl Default for CacheLimits {
    fn default() -> Self {
        Self {
            max_entries: 4096,
            max_bytes: 64 * 1024 * 1024,
            max_value_bytes: 1024 * 1024,
            default_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(3600),
            request_timeout: Duration::from_secs(1),
            max_inflight: 32,
            origin_permits: 8,
            origin_wait: Duration::from_millis(250),
            origin_deadline: Duration::from_secs(15),
            breaker_failures: 5,
            breaker_cooldown: Duration::from_secs(5),
        }
    }
}

impl CacheLimits {
    /// Standalone default: bounded Memory only, no Redis dependency.
    pub fn standalone_memory() -> Self {
        Self::default()
    }

    pub fn from_env() -> Result<Self> {
        let defaults = Self::default();
        let limits = Self {
            max_entries: number("ROOTYARD_CACHE_MAX_ENTRIES", defaults.max_entries as u64, 1, 1_000_000)? as usize,
            max_bytes: number("ROOTYARD_CACHE_MAX_BYTES", defaults.max_bytes as u64, 1024, 4 * 1024 * 1024 * 1024)?
                as usize,
            max_value_bytes: number(
                "ROOTYARD_CACHE_MAX_VALUE_BYTES",
                defaults.max_value_bytes as u64,
                1,
                64 * 1024 * 1024,
            )? as usize,
            default_ttl: Duration::from_secs(number("ROOTYARD_CACHE_TTL_SECONDS", 60, 1, 3600)?),
            max_ttl: Duration::from_secs(number("ROOTYARD_CACHE_MAX_TTL_SECONDS", 3600, 1, 86_400)?),
            request_timeout: Duration::from_millis(number("ROOTYARD_CACHE_REQUEST_TIMEOUT_MS", 1000, 10, 30_000)?),
            max_inflight: number("ROOTYARD_CACHE_MAX_INFLIGHT", 32, 1, 1024)? as usize,
            origin_permits: number("ROOTYARD_CACHE_ORIGIN_PERMITS", 8, 1, 1024)? as usize,
            origin_wait: Duration::from_millis(number("ROOTYARD_CACHE_ORIGIN_WAIT_MS", 250, 1, 30_000)?),
            origin_deadline: Duration::from_millis(number("ROOTYARD_CACHE_ORIGIN_DEADLINE_MS", 15_000, 10, 300_000)?),
            breaker_failures: number("ROOTYARD_CACHE_BREAKER_FAILURES", 5, 1, 1000)? as u32,
            breaker_cooldown: Duration::from_millis(number("ROOTYARD_CACHE_BREAKER_COOLDOWN_MS", 5000, 10, 300_000)?),
        };
        limits.validate()?;
        Ok(limits)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.max_entries > 0, "cache max_entries must be positive");
        ensure!(self.max_bytes > 0, "cache max_bytes must be positive");
        ensure!(self.max_value_bytes > 0, "cache max_value_bytes must be positive");
        ensure!(self.max_value_bytes <= self.max_bytes, "cache max_value_bytes exceeds max_bytes");
        ensure!(!self.default_ttl.is_zero(), "cache default_ttl must be positive");
        ensure!(self.default_ttl <= self.max_ttl, "cache default_ttl exceeds max_ttl");
        ensure!(!self.request_timeout.is_zero(), "cache request_timeout must be positive");
        ensure!(self.max_inflight > 0, "cache max_inflight must be positive");
        ensure!(self.origin_permits > 0, "cache origin_permits must be positive");
        ensure!(!self.origin_wait.is_zero(), "cache origin_wait must be positive");
        ensure!(!self.origin_deadline.is_zero(), "cache origin_deadline must be positive");
        ensure!(self.breaker_failures > 0, "cache breaker_failures must be positive");
        ensure!(!self.breaker_cooldown.is_zero(), "cache breaker_cooldown must be positive");
        Ok(())
    }

    pub fn effective_ttl(&self, ttl: Option<Duration>) -> Result<Duration> {
        let ttl = ttl.unwrap_or(self.default_ttl);
        ensure!(!ttl.is_zero(), "cache ttl must be positive");
        ensure!(ttl <= self.max_ttl, "cache ttl exceeds max_ttl");
        Ok(ttl)
    }
}

/// Advisory-only cache interface. Implementations never expose a durable
/// write path and never accept auth/permission decisions.
pub trait AdvisoryCache: Send + Sync {
    fn get<'a>(&'a self, key: &'a CacheKey) -> CacheTask<'a, Result<Option<CacheValue>>>;
    fn put<'a>(&'a self, key: &'a CacheKey, value: CacheValue, ttl: Option<Duration>) -> CacheTask<'a, Result<()>>;
    fn delete<'a>(&'a self, key: &'a CacheKey) -> CacheTask<'a, Result<()>>;
}

fn number(name: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    let value = match std::env::var(name) {
        Ok(raw) => raw.parse().map_err(|_| anyhow::anyhow!("invalid {name}"))?,
        Err(_) => default,
    };
    ensure!((min..=max).contains(&value), "{name} outside supported range");
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(kind: CacheKind, version: u64, discriminator: &str) -> CacheKey {
        CacheKey::new(CacheKeyParts {
            environment: "standalone",
            schema: 1,
            history_incarnation: Uuid::nil(),
            tenant: Uuid::from_u128(1),
            repo: Uuid::from_u128(2),
            kind,
            version,
            discriminator,
        })
        .unwrap()
    }

    #[test]
    fn keys_are_typed_versioned_and_do_not_embed_raw_discriminators() {
        let value = key(CacheKind::TreeListing, 7, "Bearer super-secret-cookie");
        let text = value.as_str();
        assert!(text.starts_with("ry:cache:v1:standalone:1:"));
        assert!(text.contains(":tree-listing:7:"));
        assert!(!text.contains("super-secret"));
        assert!(!text.contains("Bearer"));
        assert_eq!(value.kind(), CacheKind::TreeListing);
        assert_eq!(value.version(), 7);
        assert!(
            CacheKey::new(CacheKeyParts {
                environment: "Standalone",
                schema: 1,
                history_incarnation: Uuid::nil(),
                tenant: Uuid::nil(),
                repo: Uuid::nil(),
                kind: CacheKind::TreeListing,
                version: 1,
                discriminator: "",
            })
            .is_err()
        );
    }

    #[test]
    fn debug_never_prints_encoded_keys_scopes_or_value_bytes() {
        let key = key(CacheKind::IssueView, 9, "tenant-private-discriminator");
        let key_debug = format!("{key:?}");
        assert!(key_debug.contains("IssueView"));
        assert!(!key_debug.contains("ry:cache"));
        assert!(!key_debug.contains("tenant-private-discriminator"));
        let value = CacheValue::new(CacheKind::IssueView, 9, b"private-comment-body".to_vec());
        let value_debug = format!("{value:?}");
        assert!(value_debug.contains("IssueView"));
        assert!(!value_debug.contains("private-comment-body"));
        assert!(value_debug.contains("value_bytes"));
    }

    #[test]
    fn value_kind_and_version_must_match_key() {
        let key = key(CacheKind::IssueView, 4, "issue");
        let value = CacheValue::new(CacheKind::IssueView, 4, b"body".to_vec());
        assert_eq!(CacheValue::decode(&key, &value.encode()).unwrap(), value);
        let wrong_kind = CacheValue::new(CacheKind::PullView, 4, b"body".to_vec());
        assert!(CacheValue::decode(&key, &wrong_kind.encode()).is_err());
        let wrong_version = CacheValue::new(CacheKind::IssueView, 5, b"body".to_vec());
        assert!(CacheValue::decode(&key, &wrong_version.encode()).is_err());
        assert!(CacheValue::decode(&key, b"short").is_err());
    }

    #[test]
    fn no_authorization_or_secret_kinds_exist() {
        for kind in CacheKind::ALL {
            let name = kind.as_str().to_ascii_lowercase();
            for forbidden in ["auth", "token", "session", "credential", "secret", "quota"] {
                assert!(!name.contains(forbidden), "{name} exposes forbidden kind");
            }
            assert_eq!(CacheKind::from_code(kind.code()), Some(kind));
        }
        assert_eq!(CacheKind::from_code(0), None);
        assert_eq!(CacheKind::from_code(255), None);
    }

    #[test]
    fn limits_and_channels_are_bounded() {
        CacheLimits::default().validate().unwrap();
        let mut bad = CacheLimits::default();
        bad.max_value_bytes = bad.max_bytes + 1;
        assert!(bad.validate().is_err());
        for channel in ["", "has space", "bad\r\n", &"x".repeat(129)] {
            assert!(validate_wake_channel(channel).is_err());
        }
        assert!(validate_wake_channel("rootyard:outbox_1-v1").is_ok());
    }
}
