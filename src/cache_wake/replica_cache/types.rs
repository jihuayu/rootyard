//! Core typed identities, limits, bindings, #174 session lower-bound checks,
//! and metrics for the disposable Rubicon compute replica cache (Issue #163).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::{BlobBackendIdentity, BlobLocator, envelope::EnvelopeMetadata};

use super::error::push_field;
pub use super::error::{
    ReplicaCacheError, compute_membership_digests, is_lower_hex_exact, is_retryable_failover_error, validate_pack_stem,
    validate_ref_name_and_oid,
};

pub const REPLICA_CACHE_SCHEMA: u32 = 1;
pub const MAX_REPLICA_PACK_ENTRIES: usize = 16_384;
pub const MAX_REPLICA_VIEW_ENTRIES: usize = 4_096;
pub const MAX_QUEUE_WAITERS: usize = 4_096;
pub const MIN_VIEW_TTL: Duration = Duration::from_secs(1);
pub const MAX_VIEW_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicaObjectFormat {
    Sha1,
    Sha256,
}

impl ReplicaObjectFormat {
    pub const fn oid_hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    pub const fn git_init_flag(self) -> &'static str {
        match self {
            Self::Sha1 => "--object-format=sha1",
            Self::Sha256 => "--object-format=sha256",
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaOperation {
    GitUploadPack,
    Browse,
    ArchiveRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionCheckVerdict {
    Unchanged,
    Changed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackObjectSpec {
    pub pack_stem: String,
    pub pack_locator: BlobLocator,
    pub idx_locator: BlobLocator,
    pub pack_envelope: Option<EnvelopeMetadata>,
    pub idx_envelope: Option<EnvelopeMetadata>,
}

impl PackObjectSpec {
    pub fn provider_managed(pack_stem: impl Into<String>, pack_locator: BlobLocator, idx_locator: BlobLocator) -> Self {
        Self { pack_stem: pack_stem.into(), pack_locator, idx_locator, pack_envelope: None, idx_envelope: None }
    }

    pub fn with_envelopes(mut self, pack_envelope: EnvelopeMetadata, idx_envelope: EnvelopeMetadata) -> Self {
        self.pack_envelope = Some(pack_envelope);
        self.idx_envelope = Some(idx_envelope);
        self
    }

    pub fn total_bytes(&self) -> u64 {
        self.pack_locator.length().saturating_add(self.idx_locator.length())
    }

    pub fn validate(
        &self,
        tenant_id: Uuid,
        repo_id: Uuid,
        format: ReplicaObjectFormat,
    ) -> Result<(), ReplicaCacheError> {
        validate_pack_stem(&self.pack_stem, format)?;
        if self.pack_locator.tenant_id() != tenant_id
            || self.pack_locator.authority_id() != repo_id
            || self.idx_locator.tenant_id() != tenant_id
            || self.idx_locator.authority_id() != repo_id
        {
            return Err(ReplicaCacheError::TenantIsolationViolation("pack/idx locator tenant or repo mismatch"));
        }
        if self.pack_locator.length() == 0 || self.idx_locator.length() == 0 {
            return Err(ReplicaCacheError::InvalidInput("pack/idx lengths must be positive".into()));
        }
        if let Some(env) = &self.pack_envelope {
            env.validate()?;
            if !env.matches_locator(&self.pack_locator) {
                return Err(ReplicaCacheError::InvalidInput("pack envelope does not match pack locator".into()));
            }
        }
        if let Some(env) = &self.idx_envelope {
            env.validate()?;
            if !env.matches_locator(&self.idx_locator) {
                return Err(ReplicaCacheError::InvalidInput("idx envelope does not match idx locator".into()));
            }
        }
        Ok(())
    }

    pub fn pack_cache_key(&self, backend_identity_hex: &str, format: ReplicaObjectFormat) -> PackCacheKey {
        PackCacheKey::from_spec(self, backend_identity_hex, format)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReplicaRefSpec {
    pub name: String,
    pub oid: String,
}

impl ReplicaRefSpec {
    pub fn new(name: impl Into<String>, oid: impl Into<String>) -> Self {
        Self { name: name.into(), oid: oid.into() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackCacheKey {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub backend_identity_hex: String,
    pub object_format: ReplicaObjectFormat,
    pub pack_stem: String,
    pub pack_sha256: String,
    pub pack_length: u64,
    pub idx_sha256: String,
    pub idx_length: u64,
    pub key_digest: String,
}

impl PackCacheKey {
    fn from_spec(spec: &PackObjectSpec, backend_identity_hex: &str, object_format: ReplicaObjectFormat) -> Self {
        let tenant_id = spec.pack_locator.tenant_id();
        let repo_id = spec.pack_locator.authority_id();
        let pack_sha256 = spec.pack_locator.sha256();
        let pack_length = spec.pack_locator.length();
        let idx_sha256 = spec.idx_locator.sha256();
        let idx_length = spec.idx_locator.length();
        let mut buf = String::new();
        push_field(&mut buf, "domain", "rootyard.replica.pack.v1");
        push_field(&mut buf, "tenant", &tenant_id.to_string());
        push_field(&mut buf, "repo", &repo_id.to_string());
        push_field(&mut buf, "backend", backend_identity_hex);
        push_field(&mut buf, "fmt", object_format.as_str());
        push_field(&mut buf, "stem", &spec.pack_stem);
        push_field(&mut buf, "pack_sha", pack_sha256);
        push_field(&mut buf, "pack_len", &pack_length.to_string());
        push_field(&mut buf, "idx_sha", idx_sha256);
        push_field(&mut buf, "idx_len", &idx_length.to_string());
        let key_digest = hex::encode(Sha256::digest(buf.as_bytes()));
        Self {
            tenant_id,
            repo_id,
            backend_identity_hex: backend_identity_hex.to_owned(),
            object_format,
            pack_stem: spec.pack_stem.clone(),
            pack_sha256: pack_sha256.to_owned(),
            pack_length,
            idx_sha256: idx_sha256.to_owned(),
            idx_length,
            key_digest,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReplicaViewKey {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub cluster_incarnation: Uuid,
    pub backend_identity_hex: String,
    pub object_format: ReplicaObjectFormat,
    pub authority_epoch: i64,
    pub gate_revision: i64,
    pub pack_membership_digest: String,
    pub refs_digest: String,
    pub membership_digest: String,
    pub view_key_hex: String,
}

impl ReplicaViewKey {
    pub fn build(
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
        cluster_incarnation: Uuid,
        backend_identity: &BlobBackendIdentity,
        object_format: ReplicaObjectFormat,
        authority_epoch: i64,
        gate_revision: i64,
        packs: &[PackObjectSpec],
        refs: &[ReplicaRefSpec],
        head_ref: &str,
    ) -> Result<Self, ReplicaCacheError> {
        if tenant_id.is_nil() || repo_id.is_nil() || history_id.is_nil() || cluster_incarnation.is_nil() {
            return Err(ReplicaCacheError::InvalidInput("view key requires non-nil identity UUIDs".into()));
        }
        if authority_epoch < 0 || gate_revision < 0 {
            return Err(ReplicaCacheError::InvalidInput(
                "authority_epoch and gate_revision must be non-negative".into(),
            ));
        }
        let (pack_membership_digest, refs_digest, membership_digest) =
            compute_membership_digests(tenant_id, repo_id, object_format, packs, refs, head_ref)?;
        let backend_identity_hex = backend_identity.as_hex().to_owned();
        let mut buf = String::new();
        push_field(&mut buf, "domain", "rootyard.replica.view.v1");
        push_field(&mut buf, "tenant", &tenant_id.to_string());
        push_field(&mut buf, "repo", &repo_id.to_string());
        push_field(&mut buf, "history", &history_id.to_string());
        push_field(&mut buf, "cluster", &cluster_incarnation.to_string());
        push_field(&mut buf, "backend", &backend_identity_hex);
        push_field(&mut buf, "fmt", object_format.as_str());
        push_field(&mut buf, "auth_epoch", &authority_epoch.to_string());
        push_field(&mut buf, "gate_rev", &gate_revision.to_string());
        push_field(&mut buf, "membership", &membership_digest);
        let view_key_hex = hex::encode(Sha256::digest(buf.as_bytes()));
        Ok(Self {
            tenant_id,
            repo_id,
            history_id,
            cluster_incarnation,
            backend_identity_hex,
            object_format,
            authority_epoch,
            gate_revision,
            pack_membership_digest,
            refs_digest,
            membership_digest,
            view_key_hex,
        })
    }
}

/// #174 session consistency lower-bound requirement supplied by caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLowerBound {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub cluster_incarnation: Uuid,
    pub authority_epoch: i64,
    pub min_gate_revision: i64,
}

#[derive(Debug, Clone)]
pub struct ReplicaReadRequest {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub actor_id: String,
    pub operation: ReplicaOperation,
    pub expected_backend_identity: Option<BlobBackendIdentity>,
    pub session_lower_bound: Option<SessionLowerBound>,
    pub known_membership_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicaCacheLimits {
    pub max_pack_entries: usize,
    pub max_pack_bytes: u64,
    pub max_view_entries: usize,
    pub max_view_bytes: u64,
    pub max_active_views: usize,
    pub view_ttl: Duration,
    pub min_serve_ttl: Duration,
    pub max_inflight_builds: usize,
    pub max_waiters_per_key: usize,
    pub max_total_waiters: usize,
    pub waiter_timeout: Duration,
    pub materialization_timeout: Duration,
}

impl Default for ReplicaCacheLimits {
    fn default() -> Self {
        Self {
            max_pack_entries: 128,
            max_pack_bytes: 512 * 1024 * 1024,
            max_view_entries: 64,
            max_view_bytes: 512 * 1024 * 1024,
            max_active_views: 128,
            view_ttl: Duration::from_secs(300),
            min_serve_ttl: Duration::from_secs(5),
            max_inflight_builds: 16,
            max_waiters_per_key: 32,
            max_total_waiters: 128,
            waiter_timeout: Duration::from_secs(10),
            materialization_timeout: Duration::from_secs(30),
        }
    }
}

impl ReplicaCacheLimits {
    pub fn validate(&self) -> Result<(), ReplicaCacheError> {
        if !(1..=MAX_REPLICA_PACK_ENTRIES).contains(&self.max_pack_entries) || self.max_pack_bytes == 0 {
            return Err(ReplicaCacheError::InvalidConfig("pack cache limits out of range"));
        }
        if !(1..=MAX_REPLICA_VIEW_ENTRIES).contains(&self.max_view_entries) || self.max_view_bytes == 0 {
            return Err(ReplicaCacheError::InvalidConfig("view cache limits out of range"));
        }
        if self.max_active_views < self.max_view_entries || self.max_active_views > MAX_REPLICA_VIEW_ENTRIES {
            return Err(ReplicaCacheError::InvalidConfig("max_active_views out of range"));
        }
        if self.view_ttl < MIN_VIEW_TTL || self.view_ttl > MAX_VIEW_TTL || self.min_serve_ttl >= self.view_ttl {
            return Err(ReplicaCacheError::InvalidConfig("view_ttl or min_serve_ttl out of range"));
        }
        if self.max_inflight_builds == 0
            || self.max_waiters_per_key == 0
            || self.max_total_waiters < self.max_waiters_per_key
            || self.max_total_waiters > MAX_QUEUE_WAITERS
        {
            return Err(ReplicaCacheError::InvalidConfig("singleflight waiter limits out of range"));
        }
        if self.waiter_timeout.is_zero() || self.materialization_timeout.is_zero() {
            return Err(ReplicaCacheError::InvalidConfig("timeouts must be positive"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplicaServeSource {
    ViewCacheHit,
    PackCacheFullReuse,
    PackCachePartialRefill,
    ColdBlobMaterialized,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicaRequestMetrics {
    pub version_checked: bool,
    pub live_authorized: bool,
    pub blob_gets: u64,
    pub blob_bytes: u64,
    pub reused_pack_count: usize,
    pub reused_pack_bytes: u64,
    pub copied_bytes: u64,
    pub queue_wait_us: u64,
    pub materialize_ms: u64,
    pub total_ms: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicaCacheStats {
    pub version_checks: u64,
    pub live_auth_checks: u64,
    pub auth_denials: u64,
    pub session_behind_rejects: u64,
    pub view_hits: u64,
    pub view_misses: u64,
    pub pack_hits: u64,
    pub pack_misses: u64,
    pub blob_gets: u64,
    pub blob_bytes: u64,
    pub reused_pack_bytes: u64,
    pub copied_bytes: u64,
    pub singleflight_coalesced: u64,
    pub singleflight_waits: u64,
    pub queue_wait_us: u64,
    pub queue_rejections: u64,
    pub evicted_packs: u64,
    pub evicted_views: u64,
    pub active_pin_protections: u64,
    pub corrupt_rebuilds: u64,
    pub push_scratch_allocations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDirectoryHint {
    pub schema_version: u32,
    pub node_id: String,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub gate_revision: i64,
    pub membership_digest: String,
}
