//! Versioned manifest schema and retention binding for Blob read acceleration.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    super::{BLOB_LOCATOR_SCHEMA, BlobLocator, MAX_NAMESPACE_BYTES, envelope::EnvelopeMetadata},
    DEFAULT_SIDECAR_NAMESPACE, ENABLE_BY_DEFAULT, is_lower_hex_exact, validate_pack_stem, validate_sha256_hex,
};

pub const READ_ACCEL_MANIFEST_SCHEMA: u32 = 1;
pub const MAX_MIDX_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_COMMIT_GRAPH_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 2 * 1024 * 1024;

/// Supported Git repository object hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadAccelObjectFormat {
    Sha1,
    Sha256,
}

impl ReadAccelObjectFormat {
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
}

/// Supported rebuildable Blob read-acceleration sidecar types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadAccelArtifactKind {
    Midx,
    Bitmap,
    CommitGraph,
}

/// Explicit opt-in switch and sidecar policy for read acceleration (`ENABLE_BY_DEFAULT = false`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadAccelConfig {
    pub enabled: bool,
    pub namespace: String,
    pub include_midx: bool,
    pub include_bitmap: bool,
    pub include_commit_graph: bool,
}

impl Default for ReadAccelConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

impl ReadAccelConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: ENABLE_BY_DEFAULT,
            namespace: DEFAULT_SIDECAR_NAMESPACE.to_owned(),
            include_midx: true,
            include_bitmap: true,
            include_commit_graph: true,
        }
    }

    pub fn enabled_default() -> Self {
        Self { enabled: true, ..Self::disabled() }
    }

    pub fn validate(&self) -> Result<(), ReadAccelManifestError> {
        validate_namespace(&self.namespace)?;
        if self.include_bitmap && !self.include_midx {
            return Err(ReadAccelManifestError::InvalidField("multi-pack bitmap requires midx enabled"));
        }
        if self.enabled && !self.include_midx && !self.include_commit_graph {
            return Err(ReadAccelManifestError::InvalidField("enabled config must select an artifact"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadAccelManifestError {
    InvalidJson(String),
    InvalidField(&'static str),
    OversizedManifest { size: usize, limit: usize },
    Locator(String),
}

impl fmt::Display for ReadAccelManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson(msg) => write!(f, "invalid read-accel manifest JSON: {msg}"),
            Self::InvalidField(msg) => write!(f, "invalid read-accel manifest field: {msg}"),
            Self::OversizedManifest { size, limit } => write!(f, "manifest {size} bytes exceeds {limit}"),
            Self::Locator(msg) => write!(f, "invalid read-accel blob locator: {msg}"),
        }
    }
}

impl std::error::Error for ReadAccelManifestError {}

/// Canonical serializable mirror of read-only [`BlobLocator`]. Reconstructed locators
/// re-validate every field via [`BlobLocator::new`] and remain strictly read-only.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SerializedBlobLocator {
    pub schema: u32,
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub attempt_id: Uuid,
    pub namespace: String,
    pub sha256: String,
    pub length: u64,
}

impl SerializedBlobLocator {
    pub fn from_locator(locator: &BlobLocator) -> Self {
        Self {
            schema: locator.schema(),
            tenant_id: locator.tenant_id(),
            authority_id: locator.authority_id(),
            generation: locator.generation(),
            attempt_id: locator.attempt_id(),
            namespace: locator.namespace().to_owned(),
            sha256: locator.sha256().to_owned(),
            length: locator.length(),
        }
    }

    pub fn to_locator(&self) -> Result<BlobLocator, ReadAccelManifestError> {
        if self.schema != BLOB_LOCATOR_SCHEMA {
            return Err(ReadAccelManifestError::InvalidField("unsupported blob locator schema"));
        }
        BlobLocator::new(
            self.tenant_id,
            self.authority_id,
            self.generation,
            self.attempt_id,
            &self.namespace,
            &self.sha256,
            self.length,
        )
        .map_err(|e| ReadAccelManifestError::Locator(e.to_string()))
    }
}

/// Immutable authoritative `.pack` + `.idx` pair bound into a sidecar generation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackDigestEntry {
    pub pack_stem: String,
    pub pack_sha256: String,
    pub pack_length: u64,
    pub idx_sha256: String,
    pub idx_length: u64,
    pub pack_locator: SerializedBlobLocator,
    pub idx_locator: SerializedBlobLocator,
}

impl PackDigestEntry {
    pub fn from_locators(pack_stem: impl Into<String>, pack_locator: &BlobLocator, idx_locator: &BlobLocator) -> Self {
        Self {
            pack_stem: pack_stem.into(),
            pack_sha256: pack_locator.sha256().to_owned(),
            pack_length: pack_locator.length(),
            idx_sha256: idx_locator.sha256().to_owned(),
            idx_length: idx_locator.length(),
            pack_locator: SerializedBlobLocator::from_locator(pack_locator),
            idx_locator: SerializedBlobLocator::from_locator(idx_locator),
        }
    }

    pub fn sort_key(&self) -> (&str, &str, &str) {
        (&self.pack_stem, &self.pack_sha256, &self.idx_sha256)
    }

    fn validate_for(
        &self,
        tenant_id: Uuid,
        repo_id: Uuid,
        format: ReadAccelObjectFormat,
    ) -> Result<(), ReadAccelManifestError> {
        validate_pack_stem(&self.pack_stem, format)?;
        validate_bound_locator(&self.pack_locator, &self.pack_sha256, self.pack_length, tenant_id, repo_id)?;
        validate_bound_locator(&self.idx_locator, &self.idx_sha256, self.idx_length, tenant_id, repo_id)?;
        Ok(())
    }
}

fn validate_bound_locator(
    serialized: &SerializedBlobLocator,
    sha256: &str,
    length: u64,
    tenant_id: Uuid,
    repo_id: Uuid,
) -> Result<(), ReadAccelManifestError> {
    validate_sha256_hex(sha256)?;
    if length == 0 {
        return Err(ReadAccelManifestError::InvalidField("authoritative pack/idx lengths must be positive"));
    }
    let loc = serialized.to_locator()?;
    if loc.tenant_id() != tenant_id || loc.authority_id() != repo_id {
        return Err(ReadAccelManifestError::InvalidField("pack locator tenant/repo scope mismatch"));
    }
    if loc.sha256() != sha256 || loc.length() != length {
        return Err(ReadAccelManifestError::InvalidField("locator digest/length disagrees with entry"));
    }
    Ok(())
}

/// One generated non-authoritative sidecar object recorded in [`ReadAccelManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadAccelArtifact {
    pub kind: ReadAccelArtifactKind,
    pub relative_path: String,
    pub locator: SerializedBlobLocator,
    pub plaintext_sha256: String,
    pub plaintext_length: u64,
    pub envelope: Option<EnvelopeMetadata>,
}

impl ReadAccelArtifact {
    pub fn validate_for(
        &self,
        tenant_id: Uuid,
        repo_id: Uuid,
        format: ReadAccelObjectFormat,
    ) -> Result<(), ReadAccelManifestError> {
        validate_artifact_relative_path(self.kind, &self.relative_path, format)?;
        let max_len = match self.kind {
            ReadAccelArtifactKind::Midx | ReadAccelArtifactKind::Bitmap => MAX_MIDX_BYTES,
            ReadAccelArtifactKind::CommitGraph => MAX_COMMIT_GRAPH_BYTES,
        };
        if self.plaintext_length == 0 || self.plaintext_length > max_len {
            return Err(ReadAccelManifestError::InvalidField("sidecar plaintext_length out of range"));
        }
        if let Some(env) = &self.envelope {
            validate_sha256_hex(&self.plaintext_sha256)?;
            let loc = self.locator.to_locator()?;
            if loc.tenant_id() != tenant_id || loc.authority_id() != repo_id {
                return Err(ReadAccelManifestError::InvalidField("artifact locator tenant/repo scope mismatch"));
            }
            env.validate().map_err(|e| ReadAccelManifestError::InvalidJson(e.to_string()))?;
            if !env.matches_locator(&loc)
                || env.plaintext_sha256() != self.plaintext_sha256
                || env.plaintext_length() != self.plaintext_length
            {
                return Err(ReadAccelManifestError::InvalidField("artifact envelope mismatch"));
            }
        } else {
            validate_bound_locator(&self.locator, &self.plaintext_sha256, self.plaintext_length, tenant_id, repo_id)?;
        }
        Ok(())
    }
}

/// Immutable sidecar manifest binding acceleration caches to authoritative identity and pack set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadAccelManifest {
    pub schema_version: u32,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub object_format: ReadAccelObjectFormat,
    pub membership_generation: u64,
    pub sorted_pack_digests: Vec<PackDigestEntry>,
    pub artifacts: Vec<ReadAccelArtifact>,
}

impl ReadAccelManifest {
    pub fn validate(&self) -> Result<(), ReadAccelManifestError> {
        if self.schema_version != READ_ACCEL_MANIFEST_SCHEMA {
            return Err(ReadAccelManifestError::InvalidField("unsupported read-accel manifest schema_version"));
        }
        if self.tenant_id.is_nil() || self.repo_id.is_nil() || self.history_id.is_nil() {
            return Err(ReadAccelManifestError::InvalidField("manifest requires non-nil tenant/repo/history ids"));
        }
        if self.membership_generation == 0 {
            return Err(ReadAccelManifestError::InvalidField("membership_generation must be positive"));
        }
        if self.sorted_pack_digests.is_empty() {
            return Err(ReadAccelManifestError::InvalidField("sorted_pack_digests must not be empty"));
        }
        let mut prev: Option<(&str, &str, &str)> = None;
        let mut seen_stems = BTreeSet::new();
        for entry in &self.sorted_pack_digests {
            entry.validate_for(self.tenant_id, self.repo_id, self.object_format)?;
            if !seen_stems.insert(entry.pack_stem.as_str()) {
                return Err(ReadAccelManifestError::InvalidField("duplicate pack_stem in sorted_pack_digests"));
            }
            let key = entry.sort_key();
            if let Some(last) = prev
                && key <= last
            {
                return Err(ReadAccelManifestError::InvalidField("sorted_pack_digests must be strictly ascending"));
            }
            prev = Some(key);
        }
        if self.artifacts.is_empty() {
            return Err(ReadAccelManifestError::InvalidField("manifest artifacts must not be empty"));
        }
        let mut seen_kinds = BTreeSet::new();
        for artifact in &self.artifacts {
            if !seen_kinds.insert(artifact.kind) {
                return Err(ReadAccelManifestError::InvalidField("duplicate artifact kind in manifest"));
            }
            artifact.validate_for(self.tenant_id, self.repo_id, self.object_format)?;
        }
        if seen_kinds.contains(&ReadAccelArtifactKind::Bitmap) && !seen_kinds.contains(&ReadAccelArtifactKind::Midx) {
            return Err(ReadAccelManifestError::InvalidField("bitmap artifact requires paired midx artifact"));
        }
        Ok(())
    }

    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ReadAccelManifestError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ReadAccelManifestError::OversizedManifest { size: bytes.len(), limit: MAX_MANIFEST_BYTES });
        }
        let manifest: Self =
            serde_json::from_slice(bytes).map_err(|e| ReadAccelManifestError::InvalidJson(e.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ReadAccelManifestError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| ReadAccelManifestError::InvalidJson(e.to_string()))
    }

    pub fn manifest_sha256(&self) -> Result<String, ReadAccelManifestError> {
        let bytes = self.to_json_bytes()?;
        Ok(hex::encode(Sha256::digest(&bytes)))
    }

    pub fn artifact(&self, kind: ReadAccelArtifactKind) -> Option<&ReadAccelArtifact> {
        self.artifacts.iter().find(|a| a.kind == kind)
    }

    pub fn matches_binding(
        &self,
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
        object_format: ReadAccelObjectFormat,
        expected_membership_generation: u64,
        expected_sorted_packs: &[PackDigestEntry],
    ) -> Result<(), ReadAccelFallbackReason> {
        if self.tenant_id != tenant_id || self.repo_id != repo_id || self.history_id != history_id {
            return Err(ReadAccelFallbackReason::TenantRepoHistoryMismatch);
        }
        if self.object_format != object_format {
            return Err(ReadAccelFallbackReason::ObjectFormatMismatch);
        }
        if self.membership_generation != expected_membership_generation {
            return Err(ReadAccelFallbackReason::MembershipGenerationDrift {
                expected: expected_membership_generation,
                manifest: self.membership_generation,
            });
        }
        if self.sorted_pack_digests != expected_sorted_packs {
            return Err(ReadAccelFallbackReason::PackSetDigestDrift);
        }
        Ok(())
    }

    pub fn pinned_pack_paths(&self) -> Result<Vec<String>, ReadAccelManifestError> {
        collect_pack_paths(&self.sorted_pack_digests)
    }
}

pub fn collect_pack_paths(entries: &[PackDigestEntry]) -> Result<Vec<String>, ReadAccelManifestError> {
    let mut paths = Vec::with_capacity(entries.len() * 2);
    for entry in entries {
        paths.push(entry.pack_locator.to_locator()?.path());
        paths.push(entry.idx_locator.to_locator()?.path());
    }
    Ok(paths)
}

/// Explicit typed fallback reason when sidecars are bypassed or quarantined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadAccelFallbackReason {
    NoManifestConfigured,
    ManifestFetchFailed(String),
    ManifestInvalid(String),
    TenantRepoHistoryMismatch,
    ObjectFormatMismatch,
    MembershipGenerationDrift { expected: u64, manifest: u64 },
    PackSetDigestDrift,
    SidecarArtifactMissing(ReadAccelArtifactKind),
    SidecarArtifactCorrupt { kind: ReadAccelArtifactKind, detail: String },
    GitSidecarVerificationFailed { command: &'static str, detail: String },
}

impl fmt::Display for ReadAccelFallbackReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoManifestConfigured => f.write_str("no read-accel manifest configured"),
            Self::ManifestFetchFailed(msg) => write!(f, "manifest fetch failed: {msg}"),
            Self::ManifestInvalid(msg) => write!(f, "manifest validation failed: {msg}"),
            Self::TenantRepoHistoryMismatch => f.write_str("manifest tenant/repo/history scope mismatch"),
            Self::ObjectFormatMismatch => f.write_str("manifest object_format mismatch"),
            Self::MembershipGenerationDrift { expected, manifest } => {
                write!(f, "membership_generation drift: expected {expected}, manifest {manifest}")
            }
            Self::PackSetDigestDrift => f.write_str("sorted_pack_digests mismatch"),
            Self::SidecarArtifactMissing(kind) => write!(f, "sidecar Blob missing for {kind:?}"),
            Self::SidecarArtifactCorrupt { kind, detail } => {
                write!(f, "sidecar integrity failure for {kind:?}: {detail}")
            }
            Self::GitSidecarVerificationFailed { command, detail } => {
                write!(f, "git `{command}` verify failed: {detail}")
            }
        }
    }
}

pub(super) fn validate_namespace(ns: &str) -> Result<(), ReadAccelManifestError> {
    if ns.is_empty()
        || ns.len() > MAX_NAMESPACE_BYTES
        || !ns.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(ReadAccelManifestError::InvalidField("namespace must be 1..=48 lowercase/digit/`-`"));
    }
    Ok(())
}

pub(super) fn validate_artifact_relative_path(
    kind: ReadAccelArtifactKind,
    rel: &str,
    format: ReadAccelObjectFormat,
) -> Result<(), ReadAccelManifestError> {
    if rel.contains(['\\', '\0']) || rel.contains("..") {
        return Err(ReadAccelManifestError::InvalidField("unsafe artifact relative path"));
    }
    let ok = match kind {
        ReadAccelArtifactKind::Midx => rel == "objects/pack/multi-pack-index",
        ReadAccelArtifactKind::CommitGraph => rel == "objects/info/commit-graph",
        ReadAccelArtifactKind::Bitmap => rel
            .strip_prefix("objects/pack/multi-pack-index-")
            .and_then(|s| s.strip_suffix(".bitmap"))
            .is_some_and(|hex| is_lower_hex_exact(hex, format.oid_hex_len())),
    };
    ok.then_some(()).ok_or(ReadAccelManifestError::InvalidField("artifact relative path mismatch"))
}
