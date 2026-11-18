//! CloneKit manifest schema, object-format guards, fail-closed errors, and private file helpers.

use std::{
    fmt,
    fs::{self, Permissions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::blob_store::{BlobError, BlobLocator};

/// Current CloneKit manifest schema version.
pub const CLONEKIT_MANIFEST_SCHEMA: u32 = 1;
/// Hard cap on serialized manifest JSON reads (256 KiB).
pub const MAX_MANIFEST_JSON_BYTES: usize = 256 * 1024;
/// Default namespace for CloneKit packs stored inside `BlobStore`.
pub const CLONEKIT_PACK_NAMESPACE: &str = "clonekit-packs";
/// Default namespace for CloneKit pack indices stored inside `BlobStore`.
pub const CLONEKIT_IDX_NAMESPACE: &str = "clonekit-idx";

/// Supported Git object hash formats for CloneKit packs and checkouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloneKitObjectFormat {
    Sha1,
    Sha256,
}

impl CloneKitObjectFormat {
    /// Canonical lowercase string form matching Git's `--object-format`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    /// Parse a repository object format string fail-closed.
    pub fn parse(raw: &str) -> Result<Self, CloneKitError> {
        match raw.trim() {
            "sha1" => Ok(Self::Sha1),
            "sha256" => Ok(Self::Sha256),
            _ => Err(CloneKitError::InvalidInput("unsupported object format")),
        }
    }

    /// Hex string length of one commit/tree/blob OID in this format.
    pub const fn oid_hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    /// CLI flag passed to `git init`.
    pub const fn git_init_flag(self) -> &'static str {
        match self {
            Self::Sha1 => "--object-format=sha1",
            Self::Sha256 => "--object-format=sha256",
        }
    }

    /// Validate lowercase canonical non-zero Git OID for this object format.
    pub fn valid_oid(self, oid: &str) -> bool {
        oid.len() == self.oid_hex_len()
            && oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && oid.bytes().any(|b| b != b'0')
    }
}

/// Lifecycle state recorded in a published [`CloneKitManifest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloneKitStatus {
    Active,
    EmptyRepository,
    StaleSuperseded,
    Revoked,
}

/// Serializable locator fields required to reconstruct and validate a [`BlobLocator`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredBlobLocator {
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub attempt_id: Uuid,
    pub namespace: String,
    pub sha256: String,
    pub length: u64,
}

impl StoredBlobLocator {
    /// Convert a [`BlobLocator`] into its persistable structural form.
    pub fn from_blob_locator(loc: &BlobLocator) -> Self {
        Self {
            tenant_id: loc.tenant_id(),
            authority_id: loc.authority_id(),
            generation: loc.generation(),
            attempt_id: loc.attempt_id(),
            namespace: loc.namespace().to_owned(),
            sha256: loc.sha256().to_owned(),
            length: loc.length(),
        }
    }

    /// Reconstruct and structurally validate the [`BlobLocator`].
    pub fn to_blob_locator(&self) -> Result<BlobLocator, CloneKitError> {
        BlobLocator::new(
            self.tenant_id,
            self.authority_id,
            self.generation,
            self.attempt_id,
            &self.namespace,
            &self.sha256,
            self.length,
        )
        .map_err(|err| CloneKitError::CorruptArtifact(format!("invalid blob locator: {err}")))
    }
}

/// Content-verified artifact descriptor for a `.pack` or `.idx` inside a CloneKit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloneKitArtifactDigest {
    pub sha256: String,
    pub length: u64,
    pub hold_id: Option<Uuid>,
    pub blob_locator: Option<StoredBlobLocator>,
}

impl CloneKitArtifactDigest {
    /// Validate digest hex formatting and optional embedded locator consistency.
    pub fn validate(&self, expected_tenant: Uuid) -> Result<(), CloneKitError> {
        if !valid_sha256_hex(&self.sha256) || self.length == 0 {
            return Err(CloneKitError::CorruptArtifact("artifact sha256/length invalid".into()));
        }
        if let Some(loc) = &self.blob_locator {
            if loc.tenant_id != expected_tenant {
                return Err(CloneKitError::CrossTenantDenied);
            }
            if loc.sha256 != self.sha256 || loc.length != self.length {
                return Err(CloneKitError::CorruptArtifact("blob locator disagrees with artifact digest".into()));
            }
            let _ = loc.to_blob_locator()?;
        }
        Ok(())
    }
}

/// Verified immutable CloneKit manifest bound to repo, tenant, history, format, and pin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloneKitManifest {
    pub schema: u32,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub owner_id: Uuid,
    pub history_id: Uuid,
    pub storage_generation: i64,
    pub object_format: CloneKitObjectFormat,
    pub kit_generation: u64,
    pub status: CloneKitStatus,
    pub base_commit_oid: Option<String>,
    pub branch_ref: String,
    pub pack: Option<CloneKitArtifactDigest>,
    pub idx: Option<CloneKitArtifactDigest>,
    pub backend_identity_hex: Option<String>,
    pub retention_pin_id: Option<Uuid>,
    pub created_unix: i64,
    pub expires_unix: i64,
    pub manifest_sha256: String,
}

impl CloneKitManifest {
    /// Compute canonical domain-separated SHA-256 digest of the manifest body.
    pub fn compute_canonical_digest(&self) -> Result<String, CloneKitError> {
        let mut canonical = self.clone();
        canonical.manifest_sha256.clear();
        let encoded = serde_json::to_vec(&canonical)
            .map_err(|err| CloneKitError::CorruptArtifact(format!("canonical manifest encode: {err}")))?;
        let mut hasher = Sha256::new();
        hasher.update(b"rootyard.clonekit.manifest.v1\0");
        hasher.update(&encoded);
        Ok(hex::encode(hasher.finalize()))
    }

    /// Populate [`Self::manifest_sha256`] after structural validation.
    pub fn sealed(mut self) -> Result<Self, CloneKitError> {
        self.validate_fields_only()?;
        self.manifest_sha256 = self.compute_canonical_digest()?;
        Ok(self)
    }

    fn validate_fields_only(&self) -> Result<(), CloneKitError> {
        if self.schema != CLONEKIT_MANIFEST_SCHEMA {
            return Err(CloneKitError::CorruptArtifact("unsupported clonekit manifest schema".into()));
        }
        if self.tenant_id.is_nil() || self.repository_id.is_nil() || self.owner_id.is_nil() || self.history_id.is_nil()
        {
            return Err(CloneKitError::InvalidInput("clonekit manifest IDs must be non-nil"));
        }
        if self.storage_generation <= 0 || self.kit_generation == 0 || !valid_branch_ref(&self.branch_ref) {
            return Err(CloneKitError::InvalidInput("invalid clonekit generation or branch ref"));
        }
        if self.expires_unix <= self.created_unix {
            return Err(CloneKitError::InvalidInput("clonekit expires_unix must exceed created_unix"));
        }
        if let Some(backend) = &self.backend_identity_hex
            && !valid_sha256_hex(backend)
        {
            return Err(CloneKitError::CorruptArtifact("invalid backend_identity_hex".into()));
        }
        match self.status {
            CloneKitStatus::Active => {
                let base = self
                    .base_commit_oid
                    .as_deref()
                    .ok_or_else(|| CloneKitError::CorruptArtifact("active kit missing base_commit_oid".into()))?;
                if !self.object_format.valid_oid(base) {
                    return Err(CloneKitError::CorruptArtifact("active kit base_commit_oid invalid".into()));
                }
                self.pack
                    .as_ref()
                    .ok_or_else(|| CloneKitError::CorruptArtifact("active kit missing pack metadata".into()))?
                    .validate(self.tenant_id)?;
                self.idx
                    .as_ref()
                    .ok_or_else(|| CloneKitError::CorruptArtifact("active kit missing idx metadata".into()))?
                    .validate(self.tenant_id)?;
            }
            CloneKitStatus::EmptyRepository => {
                if self.base_commit_oid.is_some() || self.pack.is_some() || self.idx.is_some() {
                    return Err(CloneKitError::CorruptArtifact("empty repo kit must omit pack/idx/commit".into()));
                }
            }
            CloneKitStatus::StaleSuperseded | CloneKitStatus::Revoked => {}
        }
        Ok(())
    }

    /// Validate structural invariants and fail-closed digest integrity.
    pub fn verify_integrity(&self) -> Result<(), CloneKitError> {
        self.validate_fields_only()?;
        if !valid_sha256_hex(&self.manifest_sha256) || self.compute_canonical_digest()? != self.manifest_sha256 {
            return Err(CloneKitError::CorruptArtifact("manifest_sha256 mismatch".into()));
        }
        Ok(())
    }

    /// Deserialize manifest JSON rejecting unknown fields and verifying integrity.
    pub fn from_verified_json(bytes: &[u8]) -> Result<Self, CloneKitError> {
        if bytes.len() > MAX_MANIFEST_JSON_BYTES {
            return Err(CloneKitError::CorruptArtifact("manifest JSON exceeds size cap".into()));
        }
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|err| CloneKitError::CorruptArtifact(format!("manifest parse failed: {err}")))?;
        manifest.verify_integrity()?;
        Ok(manifest)
    }
}

/// Fail-closed error taxonomy across CloneKit build, grant, verification, and checkout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloneKitError {
    InvalidConfig(&'static str),
    InvalidInput(&'static str),
    Unauthorized(&'static str),
    GrantExpired,
    GrantRevoked(&'static str),
    CrossTenantDenied,
    MissingKit,
    EmptyRepository,
    StaleGeneration { expected_min: u64, actual: u64 },
    HistoryChanged { expected: Uuid, actual: Uuid },
    CorruptArtifact(String),
    ForeignBackend,
    IncompleteClosure(String),
    DependencyCheckFailed(String),
    PinProtectionActive(Uuid),
    TransferCancelled,
    GitFailed(String),
    BlobFailed(String),
    DatabaseFailed(String),
}

impl fmt::Display for CloneKitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(m) => write!(f, "clonekit config error: {m}"),
            Self::InvalidInput(m) => write!(f, "clonekit invalid input: {m}"),
            Self::Unauthorized(m) => write!(f, "clonekit unauthorized: {m}"),
            Self::GrantExpired => write!(f, "clonekit grant expired"),
            Self::GrantRevoked(m) => write!(f, "clonekit grant revoked: {m}"),
            Self::CrossTenantDenied => write!(f, "clonekit cross-tenant access denied"),
            Self::MissingKit => write!(f, "clonekit not published"),
            Self::EmptyRepository => write!(f, "repository is empty; no clonekit pack exists"),
            Self::StaleGeneration { expected_min, actual } => {
                write!(f, "clonekit generation {actual} below minimum {expected_min}")
            }
            Self::HistoryChanged { expected, actual } => {
                write!(f, "clonekit history changed (expected {expected}, got {actual})")
            }
            Self::CorruptArtifact(m) => write!(f, "clonekit corrupt artifact: {m}"),
            Self::ForeignBackend => write!(f, "clonekit blob backend identity mismatch"),
            Self::IncompleteClosure(m) => write!(f, "clonekit incomplete closure: {m}"),
            Self::DependencyCheckFailed(m) => write!(f, "clonekit dependency verification failed: {m}"),
            Self::PinProtectionActive(id) => write!(f, "clonekit bytes protected by active pin {id}"),
            Self::TransferCancelled => write!(f, "clonekit transfer cancelled"),
            Self::GitFailed(m) => write!(f, "clonekit git failed: {m}"),
            Self::BlobFailed(m) => write!(f, "clonekit blob error: {m}"),
            Self::DatabaseFailed(m) => write!(f, "clonekit database error: {m}"),
        }
    }
}

impl std::error::Error for CloneKitError {}

impl From<BlobError> for CloneKitError {
    fn from(value: BlobError) -> Self {
        match value {
            BlobError::ForeignBackend => Self::ForeignBackend,
            BlobError::DigestMismatch { expected, actual } => {
                Self::CorruptArtifact(format!("blob digest mismatch (expected {expected}, got {actual})"))
            }
            BlobError::LengthMismatch { expected, actual } => {
                Self::CorruptArtifact(format!("blob length mismatch (expected {expected}, got {actual})"))
            }
            other => Self::BlobFailed(other.to_string()),
        }
    }
}

/// Validate lowercase 64-character SHA-256 hex digest.
pub(super) fn valid_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Validate normalized reference path under `refs/heads/` or `refs/tags/`.
pub(super) fn valid_branch_ref(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 256
        && (raw.starts_with("refs/heads/") || raw.starts_with("refs/tags/"))
        && !raw.contains("..")
        && !raw.contains("@{")
        && !raw.ends_with('/')
        && !raw.bytes().any(|b| b.is_ascii_control() || b == b'\\' || b == b' ')
}

/// Read Git's canonical pack trailer checksum without hashing the pack body.
pub(super) fn read_pack_trailer_hex(path: &Path, object_format: CloneKitObjectFormat) -> Result<String, CloneKitError> {
    let meta = fs::symlink_metadata(path).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(CloneKitError::CorruptArtifact(format!("{} is not a regular file", path.display())));
    }
    let trailer_len = object_format.oid_hex_len() / 2;
    if meta.len() < 12 + trailer_len as u64 {
        return Err(CloneKitError::CorruptArtifact("staged pack shorter than header plus trailer".into()));
    }
    let mut file = fs::File::open(path).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?;
    file.seek(SeekFrom::Start(meta.len() - trailer_len as u64))
        .map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?;
    let mut trailer = [0u8; 32];
    file.read_exact(&mut trailer[..trailer_len]).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?;
    Ok(hex::encode(&trailer[..trailer_len]))
}

/// Stream-hash a regular file to lowercase SHA-256 hex + exact byte length.
pub(super) fn compute_file_sha256(path: &Path) -> Result<(String, u64), CloneKitError> {
    let meta = fs::symlink_metadata(path).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(CloneKitError::CorruptArtifact(format!("{} is not a regular file", path.display())));
    }
    let mut file = fs::File::open(path).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

/// Ensure a directory exists as a non-symlink `0o700` private directory.
pub(super) fn ensure_private_dir(dir: &Path) -> Result<(), CloneKitError> {
    if let Ok(meta) = fs::symlink_metadata(dir) {
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(CloneKitError::InvalidConfig("clonekit private directory is symlink or non-dir"));
        }
    } else {
        fs::create_dir_all(dir).map_err(|e| CloneKitError::GitFailed(e.to_string()))?;
    }
    fs::set_permissions(dir, Permissions::from_mode(0o700)).map_err(|e| CloneKitError::GitFailed(e.to_string()))?;
    let meta = fs::symlink_metadata(dir).map_err(|e| CloneKitError::GitFailed(e.to_string()))?;
    if meta.file_type().is_symlink() || !meta.is_dir() || (meta.permissions().mode() & 0o777) != 0o700 {
        return Err(CloneKitError::InvalidConfig("clonekit private directory mode verification failed"));
    }
    Ok(())
}

/// Atomically write a private `0o600` file via unique `O_EXCL` staging + fsync + rename.
pub(super) fn write_atomic_private_file(dest: &Path, bytes: &[u8]) -> Result<(), CloneKitError> {
    let parent = dest.parent().ok_or(CloneKitError::InvalidInput("destination missing parent"))?;
    ensure_private_dir(parent)?;
    let tmp = parent.join(format!(".ck-tmp-{}", Uuid::new_v4().simple()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| CloneKitError::GitFailed(e.to_string()))?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|e| CloneKitError::GitFailed(e.to_string()))?;
    drop(file);
    fs::rename(&tmp, dest).map_err(|e| CloneKitError::GitFailed(e.to_string()))
}

/// Build a sandboxed stock `git` command ignoring user/system config and disabling prompts.
pub(super) fn git_cmd(git_binary: &Path, cwd: Option<&Path>) -> Result<Command, CloneKitError> {
    if !git_binary.is_absolute() {
        return Err(CloneKitError::InvalidConfig("git_binary must be an absolute path"));
    }
    let mut cmd = Command::new(git_binary);
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    Ok(cmd)
}

/// Execute a bounded stock `git` command in an isolated environment, checking cancellation.
pub(super) fn run_git_command(
    git_binary: &Path,
    cwd: Option<&Path>,
    args: &[&str],
    cancel: Option<&CancellationToken>,
) -> Result<Vec<u8>, CloneKitError> {
    ensure_not_cancelled(cancel)?;
    let mut cmd = git_cmd(git_binary, cwd)?;
    cmd.args(args);
    let output = cmd.output().map_err(|e| CloneKitError::GitFailed(format!("spawn git {:?}: {e}", args)))?;
    ensure_not_cancelled(cancel)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CloneKitError::GitFailed(format!("git {:?} failed ({}): {}", args, output.status, stderr.trim())));
    }
    Ok(output.stdout)
}

/// Check optional cancellation token before advancing transfer or build stage.
pub(super) fn ensure_not_cancelled(cancel: Option<&CancellationToken>) -> Result<(), CloneKitError> {
    if cancel.is_some_and(CancellationToken::is_cancelled) {
        return Err(CloneKitError::TransferCancelled);
    }
    Ok(())
}

/// Keep default wait bounded across tests and helpers.
pub(super) const fn default_git_timeout() -> Duration {
    Duration::from_secs(30)
}

#[cfg(test)]
mod pack_trailer_tests {
    use super::*;
    use CloneKitObjectFormat::{Sha1, Sha256};

    #[test]
    fn pack_trailer_reads_format_sized_tail_and_rejects_short_files() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let pack = dir.path().join("owned.pack");
        for (format, len) in [(Sha1, 20), (Sha256, 32)] {
            let mut bytes = b"PACK\x00\x00\x00\x02\x00\x00\x00\x00".to_vec();
            bytes.extend(std::iter::repeat_n(0x11, len));
            fs::write(&pack, &bytes).expect("pack");
            assert_eq!(read_pack_trailer_hex(&pack, format).expect("trailer"), "11".repeat(len));
            fs::write(&pack, vec![0u8; 11 + len]).expect("short pack");
            let err = read_pack_trailer_hex(&pack, format);
            assert!(matches!(err, Err(CloneKitError::CorruptArtifact(_))));
        }
    }
}
