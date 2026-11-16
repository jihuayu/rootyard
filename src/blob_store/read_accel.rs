//! Rebuildable, non-authoritative Blob read-acceleration sidecars (Issue #165).
//!
//! Git read-acceleration artifacts (`MIDX`, multi-pack `.bitmap`, `commit-graph`)
//! are strictly non-authoritative performance caches bound to immutable
//! repository identity, `object_format`, `membership_generation`, and sorted
//! authoritative pack digests. Authoritative durability always remains with
//! `RefStore` (refs/generations) and immutable `.pack` / `.idx` Blob closures
//! (#163 / #164).
//!
//! Default policy is disabled (`ENABLE_BY_DEFAULT = false`) until measured
//! benchmark workloads show net benefit over pack-only materialization. Any
//! drift, missing object, digest/length mismatch, or Git verification error
//! fails closed to authoritative pack-only Git reads after quarantining any
//! partial or corrupt sidecar files.

pub mod builder;
pub mod manifest;
pub mod reader;

use std::{
    fmt,
    path::Path,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use uuid::Uuid;

pub use builder::{
    AuthoritativePackSource, AuthoritativeRef, BuildReadAccelRequest, BuiltReadAccelBundle, PackRetentionGuard,
    PackRetentionRegistry, ReadAccelBuildMetrics, build_and_upload_sidecars,
};
pub use manifest::{
    MAX_COMMIT_GRAPH_BYTES, MAX_MANIFEST_BYTES, MAX_MIDX_BYTES, PackDigestEntry, READ_ACCEL_MANIFEST_SCHEMA,
    ReadAccelArtifact, ReadAccelArtifactKind, ReadAccelConfig, ReadAccelFallbackReason, ReadAccelManifest,
    ReadAccelManifestError, ReadAccelObjectFormat, SerializedBlobLocator,
};
pub use reader::{
    ManifestFetchRef, MaterializeViewRequest, MaterializedAccelView, ReadAccelMaterializeMetrics,
    ReadAccelSidecarStatus, materialize_git_view_with_read_accel, scrub_sidecars_in_repo,
    verify_and_recover_view_sidecars,
};

use super::{
    BlobError, BlobLocator, BlobReceipt,
    closure::BlobClosureError,
    disposable_view::{DisposableViewError, TempViewLease},
    envelope::{EnvelopeError, EnvelopeMetadata, EnvelopeSpec, prepare_file_envelope},
    key_provider::KeyProvider,
    opendal::BlobStore,
};

/// Issue #165 policy: keep MIDX/bitmap/commit-graph disabled unless explicitly opted in.
pub const ENABLE_BY_DEFAULT: bool = false;
/// Default Blob namespace for read-acceleration sidecars and manifests.
pub const DEFAULT_SIDECAR_NAMESPACE: &str = "read-accel";
const IO_CHUNK_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const NULL_GIT_CONFIG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_GIT_CONFIG: &str = "NUL";

/// Typed error surface for read-acceleration manifest, maintenance build, and view operations.
#[derive(Debug)]
pub enum ReadAccelError {
    Manifest(ReadAccelManifestError),
    DisabledByDefault,
    InvalidInput(String),
    Blob(BlobError),
    Envelope(EnvelopeError),
    Closure(BlobClosureError),
    DisposableView(DisposableViewError),
    GitCommandFailed { command: &'static str, detail: String },
    SidecarIntegrityFailed(&'static str),
    DeadlineExceeded,
    Io(String),
}

impl fmt::Display for ReadAccelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(err) => write!(f, "{err}"),
            Self::DisabledByDefault => f.write_str("blob read-acceleration sidecars are disabled by default"),
            Self::InvalidInput(msg) => write!(f, "invalid read-acceleration input: {msg}"),
            Self::Blob(err) => write!(f, "{err}"),
            Self::Envelope(err) => write!(f, "{err}"),
            Self::Closure(err) => write!(f, "{err}"),
            Self::DisposableView(err) => write!(f, "{err}"),
            Self::GitCommandFailed { command, detail } => write!(f, "git `{command}` failed: {detail}"),
            Self::SidecarIntegrityFailed(msg) => write!(f, "read-acceleration sidecar integrity failed: {msg}"),
            Self::DeadlineExceeded => f.write_str("read-acceleration operation deadline exceeded"),
            Self::Io(msg) => write!(f, "read-acceleration IO failure: {msg}"),
        }
    }
}

impl std::error::Error for ReadAccelError {}

impl From<ReadAccelManifestError> for ReadAccelError {
    fn from(value: ReadAccelManifestError) -> Self {
        Self::Manifest(value)
    }
}

impl From<BlobError> for ReadAccelError {
    fn from(value: BlobError) -> Self {
        Self::Blob(value)
    }
}

impl From<EnvelopeError> for ReadAccelError {
    fn from(value: EnvelopeError) -> Self {
        Self::Envelope(value)
    }
}

impl From<BlobClosureError> for ReadAccelError {
    fn from(value: BlobClosureError) -> Self {
        Self::Closure(value)
    }
}

impl From<DisposableViewError> for ReadAccelError {
    fn from(value: DisposableViewError) -> Self {
        Self::DisposableView(value)
    }
}

pub(super) fn remaining_timeout(deadline: Instant) -> Result<Duration, ReadAccelError> {
    deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(ReadAccelError::DeadlineExceeded)
}

pub(super) fn is_lower_hex_exact(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn validate_sha256_hex(value: &str) -> Result<(), ReadAccelManifestError> {
    if !is_lower_hex_exact(value, 64) {
        return Err(ReadAccelManifestError::InvalidField("expected 64-char lowercase sha256 hex"));
    }
    Ok(())
}

pub(super) fn validate_pack_stem(stem: &str, format: ReadAccelObjectFormat) -> Result<(), ReadAccelManifestError> {
    let Some(oid_hex) = stem.strip_prefix("pack-") else {
        return Err(ReadAccelManifestError::InvalidField("pack_stem must start with `pack-`"));
    };
    if !is_lower_hex_exact(oid_hex, format.oid_hex_len()) {
        return Err(ReadAccelManifestError::InvalidField("pack_stem oid does not match object_format"));
    }
    Ok(())
}

pub(super) fn validate_ref_name_and_oid(
    name: &str,
    oid: &str,
    format: ReadAccelObjectFormat,
) -> Result<(), ReadAccelError> {
    if !name.starts_with("refs/") || name.contains("..") || name.contains('\0') || name.ends_with('/') {
        return Err(ReadAccelError::InvalidInput("authoritative ref name must be canonical `refs/...`".into()));
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.')) {
        return Err(ReadAccelError::InvalidInput("authoritative ref name contains disallowed characters".into()));
    }
    if !is_lower_hex_exact(oid, format.oid_hex_len()) {
        return Err(ReadAccelError::InvalidInput("authoritative ref oid does not match object_format".into()));
    }
    Ok(())
}

pub(super) async fn hash_file_sha256(path: &Path) -> Result<(String, u64), ReadAccelError> {
    let mut file = tokio::fs::File::open(path).await.map_err(|e| ReadAccelError::Io(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; IO_CHUNK_BYTES];
    loop {
        let n = file.read(&mut buf).await.map_err(|e| ReadAccelError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

pub(super) async fn verify_file_digest_and_len(
    path: &Path,
    expected_sha256: &str,
    expected_len: u64,
) -> Result<(), ReadAccelError> {
    let (actual_sha256, actual_len) = hash_file_sha256(path).await?;
    if actual_len != expected_len || actual_sha256 != expected_sha256 {
        return Err(ReadAccelError::SidecarIntegrityFailed("local sidecar SHA-256 or length mismatch"));
    }
    Ok(())
}

pub(super) async fn run_git(
    repo_dir: &Path,
    args: &[&str],
    stdin_data: Option<&[u8]>,
    deadline: Instant,
) -> Result<Vec<u8>, ReadAccelError> {
    Ok(run_git_with_stderr(repo_dir, args, stdin_data, deadline).await?.0)
}

pub(super) async fn run_git_with_stderr(
    repo_dir: &Path,
    args: &[&str],
    stdin_data: Option<&[u8]>,
    deadline: Instant,
) -> Result<(Vec<u8>, String), ReadAccelError> {
    let timeout = remaining_timeout(deadline)?;
    let cmd_name: &'static str = match args.first().copied() {
        Some("init") => "init",
        Some("verify-pack") => "verify-pack",
        Some("update-ref") => "update-ref",
        Some("multi-pack-index") => "multi-pack-index",
        Some("commit-graph") => "commit-graph",
        Some("rev-list") => "rev-list",
        _ => "git",
    };
    let mut cmd = Command::new("git");
    cmd.arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(repo_dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG)
        .env("GIT_TERMINAL_PROMPT", "0")
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin_data.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = cmd
        .spawn()
        .map_err(|e| ReadAccelError::GitCommandFailed { command: cmd_name, detail: format!("spawn failed: {e}") })?;
    if let Some(bytes) = stdin_data
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin.write_all(bytes).await.map_err(|e| ReadAccelError::GitCommandFailed {
            command: cmd_name,
            detail: format!("stdin write failed: {e}"),
        })?;
        drop(stdin);
    }
    let out = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| ReadAccelError::DeadlineExceeded)?
        .map_err(|e| ReadAccelError::GitCommandFailed { command: cmd_name, detail: format!("wait failed: {e}") })?;
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    if !out.status.success() {
        let detail = if stderr.is_empty() { format!("exit status {}", out.status) } else { stderr };
        return Err(ReadAccelError::GitCommandFailed { command: cmd_name, detail });
    }
    Ok((out.stdout, stderr))
}

pub(super) async fn upload_object_file(
    store: &BlobStore,
    tenant_id: Uuid,
    authority_id: Uuid,
    generation: i64,
    namespace: &str,
    src: &Path,
    staging_dir: &Path,
    key_provider: Option<&Arc<dyn KeyProvider>>,
    deadline: Instant,
) -> Result<(BlobReceipt, String, u64, Option<EnvelopeMetadata>), ReadAccelError> {
    let (plain_sha256, plain_len) = hash_file_sha256(src).await?;
    if store.profile().encryption().is_local_envelope() {
        let kp = key_provider.ok_or(BlobClosureError::MissingKeyProvider)?;
        let spec = EnvelopeSpec { tenant_id, authority_id, generation, namespace: namespace.to_owned() };
        let prepared = prepare_file_envelope(&spec, src, staging_dir, store.profile().max_object_bytes())?;
        let intent = store.new_upload(
            tenant_id,
            authority_id,
            generation,
            namespace,
            prepared.ciphertext_sha256(),
            prepared.ciphertext_length(),
        )?;
        let sealed = prepared.bind_and_wrap(kp.as_ref(), intent.locator())?;
        let (receipt, metadata) = store.put_encrypted_file(intent, sealed, deadline).await?;
        return Ok((receipt, plain_sha256, plain_len, Some(metadata)));
    }
    let intent = store.new_upload(tenant_id, authority_id, generation, namespace, &plain_sha256, plain_len)?;
    let receipt = store.put_file(intent, src, deadline).await?;
    Ok((receipt, plain_sha256, plain_len, None))
}

pub(super) async fn download_object_file(
    store: &BlobStore,
    locator: &BlobLocator,
    envelope: Option<&EnvelopeMetadata>,
    key_provider: Option<&Arc<dyn KeyProvider>>,
    dst: &Path,
    deadline: Instant,
) -> Result<(), ReadAccelError> {
    if store.profile().encryption().is_local_envelope() {
        let meta = envelope.ok_or(EnvelopeError::MetadataCorrupt("missing local-envelope sidecar metadata"))?;
        let kp = key_provider.ok_or(BlobClosureError::MissingKeyProvider)?;
        store.get_decrypted_to_file(locator, meta, kp, dst, deadline).await?;
        return Ok(());
    }
    if envelope.is_some() {
        return Err(EnvelopeError::EncryptionPolicyMismatch.into());
    }
    store.get_to_file(locator, dst, deadline).await?;
    Ok(())
}

pub(super) fn sort_pack_sources(
    tenant_id: Uuid,
    repo_id: Uuid,
    object_format: ReadAccelObjectFormat,
    packs: &[AuthoritativePackSource],
) -> Result<Vec<(AuthoritativePackSource, PackDigestEntry)>, ReadAccelError> {
    if packs.is_empty() {
        return Err(ReadAccelError::InvalidInput("authoritative pack list must not be empty".into()));
    }
    let mut paired = Vec::with_capacity(packs.len());
    for source in packs {
        validate_pack_stem(&source.pack_stem, object_format)?;
        if source.pack_locator.tenant_id() != tenant_id
            || source.pack_locator.authority_id() != repo_id
            || source.idx_locator.tenant_id() != tenant_id
            || source.idx_locator.authority_id() != repo_id
        {
            return Err(ReadAccelError::InvalidInput("pack/idx locator tenant or repo scope mismatch".into()));
        }
        let digest_entry = PackDigestEntry::from_locators(&source.pack_stem, &source.pack_locator, &source.idx_locator);
        paired.push((source.clone(), digest_entry));
    }
    paired.sort_by(|a, b| a.1.sort_key().cmp(&b.1.sort_key()));
    for pair in paired.windows(2) {
        if pair[0].1.pack_stem == pair[1].1.pack_stem || pair[0].1.sort_key() == pair[1].1.sort_key() {
            return Err(ReadAccelError::InvalidInput("duplicate authoritative pack_stem in closure".into()));
        }
    }
    Ok(paired)
}

pub(super) async fn populate_bare_view_from_authoritative_packs(
    store: &BlobStore,
    lease: &TempViewLease,
    object_format: ReadAccelObjectFormat,
    paired_packs: &[(AuthoritativePackSource, PackDigestEntry)],
    refs: &[AuthoritativeRef],
    key_provider: Option<&Arc<dyn KeyProvider>>,
    deadline: Instant,
) -> Result<(u64, u64), ReadAccelError> {
    let repo_path = lease.repo_path()?;
    run_git(repo_path, &["init", "--bare", object_format.git_init_flag()], None, deadline).await?;
    let mut pack_get_attempts = 0u64;
    let mut pack_get_bytes = 0u64;
    for (source, _) in paired_packs {
        let pack_rel = Path::new("objects/pack").join(format!("{}.pack", source.pack_stem));
        let idx_rel = Path::new("objects/pack").join(format!("{}.idx", source.pack_stem));
        let pack_dst = lease.resolve_repo_relative_path(&pack_rel)?;
        let idx_dst = lease.resolve_repo_relative_path(&idx_rel)?;
        pack_get_attempts = pack_get_attempts.saturating_add(1);
        download_object_file(
            store,
            &source.pack_locator,
            source.pack_envelope.as_ref(),
            key_provider,
            &pack_dst,
            deadline,
        )
        .await?;
        pack_get_bytes = pack_get_bytes.saturating_add(source.pack_locator.length());
        pack_get_attempts = pack_get_attempts.saturating_add(1);
        download_object_file(
            store,
            &source.idx_locator,
            source.idx_envelope.as_ref(),
            key_provider,
            &idx_dst,
            deadline,
        )
        .await?;
        pack_get_bytes = pack_get_bytes.saturating_add(source.idx_locator.length());
    }
    for reference in refs {
        validate_ref_name_and_oid(&reference.name, &reference.oid, object_format)?;
        run_git(repo_path, &["update-ref", &reference.name, &reference.oid], None, deadline).await?;
    }
    Ok((pack_get_attempts, pack_get_bytes))
}

#[cfg(test)]
mod tests {
    use super::super::{budget::ResourceLimits, test_support};
    use super::*;

    #[test]
    fn default_policy_and_schema_reject_unknown_fields_and_invalid_bindings() {
        assert!(!ENABLE_BY_DEFAULT && !ReadAccelConfig::default().enabled);
        assert!(serde_json::from_slice::<ReadAccelConfig>(br#"{"enabled":false,"extra":1}"#).is_err());
        assert!(serde_json::from_slice::<ReadAccelManifest>(br#"{"extra":true}"#).is_err());
        let (tenant, repo) = (Uuid::new_v4(), Uuid::new_v4());
        let loc = |seed: u8, ns: &str| {
            BlobLocator::new(tenant, repo, 1, Uuid::new_v4(), ns, &hex::encode(Sha256::digest([seed])), 64).unwrap()
        };
        let mut manifest = ReadAccelManifest {
            schema_version: READ_ACCEL_MANIFEST_SCHEMA,
            tenant_id: tenant,
            repo_id: repo,
            history_id: Uuid::new_v4(),
            object_format: ReadAccelObjectFormat::Sha256,
            membership_generation: 1,
            sorted_pack_digests: vec![PackDigestEntry::from_locators(
                format!("pack-{}", "a".repeat(64)),
                &loc(1, "packs"),
                &loc(2, "packs"),
            )],
            artifacts: vec![ReadAccelArtifact {
                kind: ReadAccelArtifactKind::Bitmap,
                relative_path: format!("objects/pack/multi-pack-index-{}.bitmap", "b".repeat(40)),
                locator: SerializedBlobLocator::from_locator(&loc(3, "read-accel")),
                plaintext_sha256: loc(3, "read-accel").sha256().to_owned(),
                plaintext_length: 64,
                envelope: None,
            }],
        };
        assert!(manifest.validate().is_err());
        manifest.membership_generation = 0;
        assert!(manifest.validate().is_err());
    }

    #[tokio::test]
    async fn disabled_config_refuses_sidecar_build_before_any_io() {
        let (store, _resources) = test_support::store(ResourceLimits::new(2, 2, 1 << 20).unwrap());
        let dir = tempfile::TempDir::new().unwrap();
        let views =
            super::super::disposable_view::DisposableViewRoot::open(dir.path(), 2, 8 << 20, Duration::from_secs(30))
                .unwrap();
        let tenant = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let pack_intent = test_support::upload(&store, "packs", b"dummy-pack-bytes");
        let idx_intent = test_support::upload(&store, "packs", b"dummy-idx-bytes");
        let req = BuildReadAccelRequest {
            tenant_id: tenant,
            repo_id: repo,
            history_id: Uuid::new_v4(),
            object_format: ReadAccelObjectFormat::Sha1,
            membership_generation: 1,
            blob_generation: 1,
            config: ReadAccelConfig::disabled(),
            packs: vec![AuthoritativePackSource::provider_managed(
                format!("pack-{}", "a".repeat(40)),
                pack_intent.locator().clone(),
                idx_intent.locator().clone(),
            )],
            refs: Vec::new(),
            retention_registry: None,
            key_provider: None,
        };
        let err =
            build_and_upload_sidecars(&store, &views, &req, Instant::now() + Duration::from_secs(5)).await.unwrap_err();
        assert!(matches!(err, ReadAccelError::DisabledByDefault));
    }
}
