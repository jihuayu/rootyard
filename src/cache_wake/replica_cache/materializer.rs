//! OpenDAL `BlobStore` + `DisposableViewRoot` + stock `git` materializer with
//! Layer 1 verified pack reuse across version updates and strict `0o444` read-only view isolation.

use std::{
    fs::DirBuilder,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Instant,
};

use sha2::{Digest, Sha256};
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

use crate::blob_store::{
    BlobError, BlobLocator, disposable_view::DisposableViewError, envelope::EnvelopeMetadata,
    key_provider::KeyProvider, opendal::BlobStore,
};

use super::{
    catalog::{CachedViewSlot, ViewCacheCatalog},
    lease_pin::AuthoritativeSnapshot,
    pack_cache::{PackCacheCatalog, PackCachePin, copy_readonly, remove_dir_safely},
    types::{
        PackObjectSpec, ReplicaCacheError, ReplicaCacheLimits, ReplicaObjectFormat, ReplicaServeSource, ReplicaViewKey,
    },
};

const IO_CHUNK_BYTES: usize = 64 * 1024;
#[cfg(unix)]
const NULL_GIT_CONFIG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_GIT_CONFIG: &str = "NUL";

pub struct MaterializationOutput {
    pub slot: Arc<CachedViewSlot>,
    pub source: ReplicaServeSource,
    pub blob_gets: u64,
    pub blob_bytes: u64,
    pub reused_pack_count: usize,
    pub reused_pack_bytes: u64,
    pub copied_bytes: u64,
    pub pack_hits: u64,
    pub pack_misses: u64,
    pub corrupt_detections: u64,
}

struct StagingCleanupGuard {
    dir: PathBuf,
}

impl Drop for StagingCleanupGuard {
    fn drop(&mut self) {
        let _ = remove_dir_safely(&self.dir);
    }
}

pub async fn materialize_version_view(
    store: &BlobStore,
    key_provider: Option<&Arc<dyn KeyProvider>>,
    packs_cache: &PackCacheCatalog,
    views_cache: &ViewCacheCatalog,
    snapshot: &AuthoritativeSnapshot,
    view_key: ReplicaViewKey,
    limits: ReplicaCacheLimits,
    deadline: Instant,
) -> Result<MaterializationOutput, ReplicaCacheError> {
    let mut sorted_packs = snapshot.packs.clone();
    sorted_packs.sort_by(|a, b| {
        (&a.pack_stem, a.pack_locator.sha256(), a.idx_locator.sha256()).cmp(&(
            &b.pack_stem,
            b.pack_locator.sha256(),
            b.idx_locator.sha256(),
        ))
    });

    let total_pack_bytes = sorted_packs.iter().fold(0u64, |acc, p| acc.saturating_add(p.total_bytes()));
    let reserved_bytes = total_pack_bytes.saturating_mul(2).max(4096);
    views_cache.ensure_admission_room(reserved_bytes)?;

    let mut blob_gets = 0u64;
    let mut blob_bytes = 0u64;
    let mut reused_pack_count = 0usize;
    let mut reused_pack_bytes = 0u64;
    let mut pack_hits = 0u64;
    let mut pack_misses = 0u64;
    let mut corrupt_detections = 0u64;
    let mut pins: Vec<PackCachePin> = Vec::with_capacity(sorted_packs.len());
    let mut expected_files: Vec<(String, u64, u64)> = Vec::with_capacity(sorted_packs.len());

    let backend_hex = store.backend_identity().as_hex();
    for spec in &sorted_packs {
        let pack_key = spec.pack_cache_key(backend_hex, snapshot.object_format)?;
        expected_files.push((spec.pack_stem.clone(), spec.pack_locator.length(), spec.idx_locator.length()));
        let (maybe_pin, corrupt) = packs_cache.pin_if_valid(&pack_key, true)?;
        if corrupt {
            corrupt_detections = corrupt_detections.saturating_add(1);
        }
        if let Some(pin) = maybe_pin {
            reused_pack_count = reused_pack_count.saturating_add(1);
            reused_pack_bytes = reused_pack_bytes.saturating_add(spec.total_bytes());
            pack_hits = pack_hits.saturating_add(1);
            pins.push(pin);
            continue;
        }
        pack_misses = pack_misses.saturating_add(1);
        let (pin, gets, bytes) = fetch_verify_and_cache_pack(
            store,
            key_provider,
            packs_cache,
            spec,
            snapshot.object_format,
            pack_key,
            deadline,
        )
        .await?;
        blob_gets = blob_gets.saturating_add(gets);
        blob_bytes = blob_bytes.saturating_add(bytes);
        pins.push(pin);
    }

    let lease = match views_cache.view_root().create_view(
        "replica-view",
        snapshot.tenant_id,
        snapshot.repo_id,
        reserved_bytes,
        Some(limits.view_ttl),
    ) {
        Ok(lease) => lease,
        Err(DisposableViewError::CapacityExceeded(_)) => {
            return Err(ReplicaCacheError::CacheCapacityExhausted("disposable view root capacity exceeded"));
        }
        Err(other) => return Err(other.into()),
    };

    let repo_path = lease.repo_path()?.to_path_buf();
    run_git(&repo_path, &["init", "--bare", snapshot.object_format.git_init_flag()], deadline).await?;

    let mut copied_bytes = 0u64;
    for (spec, pin) in sorted_packs.iter().zip(pins.iter()) {
        let pack_rel = Path::new("objects/pack").join(format!("{}.pack", spec.pack_stem));
        let idx_rel = Path::new("objects/pack").join(format!("{}.idx", spec.pack_stem));
        let pack_dst = lease.resolve_repo_relative_path(&pack_rel)?;
        let idx_dst = lease.resolve_repo_relative_path(&idx_rel)?;
        copied_bytes = copied_bytes.saturating_add(copy_readonly(pin.pack_path(), &pack_dst)?);
        copied_bytes = copied_bytes.saturating_add(copy_readonly(pin.idx_path(), &idx_dst)?);
    }

    for reference in &snapshot.refs {
        run_git(&repo_path, &["update-ref", &reference.name, &reference.oid], deadline).await?;
    }
    run_git(&repo_path, &["symbolic-ref", "HEAD", &snapshot.head_ref], deadline).await?;
    run_git(&repo_path, &["fsck", "--full", "--strict"], deadline).await?;
    set_refs_readonly(&repo_path)?;

    let slot = views_cache.admit_and_checkout(view_key, lease, pins, reserved_bytes, expected_files)?;
    let source = if reused_pack_count == sorted_packs.len() {
        ReplicaServeSource::PackCacheFullReuse
    } else if reused_pack_count > 0 {
        ReplicaServeSource::PackCachePartialRefill
    } else {
        ReplicaServeSource::ColdBlobMaterialized
    };

    Ok(MaterializationOutput {
        slot,
        source,
        blob_gets,
        blob_bytes,
        reused_pack_count,
        reused_pack_bytes,
        copied_bytes,
        pack_hits,
        pack_misses,
        corrupt_detections,
    })
}

async fn fetch_verify_and_cache_pack(
    store: &BlobStore,
    key_provider: Option<&Arc<dyn KeyProvider>>,
    packs_cache: &PackCacheCatalog,
    spec: &PackObjectSpec,
    format: ReplicaObjectFormat,
    pack_key: super::types::PackCacheKey,
    deadline: Instant,
) -> Result<(PackCachePin, u64, u64), ReplicaCacheError> {
    let stage_dir = packs_cache.staging_dir()?;
    let _cleanup = StagingCleanupGuard { dir: stage_dir.clone() };
    let verify_repo = stage_dir.join("verify.git");
    DirBuilder::new()
        .mode(0o700)
        .create(&verify_repo)
        .map_err(|e| ReplicaCacheError::Io(format!("failed creating verify dir: {e}")))?;
    run_git(&verify_repo, &["init", "--bare", format.git_init_flag()], deadline).await?;

    let pack_dst = verify_repo.join("objects/pack").join(format!("{}.pack", spec.pack_stem));
    let idx_dst = verify_repo.join("objects/pack").join(format!("{}.idx", spec.pack_stem));

    download_verified_object(store, &spec.pack_locator, spec.pack_envelope.as_ref(), key_provider, &pack_dst, deadline)
        .await?;
    download_verified_object(store, &spec.idx_locator, spec.idx_envelope.as_ref(), key_provider, &idx_dst, deadline)
        .await?;

    let idx_arg = format!("objects/pack/{}.idx", spec.pack_stem);
    run_git(&verify_repo, &["verify-pack", "-v", &idx_arg], deadline).await?;

    let pin = packs_cache.install_and_pin(pack_key, &pack_dst, &idx_dst)?;
    Ok((pin, 2, spec.total_bytes()))
}

async fn download_verified_object(
    store: &BlobStore,
    locator: &BlobLocator,
    envelope: Option<&EnvelopeMetadata>,
    key_provider: Option<&Arc<dyn KeyProvider>>,
    dst: &Path,
    deadline: Instant,
) -> Result<(), ReplicaCacheError> {
    if let Some(meta) = envelope {
        let kp =
            key_provider.ok_or(ReplicaCacheError::InvalidInput("missing KeyProvider for local-envelope".into()))?;
        store.get_decrypted_to_file(locator, meta, kp, dst, deadline).await?;
    } else {
        store.get_to_file(locator, dst, deadline).await.map_err(map_blob_err)?;
    }
    verify_file_sha256_and_len(dst, locator.sha256(), locator.length()).await
}

fn map_blob_err(err: BlobError) -> ReplicaCacheError {
    match err {
        BlobError::DeadlineExceeded => ReplicaCacheError::DeadlineExceeded,
        other => ReplicaCacheError::Blob(other),
    }
}

async fn verify_file_sha256_and_len(
    path: &Path,
    expected_sha256: &str,
    expected_len: u64,
) -> Result<(), ReplicaCacheError> {
    let mut file = fs::File::open(path).await.map_err(|e| ReplicaCacheError::Io(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; IO_CHUNK_BYTES];
    loop {
        let n = file.read(&mut buf).await.map_err(|e| ReplicaCacheError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    if total != expected_len || hex::encode(hasher.finalize()) != expected_sha256 {
        return Err(ReplicaCacheError::IntegrityFailed("downloaded blob digest or length mismatch"));
    }
    Ok(())
}

fn set_refs_readonly(repo_path: &Path) -> Result<(), ReplicaCacheError> {
    let head = repo_path.join("HEAD");
    if head.is_file() {
        std::fs::set_permissions(&head, std::fs::Permissions::from_mode(0o444))
            .map_err(|e| ReplicaCacheError::Io(format!("chmod HEAD failed: {e}")))?;
    }
    mark_files_readonly_recursive(&repo_path.join("refs"))
}

fn mark_files_readonly_recursive(dir: &Path) -> Result<(), ReplicaCacheError> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir).map_err(|e| ReplicaCacheError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| ReplicaCacheError::Io(e.to_string()))?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path).map_err(|e| ReplicaCacheError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() {
            return Err(ReplicaCacheError::IntegrityFailed("unexpected symlink inside view refs"));
        }
        if meta.is_dir() {
            mark_files_readonly_recursive(&path)?;
        } else if meta.is_file() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))
                .map_err(|e| ReplicaCacheError::Io(format!("chmod ref failed: {e}")))?;
        }
    }
    Ok(())
}

pub fn verify_read_only_view_files(repo_path: &Path) -> Result<(), ReplicaCacheError> {
    let pack_dir = repo_path.join("objects/pack");
    for entry in std::fs::read_dir(&pack_dir).map_err(|e| ReplicaCacheError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| ReplicaCacheError::Io(e.to_string()))?;
        let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| ReplicaCacheError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() {
            return Err(ReplicaCacheError::IntegrityFailed("symlink detected inside view pack dir"));
        }
        if meta.is_file() && (meta.permissions().mode() & 0o222 != 0) {
            return Err(ReplicaCacheError::IntegrityFailed("view pack/idx file is writable"));
        }
    }
    Ok(())
}

pub async fn run_git(repo_dir: &Path, args: &[&str], deadline: Instant) -> Result<Vec<u8>, ReplicaCacheError> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(ReplicaCacheError::DeadlineExceeded)?;
    let cmd_name: &'static str = match args.first().copied() {
        Some("init") => "init",
        Some("verify-pack") => "verify-pack",
        Some("update-ref") => "update-ref",
        Some("symbolic-ref") => "symbolic-ref",
        Some("fsck") => "fsck",
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
        .stdin(Stdio::null());
    let mut child = cmd
        .spawn()
        .map_err(|e| ReplicaCacheError::GitFailed { command: cmd_name, detail: format!("spawn failed: {e}") })?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.shutdown().await;
    }
    let out = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| ReplicaCacheError::DeadlineExceeded)?
        .map_err(|e| ReplicaCacheError::GitFailed { command: cmd_name, detail: format!("wait failed: {e}") })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        let detail = if stderr.is_empty() { format!("exit status {}", out.status) } else { stderr };
        return Err(ReplicaCacheError::GitFailed { command: cmd_name, detail });
    }
    Ok(out.stdout)
}
