//! Bounded stock Git and OpenDAL Blob transfer/inspection primitives.
//!
//! Runs real stock `git` with cleared config env, streams pack hashing and
//! Blob transfers in 64 KiB chunks, and pipes pack files straight to
//! `git index-pack --stdin` without buffering whole packs on the Rust heap.

use std::{
    fmt,
    fs::{self, DirBuilder},
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    time::Instant,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, process::Command};
use uuid::Uuid;

use super::limits::STREAMING_IO_CHUNK_BYTES;
use crate::blob_store::{
    BlobError, BlobLocator, BlobReceipt,
    disposable_view::{DisposableViewError, TempViewLease},
    opendal::BlobStore,
};

const PACK_HEADER_BYTES: usize = 12;

#[cfg(unix)]
const NULL_GIT_CONFIG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_GIT_CONFIG: &str = "NUL";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectFormat {
    Sha1,
    Sha256,
}

impl ObjectFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    pub const fn oid_hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    pub fn is_valid_oid(self, oid: &str) -> bool {
        oid.len() == self.oid_hex_len() && oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    pub fn is_zero_oid(self, oid: &str) -> bool {
        oid.len() == self.oid_hex_len() && oid.bytes().all(|b| b == b'0')
    }
}

#[derive(Debug)]
pub enum GitOpsError {
    DeadlineExceeded,
    Blob(BlobError),
    View(DisposableViewError),
    GitFailed { command: &'static str, detail: String },
    InvalidPack(&'static str),
    LimitExceeded(&'static str),
    Io(String),
}

impl fmt::Display for GitOpsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlineExceeded => f.write_str("git capacity verification deadline exceeded"),
            Self::Blob(err) => write!(f, "{err}"),
            Self::View(err) => write!(f, "{err}"),
            Self::GitFailed { command, detail } => write!(f, "git `{command}` failed: {detail}"),
            Self::InvalidPack(msg) => write!(f, "invalid pack artifact: {msg}"),
            Self::LimitExceeded(msg) => write!(f, "verification bound exceeded: {msg}"),
            Self::Io(msg) => write!(f, "git capacity IO error: {msg}"),
        }
    }
}

impl std::error::Error for GitOpsError {}

impl From<BlobError> for GitOpsError {
    fn from(value: BlobError) -> Self {
        Self::Blob(value)
    }
}

impl From<DisposableViewError> for GitOpsError {
    fn from(value: DisposableViewError) -> Self {
        Self::View(value)
    }
}

pub struct UploadedPackPair {
    pub pack_receipt: BlobReceipt,
    pub idx_receipt: BlobReceipt,
    pub pack_sha256: String,
    pub pack_length: u64,
    pub idx_sha256: String,
    pub idx_length: u64,
    pub object_count: u64,
}

#[derive(Debug, Clone)]
pub struct PackDownloadRef {
    pub pack_locator: BlobLocator,
    pub pack_sha256: String,
    pub pack_length: u64,
    pub idx_locator: BlobLocator,
    pub idx_sha256: String,
    pub idx_length: u64,
}

pub(super) enum GitStdin<'a> {
    Null,
    Bytes(&'a [u8]),
    File(&'a Path),
}

pub fn inspect_pack_file(path: &Path) -> Result<(String, u64, u64), GitOpsError> {
    let mut file = fs::File::open(path).map_err(|e| GitOpsError::Io(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut header = [0u8; PACK_HEADER_BYTES];
    let mut buf = vec![0u8; STREAMING_IO_CHUNK_BYTES];
    loop {
        let n = file.read(&mut buf).map_err(|e| GitOpsError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        if total < PACK_HEADER_BYTES as u64 {
            let off = total as usize;
            let take = n.min(PACK_HEADER_BYTES - off);
            header[off..off + take].copy_from_slice(&buf[..take]);
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    if total < PACK_HEADER_BYTES as u64 || &header[..4] != b"PACK" {
        return Err(GitOpsError::InvalidPack("missing PACK magic header"));
    }
    let version = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    if version != 2 && version != 3 {
        return Err(GitOpsError::InvalidPack("unsupported pack version"));
    }
    let obj_count = u64::from(u32::from_be_bytes([header[8], header[9], header[10], header[11]]));
    Ok((hex::encode(hasher.finalize()), total, obj_count))
}

pub fn hash_file_bounded(path: &Path) -> Result<(String, u64), GitOpsError> {
    let mut file = fs::File::open(path).map_err(|e| GitOpsError::Io(e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; STREAMING_IO_CHUNK_BYTES];
    loop {
        let n = file.read(&mut buf).map_err(|e| GitOpsError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    if total == 0 {
        return Err(GitOpsError::InvalidPack("pack artifact is empty"));
    }
    Ok((hex::encode(hasher.finalize()), total))
}

#[derive(Debug, Clone, Copy)]
pub struct UploadScope {
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
}

pub async fn upload_pack_pair(
    store: &BlobStore,
    scope: UploadScope,
    pack_path: &Path,
    idx_path: &Path,
    deadline: Instant,
) -> Result<UploadedPackPair, GitOpsError> {
    let (pack_sha256, pack_length, object_count) = inspect_pack_file(pack_path)?;
    let (idx_sha256, idx_length) = hash_file_bounded(idx_path)?;
    let pack_intent =
        store.new_upload(scope.tenant_id, scope.authority_id, scope.generation, "packs", &pack_sha256, pack_length)?;
    let pack_receipt = store.put_file(pack_intent, pack_path, deadline).await?;
    let idx_intent =
        store.new_upload(scope.tenant_id, scope.authority_id, scope.generation, "pack-idx", &idx_sha256, idx_length)?;
    let idx_receipt = store.put_file(idx_intent, idx_path, deadline).await?;
    if pack_receipt.backend_identity() != store.backend_identity()
        || idx_receipt.backend_identity() != store.backend_identity()
    {
        return Err(GitOpsError::Blob(BlobError::ForeignBackend));
    }
    Ok(UploadedPackPair { pack_receipt, idx_receipt, pack_sha256, pack_length, idx_sha256, idx_length, object_count })
}

pub(super) async fn run_git(
    repo_dir: &Path,
    args: &[&str],
    stdin_mode: GitStdin<'_>,
    deadline: Instant,
) -> Result<Vec<u8>, GitOpsError> {
    let timeout = deadline.checked_duration_since(Instant::now()).ok_or(GitOpsError::DeadlineExceeded)?;
    let cmd_name: &'static str = match args.first().copied() {
        Some("init") => "init",
        Some("verify-pack") => "verify-pack",
        Some("index-pack") => "index-pack",
        Some("update-ref") => "update-ref",
        Some("cat-file") => "cat-file",
        Some("fsck") => "fsck",
        Some("repack") => "repack",
        Some("rev-list") => "rev-list",
        _ => "git",
    };
    let mut cmd = Command::new("git");
    let stdin_stdio = match stdin_mode {
        GitStdin::Null => Stdio::null(),
        GitStdin::Bytes(_) => Stdio::piped(),
        GitStdin::File(path) => {
            let file = fs::File::open(path).map_err(|e| GitOpsError::Io(e.to_string()))?;
            Stdio::from(file)
        }
    };
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
        .stdin(stdin_stdio);
    let mut child =
        cmd.spawn().map_err(|e| GitOpsError::GitFailed { command: cmd_name, detail: format!("spawn failed: {e}") })?;
    if let GitStdin::Bytes(bytes) = stdin_mode
        && let Some(mut stdin) = child.stdin.take()
    {
        stdin
            .write_all(bytes)
            .await
            .map_err(|e| GitOpsError::GitFailed { command: cmd_name, detail: format!("stdin write failed: {e}") })?;
    }
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| GitOpsError::DeadlineExceeded)?
        .map_err(|e| GitOpsError::GitFailed { command: cmd_name, detail: e.to_string() })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.lines().next().unwrap_or("non-zero exit").to_owned();
        return Err(GitOpsError::GitFailed { command: cmd_name, detail });
    }
    Ok(output.stdout)
}

pub(super) fn dir_size_bytes(path: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    let mut total = 0u64;
    for entry in entries.flatten() {
        let Ok(meta) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            total = total.saturating_add(dir_size_bytes(&entry.path()));
        } else {
            total = total.saturating_add(meta.len());
        }
    }
    total
}

fn create_private_dir(path: &Path) -> Result<(), GitOpsError> {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|e| GitOpsError::Io(e.to_string()))
}

pub(super) async fn populate_bare_view(
    lease: &TempViewLease,
    store: &BlobStore,
    format: ObjectFormat,
    packs: &[PackDownloadRef],
    max_objects: u64,
    max_total_bytes: u64,
    deadline: Instant,
) -> Result<(PathBuf, u64, u64, u64), GitOpsError> {
    let repo_dir = lease.repo_path()?.to_path_buf();
    let incoming_dir = lease.dir_path()?.join("incoming");
    create_private_dir(&incoming_dir)?;
    let fmt_arg = format!("--object-format={}", format.as_str());
    run_git(&repo_dir, &["init", "--bare", "--quiet", &fmt_arg], GitStdin::Null, deadline).await?;

    let mut total_bytes = 0u64;
    let mut total_objects = 0u64;
    let mut blob_get_bytes = 0u64;
    let mut peak_scratch = dir_size_bytes(lease.dir_path()?);

    for (idx_num, pack_ref) in packs.iter().enumerate() {
        let pair_bytes = pack_ref.pack_length.saturating_add(pack_ref.idx_length);
        total_bytes = total_bytes.saturating_add(pair_bytes);
        if total_bytes > max_total_bytes {
            return Err(GitOpsError::LimitExceeded("window pack bytes exceed verifier limit"));
        }
        let pack_dst = incoming_dir.join(format!("p-{idx_num:04}.pack"));
        let idx_dst = incoming_dir.join(format!("p-{idx_num:04}.idx"));

        let pr = store
            .get_to_file_verified_receipt(
                &pack_ref.pack_locator,
                &pack_dst,
                &pack_ref.pack_sha256,
                pack_ref.pack_length,
                deadline,
            )
            .await?;
        let ir = store
            .get_to_file_verified_receipt(
                &pack_ref.idx_locator,
                &idx_dst,
                &pack_ref.idx_sha256,
                pack_ref.idx_length,
                deadline,
            )
            .await?;
        if pr.backend_identity() != store.backend_identity() || ir.backend_identity() != store.backend_identity() {
            return Err(GitOpsError::Blob(BlobError::ForeignBackend));
        }
        blob_get_bytes = blob_get_bytes.saturating_add(pair_bytes);

        let (actual_pack_sha, actual_pack_len, objs) = inspect_pack_file(&pack_dst)?;
        if actual_pack_sha != pack_ref.pack_sha256 || actual_pack_len != pack_ref.pack_length {
            return Err(GitOpsError::InvalidPack("downloaded pack SHA-256 or length mismatch"));
        }
        let (actual_idx_sha, actual_idx_len) = hash_file_bounded(&idx_dst)?;
        if actual_idx_sha != pack_ref.idx_sha256 || actual_idx_len != pack_ref.idx_length {
            return Err(GitOpsError::InvalidPack("downloaded idx SHA-256 or length mismatch"));
        }
        total_objects = total_objects.saturating_add(objs);
        if total_objects > max_objects {
            return Err(GitOpsError::LimitExceeded("window object count exceeds verifier limit"));
        }

        peak_scratch = peak_scratch.max(dir_size_bytes(lease.dir_path()?));
        let idx_arg = idx_dst.to_string_lossy().into_owned();
        run_git(&repo_dir, &["verify-pack", &idx_arg], GitStdin::Null, deadline).await?;
        run_git(
            &repo_dir,
            &["-c", "pack.writeReverseIndex=false", "index-pack", "--stdin"],
            GitStdin::File(&pack_dst),
            deadline,
        )
        .await?;
        let _ = fs::remove_file(&pack_dst);
        let _ = fs::remove_file(&idx_dst);
        peak_scratch = peak_scratch.max(dir_size_bytes(lease.dir_path()?));
    }

    Ok((repo_dir, total_objects, blob_get_bytes, peak_scratch))
}
