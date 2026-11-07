//! Authorized, bounded export of job logs and artifacts.
//!
//! Logs are an ordinary product feature and remain readable while a job is
//! running. Artifacts are immutable results and are only exported after the job
//! has a terminal state.
use crate::{AppState, Error};
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt, fs::OpenOptionsExt, fs::PermissionsExt},
    },
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub(super) const LOG_LIMIT: u64 = 16 * 1024 * 1024;
pub(super) const ARTIFACT_LIMIT: u64 = 16 * 1024 * 1024;

/// Read at most `limit` bytes from a regular log file without following
/// symlinks or blocking on a special file. A missing file is an ordinary state
/// after retention cleanup, not an internal error.
pub(super) fn read_log(path: &Path, limit: u64) -> Result<Option<(Vec<u8>, bool)>, Error> {
    let file = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::internal(error)),
    };
    if !file.metadata().map_err(Error::internal)?.is_file() {
        return Err(Error::not_found());
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).map_err(Error::internal)?;
    let truncated = bytes.len() as u64 > limit;
    bytes.truncate(limit as usize);
    Ok(Some((bytes, truncated)))
}

pub(super) fn logs(root: &Path, limit: u64) -> Result<Value, Error> {
    let stdout = read_log(&root.join("stdout.log"), limit)?;
    let stderr = read_log(&root.join("stderr.log"), limit)?;
    if stdout.is_none() && stderr.is_none() {
        return Err(Error::not_found());
    }
    let (stdout, stdout_truncated) = stdout.unwrap_or_default();
    let (stderr, stderr_truncated) = stderr.unwrap_or_default();
    Ok(json!({
        "stdout_base64": STANDARD.encode(stdout),
        "stderr_base64": STANDARD.encode(stderr),
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "log_limit_bytes": limit,
    }))
}

/// Artifacts are exported from a dedicated per-job directory mounting only the
/// terminal job root. Jobs may not use it to reach the service filesystem:
/// every open resolves beneath the directory with symlinks and magic links
/// denied.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn artifact_file(root: &Path, relative: &str) -> Result<File, Error> {
    let path = crate::browse::models::normalize_rel_path(Some(relative))?;
    if path.is_empty() || path != relative {
        return Err(Error::bad_request());
    }
    let name = CString::new(path).map_err(|_| Error::bad_request())?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)
        .map_err(|_| Error::not_found())?;
    // RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS.
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: 0x08 | 0x04 | 0x02,
    };
    let fd = unsafe {
        libc::syscall(libc::SYS_openat2, dir.as_raw_fd(), name.as_ptr(), &how, std::mem::size_of::<OpenHow>())
    };
    if fd < 0 {
        return Err(Error::not_found());
    }
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

pub(super) fn artifact(root: &Path, relative: &str) -> Result<Value, Error> {
    let file = artifact_file(root, relative)?;
    let meta = file.metadata().map_err(Error::internal)?;
    if !meta.is_file() {
        return Err(Error::not_found());
    }
    if meta.len() > ARTIFACT_LIMIT {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "artifact too large"));
    }
    let mut bytes = Vec::new();
    file.take(ARTIFACT_LIMIT + 1).read_to_end(&mut bytes).map_err(Error::internal)?;
    if bytes.len() as u64 > ARTIFACT_LIMIT {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "artifact too large"));
    }
    Ok(json!({
        "path": relative,
        "size": bytes.len(),
        "sha256": hex::encode(Sha256::digest(&bytes)),
        "content_base64": STANDARD.encode(bytes),
    }))
}

/// Artifacts are immutable results: export requires a terminal state and no
/// live process. Live logs are handled separately by `logs`.
pub(super) async fn require_terminal(state: &AppState, id: Uuid) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt("SELECT state,pid FROM sandbox_jobs WHERE id=$1", &[&id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let status: String = row.get(0);
    if !matches!(status.as_str(), "succeeded" | "failed" | "timed_out" | "cancelled")
        || row.get::<_, Option<i32>>(1).is_some()
    {
        return Err(Error(StatusCode::CONFLICT, "sandbox job is still running"));
    }
    Ok(())
}

/// Remove a completed job root. Transient workspace and checkout copies are
/// already reclaimed at terminal time; this removes the bounded logs and
/// artifacts too when the caller no longer needs them.
pub(super) fn remove_job_root(root: &Path) -> Result<bool, Error> {
    match fs::remove_dir_all(root) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::internal(error)),
    }
}

/// A deployment-provisioned artifact pool. In production cgroup mode this is
/// mandatory and must be a size-bounded tmpfs/ramfs mount owned by the service,
/// so the aggregate export store cannot exhaust the general host disk.
pub(super) fn configured_pool() -> Option<PathBuf> {
    std::env::var_os("ROOTYARD_SANDBOX_ARTIFACTS_POOL").filter(|value| !value.is_empty()).map(PathBuf::from)
}

fn pool_limit() -> Result<u64, Error> {
    let value = std::env::var("ROOTYARD_SANDBOX_ARTIFACTS_POOL_MAX_BYTES")
        .ok()
        .map(|raw| raw.parse::<u64>().map_err(|_| Error::internal("invalid artifact pool size")))
        .transpose()?
        .unwrap_or(256 * 1024 * 1024);
    if !(1024 * 1024..=64 << 30).contains(&value) {
        return Err(Error::internal("artifact pool size out of range"));
    }
    Ok(value)
}

fn unescape_mountinfo(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let digits = std::str::from_utf8(&bytes[index + 1..index + 4]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(digits, 8) {
                out.push(byte);
                index += 4;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn mount_filesystem(target: &Path) -> Result<(String, u64), Error> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").map_err(Error::internal)?;
    let mut best: Option<(usize, String)> = None;
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else { continue };
        let fields: Vec<&str> = left.split_whitespace().collect();
        let (Some(mount), Some(fstype)) = (fields.get(4), right.split_whitespace().next()) else { continue };
        let mount = PathBuf::from(unescape_mountinfo(mount));
        if target.starts_with(&mount) {
            let length = mount.as_os_str().as_bytes().len();
            if best.as_ref().is_none_or(|(best_length, _)| length >= *best_length) {
                best = Some((length, fstype.to_owned()));
            }
        }
    }
    let (_, fstype) = best.ok_or_else(|| Error::internal("artifact pool mount not found"))?;
    let name = CString::new(target.as_os_str().as_bytes()).map_err(Error::internal)?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    if unsafe { libc::statvfs(name.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(Error::internal(std::io::Error::last_os_error()));
    }
    let stat = unsafe { stat.assume_init() };
    // `statvfs` reports 64-bit `f_frsize`/`f_blocks` on the supported 64-bit
    // Linux targets; 32-bit targets are not supported by this crate.
    let block: u64 = if stat.f_frsize > 0 { stat.f_frsize } else { stat.f_bsize };
    Ok((fstype, stat.f_blocks.saturating_mul(block)))
}

/// Validate the operator-provisioned export pool before any job starts. A
/// normal host directory (even one with a soft quota walker) is rejected in
/// cgroup mode: the aggregate artifact bound must be kernel-backed.
pub(super) fn verify_pool() -> Result<PathBuf, Error> {
    let configured = configured_pool().ok_or_else(|| Error::internal("bounded artifact tmpfs pool required"))?;
    if !configured.is_absolute() {
        return Err(Error::internal("artifact pool must be an absolute path"));
    }
    let metadata = fs::symlink_metadata(&configured).map_err(Error::internal)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::internal("artifact pool must be a real directory"));
    }
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(Error::internal("artifact pool must be service-owned with no group/world access"));
    }
    let canonical = fs::canonicalize(&configured).map_err(Error::internal)?;
    let (fstype, total_bytes) = mount_filesystem(&canonical)?;
    if fstype != "tmpfs" {
        return Err(Error::internal(
            "artifact pool must be a tmpfs mount with a kernel size bound (ramfs has no accounting)",
        ));
    }
    let limit = pool_limit()?;
    if total_bytes == 0 {
        return Err(Error::internal("artifact pool mount reports no capacity"));
    }
    if total_bytes > limit {
        return Err(Error::internal("artifact pool mount is larger than the configured bound"));
    }
    Ok(canonical)
}

/// Create the per-job export directory inside the validated pool. The job only
/// ever sees its own directory through a dedicated bind mount.
pub(super) fn job_pool_dir(pool: &Path, job: Uuid) -> Result<PathBuf, Error> {
    let directory = pool.join(job.to_string());
    fs::create_dir(&directory).map_err(Error::internal)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(Error::internal)?;
    Ok(directory)
}
