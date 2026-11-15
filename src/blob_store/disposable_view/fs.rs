//! Private `0o700` directory and bounded `lease.json` OS filesystem helpers for
//! [`super::DisposableViewRoot`].

use std::{
    fs::{DirBuilder, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    DisposableViewError, LEASE_FILE_NAME, MAX_LEASE_JSON_BYTES, MAX_PURPOSE_BYTES, REPO_SUBDIR_NAME, VIEW_LEASE_SCHEMA,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ViewLeaseRecord {
    pub(super) schema: u32,
    pub(super) view_id: Uuid,
    pub(super) purpose: String,
    pub(super) tenant_id: Uuid,
    pub(super) authority_id: Uuid,
    pub(super) reserved_bytes: u64,
    pub(super) pid: u32,
    pub(super) expires_at_unix_ms: u64,
}

pub(super) fn init_view_dirs(
    root_dir: &Path,
    view_id: Uuid,
    dir_path: &Path,
    record: &ViewLeaseRecord,
) -> Result<(), DisposableViewError> {
    let staging_dir = root_dir.join(format!(".staging-{}", view_id.simple()));
    DirBuilder::new()
        .mode(0o700)
        .create(&staging_dir)
        .map_err(|_| DisposableViewError::Io("failed creating disposable staging directory"))?;
    let init_res = (|| -> Result<(), DisposableViewError> {
        verify_private_dir(&staging_dir)?;

        let repo_dir = staging_dir.join(REPO_SUBDIR_NAME);
        DirBuilder::new()
            .mode(0o700)
            .create(&repo_dir)
            .map_err(|_| DisposableViewError::Io("failed creating disposable repo directory"))?;
        verify_private_dir(&repo_dir)?;

        let encoded = serde_json::to_vec(record).map_err(|_| DisposableViewError::Io("failed encoding view lease"))?;
        let lease_path = staging_dir.join(LEASE_FILE_NAME);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lease_path)
            .map_err(|_| DisposableViewError::Io("failed creating view lease file"))?;
        file.write_all(&encoded).map_err(|_| DisposableViewError::Io("failed writing view lease file"))?;
        file.sync_all().map_err(|_| DisposableViewError::Io("failed syncing view lease file"))?;
        std::fs::rename(&staging_dir, dir_path)
            .map_err(|_| DisposableViewError::Io("failed publishing disposable view directory"))?;
        Ok(())
    })();
    if init_res.is_err() {
        let _ = std::fs::remove_dir_all(&staging_dir);
    }
    init_res
}

pub(super) fn ensure_private_dir(dir: &Path) -> Result<(), DisposableViewError> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => verify_private_dir(dir),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => verify_private_dir(dir),
        Err(_) => Err(DisposableViewError::Io("failed preparing private view root directory")),
    }
}

pub(super) fn verify_private_dir(path: &Path) -> Result<(), DisposableViewError> {
    let meta = std::fs::symlink_metadata(path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            DisposableViewError::Io("view directory missing")
        } else {
            DisposableViewError::Io("failed inspecting view directory")
        }
    })?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(DisposableViewError::UnsafePath("view path must be a real directory"));
    }
    // SAFETY: `geteuid` takes no arguments and reads this process's effective uid.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(DisposableViewError::UnsafePath("view directory owner mismatch"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(DisposableViewError::UnsafePath("view directory permits group or world access"));
    }
    Ok(())
}

pub(super) fn read_lease_record(path: &Path) -> Result<ViewLeaseRecord, DisposableViewError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| DisposableViewError::Io("failed opening view lease"))?;
    let meta = file.metadata().map_err(|_| DisposableViewError::Io("failed inspecting view lease"))?;
    if !meta.is_file() || meta.len() > MAX_LEASE_JSON_BYTES {
        return Err(DisposableViewError::UnsafePath("invalid view lease file"));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.read_to_end(&mut bytes).map_err(|_| DisposableViewError::Io("failed reading view lease"))?;
    let record: ViewLeaseRecord =
        serde_json::from_slice(&bytes).map_err(|_| DisposableViewError::InvalidArgument("malformed view lease"))?;
    if record.schema != VIEW_LEASE_SCHEMA {
        return Err(DisposableViewError::InvalidArgument("unsupported view lease schema"));
    }
    Ok(record)
}

pub(super) fn remove_view_dir_safely(dir: &Path) -> Result<bool, DisposableViewError> {
    match std::fs::symlink_metadata(dir) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(DisposableViewError::Io("failed inspecting expired view directory")),
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(DisposableViewError::UnsafePath("refusing to descend non-directory or symlink view"));
            }
            std::fs::remove_dir_all(dir).map_err(|_| DisposableViewError::Io("failed removing disposable view"))?;
            Ok(true)
        }
    }
}

pub(super) fn validate_purpose(purpose: &str) -> Result<(), DisposableViewError> {
    let valid = !purpose.is_empty()
        && purpose.len() <= MAX_PURPOSE_BYTES
        && purpose.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && purpose.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !valid {
        return Err(DisposableViewError::InvalidArgument("invalid disposable view purpose"));
    }
    Ok(())
}

pub(super) fn unix_ms_now() -> Result<u64, DisposableViewError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DisposableViewError::Io("system clock is before UNIX epoch"))?;
    Ok(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}
