//! Stable per-repository cross-process read lease for selected published generations.

use std::{
    fs::{self, File, OpenOptions, Permissions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use uuid::Uuid;

use super::read_regular_file;
use crate::ci_checkouts::clonekit::manifest::{
    CloneKitError, CloneKitManifest, CloneKitStatus, MAX_MANIFEST_JSON_BYTES,
};

/// Stable per-repository lock file shared by readers and local generation collection.
pub(super) const READ_LEASE_FILE: &str = ".read.lock";
const PACK_FILE: &str = "clonekit.pack";
const IDX_FILE: &str = "clonekit.idx";
const MANIFEST_FILE: &str = "manifest.json";

/// Shared read lease protecting one verified local generation from cross-process GC.
#[derive(Debug)]
pub struct CloneKitReadLease {
    file: File,
    repository_id: Uuid,
}

impl CloneKitReadLease {
    /// Repository whose selected generation is protected by this lease.
    pub const fn repository_id(&self) -> Uuid {
        self.repository_id
    }
}

impl Drop for CloneKitReadLease {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

/// Verified manifest paired with the shared read lease protecting its local generation.
#[derive(Debug)]
pub struct LeasedCloneKitManifest {
    manifest: CloneKitManifest,
    lease: Option<CloneKitReadLease>,
}

impl LeasedCloneKitManifest {
    pub(super) fn new(manifest: CloneKitManifest, lease: CloneKitReadLease) -> Self {
        Self { manifest, lease: Some(lease) }
    }

    /// Verified manifest selected under the read lease.
    pub fn manifest(&self) -> &CloneKitManifest {
        &self.manifest
    }

    /// Split the manifest from its lease; dropping the lease permits later local GC.
    pub fn into_parts(self) -> (CloneKitManifest, Option<CloneKitReadLease>) {
        (self.manifest, self.lease)
    }
}

fn verify_lease_path(path: &Path, file: &File) -> Result<(), CloneKitError> {
    let file_meta =
        file.metadata().map_err(|err| CloneKitError::GitFailed(format!("stat clonekit read lease: {err}")))?;
    if !file_meta.is_file() {
        return Err(CloneKitError::InvalidConfig("clonekit read lease is not a regular file"));
    }
    let path_meta = fs::symlink_metadata(path)
        .map_err(|err| CloneKitError::GitFailed(format!("stat clonekit read lease path: {err}")))?;
    if path_meta.file_type().is_symlink()
        || !path_meta.is_file()
        || (path_meta.dev(), path_meta.ino()) != (file_meta.dev(), file_meta.ino())
    {
        return Err(CloneKitError::CorruptArtifact("clonekit read lease path was replaced during open".into()));
    }
    Ok(())
}

fn open_read_lease(repo_dir: &Path) -> Result<(PathBuf, File), CloneKitError> {
    let path = repo_dir.join(READ_LEASE_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|err| CloneKitError::GitFailed(format!("open clonekit read lease: {err}")))?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|err| CloneKitError::GitFailed(format!("secure clonekit read lease: {err}")))?;
    verify_lease_path(&path, &file)?;
    Ok((path, file))
}

pub(super) fn acquire_shared(repo_dir: &Path, repository_id: Uuid) -> Result<CloneKitReadLease, CloneKitError> {
    let (path, file) = open_read_lease(repo_dir)?;
    match FileExt::try_lock_shared(&file) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
            return Err(CloneKitError::GitFailed(
                "clonekit read lease busy: local generation collection is in progress".into(),
            ));
        }
        Err(err) => return Err(CloneKitError::GitFailed(format!("clonekit read lease failed: {err}"))),
    }
    verify_lease_path(&path, &file)?;
    Ok(CloneKitReadLease { file, repository_id })
}

pub(super) struct ReadLeaseExclusive {
    file: File,
}

impl Drop for ReadLeaseExclusive {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

pub(super) fn acquire_exclusive(repo_dir: &Path) -> Result<ReadLeaseExclusive, CloneKitError> {
    let (path, file) = open_read_lease(repo_dir)?;
    match FileExt::try_lock_exclusive(&file) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
            return Err(CloneKitError::GitFailed(
                "clonekit gc busy: an active read lease protects a local generation".into(),
            ));
        }
        Err(err) => return Err(CloneKitError::GitFailed(format!("clonekit gc read lease failed: {err}"))),
    }
    verify_lease_path(&path, &file)?;
    Ok(ReadLeaseExclusive { file })
}

fn verify_regular_file(path: &Path, expected_len: u64, label: &str) -> Result<(), CloneKitError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|err| CloneKitError::CorruptArtifact(format!("{label} is unavailable: {err}")))?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() != expected_len {
        return Err(CloneKitError::CorruptArtifact(format!("{label} is not the expected regular file")));
    }
    Ok(())
}

pub(super) fn verify_generation(version_dir: &Path, manifest: &CloneKitManifest) -> Result<(), CloneKitError> {
    let dir_meta = fs::symlink_metadata(version_dir)
        .map_err(|err| CloneKitError::CorruptArtifact(format!("selected clonekit generation is unavailable: {err}")))?;
    if dir_meta.file_type().is_symlink() || !dir_meta.is_dir() {
        return Err(CloneKitError::CorruptArtifact("selected clonekit generation is not a regular directory".into()));
    }
    let dir_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(version_dir)
        .map_err(|err| CloneKitError::CorruptArtifact(format!("open selected clonekit generation: {err}")))?;
    let opened_meta = dir_file
        .metadata()
        .map_err(|err| CloneKitError::CorruptArtifact(format!("stat selected clonekit generation: {err}")))?;
    if !opened_meta.is_dir() || (opened_meta.dev(), opened_meta.ino()) != (dir_meta.dev(), dir_meta.ino()) {
        return Err(CloneKitError::CorruptArtifact(
            "selected clonekit generation directory changed during open".into(),
        ));
    }
    let bytes = read_regular_file(&version_dir.join(MANIFEST_FILE), MAX_MANIFEST_JSON_BYTES as u64)?;
    let installed = CloneKitManifest::from_verified_json(&bytes)?;
    if installed != *manifest {
        return Err(CloneKitError::CorruptArtifact(
            "selected generation manifest differs from the current pointer".into(),
        ));
    }
    if manifest.status == CloneKitStatus::Active {
        let pack = manifest.pack.as_ref().ok_or(CloneKitError::MissingKit)?;
        let idx = manifest.idx.as_ref().ok_or(CloneKitError::MissingKit)?;
        verify_regular_file(&version_dir.join(PACK_FILE), pack.length, "selected clonekit pack")?;
        verify_regular_file(&version_dir.join(IDX_FILE), idx.length, "selected clonekit idx")?;
    }
    let after = fs::symlink_metadata(version_dir)
        .map_err(|err| CloneKitError::CorruptArtifact(format!("selected clonekit generation vanished: {err}")))?;
    if after.file_type().is_symlink()
        || !after.is_dir()
        || (after.dev(), after.ino()) != (dir_meta.dev(), dir_meta.ino())
    {
        return Err(CloneKitError::CorruptArtifact("selected clonekit generation changed during verification".into()));
    }
    Ok(())
}
