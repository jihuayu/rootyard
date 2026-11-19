//! Stable per-repository cross-process read lease for selected published generations.

use std::{
    ffi::CString,
    fs::{self, File, OpenOptions, Permissions},
    io::Read,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::{Path, PathBuf},
};

use fs2::FileExt;
use uuid::Uuid;

use crate::ci_checkouts::clonekit::manifest::{
    CloneKitError, CloneKitManifest, CloneKitStatus, MAX_MANIFEST_JSON_BYTES, write_atomic_private_file,
};

/// Stable per-repository lock file shared by readers and local generation collection.
pub(super) const READ_LEASE_FILE: &str = ".read.lock";
const PACK_FILE: &str = "clonekit.pack";
const IDX_FILE: &str = "clonekit.idx";
const MANIFEST_FILE: &str = "manifest.json";
const COPY_CAPACITY_HINT: usize = 8 * 1024 * 1024;

/// Shared read lease protecting one verified local generation from cross-process GC.
#[derive(Debug)]
pub struct CloneKitReadLease {
    file: File,
    repository_id: Uuid,
    generation: VerifiedGeneration,
}

impl CloneKitReadLease {
    /// Repository whose selected generation is protected by this lease.
    pub const fn repository_id(&self) -> Uuid {
        self.repository_id
    }

    /// Copy the verified pack through the retained generation directory descriptor.
    ///
    /// The copy is synchronous and bounded by the verified manifest length; the retained
    /// descriptor prevents a fresh path lookup from selecting a replaced generation.
    pub fn copy_pack_to(&self, dest: &Path, expected_len: u64) -> Result<(), CloneKitError> {
        self.generation.copy_artifact_to(PACK_FILE, dest, expected_len, "selected clonekit pack")
    }

    /// Copy the verified idx through the retained generation directory descriptor.
    ///
    /// The copy is synchronous and bounded by the verified manifest length; the retained
    /// descriptor prevents a fresh path lookup from selecting a replaced generation.
    pub fn copy_idx_to(&self, dest: &Path, expected_len: u64) -> Result<(), CloneKitError> {
        self.generation.copy_artifact_to(IDX_FILE, dest, expected_len, "selected clonekit idx")
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

#[derive(Debug)]
pub(super) struct ReadLeaseLock {
    file: File,
    repository_id: Uuid,
}

impl ReadLeaseLock {
    pub(super) fn bind(self, generation: VerifiedGeneration) -> CloneKitReadLease {
        CloneKitReadLease { file: self.file, repository_id: self.repository_id, generation }
    }
}

#[derive(Debug)]
pub(super) struct VerifiedGeneration {
    dir: File,
    dev: u64,
    ino: u64,
}

impl VerifiedGeneration {
    fn open_file(&self, file_name: &str, label: &str) -> Result<File, CloneKitError> {
        self.verify_handle_intact()?;
        let c_name = single_component_name(file_name)?;
        // SAFETY: `self.dir` is a live verified directory descriptor, `c_name` is a valid
        // single-component NUL-terminated string, and `O_NOFOLLOW | O_NONBLOCK` never follows
        // symlinks or blocks on FIFOs.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(CloneKitError::CorruptArtifact(format!(
                "open {label} via retained generation: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `fd` is a fresh non-negative descriptor owned exclusively by the returned file.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn verify_handle_intact(&self) -> Result<(), CloneKitError> {
        let meta = self
            .dir
            .metadata()
            .map_err(|err| CloneKitError::CorruptArtifact(format!("stat retained clonekit generation: {err}")))?;
        if !meta.is_dir() || (meta.dev(), meta.ino()) != (self.dev, self.ino) {
            return Err(CloneKitError::CorruptArtifact(
                "retained clonekit generation directory identity changed".into(),
            ));
        }
        Ok(())
    }

    fn read_manifest(&self) -> Result<Vec<u8>, CloneKitError> {
        let file = self.open_file(MANIFEST_FILE, "selected clonekit manifest")?;
        let meta = file
            .metadata()
            .map_err(|err| CloneKitError::CorruptArtifact(format!("stat selected clonekit manifest: {err}")))?;
        if !meta.is_file() || meta.len() > MAX_MANIFEST_JSON_BYTES as u64 {
            return Err(CloneKitError::CorruptArtifact(
                "selected clonekit manifest is not a bounded regular file".into(),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_MANIFEST_JSON_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|err| CloneKitError::CorruptArtifact(format!("read selected clonekit manifest: {err}")))?;
        if bytes.len() > MAX_MANIFEST_JSON_BYTES {
            return Err(CloneKitError::CorruptArtifact("selected clonekit manifest exceeds the size cap".into()));
        }
        Ok(bytes)
    }

    fn verify_artifact_length(&self, file_name: &str, expected_len: u64, label: &str) -> Result<(), CloneKitError> {
        let file = self.open_file(file_name, label)?;
        let meta = file.metadata().map_err(|err| CloneKitError::CorruptArtifact(format!("stat {label}: {err}")))?;
        if !meta.is_file() || meta.len() != expected_len {
            return Err(CloneKitError::CorruptArtifact(format!("{label} is not the expected regular file")));
        }
        Ok(())
    }

    fn copy_artifact_to(
        &self,
        file_name: &str,
        dest: &Path,
        expected_len: u64,
        label: &str,
    ) -> Result<(), CloneKitError> {
        let file = self.open_file(file_name, label)?;
        let meta = file.metadata().map_err(|err| CloneKitError::CorruptArtifact(format!("stat {label}: {err}")))?;
        if !meta.is_file() || meta.len() != expected_len {
            return Err(CloneKitError::CorruptArtifact(format!("{label} is not the expected regular file")));
        }
        let capacity = usize::try_from(expected_len).unwrap_or_default().min(COPY_CAPACITY_HINT);
        let mut bytes = Vec::with_capacity(capacity);
        file.take(expected_len.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|err| CloneKitError::CorruptArtifact(format!("read {label}: {err}")))?;
        if bytes.len() as u64 != expected_len {
            return Err(CloneKitError::CorruptArtifact(format!("{label} changed length while copying")));
        }
        write_atomic_private_file(dest, &bytes)
    }
}

fn single_component_name(file_name: &str) -> Result<CString, CloneKitError> {
    let mut components = Path::new(file_name).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(_)), None) => {}
        _ => return Err(CloneKitError::CorruptArtifact("non-local clonekit generation filename".into())),
    }
    if file_name.contains('/') || file_name.contains('\\') || file_name.contains('\0') {
        return Err(CloneKitError::CorruptArtifact("invalid separator in clonekit generation filename".into()));
    }
    CString::new(file_name).map_err(|_| CloneKitError::CorruptArtifact("nul byte in clonekit filename".into()))
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

pub(super) fn acquire_shared(repo_dir: &Path, repository_id: Uuid) -> Result<ReadLeaseLock, CloneKitError> {
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
    Ok(ReadLeaseLock { file, repository_id })
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

pub(super) fn verify_generation(
    version_dir: &Path,
    manifest: &CloneKitManifest,
) -> Result<VerifiedGeneration, CloneKitError> {
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
    let generation = VerifiedGeneration { dir: dir_file, dev: opened_meta.dev(), ino: opened_meta.ino() };
    let bytes = generation.read_manifest()?;
    let installed = CloneKitManifest::from_verified_json(&bytes)?;
    if installed != *manifest {
        return Err(CloneKitError::CorruptArtifact(
            "selected generation manifest differs from the current pointer".into(),
        ));
    }
    if manifest.status == CloneKitStatus::Active {
        let pack = manifest.pack.as_ref().ok_or(CloneKitError::MissingKit)?;
        let idx = manifest.idx.as_ref().ok_or(CloneKitError::MissingKit)?;
        generation.verify_artifact_length(PACK_FILE, pack.length, "selected clonekit pack")?;
        generation.verify_artifact_length(IDX_FILE, idx.length, "selected clonekit idx")?;
    }
    let after = fs::symlink_metadata(version_dir)
        .map_err(|err| CloneKitError::CorruptArtifact(format!("selected clonekit generation vanished: {err}")))?;
    if after.file_type().is_symlink()
        || !after.is_dir()
        || (after.dev(), after.ino()) != (generation.dev, generation.ino())
    {
        return Err(CloneKitError::CorruptArtifact("selected clonekit generation changed during verification".into()));
    }
    Ok(generation)
}
