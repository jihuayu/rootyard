//! Private verified-generation preparation and fenced whole-directory CloneKit publication.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions, Permissions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use fs2::FileExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    BuildFailurePoint, BuiltCloneKitArtifacts, RetentionPinLedger, copy_private_file, read_lease, read_regular_file,
    sync_dir, verify_idx_in_ephemeral_repo, verify_prepared_artifact, write_private_file,
};
use crate::ci_checkouts::clonekit::manifest::{
    CloneKitError, CloneKitManifest, CloneKitStatus, MAX_MANIFEST_JSON_BYTES, ensure_not_cancelled, ensure_private_dir,
};

#[path = "publication_read.rs"]
mod read;

const REPOSITORY_PREFIX: &str = "repo-";
const ATTEMPT_PREFIX: &str = ".publish-";
const GENERATION_PREFIX: &str = "gen-";
const PACK_FILE: &str = "clonekit.pack";
const IDX_FILE: &str = "clonekit.idx";
const MANIFEST_FILE: &str = "manifest.json";
const CURRENT_FILE: &str = "current.json";
const PUBLICATION_LOCK_FILE: &str = ".publication.lock";
const CP_BEFORE_LOCK: &str = "before-lock";
const CP_AFTER_LOCK: &str = "after-lock";
const CP_BEFORE_INSTALL: &str = "before-install";
const CP_AFTER_INSTALL: &str = "after-install";
const CP_BEFORE_POINTER: &str = "before-pointer";
const CP_AFTER_POINTER: &str = "after-pointer";

/// Atomic versioned disk catalog storing published CloneKit generations and active pointer.
#[derive(Clone, Debug)]
pub struct CloneKitPublicationStore {
    root_dir: PathBuf,
}

impl CloneKitPublicationStore {
    /// Open or initialize a `0o700` publication catalog root directory.
    pub fn open(root_dir: &Path) -> Result<Self, CloneKitError> {
        let existed = fs::symlink_metadata(root_dir).is_ok();
        ensure_private_dir(root_dir)?;
        if !existed && let Some(parent) = root_dir.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            sync_dir(parent)?;
        }
        Ok(Self { root_dir: root_dir.to_path_buf() })
    }

    fn repo_dir(&self, repo_id: Uuid) -> PathBuf {
        self.root_dir.join(format!("{REPOSITORY_PREFIX}{}", repo_id.simple()))
    }

    fn current_pointer_path(&self, repo_id: Uuid) -> PathBuf {
        self.repo_dir(repo_id).join(CURRENT_FILE)
    }

    /// Directory containing generation `kit_generation` bytes for `repo_id`.
    pub fn version_dir(&self, repo_id: Uuid, kit_generation: u64) -> PathBuf {
        self.repo_dir(repo_id).join(format!("{GENERATION_PREFIX}{kit_generation:08}"))
    }

    /// Load the latest verified published manifest for `repo_id`, if any.
    ///
    /// This lock-free read preserves existing callers. Callers that consume local generation
    /// bytes must use [`Self::load_latest_leased`] so local GC cannot remove the selected
    /// generation before the read completes.
    pub fn load_latest(&self, repo_id: Uuid) -> Result<Option<CloneKitManifest>, CloneKitError> {
        let bytes = match fs::read(self.current_pointer_path(repo_id)) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(CloneKitError::CorruptArtifact(format!("read latest manifest: {err}"))),
        };
        Ok(Some(CloneKitManifest::from_verified_json(&bytes)?))
    }

    /// Return `(pack_path, idx_path)` for a published generation.
    pub fn artifact_paths(&self, repo_id: Uuid, kit_generation: u64) -> (PathBuf, PathBuf) {
        let vdir = self.version_dir(repo_id, kit_generation);
        (vdir.join(PACK_FILE), vdir.join(IDX_FILE))
    }

    /// Garbage-collect one superseded generation ONLY if unpinned and strictly older than current.
    pub fn try_gc_generation(
        &self,
        repo_id: Uuid,
        kit_generation: u64,
        ledger: &RetentionPinLedger,
    ) -> Result<bool, CloneKitError> {
        match fs::symlink_metadata(self.repo_dir(repo_id)) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(CloneKitError::GitFailed(format!("stat publication repository: {err}"))),
            Ok(_) => {}
        }
        let _guard = self.acquire_publication_lock(repo_id)?;
        let Some(latest) = self.read_current_locked(repo_id)? else {
            return Ok(false);
        };
        if kit_generation == latest.kit_generation {
            return Err(CloneKitError::PinProtectionActive(latest.retention_pin_id.unwrap_or(repo_id)));
        }
        if kit_generation > latest.kit_generation {
            return Ok(false);
        }
        let _read_lease = read_lease::acquire_exclusive(&self.repo_dir(repo_id))?;
        let dir = self.version_dir(repo_id, kit_generation);
        ledger.with_unpinned_generation(repo_id, kit_generation, || match fs::symlink_metadata(&dir) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(CloneKitError::GitFailed(format!("stat old kit generation: {err}"))),
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                Err(CloneKitError::CorruptArtifact("old kit generation is not a regular directory".into()))
            }
            Ok(_) => {
                fs::remove_dir_all(&dir).map_err(|err| CloneKitError::GitFailed(format!("remove old kit: {err}")))?;
                Ok(true)
            }
        })
    }

    fn ensure_repo_dir(&self, repo_id: Uuid) -> Result<PathBuf, CloneKitError> {
        let repo_dir = self.repo_dir(repo_id);
        let existed = fs::symlink_metadata(&repo_dir).is_ok();
        ensure_private_dir(&repo_dir)?;
        if !existed {
            sync_dir(&self.root_dir)?;
        }
        Ok(repo_dir)
    }

    fn acquire_publication_lock(&self, repo_id: Uuid) -> Result<PublicationGuard, CloneKitError> {
        let repo_dir = self.ensure_repo_dir(repo_id)?;
        let path = repo_dir.join(PUBLICATION_LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|err| CloneKitError::GitFailed(format!("open publication lock: {err}")))?;
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(|err| CloneKitError::GitFailed(format!("secure publication lock: {err}")))?;
        if !file
            .metadata()
            .map_err(|err| CloneKitError::GitFailed(format!("stat publication lock: {err}")))?
            .file_type()
            .is_file()
        {
            return Err(CloneKitError::InvalidConfig("publication lock is not a regular file"));
        }
        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(PublicationGuard { _file: file }),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Err(CloneKitError::GitFailed(
                "clonekit publication busy: another process holds the repository publication lock".into(),
            )),
            Err(err) => Err(CloneKitError::GitFailed(format!("publication lock failed: {err}"))),
        }
    }

    fn read_current_locked(&self, repo_id: Uuid) -> Result<Option<CloneKitManifest>, CloneKitError> {
        let path = self.current_pointer_path(repo_id);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(CloneKitError::GitFailed(format!("stat current pointer: {err}"))),
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(CloneKitError::CorruptArtifact("current pointer is not a regular file".into()));
        }
        let bytes = read_regular_file(&path, MAX_MANIFEST_JSON_BYTES as u64)?;
        let manifest = CloneKitManifest::from_verified_json(&bytes)?;
        if manifest.repository_id != repo_id {
            return Err(CloneKitError::CorruptArtifact("current pointer repository identity mismatch".into()));
        }
        Ok(Some(manifest))
    }

    fn validate_existing_generation(&self, vdir: &Path, candidate: &CloneKitManifest) -> Result<(), CloneKitError> {
        let bytes = read_regular_file(&vdir.join(MANIFEST_FILE), MAX_MANIFEST_JSON_BYTES as u64)?;
        let existing = CloneKitManifest::from_verified_json(&bytes)?;
        if existing != *candidate {
            return Err(CloneKitError::CorruptArtifact(
                "existing generation conflicts with candidate; refusing recovery".into(),
            ));
        }
        let mut expected: BTreeSet<&str> = BTreeSet::new();
        expected.insert(MANIFEST_FILE);
        if candidate.status == CloneKitStatus::Active {
            expected.insert(PACK_FILE);
            expected.insert(IDX_FILE);
            let pack = candidate.pack.as_ref().ok_or(CloneKitError::MissingKit)?;
            let idx = candidate.idx.as_ref().ok_or(CloneKitError::MissingKit)?;
            verify_prepared_artifact(&vdir.join(PACK_FILE), &pack.sha256, pack.length)?;
            verify_prepared_artifact(&vdir.join(IDX_FILE), &idx.sha256, idx.length)?;
        }
        for entry in fs::read_dir(vdir)
            .map_err(|err| CloneKitError::CorruptArtifact(format!("read existing generation: {err}")))?
        {
            let entry = entry.map_err(|err| CloneKitError::CorruptArtifact(format!("read generation entry: {err}")))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(CloneKitError::CorruptArtifact("existing generation has a non-UTF-8 entry".into()));
            };
            if !expected.contains(name) {
                return Err(CloneKitError::CorruptArtifact(
                    "existing generation has unexpected entries; refusing recovery".into(),
                ));
            }
        }
        Ok(())
    }

    fn install_or_recover(
        &self,
        prepared: &mut PreparedGeneration,
        cancel: Option<&CancellationToken>,
    ) -> Result<(), CloneKitError> {
        let repo_id = prepared.manifest.repository_id;
        let vdir = self.version_dir(repo_id, prepared.manifest.kit_generation);
        match fs::symlink_metadata(&vdir) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                checkpoint(CP_BEFORE_INSTALL)?;
                ensure_not_cancelled(cancel)?;
                fs::rename(&prepared.attempt_dir, &vdir)
                    .map_err(|err| CloneKitError::GitFailed(format!("install prepared generation: {err}")))?;
                prepared.committed = true;
                sync_dir(&self.repo_dir(repo_id))
            }
            Err(err) => Err(CloneKitError::GitFailed(format!("stat destination generation: {err}"))),
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    return Err(CloneKitError::CorruptArtifact(
                        "destination generation is not a regular directory".into(),
                    ));
                }
                self.validate_existing_generation(&vdir, &prepared.manifest)
            }
        }
    }

    fn commit_prepared(
        &self,
        prepared: PreparedGeneration,
        cancel: Option<&CancellationToken>,
    ) -> Result<CloneKitManifest, CloneKitError> {
        let mut prepared = prepared;
        let repo_id = prepared.manifest.repository_id;
        let current = self.read_current_locked(repo_id)?;
        if let Some(current) = current {
            if current.kit_generation == u64::MAX {
                return Err(generation_exhausted());
            }
            if prepared.manifest.kit_generation <= current.kit_generation {
                return Err(stale_generation(current.kit_generation, prepared.manifest.kit_generation));
            }
        }
        checkpoint(CP_AFTER_LOCK)?;
        ensure_not_cancelled(cancel)?;
        self.install_or_recover(&mut prepared, cancel)?;
        checkpoint(CP_AFTER_INSTALL)?;
        let repo_dir = self.ensure_repo_dir(repo_id)?;
        let mut staged = StagedCurrent::create(&repo_dir)?;
        staged.write_and_sync(&prepared.encoded)?;
        checkpoint(CP_BEFORE_POINTER)?;
        ensure_not_cancelled(cancel)?;
        staged.publish(&repo_dir.join(CURRENT_FILE))?;
        if checkpoint(CP_AFTER_POINTER).is_err() {
            return Err(uncertain_publication_error(self, repo_id, &prepared.manifest));
        }
        if sync_dir(&repo_dir).is_err() {
            return Err(uncertain_publication_error(self, repo_id, &prepared.manifest));
        }
        Ok(prepared.manifest.clone())
    }
}

#[derive(Debug)]
struct PublicationGuard {
    _file: File,
}

struct OwnedAttempt {
    path: PathBuf,
    armed: bool,
}

impl OwnedAttempt {
    fn create(repo_dir: &Path) -> Result<Self, CloneKitError> {
        let path = repo_dir.join(format!("{ATTEMPT_PREFIX}{}", Uuid::new_v4().simple()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|err| CloneKitError::GitFailed(format!("create publication attempt: {err}")))?;
        ensure_private_dir(&path)?;
        Ok(Self { path, armed: true })
    }

    fn into_prepared(mut self, manifest: CloneKitManifest, encoded: Vec<u8>) -> PreparedGeneration {
        self.armed = false;
        PreparedGeneration { attempt_dir: self.path.clone(), manifest, encoded, committed: false }
    }
}

impl Drop for OwnedAttempt {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

struct PreparedGeneration {
    attempt_dir: PathBuf,
    manifest: CloneKitManifest,
    encoded: Vec<u8>,
    committed: bool,
}

impl PreparedGeneration {
    fn prepare(
        store: &CloneKitPublicationStore,
        built: &BuiltCloneKitArtifacts,
        git_binary: &Path,
        cancel: Option<&CancellationToken>,
    ) -> Result<Self, CloneKitError> {
        ensure_not_cancelled(cancel)?;
        built.manifest.verify_integrity()?;
        let repo_dir = store.ensure_repo_dir(built.manifest.repository_id)?;
        let attempt = OwnedAttempt::create(&repo_dir)?;
        let manifest = built.manifest.clone();
        let encoded =
            serde_json::to_vec_pretty(&manifest).map_err(|err| CloneKitError::CorruptArtifact(err.to_string()))?;

        if manifest.status == CloneKitStatus::Active {
            let (Some(pack_src), Some(idx_src)) = (&built.staged_pack_path, &built.staged_idx_path) else {
                return Err(CloneKitError::InvalidInput("active kit publish missing staged files"));
            };
            let pack = manifest.pack.as_ref().ok_or(CloneKitError::MissingKit)?;
            let idx = manifest.idx.as_ref().ok_or(CloneKitError::MissingKit)?;
            let dest_pack = attempt.path.join(PACK_FILE);
            let dest_idx = attempt.path.join(IDX_FILE);
            copy_private_file(pack_src, &dest_pack)?;
            copy_private_file(idx_src, &dest_idx)?;
            verify_prepared_artifact(&dest_pack, &pack.sha256, pack.length)?;
            verify_prepared_artifact(&dest_idx, &idx.sha256, idx.length)?;
            verify_idx_in_ephemeral_repo(git_binary, &attempt.path, manifest.object_format, &dest_idx, cancel)?;
        }

        write_private_file(&attempt.path.join(MANIFEST_FILE), &encoded)?;
        sync_dir(&attempt.path)?;
        ensure_not_cancelled(cancel)?;
        Ok(attempt.into_prepared(manifest, encoded))
    }
}

impl Drop for PreparedGeneration {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.attempt_dir);
        }
    }
}

struct StagedCurrent {
    path: PathBuf,
    file: File,
    armed: bool,
}

impl StagedCurrent {
    fn create(repo_dir: &Path) -> Result<Self, CloneKitError> {
        let path = repo_dir.join(format!(".current-{}", Uuid::new_v4().simple()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|err| CloneKitError::GitFailed(format!("create staged current pointer: {err}")))?;
        Ok(Self { path, file, armed: true })
    }

    fn write_and_sync(&mut self, bytes: &[u8]) -> Result<(), CloneKitError> {
        self.file
            .write_all(bytes)
            .and_then(|()| self.file.sync_all())
            .map_err(|err| CloneKitError::GitFailed(format!("write staged current pointer: {err}")))
    }

    fn publish(mut self, dest: &Path) -> Result<(), CloneKitError> {
        fs::rename(&self.path, dest)
            .map_err(|err| CloneKitError::GitFailed(format!("replace current pointer: {err}")))?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for StagedCurrent {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn stale_generation(current: u64, actual: u64) -> CloneKitError {
    match current.checked_add(1) {
        Some(expected_min) => CloneKitError::StaleGeneration { expected_min, actual },
        None => generation_exhausted(),
    }
}

fn generation_exhausted() -> CloneKitError {
    CloneKitError::GitFailed("clonekit generation exhausted: current generation is u64::MAX".into())
}

fn uncertain_publication_error(
    store: &CloneKitPublicationStore,
    repo_id: Uuid,
    expected: &CloneKitManifest,
) -> CloneKitError {
    let candidate_visible = matches!(
        store.load_latest(repo_id),
        Ok(Some(manifest))
            if manifest.kit_generation == expected.kit_generation
                && manifest.manifest_sha256 == expected.manifest_sha256
    );
    let detail = if candidate_visible {
        "clonekit publication outcome uncertain: current pointer rename completed but repository directory sync failed; candidate is visible but crash durability is unconfirmed"
    } else {
        "clonekit publication outcome uncertain: current pointer rename completed but repository directory sync failed; visible current generation is unconfirmed"
    };
    CloneKitError::GitFailed(detail.into())
}

/// Atomically publish built artifacts as the latest kit only after full destination verification.
pub fn publish_clonekit_versioned(
    store: &CloneKitPublicationStore,
    built: &BuiltCloneKitArtifacts,
    git_binary: &Path,
    inject_failure: Option<BuildFailurePoint>,
    cancel: Option<&CancellationToken>,
) -> Result<CloneKitManifest, CloneKitError> {
    ensure_not_cancelled(cancel)?;
    built.manifest.verify_integrity()?;
    if inject_failure == Some(BuildFailurePoint::AfterUploadBeforePublish) {
        return Err(CloneKitError::GitFailed("injected failure before atomic catalog publish".into()));
    }
    let prepared = PreparedGeneration::prepare(store, built, git_binary, cancel)?;
    ensure_not_cancelled(cancel)?;
    checkpoint(CP_BEFORE_LOCK)?;
    let _guard = store.acquire_publication_lock(built.manifest.repository_id)?;
    store.commit_prepared(prepared, cancel)
}

#[cfg(test)]
#[path = "publication_test_seam.rs"]
mod test_seam;

#[cfg(test)]
fn checkpoint(name: &'static str) -> Result<(), CloneKitError> {
    test_seam::checkpoint(name)
}

#[cfg(not(test))]
#[inline(always)]
fn checkpoint(_name: &'static str) -> Result<(), CloneKitError> {
    Ok(())
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod publication_tests;

#[cfg(test)]
#[path = "publication_race_tests.rs"]
mod publication_race_tests;

#[cfg(test)]
#[path = "publication_barrier_tests.rs"]
mod publication_barrier_tests;

#[cfg(test)]
#[path = "publication_active_race_tests.rs"]
mod publication_active_race_tests;

#[cfg(test)]
#[path = "publication_read_lease_tests.rs"]
mod publication_read_lease_tests;
