//! Private verified-generation preparation and whole-directory CloneKit publication.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{BuildFailurePoint, BuiltCloneKitArtifacts, RetentionPinLedger};
use crate::ci_checkouts::clonekit::manifest::{
    CloneKitError, CloneKitManifest, CloneKitObjectFormat, CloneKitStatus, compute_file_sha256,
    ensure_not_cancelled, ensure_private_dir, run_git_command,
};

const REPOSITORY_PREFIX: &str = "repo-";
const ATTEMPT_PREFIX: &str = ".publish-";
const GENERATION_PREFIX: &str = "gen-";
const PACK_FILE: &str = "clonekit.pack";
const IDX_FILE: &str = "clonekit.idx";
const MANIFEST_FILE: &str = "manifest.json";
const CURRENT_FILE: &str = "current.json";

/// Atomic versioned disk catalog storing published CloneKit generations and active pointer.
#[derive(Clone, Debug)]
pub struct CloneKitPublicationStore {
    root_dir: PathBuf,
}

impl CloneKitPublicationStore {
    /// Open or initialize a `0o700` publication catalog root directory.
    pub fn open(root_dir: &Path) -> Result<Self, CloneKitError> {
        ensure_private_dir(root_dir)?;
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
        if let Some(pin) = ledger.active_pin_for(repo_id, kit_generation) {
            return Err(CloneKitError::PinProtectionActive(pin));
        }
        if let Some(latest) = self.load_latest(repo_id)?
            && latest.kit_generation == kit_generation
        {
            return Err(CloneKitError::PinProtectionActive(latest.retention_pin_id.unwrap_or(repo_id)));
        }
        let dir = self.version_dir(repo_id, kit_generation);
        if !dir.exists() {
            return Ok(false);
        }
        fs::remove_dir_all(&dir).map_err(|e| CloneKitError::GitFailed(format!("remove old kit: {e}")))?;
        Ok(true)
    }

    fn ensure_repo_dir(&self, repo_id: Uuid) -> Result<PathBuf, CloneKitError> {
        let repo_dir = self.repo_dir(repo_id);
        ensure_private_dir(&repo_dir)?;
        Ok(repo_dir)
    }

    fn install_prepared(&self, prepared: PreparedGeneration) -> Result<(), CloneKitError> {
        let repo_id = prepared.manifest.repository_id;
        let vdir = self.version_dir(repo_id, prepared.manifest.kit_generation);
        if fs::symlink_metadata(&vdir).is_ok() {
            return Err(CloneKitError::GitFailed(
                "destination generation already exists; exact recovery is not yet available".into(),
            ));
        }
        fs::rename(&prepared.attempt_dir, &vdir)
            .map_err(|e| CloneKitError::GitFailed(format!("install prepared generation: {e}")))?;
        let mut prepared = prepared;
        prepared.committed = true;
        sync_dir(&self.repo_dir(repo_id))?;
        write_current_pointer(&self.current_pointer_path(repo_id), &prepared.encoded)?;
        Ok(())
    }
}

fn sync_dir(path: &Path) -> Result<(), CloneKitError> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|err| CloneKitError::GitFailed(format!("sync clonekit directory: {err}")))
}

fn write_private_file(dest: &Path, bytes: &[u8]) -> Result<(), CloneKitError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dest)
        .map_err(|err| CloneKitError::GitFailed(format!("create prepared clonekit file: {err}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|err| CloneKitError::GitFailed(format!("write prepared clonekit file: {err}")))
}

fn copy_private_file(src: &Path, dest: &Path) -> Result<(), CloneKitError> {
    let mut input = File::open(src)
        .map_err(|err| CloneKitError::CorruptArtifact(format!("open staged clonekit artifact: {err}")))?;
    if !input
        .metadata()
        .map_err(|err| CloneKitError::CorruptArtifact(format!("stat staged clonekit artifact: {err}")))?
        .is_file()
    {
        return Err(CloneKitError::CorruptArtifact("staged clonekit artifact is not a regular file".into()));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dest)
        .map_err(|err| CloneKitError::GitFailed(format!("create prepared clonekit artifact: {err}")))?;
    io::copy(&mut input, &mut output)
        .map_err(|err| CloneKitError::GitFailed(format!("copy prepared clonekit artifact: {err}")))?;
    output
        .sync_all()
        .map_err(|err| CloneKitError::GitFailed(format!("sync prepared clonekit artifact: {err}")))
}

fn verify_prepared_artifact(path: &Path, expected: &str, expected_len: u64) -> Result<(), CloneKitError> {
    let (sha256, length) = compute_file_sha256(path)?;
    if sha256 != expected || length != expected_len {
        return Err(CloneKitError::CorruptArtifact("prepared pack/idx failed digest verification".into()));
    }
    Ok(())
}

fn verify_idx_in_ephemeral_repo(
    git_binary: &Path,
    work_parent: &Path,
    object_format: CloneKitObjectFormat,
    idx_path: &Path,
    cancel: Option<&CancellationToken>,
) -> Result<(), CloneKitError> {
    let idx_str = idx_path.to_str().ok_or(CloneKitError::InvalidInput("non-utf8 idx path"))?;
    let verify_repo = work_parent.join(format!(".verify-repo-{}", Uuid::new_v4().simple()));
    let res = (|| {
        ensure_private_dir(&verify_repo)?;
        run_git_command(
            git_binary,
            Some(&verify_repo),
            &["init", "--bare", "--quiet", object_format.git_init_flag()],
            cancel,
        )?;
        run_git_command(git_binary, Some(&verify_repo), &["verify-pack", "-s", idx_str], cancel)?;
        Ok(())
    })();
    let _ = fs::remove_dir_all(&verify_repo);
    res
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
        Ok(Self { path, armed: true })
    }

    fn into_prepared(mut self, manifest: CloneKitManifest, encoded: Vec<u8>) -> PreparedGeneration {
        self.armed = false;
        PreparedGeneration {
            attempt_dir: self.path.clone(),
            manifest,
            encoded,
            committed: false,
        }
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

fn stale_generation(current: u64, actual: u64) -> CloneKitError {
    match current.checked_add(1) {
        Some(expected_min) => CloneKitError::StaleGeneration { expected_min, actual },
        None => CloneKitError::GitFailed(
            "clonekit generation exhausted: current generation is u64::MAX".into(),
        ),
    }
}

fn write_current_pointer(current: &Path, encoded: &[u8]) -> Result<(), CloneKitError> {
    let parent = current.parent().ok_or(CloneKitError::InvalidInput("current pointer missing parent"))?;
    let temp = parent.join(format!(".current-{}", Uuid::new_v4().simple()));
    write_private_file(&temp, encoded)?;
    let result = fs::rename(&temp, current)
        .map_err(|err| CloneKitError::GitFailed(format!("replace current pointer: {err}")));
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result?;
    sync_dir(parent)
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
    if let Some(existing) = store.load_latest(built.manifest.repository_id)?
        && built.manifest.kit_generation <= existing.kit_generation
    {
        return Err(stale_generation(existing.kit_generation, built.manifest.kit_generation));
    }
    if inject_failure == Some(BuildFailurePoint::AfterUploadBeforePublish) {
        return Err(CloneKitError::GitFailed("injected failure before atomic catalog publish".into()));
    }
    let prepared = PreparedGeneration::prepare(store, built, git_binary, cancel)?;
    store.install_prepared(prepared)?;
    Ok(built.manifest.clone())
}

#[cfg(test)]
#[path = "publication_tests.rs"]
mod publication_tests;
