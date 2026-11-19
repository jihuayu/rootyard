//! Leased selection and exact-generation verification for the publication store.

use std::fs;

use uuid::Uuid;

use super::super::read_lease::{self, CloneKitReadLease, LeasedCloneKitManifest};
use super::CloneKitPublicationStore;
use crate::ci_checkouts::clonekit::manifest::{CloneKitError, CloneKitManifest};

impl CloneKitPublicationStore {
    /// Select the latest verified manifest under a shared cross-process read lease.
    ///
    /// The returned lease is acquired before the current pointer is read and verified against
    /// the exact generation directory, so a concurrent local `try_gc_generation` cannot remove
    /// the selected generation. Drop the lease only after all pack/idx bytes have been copied
    /// into owned scratch.
    pub fn load_latest_leased(&self, repo_id: Uuid) -> Result<Option<LeasedCloneKitManifest>, CloneKitError> {
        let pointer = self.current_pointer_path(repo_id);
        match fs::symlink_metadata(&pointer) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(CloneKitError::CorruptArtifact(format!("stat latest manifest: {err}"))),
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
                return Err(CloneKitError::CorruptArtifact("current pointer is not a regular file".into()));
            }
            Ok(_) => {}
        }
        let lease = read_lease::acquire_shared(&self.repo_dir(repo_id), repo_id)?;
        let Some(manifest) = self.read_current_locked(repo_id)? else {
            return Err(CloneKitError::CorruptArtifact(
                "current pointer vanished while acquiring the read lease".into(),
            ));
        };
        read_lease::verify_generation(&self.version_dir(repo_id, manifest.kit_generation), &manifest)?;
        Ok(Some(LeasedCloneKitManifest::new(manifest, lease)))
    }

    /// Acquire a shared read lease for an exact caller-supplied generation and verify it.
    pub fn acquire_generation_read_lease(
        &self,
        repo_id: Uuid,
        manifest: &CloneKitManifest,
    ) -> Result<CloneKitReadLease, CloneKitError> {
        if manifest.repository_id != repo_id {
            return Err(CloneKitError::CorruptArtifact("read lease repository identity mismatch".into()));
        }
        let lease = read_lease::acquire_shared(&self.repo_dir(repo_id), repo_id)?;
        read_lease::verify_generation(&self.version_dir(repo_id, manifest.kit_generation), manifest)?;
        Ok(lease)
    }
}
