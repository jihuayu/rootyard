//! Owned, private (0700) scratch directory for one native verification.
//!
//! The verifier has no persistent Git filesystem authority: it creates one fresh
//! directory under the process temporary directory, verifies that the created
//! inode is a real directory (not a symlink) owned by the current user with mode
//! `0700`, and removes it when the view is dropped. `create` is `mkdir` with a
//! random name, so two verifiers can never share a view, and a pre-existing path
//! is never reused.
//!
//! Cache effects and crash leftovers: the directory is only removable after the
//! proof, and a process crash may leave one behind; nothing in the committed
//! state depends on it.
use super::refuse;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Exact directory mode of the owned view root.
pub(super) const PRIVATE_DIR_MODE: u32 = 0o700;
/// Bounded number of random-name attempts before the view is refused.
const CREATE_ATTEMPTS: usize = 8;

pub(super) struct TempRoot {
    path: PathBuf,
}

impl TempRoot {
    /// Create one fresh private directory. Never reuses an existing path.
    pub(super) fn create() -> Result<Self, PackCommitError> {
        let base = std::env::temp_dir();
        for _ in 0..CREATE_ATTEMPTS {
            let path = base.join(format!("rootyard-pack-verify-{}", Uuid::new_v4()));
            match std::fs::DirBuilder::new().mode(PRIVATE_DIR_MODE).create(&path) {
                Ok(()) => {
                    if let Err(error) = Self::inspect(&path) {
                        // A view that fails inspection must not be left behind.
                        let _ = std::fs::remove_dir_all(&path);
                        return Err(error);
                    }
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(refuse("verifier scratch directory cannot be created")),
            }
        }
        Err(refuse("verifier scratch directory cannot be created"))
    }

    /// The created inode must be our own private directory, never a symlink.
    fn inspect(path: &Path) -> Result<(), PackCommitError> {
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| refuse("verifier scratch directory cannot be inspected"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(refuse("verifier scratch path is not a private directory"));
        }
        if metadata.permissions().mode() & 0o777 != PRIVATE_DIR_MODE {
            return Err(refuse("verifier scratch directory is not mode 0700"));
        }
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(refuse("verifier scratch directory is owned by another user"));
        }
        Ok(())
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// Create one bounded private child directory of the view.
    pub(super) fn subdirectory(&self, name: &str) -> Result<PathBuf, PackCommitError> {
        if !matches!(name, "home" | "template" | "incoming") {
            return Err(refuse("verifier view directory name is not a fixed literal"));
        }
        let path = self.path.join(name);
        std::fs::DirBuilder::new()
            .mode(PRIVATE_DIR_MODE)
            .create(&path)
            .map_err(|_| refuse("verifier view directory cannot be created"))?;
        Self::inspect(&path)?;
        Ok(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn created_view_is_private_and_owned() {
        let root = TempRoot::create().expect("scratch root");
        let metadata = std::fs::symlink_metadata(root.path()).expect("metadata");
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, PRIVATE_DIR_MODE);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        let home = root.subdirectory("home").expect("home");
        assert!(home.is_dir());
        assert!(root.subdirectory("incoming").is_ok());
        assert!(root.subdirectory("objects").is_err());
        let path = root.path().to_path_buf();
        drop(root);
        assert!(!path.exists(), "the owned view is removed on drop");
    }
}
