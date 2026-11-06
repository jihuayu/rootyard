//! Two-phase quarantine for physical Git object unlink.
//!
//! Candidate loose objects are renamed into a private directory under
//! `objects/rootyard-gc-quarantine` before any unlink. If the durable GC fence
//! or writer-quiescence proof is lost, every staged object is renamed back.
//! A crash leaves the manifest and files for the next collection to restore.
use crate::journal;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const ROOT: &str = "rootyard-gc-quarantine";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    oid: String,
    relative: String,
    state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Manifest {
    version: u32,
    repository_id: Uuid,
    gc_epoch: i64,
    job_id: Uuid,
    entries: Vec<Entry>,
}

fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_relative(relative: &str) -> bool {
    !relative.is_empty()
        && relative.len() <= 256
        && !relative.contains('\\')
        && relative.split('/').all(|part| !part.is_empty() && part != "." && part != "..")
        && relative.split('/').next().is_some_and(|dir| dir.len() == 2 && dir.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn relative_for(oid: &str) -> Result<String> {
    ensure!(valid_oid(oid), "invalid quarantine object ID");
    let (dir, file) = oid.split_at(2);
    Ok(format!("{dir}/{file}"))
}

fn write_manifest(path: &Path, manifest: &Manifest) -> Result<()> {
    let bytes = serde_json::to_vec(manifest)?;
    ensure!(bytes.len() <= 1024 * 1024, "quarantine manifest exceeds limit");
    let temp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file =
            OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        sync_dir(path.parent().context("manifest parent")?)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn read_manifest(path: &Path) -> Result<Manifest> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.file_type().is_file() && !meta.file_type().is_symlink() && meta.len() <= 1024 * 1024,
        "unsafe quarantine manifest"
    );
    let manifest: Manifest = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        manifest.version == 1 && manifest.gc_epoch > 0 && manifest.entries.len() <= 100_000,
        "invalid quarantine manifest"
    );
    for entry in &manifest.entries {
        ensure!(
            valid_oid(&entry.oid)
                && valid_relative(&entry.relative)
                && matches!(entry.state.as_str(), "planned" | "staged"),
            "invalid quarantine entry"
        );
    }
    Ok(manifest)
}

pub struct Quarantine {
    git_dir: PathBuf,
    root: PathBuf,
    manifest: Manifest,
    manifest_path: PathBuf,
    finished: bool,
}

impl Quarantine {
    pub fn begin(git_dir: &Path, repository_id: Uuid, gc_epoch: i64, job_id: Uuid) -> Result<Self> {
        ensure!(gc_epoch > 0, "invalid GC epoch");
        let objects = git_dir.join("objects");
        journal::safe_path(&objects)?;
        let parent = objects.join(ROOT);
        if !parent.exists() {
            fs::create_dir(&parent)?;
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
            sync_dir(&objects)?;
        }
        journal::safe_path(&parent)?;
        ensure!(fs::symlink_metadata(&parent)?.is_dir(), "quarantine root is not a directory");
        let root = parent.join(format!("{gc_epoch}-{}", Uuid::new_v4()));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let manifest = Manifest { version: 1, repository_id, gc_epoch, job_id, entries: Vec::new() };
        let manifest_path = root.join("manifest.json");
        write_manifest(&manifest_path, &manifest)?;
        sync_dir(&root)?;
        sync_dir(&parent)?;
        Ok(Self { git_dir: git_dir.to_path_buf(), root, manifest, manifest_path, finished: false })
    }

    pub fn is_empty(&self) -> bool {
        self.manifest.entries.is_empty()
    }

    /// Rename one loose object into quarantine. The durable intent must already
    /// be committed by the caller.
    pub fn stage(&mut self, oid: &str) -> Result<()> {
        let relative = relative_for(oid)?;
        let source = self.git_dir.join("objects").join(&relative);
        let dest = self.root.join("objects").join(&relative);
        let meta = fs::symlink_metadata(&source)?;
        ensure!(
            meta.file_type().is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1,
            "unsafe loose Git object"
        );
        let parent = dest.parent().context("quarantine destination parent")?;
        fs::create_dir_all(parent)?;
        ensure!(!fs::symlink_metadata(&dest).is_ok(), "quarantine destination already exists");
        self.manifest.entries.push(Entry { oid: oid.to_owned(), relative: relative.clone(), state: "planned".into() });
        write_manifest(&self.manifest_path, &self.manifest)?;
        fs::rename(&source, &dest)?;
        sync_dir(source.parent().context("source parent")?)?;
        sync_dir(parent)?;
        self.manifest.entries.last_mut().context("quarantine entry disappeared")?.state = "staged".into();
        write_manifest(&self.manifest_path, &self.manifest)?;
        Ok(())
    }

    /// Restore every staged object. This refuses to overwrite a path that has
    /// reappeared; an operator can then inspect the retained quarantine.
    pub fn rollback(&mut self) -> Result<u64> {
        let mut restored = 0u64;
        for entry in self.manifest.entries.iter().rev() {
            let source = self.git_dir.join("objects").join(&entry.relative);
            let dest = self.root.join("objects").join(&entry.relative);
            if !dest.exists() {
                continue;
            }
            ensure!(!source.exists(), "quarantine rollback destination reappeared");
            let parent = source.parent().context("restore parent")?;
            fs::create_dir_all(parent)?;
            fs::rename(&dest, &source)?;
            sync_dir(parent)?;
            restored += 1;
        }
        self.cleanup_root()?;
        self.finished = true;
        Ok(restored)
    }

    /// Unlink staged files only after the caller has re-verified the durable
    /// fence and writer quiescence. The durable tombstone intents remain the
    /// crash-recovery record if the process stops partway through.
    pub fn commit(&mut self) -> Result<u64> {
        let mut deleted = 0u64;
        for entry in &self.manifest.entries {
            let dest = self.root.join("objects").join(&entry.relative);
            match fs::symlink_metadata(&dest) {
                Ok(meta) => {
                    ensure!(
                        meta.file_type().is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1,
                        "unsafe quarantined Git object"
                    );
                    fs::remove_file(&dest)?;
                    sync_dir(dest.parent().context("quarantine unlink parent")?)?;
                    deleted += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.cleanup_root()?;
        self.finished = true;
        Ok(deleted)
    }

    fn cleanup_root(&self) -> Result<()> {
        if self.manifest_path.exists() {
            fs::remove_file(&self.manifest_path)?;
        }
        let _ = fs::remove_dir_all(self.root.join("objects"));
        let _ = fs::remove_dir(self.root.as_path());
        if let Some(parent) = self.root.parent() {
            let _ = fs::remove_dir(parent);
        }
        Ok(())
    }
}

impl Drop for Quarantine {
    fn drop(&mut self) {
        // A normal caller always commits or rolls back explicitly. Dropping
        // without either leaves the manifest for `recover`, which restores it.
        let _ = self.finished;
    }
}

/// Restore abandoned quarantine transactions before a new collection. This is
/// deliberately conservative: the original object path must be absent.
pub fn recover(git_dir: &Path, repository_id: Uuid) -> Result<u64> {
    let parent = git_dir.join("objects").join(ROOT);
    if !parent.exists() {
        return Ok(0);
    }
    journal::safe_path(&parent)?;
    ensure!(fs::symlink_metadata(&parent)?.is_dir(), "quarantine root is not a directory");
    let mut restored = 0u64;
    for entry in fs::read_dir(&parent)? {
        let entry = entry?;
        let root = entry.path();
        let meta = fs::symlink_metadata(&root)?;
        ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "unsafe quarantine transaction");
        let manifest_path = root.join("manifest.json");
        if !manifest_path.exists() {
            // The transaction may have crashed after creating its private
            // directory but before writing any manifest. No object can have
            // been moved yet, so an empty directory is safe to retire.
            let objects = root.join("objects");
            let empty = !objects.exists() || fs::read_dir(&objects)?.next().is_none();
            ensure!(empty, "quarantine directory has no manifest");
            let _ = fs::remove_dir_all(&objects);
            fs::remove_dir(&root)?;
            continue;
        }
        let manifest = read_manifest(&manifest_path)?;
        ensure!(manifest.repository_id == repository_id, "quarantine belongs to another repository");
        for candidate in manifest.entries.iter().rev() {
            let source = git_dir.join("objects").join(&candidate.relative);
            let dest = root.join("objects").join(&candidate.relative);
            if !dest.exists() {
                continue;
            }
            ensure!(!source.exists(), "quarantine recovery destination reappeared");
            let destination_parent = source.parent().context("recovery parent")?;
            fs::create_dir_all(destination_parent)?;
            fs::rename(&dest, &source)?;
            sync_dir(destination_parent)?;
            restored += 1;
        }
        fs::remove_file(&manifest_path)?;
        let _ = fs::remove_dir_all(root.join("objects"));
        fs::remove_dir(&root)?;
    }
    let _ = fs::remove_dir(&parent);
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn object(path: &Path, oid: &str) -> PathBuf {
        let relative = relative_for(oid).unwrap();
        let path = path.join("objects").join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"unreachable\n").unwrap();
        path
    }

    #[test]
    fn rollback_restores_staged_objects() {
        let dir = tempdir().unwrap();
        let oid = "a".repeat(40);
        let original = object(dir.path(), &oid);
        let mut quarantine = Quarantine::begin(dir.path(), Uuid::new_v4(), 3, Uuid::new_v4()).unwrap();
        quarantine.stage(&oid).unwrap();
        assert!(!original.exists());
        assert_eq!(quarantine.rollback().unwrap(), 1);
        assert!(original.is_file());
        assert_eq!(fs::read(&original).unwrap(), b"unreachable\n");
    }

    #[test]
    fn commit_unlinks_only_quarantined_objects() {
        let dir = tempdir().unwrap();
        let staged = "b".repeat(40);
        let retained = "c".repeat(40);
        let staged_path = object(dir.path(), &staged);
        let retained_path = object(dir.path(), &retained);
        let mut quarantine = Quarantine::begin(dir.path(), Uuid::new_v4(), 4, Uuid::new_v4()).unwrap();
        quarantine.stage(&staged).unwrap();
        assert_eq!(quarantine.commit().unwrap(), 1);
        assert!(!staged_path.exists());
        assert!(retained_path.is_file());
    }

    #[test]
    fn crash_recovery_restores_manifest_entries() {
        let dir = tempdir().unwrap();
        let oid = "d".repeat(40);
        let original = object(dir.path(), &oid);
        let repo = Uuid::new_v4();
        let mut quarantine = Quarantine::begin(dir.path(), repo, 5, Uuid::new_v4()).unwrap();
        quarantine.stage(&oid).unwrap();
        assert!(!original.exists());
        // Simulate a crash: forget the explicit finish and let recovery walk
        // the durable manifest.
        std::mem::forget(quarantine);
        assert_eq!(recover(dir.path(), repo).unwrap(), 1);
        assert!(original.is_file());
    }

    #[test]
    fn relative_paths_cannot_escape_objects_directory() {
        assert!(!valid_relative("../escape"));
        assert!(!valid_relative("aa/../../escape"));
        assert!(!valid_relative("/aa/object"));
        assert!(valid_relative("aa/bbbb"));
    }
}
