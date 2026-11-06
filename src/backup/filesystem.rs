//! Confined offline volume inventory, copy and publication.
use super::*;

pub(super) fn hash(path: &Path) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(file.metadata()?.is_file(), "expected regular file");
    let mut digest = Sha256::new();
    let mut buf = [0; 128 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    Ok(hex::encode(digest.finalize()))
}
pub(super) fn private_dir(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}
use std::os::unix::fs::DirBuilderExt;

// No symlink components, '..', root alias, or ambiguous relative paths. Parents
// must exist and be operator-controlled. A hostile same-UID writer is unsupported.
pub(super) fn absolute(path: &Path, exists: bool) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    ensure!(
        path.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
        "noncanonical path"
    );
    ensure!(path.file_name().is_some(), "root path is not a target");
    let mut current = PathBuf::new();
    let count = path.components().count();
    for (i, part) in path.components().enumerate() {
        current.push(part);
        if !exists && i + 1 == count {
            break;
        }
        let meta = fs::symlink_metadata(&current)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "path component is not a real directory"
        );
    }
    if !exists {
        ensure!(
            fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "destination must not exist"
        );
    }
    Ok(path)
}
pub(super) fn disjoint(a: &Path, b: &Path) -> Result<()> {
    ensure!(
        !a.starts_with(b) && !b.starts_with(a),
        "source and destination overlap"
    );
    Ok(())
}
pub(super) fn restore_guard_path(target: &Path) -> Result<PathBuf> {
    let path = if target.is_absolute() {
        target.to_owned()
    } else {
        std::env::current_dir()?.join(target)
    };
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().context("invalid restore target")?);
    name.push(".rootyard-restoring");
    Ok(path.parent().context("missing target parent")?.join(name))
}
/// Crash-persistent admission guard. Only a reviewed operator may remove a
/// leftover guard after discarding/recovering BOTH isolated targets.
pub fn ensure_not_restoring(target: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(restore_guard_path(target)?)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "incomplete restore guard blocks service startup"
    );
    Ok(())
}
pub(super) fn volume_identity(root: &Path) -> Result<Uuid> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root.join(".volume-id"))?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() == 36 && meta.nlink() == 1 && meta.mode() & 0o7777 == 0o600,
        "missing or invalid volume identity"
    );
    let mut value = String::new();
    file.read_to_string(&mut value)?;
    Ok(value.parse()?)
}
pub(super) fn volume_lock(root: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(".rootyard.lock"))?;
    let meta = file.metadata()?;
    ensure!(meta.is_file() && meta.nlink() == 1, "invalid volume lock");
    file.try_lock_exclusive()
        .context("offline backup requires Rootyard and all Git descendants to be stopped")?;
    Ok(file)
}
pub(super) fn allowed_link(path: &str, target: &str) -> bool {
    matches!(
        path,
        "managed-hooks/pre-receive"
            | "managed-hooks/post-receive"
            | "managed-hooks/reference-transaction"
    ) && target == ".runner"
}
pub(super) fn inventory(root: &Path) -> Result<BTreeMap<String, Entry>> {
    let meta = fs::symlink_metadata(root)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "volume root must be a real directory"
    );
    let mut entries = BTreeMap::new();
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<String, Entry>) -> Result<()> {
        let mut children = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        children.sort_by_key(|e| e.file_name());
        for child in children {
            let path = child.path();
            let name = path
                .strip_prefix(root)?
                .to_str()
                .context("non UTF-8 filename unsupported")?
                .to_owned();
            ensure!(
                name.len() <= 4096 && !name.contains(['\n', '\r']),
                "invalid filename"
            );
            ensure!(
                entries.len() < MAX_ENTRIES,
                "backup file count exceeds bound"
            );
            let meta = fs::symlink_metadata(&path)?;
            ensure!(
                meta.dev() == fs::metadata(root)?.dev(),
                "nested mount unsupported"
            );
            let mode = meta.mode() & 0o7777;
            ensure!(mode & 0o7000 == 0, "special file modes unsupported");
            let entry = if meta.file_type().is_symlink() {
                let target = fs::read_link(&path)?
                    .to_str()
                    .context("non UTF-8 link")?
                    .to_owned();
                ensure!(
                    allowed_link(&name, &target),
                    "unsupported or external symlink"
                );
                Entry {
                    kind: "symlink".into(),
                    mode,
                    bytes: 0,
                    sha256: None,
                    target: Some(target),
                }
            } else if meta.is_file() {
                ensure!(meta.nlink() == 1, "hard-linked files unsupported");
                Entry {
                    kind: "file".into(),
                    mode,
                    bytes: meta.len(),
                    sha256: Some(hash(&path)?),
                    target: None,
                }
            } else if meta.is_dir() {
                Entry {
                    kind: "directory".into(),
                    mode,
                    bytes: 0,
                    sha256: None,
                    target: None,
                }
            } else {
                bail!("special files unsupported");
            };
            entries.insert(name, entry);
            if meta.is_dir() {
                visit(root, &path, entries)?;
            }
        }
        Ok(())
    }
    visit(root, root, &mut entries)?;
    Ok(entries)
}
pub(super) fn copy_volume(source: &Path, target: &Path, entries: &BTreeMap<String, Entry>) -> Result<()> {
    private_dir(target)?;
    for (name, entry) in entries {
        ensure!(
            Path::new(name)
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
            "invalid manifest path"
        );
        let dest = target.join(name);
        match entry.kind.as_str() {
            "directory" => private_dir(&dest)?,
            "file" => {
                let mut input = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(source.join(name))?;
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&dest)?;
                std::io::copy(&mut input, &mut output)?;
                output.set_permissions(fs::Permissions::from_mode(entry.mode))?;
                output.sync_all()?;
            }
            "symlink" => {
                let link = entry.target.as_deref().context("missing link")?;
                ensure!(allowed_link(name, link), "invalid link");
                std::os::unix::fs::symlink(link, dest)?;
            }
            _ => bail!("unsupported entry"),
        }
    }
    for (name, entry) in entries.iter().rev() {
        if entry.kind == "directory" {
            fs::set_permissions(target.join(name), fs::Permissions::from_mode(entry.mode))?;
            File::open(target.join(name))?.sync_all()?;
        }
    }
    File::open(target)?.sync_all()?;
    ensure!(
        inventory(target)? == *entries,
        "copied volume checksum mismatch"
    );
    Ok(())
}
pub(super) fn publish(source: &Path, target: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let source = std::ffi::CString::new(source.as_os_str().as_bytes())?;
    let target = std::ffi::CString::new(target.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn traversal_links_specials_and_overlap_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(absolute(&tmp.path().join("../escape"), false).is_err());
        assert!(disjoint(tmp.path(), &tmp.path().join("backup")).is_err());
        std::os::unix::fs::symlink("/etc", tmp.path().join("escape")).unwrap();
        assert!(inventory(tmp.path()).is_err());
        assert!(!allowed_link("repos/evil.git/objects", "../../other"));
        assert!(allowed_link("managed-hooks/pre-receive", ".runner"));
    }
    #[test]
    fn publication_never_replaces_an_existing_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("staging");
        let target = tmp.path().join("already-exists");
        private_dir(&source).unwrap();
        private_dir(&target).unwrap();
        write_private(&source.join("sentinel"), b"not published").unwrap();
        assert!(publish(&source, &target).is_err());
        assert!(source.join("sentinel").exists());
        assert!(!target.join("sentinel").exists());
    }
    #[test]
    fn restore_guard_blocks_nonexistent_target() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("not-created");
        assert!(ensure_not_restoring(&target).is_ok());
        write_private(&restore_guard_path(&target).unwrap(), b"test backup id").unwrap();
        assert!(ensure_not_restoring(&target).is_err());
        assert!(!target.exists());
    }
    #[test]
    fn private_copy_preserves_bytes_and_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        private_dir(&source).unwrap();
        write_private(&source.join("hidden"), b"durable evidence").unwrap();
        let before = inventory(&source).unwrap();
        let target = tmp.path().join("new");
        copy_volume(&source, &target, &before).unwrap();
        assert_eq!(inventory(&target).unwrap(), before);
        fs::write(target.join("hidden"), b"changed").unwrap();
        assert_ne!(inventory(&target).unwrap(), before);
    }
}
