//! Pre-`COMMIT` filesystem and `.git` rollback guards for split-transaction
//! workspace mutations (`files::put` and `files::git`).
use crate::{Error, workspace_lab::core};
use axum::http::StatusCode;
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub(super) fn safe_path(raw: &str) -> Result<PathBuf, Error> {
    Ok(PathBuf::from(crate::browse::models::normalize_rel_path(Some(raw))?))
}

pub(super) fn safe_file(repo: &Path, raw: &str) -> Result<PathBuf, Error> {
    let rel = safe_path(raw)?;
    if rel.as_os_str().is_empty() {
        return Err(Error::bad_request());
    }
    let path = repo.join(rel);
    let mut cur = repo.to_path_buf();
    for seg in path.strip_prefix(repo).map_err(Error::internal)?.components() {
        cur.push(seg);
        if let Ok(meta) = fs::symlink_metadata(&cur)
            && meta.file_type().is_symlink()
        {
            return Err(Error::bad_request());
        }
    }
    Ok(path)
}

pub(super) fn atomic_put(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Error> {
    let parent = path.parent().ok_or_else(Error::bad_request)?;
    fs::create_dir_all(parent).map_err(Error::internal)?;
    let tmp = parent.join(format!(".rootyard-{}", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode & 0o777)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(Error::internal)?;
    let staged = (|| -> Result<(), Error> {
        file.write_all(bytes).map_err(Error::internal)?;
        file.set_permissions(fs::Permissions::from_mode(mode & 0o777)).map_err(Error::internal)?;
        file.sync_all().map_err(Error::internal)?;
        drop(file);
        fs::rename(&tmp, path).map_err(Error::internal)?;
        Ok(())
    })();
    if let Err(err) = staged {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    File::open(parent).and_then(|d| d.sync_all()).map_err(Error::internal)?;
    Ok(())
}

fn remove_file_strict(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn missing_ancestors(root: &Path, target: &Path) -> Vec<PathBuf> {
    let mut missing = Vec::new();
    let mut cur = target.parent();
    while let Some(dir) = cur {
        if dir == root || !dir.starts_with(root) {
            break;
        }
        if !dir.exists() {
            missing.push(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    missing
}

fn read_prior_file(path: &Path) -> Result<Option<(Vec<u8>, u32)>, Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(Error::bad_request());
            }
            if meta.len() > core::MAX_BYTES {
                return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "file too large"));
            }
            let bytes = fs::read(path).map_err(Error::internal)?;
            Ok(Some((bytes, meta.permissions().mode() & 0o777)))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::internal(err)),
    }
}

fn restore_file_tree(
    root: &Path,
    target: &Path,
    prior: &Option<(Vec<u8>, u32)>,
    created_dirs: &[PathBuf],
) -> std::io::Result<()> {
    match prior {
        Some((bytes, mode)) => atomic_put(target, bytes, *mode).map_err(std::io::Error::other)?,
        None => {
            remove_file_strict(target)?;
            for dir in created_dirs {
                let _ = fs::remove_dir(dir);
            }
            if let Some(mut cur) = target.parent() {
                while !cur.exists() && cur != root && cur.starts_with(root) {
                    let Some(next) = cur.parent() else { break };
                    cur = next;
                }
                if cur.exists() {
                    let _ = File::open(cur).and_then(|d| d.sync_all());
                }
            }
        }
    }
    Ok(())
}

struct UpperPutSnapshot {
    upper_root: PathBuf,
    upper_target: PathBuf,
    prior: Option<(Vec<u8>, u32)>,
    created_dirs: Vec<PathBuf>,
    whiteouts: Option<Vec<u8>>,
}

struct PutRollbackState {
    repo: PathBuf,
    target: PathBuf,
    prior: Option<(Vec<u8>, u32)>,
    created_dirs: Vec<PathBuf>,
    upper: Option<UpperPutSnapshot>,
}

impl PutRollbackState {
    fn restore_sync(&self) {
        if restore_file_tree(&self.repo, &self.target, &self.prior, &self.created_dirs).is_err()
            && let Some(ref up) = self.upper
        {
            let _ = restore_file_tree(&up.upper_root, &up.upper_target, &up.prior, &up.created_dirs);
            let whiteout_path = up.upper_root.join(".rootyard-whiteouts.json");
            match &up.whiteouts {
                Some(raw) => {
                    let _ = atomic_put(&whiteout_path, raw, 0o600);
                }
                None => {
                    let _ = fs::remove_file(&whiteout_path);
                }
            }
        }
    }
}

pub(super) struct PutRollback {
    state: Option<PutRollbackState>,
}

impl PutRollback {
    pub(super) fn capture(repo: &Path, raw_path: &str, upper_root: Option<PathBuf>) -> Result<Self, Error> {
        let target = safe_file(repo, raw_path)?;
        let rel = safe_path(raw_path)?;
        let prior = read_prior_file(&target)?;
        let created_dirs = missing_ancestors(repo, &target);
        let upper = match upper_root {
            Some(up_root) => {
                let up_target = up_root.join(&rel);
                let up_prior = read_prior_file(&up_target)?;
                let up_dirs = missing_ancestors(&up_root, &up_target);
                let whiteouts = read_prior_file(&up_root.join(".rootyard-whiteouts.json"))?.map(|(b, _)| b);
                Some(UpperPutSnapshot {
                    upper_root: up_root,
                    upper_target: up_target,
                    prior: up_prior,
                    created_dirs: up_dirs,
                    whiteouts,
                })
            }
            None => None,
        };
        Ok(Self { state: Some(PutRollbackState { repo: repo.to_path_buf(), target, prior, created_dirs, upper }) })
    }

    pub(super) fn target(&self) -> &Path {
        &self.state.as_ref().expect("put rollback armed").target
    }

    pub(super) fn disarm(&mut self) {
        self.state = None;
    }

    pub(super) fn restore_now(&mut self) {
        if let Some(state) = self.state.take() {
            state.restore_sync();
        }
    }

    pub(super) async fn rollback(mut self) {
        if let Some(state) = self.state.take() {
            let _ = super::super::blocking::run(move || {
                state.restore_sync();
                Ok(())
            })
            .await;
        }
    }
}

impl Drop for PutRollback {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            super::super::cleanup::dispatch_cleanup(move || state.restore_sync());
        }
    }
}

fn walk_git_objects(objects_dir: &Path) -> Result<(HashSet<PathBuf>, HashSet<PathBuf>), Error> {
    walk_git_objects_bounded(objects_dir, core::MAX_ENTRIES).map_err(Error::internal)
}

fn walk_git_objects_bounded(
    objects_dir: &Path,
    max_entries: usize,
) -> std::io::Result<(HashSet<PathBuf>, HashSet<PathBuf>)> {
    let mut files = HashSet::new();
    let mut dirs = HashSet::new();
    match fs::symlink_metadata(objects_dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(std::io::Error::other("invalid .git/objects metadata")),
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok((files, dirs)),
        Err(err) => return Err(err),
    }
    let mut total = 0usize;
    let mut stack = vec![objects_dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        for entry in fs::read_dir(&cur)? {
            let entry = entry?;
            total = total.saturating_add(1);
            if total > max_entries {
                return Err(std::io::Error::other("workspace .git/objects exceeds entry cap"));
            }
            let path = entry.path();
            let rel = path.strip_prefix(objects_dir).map_err(std::io::Error::other)?.to_path_buf();
            let meta = fs::symlink_metadata(&path)?;
            if meta.file_type().is_dir() {
                dirs.insert(rel);
                stack.push(path);
            } else {
                files.insert(rel);
            }
        }
    }
    Ok((files, dirs))
}

fn path_exists_strict(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(Error::internal(err)),
    }
}

fn restore_git_tree(
    git_dir: &Path,
    pre_index_lock: bool,
    prior_index: &Option<(Vec<u8>, u32)>,
    pre_files: &HashSet<PathBuf>,
    pre_dirs: &HashSet<PathBuf>,
) -> std::io::Result<()> {
    if !pre_index_lock {
        remove_file_strict(&git_dir.join("index.lock"))?;
    }
    let index_path = git_dir.join("index");
    match prior_index {
        Some((bytes, mode)) => atomic_put(&index_path, bytes, *mode).map_err(std::io::Error::other)?,
        None => remove_file_strict(&index_path)?,
    }
    let objects_dir = git_dir.join("objects");
    match fs::symlink_metadata(&objects_dir) {
        Ok(meta) if meta.is_dir() => {
            let (now_files, now_dirs) = walk_git_objects_bounded(&objects_dir, core::MAX_ENTRIES)?;
            for rel in now_files.difference(pre_files) {
                let full = objects_dir.join(rel);
                let meta = match fs::symlink_metadata(&full) {
                    Ok(meta) => meta,
                    Err(err) if err.kind() == ErrorKind::NotFound => continue,
                    Err(err) => return Err(err),
                };
                if !meta.file_type().is_symlink() && (meta.permissions().mode() & 0o200) == 0 {
                    match fs::set_permissions(&full, fs::Permissions::from_mode(0o600)) {
                        Ok(()) => {}
                        Err(err) if err.kind() == ErrorKind::NotFound => continue,
                        Err(err) => return Err(err),
                    }
                }
                remove_file_strict(&full)?;
            }
            let mut extra_dirs: Vec<&PathBuf> = now_dirs.difference(pre_dirs).collect();
            extra_dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
            for rel in extra_dirs {
                match fs::remove_dir(objects_dir.join(rel)) {
                    Ok(()) => {}
                    Err(err) if matches!(err.kind(), ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty) => {}
                    Err(err) => return Err(err),
                }
            }
            let _ = File::open(&objects_dir).and_then(|d| d.sync_all());
        }
        Ok(_) => return Err(std::io::Error::other("invalid .git/objects metadata")),
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let _ = File::open(git_dir).and_then(|d| d.sync_all());
    Ok(())
}

struct GitTreeSnapshot {
    git_dir: PathBuf,
    pre_index_lock: bool,
    prior_index: Option<(Vec<u8>, u32)>,
    pre_files: HashSet<PathBuf>,
    pre_dirs: HashSet<PathBuf>,
}

impl GitTreeSnapshot {
    fn capture(git_dir: PathBuf) -> Result<Self, Error> {
        let pre_index_lock = path_exists_strict(&git_dir.join("index.lock"))?;
        let prior_index = read_prior_file(&git_dir.join("index"))?;
        let (pre_files, pre_dirs) = walk_git_objects(&git_dir.join("objects"))?;
        Ok(Self { git_dir, pre_index_lock, prior_index, pre_files, pre_dirs })
    }

    fn restore(&self) -> std::io::Result<()> {
        restore_git_tree(&self.git_dir, self.pre_index_lock, &self.prior_index, &self.pre_files, &self.pre_dirs)
    }
}

struct UpperGitSnapshot {
    upper_root: PathBuf,
    tree: GitTreeSnapshot,
    whiteouts: Option<Vec<u8>>,
}

struct GitRollbackState {
    primary: GitTreeSnapshot,
    upper: Option<UpperGitSnapshot>,
}

impl GitRollbackState {
    fn restore_sync(&self) {
        if self.primary.restore().is_err()
            && let Some(ref up) = self.upper
        {
            let _ = up.tree.restore();
            let whiteout_path = up.upper_root.join(".rootyard-whiteouts.json");
            match &up.whiteouts {
                Some(raw) => {
                    let _ = atomic_put(&whiteout_path, raw, 0o600);
                }
                None => {
                    let _ = fs::remove_file(&whiteout_path);
                }
            }
        }
    }
}

pub(super) struct GitRollback {
    state: Option<GitRollbackState>,
}

impl GitRollback {
    pub(super) fn capture(repo: &Path, paths: &[String], upper_root: Option<PathBuf>) -> Result<Self, Error> {
        for path in paths {
            safe_file(repo, path)?;
        }
        let primary = GitTreeSnapshot::capture(repo.join(".git"))?;
        let upper = match upper_root {
            Some(up_root) => {
                let tree = GitTreeSnapshot::capture(up_root.join(".git"))?;
                let whiteouts = read_prior_file(&up_root.join(".rootyard-whiteouts.json"))?.map(|(b, _)| b);
                Some(UpperGitSnapshot { upper_root: up_root, tree, whiteouts })
            }
            None => None,
        };
        Ok(Self { state: Some(GitRollbackState { primary, upper }) })
    }

    pub(super) fn disarm(&mut self) {
        self.state = None;
    }

    pub(super) async fn rollback(mut self) {
        if let Some(state) = self.state.take() {
            let _ = super::super::blocking::run(move || {
                state.restore_sync();
                Ok(())
            })
            .await;
        }
    }
}

impl Drop for GitRollback {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            super::super::cleanup::dispatch_cleanup(move || state.restore_sync());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_rollback_restores_files_and_failed_atomic_put_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        fs::write(repo.join("existing.txt"), b"v1\n").unwrap();
        fs::set_permissions(repo.join("existing.txt"), fs::Permissions::from_mode(0o644)).unwrap();

        let mut rb = PutRollback::capture(repo, "existing.txt", None).unwrap();
        atomic_put(rb.target(), b"v2-rejected\n", 0o600).unwrap();
        rb.restore_now();
        assert_eq!(fs::read(repo.join("existing.txt")).unwrap(), b"v1\n");
        assert_eq!(fs::metadata(repo.join("existing.txt")).unwrap().permissions().mode() & 0o777, 0o644);

        let mut rb_new = PutRollback::capture(repo, "nested/sub/new.txt", None).unwrap();
        atomic_put(rb_new.target(), b"created\n", 0o600).unwrap();
        rb_new.restore_now();
        assert!(!repo.join("nested").exists());

        fs::create_dir(repo.join("dir_target")).unwrap();
        assert!(atomic_put(&repo.join("dir_target"), b"boom", 0o600).is_err());
        let leftovers: Vec<_> = fs::read_dir(repo)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".rootyard-"))
            .collect();
        assert!(leftovers.is_empty(), "atomic_put failure must unlink temporary file");
    }

    #[test]
    fn git_rollback_cleans_index_lock_fails_closed_and_triggers_upper_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("mount");
        let upper = dir.path().join("upper");
        fs::create_dir_all(repo.join(".git/objects/aa")).unwrap();
        fs::create_dir_all(&upper).unwrap();
        fs::write(repo.join(".git/index"), b"index-v1").unwrap();
        fs::write(repo.join(".git/objects/aa/keep"), b"keep").unwrap();
        fs::write(repo.join("hello.txt"), b"hello").unwrap();

        assert!(walk_git_objects_bounded(&repo.join(".git/objects"), 1).is_err());
        fs::set_permissions(repo.join(".git/objects/aa"), fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read_dir(repo.join(".git/objects/aa")).is_err() {
            assert!(GitRollback::capture(&repo, &[String::from("hello.txt")], None).is_err());
        }
        fs::set_permissions(repo.join(".git/objects/aa"), fs::Permissions::from_mode(0o700)).unwrap();

        let mut rb = GitRollback::capture(&repo, &[String::from("hello.txt")], Some(upper.clone())).unwrap();
        fs::create_dir_all(upper.join(".git/objects/bb")).unwrap();
        fs::write(upper.join(".git/index"), b"index-v2-rejected").unwrap();
        fs::write(upper.join(".git/index.lock"), b"stranded-by-timeout").unwrap();
        fs::write(upper.join(".git/objects/bb/newblob"), b"new").unwrap();
        fs::create_dir_all(repo.join(".git/objects/bb")).unwrap();
        fs::write(repo.join(".git/objects/bb/newblob"), b"new").unwrap();
        fs::set_permissions(repo.join(".git/objects/bb"), fs::Permissions::from_mode(0o500)).unwrap();

        rb.state.take().unwrap().restore_sync();
        fs::set_permissions(repo.join(".git/objects/bb"), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!upper.join(".git/index.lock").exists(), "upper fallback must remove index.lock");
        assert!(!upper.join(".git/index").exists(), "upper fallback must remove copy-up index");
        assert!(!upper.join(".git/objects/bb").exists(), "upper fallback must prune loose objects");

        let mut rb_direct = GitRollback::capture(&repo, &[String::from("hello.txt")], None).unwrap();
        fs::write(repo.join(".git/index"), b"index-v2").unwrap();
        fs::write(repo.join(".git/index.lock"), b"lock").unwrap();
        fs::create_dir_all(repo.join(".git/objects/cc")).unwrap();
        fs::write(repo.join(".git/objects/cc/newblob"), b"new").unwrap();
        fs::set_permissions(repo.join(".git/objects/cc/newblob"), fs::Permissions::from_mode(0o444)).unwrap();
        rb_direct.state.take().unwrap().restore_sync();
        assert_eq!(fs::read(repo.join(".git/index")).unwrap(), b"index-v1");
        assert!(!repo.join(".git/index.lock").exists() && !repo.join(".git/objects/cc").exists());
    }
}
