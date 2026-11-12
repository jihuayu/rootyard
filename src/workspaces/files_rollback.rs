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
    file.write_all(bytes).map_err(Error::internal)?;
    file.set_permissions(fs::Permissions::from_mode(mode & 0o777)).map_err(Error::internal)?;
    file.sync_all().map_err(Error::internal)?;
    drop(file);
    fs::rename(&tmp, path).map_err(Error::internal)?;
    File::open(parent).and_then(|d| d.sync_all()).map_err(Error::internal)?;
    Ok(())
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
            match fs::remove_file(target) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
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
                let whiteouts = fs::read(up_root.join(".rootyard-whiteouts.json")).ok();
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

fn walk_git_objects(objects_dir: &Path) -> (HashSet<PathBuf>, HashSet<PathBuf>) {
    let mut files = HashSet::new();
    let mut dirs = HashSet::new();
    if !objects_dir.is_dir() {
        return (files, dirs);
    }
    let mut stack = vec![objects_dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        let Ok(entries) = fs::read_dir(&cur) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(rel) = path.strip_prefix(objects_dir) else { continue };
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                dirs.insert(rel.to_path_buf());
                stack.push(path);
            } else {
                files.insert(rel.to_path_buf());
            }
        }
    }
    (files, dirs)
}

fn restore_git_tree(
    git_dir: &Path,
    prior_index: &Option<(Vec<u8>, u32)>,
    pre_files: &HashSet<PathBuf>,
    pre_dirs: &HashSet<PathBuf>,
) -> std::io::Result<()> {
    let index_path = git_dir.join("index");
    match prior_index {
        Some((bytes, mode)) => atomic_put(&index_path, bytes, *mode).map_err(std::io::Error::other)?,
        None => match fs::remove_file(&index_path) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        },
    }
    let objects_dir = git_dir.join("objects");
    if objects_dir.is_dir() {
        let (now_files, now_dirs) = walk_git_objects(&objects_dir);
        for rel in now_files.difference(pre_files) {
            let full = objects_dir.join(rel);
            let _ = fs::set_permissions(&full, fs::Permissions::from_mode(0o600));
            let _ = fs::remove_file(&full);
        }
        let mut extra_dirs: Vec<&PathBuf> = now_dirs.difference(pre_dirs).collect();
        extra_dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
        for rel in extra_dirs {
            let _ = fs::remove_dir(objects_dir.join(rel));
        }
        let _ = File::open(&objects_dir).and_then(|d| d.sync_all());
    }
    let _ = File::open(git_dir).and_then(|d| d.sync_all());
    Ok(())
}

struct UpperGitSnapshot {
    git_dir: PathBuf,
    prior_index: Option<(Vec<u8>, u32)>,
    pre_files: HashSet<PathBuf>,
    pre_dirs: HashSet<PathBuf>,
}

struct GitRollbackState {
    git_dir: PathBuf,
    prior_index: Option<(Vec<u8>, u32)>,
    pre_files: HashSet<PathBuf>,
    pre_dirs: HashSet<PathBuf>,
    upper: Option<UpperGitSnapshot>,
}

impl GitRollbackState {
    fn restore_sync(&self) {
        if restore_git_tree(&self.git_dir, &self.prior_index, &self.pre_files, &self.pre_dirs).is_err()
            && let Some(ref up) = self.upper
        {
            let _ = restore_git_tree(&up.git_dir, &up.prior_index, &up.pre_files, &up.pre_dirs);
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
        let git_dir = repo.join(".git");
        let prior_index = read_prior_file(&git_dir.join("index"))?;
        let (pre_files, pre_dirs) = walk_git_objects(&git_dir.join("objects"));
        let upper = match upper_root {
            Some(up_root) => {
                let up_git = up_root.join(".git");
                let up_index = read_prior_file(&up_git.join("index"))?;
                let (up_files, up_dirs) = walk_git_objects(&up_git.join("objects"));
                Some(UpperGitSnapshot {
                    git_dir: up_git,
                    prior_index: up_index,
                    pre_files: up_files,
                    pre_dirs: up_dirs,
                })
            }
            None => None,
        };
        Ok(Self { state: Some(GitRollbackState { git_dir, prior_index, pre_files, pre_dirs, upper }) })
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
    fn put_rollback_restores_modified_and_new_files_and_prunes_empty_dirs() {
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
        assert!(repo.join("nested/sub/new.txt").is_file());
        rb_new.restore_now();
        assert!(!repo.join("nested").exists(), "newly created ancestor directories must be pruned");
    }

    #[test]
    fn git_rollback_restores_index_and_prunes_new_loose_objects() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        fs::create_dir_all(repo.join(".git/objects/aa")).unwrap();
        fs::write(repo.join(".git/index"), b"index-v1").unwrap();
        fs::write(repo.join(".git/objects/aa/keep"), b"keep").unwrap();
        fs::write(repo.join("hello.txt"), b"hello").unwrap();

        let mut rb = GitRollback::capture(repo, &[String::from("hello.txt")], None).unwrap();
        fs::write(repo.join(".git/index"), b"index-v2-rejected").unwrap();
        fs::create_dir_all(repo.join(".git/objects/bb")).unwrap();
        let loose = repo.join(".git/objects/bb/newblob");
        fs::write(&loose, b"new").unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o444)).unwrap();

        rb.state.take().unwrap().restore_sync();
        assert_eq!(fs::read(repo.join(".git/index")).unwrap(), b"index-v1");
        assert!(repo.join(".git/objects/aa/keep").is_file());
        assert!(!repo.join(".git/objects/bb").exists());
    }
}
