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
    fence: Option<super::super::blocking::ScanToken>,
}

impl PutRollbackState {
    fn restore_sync(self) {
        let _fence = self.fence;
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
    pub(super) fn capture(
        repo: &Path,
        raw_path: &str,
        upper_root: Option<PathBuf>,
        fence: Option<super::super::blocking::ScanToken>,
    ) -> Result<Self, Error> {
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
        Ok(Self {
            state: Some(PutRollbackState { repo: repo.to_path_buf(), target, prior, created_dirs, upper, fence }),
        })
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
            let _ = super::super::blocking::run_cleanup(move || state.restore_sync()).await;
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
    fence: Option<super::super::blocking::ScanToken>,
}

impl GitRollbackState {
    fn restore_sync(self) {
        let _fence = self.fence;
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
    pub(super) fn capture(
        repo: &Path,
        paths: &[String],
        upper_root: Option<PathBuf>,
        fence: Option<super::super::blocking::ScanToken>,
    ) -> Result<Self, Error> {
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
        Ok(Self { state: Some(GitRollbackState { primary, upper, fence }) })
    }

    pub(super) fn disarm(&mut self) {
        self.state = None;
    }

    pub(super) async fn rollback(mut self) {
        if let Some(state) = self.state.take() {
            let _ = super::super::blocking::run_cleanup(move || state.restore_sync()).await;
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
#[path = "files_rollback_tests.rs"]
mod tests;
