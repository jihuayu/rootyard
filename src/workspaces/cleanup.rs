//! Off-thread cleanup for uncommitted workspace trees and sidecar manifests.
//!
//! Pre-`COMMIT` guards (`DirCleanupGuard`, `Published`, `LazyPublished`) own
//! newly created directories or manifests until disarmed immediately before
//! `tx.commit().await`. Normal async error paths call explicit `.cleanup().await`
//! while still holding the per-workspace mutation guard. If a guard is dropped
//! while armed inside a Tokio runtime (cancellation or early `?` unwind), `Drop`
//! performs only an O(1) same-filesystem `rename(2)` into a unique `.trash-*`
//! path — immediately vacating the canonical `workspaces/<id>` or `lazy/<id>.json`
//! path so retries cannot collide — and dispatches recursive `remove_dir_all` +
//! parent `fsync` onto a bounded background cleanup bulkhead so Tokio async
//! worker threads never block on directory traversal or `fsync`.
use crate::observability::worker;
use std::{
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};
use tokio::sync::Semaphore;
use uuid::Uuid;

const CLEANUP_CONCURRENCY: usize = 8;

fn cleanup_bulkhead() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(CLEANUP_CONCURRENCY)))
}

/// Schedule a bounded background filesystem cleanup closure when running inside
/// a Tokio runtime, or run it synchronously when no runtime is active.
pub(super) fn dispatch_cleanup<F>(work: F)
where
    F: FnOnce() + Send + 'static,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            let sem = cleanup_bulkhead().clone();
            handle.spawn(async move {
                let Ok(permit) = sem.acquire_owned().await else {
                    return;
                };
                let _ = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    worker::blocking(None, work);
                })
                .await;
            });
        }
        Err(_) => work(),
    }
}

fn trash_target_for(path: &Path, prefix: &str) -> Option<PathBuf> {
    let parent = path.parent()?;
    if let Some(ws_root) = parent.parent() {
        let staging = ws_root.join("staging");
        if staging.is_dir() {
            return Some(staging.join(format!(".{prefix}-{}", Uuid::new_v4())));
        }
    }
    Some(parent.join(format!(".{prefix}-{}", Uuid::new_v4())))
}

fn sync_parent_dir(parent: &Path) {
    let _ = File::open(parent).and_then(|directory| directory.sync_all());
}

fn remove_sync(dir: Option<PathBuf>, file: Option<PathBuf>, parents: Vec<PathBuf>) {
    if let Some(dir) = dir {
        let _ = fs::remove_dir_all(&dir);
    }
    if let Some(file) = file {
        let _ = fs::remove_file(&file);
    }
    for parent in parents {
        sync_parent_dir(&parent);
    }
}

/// Explicit bounded off-thread cleanup for async pre-`COMMIT` error paths.
pub(super) async fn cleanup_paths_async(dir: Option<PathBuf>, file: Option<PathBuf>, sync_parent: bool) {
    let mut parents = Vec::new();
    if sync_parent {
        if let Some(parent) = dir.as_deref().and_then(Path::parent) {
            parents.push(parent.to_path_buf());
        }
        if let Some(parent) = file.as_deref().and_then(Path::parent)
            && !parents.iter().any(|existing| existing == parent)
        {
            parents.push(parent.to_path_buf());
        }
    }
    let _ = super::blocking::run(move || {
        remove_sync(dir, file, parents);
        Ok(())
    })
    .await;
}

/// Non-blocking `Drop` helper: vacates canonical paths in O(1) via `rename` when
/// on a Tokio runtime and runs recursive deletion + `fsync` off-thread.
pub(super) fn cleanup_paths_on_drop(dir: Option<PathBuf>, file: Option<PathBuf>, sync_parent: bool) {
    let mut parents = Vec::new();
    if sync_parent {
        if let Some(parent) = dir.as_deref().and_then(Path::parent) {
            parents.push(parent.to_path_buf());
        }
        if let Some(parent) = file.as_deref().and_then(Path::parent)
            && !parents.iter().any(|existing| existing == parent)
        {
            parents.push(parent.to_path_buf());
        }
    }
    if tokio::runtime::Handle::try_current().is_err() {
        remove_sync(dir, file, parents);
        return;
    }
    let moved_dir = dir.and_then(|orig| match trash_target_for(&orig, "trash-dir") {
        Some(trash) => match fs::rename(&orig, &trash) {
            Ok(()) => {
                if sync_parent
                    && let Some(tp) = trash.parent()
                    && !parents.iter().any(|existing| existing == tp)
                {
                    parents.push(tp.to_path_buf());
                }
                Some(trash)
            }
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(_) => Some(orig),
        },
        None => Some(orig),
    });
    let moved_file = file.and_then(|orig| match trash_target_for(&orig, "trash-file") {
        Some(trash) => match fs::rename(&orig, &trash) {
            Ok(()) => {
                if sync_parent
                    && let Some(tp) = trash.parent()
                    && !parents.iter().any(|existing| existing == tp)
                {
                    parents.push(tp.to_path_buf());
                }
                Some(trash)
            }
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(_) => Some(orig),
        },
        None => Some(orig),
    });
    if moved_dir.is_none() && moved_file.is_none() {
        return;
    }
    dispatch_cleanup(move || remove_sync(moved_dir, moved_file, parents));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_drop_vacates_canonical_paths_immediately_and_reaps_trash() {
        let root = tempfile::tempdir().unwrap();
        let staging = root.path().join("workspace-service/staging");
        let workspaces = root.path().join("workspace-service/workspaces");
        let lazy_dir = root.path().join("workspace-service/lazy");
        fs::create_dir_all(&staging).unwrap();
        fs::create_dir_all(&workspaces).unwrap();
        fs::create_dir_all(&lazy_dir).unwrap();

        let ws_dir = workspaces.join("ws-1");
        fs::create_dir_all(ws_dir.join("nested")).unwrap();
        fs::write(ws_dir.join("nested/file.txt"), b"uncommitted").unwrap();
        let sidecar = lazy_dir.join("ws-1.json");
        fs::write(&sidecar, b"{}").unwrap();

        cleanup_paths_on_drop(Some(ws_dir.clone()), Some(sidecar.clone()), true);
        assert!(!ws_dir.exists(), "canonical workspace dir must be vacated before Drop returns");
        assert!(!sidecar.exists(), "canonical lazy sidecar must be vacated before Drop returns");

        let deadline = Instant::now() + Duration::from_secs(5);
        while fs::read_dir(&staging).unwrap().next().is_some() {
            assert!(Instant::now() < deadline, "background trash cleanup did not finish");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
