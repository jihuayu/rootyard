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

pub(super) fn cleanup_bulkhead() -> &'static Arc<Semaphore> {
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
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
                    return;
                };
                let _ = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker::blocking(None, work)));
                })
                .await;
            });
        }
        Err(_) => {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
        }
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

fn collect_parents(dir: Option<&Path>, file: Option<&Path>, sync_parent: bool) -> Vec<PathBuf> {
    let mut parents = Vec::new();
    if sync_parent {
        if let Some(parent) = dir.and_then(Path::parent) {
            parents.push(parent.to_path_buf());
        }
        if let Some(parent) = file.and_then(Path::parent)
            && !parents.iter().any(|existing| existing == parent)
        {
            parents.push(parent.to_path_buf());
        }
    }
    parents
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

pub(super) fn cleanup_paths_sync(
    dir: Option<PathBuf>,
    file: Option<PathBuf>,
    sync_parent: bool,
    fence: Option<super::blocking::ScanToken>,
) {
    let _fence = fence;
    let parents = collect_parents(dir.as_deref(), file.as_deref(), sync_parent);
    remove_sync(dir, file, parents);
}

struct ArmedPathsCleanup {
    payload: Option<(Option<PathBuf>, Option<PathBuf>, bool, Option<super::blocking::ScanToken>)>,
}

impl Drop for ArmedPathsCleanup {
    fn drop(&mut self) {
        if let Some((dir, file, sync_parent, fence)) = self.payload.take() {
            cleanup_paths_on_drop(dir, file, sync_parent, fence);
        }
    }
}

/// Explicit non-rejecting off-thread cleanup for async pre-`COMMIT` error paths.
/// Retains `ArmedPathsCleanup` until the blocking worker begins so task
/// cancellation mid-semaphore-wait still vacates canonical paths via `Drop`.
pub(super) async fn cleanup_paths_async(
    dir: Option<PathBuf>,
    file: Option<PathBuf>,
    sync_parent: bool,
    fence: Option<super::blocking::ScanToken>,
) {
    let mut armed = ArmedPathsCleanup { payload: Some((dir, file, sync_parent, fence)) };
    let Ok(permit) = cleanup_bulkhead().clone().acquire_owned().await else {
        if let Some((d, f, sp, tok)) = armed.payload.take() {
            cleanup_paths_sync(d, f, sp, tok);
        }
        return;
    };
    let operation = worker::blocking_scope();
    let _ = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if let Some((d, f, sp, tok)) = armed.payload.take() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                worker::blocking(operation, move || cleanup_paths_sync(d, f, sp, tok));
            }));
        }
    })
    .await;
}

/// Non-blocking `Drop` helper: vacates canonical paths in O(1) via `rename` when
/// on a Tokio runtime and runs recursive deletion + `fsync` off-thread while
/// holding any `ScanToken` until removal finishes.
pub(super) fn cleanup_paths_on_drop(
    dir: Option<PathBuf>,
    file: Option<PathBuf>,
    sync_parent: bool,
    fence: Option<super::blocking::ScanToken>,
) {
    let mut parents = collect_parents(dir.as_deref(), file.as_deref(), sync_parent);
    if tokio::runtime::Handle::try_current().is_err() {
        let _fence = fence;
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
        drop(fence);
        return;
    }
    dispatch_cleanup(move || {
        let _fence = fence;
        remove_sync(moved_dir, moved_file, parents);
    });
}

/// Guard for temporary staging files so early unwinds, cancellations, or `503`
/// bulkhead rejections still unlink the file on the cleanup bulkhead.
pub(super) struct FileCleanupGuard {
    path: PathBuf,
    kept: bool,
}

impl FileCleanupGuard {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path, kept: false }
    }

    pub(super) fn keep(mut self) {
        self.kept = true;
    }

    pub(super) async fn cleanup(mut self) {
        if !self.kept {
            self.kept = true;
            cleanup_paths_async(None, Some(self.path.clone()), false, None).await;
        }
    }
}

impl Drop for FileCleanupGuard {
    fn drop(&mut self) {
        if !self.kept {
            cleanup_paths_on_drop(None, Some(self.path.clone()), false, None);
        }
    }
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

        let ws_id = Uuid::new_v4();
        let scan_tok = super::super::blocking::begin_scan(ws_id).expect("scan token");
        let ws_dir = workspaces.join("ws-1");
        fs::create_dir_all(ws_dir.join("nested")).unwrap();
        fs::write(ws_dir.join("nested/file.txt"), b"uncommitted").unwrap();
        let sidecar = lazy_dir.join("ws-1.json");
        fs::write(&sidecar, b"{}").unwrap();

        cleanup_paths_on_drop(Some(ws_dir.clone()), Some(sidecar.clone()), true, Some(scan_tok));
        assert!(!ws_dir.exists(), "canonical workspace dir must be vacated before Drop returns");
        assert!(!sidecar.exists(), "canonical lazy sidecar must be vacated before Drop returns");

        let deadline = Instant::now() + Duration::from_secs(5);
        while fs::read_dir(&staging).unwrap().next().is_some() {
            assert!(Instant::now() < deadline, "background trash cleanup did not finish");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let guard = super::super::blocking::lock_mutation(ws_id, Duration::from_secs(2)).await.unwrap();
        drop(guard);
    }
}
