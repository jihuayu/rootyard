//! Persistent, repository-authorized native workspaces.
#[path = "workspaces/blocking.rs"]
mod blocking;
#[path = "workspaces/capture.rs"]
pub mod capture;
#[path = "workspaces/checkpoints.rs"]
mod checkpoints;
#[path = "workspaces/cleanup.rs"]
mod cleanup;
#[path = "workspaces/compat.rs"]
mod compat;
#[cfg(test)]
#[path = "workspaces/compat_tests.rs"]
mod compat_tests;
#[path = "workspaces/events.rs"]
mod events;
#[path = "workspaces/files.rs"]
mod files;
#[path = "workspaces/git.rs"]
mod git;
#[path = "workspaces/lazy.rs"]
pub(crate) mod lazy;
#[path = "workspaces/models.rs"]
mod models;
#[path = "workspaces/mounts.rs"]
pub mod mounts;
#[path = "workspaces/remote.rs"]
pub(crate) mod remote;
#[path = "workspaces/remote_gc.rs"]
mod remote_gc;
#[path = "workspaces/remote_publish_guard.rs"]
mod remote_publish_guard;
#[path = "workspaces/scan.rs"]
mod scan;
#[path = "workspaces/service.rs"]
pub(crate) mod service;
#[path = "workspaces/shutdown.rs"]
mod shutdown;
#[path = "workspaces/snapshot.rs"]
pub(crate) mod snapshot;
#[cfg(test)]
#[path = "workspaces/snapshot_tests.rs"]
mod snapshot_tests;

pub use shutdown::{capture_shutdown_grace, stop_capture_before_helper};

static PROCESS_CLEANUP_FAILED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static PROCESS_CLEANUP_DEADLINE: std::sync::OnceLock<std::sync::Mutex<Option<tokio::time::Instant>>> =
    std::sync::OnceLock::new();

/// Record that some native Git process group could not be proved quiescent.
/// This is a process-wide shutdown fact: a later clean join cannot erase it.
pub(crate) fn mark_process_cleanup_failure() {
    PROCESS_CLEANUP_FAILED.store(true, std::sync::atomic::Ordering::Release);
}

/// Publish the one absolute normal-shutdown deadline so every Process cleanup
/// can cap its already-started per-child budget. Repeated publication only
/// tightens; it never extends an existing cap.
pub fn set_process_cleanup_deadline(deadline: tokio::time::Instant) {
    let cell = PROCESS_CLEANUP_DEADLINE.get_or_init(|| std::sync::Mutex::new(None));
    let mut current = cell.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    *current = Some(match *current {
        Some(existing) if existing <= deadline => existing,
        _ => deadline,
    });
}

/// The shared normal-shutdown cap, if the signal path has published it.
pub(crate) fn process_cleanup_deadline() -> Option<tokio::time::Instant> {
    let cell = PROCESS_CLEANUP_DEADLINE.get_or_init(|| std::sync::Mutex::new(None));
    *cell.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether any native Git process-group cleanup failed to prove quiescence.
/// This remains true for the life of the process.
pub fn process_cleanup_failed() -> bool {
    PROCESS_CLEANUP_FAILED.load(std::sync::atomic::Ordering::Acquire)
}

use crate::AppState;
use axum::{
    Router,
    routing::{get, post},
};
pub use service::fence_restored;

/// Graceful-shutdown hook: wait for owned workspace Git mutations to reach
/// their bounded finish before the runtime exits. A SIGKILLed server cannot
/// provide this guarantee; retry an unknown mutation with the same key.
pub async fn drain_git_jobs(grace: std::time::Duration) {
    git::drain(grace).await;
}

/// Close new workspace Git admission while already accepted jobs remain owned.
pub fn close_git_admission() {
    git::close_admission();
}

/// Join the retained owned Git set within the caller's one shutdown deadline.
/// Returns false on any missed join, cancelled/failed job, or deadline expiry.
pub async fn drain_git_jobs_until(deadline: tokio::time::Instant) -> bool {
    git::drain_until(deadline).await
}
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/workspaces", post(service::create))
        .route("/api/workspaces/{id}", get(service::get))
        .route("/api/workspaces/{id}/lease", post(service::lease))
        .route("/api/workspaces/{id}/prewarm", post(mounts::prewarm))
        .route("/api/workspaces/{id}/fork", post(checkpoints::fork))
        .route("/api/workspaces/{id}/files", get(files::get).put(files::put))
        .route("/api/workspaces/{id}/git", post(files::git))
        .route("/api/workspaces/{id}/checkpoints", post(checkpoints::create))
        .route("/api/workspaces/{id}/events", get(events::list))
        .route("/api/workspaces/{id}/events/stream", get(events::stream))
        .route("/api/checkpoints/{id}/restore", post(checkpoints::restore))
        .route("/api/checkpoints/{id}/publish", post(remote::publish))
        .route("/api/checkpoints/{id}/abandon", post(remote_gc::abandon))
}
