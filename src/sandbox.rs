//! Bubblewrap process isolation for Agent and CI jobs.
#[path = "sandbox/handlers.rs"]
mod handlers;
#[path = "sandbox/runner.rs"]
mod runner;
#[path = "sandbox/ci.rs"]
pub mod ci;

use crate::AppState;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs", post(ci::start))
        .route("/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}", get(ci::status).delete(ci::cancel))
        .route("/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}/logs", get(ci::logs))
        .route("/api/workspaces/{id}/sandbox-jobs", post(handlers::start))
        .route("/api/sandbox-jobs/{id}", get(handlers::status))
        .route("/api/sandbox-jobs/{id}/stop", post(handlers::stop))
        .route("/api/sandbox-jobs/{id}/logs", get(handlers::logs))
        .route("/api/sandbox-jobs/{id}/artifacts", get(handlers::artifact))
}
pub use runner::reconcile_startup;
