//! Bubblewrap process isolation for Agent and CI jobs.
#[path = "sandbox/ci.rs"]
pub mod ci;
#[path = "sandbox/handlers.rs"]
mod handlers;
#[path = "sandbox/runner.rs"]
mod runner;
#[path = "sandbox/terminal.rs"]
mod terminal;

use crate::AppState;
use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs", post(ci::start))
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}",
            get(ci::status).delete(ci::cancel),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}/logs",
            get(ci::logs),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}/terminal/input",
            post(ci::terminal_input),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}/terminal/output",
            get(ci::terminal_output),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/sandbox-jobs/{job_id}/terminal/resize",
            post(ci::terminal_resize),
        )
        .route("/api/workspaces/{id}/sandbox-jobs", post(handlers::start))
        .route("/api/sandbox-jobs/{id}", get(handlers::status))
        .route("/api/sandbox-jobs/{id}/stop", post(handlers::stop))
        .route("/api/sandbox-jobs/{id}/logs", get(handlers::logs))
        .route("/api/sandbox-jobs/{id}/artifacts", get(handlers::artifact))
        .route("/api/sandbox-jobs/{id}/terminal/input", post(handlers::terminal_input))
        .route("/api/sandbox-jobs/{id}/terminal/output", get(handlers::terminal_output))
        .route("/api/sandbox-jobs/{id}/terminal/resize", post(handlers::terminal_resize))
}
pub use runner::reconcile_startup;
