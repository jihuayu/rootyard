//! Bubblewrap process isolation for Agent and CI jobs.
#[path = "sandbox/handlers.rs"]
mod handlers;
#[path = "sandbox/runner.rs"]
mod runner;

use crate::AppState;
use axum::{Router,routing::{get,post}};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/workspaces/{id}/sandbox-jobs",post(handlers::start))
        .route("/api/sandbox-jobs/{id}",get(handlers::status))
        .route("/api/sandbox-jobs/{id}/stop",post(handlers::stop))
        .route("/api/sandbox-jobs/{id}/logs",get(handlers::logs))
}
pub use runner::reconcile_startup;
