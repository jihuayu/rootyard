//! Persistent, repository-authorized native workspaces.
#[path = "workspaces/capture.rs"]
pub mod capture;
#[path = "workspaces/checkpoints.rs"]
mod checkpoints;
#[path = "workspaces/events.rs"]
mod events;
#[path = "workspaces/files.rs"]
mod files;
#[path = "workspaces/models.rs"]
mod models;
#[path = "workspaces/remote.rs"]
mod remote;
#[path = "workspaces/remote_gc.rs"]
mod remote_gc;
#[path = "workspaces/service.rs"]
pub(crate) mod service;

use crate::AppState;
use axum::{
    routing::{get, post},
    Router,
};
pub use service::fence_restored;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/workspaces", post(service::create))
        .route("/api/workspaces/{id}", get(service::get))
        .route("/api/workspaces/{id}/lease", post(service::lease))
        .route("/api/workspaces/{id}/fork", post(checkpoints::fork))
        .route(
            "/api/workspaces/{id}/files",
            get(files::get).put(files::put),
        )
        .route("/api/workspaces/{id}/git", post(files::git))
        .route(
            "/api/workspaces/{id}/checkpoints",
            post(checkpoints::create),
        )
        .route("/api/workspaces/{id}/events", get(events::list))
        .route("/api/workspaces/{id}/events/stream", get(events::stream))
        .route("/api/checkpoints/{id}/restore", post(checkpoints::restore))
        .route("/api/checkpoints/{id}/publish", post(remote::publish))
        .route("/api/checkpoints/{id}/abandon", post(remote_gc::abandon))
}
