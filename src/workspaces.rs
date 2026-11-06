//! Persistent, repository-authorized native workspaces.
#[path = "workspaces/models.rs"]
mod models;
#[path = "workspaces/service.rs"]
mod service;
#[path = "workspaces/files.rs"]
mod files;
#[path = "workspaces/checkpoints.rs"]
mod checkpoints;
#[path = "workspaces/events.rs"]
mod events;

use crate::AppState;
use axum::{Router, routing::{get, post}};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/workspaces", post(service::create))
        .route("/api/workspaces/{id}", get(service::get))
        .route("/api/workspaces/{id}/fork", post(checkpoints::fork))
        .route("/api/workspaces/{id}/files", get(files::get).put(files::put))
        .route("/api/workspaces/{id}/git", post(files::git))
        .route("/api/workspaces/{id}/checkpoints", post(checkpoints::create))
        .route("/api/workspaces/{id}/events", get(events::list))
        .route("/api/workspaces/{id}/events/stream", get(events::stream))
        .route("/api/checkpoints/{id}/restore", post(checkpoints::restore))
}
