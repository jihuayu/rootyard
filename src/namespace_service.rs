//! Immutable repository namespace revisions and Git view projection service.
#[path = "namespace_service/changesets.rs"]
mod changesets;
#[path = "namespace_service/handlers.rs"]
mod handlers;
#[path = "namespace_service/views.rs"]
mod views;

use crate::AppState;
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/namespaces", post(handlers::create))
        .route("/api/namespaces/{id}", get(handlers::get))
        .route("/api/namespaces/{id}/views", post(views::create))
        .route("/api/views/{id}", get(views::get))
        .route("/api/views/{id}/bundle", get(views::bundle))
        .route("/api/namespaces/{id}/changesets", post(changesets::create))
        .route("/api/changesets/{id}", get(changesets::get))
        .route("/api/changesets/{id}/review", post(changesets::review))
        .route(
            "/api/changesets/{id}/integrate",
            post(changesets::integrate),
        )
        .route("/api/changesets/{id}/recover", post(changesets::recover))
}
