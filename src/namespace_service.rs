//! Immutable repository namespace revisions and Git view projection service.
#[path = "namespace_service/handlers.rs"]
mod handlers;
#[path = "namespace_service/views.rs"]
mod views;

use crate::AppState;
use axum::{Router,routing::{get,post}};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/namespaces",post(handlers::create))
        .route("/api/namespaces/{id}",get(handlers::get))
        .route("/api/namespaces/{id}/views",post(views::create))
        .route("/api/views/{id}",get(views::get))
        .route("/api/views/{id}/bundle",get(views::bundle))
}
