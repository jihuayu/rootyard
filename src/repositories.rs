//! Repository discovery and creation routes.
mod handlers;
use crate::AppState;
use axum::{
    Router,
    routing::{get, post},
};
pub use handlers::recover;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/repos", post(handlers::create_repo).get(handlers::list_repos))
        .route("/api/repos/{owner}/{name}", get(handlers::get_repo))
}
