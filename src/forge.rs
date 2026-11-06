//! Repository Issue and comment HTTP API with tenant-scoped authorization.
#[path = "forge/backend.rs"]
mod backend;
#[path = "forge/handlers.rs"]
mod handlers;
#[path = "forge/comments.rs"]
mod comments;
pub(crate) use backend::build_backend_status;

use crate::AppState;
use axum::{Router, routing::get};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/repos/{owner}/{name}/issues", get(handlers::list_issues).post(handlers::create_issue))
        .route("/api/repos/{owner}/{name}/issues/{number}", get(handlers::get_issue).patch(handlers::update_issue))
        .route("/api/repos/{owner}/{name}/issues/{number}/comments", get(comments::list_comments).post(comments::create_comment))
        .route("/api/repos/{owner}/{name}/issues/{number}/comments/{comment_number}", get(comments::get_comment).patch(comments::update_comment))
        .route("/api/repos/{owner}/{name}/backend", get(backend::get_backend).patch(backend::set_backend))
}

#[cfg(test)]
#[path = "forge/tests.rs"]
mod tests;
