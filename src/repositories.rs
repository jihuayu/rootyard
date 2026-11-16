//! Repository discovery, creation, lifecycle, alias, purge, and transfer domain.
pub mod alias;
pub mod alias_middleware;
pub mod deletion_handlers;
mod handlers;
pub mod lifecycle;
pub mod lifecycle_handlers;
pub mod lifecycle_ops;
pub mod purge_db;
pub mod purge_exec;
pub mod purge_safety;
pub mod remote_copy;
pub mod transfer_db;
pub mod transfer_exec;
pub mod transfer_model;
pub mod transfer_phases;
pub mod transfer_remote;
use crate::AppState;
use axum::{
    Router,
    routing::{delete, get, post},
};
pub use handlers::recover;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/repos", post(handlers::create_repo).get(handlers::list_repos))
        .route("/api/repos/{owner}/{name}", get(handlers::get_repo).delete(deletion_handlers::delete_repo))
        .route("/api/repos/{owner}/{name}/lifecycle", get(lifecycle_handlers::get_lifecycle))
        .route("/api/repos/{owner}/{name}/archive", post(lifecycle_handlers::archive))
        .route("/api/repos/{owner}/{name}/unarchive", post(lifecycle_handlers::unarchive))
        .route("/api/repos/{owner}/{name}/rename", post(lifecycle_handlers::rename))
        .route("/api/repos/{owner}/{name}/restore", post(deletion_handlers::restore))
        .route("/api/repos/{owner}/{name}/purge", post(deletion_handlers::purge))
        .route("/api/repos/{owner}/{name}/aliases/{alias_owner}/{alias_name}", delete(deletion_handlers::delete_alias))
}
