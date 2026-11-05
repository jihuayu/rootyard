//! Track 2A: read-only repository browsing and atomic multi-ref CAS transactions.
pub mod git_read;
pub mod handlers;
pub mod models;
pub mod transactions;

use crate::AppState;
use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/repos/{owner}/{name}/refs", get(handlers::list_refs))
        .route(
            "/api/repos/{owner}/{name}/commits",
            get(handlers::list_commits),
        )
        .route(
            "/api/repos/{owner}/{name}/commits/{oid}",
            get(handlers::get_commit),
        )
        .route("/api/repos/{owner}/{name}/tree", get(handlers::get_tree))
        .route(
            "/api/repos/{owner}/{name}/tree/{oid}",
            get(handlers::get_tree_by_oid),
        )
        .route("/api/repos/{owner}/{name}/blob", get(handlers::get_blob))
        .route(
            "/api/repos/{owner}/{name}/blob/{oid}",
            get(handlers::get_blob_by_oid),
        )
        .route(
            "/api/repos/{owner}/{name}/compare",
            get(handlers::compare_commits),
        )
        .route(
            "/api/repos/{owner}/{name}/ref-transactions",
            post(transactions::execute_ref_transaction),
        )
        .route(
            "/api/repos/{owner}/{name}/storage-route",
            get(handlers::get_storage_route),
        )
}
