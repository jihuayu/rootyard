//! Track 2B: Git LFS Batch API and verified streaming object transfers.
pub mod handlers;
pub mod models;
pub mod publication;
pub mod storage;

use crate::AppState;
use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post, put},
};
use std::sync::Arc;

pub const MIGRATION_020_SQL: &str = include_str!("lfs/020_lfs_objects.sql");

pub fn routes() -> Router<Arc<AppState>> {
    let upload_routes = Router::new()
        .route("/git/{owner}/{name}/info/lfs/objects/{oid}", put(handlers::upload_object))
        .route("/git/{owner}/{name}/info/lfs/objects/{oid}/{size}", put(handlers::upload_object_with_size))
        .route("/{owner}/{name}/info/lfs/objects/{oid}", put(handlers::upload_object))
        .route("/{owner}/{name}/info/lfs/objects/{oid}/{size}", put(handlers::upload_object_with_size))
        .route("/api/repos/{owner}/{name}/lfs/objects/{oid}", put(handlers::upload_object))
        .route("/api/repos/{owner}/{name}/lfs/objects/{oid}/{size}", put(handlers::upload_object_with_size))
        .route("/api/repos/{owner}/{name}/info/lfs/objects/{oid}", put(handlers::upload_object))
        .route("/api/repos/{owner}/{name}/info/lfs/objects/{oid}/{size}", put(handlers::upload_object_with_size))
        .layer(DefaultBodyLimit::disable());

    Router::new()
        .route("/git/{owner}/{name}/info/lfs/objects/batch", post(handlers::batch))
        .route("/{owner}/{name}/info/lfs/objects/batch", post(handlers::batch))
        .route("/api/repos/{owner}/{name}/lfs/objects/batch", post(handlers::batch))
        .route("/api/repos/{owner}/{name}/info/lfs/objects/batch", post(handlers::batch))
        .route("/git/{owner}/{name}/info/lfs/verify", post(handlers::verify_object))
        .route("/{owner}/{name}/info/lfs/verify", post(handlers::verify_object))
        .route("/api/repos/{owner}/{name}/lfs/verify", post(handlers::verify_object))
        .route("/api/repos/{owner}/{name}/info/lfs/verify", post(handlers::verify_object))
        .route(
            "/git/{owner}/{name}/info/lfs/objects/{oid}",
            get(handlers::download_object).post(handlers::post_object_or_verify),
        )
        .route("/git/{owner}/{name}/info/lfs/objects/{oid}/{size}", get(handlers::download_object_with_size))
        .route(
            "/{owner}/{name}/info/lfs/objects/{oid}",
            get(handlers::download_object).post(handlers::post_object_or_verify),
        )
        .route("/{owner}/{name}/info/lfs/objects/{oid}/{size}", get(handlers::download_object_with_size))
        .route(
            "/api/repos/{owner}/{name}/lfs/objects/{oid}",
            get(handlers::download_object).post(handlers::post_object_or_verify),
        )
        .route("/api/repos/{owner}/{name}/lfs/objects/{oid}/{size}", get(handlers::download_object_with_size))
        .route(
            "/api/repos/{owner}/{name}/info/lfs/objects/{oid}",
            get(handlers::download_object).post(handlers::post_object_or_verify),
        )
        .route("/api/repos/{owner}/{name}/info/lfs/objects/{oid}/{size}", get(handlers::download_object_with_size))
        .merge(upload_routes)
}
