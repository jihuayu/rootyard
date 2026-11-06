//! Track 2B: Git LFS Batch API and verified streaming object transfers.
pub mod handlers;
pub mod locks;
pub mod models;
pub mod publication;
pub mod storage;
mod upload;
pub const MIGRATION_020_SQL: &str = include_str!("lfs/020_lfs_objects.sql");

mod routes;
use crate::AppState;
use axum::Router;
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> { routes::routes() }
