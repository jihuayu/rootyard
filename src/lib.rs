#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
#![allow(clippy::too_many_arguments, clippy::type_complexity)]

#[rustfmt::skip]
pub mod auth;
pub mod backup;
#[rustfmt::skip]
pub mod browse;
#[rustfmt::skip]
pub mod ci_checkouts;
#[rustfmt::skip]
pub mod ci_pins;
pub mod config;
pub mod db;
pub mod dispatch;
pub mod events;
#[rustfmt::skip]
pub mod forge;
pub mod git_http;
pub mod journal;
pub mod kafka_wake;
pub mod pando_gateway;
#[rustfmt::skip]
pub mod lfs;
pub mod maintenance;
#[rustfmt::skip]
pub mod members;
pub mod metrics;
pub mod metrics_workers;
pub mod namespace_service;
pub mod observability;
pub mod organizations;
pub mod pagination;
#[rustfmt::skip]
pub mod mirror;
#[rustfmt::skip]
pub mod pulls;
pub mod reliability;
pub mod sandbox;
#[rustfmt::skip]
pub mod sharding;
pub mod storage;
pub mod storage_lifecycle;
pub mod token_management;
#[rustfmt::skip]
pub mod token_scopes;
pub mod view_lab;
pub mod workspace_lab;
pub mod workspaces;
#[rustfmt::skip]
pub mod web;
#[rustfmt::skip]
pub mod webhooks;

mod application;
pub mod repositories;
pub use application::{AppState, Error};
use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    routing::get,
};
pub use repositories::recover;
use std::sync::Arc;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(application::ready))
        .merge(repositories::routes())
        .merge(browse::routes(state.clone()))
        .merge(ci_pins::routes())
        .merge(ci_checkouts::routes())
        .merge(reliability::routes())
        .merge(storage_lifecycle::routes())
        .merge(forge::routes())
        .merge(pulls::routes())
        .merge(lfs::routes())
        .merge(webhooks::routes())
        .merge(members::routes())
        .merge(organizations::routes())
        .merge(token_management::routes())
        .merge(web::routes(state.clone()))
        .merge(sharding::routes())
        .merge(workspaces::routes())
        .merge(sandbox::routes())
        .merge(namespace_service::routes())
        .fallback(|State(state): State<Arc<AppState>>, request| async move { git_http::handle(state, request).await })
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(axum::middleware::from_fn(observability::middleware))
        .with_state(state)
}
