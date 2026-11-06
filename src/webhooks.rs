//! Track A: External CI Webhooks, HMAC-SHA256 Delivery & Auto PR CI Pipeline Orchestration.
pub mod delivery;
pub mod claims;
pub mod background;
pub mod trust;
pub mod runs;
pub mod mirrors;
pub mod handlers;
pub mod models;
pub mod signing;

use crate::AppState;
use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

pub const MIGRATION_040_SQL: &str = include_str!("webhooks/040_webhooks.sql");

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/repos/{owner}/{name}/webhooks",
            get(handlers::list_webhooks).post(handlers::create_webhook),
        )
        .route(
            "/api/repos/{owner}/{name}/webhooks/dispatch",
            post(handlers::dispatch_webhooks),
        )
        .route(
            "/api/repos/{owner}/{name}/webhooks/{hook_id}",
            get(handlers::get_webhook)
                .patch(handlers::update_webhook)
                .delete(handlers::delete_webhook),
        )
        .route(
            "/api/repos/{owner}/{name}/webhooks/{hook_id}/ping",
            post(handlers::ping_webhook),
        )
        .route(
            "/api/repos/{owner}/{name}/webhooks/{hook_id}/callback",
            post(handlers::ci_callback),
        )
        .route(
            "/api/repos/{owner}/{name}/webhooks/{hook_id}/deliveries",
            get(handlers::list_deliveries),
        )
        .route(
            "/api/repos/{owner}/{name}/webhooks/{hook_id}/deliveries/{delivery_id}",
            get(handlers::get_delivery),
        )
        .route(
            "/api/repos/{owner}/{name}/webhooks/{hook_id}/deliveries/{delivery_id}/retry",
            post(handlers::retry_delivery),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/check-runs",
            post(handlers::ci_callback),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/trusted-contexts",
            axum::routing::put(trust::bind).delete(trust::revoke),
        )
        .route(
            "/api/repos/{owner}/{name}/ci-source-grants/{hook_id}",
            axum::routing::put(trust::source_grant).delete(trust::source_revoke),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/claim",
            post(runs::claim),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/report",
            post(runs::report),
        )
        .route(
            "/api/repos/{owner}/{name}/integrations/{hook_id}/runs/{run_id}/heartbeat",
            post(runs::heartbeat),
        )
        .route(
            "/api/repos/{owner}/{name}/ci-mirrors/{mirror_id}/heartbeat",
            post(mirrors::heartbeat),
        )
}
