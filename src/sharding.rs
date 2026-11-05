//! Track 4: Multi-Node Consistent Shard Routing, Primary Lease & Epoch/Generation Storage Fencing,
//! Automated 4-Stage Failover Takeover, and Read-Only Degradation Drills.
pub mod failover;
pub mod fencing;
pub mod models;
pub mod router;

use crate::AppState;
use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

pub const MIGRATION_060_SQL: &str = include_str!("sharding/060_sharding_fencing.sql");

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/shards/nodes",
            get(router::list_nodes).post(router::upsert_node),
        )
        .route(
            "/api/shards/nodes/{node_id}",
            get(router::get_node).patch(router::patch_node),
        )
        .route(
            "/api/shards/nodes/{node_id}/lease",
            post(router::renew_node_lease),
        )
        .route(
            "/api/shards/buckets",
            get(router::list_buckets).post(router::upsert_bucket),
        )
        .route(
            "/api/repos/{owner}/{name}/shard-route",
            get(router::get_repo_route).put(router::configure_repo_route),
        )
        .route(
            "/api/repos/{owner}/{name}/shard-route/resolve",
            get(router::resolve_repo_route),
        )
        .route(
            "/api/repos/{owner}/{name}/shard-fence",
            get(fencing::get_fence_status).post(fencing::apply_or_verify_fence),
        )
        .route(
            "/api/repos/{owner}/{name}/shard-failover",
            get(failover::list_failovers).post(failover::execute_failover),
        )
        .route(
            "/api/repos/{owner}/{name}/shard-degrade",
            post(failover::degrade_or_recover_repo),
        )
}
