//! Track 4: Multi-Node Consistent Shard Routing, Primary Lease & Epoch/Generation Storage Fencing,
//! Automated 4-Stage Failover Takeover, and Read-Only Degradation Drills.
pub mod benchmark;
pub mod failover;
pub mod fencing;
pub mod models;
pub mod rebalance;
pub mod router;
pub mod security;
pub mod transitions;
pub mod transport;
pub mod migration;
pub mod local_fence;
pub mod controller;

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
            "/api/shards/rebalance",
            get(rebalance::list_rebalances).post(rebalance::execute_rebalance),
        )
        .route("/api/repos/{owner}/{name}/shard-migrate", post(migration::migrate_repository))
        .route("/internal/shards/{repo_id}/snapshot/{op_id}", post(migration::receive_snapshot))
        .route(
            "/api/shards/benchmark",
            get(benchmark::list_cluster_benchmarks).post(benchmark::run_cluster_benchmark),
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
        .route(
            "/api/repos/{owner}/{name}/shard-dr-drill",
            get(rebalance::list_dr_drills).post(rebalance::execute_dr_drill),
        )
        .route(
            "/api/repos/{owner}/{name}/shard-benchmark",
            get(benchmark::list_repo_benchmarks).post(benchmark::run_repo_benchmark),
        )
}
