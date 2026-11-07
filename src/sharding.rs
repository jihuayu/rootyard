//! Track 4: Multi-Node Consistent Shard Routing, Primary Lease & Epoch/Generation Storage Fencing,
//! Automated 4-Stage Failover Takeover, and Read-Only Degradation Drills.
pub mod benchmark;
pub mod controller;
pub mod failover;
pub mod faults;
pub mod fencing;
pub mod local_fence;
mod locks;
pub mod migration;
pub mod models;
pub mod rebalance;
pub mod replication;
pub mod replication_target;
pub mod router;
mod routes;
pub mod security;
pub mod sidecar;
pub mod transitions;
pub mod transport;

use crate::AppState;
use axum::Router;
use std::sync::Arc;

pub const MIGRATION_060_SQL: &str = include_str!("sharding/060_sharding_fencing.sql");

pub fn routes() -> Router<Arc<AppState>> {
    routes::routes()
}
