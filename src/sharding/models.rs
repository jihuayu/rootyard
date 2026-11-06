//! Data models, deterministic 1024-virtual-bucket hashing, validators, and schema initialization
//! for Track 4 Multi-Node Sharding Routing & Lease/Epoch Storage Fencing.
use crate::{AppState, Error, auth, db::Identity};
use axum::{
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::{Object, Pool};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_postgres::Row;
use uuid::Uuid;

pub type RepoState = crate::db::Repository;
pub type RepoRole = crate::auth::Role;

pub const VIRTUAL_BUCKET_COUNT: i32 = 1024;
pub const VOLUME_FENCE_MARKER_FILE: &str = "rootyard-shard-fence.json";
pub const DEFAULT_NODE_ID: &str = "shard-primary-0";
pub const DEFAULT_NODE_ENDPOINT: &str = "http://127.0.0.1:8080";
pub const DEFAULT_CAPACITY_BYTES: i64 = 107_374_182_400;
pub const DEFAULT_LEASE_TTL_SECONDS: i64 = 60;

pub const SHARD_NODE_FIELDS: &str = "node_id,endpoint,role,status,capacity_bytes,used_bytes,lease_epoch,lease_expires_unix,fenced_epoch,version,created_at::text,updated_at::text";
pub const BUCKET_FIELDS: &str =
    "bucket_id,primary_node_id,read_replica_nodes,route_epoch,updated_at::text";
pub const REPO_ROUTE_FIELDS: &str = "tenant_id,repository_id,bucket_id,primary_node_id,read_replica_nodes,replica_watermarks,explicit_override,route_epoch,fencing_token,fenced_epoch,draining,read_only_degraded,degraded_reason,in_flight_writes,required_generation,required_op_sequence,version,created_at::text,updated_at::text";
pub const FAILOVER_OP_FIELDS: &str = "id,tenant_id,repository_id,old_primary_node_id,new_primary_node_id,old_route_epoch,new_route_epoch,fencing_token,storage_generation,state,reason,snapshot,created_at::text,updated_at::text";

const fn default_one() -> i64 {
    1
}

pub const fn conflict(msg: &'static str) -> Error {
    Error(StatusCode::CONFLICT, msg)
}

pub const fn forbidden(msg: &'static str) -> Error {
    Error(StatusCode::FORBIDDEN, msg)
}

pub fn json(status: StatusCode, value: impl Serialize) -> Response {
    match serde_json::to_vec(&value) {
        Ok(bytes) => (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response(),
        Err(err) => Error::internal(err).into_response(),
    }
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub async fn open_client(state: &AppState, headers: &HeaderMap) -> Result<(Identity, Object), Error> {
    ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, headers).await?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    Ok((actor, client))
}

/// Maps a repository UUID deterministically to a virtual bucket in `0..1024`
/// using domain-separated SHA-256 (`"rootyard-shard-bucket-v1\0"` + 16 raw UUID bytes).
pub fn deterministic_bucket_id(repo_id: Uuid) -> i32 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"rootyard-shard-bucket-v1\0");
    hasher.update(repo_id.as_bytes());
    let digest = hasher.finalize();
    let raw = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    (raw % (VIRTUAL_BUCKET_COUNT as u32)) as i32
}

pub fn valid_node_id(node_id: &str) -> bool {
    let b = node_id.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(*c, b'.' | b'_' | b'-'))
}

pub fn valid_endpoint(endpoint: &str) -> bool {
    let trimmed = endpoint.trim();
    !trimmed.is_empty() && endpoint.len() <= 512 && !endpoint.chars().any(char::is_control)
}

pub fn valid_node_role(role: &str) -> bool {
    matches!(role, "primary" | "replica" | "draining" | "fenced")
}

pub fn valid_node_status(status: &str) -> bool {
    matches!(status, "healthy" | "degraded" | "draining" | "fenced" | "offline")
}

pub fn valid_route_op(op: &str) -> bool {
    matches!(op, "read" | "write" | "merge_check" | "strong")
}

pub fn valid_replica_list(primary_node_id: &str, replicas: &[String]) -> bool {
    if replicas.len() > 16 {
        return false;
    }
    let mut seen = HashSet::with_capacity(replicas.len());
    replicas
        .iter()
        .all(|n| valid_node_id(n) && n != primary_node_id && seen.insert(n.as_str()))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardNode {
    pub node_id: String,
    pub endpoint: String,
    pub role: String,
    pub status: String,
    pub capacity_bytes: i64,
    pub used_bytes: i64,
    pub lease_epoch: i64,
    pub lease_expires_unix: i64,
    pub fenced_epoch: i64,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl ShardNode {
    pub fn row(row: &Row) -> Self {
        Self {
            node_id: row.get(0),
            endpoint: row.get(1),
            role: row.get(2),
            status: row.get(3),
            capacity_bytes: row.get(4),
            used_bytes: row.get(5),
            lease_epoch: row.get(6),
            lease_expires_unix: row.get(7),
            fenced_epoch: row.get(8),
            version: row.get(9),
            created_at: row.get(10),
            updated_at: row.get(11),
        }
    }

    pub fn is_lease_active(&self, now_unix: i64) -> bool {
        self.lease_expires_unix == 0 || now_unix <= self.lease_expires_unix
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertNodeInput {
    pub node_id: String,
    pub endpoint: String,
    pub role: Option<String>,
    pub status: Option<String>,
    pub capacity_bytes: Option<i64>,
    pub used_bytes: Option<i64>,
    pub lease_ttl_seconds: Option<i64>,
    pub now_unix: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchNodeInput {
    pub endpoint: Option<String>,
    pub role: Option<String>,
    pub status: Option<String>,
    pub capacity_bytes: Option<i64>,
    pub used_bytes: Option<i64>,
    pub expected_version: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeLeaseInput {
    pub lease_ttl_seconds: Option<i64>,
    pub expected_lease_epoch: Option<i64>,
    pub bump_epoch: Option<bool>,
    pub now_unix: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodesQuery {
    pub role: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VirtualBucket {
    pub bucket_id: i32,
    pub primary_node_id: String,
    pub read_replica_nodes: Vec<String>,
    pub route_epoch: i64,
    pub updated_at: String,
}

impl VirtualBucket {
    pub fn row(row: &Row) -> Self {
        Self {
            bucket_id: row.get(0),
            primary_node_id: row.get(1),
            read_replica_nodes: serde_json::from_value(row.get(2)).unwrap_or_default(),
            route_epoch: row.get(3),
            updated_at: row.get(4),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpsertBucketInput {
    pub bucket_id: i32,
    pub primary_node_id: String,
    pub read_replica_nodes: Option<Vec<String>>,
    pub expected_route_epoch: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BucketsQuery {
    pub primary_node_id: Option<String>,
    pub limit: Option<i64>,
    pub after_bucket: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplicaWatermark {
    #[serde(default = "default_one")]
    pub storage_generation: i64,
    #[serde(default)]
    pub op_sequence: i64,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub updated_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoShardRoute {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub bucket_id: i32,
    pub primary_node_id: String,
    pub read_replica_nodes: Vec<String>,
    pub replica_watermarks: BTreeMap<String, ReplicaWatermark>,
    pub explicit_override: bool,
    pub route_epoch: i64,
    pub fencing_token: i64,
    pub fenced_epoch: i64,
    pub draining: bool,
    pub read_only_degraded: bool,
    pub degraded_reason: String,
    pub in_flight_writes: i64,
    pub required_generation: i64,
    pub required_op_sequence: i64,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl RepoShardRoute {
    pub fn row(row: &Row) -> Self {
        Self {
            tenant_id: row.get(0),
            repository_id: row.get(1),
            bucket_id: row.get(2),
            primary_node_id: row.get(3),
            read_replica_nodes: serde_json::from_value(row.get(4)).unwrap_or_default(),
            replica_watermarks: serde_json::from_value(row.get(5)).unwrap_or_default(),
            explicit_override: row.get(6),
            route_epoch: row.get(7),
            fencing_token: row.get(8),
            fenced_epoch: row.get(9),
            draining: row.get(10),
            read_only_degraded: row.get(11),
            degraded_reason: row.get(12),
            in_flight_writes: row.get(13),
            required_generation: row.get(14),
            required_op_sequence: row.get(15),
            version: row.get(16),
            created_at: row.get(17),
            updated_at: row.get(18),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigureRouteInput {
    pub primary_node_id: Option<String>,
    pub read_replica_nodes: Option<Vec<String>>,
    pub replica_watermarks: Option<BTreeMap<String, ReplicaWatermark>>,
    pub explicit_override: Option<bool>,
    pub required_generation: Option<i64>,
    pub required_op_sequence: Option<i64>,
    pub in_flight_writes: Option<i64>,
    pub expected_route_epoch: Option<i64>,
    pub expected_version: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveRouteQuery {
    pub op: Option<String>,
    pub client_route_epoch: Option<i64>,
    pub min_generation: Option<i64>,
    pub min_op_sequence: Option<i64>,
    pub now_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteResolution {
    pub repository_id: Uuid,
    pub bucket_id: i32,
    pub operation: String,
    pub target_node_id: String,
    pub target_endpoint: String,
    pub target_role: String,
    pub primary_node_id: String,
    pub route_epoch: i64,
    pub fencing_token: i64,
    pub fenced_epoch: i64,
    pub storage_generation: i64,
    pub required_op_sequence: i64,
    pub fallback_to_primary: bool,
    pub read_only_degraded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VolumeFenceMarker {
    pub version: i32,
    pub repository_id: Uuid,
    pub primary_node_id: String,
    pub route_epoch: i64,
    pub fencing_token: i64,
    pub fenced_epoch: i64,
    pub storage_generation: i64,
    pub fenced_node_id: Option<String>,
    pub read_only_degraded: bool,
    pub updated_unix: i64,
}

impl VolumeFenceMarker {
    pub fn from_route(
        route: &RepoShardRoute,
        storage_generation: i64,
        fenced_node_id: Option<String>,
        updated_unix: i64,
    ) -> Self {
        Self {
            version: 1,
            repository_id: route.repository_id,
            primary_node_id: route.primary_node_id.clone(),
            route_epoch: route.route_epoch,
            fencing_token: route.fencing_token,
            fenced_epoch: route.fenced_epoch,
            storage_generation,
            fenced_node_id,
            read_only_degraded: route.read_only_degraded,
            updated_unix,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FenceActionInput {
    pub action: String,
    pub writer_node_id: Option<String>,
    pub writer_route_epoch: Option<i64>,
    pub writer_fencing_token: Option<i64>,
    pub writer_storage_generation: Option<i64>,
    pub fenced_epoch: Option<i64>,
    pub storage_generation: Option<i64>,
    pub fenced_node_id: Option<String>,
    pub reason: Option<String>,
    pub now_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FenceStatusResponse {
    pub repository_id: Uuid,
    pub primary_node_id: String,
    pub route_epoch: i64,
    pub fencing_token: i64,
    pub fenced_epoch: i64,
    pub storage_generation: i64,
    pub draining: bool,
    pub read_only_degraded: bool,
    pub write_admitted: bool,
    pub volume_marker: Option<VolumeFenceMarker>,
}

impl FenceStatusResponse {
    pub fn from_route(
        route: &RepoShardRoute,
        storage_generation: i64,
        write_admitted: bool,
        volume_marker: Option<VolumeFenceMarker>,
    ) -> Self {
        Self {
            repository_id: route.repository_id,
            primary_node_id: route.primary_node_id.clone(),
            route_epoch: route.route_epoch,
            fencing_token: route.fencing_token,
            fenced_epoch: route.fenced_epoch,
            storage_generation,
            draining: route.draining,
            read_only_degraded: route.read_only_degraded,
            write_admitted,
            volume_marker,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverOperation {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub old_primary_node_id: String,
    pub new_primary_node_id: String,
    pub old_route_epoch: i64,
    pub new_route_epoch: i64,
    pub fencing_token: i64,
    pub storage_generation: i64,
    pub state: String,
    pub reason: String,
    pub snapshot: Value,
    pub created_at: String,
    pub updated_at: String,
}

impl FailoverOperation {
    pub fn row(row: &Row) -> Self {
        Self {
            id: row.get(0),
            tenant_id: row.get(1),
            repository_id: row.get(2),
            old_primary_node_id: row.get(3),
            new_primary_node_id: row.get(4),
            old_route_epoch: row.get(5),
            new_route_epoch: row.get(6),
            fencing_token: row.get(7),
            storage_generation: row.get(8),
            state: row.get(9),
            reason: row.get(10),
            snapshot: row.get(11),
            created_at: row.get(12),
            updated_at: row.get(13),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailoverInput {
    pub new_primary_node_id: String,
    pub reason: Option<String>,
    pub expected_route_epoch: Option<i64>,
    pub force_drain: Option<bool>,
    pub bump_generation: Option<bool>,
    pub now_unix: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DegradeDrillInput {
    pub mode: String,
    pub reason: Option<String>,
    pub now_unix: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradeDrillResponse {
    pub repository_id: Uuid,
    pub mode: String,
    pub read_only_degraded: bool,
    pub degraded_reason: String,
    pub primary_node_id: String,
    pub route_epoch: i64,
    pub fencing_token: i64,
    pub write_admitted: bool,
    pub volume_marker: Option<VolumeFenceMarker>,
}

/// Idempotently initializes the Track 4 sharding & fencing tables under an advisory lock.
pub async fn ensure_schema(pool: &Pool) -> Result<(), Error> {
    let mut client = pool.get().await.map_err(Error::internal)?;
    let sql = "SELECT to_regclass('shard_nodes') IS NOT NULL AND to_regclass('shard_virtual_buckets') IS NOT NULL AND to_regclass('repository_shard_routes') IS NOT NULL AND to_regclass('shard_failover_operations') IS NOT NULL";
    if client.query_one(sql, &[]).await.map_err(Error::internal)?.get::<_, bool>(0) {
        return Ok(());
    }
    let tx = client.transaction().await.map_err(Error::internal)?;
    tx.execute("SELECT pg_advisory_xact_lock(600602026)", &[]).await.map_err(Error::internal)?;
    let ddl = crate::sharding::MIGRATION_060_SQL
        .split("INSERT INTO schema_migrations")
        .next()
        .unwrap_or(crate::sharding::MIGRATION_060_SQL);
    tx.batch_execute(ddl).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_bucket_id_and_validators() {
        let nil = Uuid::nil();
        assert!((0..VIRTUAL_BUCKET_COUNT).contains(&deterministic_bucket_id(nil)));
        assert_eq!(deterministic_bucket_id(nil), deterministic_bucket_id(nil));
        assert!(valid_node_id("shard-node-a") && !valid_node_id("") && !valid_node_id("UPPER"));
        assert!(valid_replica_list("node-a", &["node-b".into()]) && !valid_replica_list("node-a", &["node-a".into()]));
        let bad = r#"{"node_id":"node-a","endpoint":"http://127.0.0.1:9000","extra":1}"#;
        assert!(serde_json::from_str::<UpsertNodeInput>(bad).is_err());
    }
}
