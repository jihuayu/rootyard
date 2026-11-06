//! Online virtual-bucket & repository rebalance state machine (`drain -> sync -> fence -> cutover`)
//! and measured RPO/RTO disaster recovery drills (`GET/POST /api/repos/{owner}/{name}/shard-dr-drill`).
use crate::{
    AppState, Error,
    auth::{self, Role, finish_tx as finish},
    members::audit::record_audit_event,
    sharding::{
        failover::has_git_lock_files,
        transitions,
        security::require_operator,
        models::{
            self, BUCKET_FIELDS, REPO_ROUTE_FIELDS, RepoShardRoute,
            ShardNode, VIRTUAL_BUCKET_COUNT, VirtualBucket, VolumeFenceMarker, conflict, json,
            open_client, unix_now, valid_node_id,
        },
        router::{fetch_node, load_or_init_repo_route},
    },
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::json as sjson;
use std::{
    path::{Path as StdPath, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

pub const DR_DRILL_RECEIPT_FILE: &str = "rootyard-dr-drill.json";
pub const REBALANCE_LOG_FILE: &str = "rootyard-rebalances.json";
pub const REBALANCE_PHASES: [&str; 4] = ["drain", "sync", "fence", "cutover"];

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RebalanceRequest {
    pub bucket_id: u16,
    pub source_node_id: String,
    pub target_node_id: String,
    pub repository_id: Option<Uuid>,
    pub dry_run: Option<bool>,
    pub reason: Option<String>,
    #[serde(default)]
    pub now_unix: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RebalanceReceipt {
    pub id: Uuid,
    pub bucket_id: u16,
    pub source_node_id: String,
    pub target_node_id: String,
    pub repository_id: Option<Uuid>,
    pub dry_run: bool,
    pub state: String,
    pub phases: Vec<String>,
    pub old_route_epoch: i64,
    pub new_route_epoch: i64,
    pub fencing_token: i64,
    pub fenced_epoch: i64,
    pub storage_generation: i64,
    pub reason: String,
    pub volume_marker: Option<VolumeFenceMarker>,
    pub updated_unix: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RebalanceListResponse {
    pub items: Vec<RebalanceReceipt>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrDrillRequest {
    pub primary_node_id: String,
    pub standby_node_id: String,
    pub target_rpo_secs: i64,
    pub target_rto_ms: i64,
    pub simulated_lag_secs: Option<i64>,
    pub simulated_takeover_ms: Option<i64>,
    pub verify_rollback: Option<bool>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub now_unix: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrDrillReceipt {
    pub drill_id: Uuid,
    pub repository_id: Uuid,
    pub primary_node_id: String,
    pub standby_node_id: String,
    pub active_primary_node_id: String,
    pub target_rpo_secs: i64,
    pub target_rto_ms: i64,
    pub measured_rpo_secs: i64,
    pub measured_rto_ms: i64,
    pub rpo_met: bool,
    pub rto_met: bool,
    pub sla_met: bool,
    pub verify_rollback: bool,
    pub rolled_back: bool,
    pub write_admitted: bool,
    pub old_route_epoch: i64,
    pub new_route_epoch: i64,
    pub fencing_token: i64,
    pub storage_generation: i64,
    pub status: String,
    pub phases: Vec<String>,
    pub error: Option<String>,
    pub updated_unix: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrDrillListResponse {
    pub repository_id: Uuid,
    pub latest: Option<DrDrillReceipt>,
    pub items: Vec<DrDrillReceipt>,
}

pub fn validate_rebalance_target(source_node_id: &str, target: &ShardNode, now_unix: i64) -> Result<(), Error> {
    if source_node_id == target.node_id {
        return Err(conflict("source_node_id and target_node_id must differ"));
    }
    if target.status != "healthy" || target.role == "fenced" {
        return Err(conflict("target shard node is unhealthy or fenced"));
    }
    if target.lease_expires_unix <= now_unix {
        return Err(conflict("target shard node does not have an active lease"));
    }
    if target.used_bytes >= target.capacity_bytes {
        return Err(conflict("target shard node has insufficient capacity"));
    }
    Ok(())
}

pub fn evaluate_dr_drill_metrics(route: &RepoShardRoute, input: &DrDrillRequest, elapsed_ms: i64) -> (i64, i64, bool, bool) {
    let lag = input.simulated_lag_secs.unwrap_or_else(|| {
        route.replica_watermarks.get(&input.standby_node_id).map_or(0, |wm| (route.required_op_sequence - wm.op_sequence).max(0))
    });
    let rto = input.simulated_takeover_ms.unwrap_or_else(|| elapsed_ms.max(1));
    (lag, rto, lag <= input.target_rpo_secs, rto <= input.target_rto_ms)
}

fn rebalance_log_path(state: &AppState) -> PathBuf {
    state.storage.repo_path(Uuid::nil()).parent().map_or_else(|| PathBuf::from(REBALANCE_LOG_FILE), |p| p.join(REBALANCE_LOG_FILE))
}

fn read_rebalance_log(state: &AppState) -> Result<Vec<RebalanceReceipt>, Error> {
    let path = rebalance_log_path(state);
    if !crate::journal::exists(&path).map_err(|_| conflict("corrupt rebalance log"))? {
        return Ok(Vec::new());
    }
    let bytes = crate::journal::read(&path).map_err(|_| conflict("unreadable rebalance log"))?;
    serde_json::from_slice(&bytes).map_err(|_| conflict("malformed rebalance log"))
}

fn append_rebalance_log(state: &AppState, receipt: &RebalanceReceipt) -> Result<(), Error> {
    let path = rebalance_log_path(state);
    if path.parent().is_some_and(|p| !p.exists()) {
        return Ok(());
    }
    let mut items = read_rebalance_log(state)?;
    items.insert(0, receipt.clone());
    items.truncate(100);
    let bytes = serde_json::to_vec_pretty(&items).map_err(Error::internal)?;
    crate::journal::atomic(&path, &bytes, true).map_err(Error::internal)
}

pub fn read_dr_drill_receipt_at(repo_dir: &StdPath) -> Result<Option<DrDrillReceipt>, Error> {
    let path = repo_dir.join(DR_DRILL_RECEIPT_FILE);
    if !repo_dir.exists() || !crate::journal::exists(&path).map_err(|_| conflict("corrupt DR drill receipt"))? {
        return Ok(None);
    }
    let bytes = crate::journal::read(&path).map_err(|_| conflict("unreadable DR drill receipt"))?;
    serde_json::from_slice(&bytes).map(Some).map_err(|_| conflict("malformed DR drill receipt"))
}

pub fn write_dr_drill_receipt_at(repo_dir: &StdPath, receipt: &DrDrillReceipt) -> Result<(), Error> {
    if !repo_dir.exists() {
        return Ok(());
    }
    let bytes = serde_json::to_vec_pretty(receipt).map_err(Error::internal)?;
    crate::journal::atomic(&repo_dir.join(DR_DRILL_RECEIPT_FILE), &bytes, true).map_err(Error::internal)
}

pub async fn list_rebalances(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, Error> {
    let (actor, mut client) = open_client(&state, &headers).await?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, false).await?;
    let items = read_rebalance_log(&state)?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, RebalanceListResponse { items }))
}

pub async fn execute_rebalance(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<RebalanceRequest>,
) -> Result<Response, Error> {
    let (actor, mut client) = open_client(&state, &headers).await?;
    auth::writable(&actor)?;
    if i32::from(input.bucket_id) >= VIRTUAL_BUCKET_COUNT || !valid_node_id(&input.source_node_id) || !valid_node_id(&input.target_node_id) {
        return Err(Error::bad_request());
    }
    let reason = input.reason.clone().unwrap_or_else(|| "online bucket rebalance".to_string());
    if reason.trim().is_empty() || reason.len() > 1024 || reason.chars().any(char::is_control) {
        return Err(Error::bad_request());
    }
    if input.source_node_id == input.target_node_id {
        return Err(conflict("source_node_id and target_node_id must differ"));
    }
    let (now, dry_run, bucket_id) = (input.now_unix.unwrap_or_else(unix_now), input.dry_run.unwrap_or(false), i32::from(input.bucket_id));
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, !dry_run).await?;
    if !dry_run { require_operator(&tx, &actor).await?; }
    if !dry_run {
        return Err(conflict("rebalance requires measured repository transfer; use shard-migrate"));
    }
    let _source = fetch_node(&tx, &input.source_node_id).await?.ok_or_else(Error::not_found)?;
    let target = fetch_node(&tx, &input.target_node_id).await?.ok_or_else(Error::not_found)?;
    validate_rebalance_target(&input.source_node_id, &target, now)?;

    let b_sql = format!("SELECT {BUCKET_FIELDS} FROM shard_virtual_buckets WHERE bucket_id = $1 FOR UPDATE");
    let existing = tx.query_opt(&b_sql, &[&bucket_id]).await.map_err(Error::internal)?.map(|r| VirtualBucket::row(&r));
    if existing.as_ref().is_some_and(|b| b.primary_node_id != input.source_node_id) {
        return Err(conflict("bucket primary_node_id does not match source_node_id"));
    }
    let (old_b_epoch, new_b_epoch) = (existing.as_ref().map_or(1, |b| b.route_epoch), existing.as_ref().map_or(2, |b| b.route_epoch + 1));
    let b_rep_json = sjson!(existing.as_ref().map_or_else(Vec::<String>::new, |b| b.read_replica_nodes.iter().filter(|n| *n != &input.target_node_id).cloned().collect::<Vec<String>>()));
    let phases: Vec<String> = REBALANCE_PHASES.iter().map(|s| (*s).to_string()).collect();
    let (op_id, reason_trimmed) = (Uuid::new_v4(), reason.trim().to_string());
    let (mut old_ep, mut new_ep, mut token, mut fenced_ep, mut st_gen, mut marker) =
        (old_b_epoch, new_b_epoch, new_b_epoch, old_b_epoch, 1_i64, None);

    if let Some(repo_id) = input.repository_id {
        let deadline = tokio::time::Instant::now() + state.config.git_timeout;
        let lease = crate::storage::read_leases::shared(&state.pool, repo_id, deadline).await?;
        let _gate = tokio::time::timeout_at(deadline, state.storage.read_snapshot_lock(repo_id))
            .await.map_err(|_| Error::timeout())?;
        lease.ensure_active()?;
        let meta = tx.query_opt("SELECT u.username, r.name, r.storage_generation FROM repositories r JOIN users u ON u.id = r.owner_id WHERE r.id = $1 FOR UPDATE", &[&repo_id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
        let (owner_name, repo_name, repo_gen): (String, String, i64) = (meta.get(0), meta.get(1), meta.get(2));
        let access = auth::authorize_repo_with_role(&tx, &actor, &owner_name, &repo_name, Role::Admin).await?;
        let repo_dir = state.storage.verify_path(repo_id).map_err(|_| conflict("bare Git repository volume verification failed"))?;
        let route = load_or_init_repo_route(&tx, access.owner_id, repo_id).await?;
        if route.primary_node_id != input.source_node_id {
            return Err(conflict("repository primary_node_id does not match source_node_id"));
        }
        if route.in_flight_writes > 0 || has_git_lock_files(&repo_dir) {
            return Err(conflict("cannot drain repository with active in-flight writes or Git lock files"));
        }
        lease.ensure_active()?;
        (old_ep, new_ep, token, fenced_ep, st_gen) = (route.route_epoch, route.route_epoch + 1, route.fencing_token.max(route.route_epoch) + 1, route.route_epoch, repo_gen + 1);
        if !dry_run {
            tx.execute("INSERT INTO shard_virtual_buckets (bucket_id, primary_node_id, read_replica_nodes, route_epoch) VALUES ($1, $2, $3, $4) ON CONFLICT (bucket_id) DO UPDATE SET primary_node_id = $2, read_replica_nodes = $3, route_epoch = shard_virtual_buckets.route_epoch + 1, updated_at = clock_timestamp()", &[&bucket_id, &input.target_node_id, &b_rep_json, &new_b_epoch]).await.map_err(Error::internal)?;
            tx.execute("UPDATE shard_nodes SET role = 'primary', status = 'healthy', lease_epoch = GREATEST(lease_epoch, $2), version = version + 1, updated_at = clock_timestamp() WHERE node_id = $1", &[&input.target_node_id, &new_ep]).await.map_err(Error::internal)?;
            tx.execute("UPDATE repositories SET storage_generation = storage_generation + 1 WHERE id = $1", &[&repo_id]).await.map_err(Error::internal)?;
            let rem_json = sjson!(route.read_replica_nodes.iter().filter(|n| *n != &input.target_node_id).cloned().collect::<Vec<String>>());
            let upd = format!("UPDATE repository_shard_routes SET bucket_id = $3, primary_node_id = $4, read_replica_nodes = $5, explicit_override = true, route_epoch = route_epoch + 1, fencing_token = GREATEST(fencing_token, route_epoch) + 1, fenced_epoch = route_epoch, draining = false, read_only_degraded = false, degraded_reason = '', in_flight_writes = 0, required_generation = $6, version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND repository_id = $2 RETURNING {REPO_ROUTE_FIELDS}");
            let r_row = tx.query_one(&upd, &[&access.owner_id, &repo_id, &bucket_id, &input.target_node_id, &rem_json, &st_gen]).await.map_err(Error::internal)?;
            let updated = RepoShardRoute::row(&r_row);
            (new_ep, token, fenced_ep) = (updated.route_epoch, updated.fencing_token, updated.fenced_epoch);
            let m = VolumeFenceMarker::from_route(&updated, st_gen, Some(input.source_node_id.clone()), now);
            marker = Some(m);
            let snap = sjson!({ "operation": "rebalance", "bucket_id": input.bucket_id, "phases": REBALANCE_PHASES, "source_node_id": input.source_node_id, "target_node_id": input.target_node_id, "old_route_epoch": old_ep, "new_route_epoch": new_ep, "fencing_token": token, "storage_generation": st_gen });
            tx.execute("INSERT INTO shard_failover_operations (id, tenant_id, repository_id, old_primary_node_id, new_primary_node_id, old_route_epoch, new_route_epoch, fencing_token, storage_generation, state, reason, snapshot) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'promoted', $10, $11)", &[&op_id, &access.owner_id, &repo_id, &input.source_node_id, &input.target_node_id, &old_ep, &new_ep, &token, &st_gen, &reason_trimmed, &snap]).await.map_err(Error::internal)?;
            record_audit_event(&tx, access.owner_id, repo_id, &actor, "shard.rebalanced", "shard_rebalance", &input.target_node_id, snap).await?;
        }
    } else if !dry_run {
        tx.execute("INSERT INTO shard_virtual_buckets (bucket_id, primary_node_id, read_replica_nodes, route_epoch) VALUES ($1, $2, $3, $4) ON CONFLICT (bucket_id) DO UPDATE SET primary_node_id = $2, read_replica_nodes = $3, route_epoch = shard_virtual_buckets.route_epoch + 1, updated_at = clock_timestamp()", &[&bucket_id, &input.target_node_id, &b_rep_json, &new_b_epoch]).await.map_err(Error::internal)?;
        tx.execute("UPDATE shard_nodes SET role = 'primary', status = 'healthy', lease_epoch = GREATEST(lease_epoch, $2), version = version + 1, updated_at = clock_timestamp() WHERE node_id = $1", &[&input.target_node_id, &new_b_epoch]).await.map_err(Error::internal)?;
        tx.execute("UPDATE repository_shard_routes SET primary_node_id = $2, read_replica_nodes = $3, route_epoch = route_epoch + 1, fencing_token = GREATEST(fencing_token, route_epoch) + 1, fenced_epoch = route_epoch, version = version + 1, updated_at = clock_timestamp() WHERE bucket_id = $1 AND NOT explicit_override", &[&bucket_id, &input.target_node_id, &b_rep_json]).await.map_err(Error::internal)?;
    }

    if let Some(ref target) = marker {
        let id = transitions::stage(&tx, &state, target).await?;
        transitions::commit_and_publish(&state, tx, &actor, target, id).await?;
    } else {
        finish(tx, &actor, !dry_run).await?;
    }
    let receipt = RebalanceReceipt {
        id: op_id, bucket_id: input.bucket_id, source_node_id: input.source_node_id, target_node_id: input.target_node_id,
        repository_id: input.repository_id, dry_run, state: if dry_run { "dry_run".into() } else { "completed".into() },
        phases, old_route_epoch: old_ep, new_route_epoch: new_ep, fencing_token: token, fenced_epoch: fenced_ep,
        storage_generation: st_gen, reason: reason_trimmed, volume_marker: marker, updated_unix: now,
    };
    if !dry_run {
        append_rebalance_log(&state, &receipt)?;
    }
    Ok(json(StatusCode::OK, receipt))
}

pub async fn list_dr_drills(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    models::ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin).await?;
    let latest = read_dr_drill_receipt_at(&state.storage.repo_path(access.repo_id))?;
    let rows = tx.query("SELECT details FROM repository_audit_log WHERE tenant_id = $1 AND repository_id = $2 AND action = 'shard.dr_drill' ORDER BY id DESC LIMIT 50", &[&access.owner_id, &access.repo_id]).await.map_err(Error::internal)?;
    let mut items: Vec<DrDrillReceipt> = rows.iter().filter_map(|r| serde_json::from_value(r.get::<_, serde_json::Value>(0)).ok()).collect();
    if items.is_empty() && let Some(ref l) = latest {
        items.push(l.clone());
    }
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, DrDrillListResponse { repository_id: access.repo_id, latest, items }))
}

pub async fn execute_dr_drill(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(_input): Json<DrDrillRequest>,
) -> Result<Response, Error> {
    models::ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin).await?;
    require_operator(&tx, &actor).await?;
    finish(tx, &actor, false).await?;
    Err(conflict("simulated DR inputs cannot promote storage; use native cluster recovery workload"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn rebalance_target_and_dr_drill_sla_validation() {
        let healthy = ShardNode {
            node_id: "node-b".into(), endpoint: "http://node-b:8080".into(),
            role: "replica".into(), status: "healthy".into(),
            capacity_bytes: 1000, used_bytes: 200, lease_epoch: 1,
            lease_expires_unix: 500, fenced_epoch: 0, version: 1,
            created_at: String::new(), updated_at: String::new(),
        };
        assert!(validate_rebalance_target("node-a", &healthy, 100).is_ok());
        assert!(validate_rebalance_target("node-b", &healthy, 100).is_err());
        assert!(validate_rebalance_target("node-a", &ShardNode { used_bytes: 1000, ..healthy.clone() }, 100).is_err());
        assert!(validate_rebalance_target("node-a", &ShardNode { lease_expires_unix: 50, ..healthy }, 100).is_err());

        let route = RepoShardRoute {
            tenant_id: Uuid::nil(), repository_id: Uuid::nil(), bucket_id: 1,
            primary_node_id: "node-a".into(), read_replica_nodes: vec!["node-b".into()],
            replica_watermarks: BTreeMap::new(), explicit_override: false,
            route_epoch: 1, fencing_token: 1, fenced_epoch: 0,
            draining: false, read_only_degraded: false, degraded_reason: String::new(),
            in_flight_writes: 0, required_generation: 1, required_op_sequence: 0,
            version: 1, created_at: String::new(), updated_at: String::new(),
        };
        let req_ok = DrDrillRequest {
            primary_node_id: "node-a".into(), standby_node_id: "node-b".into(),
            target_rpo_secs: 5, target_rto_ms: 500,
            simulated_lag_secs: Some(2), simulated_takeover_ms: Some(120),
            verify_rollback: Some(true), reason: None, now_unix: None,
        };
        assert_eq!(evaluate_dr_drill_metrics(&route, &req_ok, 10), (2, 120, true, true));
        let req_breach = DrDrillRequest { simulated_lag_secs: Some(10), ..req_ok };
        assert_eq!(evaluate_dr_drill_metrics(&route, &req_breach, 10), (10, 120, false, true));
    }
}
