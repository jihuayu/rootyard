//! 4-stage automated node failover state machine (`draining -> fenced -> verified -> promoted`)
//! and read-only degradation drill & writable recovery (`POST /api/repos/{owner}/{name}/shard-degrade`).
use crate::{
    AppState, Error,
    auth::{self, Role, finish_tx as finish},
    members::audit::record_audit_event,
    sharding::{
        security::require_operator,
        transitions,
        fencing::read_volume_marker_at,
        models::{
            self, DegradeDrillInput, DegradeDrillResponse,
            FAILOVER_OP_FIELDS, FailoverInput, FailoverOperation, REPO_ROUTE_FIELDS,
            RepoShardRoute, ShardNode, VolumeFenceMarker, conflict, json, unix_now,
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
use serde_json::json as sjson;
use std::{path::Path as StdPath, sync::Arc};

pub fn has_git_lock_files(repo_dir: &StdPath) -> bool {
    repo_dir.exists()
        && ["HEAD.lock", "packed-refs.lock", "config.lock"]
            .iter()
            .any(|name| repo_dir.join(name).exists())
}

pub fn validate_failover_candidate(
    route: &RepoShardRoute,
    repo_generation: i64,
    candidate: &ShardNode,
    input: &FailoverInput,
    has_git_locks: bool,
) -> Result<(i64, i64, i64), Error> {
    if candidate.node_id == route.primary_node_id {
        return Err(conflict("new_primary_node_id must differ from current primary_node_id"));
    }
    if input.expected_route_epoch.is_some_and(|e| e != route.route_epoch) {
        return Err(conflict("failover expected_route_epoch mismatch"));
    }
    if (route.in_flight_writes > 0 && !input.force_drain.unwrap_or(false)) || has_git_locks {
        return Err(conflict(
            "cannot drain repository with active in-flight writes or Git lock files",
        ));
    }
    if candidate.status != "healthy" || candidate.role == "fenced" {
        return Err(conflict(
            "target replica node is unhealthy or fenced and cannot be promoted",
        ));
    }

    let req_gen = repo_generation.max(route.required_generation);
    let req_seq = route.required_op_sequence;
    let Some(wm) = route.replica_watermarks.get(&candidate.node_id) else {
        return Err(conflict("target replica has no verified replication watermark"));
    };
    if !wm.verified || wm.storage_generation < req_gen || wm.op_sequence < req_seq {
        return Err(conflict(
            "target replica watermark is unverified or lags behind required generation/sequence",
        ));
    }

    let new_epoch = route.route_epoch + 1;
    let new_token = route.fencing_token.max(route.route_epoch) + 1;
    let base_gen = wm.storage_generation.max(req_gen);
    let new_gen = if input.bump_generation.unwrap_or(false) { base_gen + 1 } else { base_gen };
    Ok((new_epoch, new_token, new_gen))
}

pub async fn list_failovers(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    models::ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, crate::token_scopes::RepoAction::RepoRead).await?;
    let sql = format!(
        "SELECT {FAILOVER_OP_FIELDS} FROM shard_failover_operations \
         WHERE tenant_id = $1 AND repository_id = $2 ORDER BY created_at DESC, id DESC LIMIT 100"
    );
    let rows = tx.query(&sql, &[&access.owner_id, &access.repo_id]).await.map_err(Error::internal)?;
    let items: Vec<FailoverOperation> = rows.iter().map(FailoverOperation::row).collect();
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "items": items })))
}

pub async fn execute_failover(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(_input): Json<FailoverInput>,
) -> Result<Response, Error> {
    models::ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin, crate::token_scopes::RepoAction::RepoAdmin).await?;
    require_operator(&tx, &actor).await?;
    finish(tx, &actor, false).await?;
    Err(conflict("automatic takeover requires verified target data and physical source fencing"))
}

pub async fn degrade_or_recover_repo(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<DegradeDrillInput>,
) -> Result<Response, Error> {
    models::ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&actor)?;
    let mode = input.mode.as_str();
    let reason = input.reason.unwrap_or_default();
    if !matches!(mode, "degrade" | "recover") || reason.len() > 1024 || reason.chars().any(char::is_control) {
        return Err(Error::bad_request());
    }
    let now = input.now_unix.unwrap_or_else(unix_now);

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin, crate::token_scopes::RepoAction::RepoAdmin).await?;
    let mutation = super::locks::exclusive(&state, access.repo_id).await?;
    transitions::reject_any_pending(&tx, access.repo_id).await?;
    let route = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
    let repo_gen: i64 = tx
        .query_one("SELECT storage_generation FROM repositories WHERE id = $1", &[&access.repo_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    let repo_dir = state.storage.repo_path(access.repo_id);
    let prev_marker = read_volume_marker_at(&repo_dir)?;

    let (degraded, deg_reason, new_epoch, new_token, audit_action) = if mode == "degrade" {
        let r = if reason.trim().is_empty() { "read-only degradation drill".into() } else { reason.trim().into() };
        (true, r, route.route_epoch, route.fencing_token, "shard.degraded")
    } else {
        let primary = fetch_node(&tx, &route.primary_node_id).await?.ok_or_else(|| conflict("primary shard node missing"))?;
        if primary.role != "primary" || primary.status != "healthy" || !primary.is_lease_active(now) {
            return Err(conflict(
                "cannot recover from read-only degradation while primary node is unhealthy or lease-expired",
            ));
        }
        let next_epoch = route.route_epoch.max(route.fenced_epoch) + 1;
        let next_token = route.fencing_token.max(next_epoch) + 1;
        (false, String::new(), next_epoch, next_token, "shard.degrade_recovered")
    };

    let upd_sql = format!(
        "UPDATE repository_shard_routes SET read_only_degraded = $3, degraded_reason = $4, \
         draining = false, route_epoch = $5, fencing_token = $6, version = version + 1, updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND repository_id = $2 RETURNING {REPO_ROUTE_FIELDS}"
    );
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &access.owner_id,
        &access.repo_id,
        &degraded,
        &deg_reason,
        &new_epoch,
        &new_token,
    ];
    let r_row = tx.query_one(&upd_sql, params).await.map_err(Error::internal)?;
    let updated = RepoShardRoute::row(&r_row);
    crate::storage::ref_admission::fence_epoch(&tx, access.repo_id, route.route_epoch,
        std::time::Duration::ZERO).await?;

    let eff_gen = repo_gen.max(updated.required_generation);
    let marker = VolumeFenceMarker::from_route(&updated, eff_gen, prev_marker.and_then(|m| m.fenced_node_id), now);

    let details = sjson!({ "mode": mode, "read_only_degraded": degraded, "route_epoch": updated.route_epoch });
    record_audit_event(&tx, access.owner_id, access.repo_id, &actor, audit_action, "shard_degrade", &updated.primary_node_id, details).await?;
    let transition_id = transitions::stage(&tx, &state, &marker).await?;
    mutation.ensure_active()?;
    transitions::commit_and_publish(&state, tx, &actor, &marker, transition_id).await?;

    Ok(json(
        StatusCode::OK,
        DegradeDrillResponse {
            repository_id: access.repo_id,
            mode: mode.to_string(),
            read_only_degraded: degraded,
            degraded_reason: deg_reason,
            primary_node_id: updated.primary_node_id,
            route_epoch: updated.route_epoch,
            fencing_token: updated.fencing_token,
            write_admitted: !degraded,
            volume_marker: Some(marker),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::models::ReplicaWatermark;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    #[test]
    fn failover_candidate_validation_checks_watermark_and_in_flight_writes() {
        let mut wms = BTreeMap::new();
        wms.insert("node-b".into(), ReplicaWatermark { storage_generation: 2, op_sequence: 20, verified: true, updated_unix: 100 });
        wms.insert("node-lag".into(), ReplicaWatermark { storage_generation: 2, op_sequence: 5, verified: true, updated_unix: 100 });
        let route = RepoShardRoute {
            tenant_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            bucket_id: 7,
            primary_node_id: "node-a".into(),
            read_replica_nodes: vec!["node-b".into(), "node-lag".into()],
            replica_watermarks: wms,
            explicit_override: false,
            route_epoch: 1,
            fencing_token: 1,
            fenced_epoch: 0,
            draining: false,
            read_only_degraded: false,
            degraded_reason: String::new(),
            in_flight_writes: 0,
            required_generation: 2,
            required_op_sequence: 10,
            version: 1,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let node_b = ShardNode {
            node_id: "node-b".into(),
            endpoint: "http://node-b:8080".into(),
            role: "replica".into(),
            status: "healthy".into(),
            capacity_bytes: 1000,
            used_bytes: 0,
            lease_epoch: 1,
            lease_expires_unix: 0,
            fenced_epoch: 0,
            version: 1,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let ok_in = FailoverInput { new_primary_node_id: "node-b".into(), reason: None, expected_route_epoch: Some(1), force_drain: Some(false), bump_generation: Some(true), now_unix: None };
        assert_eq!(validate_failover_candidate(&route, 2, &node_b, &ok_in, false).unwrap(), (2, 2, 3));
        let node_lag = ShardNode { node_id: "node-lag".into(), ..node_b };
        let lag_in = FailoverInput { new_primary_node_id: "node-lag".into(), bump_generation: Some(false), ..ok_in };
        assert!(validate_failover_candidate(&route, 2, &node_lag, &lag_in, false).is_err());
    }
}
