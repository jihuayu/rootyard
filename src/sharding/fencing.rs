//! Dual-layer storage write barriers (`route_epoch`/`fenced_epoch` + `fencing_token` + `storage_generation`)
//! enforced across PostgreSQL and atomic on-disk `<repo_dir>/rootyard-shard-fence.json` markers.
use crate::{
    AppState, Error,
    auth::{self, Role, finish_tx as finish},
    members::audit::record_audit_event,
    sharding::{
        transitions,
        models::{
            self, FenceActionInput, FenceStatusResponse, REPO_ROUTE_FIELDS, RepoShardRoute,
            RepoState, SHARD_NODE_FIELDS, ShardNode, VOLUME_FENCE_MARKER_FILE, VolumeFenceMarker,
            conflict, json, unix_now, valid_node_id,
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
use std::{
    path::{Path as StdPath, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

pub fn marker_path(state: &AppState, repo_id: Uuid) -> PathBuf {
    state.storage.repo_path(repo_id).join(VOLUME_FENCE_MARKER_FILE)
}

pub fn read_volume_marker_at(repo_dir: &StdPath) -> Result<Option<VolumeFenceMarker>, Error> {
    if !repo_dir.exists() {
        return Ok(None);
    }
    let path = repo_dir.join(VOLUME_FENCE_MARKER_FILE);
    let exists = crate::journal::exists(&path)
        .map_err(|_| conflict("corrupt or symlinked shard fence marker"))?;
    if !exists {
        return Ok(None);
    }
    let bytes = crate::journal::read(&path).map_err(|_| conflict("unreadable shard fence marker"))?;
    let marker: VolumeFenceMarker = serde_json::from_slice(&bytes)
        .map_err(|_| conflict("corrupt or malformed shard volume fence marker"))?;
    if marker.version != 1
        || marker.route_epoch <= 0
        || marker.fencing_token < marker.route_epoch
        || marker.fenced_epoch < 0
        || marker.storage_generation <= 0
    {
        return Err(conflict("invalid shard volume fence marker invariants"));
    }
    Ok(Some(marker))
}

pub fn write_volume_marker_at(repo_dir: &StdPath, marker: &VolumeFenceMarker) -> Result<(), Error> {
    if !repo_dir.exists() {
        return Err(conflict("repository volume missing during shard marker publication"));
    }
    let path = repo_dir.join(VOLUME_FENCE_MARKER_FILE);
    let bytes = serde_json::to_vec_pretty(marker).map_err(Error::internal)?;
    crate::journal::atomic(&path, &bytes, true).map_err(Error::internal)
}

pub fn evaluate_write_barrier(
    route: &RepoShardRoute,
    primary: &ShardNode,
    repo_generation: i64,
    marker: Option<&VolumeFenceMarker>,
    probe: Option<&FenceActionInput>,
    now_unix: i64,
) -> Result<(), Error> {
    if route.draining || route.read_only_degraded {
        return Err(conflict(
            "repository write blocked by draining or read-only degradation mode",
        ));
    }
    if route.fenced_epoch >= route.route_epoch || primary.fenced_epoch >= route.route_epoch {
        return Err(conflict("repository or primary shard node route_epoch is fenced"));
    }
    if primary.role != "primary" || primary.status != "healthy" || !primary.is_lease_active(now_unix) {
        return Err(conflict(
            "primary shard node is unhealthy, fenced, or has an expired lease",
        ));
    }

    let eff_node = probe
        .and_then(|p| p.writer_node_id.as_deref())
        .unwrap_or(&route.primary_node_id);
    if eff_node != route.primary_node_id {
        return Err(conflict("writer node is not the active primary for this repository"));
    }
    let eff_epoch = probe
        .and_then(|p| p.writer_route_epoch)
        .unwrap_or(route.route_epoch);
    if eff_epoch < route.route_epoch
        || eff_epoch <= route.fenced_epoch
        || eff_epoch <= primary.fenced_epoch
    {
        return Err(conflict("stale or fenced writer route_epoch rejected"));
    }
    let eff_token = probe
        .and_then(|p| p.writer_fencing_token)
        .unwrap_or(route.fencing_token);
    if eff_token < route.fencing_token {
        return Err(conflict("stale writer fencing_token rejected"));
    }
    let req_gen = repo_generation.max(route.required_generation);
    let eff_gen = probe
        .and_then(|p| p.writer_storage_generation)
        .unwrap_or(repo_generation);
    if eff_gen < req_gen {
        return Err(conflict("stale writer storage_generation rejected"));
    }

    if let Some(m) = marker {
        if m.repository_id != route.repository_id {
            return Err(conflict("volume fence marker repository_id mismatch"));
        }
        if m.primary_node_id != route.primary_node_id || m.route_epoch != route.route_epoch
            || m.fencing_token != route.fencing_token || m.storage_generation != req_gen {
            return Err(conflict("volume fence marker does not match current storage placement"));
        }
        if m.read_only_degraded {
            return Err(conflict("volume fence marker enforces read-only degradation"));
        }
        if eff_epoch < m.route_epoch || eff_epoch <= m.fenced_epoch || route.route_epoch <= m.fenced_epoch {
            return Err(conflict("volume fence marker rejects stale or fenced route_epoch"));
        }
        if eff_token < m.fencing_token {
            return Err(conflict("volume fence marker rejects stale fencing_token"));
        }
        if eff_gen < m.storage_generation || repo_generation < m.storage_generation {
            return Err(conflict("volume fence marker rejects stale storage_generation"));
        }
        if m.fenced_node_id.as_deref() == Some(eff_node) && eff_epoch <= m.fenced_epoch {
            return Err(conflict("writer node is explicitly fenced in volume marker"));
        }
    }
    Ok(())
}

/// Pre-push storage fencing hook ready to be wired into `src/reliability.rs::before_push` in M17.
pub async fn check_before_push(state: &AppState, repo: &RepoState) -> Result<(), Error> {
    transitions::reject_pending(state, repo.id).await?;
    let repo_dir = state.storage.repo_path(repo.id);
    let marker = read_volume_marker_at(&repo_dir)?;
    if let Some(ref m) = marker
        && (m.repository_id != repo.id
            || m.read_only_degraded
            || m.fenced_epoch >= m.route_epoch
            || repo.storage_generation < m.storage_generation)
    {
        return Err(conflict("repository write blocked by on-disk shard volume fence"));
    }

    let client = state.pool.get().await.map_err(Error::internal)?;
    let installed: bool = client
        .query_one("SELECT to_regclass('repository_shard_routes') IS NOT NULL", &[])
        .await
        .map_err(Error::internal)?
        .get(0);
    if !installed {
        return Ok(());
    }

    let r_sql = format!("SELECT {REPO_ROUTE_FIELDS} FROM repository_shard_routes WHERE repository_id = $1");
    let Some(r_row) = client.query_opt(&r_sql, &[&repo.id]).await.map_err(Error::internal)? else {
        let count: i64 = client.query_one("SELECT COUNT(*) FROM shard_nodes", &[]).await.map_err(Error::internal)?.get(0);
        if count > 1 { return Err(conflict("cluster writer requires a durable repository route")); }
        return Ok(());
    };
    let route = RepoShardRoute::row(&r_row);
    let local_node = crate::sharding::transport::node_id()?;
    if local_node.as_deref().is_some_and(|node| node != route.primary_node_id) {
        return Err(conflict("local storage node is not repository primary"));
    }
    if local_node.is_none() {
        let count: i64 = client.query_one("SELECT COUNT(*) FROM shard_nodes", &[]).await.map_err(Error::internal)?.get(0);
        if count > 1 { return Err(conflict("cluster writer requires a local node identity")); }
    }

    let n_sql = format!("SELECT {SHARD_NODE_FIELDS} FROM shard_nodes WHERE node_id = $1");
    let primary = client
        .query_opt(&n_sql, &[&route.primary_node_id])
        .await
        .map_err(Error::internal)?
        .as_ref()
        .map(ShardNode::row)
        .ok_or_else(|| conflict("primary shard node missing"))?;

    evaluate_write_barrier(&route, &primary, repo.storage_generation, marker.as_ref(), None, unix_now())
}

/// The native Git hook repeats the barrier immediately before ref publication.
/// It must run for both pre-receive and reference-transaction preparing events.
pub async fn check_hook_fence(
    client: &tokio_postgres::Client,
    repo_id: Uuid,
    repo_dir: &StdPath,
    admitted_generation: i64,
    admitted_epoch: i64,
) -> Result<(), Error> {
    let marker = read_volume_marker_at(repo_dir)?;
    let pending = client.query_opt(
        "SELECT id FROM shard_marker_transitions WHERE repository_id=$1 AND state='pending' LIMIT 1",
        &[&repo_id],
    ).await.map_err(Error::internal)?.is_some();
    if pending { return Err(conflict("shard marker transition pending")); }
    let repo_generation: i64 = client.query_one(
        "SELECT storage_generation FROM repositories WHERE id=$1", &[&repo_id],
    ).await.map_err(Error::internal)?.get(0);
    if admitted_generation != repo_generation {
        return Err(conflict("admitted writer storage generation is stale"));
    }
    let r_sql = format!("SELECT {REPO_ROUTE_FIELDS} FROM repository_shard_routes WHERE repository_id=$1");
    let Some(row) = client.query_opt(&r_sql, &[&repo_id]).await.map_err(Error::internal)? else {
        if marker.is_some() { return Err(conflict("shard marker exists without route")); }
        let count: i64 = client.query_one("SELECT COUNT(*) FROM shard_nodes", &[]).await.map_err(Error::internal)?.get(0);
        if count > 1 { return Err(conflict("native Git cluster writer lacks durable repository route")); }
        if admitted_epoch > 1 { return Err(conflict("native Git writer has a shard epoch without a route")); }
        return Ok(());
    };
    let route = RepoShardRoute::row(&row);
    if admitted_epoch > 0 && route.route_epoch != admitted_epoch {
        return Err(conflict("native Git writer shard epoch is stale"));
    }
    let local_node = crate::sharding::transport::node_id()?;
    if local_node.as_deref().is_some_and(|node| node != route.primary_node_id) {
        return Err(conflict("native Git writer is not current storage primary"));
    }
    if local_node.is_none() {
        let count: i64 = client.query_one("SELECT COUNT(*) FROM shard_nodes", &[]).await.map_err(Error::internal)?.get(0);
        if count > 1 { return Err(conflict("native Git cluster writer lacks node identity")); }
    }
    let n_sql = format!("SELECT {SHARD_NODE_FIELDS} FROM shard_nodes WHERE node_id=$1");
    let primary = client.query_opt(&n_sql, &[&route.primary_node_id]).await.map_err(Error::internal)?
        .as_ref().map(ShardNode::row).ok_or_else(|| conflict("shard primary missing"))?;
    evaluate_write_barrier(&route, &primary, repo_generation, marker.as_ref(), None, unix_now())
}

pub async fn get_fence_status(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    models::ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read).await?;
    let route = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
    let repo_gen: i64 = tx
        .query_one("SELECT storage_generation FROM repositories WHERE id = $1", &[&access.repo_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    let primary = fetch_node(&tx, &route.primary_node_id)
        .await?
        .ok_or_else(|| conflict("primary shard node missing"))?;
    let repo_dir = state.storage.repo_path(access.repo_id);
    let marker = read_volume_marker_at(&repo_dir)?;
    let admitted = transitions::reject_pending(&state, access.repo_id).await.is_ok()
        && evaluate_write_barrier(&route, &primary, repo_gen, marker.as_ref(), None, unix_now()).is_ok();
    finish(tx, &actor, false).await?;
    let eff_gen = repo_gen.max(route.required_generation);
    Ok(json(StatusCode::OK, FenceStatusResponse::from_route(&route, eff_gen, admitted, marker)))
}

pub async fn apply_or_verify_fence(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<FenceActionInput>,
) -> Result<Response, Error> {
    models::ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let action = input.action.as_str();
    if !matches!(action, "verify" | "check_write" | "fence" | "unfence" | "advance_epoch") {
        return Err(Error::bad_request());
    }
    let now = input.now_unix.unwrap_or_else(unix_now);

    if matches!(action, "verify" | "check_write") {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read).await?;
        let route = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
        let repo_gen: i64 = tx
            .query_one("SELECT storage_generation FROM repositories WHERE id = $1", &[&access.repo_id])
            .await
            .map_err(Error::internal)?
            .get(0);
        let primary = fetch_node(&tx, &route.primary_node_id)
            .await?
            .ok_or_else(|| conflict("primary shard node missing"))?;
        let repo_dir = state.storage.repo_path(access.repo_id);
        let marker = read_volume_marker_at(&repo_dir)?;
        evaluate_write_barrier(&route, &primary, repo_gen, marker.as_ref(), Some(&input), now)?;
        finish(tx, &actor, false).await?;
        let eff_gen = repo_gen.max(route.required_generation);
        return Ok(json(StatusCode::OK, FenceStatusResponse::from_route(&route, eff_gen, true, marker)));
    }

    auth::writable(&actor)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin).await?;
    let mutation = super::locks::exclusive(&state, access.repo_id).await?;
    let route = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
    let repo_gen: i64 = tx
        .query_one("SELECT storage_generation FROM repositories WHERE id = $1 FOR UPDATE", &[&access.repo_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    let new_gen = input.storage_generation.unwrap_or(repo_gen.max(route.required_generation));
    if new_gen < repo_gen {
        return Err(conflict("storage_generation cannot move backward"));
    }
    if new_gen > repo_gen {
        tx.execute("UPDATE repositories SET storage_generation = $2 WHERE id = $1", &[&access.repo_id, &new_gen])
            .await
            .map_err(Error::internal)?;
    }

    let old_route_epoch = route.route_epoch;
    if action == "fence" {
        let target_node = input.fenced_node_id.clone().unwrap_or_else(|| route.primary_node_id.clone());
        if !valid_node_id(&target_node) {
            return Err(Error::bad_request());
        }
        if target_node != route.primary_node_id {
            return Err(conflict("repository fence can target only its current primary"));
        }
        let f_epoch = input.fenced_epoch.unwrap_or(route.route_epoch);
        if f_epoch <= 0 || f_epoch < route.fenced_epoch {
            return Err(conflict("fenced_epoch cannot move backward"));
        }
        let new_route_epoch = route.route_epoch.max(f_epoch);
        let new_token = route.fencing_token.max(new_route_epoch) + 1;

        let upd_sql = format!(
            "UPDATE repository_shard_routes SET route_epoch = $3, fencing_token = $4, \
             fenced_epoch = $5, required_generation = $6, version = version + 1, updated_at = clock_timestamp() \
             WHERE tenant_id = $1 AND repository_id = $2 RETURNING {REPO_ROUTE_FIELDS}"
        );
        let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
            &access.owner_id,
            &access.repo_id,
            &new_route_epoch,
            &new_token,
            &f_epoch,
            &new_gen,
        ];
        let row = tx.query_one(&upd_sql, params).await.map_err(Error::internal)?;
        let updated = RepoShardRoute::row(&row);
        crate::storage::ref_admission::fence_epoch(&tx, access.repo_id, old_route_epoch,
            std::time::Duration::ZERO).await?;
        let marker = VolumeFenceMarker::from_route(&updated, new_gen, Some(target_node.clone()), now);
        let details = sjson!({ "fenced_epoch": f_epoch, "fencing_token": new_token, "storage_generation": new_gen });
        record_audit_event(&tx, access.owner_id, access.repo_id, &actor, "shard.fenced", "shard_fence", &target_node, details).await?;
        let transition_id = transitions::stage(&tx, &state, &marker).await?;
        mutation.ensure_active()?;
        transitions::commit_and_publish(&state, tx, &actor, &marker, transition_id).await?;
        return Ok(json(StatusCode::OK, FenceStatusResponse::from_route(&updated, new_gen, false, Some(marker))));
    }

    let new_route_epoch = route.route_epoch.max(route.fenced_epoch) + 1;
    let new_token = route.fencing_token.max(new_route_epoch) + 1;
    let upd_sql = format!(
        "UPDATE repository_shard_routes SET route_epoch = $3, fencing_token = $4, \
         required_generation = $5, draining = false, version = version + 1, updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND repository_id = $2 RETURNING {REPO_ROUTE_FIELDS}"
    );
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &access.owner_id,
        &access.repo_id,
        &new_route_epoch,
        &new_token,
        &new_gen,
    ];
    let row = tx.query_one(&upd_sql, params).await.map_err(Error::internal)?;
    let updated = RepoShardRoute::row(&row);
    crate::storage::ref_admission::fence_epoch(&tx, access.repo_id, old_route_epoch,
        std::time::Duration::ZERO).await?;
    let marker = VolumeFenceMarker::from_route(&updated, new_gen, None, now);
    let details = sjson!({ "route_epoch": new_route_epoch, "fencing_token": new_token, "storage_generation": new_gen });
    record_audit_event(&tx, access.owner_id, access.repo_id, &actor, "shard.unfenced", "shard_fence", &updated.primary_node_id, details).await?;
    let transition_id = transitions::stage(&tx, &state, &marker).await?;
    mutation.ensure_active()?;
    transitions::commit_and_publish(&state, tx, &actor, &marker, transition_id).await?;
    let admitted = !updated.read_only_degraded;
    Ok(json(StatusCode::OK, FenceStatusResponse::from_route(&updated, new_gen, admitted, Some(marker))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn dual_layer_barrier_rejects_stale_epoch_token_generation_and_marker() {
        let repo_id = Uuid::new_v4();
        let route = RepoShardRoute {
            tenant_id: Uuid::nil(),
            repository_id: repo_id,
            bucket_id: 1,
            primary_node_id: "node-a".into(),
            read_replica_nodes: vec![],
            replica_watermarks: BTreeMap::new(),
            explicit_override: false,
            route_epoch: 3,
            fencing_token: 4,
            fenced_epoch: 2,
            draining: false,
            read_only_degraded: false,
            degraded_reason: String::new(),
            in_flight_writes: 0,
            required_generation: 2,
            required_op_sequence: 0,
            version: 1,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let primary = ShardNode {
            node_id: "node-a".into(),
            endpoint: "http://node-a:8080".into(),
            role: "primary".into(),
            status: "healthy".into(),
            capacity_bytes: 1000,
            used_bytes: 0,
            lease_epoch: 3,
            lease_expires_unix: 500,
            fenced_epoch: 2,
            version: 1,
            created_at: String::new(),
            updated_at: String::new(),
        };
        let marker = VolumeFenceMarker::from_route(&route, 2, Some("node-old".into()), 100);
        assert!(evaluate_write_barrier(&route, &primary, 2, Some(&marker), None, 200).is_ok());

        let stale_ep = FenceActionInput { action: "verify".into(), writer_route_epoch: Some(2), ..Default::default() };
        assert!(evaluate_write_barrier(&route, &primary, 2, Some(&marker), Some(&stale_ep), 200).is_err());

        let stale_gen = FenceActionInput { action: "verify".into(), writer_storage_generation: Some(1), ..Default::default() };
        assert!(evaluate_write_barrier(&route, &primary, 2, Some(&marker), Some(&stale_gen), 200).is_err());
    }
}
