//! Multi-node consistent 1024-virtual-bucket routing, primary node lease management,
//! per-repository route overrides, and watermark-aware read/write routing resolution.
use crate::{
    AppState, Error,
    auth::{self, Role, finish_tx as finish},
    members::audit::record_audit_event,
    sharding::models::{
        BUCKET_FIELDS, BucketsQuery, ConfigureRouteInput, DEFAULT_CAPACITY_BYTES,
        DEFAULT_LEASE_TTL_SECONDS, DEFAULT_NODE_ENDPOINT, DEFAULT_NODE_ID, NodeLeaseInput,
        NodesQuery, PatchNodeInput, REPO_ROUTE_FIELDS, RepoShardRoute, ResolveRouteQuery,
        RouteResolution, SHARD_NODE_FIELDS, ShardNode, UpsertBucketInput, UpsertNodeInput,
        VIRTUAL_BUCKET_COUNT, VirtualBucket, conflict, deterministic_bucket_id, json, open_client,
        unix_now, valid_endpoint, valid_node_id, valid_node_role, valid_node_status,
        valid_replica_list, valid_route_op,
    },
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use deadpool_postgres::Transaction;
use serde_json::json as sjson;
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

type App = State<Arc<AppState>>;
type RepoPath = Path<(String, String)>;
type Res = Result<Response, Error>;

pub async fn fetch_node(tx: &Transaction<'_>, node_id: &str) -> Result<Option<ShardNode>, Error> {
    let sql = format!("SELECT {SHARD_NODE_FIELDS} FROM shard_nodes WHERE node_id = $1");
    let row = tx.query_opt(&sql, &[&node_id]).await.map_err(Error::internal)?;
    Ok(row.as_ref().map(ShardNode::row))
}

async fn validate_placement_nodes(
    tx: &Transaction<'_>,
    primary_id: &str,
    replicas: &[String],
) -> Result<(), Error> {
    let primary = fetch_node(tx, primary_id).await?.ok_or_else(Error::not_found)?;
    if primary.role == "fenced" || primary.status == "fenced" || primary.status == "offline" {
        return Err(conflict("primary shard node is fenced or offline"));
    }
    for rep_id in replicas {
        if fetch_node(tx, rep_id).await?.is_none() {
            return Err(Error::not_found());
        }
    }
    Ok(())
}

pub async fn ensure_default_node(tx: &Transaction<'_>) -> Result<ShardNode, Error> {
    let q = format!(
        "SELECT {SHARD_NODE_FIELDS} FROM shard_nodes WHERE role = 'primary' AND status = 'healthy' ORDER BY node_id ASC LIMIT 1"
    );
    if let Some(first) = tx.query_opt(&q, &[]).await.map_err(Error::internal)? {
        return Ok(ShardNode::row(&first));
    }
    let ins = format!(
        "INSERT INTO shard_nodes (node_id, endpoint, role, status, capacity_bytes, used_bytes, lease_epoch, lease_expires_unix, fenced_epoch, version) \
         VALUES ($1, $2, 'primary', 'healthy', $3, 0, 1, 0, 0, 1) \
         ON CONFLICT (node_id) DO UPDATE SET updated_at = shard_nodes.updated_at RETURNING {SHARD_NODE_FIELDS}"
    );
    let row = tx
        .query_one(&ins, &[&DEFAULT_NODE_ID, &DEFAULT_NODE_ENDPOINT, &DEFAULT_CAPACITY_BYTES])
        .await
        .map_err(Error::internal)?;
    Ok(ShardNode::row(&row))
}

pub async fn load_or_init_repo_route(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
) -> Result<RepoShardRoute, Error> {
    let sel = format!(
        "SELECT {REPO_ROUTE_FIELDS} FROM repository_shard_routes WHERE tenant_id = $1 AND repository_id = $2"
    );
    if let Some(row) = tx.query_opt(&sel, &[&tenant_id, &repo_id]).await.map_err(Error::internal)? {
        return Ok(RepoShardRoute::row(&row));
    }
    let bucket_id = deterministic_bucket_id(repo_id);
    let b_sql = format!("SELECT {BUCKET_FIELDS} FROM shard_virtual_buckets WHERE bucket_id = $1");
    let (primary_id, replicas_val, epoch) = match tx.query_opt(&b_sql, &[&bucket_id]).await.map_err(Error::internal)? {
        Some(b_row) => {
            let b = VirtualBucket::row(&b_row);
            (b.primary_node_id, sjson!(b.read_replica_nodes), b.route_epoch)
        }
        None => (ensure_default_node(tx).await?.node_id, sjson!([]), 1_i64),
    };
    let repo_gen: i64 = tx
        .query_one("SELECT storage_generation FROM repositories WHERE id = $1", &[&repo_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    let req_gen = repo_gen.max(1);
    let ins = format!(
        "INSERT INTO repository_shard_routes \
         (tenant_id, repository_id, bucket_id, primary_node_id, read_replica_nodes, replica_watermarks, \
          explicit_override, route_epoch, fencing_token, fenced_epoch, draining, read_only_degraded, \
          degraded_reason, in_flight_writes, required_generation, required_op_sequence, version) \
         VALUES ($1, $2, $3, $4, $5, '{{}}'::jsonb, false, $6, $6, 0, false, false, '', 0, $7, 0, 1) \
         ON CONFLICT (repository_id) DO UPDATE SET updated_at = repository_shard_routes.updated_at \
         RETURNING {REPO_ROUTE_FIELDS}"
    );
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &tenant_id, &repo_id, &bucket_id, &primary_id, &replicas_val, &epoch, &req_gen,
    ];
    let row = tx.query_one(&ins, params).await.map_err(Error::internal)?;
    Ok(RepoShardRoute::row(&row))
}

pub fn select_route_target(
    route: &RepoShardRoute,
    repo_generation: i64,
    primary: &ShardNode,
    replicas: &BTreeMap<String, ShardNode>,
    query: &ResolveRouteQuery,
) -> Result<RouteResolution, Error> {
    let op = query.op.as_deref().unwrap_or("read");
    if !valid_route_op(op) {
        return Err(Error::bad_request());
    }
    if query.client_route_epoch.is_some_and(|e| e != route.route_epoch) {
        return Err(conflict("stale or mismatched client route_epoch"));
    }
    let now_unix = query.now_unix.unwrap_or_else(unix_now);
    let req_gen = repo_generation.max(route.required_generation).max(query.min_generation.unwrap_or(1));
    let req_seq = route.required_op_sequence.max(query.min_op_sequence.unwrap_or(0));
    let primary_unfenced = primary.fenced_epoch < route.route_epoch && route.fenced_epoch < route.route_epoch;
    let primary_healthy = primary.role == "primary"
        && primary.status == "healthy"
        && primary.is_lease_active(now_unix)
        && primary_unfenced;

    let find_qualified_replica = || -> Option<&ShardNode> {
        for rep_id in &route.read_replica_nodes {
            if let Some(rep_node) = replicas.get(rep_id)
                && rep_node.status == "healthy"
                && rep_node.role != "fenced"
                && let Some(wm) = route.replica_watermarks.get(rep_id)
                && wm.verified
                && wm.storage_generation >= req_gen
                && wm.op_sequence >= req_seq
            {
                return Some(rep_node);
            }
        }
        None
    };

    let build_res = |target: &ShardNode, role: &str, fallback: bool, degraded: bool| RouteResolution {
        repository_id: route.repository_id,
        bucket_id: route.bucket_id,
        operation: op.to_string(),
        target_node_id: target.node_id.clone(),
        target_endpoint: target.endpoint.clone(),
        target_role: role.to_string(),
        primary_node_id: route.primary_node_id.clone(),
        route_epoch: route.route_epoch,
        fencing_token: route.fencing_token,
        fenced_epoch: route.fenced_epoch,
        storage_generation: req_gen,
        required_op_sequence: req_seq,
        fallback_to_primary: fallback,
        read_only_degraded: degraded,
    };

    match op {
        "write" => {
            if route.draining || route.read_only_degraded || !primary_healthy {
                return Err(conflict("primary shard node unavailable, fenced, lease-expired, or degraded for writes"));
            }
            Ok(build_res(primary, "primary", false, false))
        }
        "merge_check" | "strong" => {
            if !route.read_only_degraded && !route.draining && primary_healthy {
                return Ok(build_res(primary, "primary", false, false));
            }
            if route.read_only_degraded && let Some(rep) = find_qualified_replica() {
                return Ok(build_res(rep, "replica", false, true));
            }
            Err(conflict("primary shard node unavailable or fenced for strong operation"))
        }
        "read" => {
            if let Some(rep) = find_qualified_replica() {
                return Ok(build_res(rep, "replica", false, route.read_only_degraded));
            }
            let primary_readable = primary.status != "offline"
                && primary.status != "fenced"
                && primary.role != "fenced"
                && primary.is_lease_active(now_unix)
                && primary_unfenced;
            if primary_readable {
                return Ok(build_res(primary, "primary", true, route.read_only_degraded));
            }
            Err(conflict("no watermark-qualified replica or readable primary available"))
        }
        _ => Err(Error::bad_request()),
    }
}

pub async fn list_nodes(State(state): App, Query(query): Query<NodesQuery>, headers: HeaderMap) -> Res {
    if query.role.as_deref().is_some_and(|r| !valid_node_role(r))
        || query.status.as_deref().is_some_and(|s| !valid_node_status(s))
    {
        return Err(Error::bad_request());
    }
    let (actor, mut client) = open_client(&state, &headers).await?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, false).await?;
    let sql = format!(
        "SELECT {SHARD_NODE_FIELDS} FROM shard_nodes \
         WHERE ($1::text IS NULL OR role = $1) AND ($2::text IS NULL OR status = $2) ORDER BY node_id ASC"
    );
    let rows = tx.query(&sql, &[&query.role, &query.status]).await.map_err(Error::internal)?;
    let items: Vec<ShardNode> = rows.iter().map(ShardNode::row).collect();
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "items": items })))
}

pub async fn upsert_node(State(state): App, headers: HeaderMap, Json(input): Json<UpsertNodeInput>) -> Res {
    let (actor, mut client) = open_client(&state, &headers).await?;
    auth::writable(&actor)?;
    let role = input.role.as_deref().unwrap_or("primary");
    let status = input.status.as_deref().unwrap_or("healthy");
    let cap = input.capacity_bytes.unwrap_or(DEFAULT_CAPACITY_BYTES);
    let used = input.used_bytes.unwrap_or(0);
    let ep = input.endpoint.trim();
    if !valid_node_id(&input.node_id) || !valid_endpoint(ep) || !valid_node_role(role) || !valid_node_status(status) || cap <= 0 || used < 0 || used > cap {
        return Err(Error::bad_request());
    }
    let now = input.now_unix.unwrap_or_else(unix_now);
    let lease_exp = match input.lease_ttl_seconds {
        Some(ttl) if (1..=86_400).contains(&ttl) => now.saturating_add(ttl),
        Some(0) | None => 0,
        Some(_) => return Err(Error::bad_request()),
    };

    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    let code = if fetch_node(&tx, &input.node_id).await?.is_some() { StatusCode::OK } else { StatusCode::CREATED };
    let sql = format!(
        "INSERT INTO shard_nodes (node_id, endpoint, role, status, capacity_bytes, used_bytes, lease_epoch, lease_expires_unix, fenced_epoch, version) \
         VALUES ($1, $2, $3, $4, $5, $6, 1, $7, 0, 1) ON CONFLICT (node_id) DO UPDATE SET \
           endpoint = EXCLUDED.endpoint, role = EXCLUDED.role, status = EXCLUDED.status, \
           capacity_bytes = EXCLUDED.capacity_bytes, used_bytes = EXCLUDED.used_bytes, \
           lease_expires_unix = CASE WHEN $7 > 0 THEN $7 ELSE shard_nodes.lease_expires_unix END, \
           version = shard_nodes.version + 1, updated_at = clock_timestamp() RETURNING {SHARD_NODE_FIELDS}"
    );
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] =
        &[&input.node_id, &ep, &role, &status, &cap, &used, &lease_exp];
    let row = tx.query_one(&sql, params).await.map_err(Error::internal)?;
    let node = ShardNode::row(&row);
    finish(tx, &actor, true).await?;
    Ok(json(code, node))
}

pub async fn get_node(State(state): App, Path(node_id): Path<String>, headers: HeaderMap) -> Res {
    let (actor, mut client) = open_client(&state, &headers).await?;
    if !valid_node_id(&node_id) {
        return Err(Error::not_found());
    }
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, false).await?;
    let node = fetch_node(&tx, &node_id).await?.ok_or_else(Error::not_found)?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, node))
}

pub async fn patch_node(State(state): App, Path(node_id): Path<String>, headers: HeaderMap, Json(input): Json<PatchNodeInput>) -> Res {
    let (actor, mut client) = open_client(&state, &headers).await?;
    auth::writable(&actor)?;
    if !valid_node_id(&node_id) {
        return Err(Error::not_found());
    }
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    let current = fetch_node(&tx, &node_id).await?.ok_or_else(Error::not_found)?;
    if input.expected_version.is_some_and(|v| v != current.version) {
        return Err(conflict("shard node version conflict"));
    }
    let ep = input.endpoint.as_deref().unwrap_or(&current.endpoint).trim();
    let role = input.role.as_deref().unwrap_or(&current.role);
    let status = input.status.as_deref().unwrap_or(&current.status);
    let cap = input.capacity_bytes.unwrap_or(current.capacity_bytes);
    let used = input.used_bytes.unwrap_or(current.used_bytes);
    if !valid_endpoint(ep) || !valid_node_role(role) || !valid_node_status(status) || cap <= 0 || used < 0 || used > cap {
        return Err(Error::bad_request());
    }
    let sql = format!(
        "UPDATE shard_nodes SET endpoint = $2, role = $3, status = $4, capacity_bytes = $5, \
         used_bytes = $6, version = version + 1, updated_at = clock_timestamp() \
         WHERE node_id = $1 RETURNING {SHARD_NODE_FIELDS}"
    );
    let row = tx.query_one(&sql, &[&node_id, &ep, &role, &status, &cap, &used]).await.map_err(Error::internal)?;
    let updated = ShardNode::row(&row);
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, updated))
}

pub async fn renew_node_lease(State(state): App, Path(node_id): Path<String>, headers: HeaderMap, Json(input): Json<NodeLeaseInput>) -> Res {
    let (actor, mut client) = open_client(&state, &headers).await?;
    auth::writable(&actor)?;
    if !valid_node_id(&node_id) {
        return Err(Error::not_found());
    }
    let ttl = input.lease_ttl_seconds.unwrap_or(DEFAULT_LEASE_TTL_SECONDS);
    let now = input.now_unix.unwrap_or_else(unix_now);
    if !(1..=86_400).contains(&ttl) || now < 0 {
        return Err(Error::bad_request());
    }
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    let current = fetch_node(&tx, &node_id).await?.ok_or_else(Error::not_found)?;
    if current.role == "fenced" || current.status == "fenced" || current.status == "offline" {
        return Err(conflict("cannot renew lease on fenced or offline shard node"));
    }
    if input.expected_lease_epoch.is_some_and(|e| e != current.lease_epoch) {
        return Err(conflict("stale or mismatched node lease_epoch"));
    }
    let new_epoch = if input.bump_epoch.unwrap_or(true) {
        current.lease_epoch.max(current.fenced_epoch) + 1
    } else if current.lease_epoch > current.fenced_epoch {
        current.lease_epoch
    } else {
        return Err(conflict("node lease_epoch is fenced"));
    };
    let expires = now.saturating_add(ttl);
    let sql = format!(
        "UPDATE shard_nodes SET lease_epoch = $2, lease_expires_unix = $3, version = version + 1, updated_at = clock_timestamp() \
         WHERE node_id = $1 RETURNING {SHARD_NODE_FIELDS}"
    );
    let row = tx.query_one(&sql, &[&node_id, &new_epoch, &expires]).await.map_err(Error::internal)?;
    let updated = ShardNode::row(&row);
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, updated))
}

pub async fn list_buckets(State(state): App, Query(query): Query<BucketsQuery>, headers: HeaderMap) -> Res {
    let (actor, mut client) = open_client(&state, &headers).await?;
    let after = query.after_bucket.unwrap_or(-1);
    let limit = query.limit.unwrap_or(128);
    if after < -1 || !(1..=1024).contains(&limit) {
        return Err(Error::bad_request());
    }
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, false).await?;
    let sql = format!(
        "SELECT {BUCKET_FIELDS} FROM shard_virtual_buckets \
         WHERE bucket_id > $1 AND ($2::text IS NULL OR primary_node_id = $2) ORDER BY bucket_id ASC LIMIT $3"
    );
    let rows = tx.query(&sql, &[&after, &query.primary_node_id, &limit]).await.map_err(Error::internal)?;
    let items: Vec<VirtualBucket> = rows.iter().map(VirtualBucket::row).collect();
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({ "virtual_bucket_count": VIRTUAL_BUCKET_COUNT, "items": items })))
}

pub async fn upsert_bucket(State(state): App, headers: HeaderMap, Json(input): Json<UpsertBucketInput>) -> Res {
    let (actor, mut client) = open_client(&state, &headers).await?;
    auth::writable(&actor)?;
    let replicas = input.read_replica_nodes.unwrap_or_default();
    if !(0..VIRTUAL_BUCKET_COUNT).contains(&input.bucket_id)
        || !valid_node_id(&input.primary_node_id)
        || !valid_replica_list(&input.primary_node_id, &replicas)
    {
        return Err(Error::bad_request());
    }
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    validate_placement_nodes(&tx, &input.primary_node_id, &replicas).await?;

    let b_sql = format!("SELECT {BUCKET_FIELDS} FROM shard_virtual_buckets WHERE bucket_id = $1");
    let existing = tx.query_opt(&b_sql, &[&input.bucket_id]).await.map_err(Error::internal)?.map(|r| VirtualBucket::row(&r));
    if input.expected_route_epoch.is_some_and(|e| e != existing.as_ref().map_or(0, |b| b.route_epoch)) {
        return Err(conflict("virtual bucket route_epoch conflict"));
    }
    let new_epoch = existing.as_ref().map_or(1, |b| b.route_epoch + 1);
    let code = if existing.is_some() { StatusCode::OK } else { StatusCode::CREATED };
    let replicas_val = sjson!(replicas);
    let ins = format!(
        "INSERT INTO shard_virtual_buckets (bucket_id, primary_node_id, read_replica_nodes, route_epoch) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (bucket_id) DO UPDATE SET \
           primary_node_id = EXCLUDED.primary_node_id, read_replica_nodes = EXCLUDED.read_replica_nodes, \
           route_epoch = EXCLUDED.route_epoch, updated_at = clock_timestamp() \
         RETURNING {BUCKET_FIELDS}"
    );
    let row = tx.query_one(&ins, &[&input.bucket_id, &input.primary_node_id, &replicas_val, &new_epoch]).await.map_err(Error::internal)?;
    tx.execute(
        "UPDATE repository_shard_routes SET primary_node_id = $2, read_replica_nodes = $3, \
         route_epoch = GREATEST(route_epoch + 1, $4), fencing_token = GREATEST(fencing_token + 1, $4), \
         version = version + 1, updated_at = clock_timestamp() WHERE bucket_id = $1 AND NOT explicit_override",
        &[&input.bucket_id, &input.primary_node_id, &replicas_val, &new_epoch],
    )
    .await
    .map_err(Error::internal)?;
    let bucket = VirtualBucket::row(&row);
    finish(tx, &actor, true).await?;
    Ok(json(code, bucket))
}

pub async fn get_repo_route(State(state): App, Path((owner, name)): RepoPath, headers: HeaderMap) -> Res {
    let (actor, mut client) = open_client(&state, &headers).await?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read).await?;
    let route = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, route))
}

pub async fn configure_repo_route(State(state): App, Path((owner, name)): RepoPath, headers: HeaderMap, Json(input): Json<ConfigureRouteInput>) -> Res {
    let (actor, mut client) = open_client(&state, &headers).await?;
    auth::writable(&actor)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin).await?;
    let current = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
    if input.expected_route_epoch.is_some_and(|e| e != current.route_epoch)
        || input.expected_version.is_some_and(|v| v != current.version)
    {
        return Err(conflict("repository shard route version or epoch conflict"));
    }

    let primary_id = input.primary_node_id.unwrap_or_else(|| current.primary_node_id.clone());
    let replicas = input.read_replica_nodes.unwrap_or_else(|| current.read_replica_nodes.clone());
    if !valid_node_id(&primary_id) || !valid_replica_list(&primary_id, &replicas) {
        return Err(Error::bad_request());
    }
    validate_placement_nodes(&tx, &primary_id, &replicas).await?;

    let watermarks = input.replica_watermarks.unwrap_or_else(|| current.replica_watermarks.clone());
    let req_gen = input.required_generation.unwrap_or(current.required_generation);
    let req_seq = input.required_op_sequence.unwrap_or(current.required_op_sequence);
    let in_flight = input.in_flight_writes.unwrap_or(current.in_flight_writes);
    if req_gen <= 0 || req_seq < 0 || in_flight < 0 {
        return Err(Error::bad_request());
    }

    let changed = primary_id != current.primary_node_id || replicas != current.read_replica_nodes;
    let explicit_override = input.explicit_override.unwrap_or(current.explicit_override || changed);
    let new_epoch = if changed { current.route_epoch + 1 } else { current.route_epoch };
    let new_token = current.fencing_token.max(new_epoch);
    let rep_json = sjson!(replicas);
    let wm_json = sjson!(watermarks);

    let upd = format!(
        "UPDATE repository_shard_routes SET primary_node_id = $3, read_replica_nodes = $4, \
         replica_watermarks = $5, explicit_override = $6, route_epoch = $7, fencing_token = $8, \
         required_generation = $9, required_op_sequence = $10, in_flight_writes = $11, \
         version = version + 1, updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND repository_id = $2 RETURNING {REPO_ROUTE_FIELDS}"
    );
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &access.owner_id, &access.repo_id, &primary_id, &rep_json, &wm_json,
        &explicit_override, &new_epoch, &new_token, &req_gen, &req_seq, &in_flight,
    ];
    let row = tx.query_one(&upd, params).await.map_err(Error::internal)?;
    let updated = RepoShardRoute::row(&row);
    let details = sjson!({ "bucket_id": updated.bucket_id, "route_epoch": updated.route_epoch, "explicit_override": updated.explicit_override });
    record_audit_event(&tx, access.owner_id, access.repo_id, &actor, "shard.route_updated", "shard_route", &updated.primary_node_id, details).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, updated))
}

pub async fn resolve_repo_route(State(state): App, Path((owner, name)): RepoPath, Query(query): Query<ResolveRouteQuery>, headers: HeaderMap) -> Res {
    let (actor, mut client) = open_client(&state, &headers).await?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read).await?;
    let route = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
    let repo_gen: i64 = tx
        .query_one("SELECT storage_generation FROM repositories WHERE id = $1", &[&access.repo_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    let primary = fetch_node(&tx, &route.primary_node_id).await?.ok_or_else(|| conflict("primary shard node missing"))?;
    let mut replicas_map = BTreeMap::new();
    for rep_id in &route.read_replica_nodes {
        if let Some(n) = fetch_node(&tx, rep_id).await? {
            replicas_map.insert(rep_id.clone(), n);
        }
    }
    let resolution = select_route_target(&route, repo_gen, &primary, &replicas_map, &query)?;
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, resolution))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::models::ReplicaWatermark;

    #[test]
    fn route_resolution_enforces_watermarks_and_lease_expiry() {
        let primary = ShardNode {
            node_id: "node-a".into(), endpoint: "http://node-a:8080".into(),
            role: "primary".into(), status: "healthy".into(),
            capacity_bytes: 1000, used_bytes: 100, lease_epoch: 2,
            lease_expires_unix: 200, fenced_epoch: 0, version: 1,
            created_at: String::new(), updated_at: String::new(),
        };
        let mut replicas = BTreeMap::new();
        replicas.insert("node-b".into(), ShardNode { node_id: "node-b".into(), role: "replica".into(), ..primary.clone() });
        let mut wms = BTreeMap::new();
        wms.insert("node-b".into(), ReplicaWatermark { storage_generation: 2, op_sequence: 15, verified: true, updated_unix: 100 });
        let route = RepoShardRoute {
            tenant_id: Uuid::nil(), repository_id: Uuid::nil(), bucket_id: 42,
            primary_node_id: "node-a".into(), read_replica_nodes: vec!["node-b".into()],
            replica_watermarks: wms, explicit_override: false,
            route_epoch: 2, fencing_token: 2, fenced_epoch: 1,
            draining: false, read_only_degraded: false, degraded_reason: String::new(),
            in_flight_writes: 0, required_generation: 2, required_op_sequence: 10,
            version: 1, created_at: String::new(), updated_at: String::new(),
        };
        let q_read = ResolveRouteQuery { op: Some("read".into()), client_route_epoch: Some(2), min_generation: None, min_op_sequence: None, now_unix: Some(150) };
        assert_eq!(select_route_target(&route, 2, &primary, &replicas, &q_read).unwrap().target_node_id, "node-b");
        let q_exp = ResolveRouteQuery { op: Some("write".into()), now_unix: Some(250), ..q_read };
        assert!(select_route_target(&route, 2, &primary, &replicas, &q_exp).is_err());
    }
}
