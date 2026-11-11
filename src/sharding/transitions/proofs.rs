//! Marker shape, rollback, and committed-route proofs for shard transitions.
use crate::{
    Error,
    sharding::models::{RepoShardRoute, VolumeFenceMarker, conflict, unix_now},
};

fn valid_marker_shape(marker: &VolumeFenceMarker) -> bool {
    marker.version == 1 && marker.route_epoch > 0 && marker.fencing_token >= marker.route_epoch
        && marker.fenced_epoch >= 0 && marker.storage_generation > 0
}

fn marker_from_route(route: &RepoShardRoute, eff_gen: i64) -> VolumeFenceMarker {
    VolumeFenceMarker::from_route(
        route,
        eff_gen,
        (route.fenced_epoch >= route.route_epoch).then(|| route.primary_node_id.clone()),
        unix_now(),
    )
}

fn matches_current_route(
    route: &RepoShardRoute,
    eff_gen: i64,
    marker: &VolumeFenceMarker,
) -> bool {
    route.primary_node_id == marker.primary_node_id
        && route.read_only_degraded == marker.read_only_degraded
        && route.route_epoch == marker.route_epoch
        && route.fencing_token == marker.fencing_token
        && route.fenced_epoch == marker.fenced_epoch
        && eff_gen == marker.storage_generation
}

async fn proven_source_retirement(
    client: &tokio_postgres::Client,
    route_if_same_epoch: Option<&str>,
    marker: &VolumeFenceMarker,
) -> Result<bool, Error> {
    if marker.route_epoch <= 1 || marker.fenced_epoch != marker.route_epoch - 1 {
        return Ok(false);
    }
    let replicated = client
        .query_opt(
            "SELECT id FROM shard_replication_operations WHERE repository_id=$1 \
             AND source_node_id=$2 AND ($3::text IS NULL OR target_node_id=$3) \
             AND source_route_epoch=$4 AND source_generation <= $5 AND state='completed' LIMIT 1",
            &[&marker.repository_id, &marker.primary_node_id, &route_if_same_epoch,
              &(marker.route_epoch - 1), &marker.storage_generation],
        )
        .await
        .map_err(Error::internal)?
        .is_some();
    if replicated {
        return Ok(true);
    }
    let promoted = client
        .query_opt(
            "SELECT id FROM shard_failover_operations WHERE repository_id=$1 \
             AND old_primary_node_id=$2 AND ($3::text IS NULL OR new_primary_node_id=$3) \
             AND new_route_epoch=$4 AND fencing_token=$5 AND storage_generation=$6 \
             AND state='promoted' LIMIT 1",
            &[&marker.repository_id, &marker.primary_node_id, &route_if_same_epoch,
              &marker.route_epoch, &marker.fencing_token, &marker.storage_generation],
        )
        .await
        .map_err(Error::internal)?
        .is_some();
    Ok(promoted)
}

async fn proven_return_to_primary(
    client: &tokio_postgres::Client,
    marker: &VolumeFenceMarker,
    route: &RepoShardRoute,
) -> Result<bool, Error> {
    let failed_back = client
        .query_opt(
            "SELECT id FROM shard_failover_operations WHERE repository_id=$1 \
             AND new_primary_node_id=$2 AND new_route_epoch > $3 AND new_route_epoch <= $4 \
             AND state='promoted' LIMIT 1",
            &[&marker.repository_id, &route.primary_node_id, &marker.route_epoch, &route.route_epoch],
        )
        .await
        .map_err(Error::internal)?
        .is_some();
    if failed_back {
        return Ok(true);
    }
    let replicated_back = client
        .query_opt(
            "SELECT id FROM shard_replication_operations WHERE repository_id=$1 \
             AND target_node_id=$2 AND source_route_epoch >= $3 AND source_route_epoch < $4 \
             AND state='completed' LIMIT 1",
            &[&marker.repository_id, &route.primary_node_id, &marker.route_epoch, &route.route_epoch],
        )
        .await
        .map_err(Error::internal)?
        .is_some();
    Ok(replicated_back)
}

async fn proven_rolled_back_candidate(
    client: &tokio_postgres::Client,
    marker: &VolumeFenceMarker,
) -> Result<bool, Error> {
    if marker.route_epoch <= 1 || marker.fenced_epoch != marker.route_epoch - 1 {
        return Ok(false);
    }
    let candidate = client
        .query_opt(
            "SELECT id FROM shard_replication_operations WHERE repository_id = $1 \
             AND source_node_id = $2 AND source_route_epoch = $3 \
             AND source_generation + 1 = $4 AND state IN ('verified', 'aborted') LIMIT 1",
            &[&marker.repository_id, &marker.primary_node_id,
              &(marker.route_epoch - 1), &marker.storage_generation],
        )
        .await
        .map_err(Error::internal)?
        .is_some();
    if !candidate {
        return Ok(false);
    }
    let promoted_away = client
        .query_opt(
            "SELECT id FROM shard_failover_operations WHERE repository_id = $1 \
             AND old_primary_node_id = $2 AND new_route_epoch = $3 \
             AND state = 'promoted' LIMIT 1",
            &[&marker.repository_id, &marker.primary_node_id, &marker.route_epoch],
        )
        .await
        .map_err(Error::internal)?
        .is_some();
    Ok(!promoted_away)
}

pub(super) async fn restored_live_marker(
    client: &tokio_postgres::Client,
    route: &RepoShardRoute,
    repo_generation: i64,
    marker: &VolumeFenceMarker,
) -> Result<Option<VolumeFenceMarker>, Error> {
    let eff_gen = repo_generation.max(route.required_generation);
    if !valid_marker_shape(marker)
        || marker.repository_id != route.repository_id
        || matches_current_route(route, eff_gen, marker)
        || !marker.read_only_degraded
        || marker.primary_node_id != route.primary_node_id
        || marker.fenced_node_id.as_deref() != Some(marker.primary_node_id.as_str())
    {
        return Ok(None);
    }
    if route.route_epoch < marker.route_epoch {
        return Ok(Some(marker_from_route(route, eff_gen)));
    }
    let restored = if proven_source_retirement(client, None, marker).await? {
        !route.read_only_degraded
            && route.route_epoch > marker.route_epoch
            && route.fencing_token >= marker.fencing_token
            && route.fenced_epoch >= marker.fenced_epoch
            && eff_gen >= marker.storage_generation
            && proven_return_to_primary(client, marker, route).await?
    } else {
        proven_rolled_back_candidate(client, marker).await?
    };
    Ok(restored.then(|| marker_from_route(route, eff_gen)))
}

pub(super) async fn validate_committed(
    client: &tokio_postgres::Client,
    route: &RepoShardRoute,
    repo_generation: i64,
    marker: &VolumeFenceMarker,
) -> Result<(), Error> {
    if !valid_marker_shape(marker) {
        return Err(conflict("shard marker transition has an invalid shape"));
    }
    if marker.repository_id != route.repository_id {
        return Err(conflict("shard marker transition repository mismatch"));
    }
    let eff_gen = repo_generation.max(route.required_generation);
    if matches_current_route(route, eff_gen, marker) {
        return Ok(());
    }
    let retired_source = marker.read_only_degraded
        && marker.primary_node_id != route.primary_node_id
        && marker.fenced_node_id.as_deref() == Some(marker.primary_node_id.as_str());
    if !retired_source
        || route.route_epoch < marker.route_epoch
        || route.fencing_token < marker.fencing_token
        || route.fenced_epoch < marker.fenced_epoch
        || eff_gen < marker.storage_generation
    {
        return Err(conflict("shard marker transition differs from committed route; writes blocked"));
    }
    if route.route_epoch == marker.route_epoch {
        if route.fencing_token != marker.fencing_token
            || route.fenced_epoch != marker.fenced_epoch
            || eff_gen != marker.storage_generation
            || !proven_source_retirement(client, Some(&route.primary_node_id), marker).await?
        {
            return Err(conflict("shard marker transition differs from committed route; writes blocked"));
        }
    } else if !proven_source_retirement(client, None, marker).await? {
        return Err(conflict("shard marker transition lacks source retirement proof; writes blocked"));
    }
    Ok(())
}
