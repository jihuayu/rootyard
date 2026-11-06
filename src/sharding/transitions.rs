//! Durable, fail-closed publication of shard volume markers.
use crate::{AppState, Error, auth, db::Identity, sharding::{fencing::write_volume_marker_at, models::{VolumeFenceMarker, conflict}}};
use deadpool_postgres::Transaction;
use uuid::Uuid;

pub async fn stage(tx: &Transaction<'_>, marker: &VolumeFenceMarker) -> Result<Uuid, Error> {
    let pending: i64 = tx.query_one(
        "SELECT COUNT(*) FROM shard_marker_transitions WHERE repository_id = $1 AND state = 'pending'",
        &[&marker.repository_id],
    ).await.map_err(Error::internal)?.get(0);
    if pending != 0 {
        return Err(conflict("shard volume marker transition needs reconciliation"));
    }
    let id = Uuid::new_v4();
    let target = serde_json::to_value(marker).map_err(Error::internal)?;
    tx.execute(
        "INSERT INTO shard_marker_transitions(id, repository_id, target_marker) VALUES ($1, $2, $3)",
        &[&id, &marker.repository_id, &target],
    ).await.map_err(Error::internal)?;
    Ok(id)
}

pub async fn commit_and_publish(
    state: &AppState,
    tx: Transaction<'_>,
    actor: &Identity,
    marker: &VolumeFenceMarker,
    transition_id: Uuid,
) -> Result<(), Error> {
    auth::finish_tx(tx, actor, true).await?;
    publish(state, marker, transition_id).await
}

async fn publish(state: &AppState, marker: &VolumeFenceMarker, id: Uuid) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client.query_one(
        "SELECT r.primary_node_id, r.route_epoch, r.fencing_token, r.fenced_epoch, r.read_only_degraded, r.required_generation, p.storage_generation FROM repository_shard_routes r JOIN repositories p ON p.id = r.repository_id WHERE r.repository_id = $1",
        &[&marker.repository_id],
    ).await.map_err(Error::internal)?;
    let primary: String = row.get(0);
    let epoch: i64 = row.get(1);
    let token: i64 = row.get(2);
    let fenced: i64 = row.get(3);
    let degraded: bool = row.get(4);
    let required_gen: i64 = row.get(5);
    let repo_gen: i64 = row.get(6);
    if primary != marker.primary_node_id || epoch != marker.route_epoch
        || token != marker.fencing_token || fenced != marker.fenced_epoch
        || degraded != marker.read_only_degraded
        || repo_gen.max(required_gen) != marker.storage_generation {
        return Err(conflict("shard marker transition differs from committed route; writes blocked"));
    }
    let repo_dir = state.storage.repo_path(marker.repository_id);
    write_volume_marker_at(&repo_dir, marker)?;
    client.execute(
        "UPDATE shard_marker_transitions SET state = 'complete', completed_at = clock_timestamp() WHERE id = $1 AND state = 'pending'",
        &[&id],
    ).await.map_err(Error::internal)?;
    Ok(())
}

pub async fn reject_pending(state: &AppState, repo_id: Uuid) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let pending = client.query_opt(
        "SELECT id FROM shard_marker_transitions WHERE repository_id = $1 AND state = 'pending' LIMIT 1",
        &[&repo_id],
    ).await.map_err(Error::internal)?.is_some();
    if pending {
        return Err(conflict("shard marker transition pending; writes blocked until reconciliation"));
    }
    Ok(())
}

/// Called on writer startup before serving requests. A mismatch remains pending and blocks writes.
pub async fn reconcile_pending(state: &AppState) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client.query(
        "SELECT id, target_marker FROM shard_marker_transitions WHERE state = 'pending' ORDER BY created_at, id",
        &[],
    ).await.map_err(Error::internal)?;
    drop(client);
    for row in rows {
        let id: Uuid = row.get(0);
        let target: serde_json::Value = row.get(1);
        let marker: VolumeFenceMarker = serde_json::from_value(target).map_err(Error::internal)?;
        let _lock = state.storage.write_lock(marker.repository_id).await;
        publish(state, &marker, id).await?;
    }
    Ok(())
}
