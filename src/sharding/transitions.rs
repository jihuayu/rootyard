//! Durable, fail-closed publication and rollback reconciliation of shard volume markers.
use crate::{
    AppState, Error, auth, db::Identity,
    sharding::{
        faults, fencing::write_volume_marker_at, local_fence, locks,
        models::{REPO_ROUTE_FIELDS, RepoShardRoute, VolumeFenceMarker, conflict},
    },
};
use deadpool_postgres::Transaction;
use serde_json::Value;
use uuid::Uuid;

mod proofs;
use proofs::{restored_live_marker, validate_committed};

pub async fn stage(
    tx: &Transaction<'_>,
    state: &AppState,
    marker: &VolumeFenceMarker,
) -> Result<Uuid, Error> {
    stage_on_volume(tx, state.storage.volume_id, marker).await
}

/// Record the exact marker one volume must publish. The pending row is bound to its
/// volume so source and target transitions coexist during takeover; a marker must be staged first.
pub async fn stage_on_volume(
    tx: &Transaction<'_>,
    volume_id: Uuid,
    marker: &VolumeFenceMarker,
) -> Result<Uuid, Error> {
    let pending: i64 = tx.query_one(
        "SELECT COUNT(*) FROM shard_marker_transitions WHERE repository_id = $1 \
         AND volume_id = $2 AND state = 'pending'",
        &[&marker.repository_id, &volume_id],
    ).await.map_err(Error::internal)?.get(0);
    if pending != 0 {
        return Err(conflict("shard volume marker transition needs reconciliation"));
    }
    let id = Uuid::new_v4();
    let target = serde_json::to_value(marker).map_err(Error::internal)?;
    tx.execute(
        "INSERT INTO shard_marker_transitions(id, repository_id, volume_id, target_marker) \
         VALUES ($1, $2, $3, $4)",
        &[&id, &marker.repository_id, &volume_id, &target],
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
    let event = serde_json::json!({"repository_id": marker.repository_id, "transition_id": transition_id,
        "route_epoch": marker.route_epoch, "storage_generation": marker.storage_generation});
    faults::hit(&state.storage.root, "transition-before-commit", event.clone());
    auth::finish_tx(tx, actor, true).await?;
    faults::hit(&state.storage.root, "cutover-after-commit", event);
    publish(state, marker, transition_id).await
}

async fn transition_row(
    client: &tokio_postgres::Client,
    id: Uuid,
    repository_id: Uuid,
) -> Result<(Uuid, Value), Error> {
    let row = client.query_opt(
        "SELECT volume_id, target_marker FROM shard_marker_transitions \
         WHERE id=$1 AND repository_id=$2 AND state='pending'",
        &[&id, &repository_id],
    ).await.map_err(Error::internal)?
        .ok_or_else(|| conflict("pending shard marker transition missing"))?;
    Ok((row.get(0), row.get(1)))
}

async fn load_route(
    client: &tokio_postgres::Client,
    repository_id: Uuid,
) -> Result<(RepoShardRoute, i64), Error> {
    let fields = REPO_ROUTE_FIELDS
        .split(',')
        .map(|field| format!("r.{field}"))
        .collect::<Vec<_>>()
        .join(",");
    let query = format!(
        "SELECT {fields}, p.storage_generation FROM repository_shard_routes r \
         JOIN repositories p ON p.id = r.repository_id WHERE r.repository_id = $1"
    );
    let row = client.query_one(&query, &[&repository_id]).await.map_err(Error::internal)?;
    Ok((RepoShardRoute::row(&row), row.get(19)))
}

pub async fn reject_any_pending(tx: &Transaction<'_>, repo_id: Uuid) -> Result<(), Error> {
    let pending = tx.query_opt(
        "SELECT id FROM shard_marker_transitions WHERE repository_id = $1 \
         AND state = 'pending' LIMIT 1",
        &[&repo_id],
    ).await.map_err(Error::internal)?.is_some();
    if pending {
        return Err(conflict("shard marker transition pending; writes blocked until reconciliation"));
    }
    Ok(())
}

async fn complete(
    client: &tokio_postgres::Client,
    id: Uuid,
    repository_id: Uuid,
    volume_id: Uuid,
    marker: &VolumeFenceMarker,
) -> Result<(), Error> {
    let target = serde_json::to_value(marker).map_err(Error::internal)?;
    let updated = client.execute(
        "UPDATE shard_marker_transitions SET state = 'complete', target_marker = $2, \
         completed_at = clock_timestamp() WHERE id = $1 AND repository_id = $3 \
         AND volume_id = $4 AND state = 'pending'",
        &[&id, &target, &repository_id, &volume_id],
    ).await.map_err(Error::internal)?;
    if updated != 1 {
        return Err(conflict("pending shard marker transition missing"));
    }
    Ok(())
}

async fn publish(
    state: &AppState,
    marker: &VolumeFenceMarker,
    id: Uuid,
) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let (volume_id, target) = transition_row(&client, id, marker.repository_id).await?;
    if volume_id != state.storage.volume_id
        || target != serde_json::to_value(marker).map_err(Error::internal)?
    {
        return Err(conflict("shard marker transition belongs to another volume or target"));
    }
    let (route, repo_generation) = load_route(&client, marker.repository_id).await?;
    let write_marker = if let Some(restored) =
        restored_live_marker(&client, &route, repo_generation, marker).await?
    {
        restored
    } else {
        validate_committed(&client, &route, repo_generation, marker).await?;
        marker.clone()
    };
    let repo_dir = state.storage.repo_path(marker.repository_id);
    write_volume_marker_at(&repo_dir, &write_marker)?;
    complete(&client, id, marker.repository_id, state.storage.volume_id, &write_marker).await
}

async fn reconcile_foreign(
    state: &AppState,
    id: Uuid,
    row_repository_id: Uuid,
    volume_id: Uuid,
    target: Value,
) -> Result<(), Error> {
    let marker: VolumeFenceMarker = serde_json::from_value(target).map_err(Error::internal)?;
    if marker.repository_id != row_repository_id {
        return Err(conflict("shard marker transition repository mismatch"));
    }
    let registration = local_fence::registered_volume(&marker.primary_node_id)
        .map_err(|_| conflict("local volume registration is unreadable"))?;
    let Some(registration) = registration else { return Ok(()); };
    if registration.volume_id != volume_id {
        return Ok(());
    }
    let mutation = locks::exclusive(state, marker.repository_id).await?;
    mutation.ensure_active()?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let (db_volume_id, db_target) = transition_row(&client, id, row_repository_id).await?;
    if db_volume_id != volume_id
        || db_target != serde_json::to_value(&marker).map_err(Error::internal)?
    {
        return Err(conflict("shard marker transition belongs to another volume or target"));
    }
    let (route, repo_generation) = load_route(&client, marker.repository_id).await?;
    if let Some(restored) = restored_live_marker(&client, &route, repo_generation, &marker).await? {
        local_fence::write_volume_repository(&marker.primary_node_id, marker.repository_id, &restored)
            .map_err(|_| conflict("retired source marker rollback failed; writes remain blocked"))?;
        return complete(&client, id, row_repository_id, volume_id, &restored).await;
    }
    validate_committed(&client, &route, repo_generation, &marker).await?;
    local_fence::retire_volume_repository(&marker.primary_node_id, marker.repository_id, &marker)
        .map_err(|_| conflict("retired source marker publication failed; writes remain blocked"))?;
    complete(&client, id, row_repository_id, volume_id, &marker).await
}

pub async fn reject_pending(state: &AppState, repo_id: Uuid) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    // A pending marker is owned by one volume. A promoted target must not be blocked
    // forever by an unpublished retired marker on a dead source volume; its own transition still fails closed.
    let pending = client.query_opt(
        "SELECT id FROM shard_marker_transitions WHERE repository_id = $1 \
         AND volume_id = $2 AND state = 'pending' LIMIT 1",
        &[&repo_id, &state.storage.volume_id],
    ).await.map_err(Error::internal)?.is_some();
    if pending {
        return Err(conflict("shard marker transition pending; writes blocked until reconciliation"));
    }
    Ok(())
}

/// Called on writer startup and periodically before serving writes. Own-volume markers are
/// republished after a committed transition; a same-host target also reconciles the retired
/// source marker it staged before promotion: committed keeps it read-only, rolled back restores it.
pub async fn reconcile_pending(state: &AppState) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let own_rows = client.query(
        "SELECT id, repository_id, target_marker FROM shard_marker_transitions \
         WHERE state = 'pending' AND volume_id=$1 ORDER BY created_at, id",
        &[&state.storage.volume_id],
    ).await.map_err(Error::internal)?;
    let foreign_rows = client.query(
        "SELECT id, repository_id, volume_id, target_marker FROM shard_marker_transitions \
         WHERE state = 'pending' AND volume_id <> $1 \
         AND target_marker->>'read_only_degraded' = 'true' \
         ORDER BY created_at, id LIMIT 64",
        &[&state.storage.volume_id],
    ).await.map_err(Error::internal)?;
    drop(client);
    let mut first_error: Option<Error> = None;
    for row in foreign_rows {
        let result = reconcile_foreign(
            state, row.get(0), row.get(1), row.get(2), row.get(3),
        ).await;
        if let Err(err) = result && first_error.is_none() {
            first_error = Some(err);
        }
    }
    for row in own_rows {
        let id: Uuid = row.get(0);
        let row_repository_id: Uuid = row.get(1);
        let target: Value = row.get(2);
        let result: Result<(), Error> = async {
            let marker: VolumeFenceMarker =
                serde_json::from_value(target).map_err(Error::internal)?;
            if marker.repository_id != row_repository_id {
                return Err(conflict("shard marker transition repository mismatch"));
            }
            let mutation = locks::exclusive(state, marker.repository_id).await?;
            mutation.ensure_active()?;
            faults::hit(
                &state.storage.root,
                "recover-before-reconcile",
                serde_json::json!({"repository_id": marker.repository_id, "transition_id": id}),
            );
            publish(state, &marker, id).await
        }
        .await;
        if let Err(err) = result && first_error.is_none() {
            first_error = Some(err);
        }
    }
    if let Some(err) = first_error {
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
