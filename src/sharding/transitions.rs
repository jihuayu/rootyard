//! Durable, fail-closed publication of shard volume markers.
use crate::{AppState, Error, auth, db::Identity, sharding::{fencing::write_volume_marker_at, models::{VolumeFenceMarker, conflict}}};
use deadpool_postgres::Transaction;
use uuid::Uuid;

pub async fn stage(tx: &Transaction<'_>, state: &AppState, marker: &VolumeFenceMarker) -> Result<Uuid, Error> {
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
        "INSERT INTO shard_marker_transitions(id, repository_id, volume_id, target_marker) VALUES ($1, $2, $3, $4)",
        &[&id, &marker.repository_id, &state.storage.volume_id, &target],
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
    let transition = client.query_opt(
        "SELECT volume_id, target_marker FROM shard_marker_transitions WHERE id=$1 AND repository_id=$2 AND state='pending'",
        &[&id, &marker.repository_id],
    ).await.map_err(Error::internal)?.ok_or_else(|| conflict("pending shard marker transition missing"))?;
    let volume_id: Uuid = transition.get(0);
    let target: serde_json::Value = transition.get(1);
    if volume_id != state.storage.volume_id || target != serde_json::to_value(marker).map_err(Error::internal)? {
        return Err(conflict("shard marker transition belongs to another volume or target"));
    }
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
    let current = primary == marker.primary_node_id && degraded == marker.read_only_degraded;
    let retired_source = if !current && marker.read_only_degraded && marker.primary_node_id != primary
        && marker.fenced_node_id.as_deref() == Some(marker.primary_node_id.as_str()) {
        client.query_opt(
            "SELECT id FROM shard_replication_operations WHERE repository_id=$1 AND source_node_id=$2 \
             AND target_node_id=$3 AND source_route_epoch=$4 AND state='completed' LIMIT 1",
            &[&marker.repository_id, &marker.primary_node_id, &primary, &(epoch - 1)],
        ).await.map_err(Error::internal)?.is_some()
    } else { false };
    if !(current || retired_source) || epoch != marker.route_epoch
        || token != marker.fencing_token || fenced != marker.fenced_epoch
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
        "SELECT id, target_marker FROM shard_marker_transitions WHERE state = 'pending' AND volume_id=$1 ORDER BY created_at, id",
        &[&state.storage.volume_id],
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, db, dispatch, metrics, sharding::router::load_or_init_repo_route, storage::Storage};
    use std::{path::PathBuf, sync::Arc, time::Duration};

    fn state(pool: deadpool_postgres::Pool, root: PathBuf) -> AppState {
        let config = Config {
            database_url: String::new(), data_dir: root, bind: "127.0.0.1:0".parse().unwrap(),
            git: PathBuf::from("/usr/local/bin/git"), max_request_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024, max_concurrent_git: 1,
            git_timeout: Duration::from_secs(10), git_memory_bytes: 1024 * 1024 * 1024,
            max_repo_bytes: 1024 * 1024, max_pending_deliveries: 100, outbox_worker: false,
            metrics_bind: None,
        };
        let storage = Storage::open(&config).unwrap();
        AppState { mirror_primary: None, dispatch: dispatch::Signals::default(),
            config, pool, storage, hooks: None,
            transfer_metrics: Arc::new(metrics::TransferCounters::default()),
            git_slots: Arc::new(tokio::sync::Semaphore::new(1)) }
    }

    #[tokio::test]
    async fn committed_but_unpublished_marker_reconciles_only_on_own_volume() {
        let Ok(base_url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else { return; };
        let schema = format!("cluster_transition_{}", Uuid::new_v4().simple());
        let base = db::pool(&base_url).unwrap();
        base.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA \"{schema}\"")).await.unwrap();
        let mut url = reqwest::Url::parse(&base_url).unwrap();
        url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
        let pool = db::pool(url.as_str()).unwrap();
        db::migrate(&pool).await.unwrap();
        let root = tempfile::tempdir().unwrap();
        let local = state(pool.clone(), root.path().join("local"));
        let foreign = state(pool.clone(), root.path().join("foreign"));
        let owner = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let digest = vec![7_u8; 32];
        let mut client = pool.get().await.unwrap();
        let tx = client.transaction().await.unwrap();
        tx.execute("INSERT INTO users(id,username) VALUES($1,'fixture')", &[&owner]).await.unwrap();
        tx.execute("INSERT INTO tokens(id,user_id,digest) VALUES($1,$2,$3)", &[&token_id, &owner, &digest]).await.unwrap();
        tx.execute("INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'demo','ready')", &[&repo_id, &owner]).await.unwrap();
        let route = load_or_init_repo_route(&tx, owner, repo_id).await.unwrap();
        let marker = VolumeFenceMarker::from_route(&route, 1, None, 1);
        let transition_id = stage(&tx, &local, &marker).await.unwrap();
        let actor = db::Identity { id: owner, token_id, username: "fixture".into(), read_only: false, token_digest: digest };
        assert!(commit_and_publish(&local, tx, &actor, &marker, transition_id).await.is_err());
        assert!(reject_pending(&local, repo_id).await.is_err());
        reconcile_pending(&foreign).await.unwrap();
        assert!(reject_pending(&local, repo_id).await.is_err());
        assert!(!foreign.storage.repo_path(repo_id).exists());
        std::fs::create_dir(local.storage.repo_path(repo_id)).unwrap();
        reconcile_pending(&local).await.unwrap();
        assert!(reject_pending(&local, repo_id).await.is_ok());
        assert!(local.storage.repo_path(repo_id).join("rootyard-shard-fence.json").is_file());
        drop(client);
        drop(local);
        drop(foreign);
        drop(pool);
        base.get().await.unwrap().batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await.unwrap();
    }
}
