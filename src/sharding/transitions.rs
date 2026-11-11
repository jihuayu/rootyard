//! Durable, fail-closed publication and rollback reconciliation of shard volume markers.
use crate::{
    AppState, Error, auth,
    db::Identity,
    sharding::{
        faults,
        fencing::write_volume_marker_at,
        local_fence,
        locks,
        models::{REPO_ROUTE_FIELDS, RepoShardRoute, VolumeFenceMarker, conflict, unix_now},
    },
};
use deadpool_postgres::Transaction;
use serde_json::Value;
use uuid::Uuid;

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
    let pending: i64 = tx
        .query_one(
            "SELECT COUNT(*) FROM shard_marker_transitions WHERE repository_id = $1 \
             AND volume_id = $2 AND state = 'pending'",
            &[&marker.repository_id, &volume_id],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    if pending != 0 {
        return Err(conflict("shard volume marker transition needs reconciliation"));
    }
    let id = Uuid::new_v4();
    let target = serde_json::to_value(marker).map_err(Error::internal)?;
    tx.execute(
        "INSERT INTO shard_marker_transitions(id, repository_id, volume_id, target_marker) \
         VALUES ($1, $2, $3, $4)",
        &[&id, &marker.repository_id, &volume_id, &target],
    )
    .await
    .map_err(Error::internal)?;
    Ok(id)
}

pub async fn commit_and_publish(
    state: &AppState,
    tx: Transaction<'_>,
    actor: &Identity,
    marker: &VolumeFenceMarker,
    transition_id: Uuid,
) -> Result<(), Error> {
    faults::hit(
        &state.storage.root,
        "transition-before-commit",
        serde_json::json!({"repository_id": marker.repository_id, "transition_id": transition_id,
                          "route_epoch": marker.route_epoch, "storage_generation": marker.storage_generation}),
    );
    auth::finish_tx(tx, actor, true).await?;
    faults::hit(
        &state.storage.root,
        "cutover-after-commit",
        serde_json::json!({"repository_id": marker.repository_id, "transition_id": transition_id,
                          "route_epoch": marker.route_epoch, "storage_generation": marker.storage_generation}),
    );
    publish(state, marker, transition_id).await
}

async fn transition_row(
    client: &tokio_postgres::Client,
    id: Uuid,
    repository_id: Uuid,
) -> Result<(Uuid, Value), Error> {
    let row = client
        .query_opt(
            "SELECT volume_id, target_marker FROM shard_marker_transitions \
             WHERE id=$1 AND repository_id=$2 AND state='pending'",
            &[&id, &repository_id],
        )
        .await
        .map_err(Error::internal)?
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
    let row = client
        .query_one(&query, &[&repository_id])
        .await
        .map_err(Error::internal)?;
    Ok((RepoShardRoute::row(&row), row.get(19)))
}

/// A promotion that rolled back leaves the source marker read-only even though PostgreSQL
/// still names it primary. Restore it from the committed route before admitting writers.
fn rolled_back_marker(
    route: &RepoShardRoute,
    repo_generation: i64,
    marker: &VolumeFenceMarker,
) -> Option<VolumeFenceMarker> {
    (marker.repository_id == route.repository_id
        && marker.read_only_degraded
        && marker.primary_node_id == route.primary_node_id
        && marker.fenced_node_id.as_deref() == Some(marker.primary_node_id.as_str())
        && route.route_epoch < marker.route_epoch)
        .then(|| {
            VolumeFenceMarker::from_route(
                route,
                repo_generation.max(route.required_generation),
                None,
                unix_now(),
            )
        })
}

async fn validate_committed(
    client: &tokio_postgres::Client,
    route: &RepoShardRoute,
    repo_generation: i64,
    marker: &VolumeFenceMarker,
) -> Result<(), Error> {
    if marker.repository_id != route.repository_id {
        return Err(conflict("shard marker transition repository mismatch"));
    }
    let current = route.primary_node_id == marker.primary_node_id
        && route.read_only_degraded == marker.read_only_degraded;
    let retired_source = if !current
        && marker.read_only_degraded
        && marker.primary_node_id != route.primary_node_id
        && marker.fenced_node_id.as_deref() == Some(marker.primary_node_id.as_str())
    {
        client
            .query_opt(
                "SELECT id FROM shard_replication_operations WHERE repository_id=$1 AND source_node_id=$2 \
                 AND target_node_id=$3 AND source_route_epoch=$4 AND state='completed' LIMIT 1",
                &[&marker.repository_id, &marker.primary_node_id, &route.primary_node_id, &(route.route_epoch - 1)],
            )
            .await
            .map_err(Error::internal)?
            .is_some()
    } else {
        false
    };
    if !(current || retired_source)
        || route.route_epoch != marker.route_epoch
        || route.fencing_token != marker.fencing_token
        || route.fenced_epoch != marker.fenced_epoch
        || repo_generation.max(route.required_generation) != marker.storage_generation
    {
        return Err(conflict("shard marker transition differs from committed route; writes blocked"));
    }
    Ok(())
}

async fn complete(
    client: &tokio_postgres::Client,
    id: Uuid,
    marker: &VolumeFenceMarker,
) -> Result<(), Error> {
    let target = serde_json::to_value(marker).map_err(Error::internal)?;
    let updated = client
        .execute(
            "UPDATE shard_marker_transitions SET state = 'complete', target_marker = $2, \
             completed_at = clock_timestamp() WHERE id = $1",
            &[&id, &target],
        )
        .await
        .map_err(Error::internal)?;
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
    let write_marker = if let Some(restored) = rolled_back_marker(&route, repo_generation, marker) {
        restored
    } else {
        validate_committed(&client, &route, repo_generation, marker).await?;
        marker.clone()
    };
    let repo_dir = state.storage.repo_path(marker.repository_id);
    write_volume_marker_at(&repo_dir, &write_marker)?;
    complete(&client, id, &write_marker).await
}

async fn reconcile_foreign(
    state: &AppState,
    id: Uuid,
    volume_id: Uuid,
    target: Value,
) -> Result<(), Error> {
    let marker: VolumeFenceMarker = serde_json::from_value(target).map_err(Error::internal)?;
    let registration = local_fence::registered_volume(&marker.primary_node_id)
        .map_err(|_| conflict("local volume registration is unreadable"))?;
    let Some(registration) = registration else { return Ok(()); };
    if registration.volume_id != volume_id {
        return Ok(());
    }
    let mutation = locks::exclusive(state, marker.repository_id).await?;
    mutation.ensure_active()?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let (route, repo_generation) = load_route(&client, marker.repository_id).await?;
    if let Some(restored) = rolled_back_marker(&route, repo_generation, &marker) {
        local_fence::write_volume_repository(&marker.primary_node_id, marker.repository_id, &restored)
            .map_err(|_| conflict("retired source marker rollback failed; writes remain blocked"))?;
        return complete(&client, id, &restored).await;
    }
    validate_committed(&client, &route, repo_generation, &marker).await?;
    local_fence::retire_volume_repository(&marker.primary_node_id, marker.repository_id, &marker)
        .map_err(|_| conflict("retired source marker publication failed; writes remain blocked"))?;
    complete(&client, id, &marker).await
}

pub async fn reject_pending(state: &AppState, repo_id: Uuid) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    // A pending marker is owned by one volume. A promoted target must not be blocked
    // forever by an unpublished retired marker on a dead source volume; its own transition still fails closed.
    let pending = client
        .query_opt(
            "SELECT id FROM shard_marker_transitions WHERE repository_id = $1 \
             AND volume_id = $2 AND state = 'pending' LIMIT 1",
            &[&repo_id, &state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?
        .is_some();
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
    let own_rows = client
        .query(
            "SELECT id, target_marker FROM shard_marker_transitions \
             WHERE state = 'pending' AND volume_id=$1 ORDER BY created_at, id",
            &[&state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    let foreign_rows = client
        .query(
            "SELECT id, volume_id, target_marker FROM shard_marker_transitions \
             WHERE state = 'pending' AND volume_id <> $1 \
             AND target_marker->>'read_only_degraded' = 'true' \
             ORDER BY created_at, id LIMIT 64",
            &[&state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    drop(client);
    for row in foreign_rows {
        reconcile_foreign(state, row.get(0), row.get(1), row.get(2)).await?;
    }
    for row in own_rows {
        let id: Uuid = row.get(0);
        let target: Value = row.get(1);
        let marker: VolumeFenceMarker = serde_json::from_value(target).map_err(Error::internal)?;
        let mutation = locks::exclusive(state, marker.repository_id).await?;
        mutation.ensure_active()?;
        faults::hit(
            &state.storage.root,
            "recover-before-reconcile",
            serde_json::json!({"repository_id": marker.repository_id, "transition_id": id}),
        );
        publish(state, &marker, id).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, db, dispatch, metrics, sharding::router::load_or_init_repo_route, storage::Storage};
    use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration};

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

#[tokio::test]
async fn pre_commit_rollback_keeps_every_transition_marker_unpublished() {
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
    let owner = Uuid::new_v4();
    let repo_id = Uuid::new_v4();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute("INSERT INTO users(id,username) VALUES($1,'fixture')", &[&owner]).await.unwrap();
    tx.execute("INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'demo','ready')", &[&repo_id, &owner]).await.unwrap();
    load_or_init_repo_route(&tx, owner, repo_id).await.unwrap();
    tx.commit().await.unwrap();
    drop(client);
    let dir = local.storage.repo_path(repo_id);
    std::fs::create_dir_all(&dir).unwrap();
    let marker_file = dir.join("rootyard-shard-fence.json");
    let prototype = VolumeFenceMarker {
        version: 1, repository_id: repo_id, primary_node_id: "shard-primary-0".into(),
        route_epoch: 1, fencing_token: 2, fenced_epoch: 1, storage_generation: 1,
        fenced_node_id: None, read_only_degraded: false, updated_unix: 1,
    };
    write_volume_marker_at(&dir, &prototype).unwrap();
    let original_marker = std::fs::read(&marker_file).unwrap();
    let transitions = [
        ("failover", VolumeFenceMarker { primary_node_id: "node1".into(), route_epoch: 2,
            fencing_token: 3, read_only_degraded: true, fenced_node_id: Some("shard-primary-0".into()),
            storage_generation: 2, ..prototype.clone() }),
        ("degrade", VolumeFenceMarker { read_only_degraded: true, ..prototype.clone() }),
        ("recover", VolumeFenceMarker { route_epoch: 2, fencing_token: 3, ..prototype.clone() }),
        ("fence", VolumeFenceMarker { fencing_token: 3, fenced_node_id: Some("shard-primary-0".into()),
            ..prototype.clone() }),
    ];
    for (name, marker) in transitions {
        let mut staged = pool.get().await.unwrap();
        let tx = staged.transaction().await.unwrap();
        stage(&tx, &local, &marker).await.unwrap();
        // A SIGKILL before commit aborts this transaction: no intent survives and the volume is bare.
        drop(tx);
        drop(staged);
        assert!(reject_pending(&local, repo_id).await.is_ok(), "{name} left a pending intent");
        assert_eq!(std::fs::read(&marker_file).unwrap(), original_marker,
            "{name} changed the pre-existing marker before commit");
        let mut check_client = pool.get().await.unwrap();
        let check_tx = check_client.transaction().await.unwrap();
        let route = load_or_init_repo_route(&check_tx, owner, repo_id).await.unwrap();
        drop(check_tx);
        assert_eq!(route.route_epoch, 1, "{name} changed PostgreSQL before commit");
    }
    drop(local);
    drop(pool);
    base.get().await.unwrap().batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await.unwrap();
}

#[tokio::test]
async fn retired_source_rollback_restores_marker_from_committed_route() {
    let Ok(base_url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else { return; };
    let schema = format!("cluster_transition_{}", Uuid::new_v4().simple());
    let base = db::pool(&base_url).unwrap();
    base.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA \"{schema}\"")).await.unwrap();
    let mut url = reqwest::Url::parse(&base_url).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = db::pool(url.as_str()).unwrap();
    db::migrate(&pool).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    // SAFETY: this test's unique node registration is read only after it is written.
    unsafe { std::env::set_var("ROOTYARD_LOCAL_FENCE_DIR", root.path()) };
    let source = state(pool.clone(), root.path().join("source"));
    let target = state(pool.clone(), root.path().join("target"));
    let owner = Uuid::new_v4();
    let repo_id = Uuid::new_v4();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute("INSERT INTO users(id,username) VALUES($1,'fixture')", &[&owner]).await.unwrap();
    tx.execute("INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'demo','ready')", &[&repo_id, &owner]).await.unwrap();
    let route = load_or_init_repo_route(&tx, owner, repo_id).await.unwrap();
    tx.commit().await.unwrap();
    drop(client);
    let node = route.primary_node_id.as_str();
    let dir = source.storage.repo_path(repo_id);
    std::fs::create_dir_all(&dir).unwrap();
    local_fence::register_local_volume(node, &source.storage.root, source.storage.volume_id).unwrap();
    let retired = VolumeFenceMarker {
        version: 1, repository_id: repo_id, primary_node_id: route.primary_node_id.clone(),
        route_epoch: route.route_epoch + 1, fencing_token: route.fencing_token + 2,
        fenced_epoch: route.route_epoch, storage_generation: 2,
        fenced_node_id: Some(route.primary_node_id.clone()), read_only_degraded: true, updated_unix: 1,
    };
    let mut staged = pool.get().await.unwrap();
    let tx = staged.transaction().await.unwrap();
    stage_on_volume(&tx, source.storage.volume_id, &retired).await.unwrap();
    tx.commit().await.unwrap();
    drop(staged);
    local_fence::retire_volume_repository(node, repo_id, &retired).unwrap();
    assert!(crate::sharding::fencing::read_volume_marker_at(&dir).unwrap().unwrap().read_only_degraded);
    reconcile_pending(&target).await.unwrap();
    let restored = crate::sharding::fencing::read_volume_marker_at(&dir).unwrap().unwrap();
    assert!(!restored.read_only_degraded);
    assert_eq!(restored.primary_node_id, route.primary_node_id);
    assert_eq!((restored.route_epoch, restored.fencing_token, restored.fenced_epoch),
        (route.route_epoch, route.fencing_token, route.fenced_epoch));
    assert_eq!(restored.storage_generation, route.required_generation.max(1));
    let row = pool.get().await.unwrap().query_one(
        "SELECT state FROM shard_marker_transitions WHERE repository_id=$1", &[&repo_id]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "complete");
    assert!(reject_pending(&source, repo_id).await.is_ok());
    drop(source);
    drop(target);
    drop(pool);
    base.get().await.unwrap().batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await.unwrap();
}
}
