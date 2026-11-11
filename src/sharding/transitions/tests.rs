use super::*;
use crate::{
    config::Config, db, dispatch, metrics, sharding::router::load_or_init_repo_route, storage::Storage,
};
use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration};

static FENCE_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn state(pool: deadpool_postgres::Pool, root: PathBuf) -> AppState {
    let config = Config {
        database_url: String::new(), data_dir: root, bind: "127.0.0.1:0".parse().unwrap(),
        git: PathBuf::from("/usr/local/bin/git"), max_request_bytes: 1024 * 1024,
        max_output_bytes: 1024 * 1024, max_concurrent_git: 1, git_timeout: Duration::from_secs(10),
        git_memory_bytes: 1024 * 1024 * 1024, max_repo_bytes: 1024 * 1024,
        max_pending_deliveries: 100, outbox_worker: false, metrics_bind: None,
    };
    let storage = Storage::open(&config).unwrap();
    AppState {
        mirror_primary: None, dispatch: dispatch::Signals::default(), config, pool, storage,
        hooks: None, transfer_metrics: Arc::new(metrics::TransferCounters::default()),
        git_slots: Arc::new(tokio::sync::Semaphore::new(1)),
    }
}

async fn db_fixture() -> Option<(
    deadpool_postgres::Pool,
    deadpool_postgres::Pool,
    String,
    tempfile::TempDir,
)> {
    let base_url = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok()?;
    let schema = format!("cluster_transition_{}", Uuid::new_v4().simple());
    let base = db::pool(&base_url).unwrap();
    base.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA \"{schema}\"")).await.unwrap();
    let mut url = reqwest::Url::parse(&base_url).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = db::pool(url.as_str()).unwrap();
    db::migrate(&pool).await.unwrap();
    Some((base, pool, schema, tempfile::tempdir().unwrap()))
}

async fn transition_state(pool: &deadpool_postgres::Pool, repo_id: Uuid) -> String {
    pool.get().await.unwrap().query_one(
        "SELECT state FROM shard_marker_transitions WHERE repository_id=$1 \
         ORDER BY created_at DESC, id DESC LIMIT 1",
        &[&repo_id],
    ).await.unwrap().get(0)
}

#[tokio::test]
async fn committed_but_unpublished_marker_reconciles_only_on_own_volume() {
    let Some((base, pool, schema, root)) = db_fixture().await else { return; };
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
    let Some((base, pool, schema, root)) = db_fixture().await else { return; };
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
    let Some((base, pool, schema, root)) = db_fixture().await else { return; };
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let _fence_guard = FENCE_ENV_LOCK.lock().await;
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
    unsafe { std::env::remove_var("ROOTYARD_LOCAL_FENCE_DIR") };
    drop(_fence_guard);
    drop(source);
    drop(target);
    drop(pool);
    base.get().await.unwrap().batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await.unwrap();
}

#[tokio::test]
async fn reconcile_pending_isolates_per_row_failures() {
    let Some((base, pool, schema, root)) = db_fixture().await else { return; };
    let local = state(pool.clone(), root.path().join("local"));
    let owner = Uuid::new_v4();
    let bad_repo = Uuid::new_v4();
    let good_repo = Uuid::new_v4();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute("INSERT INTO users(id,username) VALUES($1,'fixture')", &[&owner]).await.unwrap();
    for (id, name) in [(bad_repo, "bad"), (good_repo, "good")] {
        tx.execute(
            "INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,$3,'ready')",
            &[&id, &owner, &name],
        ).await.unwrap();
    }
    let bad_route = load_or_init_repo_route(&tx, owner, bad_repo).await.unwrap();
    let good_route = load_or_init_repo_route(&tx, owner, good_repo).await.unwrap();
    let bad_marker = VolumeFenceMarker {
        route_epoch: bad_route.route_epoch + 1,
        fencing_token: bad_route.fencing_token + 1,
        ..VolumeFenceMarker::from_route(&bad_route, 1, None, 1)
    };
    let good_marker = VolumeFenceMarker::from_route(&good_route, 1, None, 1);
    stage(&tx, &local, &bad_marker).await.unwrap();
    stage(&tx, &local, &good_marker).await.unwrap();
    tx.execute(
        "UPDATE shard_marker_transitions SET created_at=clock_timestamp()-interval '1 minute' \
         WHERE repository_id=$1",
        &[&bad_repo],
    ).await.unwrap();
    tx.commit().await.unwrap();
    drop(client);
    for repo_id in [bad_repo, good_repo] {
        std::fs::create_dir_all(local.storage.repo_path(repo_id)).unwrap();
    }
    assert!(reconcile_pending(&local).await.is_err());
    assert!(reject_pending(&local, bad_repo).await.is_err());
    assert!(reject_pending(&local, good_repo).await.is_ok());
    let written = crate::sharding::fencing::read_volume_marker_at(
        &local.storage.repo_path(good_repo),
    ).unwrap().unwrap();
    assert_eq!(written, good_marker);
    drop(local);
    drop(pool);
    base.get().await.unwrap().batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await.unwrap();
}

#[tokio::test]
async fn superseded_epoch_reconciles_proven_retirement_and_rejects_forged_markers() {
    let Some((base, pool, schema, root)) = db_fixture().await else { return; };
    let local = state(pool.clone(), root.path().join("local"));
    let owner = Uuid::new_v4();
    let repo_id = Uuid::new_v4();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute("INSERT INTO users(id,username) VALUES($1,'fixture')", &[&owner]).await.unwrap();
    tx.execute(
        "INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'demo','ready')",
        &[&repo_id, &owner],
    ).await.unwrap();
    let route = load_or_init_repo_route(&tx, owner, repo_id).await.unwrap();
    let source = route.primary_node_id.clone();
    for node in ["node-b", "node-c"] {
        tx.execute(
            "INSERT INTO shard_nodes(node_id,endpoint,role,status) \
             VALUES($1,$2,'replica','healthy')",
            &[&node, &format!("http://{node}")],
        ).await.unwrap();
    }
    tx.execute(
        "UPDATE repository_shard_routes SET primary_node_id='node-c',route_epoch=3, \
         fencing_token=3,fenced_epoch=2,required_generation=3 WHERE repository_id=$1",
        &[&repo_id],
    ).await.unwrap();
    tx.execute(
        "UPDATE repositories SET storage_generation=3 WHERE id=$1",
        &[&repo_id],
    ).await.unwrap();
    let marker = VolumeFenceMarker {
        version: 1, repository_id: repo_id, primary_node_id: source.clone(),
        route_epoch: 2, fencing_token: 2, fenced_epoch: 1, storage_generation: 2,
        fenced_node_id: Some(source.clone()), read_only_degraded: true, updated_unix: 1,
    };
    stage(&tx, &local, &marker).await.unwrap();
    tx.commit().await.unwrap();
    drop(client);
    std::fs::create_dir_all(local.storage.repo_path(repo_id)).unwrap();
    assert!(reconcile_pending(&local).await.is_err());
    assert_eq!(transition_state(&pool, repo_id).await, "pending");
    let client = pool.get().await.unwrap();
    client.execute(
        "INSERT INTO shard_replication_operations \
         (id,repository_id,source_node_id,target_node_id,source_route_epoch,source_generation,state) \
         VALUES($1,$2,$3,'node-b',1,2,'completed')",
        &[&Uuid::new_v4(), &repo_id, &source],
    ).await.unwrap();
    drop(client);
    reconcile_pending(&local).await.unwrap();
    assert_eq!(transition_state(&pool, repo_id).await, "complete");
    let written = crate::sharding::fencing::read_volume_marker_at(&local.storage.repo_path(repo_id))
        .unwrap().unwrap();
    assert_eq!(written, marker);
    assert!(written.read_only_degraded);

    let mut client = pool.get().await.unwrap();
    client.execute(
        "DELETE FROM shard_replication_operations WHERE repository_id=$1",
        &[&repo_id],
    ).await.unwrap();
    let tx = client.transaction().await.unwrap();
    stage(&tx, &local, &marker).await.unwrap();
    tx.commit().await.unwrap();
    drop(client);
    assert!(reconcile_pending(&local).await.is_err());
    let client = pool.get().await.unwrap();
    client.execute(
        "INSERT INTO shard_failover_operations \
         (id,tenant_id,repository_id,old_primary_node_id,new_primary_node_id,old_route_epoch, \
          new_route_epoch,fencing_token,storage_generation,state) \
         VALUES($1,$2,$3,$4,'node-b',1,2,2,2,'promoted')",
        &[&Uuid::new_v4(), &owner, &repo_id, &source],
    ).await.unwrap();
    drop(client);
    reconcile_pending(&local).await.unwrap();
    assert_eq!(transition_state(&pool, repo_id).await, "complete");

    let repo_b = Uuid::new_v4();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    tx.execute(
        "INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'demo-b','ready')",
        &[&repo_b, &owner],
    ).await.unwrap();
    let route_b = load_or_init_repo_route(&tx, owner, repo_b).await.unwrap();
    let node_a = route_b.primary_node_id.clone();
    tx.execute(
        "UPDATE repository_shard_routes SET route_epoch=3,fencing_token=3,fenced_epoch=2, \
         required_generation=3 WHERE repository_id=$1",
        &[&repo_b],
    ).await.unwrap();
    tx.execute(
        "UPDATE repositories SET storage_generation=3 WHERE id=$1",
        &[&repo_b],
    ).await.unwrap();
    let multi_hop = VolumeFenceMarker {
        version: 1, repository_id: repo_b, primary_node_id: node_a.clone(),
        route_epoch: 2, fencing_token: 2, fenced_epoch: 1, storage_generation: 2,
        fenced_node_id: Some(node_a.clone()), read_only_degraded: true, updated_unix: 1,
    };
    stage(&tx, &local, &multi_hop).await.unwrap();
    tx.commit().await.unwrap();
    drop(client);
    std::fs::create_dir_all(local.storage.repo_path(repo_b)).unwrap();
    assert!(reconcile_pending(&local).await.is_err());
    assert_eq!(transition_state(&pool, repo_b).await, "pending");
    let client = pool.get().await.unwrap();
    for (old, new, epoch, generation) in [
        (node_a.as_str(), "node-b", 2_i64, 2_i64),
        ("node-b", node_a.as_str(), 3_i64, 3_i64),
    ] {
        client.execute(
            "INSERT INTO shard_failover_operations \
             (id,tenant_id,repository_id,old_primary_node_id,new_primary_node_id,old_route_epoch, \
              new_route_epoch,fencing_token,storage_generation,state) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$7,$8,'promoted')",
            &[&Uuid::new_v4(), &owner, &repo_b, &old, &new, &(epoch - 1), &epoch, &generation],
        ).await.unwrap();
    }
    drop(client);
    reconcile_pending(&local).await.unwrap();
    assert_eq!(transition_state(&pool, repo_b).await, "complete");
    let restored = crate::sharding::fencing::read_volume_marker_at(&local.storage.repo_path(repo_b))
        .unwrap().unwrap();
    assert!(!restored.read_only_degraded);
    assert_eq!(restored.primary_node_id, node_a);
    assert_eq!(restored.fenced_node_id, None);
    assert_eq!(
        (
            restored.route_epoch,
            restored.fencing_token,
            restored.fenced_epoch,
            restored.storage_generation,
        ),
        (3, 3, 2, 3)
    );
    drop(local);
    drop(pool);
    base.get().await.unwrap().batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await.unwrap();
}
