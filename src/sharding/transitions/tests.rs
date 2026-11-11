use super::*;
mod support;
use support::*;

use crate::{db, sharding::router::load_or_init_repo_route};
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn committed_but_unpublished_marker_reconciles_only_on_own_volume() {
    let Some((base, pool, schema, root)) = db_fixture().await else { return; };
    let local = state(pool.clone(), root.path().join("local"));
    let foreign = state(pool.clone(), root.path().join("foreign"));
    let owner = Uuid::new_v4();
    let token_id = Uuid::new_v4();
    let digest = vec![7_u8; 32];
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let (repo_id, route) = seed_route(&tx, owner, "demo").await;
    tx.execute("INSERT INTO tokens(id,user_id,digest) VALUES($1,$2,$3)", &[&token_id, &owner, &digest]).await.unwrap();
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
    drop_schema(base, &schema).await;
}

#[tokio::test]
async fn pre_commit_rollback_keeps_every_transition_marker_unpublished() {
    let Some((base, pool, schema, root)) = db_fixture().await else { return; };
    let local = state(pool.clone(), root.path().join("local"));
    let owner = Uuid::new_v4();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let (repo_id, route) = seed_route(&tx, owner, "demo").await;
    tx.commit().await.unwrap();
    drop(client);
    let dir = local.storage.repo_path(repo_id);
    std::fs::create_dir_all(&dir).unwrap();
    let marker_file = dir.join("rootyard-shard-fence.json");
    let prototype = route_marker(&route, 1, 2, 1, 1, false);
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
        load_or_init_repo_route(&check_tx, owner, repo_id).await.unwrap();
        drop(check_tx);
        assert_eq!(route.route_epoch, 1, "{name} changed PostgreSQL before commit");
    }
    drop(local);
    drop(pool);
    drop_schema(base, &schema).await;
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
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let (repo_id, route) = seed_route(&tx, owner, "demo").await;
    tx.commit().await.unwrap();
    drop(client);
    let node = route.primary_node_id.as_str();
    let dir = source.storage.repo_path(repo_id);
    std::fs::create_dir_all(&dir).unwrap();
    local_fence::register_local_volume(node, &source.storage.root, source.storage.volume_id).unwrap();
    let retired = route_marker(
        &route, route.route_epoch + 1, route.fencing_token + 2, route.route_epoch, 2, true,
    );
    let mut staged = pool.get().await.unwrap();
    let tx = staged.transaction().await.unwrap();
    stage_on_volume(&tx, source.storage.volume_id, &retired).await.unwrap();
    tx.commit().await.unwrap();
    drop(staged);
    local_fence::retire_volume_repository(node, repo_id, &retired).unwrap();
    assert!(read_marker(&source, repo_id).read_only_degraded);
    reconcile_pending(&target).await.unwrap();
    let restored = read_marker(&source, repo_id);
    assert!(!restored.read_only_degraded);
    assert_eq!(restored.primary_node_id, route.primary_node_id);
    assert_eq!((restored.route_epoch, restored.fencing_token, restored.fenced_epoch),
        (route.route_epoch, route.fencing_token, route.fenced_epoch));
    assert_eq!(restored.storage_generation, route.required_generation.max(1));
    assert_eq!(transition_state(&pool, repo_id).await, "complete");
    assert!(reject_pending(&source, repo_id).await.is_ok());
    unsafe { std::env::remove_var("ROOTYARD_LOCAL_FENCE_DIR") };
    drop(_fence_guard);
    drop(source);
    drop(target);
    drop(pool);
    drop_schema(base, &schema).await;
}

#[tokio::test]
async fn reconcile_pending_isolates_per_row_failures() {
    let Some((base, pool, schema, root)) = db_fixture().await else { return; };
    let local = state(pool.clone(), root.path().join("local"));
    let owner = Uuid::new_v4();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let (bad_repo, bad_route) = seed_route(&tx, owner, "bad").await;
    let (good_repo, good_route) = seed_route(&tx, owner, "good").await;
    let bad_marker = route_marker(
        &bad_route, bad_route.route_epoch + 1, bad_route.fencing_token + 1,
        bad_route.fenced_epoch, 1, false,
    );
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
    assert_eq!(read_marker(&local, good_repo), good_marker);
    drop(local);
    drop(pool);
    drop_schema(base, &schema).await;
}

#[tokio::test]
async fn superseded_epoch_reconciles_proven_retirement_and_rejects_forged_markers() {
    let Some((base, pool, schema, root)) = db_fixture().await else { return; };
    let local = state(pool.clone(), root.path().join("local"));
    let owner = Uuid::new_v4();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let (repo_id, route) = seed_route(&tx, owner, "demo").await;
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
    let marker = route_marker(&route, 2, 2, 1, 2, true);
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
    assert_eq!(read_marker(&local, repo_id), marker);

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

    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let (repo_b, route_b) = seed_route(&tx, owner, "demo-b").await;
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
    let multi_hop = route_marker(&route_b, 2, 2, 1, 2, true);
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
    let restored = read_marker(&local, repo_b);
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
    drop_schema(base, &schema).await;
}

#[tokio::test]
async fn foreign_row_repository_mismatch_is_rejected_and_isolated() {
    let Some((base, pool, schema, root)) = db_fixture().await else { return; };
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let _fence_guard = FENCE_ENV_LOCK.lock().await;
    // SAFETY: this test's unique node registration is read only after it is written.
    unsafe { std::env::set_var("ROOTYARD_LOCAL_FENCE_DIR", root.path()) };
    let local = state(pool.clone(), root.path().join("local"));
    let target = state(pool.clone(), root.path().join("target"));
    let owner = Uuid::new_v4();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let (repo_a, route_a) = seed_route(&tx, owner, "repo-a").await;
    let (repo_b, route_b) = seed_route(&tx, owner, "repo-b").await;
    let (own_repo, own_route) = seed_route(&tx, owner, "repo-own").await;
    let corrupt = VolumeFenceMarker {
        repository_id: repo_b, ..route_marker(&route_a, 1, 2, 1, 1, true)
    };
    let own = VolumeFenceMarker {
        repository_id: repo_b, ..route_marker(&own_route, 1, 2, 1, 1, true)
    };
    let valid = route_marker(&route_b, 2, 3, 1, 2, true);
    let corrupt_id = Uuid::new_v4();
    let own_id = Uuid::new_v4();
    for (id, repo_id, volume_id, marker) in [
        (corrupt_id, repo_a, target.storage.volume_id, corrupt),
        (own_id, own_repo, local.storage.volume_id, own),
    ] {
        let target_marker = serde_json::to_value(&marker).unwrap();
        tx.execute(
            "INSERT INTO shard_marker_transitions(id,repository_id,volume_id,target_marker) \
             VALUES($1,$2,$3,$4)",
            &[&id, &repo_id, &volume_id, &target_marker],
        ).await.unwrap();
    }
    stage_on_volume(&tx, target.storage.volume_id, &valid).await.unwrap();
    tx.execute(
        "UPDATE shard_marker_transitions SET created_at=clock_timestamp()-interval '1 minute' \
         WHERE id=$1",
        &[&corrupt_id],
    ).await.unwrap();
    tx.commit().await.unwrap();
    drop(client);
    local_fence::register_local_volume(
        &route_b.primary_node_id, &target.storage.root, target.storage.volume_id,
    ).unwrap();
    std::fs::create_dir_all(target.storage.repo_path(repo_b)).unwrap();
    assert!(reconcile_pending(&local).await.is_err());
    assert_eq!(transition_state(&pool, repo_a).await, "pending");
    assert_eq!(transition_state(&pool, own_repo).await, "pending");
    assert_eq!(transition_state(&pool, repo_b).await, "complete");
    let restored = read_marker(&target, repo_b);
    assert!(!restored.read_only_degraded);
    assert_eq!(restored.fenced_node_id, None);
    assert_eq!((restored.route_epoch, restored.storage_generation), (1, 1));
    unsafe { std::env::remove_var("ROOTYARD_LOCAL_FENCE_DIR") };
    drop(_fence_guard);
    drop(local);
    drop(target);
    drop(pool);
    drop_schema(base, &schema).await;
}

#[tokio::test]
async fn same_primary_epoch_bump_restores_proven_rollback_and_rejects_forged_marker() {
    let Some((base, pool, schema, root)) = db_fixture().await else { return; };
    let local = state(pool.clone(), root.path().join("local"));
    let owner = Uuid::new_v4();
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let (repo_id, route) = seed_route(&tx, owner, "demo").await;
    tx.execute(
        "UPDATE repository_shard_routes SET route_epoch=2,fencing_token=3,fenced_epoch=1, \
         required_generation=1 WHERE repository_id=$1",
        &[&repo_id],
    ).await.unwrap();
    tx.execute("UPDATE repositories SET storage_generation=1 WHERE id=$1", &[&repo_id]).await.unwrap();
    let marker = route_marker(&route, 2, 3, 1, 2, true);
    stage(&tx, &local, &marker).await.unwrap();
    assert!(reject_any_pending(&tx, repo_id).await.is_err());
    tx.commit().await.unwrap();
    drop(client);
    std::fs::create_dir_all(local.storage.repo_path(repo_id)).unwrap();
    assert!(reconcile_pending(&local).await.is_err());
    assert_eq!(transition_state(&pool, repo_id).await, "pending");
    let client = pool.get().await.unwrap();
    client.execute(
        "INSERT INTO shard_nodes(node_id,endpoint,role,status) \
         VALUES('node-b','http://node-b','replica','healthy')",
        &[],
    ).await.unwrap();
    client.execute(
        "INSERT INTO shard_replication_operations \
         (id,repository_id,source_node_id,target_node_id,source_route_epoch,source_generation,state) \
         VALUES($1,$2,$3,'node-b',1,1,'verified')",
        &[&Uuid::new_v4(), &repo_id, &marker.primary_node_id],
    ).await.unwrap();
    drop(client);
    reconcile_pending(&local).await.unwrap();
    assert_eq!(transition_state(&pool, repo_id).await, "complete");
    let restored = read_marker(&local, repo_id);
    assert!(!restored.read_only_degraded);
    assert_eq!(restored.fenced_node_id, None);
    assert_eq!((restored.route_epoch, restored.storage_generation), (2, 1));
    drop(local);
    drop(pool);
    drop_schema(base, &schema).await;
}
