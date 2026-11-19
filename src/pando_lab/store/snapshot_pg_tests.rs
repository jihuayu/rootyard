//! Source-only PostgreSQL barrier regressions for retained read snapshots.
//!
//! These cases are `#[ignore]`d and were not executed in this checkpoint.

use super::super::{repack, store};
use super::snapshot_pg_barrier::*;
use super::snapshot_pg_support::*;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_snapshot_wins_retains_old_pack_before_insert() {
    let _lock = test_lock().await;
    let _hooks = HookGuard::new();
    let (config, root) = config_for("snapshot-wins");
    let repo = Uuid::new_v4();
    let nonce = case_nonce();
    let admin_name = actor_appname(&nonce, repo, "admin");
    let snapshot_name = actor_appname(&nonce, repo, "snap");
    let repack_name = actor_appname(&nonce, repo, "repack");
    let admin = connect_named(&config, &admin_name).await;
    insert_repo(&admin, repo).await;
    let (old, _) = seed_single_pack(&config, &admin, repo).await;
    insert_old_metadata(&admin, repo, &old).await;
    let obj_dir = config.root.join("objects").join(repo.to_string());

    let case = BarrierCase::arm(root.join("barrier"), repo, "snapshot-after-select", &snapshot_name, &nonce);
    let snapshot_config = actor_config(&config, &snapshot_name);
    let snapshot = tokio::spawn(async move {
        let mut client = snapshot_config.db().await.unwrap();
        store::snapshot_and_retain(&mut client, repo, "reader").await
    });
    case.wait_ready().await;
    case.assert_read_committed();
    let before: i64 =
        admin.query_one("SELECT count(*) FROM pando_lab.snapshots WHERE repo=$1", &[&repo]).await.unwrap().get(0);
    assert_eq!(before, 0, "no token row may exist before the helper commits");

    let repack_config = actor_config(&config, &repack_name);
    let opts = options();
    let repack = tokio::spawn(async move { repack::repack_repo(&repack_config, repo, &opts).await });
    wait_for_actor_lock_wait(&admin, &repack_name, repo, "FOR UPDATE", 3000).await;

    case.release();
    let token = snapshot.await.unwrap().unwrap();
    let report = repack.await.unwrap().unwrap();

    assert!(report.snapshot_retained_packs.contains(&old.id));
    assert!(!report.superseded_packs.contains(&old.id));
    assert!(obj_dir.join(format!("{}.pack", old.id)).is_file());
    assert!(obj_dir.join(format!("{}.idx", old.id)).is_file());
    assert_eq!(metadata_count(&admin, repo, old.id).await, 1);
    let retained = retained_snapshot(&admin, token, repo, "reader").await;
    assert!(retained.packs.iter().any(|pack| pack.id == old.id));
    assert_token_ttl(&admin, token).await;
    let wrong_principal: i64 = admin
        .query_one("SELECT count(*) FROM pando_lab.snapshots WHERE id=$1 AND principal='other'", &[&token])
        .await
        .unwrap()
        .get(0);
    assert_eq!(wrong_principal, 0);
    let text = materialize_and_read(&config, &retained, &root.join("materialized"), "a.txt").await;
    assert_eq!(text, "one\n");

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_repack_wins_snapshot_selects_replacement_after_commit() {
    let _lock = test_lock().await;
    let _hooks = HookGuard::new();
    let (config, root) = config_for("repack-wins");
    let repo = Uuid::new_v4();
    let nonce = case_nonce();
    let admin_name = actor_appname(&nonce, repo, "admin");
    let snapshot_name = actor_appname(&nonce, repo, "snap");
    let repack_name = actor_appname(&nonce, repo, "repack");
    let admin = connect_named(&config, &admin_name).await;
    insert_repo(&admin, repo).await;
    let (old, _) = seed_single_pack(&config, &admin, repo).await;
    let obj_dir = config.root.join("objects").join(repo.to_string());

    let case = BarrierCase::arm(root.join("barrier"), repo, "repack-after-lock", &repack_name, &nonce);
    let repack_config = actor_config(&config, &repack_name);
    let opts = options();
    let repack = tokio::spawn(async move { repack::repack_repo(&repack_config, repo, &opts).await });
    case.wait_ready().await;
    case.assert_read_committed();

    let snapshot_config = actor_config(&config, &snapshot_name);
    let snapshot = tokio::spawn(async move {
        let mut client = snapshot_config.db().await.unwrap();
        store::snapshot_and_retain(&mut client, repo, "reader").await
    });
    wait_for_actor_lock_wait(&admin, &snapshot_name, repo, "FOR SHARE", 900).await;
    let before: i64 =
        admin.query_one("SELECT count(*) FROM pando_lab.snapshots WHERE repo=$1", &[&repo]).await.unwrap().get(0);
    assert_eq!(before, 0, "the snapshot must not select or insert before repack commits");

    case.release();
    let report = repack.await.unwrap().unwrap();
    let token = snapshot.await.unwrap().unwrap();

    assert!(report.superseded_packs.contains(&old.id));
    assert!(!report.snapshot_retained_packs.contains(&old.id));
    assert!(!obj_dir.join(format!("{}.pack", old.id)).exists());
    assert!(!obj_dir.join(format!("{}.idx", old.id)).exists());
    let retained = retained_snapshot(&admin, token, repo, "reader").await;
    let replacement = report.compacted_pack_id.expect("compacted replacement pack");
    assert_eq!(retained.packs.len(), 1);
    assert_eq!(retained.packs[0].id, replacement);
    assert!(!retained.packs.iter().any(|pack| pack.id == old.id));
    let text = materialize_and_read(&config, &retained, &root.join("materialized"), "a.txt").await;
    assert_eq!(text, "one\n");

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(root);
}
