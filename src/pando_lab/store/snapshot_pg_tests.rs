//! Source-only PostgreSQL barrier regressions for retained read snapshots.
//!
//! These cases are `#[ignore]`d and were not executed in this checkpoint.

use super::snapshot_pg_support::*;
use super::super::{repack, store};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_snapshot_wins_retains_old_pack_before_insert() {
    let _lock = test_lock();
    let _hooks = HookGuard::new();
    let Some((config, root)) = config_for("snapshot-wins") else {
        return;
    };
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    insert_repo(&admin, repo).await;
    let (old, _) = seed_single_pack(&config, &admin, repo).await;
    insert_old_metadata(&admin, repo, &old).await;
    let obj_dir = config.root.join("objects").join(repo.to_string());

    let barrier = root.join("barrier");
    set_barrier(Some(barrier.clone()));
    let snapshot_config = config.clone();
    let snapshot = tokio::spawn(async move {
        let mut client = snapshot_config.db().await.unwrap();
        store::snapshot_and_retain(&mut client, repo, "reader").await
    });
    wait_ready(&barrier, "snapshot-after-select").await;
    assert_read_committed(&barrier, "snapshot-after-select");
    // The snapshot waiter already owns this barrier directory. Clear the
    // process-wide arm so the repack seam stays inert for this half of the
    // race; clearing does not wake or cancel the snapshot waiter.
    set_barrier(None);
    let before: i64 = admin
        .query_one("SELECT count(*) FROM pando_lab.snapshots WHERE repo=$1", &[&repo])
        .await
        .unwrap()
        .get(0);
    assert_eq!(before, 0, "no token row may exist before the helper commits");

    let repack_config = config.clone();
    let opts = options();
    let repack = tokio::spawn(async move { repack::repack_repo(&repack_config, repo, &opts).await });
    wait_for_lock_wait(
        &admin,
        "FOR UPDATE",
        "pando_lab.repositories",
        "repack final lock",
        3000,
    )
    .await;

    std::fs::write(barrier.join("snapshot-after-select.release"), b"").unwrap();
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
        .query_one(
            "SELECT count(*) FROM pando_lab.snapshots WHERE id=$1 AND principal='other'",
            &[&token],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(wrong_principal, 0);
    let text = materialize_and_read(
        &config,
        &retained,
        &root.join("materialized"),
        "a.txt",
    )
    .await;
    assert_eq!(text, "one\n");

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_repack_wins_snapshot_selects_replacement_after_commit() {
    let _lock = test_lock();
    let _hooks = HookGuard::new();
    let Some((config, root)) = config_for("repack-wins") else {
        return;
    };
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    insert_repo(&admin, repo).await;
    let (old, _) = seed_single_pack(&config, &admin, repo).await;
    let obj_dir = config.root.join("objects").join(repo.to_string());

    let barrier = root.join("barrier");
    set_barrier(Some(barrier.clone()));
    let repack_config = config.clone();
    let opts = options();
    let repack = tokio::spawn(async move { repack::repack_repo(&repack_config, repo, &opts).await });
    wait_ready(&barrier, "repack-after-lock").await;
    assert_read_committed(&barrier, "repack-after-lock");
    // The repack waiter already owns this barrier directory. Clear the
    // process-wide arm so the snapshot seam stays inert while repack finishes.
    set_barrier(None);

    let snapshot_config = config.clone();
    let snapshot = tokio::spawn(async move {
        let mut client = snapshot_config.db().await.unwrap();
        store::snapshot_and_retain(&mut client, repo, "reader").await
    });
    wait_for_lock_wait(
        &admin,
        "FOR SHARE",
        "pando_lab.repositories",
        "retained snapshot lock",
        900,
    )
    .await;
    let before: i64 = admin
        .query_one("SELECT count(*) FROM pando_lab.snapshots WHERE repo=$1", &[&repo])
        .await
        .unwrap()
        .get(0);
    assert_eq!(before, 0, "the snapshot must not select or insert before repack commits");

    std::fs::write(barrier.join("repack-after-lock.release"), b"").unwrap();
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
    let text = materialize_and_read(
        &config,
        &retained,
        &root.join("materialized"),
        "a.txt",
    )
    .await;
    assert_eq!(text, "one\n");

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(root);
}
