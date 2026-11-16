//! Source-only PostgreSQL cases for snapshot rollback and expiry boundaries.
//!
//! These cases are `#[ignore]`d and were not executed in this checkpoint.

use super::snapshot_pg_barrier::*;
use super::snapshot_pg_support::*;
use super::super::{repack, store};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_snapshot_fault_rolls_back_without_token_and_releases_lock() {
    let _lock = test_lock();
    let _hooks = HookGuard::new();
    let (config, root) = config_for("snapshot-rollback");
    let repo = Uuid::new_v4();
    let nonce = case_nonce();
    let admin_name = actor_appname(&nonce, repo, "admin");
    let admin = connect_named(&config, &admin_name).await;
    insert_repo(&admin, repo).await;
    seed_single_pack(&config, &admin, repo).await;

    arm_fault("snapshot-before-commit", repo);
    let mut client = config.db().await.unwrap();
    let error = store::snapshot_and_retain(&mut client, repo, "reader")
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("snapshot retention test fault"));
    // Drain the client after the dropped transaction so the rollback is
    // complete before the lock-release probe.
    let _ = client.simple_query("SELECT 1").await.unwrap();

    let rows: i64 = admin
        .query_one("SELECT count(*) FROM pando_lab.snapshots WHERE repo=$1", &[&repo])
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 0, "a failed helper must not expose a token row");

    let probe_name = actor_appname(&nonce, repo, "probe");
    let probe = connect_named(&config, &probe_name).await;
    let row = probe
        .query_one(
            "SELECT generation FROM pando_lab.repositories WHERE id=$1 FOR UPDATE NOWAIT",
            &[&repo],
        )
        .await
        .expect("the repository lock must be released by rollback");
    let _: i64 = row.get(0);

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_snapshot_retention_uses_live_expiry_not_expired_rows() {
    let _lock = test_lock();
    let _hooks = HookGuard::new();
    let (config, root) = config_for("snapshot-expiry");
    let repo = Uuid::new_v4();
    let nonce = case_nonce();
    let admin = connect_named(&config, &actor_appname(&nonce, repo, "admin")).await;
    insert_repo(&admin, repo).await;
    let (live, expired) = seed_two_packs(&config, &admin, repo).await;
    insert_snapshot(&admin, repo, "live", &[live.clone()], "1 minute").await;
    insert_snapshot(&admin, repo, "expired", &[expired.clone()], "-1 minute").await;

    let opts = options();
    let report = repack::repack_repo(&config, repo, &opts).await.unwrap();
    let obj_dir = config.root.join("objects").join(repo.to_string());
    assert!(report.snapshot_retained_packs.contains(&live.id));
    assert!(report.superseded_packs.contains(&expired.id));
    assert!(!report.snapshot_retained_packs.contains(&expired.id));
    assert!(obj_dir.join(format!("{}.pack", live.id)).is_file());
    assert!(obj_dir.join(format!("{}.idx", live.id)).is_file());
    assert!(!obj_dir.join(format!("{}.pack", expired.id)).exists());
    assert!(!obj_dir.join(format!("{}.idx", expired.id)).exists());

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_ordinary_snapshot_still_does_not_retain() {
    let _lock = test_lock();
    let _hooks = HookGuard::new();
    let (config, root) = config_for("ordinary-snapshot");
    let repo = Uuid::new_v4();
    let nonce = case_nonce();
    let admin = connect_named(&config, &actor_appname(&nonce, repo, "admin")).await;
    insert_repo(&admin, repo).await;
    let (pack, _) = seed_single_pack(&config, &admin, repo).await;

    let snapshot = store::snapshot(&config, repo).await.unwrap();
    assert_eq!(snapshot.repo, repo);
    assert!(snapshot.packs.iter().any(|candidate| candidate.id == pack.id));
    let rows: i64 = admin
        .query_one("SELECT count(*) FROM pando_lab.snapshots WHERE repo=$1", &[&repo])
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 0, "the ordinary readiness read must not create a token");

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(root);
}
