//! Source-only PostgreSQL behavior cases for migration producer adoption.
//!
//! These cases are intentionally `#[ignore]`d and were not executed in this
//! checkpoint. They run against the real `ROOTYARD_TEST_DATABASE_URL` fixture
//! with the installed `pando_lab` schema. The schema name is fixed by the
//! product SQL, so every case owns a unique repository UUID, temp root and
//! all repo-scoped cleanup rather than replacing the fixture with a mock.
//! Fixture preflight and complete-row assertions live in `pg_test_support`.

use super::super::lifecycle;
use super::pg_test_support::*;
use super::producer;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the installed pando_lab schema"]
async fn pg_copy_authenticated_publication_commits_pair_rows_and_mirror_together() {
    let (config, root) = config_for("copy");
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id, storage_generation) VALUES($1, 1)", &[&repo]).await.unwrap();
    let gitfs = root.join("gitfs.git");
    init_bare(&config, &gitfs).await;
    let first = commit_file(&config, &gitfs, "app.txt", "one\n", &[]).await;
    config.git(&gitfs, &["update-ref", "refs/heads/main", first.as_str()], b"").await.unwrap();
    insert_local_checkpoint(&admin, repo, "IN_PROGRESS", 1).await;

    let gitfs_path = std::fs::canonicalize(&gitfs).unwrap().to_string_lossy().into_owned();
    let report = super::step_copy(&config, repo, &gitfs).await.unwrap();
    assert_eq!(report.state, "COPYING");
    assert_eq!(report.storage_backend, "gitfs");
    assert_eq!(report.migration_state, "copying");
    assert!(!report.write_paused);
    assert_eq!(report.generation, 1);
    assert_eq!(report.old_storage_generation, 1);
    assert_eq!(report.new_storage_generation, 1);
    assert_eq!(report.copied_packs, 1);
    assert!(report.copied_objects > 0);
    assert!(report.incremental_objects_synced > 0);
    assert_repo_row(&admin, repo, 1, 1, "gitfs", "copying", false, Some(&gitfs_path)).await;
    assert_migration_row(&admin, repo, "COPYING").await;
    assert_key_policy(&admin, repo).await;

    assert_eq!(pair_count(&admin, repo).await, (1, 1));
    assert_eq!(table_count(&admin, "manifests", repo).await, 1);
    assert!(table_count(&admin, "objects", repo).await > 0);
    assert_eq!(table_count(&admin, "refs", repo).await, 1);
    assert_eq!(table_count(&admin, "migrations", repo).await, 1);
    let pack_id: Uuid =
        admin.query_one("SELECT pack_id FROM pando_lab.manifests WHERE repo=$1", &[&repo]).await.unwrap().get(0);
    let envelope = admin
        .query_one(
            "SELECT provider_kind,key_id,key_version FROM pando_lab.kms_envelopes WHERE repo=$1 AND pack_id=$2",
            &[&repo, &pack_id],
        )
        .await
        .unwrap();
    assert_eq!(envelope.get::<_, String>(0), lifecycle::provider::PROVIDER_KIND_LOCAL);
    assert_eq!(envelope.get::<_, String>(1), lifecycle::DEFAULT_KMS_KEY_ID);
    assert_eq!(envelope.get::<_, i32>(2), lifecycle::DEFAULT_KMS_KEY_VERSION);
    assert!(lifecycle::envelope_file_path(&config.root, repo, pack_id).is_file());
    let ref_oid: String =
        admin.query_one("SELECT oid FROM pando_lab.refs WHERE repo=$1", &[&repo]).await.unwrap().get(0);
    assert_eq!(ref_oid, first);

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the installed pando_lab schema"]
async fn pg_drain_authenticated_incremental_publication_is_atomic_and_targeted() {
    let (config, root) = config_for("drain");
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id, storage_generation) VALUES($1, 1)", &[&repo]).await.unwrap();
    let gitfs = root.join("gitfs.git");
    init_bare(&config, &gitfs).await;
    let first = commit_file(&config, &gitfs, "app.txt", "one\n", &[]).await;
    config.git(&gitfs, &["update-ref", "refs/heads/main", first.as_str()], b"").await.unwrap();
    insert_local_checkpoint(&admin, repo, "IN_PROGRESS", 1).await;
    super::step_copy(&config, repo, &gitfs).await.unwrap();

    let second = commit_file(&config, &gitfs, "app.txt", "two\n", &[first.as_str()]).await;
    config.git(&gitfs, &["update-ref", "refs/heads/main", second.as_str()], b"").await.unwrap();

    let gitfs_path = std::fs::canonicalize(&gitfs).unwrap().to_string_lossy().into_owned();
    let report = super::step_drain(&config, repo, &gitfs).await.unwrap();
    assert_eq!(report.state, "DRAINED");
    assert_eq!(report.migration_state, "draining");
    assert!(report.write_paused);
    assert_eq!(report.generation, 2);
    assert_eq!(report.old_storage_generation, 1);
    assert_eq!(report.new_storage_generation, 1);
    assert_eq!(report.copied_packs, 2);
    assert!(report.copied_objects > 0);
    assert!(report.incremental_objects_synced > 0);
    assert!(report.diff_report.as_ref().unwrap().matched);
    assert!(report.diff_report.as_ref().unwrap().bit_for_bit_match);
    assert_repo_row(&admin, repo, 2, 1, "gitfs", "draining", true, Some(&gitfs_path)).await;
    assert_migration_row(&admin, repo, "DRAINED").await;
    assert_key_policy(&admin, repo).await;
    assert_eq!(pair_count(&admin, repo).await, (2, 2));
    let ref_oid: String =
        admin.query_one("SELECT oid FROM pando_lab.refs WHERE repo=$1", &[&repo]).await.unwrap().get(0);
    assert_eq!(ref_oid, second);
    let envelopes = admin
        .query("SELECT provider_kind,key_id,key_version FROM pando_lab.kms_envelopes WHERE repo=$1", &[&repo])
        .await
        .unwrap();
    assert_eq!(envelopes.len(), 2);
    for envelope in envelopes {
        assert_eq!(envelope.get::<_, String>(0), lifecycle::provider::PROVIDER_KIND_LOCAL);
        assert_eq!(envelope.get::<_, String>(1), lifecycle::DEFAULT_KMS_KEY_ID);
        assert_eq!(envelope.get::<_, i32>(2), lifecycle::DEFAULT_KMS_KEY_VERSION);
    }
    for row in admin.query("SELECT pack_id FROM pando_lab.manifests WHERE repo=$1", &[&repo]).await.unwrap() {
        let pack_id: Uuid = row.get(0);
        assert!(lifecycle::envelope_file_path(&config.root, repo, pack_id).is_file());
    }

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the installed pando_lab schema"]
async fn pg_publication_rollback_leaves_no_authority_rows_or_mirror() {
    let (config, root) = config_for("rollback");
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id, storage_generation) VALUES($1, 1)", &[&repo]).await.unwrap();
    insert_local_checkpoint(&admin, repo, "IN_PROGRESS", 1).await;
    assert_repo_row(&admin, repo, 0, 1, "pando", "idle", false, None).await;
    let pack = write_fixture_pack(&config.root, repo, b"rollback-pack");

    let mut session = producer::ProducerSession::begin(&config, repo).await.unwrap();
    assert!(session.needs_prepared());
    let prepared = session.prepare(&config, repo, &pack).await.unwrap().unwrap();
    let t = session.client_mut().transaction().await.unwrap();
    t.execute(
        "INSERT INTO pando_lab.manifests(repo,pack_id,pack_sha256,idx_sha256) VALUES($1,$2,$3,$4)",
        &[&repo, &pack.id, &pack.pack_sha256, &pack.idx_sha256],
    )
    .await
    .unwrap();
    let oid = "a".repeat(40);
    t.execute("INSERT INTO pando_lab.objects(repo,oid,pack_id) VALUES($1,$2,$3)", &[&repo, &oid, &pack.id])
        .await
        .unwrap();
    t.execute("INSERT INTO pando_lab.refs(repo,name,oid) VALUES($1,'refs/heads/main',$2)", &[&repo, &oid])
        .await
        .unwrap();
    let _receipt = prepared.publish_in(&t).await.unwrap();
    assert!(!lifecycle::envelope_file_path(&config.root, repo, pack.id).exists());
    t.rollback().await.unwrap();

    assert_repo_row(&admin, repo, 0, 1, "pando", "idle", false, None).await;
    assert_eq!(pair_count(&admin, repo).await, (0, 0));
    assert_no_authority(&admin, repo).await;
    assert!(!lifecycle::envelope_file_path(&config.root, repo, pack.id).exists());

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the installed pando_lab schema"]
async fn pg_exact_preparation_retry_returns_same_physical_winner() {
    let (config, root) = config_for("retry");
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id, storage_generation) VALUES($1, 1)", &[&repo]).await.unwrap();
    insert_local_checkpoint(&admin, repo, "IN_PROGRESS", 1).await;
    let pack = write_fixture_pack(&config.root, repo, b"exact-retry-pack");

    let mut session = producer::ProducerSession::begin(&config, repo).await.unwrap();
    let prepared = session.prepare(&config, repo, &pack).await.unwrap().unwrap();
    let t = session.client_mut().transaction().await.unwrap();
    let first = prepared.publish_in(&t).await.unwrap();
    t.commit().await.unwrap();
    first.refresh_mirrors();
    let first_envelope = first.envelope().envelope_id;
    let first_report = first.report();
    let first_ciphertext = std::fs::read(first_report.bucket_pack_path.as_str()).unwrap();
    drop(session);

    let mut session = producer::ProducerSession::begin(&config, repo).await.unwrap();
    let selected = session.checkpoint().cloned();
    let retry = session.prepare(&config, repo, &pack).await.unwrap().unwrap();
    let t = session.client_mut().transaction().await.unwrap();
    let winner = retry.publish_in(&t).await.unwrap();
    producer::validate_receipt(&winner, repo, &pack, selected.as_ref()).unwrap();
    t.commit().await.unwrap();
    winner.refresh_mirrors();

    assert_repo_row(&admin, repo, 0, 1, "pando", "idle", false, None).await;
    assert_key_policy(&admin, repo).await;
    assert_eq!(pair_count(&admin, repo).await, (1, 1));
    assert_eq!(winner.envelope().envelope_id, first_envelope);
    assert_eq!(std::fs::read(winner.report().bucket_pack_path.as_str()).unwrap(), first_ciphertext);
    assert_eq!(winner.manifest(), retry.manifest());

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the installed pando_lab schema"]
async fn pg_stale_repository_generation_fails_before_commit() {
    let (config, root) = config_for("stale");
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id, storage_generation) VALUES($1, 1)", &[&repo]).await.unwrap();
    let mut session = producer::ProducerSession::begin(&config, repo).await.unwrap();
    let t = session.client_mut().transaction().await.unwrap();
    let stale = producer::lock_repo_and_validate(
        &t,
        repo,
        &producer::ExpectedRepoState {
            generation: 1,
            storage_generation: 1,
            storage_backend: "gitfs",
            migration_state: "copying",
            write_paused: false,
            gitfs_path: "/tmp/migration-fixture.git",
        },
    )
    .await;
    assert!(stale.is_err());
    let _ = t
        .execute(
            "INSERT INTO pando_lab.manifests(repo,pack_id,pack_sha256,idx_sha256) VALUES($1,$2,$3,$4)",
            &[&repo, &Uuid::new_v4(), &"a".repeat(64), &"b".repeat(64)],
        )
        .await;
    t.rollback().await.unwrap();
    assert_eq!(table_count(&admin, "manifests", repo).await, 0);

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the installed pando_lab schema"]
async fn pg_shared_gate_blocks_exclusive_rotation_and_stale_target_fails_cleanly() {
    let (config, root) = config_for("target-race");
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id, storage_generation) VALUES($1, 1)", &[&repo]).await.unwrap();
    insert_local_checkpoint(&admin, repo, "IN_PROGRESS", 1).await;

    let mut session = producer::ProducerSession::begin(&config, repo).await.unwrap();
    let selected = session.checkpoint().cloned().unwrap();
    let rival = lifecycle::publication::PgSession::connect(&config).await.unwrap();
    assert!(rival.acquire_publication_exclusive(repo).await.is_err());
    drop(rival);

    // A real rotation cannot pass the shared gate while this session is held.
    // Simulate the stale-selection branch directly and prove it fails closed.
    let changed = local_checkpoint(repo, "IN_PROGRESS", 2);
    let value = serde_json::to_value(&changed).unwrap();
    admin
        .execute(
            "UPDATE pando_lab.kms_rotations SET checkpoint_json=$2, state='IN_PROGRESS' WHERE repo=$1",
            &[&repo, &value],
        )
        .await
        .unwrap();

    let t = session.client_mut().transaction().await.unwrap();
    let fresh = lifecycle::publication::active_rotation(t.client(), repo).await.unwrap();
    assert!(producer::ensure_target_unchanged(Some(&selected), fresh.as_ref()).is_err());
    t.rollback().await.unwrap();
    assert_eq!(table_count(&admin, "manifests", repo).await, 0);
    assert_eq!(table_count(&admin, "object_store_manifests", repo).await, 0);
    assert_eq!(table_count(&admin, "kms_envelopes", repo).await, 0);

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the installed pando_lab schema"]
async fn pg_local_default_and_legacy_completed_epoch_zero_keep_raw_behavior() {
    let (config, root) = config_for("local");
    let admin = connect(&config).await;

    for (label, legacy_epoch_zero) in [("default", false), ("epoch-zero", true)] {
        let repo = Uuid::new_v4();
        if legacy_epoch_zero {
            // Completed Local epoch 0 is a legacy completion row, not a DB pin.
            admin
                .execute("INSERT INTO pando_lab.repositories(id, storage_generation) VALUES($1, 1)", &[&repo])
                .await
                .unwrap();
            insert_local_checkpoint(&admin, repo, "COMPLETED", 0).await;
        }
        let gitfs = root.join(format!("{label}.git"));
        init_bare(&config, &gitfs).await;
        let commit = commit_file(&config, &gitfs, "local.txt", label, &[]).await;
        config.git(&gitfs, &["update-ref", "refs/heads/main", commit.as_str()], b"").await.unwrap();

        let gitfs_path = std::fs::canonicalize(&gitfs).unwrap().to_string_lossy().into_owned();
        let report = super::step_copy(&config, repo, &gitfs).await.unwrap();
        assert_eq!(report.state, "COPYING");
        assert_eq!(report.migration_state, "copying");
        assert_eq!(report.generation, 1);
        assert_repo_row(&admin, repo, 1, 1, "gitfs", "copying", false, Some(&gitfs_path)).await;
        assert_migration_row(&admin, repo, "COPYING").await;
        assert_eq!(pair_count(&admin, repo).await, (0, 0));
        assert_eq!(table_count(&admin, "kms_key_policies", repo).await, 0);
        assert_eq!(table_count(&admin, "manifests", repo).await, 1);
        assert_eq!(table_count(&admin, "refs", repo).await, 1);
        assert_eq!(table_count(&admin, "migrations", repo).await, 1);

        cleanup(&admin, repo).await;
    }

    let _ = std::fs::remove_dir_all(&root);
}
