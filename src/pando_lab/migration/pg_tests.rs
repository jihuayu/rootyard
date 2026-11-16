//! Source-only PostgreSQL behavior cases for migration producer adoption.
//!
//! These cases are intentionally `#[ignore]`d and were not executed in this
//! checkpoint. They run against the real `ROOTYARD_TEST_DATABASE_URL` fixture
//! with the installed `pando_lab` schema. The schema name is fixed by the
//! product SQL, so every case owns a unique repository UUID, temp root and
//! all repo-scoped cleanup rather than replacing the fixture with a mock.

use super::super::{Config, Pack, delta, lifecycle};
use super::producer;
use std::path::{Path, PathBuf};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

fn config_for(label: &str) -> (Config, PathBuf) {
    let database = std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set when running the ignored migration PG cases");
    assert!(!database.trim().is_empty(), "ROOTYARD_TEST_DATABASE_URL must not be empty");
    // Preflight every production override that could escape the temporary
    // fixture root or select a non-Local provider. Presence only: never read or
    // print the external values, and never mutate process-global environment
    // from parallel Rust tests. This runs before any temp directory or DB row.
    for name in
        ["PANDO_OBJECT_STORE_ROOT", "PANDO_KMS_KEYRING_DIR", "PANDO_KMS_PROVIDER", "ROOTYARD_OBJECT_STORE_ENDPOINT"]
    {
        assert!(std::env::var_os(name).is_none(), "migration PG cases require an owned fixture; unset {name}");
    }
    let root = std::env::temp_dir().join(format!("pando-migration-pg-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(root.join("objects")).unwrap();
    std::fs::create_dir_all(root.join("sessions")).unwrap();
    let config = Config { database, root: root.clone(), git: PathBuf::from("/usr/bin/git") };
    (config, root)
}

async fn connect(config: &Config) -> Client {
    let (client, connection) = tokio_postgres::connect(&config.database, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

async fn cleanup(client: &Client, repo: Uuid) {
    for sql in [
        "DELETE FROM pando_lab.migrations WHERE repo=$1",
        "DELETE FROM pando_lab.refs WHERE repo=$1",
        "DELETE FROM pando_lab.objects WHERE repo=$1",
        "DELETE FROM pando_lab.manifests WHERE repo=$1",
        "DELETE FROM pando_lab.object_store_manifests WHERE repo=$1",
        "DELETE FROM pando_lab.kms_envelopes WHERE repo=$1",
        "DELETE FROM pando_lab.kms_key_policies WHERE repo=$1",
        "DELETE FROM pando_lab.lifecycle_policies WHERE repo=$1",
        "DELETE FROM pando_lab.kms_keys WHERE repo=$1",
        "DELETE FROM pando_lab.kms_rotations WHERE repo=$1",
        "DELETE FROM pando_lab.acl WHERE repo=$1",
        "DELETE FROM pando_lab.repositories WHERE id=$1",
    ] {
        let _ = client.execute(sql, &[&repo]).await;
    }
}

async fn table_count(client: &Client, table: &str, repo: Uuid) -> i64 {
    client.query_one(&format!("SELECT count(*) FROM pando_lab.{table} WHERE repo=$1"), &[&repo]).await.unwrap().get(0)
}

async fn pair_count(client: &Client, repo: Uuid) -> (i64, i64) {
    let manifests = table_count(client, "object_store_manifests", repo).await;
    let envelopes = table_count(client, "kms_envelopes", repo).await;
    (manifests, envelopes)
}

async fn init_bare(config: &Config, path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    config.git(path, &["init", "--bare", "--initial-branch=main", "."], b"").await.unwrap();
}

async fn commit_file(config: &Config, gitfs: &Path, file: &str, content: &str, parents: &[&str]) -> String {
    let blob =
        String::from_utf8(config.git(gitfs, &["hash-object", "-w", "--stdin"], content.as_bytes()).await.unwrap())
            .unwrap()
            .trim()
            .to_owned();
    let tree_input = format!("100644 blob {blob}\t{file}\n");
    let tree = String::from_utf8(config.git(gitfs, &["mktree"], tree_input.as_bytes()).await.unwrap())
        .unwrap()
        .trim()
        .to_owned();
    let mut args = vec![
        "-c",
        "user.name=Migration Fixture",
        "-c",
        "user.email=migration@example.invalid",
        "commit-tree",
        tree.as_str(),
        "-m",
        "fixture commit",
    ];
    for parent in parents {
        args.push("-p");
        args.push(*parent);
    }
    String::from_utf8(config.git(gitfs, &args, b"").await.unwrap()).unwrap().trim().to_owned()
}

fn local_checkpoint(repo: Uuid, state: &str, write_epoch: u64) -> lifecycle::rotation::KmsRotationCheckpoint {
    lifecycle::rotation::KmsRotationCheckpoint {
        rotation_id: Uuid::new_v4(),
        repo,
        from_key_id: lifecycle::DEFAULT_KMS_KEY_ID.to_owned(),
        from_key_version: lifecycle::DEFAULT_KMS_KEY_VERSION,
        to_key_id: lifecycle::DEFAULT_KMS_KEY_ID.to_owned(),
        to_key_version: lifecycle::DEFAULT_KMS_KEY_VERSION,
        state: state.to_owned(),
        revoke_previous: false,
        target_pack_ids: Vec::new(),
        completed_pack_ids: Vec::new(),
        failed_pack_id: None,
        from_provider_kind: lifecycle::provider::PROVIDER_KIND_LOCAL.to_owned(),
        to_provider_kind: lifecycle::provider::PROVIDER_KIND_LOCAL.to_owned(),
        expected_to_version: lifecycle::DEFAULT_KMS_KEY_VERSION,
        external_rotate_issued: false,
        reconcile_stage: lifecycle::rotation::KmsReconcileStage::NotIssued,
        target_contract: lifecycle::rotation::EXISTING_TARGET_CONTRACT.to_owned(),
        write_epoch,
    }
}

async fn insert_local_checkpoint(client: &Client, repo: Uuid, state: &str, write_epoch: u64) {
    let checkpoint = local_checkpoint(repo, state, write_epoch);
    let value = serde_json::to_value(&checkpoint).unwrap();
    client
        .execute(
            "INSERT INTO pando_lab.kms_rotations(id,repo,from_key_id,from_key_version,to_key_id,to_key_version,state,revoke_previous,total_packs,processed_packs,failed_pack_id,checkpoint_json) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
            &[
                &checkpoint.rotation_id,
                &repo,
                &checkpoint.from_key_id,
                &checkpoint.from_key_version,
                &checkpoint.to_key_id,
                &checkpoint.to_key_version,
                &checkpoint.state,
                &checkpoint.revoke_previous,
                &(checkpoint.target_pack_ids.len() as i32),
                &(checkpoint.completed_pack_ids.len() as i32),
                &checkpoint.failed_pack_id,
                &value,
            ],
        )
        .await
        .unwrap();
}

fn write_fixture_pack(root: &Path, repo: Uuid, payload: &[u8]) -> Pack {
    let pack_id = Uuid::new_v4();
    let dir = root.join("objects").join(repo.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let mut pack = Vec::from(&b"PACK\x00\x00\x00\x02\x00\x00\x00\x01"[..]);
    pack.push(0x80 | 0x30 | ((payload.len() & 0x0f) as u8));
    pack.push((payload.len() >> 4) as u8);
    pack.extend_from_slice(&delta::compress_zlib_stored(payload));
    let trailer = delta::sha1_digest(&pack);
    pack.extend_from_slice(&trailer);
    let idx = format!("idx-{}", payload.len()).into_bytes();
    std::fs::write(dir.join(format!("{pack_id}.pack")), &pack).unwrap();
    std::fs::write(dir.join(format!("{pack_id}.idx")), &idx).unwrap();
    Pack { id: pack_id, pack_sha256: delta::sha256_hex(&pack), idx_sha256: delta::sha256_hex(&idx) }
}

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

    let report = super::step_copy(&config, repo, &gitfs).await.unwrap();
    assert_eq!(report.state, "COPYING");
    assert_eq!(report.storage_backend, "gitfs");
    assert_eq!(report.migration_state, "copying");
    assert!(!report.write_paused);
    assert!(report.incremental_objects_synced > 0);

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

    let report = super::step_drain(&config, repo, &gitfs).await.unwrap();
    assert_eq!(report.state, "DRAINED");
    assert_eq!(report.migration_state, "draining");
    assert!(report.write_paused);
    assert!(report.incremental_objects_synced > 0);
    assert!(report.diff_report.as_ref().unwrap().matched);
    assert!(report.diff_report.as_ref().unwrap().bit_for_bit_match);
    assert_eq!(pair_count(&admin, repo).await, (2, 2));
    assert_eq!(table_count(&admin, "migrations", repo).await, 1);
    let migration_state: String =
        admin.query_one("SELECT state FROM pando_lab.migrations WHERE repo=$1", &[&repo]).await.unwrap().get(0);
    assert_eq!(migration_state, "DRAINED");
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

    assert_eq!(pair_count(&admin, repo).await, (0, 0));
    assert_eq!(table_count(&admin, "manifests", repo).await, 0);
    assert_eq!(table_count(&admin, "objects", repo).await, 0);
    assert_eq!(table_count(&admin, "refs", repo).await, 0);
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

        let report = super::step_copy(&config, repo, &gitfs).await.unwrap();
        assert_eq!(report.state, "COPYING");
        assert_eq!(report.migration_state, "copying");
        assert_eq!(pair_count(&admin, repo).await, (0, 0));
        assert_eq!(table_count(&admin, "manifests", repo).await, 1);
        assert_eq!(table_count(&admin, "refs", repo).await, 1);
        assert_eq!(table_count(&admin, "migrations", repo).await, 1);
        assert_eq!(
            admin.query("SELECT pack_id FROM pando_lab.kms_envelopes WHERE repo=$1", &[&repo]).await.unwrap().len(),
            0
        );

        cleanup(&admin, repo).await;
    }

    let _ = std::fs::remove_dir_all(&root);
}
