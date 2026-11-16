//! Shared private support for the ignored migration producer PostgreSQL cases.
//!
//! This module contains only test fixture construction, isolation preflight and
//! complete-row assertion helpers. It does not change production behavior.

use super::super::{Config, Pack, delta, lifecycle};
use std::path::{Path, PathBuf};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

pub(super) fn config_for(label: &str) -> (Config, PathBuf) {
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

pub(super) async fn connect(config: &Config) -> Client {
    let (client, connection) = tokio_postgres::connect(&config.database, NoTls).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

pub(super) async fn cleanup(client: &Client, repo: Uuid) {
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

pub(super) async fn table_count(client: &Client, table: &str, repo: Uuid) -> i64 {
    client.query_one(&format!("SELECT count(*) FROM pando_lab.{table} WHERE repo=$1"), &[&repo]).await.unwrap().get(0)
}

pub(super) async fn pair_count(client: &Client, repo: Uuid) -> (i64, i64) {
    let manifests = table_count(client, "object_store_manifests", repo).await;
    let envelopes = table_count(client, "kms_envelopes", repo).await;
    (manifests, envelopes)
}

pub(super) async fn init_bare(config: &Config, path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    config.git(path, &["init", "--bare", "--initial-branch=main", "."], b"").await.unwrap();
}

pub(super) async fn commit_file(config: &Config, gitfs: &Path, file: &str, content: &str, parents: &[&str]) -> String {
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

pub(super) fn local_checkpoint(
    repo: Uuid,
    state: &str,
    write_epoch: u64,
) -> lifecycle::rotation::KmsRotationCheckpoint {
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

pub(super) async fn insert_local_checkpoint(client: &Client, repo: Uuid, state: &str, write_epoch: u64) {
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

pub(super) fn write_fixture_pack(root: &Path, repo: Uuid, payload: &[u8]) -> Pack {
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn assert_repo_row(
    client: &Client,
    repo: Uuid,
    generation: i64,
    storage_generation: i64,
    storage_backend: &str,
    migration_state: &str,
    write_paused: bool,
    gitfs_path: Option<&str>,
) {
    let row = client
        .query_one(
            "SELECT generation,storage_generation,storage_backend,migration_state,write_paused,gitfs_path \
             FROM pando_lab.repositories WHERE id=$1",
            &[&repo],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), generation);
    assert_eq!(row.get::<_, i64>(1), storage_generation);
    assert_eq!(row.get::<_, String>(2), storage_backend);
    assert_eq!(row.get::<_, String>(3), migration_state);
    assert_eq!(row.get::<_, bool>(4), write_paused);
    assert_eq!(row.get::<_, Option<String>>(5).as_deref(), gitfs_path);
}

pub(super) async fn assert_migration_row(client: &Client, repo: Uuid, state: &str) {
    let row = client
        .query_one("SELECT state,copied_packs,copied_objects FROM pando_lab.migrations WHERE repo=$1", &[&repo])
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), state);
    assert_eq!(row.get::<_, i64>(1), table_count(client, "manifests", repo).await);
    assert_eq!(row.get::<_, i64>(2), table_count(client, "objects", repo).await);
}

pub(super) async fn assert_key_policy(client: &Client, repo: Uuid) {
    let row = client
        .query_one(
            "SELECT active_key_id,active_key_version,retain_previous_generations,min_readable_key_version,\
             provider_revoked,encryption_mode FROM pando_lab.kms_key_policies WHERE repo=$1",
            &[&repo],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), lifecycle::DEFAULT_KMS_KEY_ID);
    assert_eq!(row.get::<_, i32>(1), lifecycle::DEFAULT_KMS_KEY_VERSION);
    assert!(row.get::<_, bool>(2));
    assert_eq!(row.get::<_, i32>(3), 1);
    assert!(!row.get::<_, bool>(4));
    assert_eq!(row.get::<_, String>(5), lifecycle::crypto::AUTHENTICATED_ENVELOPE_MODE);
}

pub(super) async fn assert_no_authority(client: &Client, repo: Uuid) {
    for table in [
        "manifests",
        "objects",
        "refs",
        "object_store_manifests",
        "kms_envelopes",
        "kms_key_policies",
        "lifecycle_policies",
        "migrations",
    ] {
        assert_eq!(table_count(client, table, repo).await, 0, "leftover pando_lab.{table} authority");
    }
}
