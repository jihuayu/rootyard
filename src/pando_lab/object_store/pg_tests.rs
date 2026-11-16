//! Source-only PostgreSQL behavior cases for staged local-CAS publication.
//!
//! These are intentionally `#[ignore]`d: the checkpoint-required environment
//! for this task forbids running PostgreSQL. They use an owned repository row
//! and a disposable root, and assume the normal `experimental/pando/schema.sql`
//! schema is installed in `ROOTYARD_TEST_DATABASE_URL`.

use super::super::{Config, lifecycle};
use super::*;
use std::path::{Path, PathBuf};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

fn temp_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pando-pg-{label}-{}", Uuid::new_v4()))
}

fn fixture_pack(payload: &[u8]) -> Vec<u8> {
    let mut pack = Vec::from(&b"PACK\x00\x00\x00\x02\x00\x00\x00\x01"[..]);
    pack.push(0x80 | 0x30 | ((payload.len() & 0x0f) as u8));
    pack.push((payload.len() >> 4) as u8);
    pack.extend_from_slice(&delta::compress_zlib_stored(payload));
    let trailer = delta::sha1_digest(&pack);
    pack.extend_from_slice(&trailer);
    pack
}

fn write_fixture(objects_root: &Path, repo: Uuid, pack_id: Uuid, payload: &[u8]) {
    let dir = objects_root.join(repo.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let pack = fixture_pack(payload);
    let idx = format!("idx-{}", payload.len()).into_bytes();
    std::fs::write(dir.join(format!("{pack_id}.pack")), &pack).unwrap();
    std::fs::write(dir.join(format!("{pack_id}.idx")), &idx).unwrap();
}

fn options() -> ObjectStorePutOptions {
    ObjectStorePutOptions { bucket: "b1".into(), chunk_size: 8, ..Default::default() }
}

fn config_for(label: &str) -> Option<(Config, PathBuf)> {
    let Ok(database) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else {
        return None;
    };
    if database.trim().is_empty() {
        return None;
    }
    let root = temp_root(label);
    std::fs::create_dir_all(root.join("objects")).ok()?;
    let config = Config { database, root: root.clone(), git: PathBuf::from("/usr/bin/git") };
    Some((config, root))
}

async fn connect(config: &Config) -> Client {
    let (client, connection) = tokio_postgres::connect(&config.database, NoTls)
        .await
        .expect("ROOTYARD_TEST_DATABASE_URL must accept PostgreSQL connections");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

async fn cleanup(client: &Client, repo: Uuid) {
    for sql in [
        "DELETE FROM pando_lab.refs WHERE repo=$1",
        "DELETE FROM pando_lab.objects WHERE repo=$1",
        "DELETE FROM pando_lab.manifests WHERE repo=$1",
        "DELETE FROM pando_lab.object_store_manifests WHERE repo=$1",
        "DELETE FROM pando_lab.kms_envelopes WHERE repo=$1",
        "DELETE FROM pando_lab.kms_key_policies WHERE repo=$1",
        "DELETE FROM pando_lab.lifecycle_policies WHERE repo=$1",
        "DELETE FROM pando_lab.kms_keys WHERE repo=$1",
        "DELETE FROM pando_lab.kms_rotations WHERE repo=$1",
        "DELETE FROM pando_lab.repositories WHERE id=$1",
    ] {
        let _ = client.execute(sql, &[&repo]).await;
    }
}

async fn pair_count(client: &Client, repo: Uuid) -> (i64, i64) {
    let manifests: i64 = client
        .query_one("SELECT count(*) FROM pando_lab.object_store_manifests WHERE repo=$1", &[&repo])
        .await
        .unwrap()
        .get(0);
    let envelopes: i64 =
        client.query_one("SELECT count(*) FROM pando_lab.kms_envelopes WHERE repo=$1", &[&repo]).await.unwrap().get(0);
    (manifests, envelopes)
}

async fn pack_pair_count(client: &Client, repo: Uuid, pack_id: Uuid) -> (i64, i64) {
    let manifests: i64 = client
        .query_one(
            "SELECT count(*) FROM pando_lab.object_store_manifests WHERE repo=$1 AND pack_id=$2",
            &[&repo, &pack_id],
        )
        .await
        .unwrap()
        .get(0);
    let envelopes: i64 = client
        .query_one("SELECT count(*) FROM pando_lab.kms_envelopes WHERE repo=$1 AND pack_id=$2", &[&repo, &pack_id])
        .await
        .unwrap()
        .get(0);
    (manifests, envelopes)
}

fn replace_physical_file(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_first_pair_exact_retry_conflicts_and_partial_pairs_fail_closed() {
    let Some((config, root)) = config_for("pairs") else {
        return;
    };
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    let pack_id = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id) VALUES($1)", &[&repo]).await.unwrap();
    write_fixture(&config.root.join("objects"), repo, pack_id, b"first-pair");
    let opts = options();

    let (report, envelope) = super::put_pack_db_inner(&config, repo, pack_id, &opts, "hot").await.unwrap();
    assert_eq!(pair_count(&admin, repo).await, (1, 1));
    assert!(lifecycle::envelope_file_path(&config.root, repo, pack_id).is_file());
    let ciphertext = std::fs::read(&report.bucket_pack_path).unwrap();

    // Exact retry recovers the durable pair and never reseals replacement
    // randomized ciphertext.
    let (retry, retry_envelope) = super::put_pack_db_inner(&config, repo, pack_id, &opts, "hot").await.unwrap();
    assert_eq!(pair_count(&admin, repo).await, (1, 1));
    assert_eq!(retry.pack_sha256, report.pack_sha256);
    assert_eq!(retry_envelope.envelope_id, envelope.envelope_id);
    assert_eq!(std::fs::read(&retry.bucket_pack_path).unwrap(), ciphertext);

    // A conflicting plaintext identity for the same pack ID fails before any
    // row or ciphertext mutation.
    write_fixture(&config.root.join("objects"), repo, pack_id, b"conflicting-pair");
    assert!(super::put_pack_db_inner(&config, repo, pack_id, &opts, "hot").await.is_err());
    assert_eq!(pair_count(&admin, repo).await, (1, 1));

    // Manifest-only state is a partial authority and must not be repaired by
    // the writer.
    let manifest_only = Uuid::new_v4();
    write_fixture(&config.root.join("objects"), repo, manifest_only, b"manifest-only");
    let prepared = super::prepare_pack_files_sealed(
        &super::store_root(&config),
        &config.root.join("objects"),
        repo,
        manifest_only,
        &opts,
        "hot",
        None,
        Some(&admin),
    )
    .await
    .unwrap();
    admin
        .execute(
            "INSERT INTO pando_lab.object_store_manifests(repo,pack_id,bucket,pack_key,idx_key,manifest_key,pack_sha256,idx_sha256,pack_bytes,idx_bytes,object_count,chunk_size,chunk_count,manifest_json) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            &[
                &repo,
                &manifest_only,
                &prepared.manifest().bucket,
                &prepared.manifest().pack_key,
                &prepared.manifest().idx_key,
                &prepared.manifest().manifest_key,
                &prepared.manifest().pack_sha256,
                &prepared.manifest().idx_sha256,
                &(prepared.manifest().pack_bytes as i64),
                &(prepared.manifest().idx_bytes as i64),
                &(prepared.manifest().object_count as i64),
                &(prepared.manifest().chunk_size as i64),
                &(prepared.manifest().pack_chunks.len() as i64),
                &serde_json::to_value(prepared.manifest()).unwrap(),
            ],
        )
        .await
        .unwrap();
    assert!(super::put_pack_db_inner(&config, repo, manifest_only, &opts, "hot").await.is_err());
    let manifest_only_count: i64 = admin
        .query_one(
            "SELECT count(*) FROM pando_lab.kms_envelopes WHERE repo=$1 AND pack_id=$2",
            &[&repo, &manifest_only],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(manifest_only_count, 0);

    // Envelope-only state is equally partial.
    let envelope_only = Uuid::new_v4();
    write_fixture(&config.root.join("objects"), repo, envelope_only, b"envelope-only");
    let prepared = super::prepare_pack_files_sealed(
        &super::store_root(&config),
        &config.root.join("objects"),
        repo,
        envelope_only,
        &opts,
        "hot",
        None,
        None,
    )
    .await
    .unwrap();
    lifecycle::rotation::upsert_envelope_in_db(&admin, prepared.envelope()).await.unwrap();
    assert!(super::put_pack_db_inner(&config, repo, envelope_only, &opts, "hot").await.is_err());
    let envelope_only_count: i64 = admin
        .query_one(
            "SELECT count(*) FROM pando_lab.object_store_manifests WHERE repo=$1 AND pack_id=$2",
            &[&repo, &envelope_only],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(envelope_only_count, 0);

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_publish_transaction_rollback_leaves_no_authority_pair_or_mirror() {
    let Some((config, root)) = config_for("rollback") else {
        return;
    };
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    let pack_id = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id) VALUES($1)", &[&repo]).await.unwrap();
    write_fixture(&config.root.join("objects"), repo, pack_id, b"rollback-pair");
    let opts = options();

    let mut session = lifecycle::publication::writer_session(&config, repo).await.unwrap();
    let prepared = super::prepare_pack_files_sealed(
        &super::store_root(&config),
        &config.root.join("objects"),
        repo,
        pack_id,
        &opts,
        "hot",
        None,
        Some(session.client()),
    )
    .await
    .unwrap();
    assert!(!lifecycle::envelope_file_path(&config.root, repo, pack_id).exists());

    let tx = session.client_mut().transaction().await.unwrap();
    prepared.publish_in(&tx).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(pair_count(&admin, repo).await, (0, 0));
    assert!(!lifecycle::envelope_file_path(&config.root, repo, pack_id).exists());

    let tx = session.client_mut().transaction().await.unwrap();
    let envelope = prepared.publish_in(&tx).await.unwrap();
    tx.commit().await.unwrap();
    prepared.refresh_mirrors();
    assert_eq!(pair_count(&admin, repo).await, (1, 1));
    assert!(lifecycle::envelope_file_path(&config.root, repo, pack_id).is_file());
    assert_eq!(envelope.pack_id, pack_id);

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_shared_gate_pins_selected_target_and_blocks_exclusive_rotation() {
    let Some((config, root)) = config_for("gate") else {
        return;
    };
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    let pack_id = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id) VALUES($1)", &[&repo]).await.unwrap();
    write_fixture(&config.root.join("objects"), repo, pack_id, b"gate-pair");
    let opts = options();

    let checkpoint = lifecycle::rotation::KmsRotationCheckpoint {
        rotation_id: Uuid::new_v4(),
        repo,
        from_key_id: lifecycle::DEFAULT_KMS_KEY_ID.to_owned(),
        from_key_version: 1,
        to_key_id: lifecycle::DEFAULT_KMS_KEY_ID.to_owned(),
        to_key_version: 1,
        state: "IN_PROGRESS".to_owned(),
        revoke_previous: false,
        target_pack_ids: vec![pack_id],
        completed_pack_ids: Vec::new(),
        failed_pack_id: None,
        from_provider_kind: lifecycle::provider::PROVIDER_KIND_LOCAL.to_owned(),
        to_provider_kind: lifecycle::provider::PROVIDER_KIND_LOCAL.to_owned(),
        expected_to_version: 1,
        external_rotate_issued: false,
        reconcile_stage: lifecycle::rotation::KmsReconcileStage::NotIssued,
        target_contract: String::new(),
        write_epoch: 1,
    };
    admin
        .execute(
            "INSERT INTO pando_lab.kms_rotations(id,repo,from_key_id,from_key_version,to_key_id,to_key_version,state,revoke_previous,total_packs,processed_packs,checkpoint_json) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            &[
                &checkpoint.rotation_id,
                &repo,
                &checkpoint.from_key_id,
                &checkpoint.from_key_version,
                &checkpoint.to_key_id,
                &checkpoint.to_key_version,
                &checkpoint.state,
                &checkpoint.revoke_previous,
                &1i32,
                &0i32,
                &serde_json::to_value(&checkpoint).unwrap(),
            ],
        )
        .await
        .unwrap();

    let mut session = lifecycle::publication::writer_session(&config, repo).await.unwrap();
    let exclusive = lifecycle::publication::PgSession::connect(&config).await.unwrap();
    assert!(exclusive.acquire_publication_exclusive(repo).await.is_err());

    let active = lifecycle::publication::active_rotation(session.client(), repo).await.unwrap().unwrap();
    let prepared = super::prepare_pack_files_sealed(
        &super::store_root(&config),
        &config.root.join("objects"),
        repo,
        pack_id,
        &opts,
        "hot",
        Some(&active),
        Some(session.client()),
    )
    .await
    .unwrap();
    assert_eq!(prepared.envelope().provider_kind, active.to_provider_kind);
    assert_eq!(prepared.envelope().key_id, active.to_key_id);
    assert_eq!(prepared.envelope().key_version, active.expected_version());

    let tx = session.client_mut().transaction().await.unwrap();
    let envelope = prepared.publish_in(&tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(envelope.key_id, active.to_key_id);
    assert_eq!(envelope.key_version, active.expected_version());
    assert_eq!(pair_count(&admin, repo).await, (1, 1));

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_db_retry_rejects_missing_or_corrupt_physical_artifacts() {
    let Some((config, root)) = config_for("physical-retry") else {
        return;
    };
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id) VALUES($1)", &[&repo]).await.unwrap();
    let opts = options();

    for (label, mutation) in [
        ("missing-manifest", "missing"),
        ("corrupt-manifest", "corrupt-manifest"),
        ("corrupt-cipher", "corrupt-cipher"),
        ("corrupt-idx", "corrupt-idx"),
        ("different-manifest", "different-manifest"),
    ] {
        let pack_id = Uuid::new_v4();
        write_fixture(&config.root.join("objects"), repo, pack_id, label.as_bytes());
        let (report, _) = super::put_pack_db_inner(&config, repo, pack_id, &opts, "hot").await.unwrap();
        assert_eq!(pack_pair_count(&admin, repo, pack_id).await, (1, 1), "{label}");
        let mirror_path = lifecycle::envelope_file_path(&config.root, repo, pack_id);
        let mirror_before = std::fs::read(&mirror_path).unwrap();
        let cipher_path = PathBuf::from(&report.bucket_pack_path);
        let idx_path = PathBuf::from(&report.bucket_idx_path);
        let manifest_path = PathBuf::from(&report.manifest_path);

        match mutation {
            "missing" => std::fs::remove_file(&manifest_path).unwrap(),
            "corrupt-manifest" => replace_physical_file(&manifest_path, b"{"),
            "corrupt-cipher" => {
                let mut cipher = std::fs::read(&cipher_path).unwrap();
                cipher[0] ^= 0xff;
                replace_physical_file(&cipher_path, &cipher);
            }
            "corrupt-idx" => {
                let mut idx = std::fs::read(&idx_path).unwrap();
                idx[0] ^= 0xff;
                replace_physical_file(&idx_path, &idx);
            }
            "different-manifest" => {
                let mut different: super::CasPackManifest =
                    serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
                different.chunk_size += 1;
                different.manifest_sha256 = delta::sha256_hex(&serde_json::to_vec(&different).unwrap());
                replace_physical_file(&manifest_path, &serde_json::to_vec_pretty(&different).unwrap());
            }
            other => panic!("unknown physical mutation {other}"),
        }

        let cipher_after_mutation = std::fs::read(&cipher_path).ok();
        let idx_after_mutation = std::fs::read(&idx_path).ok();
        let manifest_after_mutation = std::fs::read(&manifest_path).ok();
        let retry = super::put_pack_db_inner(&config, repo, pack_id, &opts, "hot").await;
        assert!(retry.is_err(), "{label} retry must fail closed");
        assert_eq!(pack_pair_count(&admin, repo, pack_id).await, (1, 1), "{label}");
        assert_eq!(std::fs::read(&mirror_path).unwrap(), mirror_before, "{label}");
        assert_eq!(std::fs::read(&cipher_path).ok(), cipher_after_mutation, "{label}");
        assert_eq!(std::fs::read(&idx_path).ok(), idx_after_mutation, "{label}");
        assert_eq!(std::fs::read(&manifest_path).ok(), manifest_after_mutation, "{label}");
    }

    // An intact exact retry still succeeds and keeps the exact bytes.
    let pack_id = Uuid::new_v4();
    write_fixture(&config.root.join("objects"), repo, pack_id, b"intact-retry");
    let (report, envelope) = super::put_pack_db_inner(&config, repo, pack_id, &opts, "hot").await.unwrap();
    let cipher_before = std::fs::read(&report.bucket_pack_path).unwrap();
    let (retry_report, retry_envelope) = super::put_pack_db_inner(&config, repo, pack_id, &opts, "hot").await.unwrap();
    assert_eq!(retry_report.pack_sha256, report.pack_sha256);
    assert_eq!(retry_envelope.envelope_id, envelope.envelope_id);
    assert_eq!(std::fs::read(&retry_report.bucket_pack_path).unwrap(), cipher_before);
    assert_eq!(pack_pair_count(&admin, repo, pack_id).await, (1, 1));

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}
