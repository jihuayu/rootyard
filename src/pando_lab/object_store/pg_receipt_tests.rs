//! Source-only PostgreSQL cases for authoritative publication receipts.
//!
//! These are intentionally `#[ignore]`d and were not executed. They use an
//! owned repository/root and the normal `experimental/pando/schema.sql`.

use super::super::{Config, Pack, delta, lifecycle};
use super::*;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

fn temp_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pando-receipt-{label}-{}", Uuid::new_v4()))
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
    let (client, connection) = tokio_postgres::connect(&config.database, NoTls).await.unwrap();
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
        "DELETE FROM pando_lab.operations WHERE repo=$1",
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

async fn table_count(client: &Client, table: &str, repo: Uuid) -> i64 {
    client.query_one(&format!("SELECT count(*) FROM pando_lab.{table} WHERE repo=$1"), &[&repo]).await.unwrap().get(0)
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_rewrapped_envelope_winner_drives_receipt_and_mirror() {
    let Some((config, root)) = config_for("rewrap") else {
        return;
    };
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id) VALUES($1)", &[&repo]).await.unwrap();
    let pack_id = Uuid::new_v4();
    write_fixture(&config.root.join("objects"), repo, pack_id, b"rewrapped-winner");
    let opts = options();

    let (report, old_envelope) = super::put_pack_db_inner(&config, repo, pack_id, &opts, "hot").await.unwrap();
    let cipher_before = std::fs::read(&report.bucket_pack_path).unwrap();

    // Genuine rewrap through the provider: no MAC field patching.
    let provider = lifecycle::provider_selection::for_write(&config.root, repo, None).unwrap();
    let (key_id, wrapped_key_json) = lifecycle::crypto::rewrap_pack_dek(
        provider.provider(),
        repo,
        pack_id,
        old_envelope.envelope_id.unwrap(),
        &old_envelope.plaintext_sha256,
        old_envelope.wrapped_key_json.as_deref().unwrap(),
    )
    .await
    .unwrap();
    let mut rewrapped = old_envelope.clone();
    rewrapped.key_id = key_id;
    rewrapped.wrapped_key_json = Some(wrapped_key_json);
    rewrapped.envelope_mac =
        lifecycle::crypto::compute_authenticated_envelope_mac(&lifecycle::crypto::EnvelopeMacInputs {
            encryption_mode: &rewrapped.encryption_mode,
            repo,
            pack_id,
            key_id: &rewrapped.key_id,
            key_version: rewrapped.key_version,
            cipher_suite: &rewrapped.cipher_suite,
            pack_sha256: &rewrapped.pack_sha256,
            idx_sha256: &rewrapped.idx_sha256,
            ciphertext_sha256: rewrapped.ciphertext_sha256.as_deref().unwrap(),
            ciphertext_bytes: rewrapped.ciphertext_bytes.unwrap(),
            envelope_id: rewrapped.envelope_id.unwrap(),
            nonce_prefix: rewrapped.nonce_prefix.as_deref().unwrap(),
            wrapped_key_json: rewrapped.wrapped_key_json.as_deref().unwrap(),
        });
    lifecycle::verify_envelope_record(&rewrapped).unwrap();
    assert_ne!(rewrapped.envelope_mac, old_envelope.envelope_mac);
    lifecycle::rotation::upsert_envelope_in_db(&admin, &rewrapped).await.unwrap();

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
    assert_eq!(prepared.envelope(), &rewrapped);

    let tx = session.client_mut().transaction().await.unwrap();
    let receipt = prepared.publish_in(&tx).await.unwrap();
    assert_eq!(receipt.envelope(), &rewrapped);
    assert_eq!(receipt.manifest(), prepared.manifest());
    tx.commit().await.unwrap();
    receipt.refresh_mirrors();

    let mirror: lifecycle::KmsEnvelopeRecord =
        serde_json::from_slice(&std::fs::read(lifecycle::envelope_file_path(&config.root, repo, pack_id)).unwrap())
            .unwrap();
    assert_eq!(mirror, rewrapped);

    let (retry_report, retry_envelope) = super::put_pack_db_inner(&config, repo, pack_id, &opts, "hot").await.unwrap();
    assert_eq!(retry_envelope, rewrapped);
    assert_eq!(retry_report.pack_sha256, report.pack_sha256);
    assert_eq!(std::fs::read(&report.bucket_pack_path).unwrap(), cipher_before);

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_cross_root_random_cipher_conflict_rolls_back_all_caller_metadata() {
    let Some((config_a, root_a)) = config_for("cross-a") else {
        return;
    };
    let Some((config_b, root_b)) = config_for("cross-b") else {
        return;
    };
    assert_eq!(config_a.database, config_b.database);
    let admin = connect(&config_a).await;
    let repo = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id) VALUES($1)", &[&repo]).await.unwrap();
    let pack_id = Uuid::new_v4();
    write_fixture(&config_a.root.join("objects"), repo, pack_id, b"cross-root");
    write_fixture(&config_b.root.join("objects"), repo, pack_id, b"cross-root");
    let opts = options();

    let mut session_a = lifecycle::publication::writer_session(&config_a, repo).await.unwrap();
    let mut session_b = lifecycle::publication::writer_session(&config_b, repo).await.unwrap();
    let prepared_a = super::prepare_pack_files_sealed(
        &super::store_root(&config_a),
        &config_a.root.join("objects"),
        repo,
        pack_id,
        &opts,
        "hot",
        None,
        Some(session_a.client()),
    )
    .await
    .unwrap();
    let prepared_b = super::prepare_pack_files_sealed(
        &super::store_root(&config_b),
        &config_b.root.join("objects"),
        repo,
        pack_id,
        &opts,
        "hot",
        None,
        Some(session_b.client()),
    )
    .await
    .unwrap();
    assert_ne!(prepared_a.manifest(), prepared_b.manifest());

    let tx = session_a.client_mut().transaction().await.unwrap();
    let receipt_a = prepared_a.publish_in(&tx).await.unwrap();
    tx.commit().await.unwrap();
    receipt_a.refresh_mirrors();
    let cipher_a_before = std::fs::read(&prepared_a.report().bucket_pack_path).unwrap();

    let op = Uuid::new_v4();
    let tx = session_b.client_mut().transaction().await.unwrap();
    tx.execute(
        "INSERT INTO pando_lab.manifests VALUES($1,$2,$3,$4)",
        &[&repo, &pack_id, &prepared_b.manifest().pack_sha256, &prepared_b.manifest().idx_sha256],
    )
    .await
    .unwrap();
    tx.execute(
        "INSERT INTO pando_lab.operations(id,repo,principal,state,commands) VALUES($1,$2,'conflict','PREPARED','[]'::jsonb)",
        &[&op, &repo],
    )
    .await
    .unwrap();
    assert!(prepared_b.publish_in(&tx).await.is_err());
    tx.rollback().await.unwrap();

    assert_eq!(pair_count(&admin, repo).await, (1, 1));
    assert_eq!(table_count(&admin, "manifests", repo).await, 0);
    assert_eq!(
        admin
            .query_one("SELECT count(*) FROM pando_lab.operations WHERE id=$1", &[&op])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let pack = Pack {
        id: pack_id,
        pack_sha256: prepared_a.manifest().pack_sha256.clone(),
        idx_sha256: prepared_a.manifest().idx_sha256.clone(),
    };
    let db_envelope = lifecycle::load_envelope_from_db(&admin, repo, &pack).await.unwrap().unwrap();
    assert_eq!(&db_envelope, receipt_a.envelope());
    assert_eq!(std::fs::read(&prepared_a.report().bucket_pack_path).unwrap(), cipher_a_before);
    assert!(!lifecycle::envelope_file_path(&config_b.root, repo, pack_id).exists());

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root_a);
    let _ = std::fs::remove_dir_all(&root_b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_two_shared_writers_barrier_install_one_file_winner_and_retry_verifies() {
    let Some((config, root)) = config_for("same-root-race") else {
        return;
    };
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id) VALUES($1)", &[&repo]).await.unwrap();
    let pack_id = Uuid::new_v4();
    write_fixture(&config.root.join("objects"), repo, pack_id, b"same-root-race");
    let opts = options();
    // Initialize Local key material before the concurrent preparations.
    let _ = lifecycle::provider_selection::for_write(&config.root, repo, None).unwrap();

    let session_a = lifecycle::publication::writer_session(&config, repo).await.unwrap();
    let session_b = lifecycle::publication::writer_session(&config, repo).await.unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for mut session in [session_a, session_b] {
        let config = config.clone();
        let opts = opts.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            let result = super::prepare_pack_files_sealed_with_install_barrier(
                &super::store_root(&config),
                &config.root.join("objects"),
                repo,
                pack_id,
                &opts,
                "hot",
                None,
                Some(session.client()),
                &barrier,
            )
            .await;
            (session, result)
        }));
    }
    let (mut session_a, result_a) = handles.remove(0).await.unwrap();
    let (mut session_b, result_b) = handles.remove(0).await.unwrap();
    let (mut winner_session, prepared) = match (result_a, result_b) {
        (Ok(prepared), Err(_)) => (session_a, prepared),
        (Err(_), Ok(prepared)) => (session_b, prepared),
        (Ok(_), Ok(_)) => panic!("both immutable installers unexpectedly succeeded"),
        (Err(_), Err(_)) => panic!("both immutable installers unexpectedly failed"),
    };

    let tx = winner_session.client_mut().transaction().await.unwrap();
    let receipt = prepared.publish_in(&tx).await.unwrap();
    tx.commit().await.unwrap();
    receipt.refresh_mirrors();
    assert_eq!(pair_count(&admin, repo).await, (1, 1));

    let store_root = super::store_root(&config);
    super::authority::verify_existing_cas_artifacts(&store_root, prepared.manifest()).unwrap();
    let cipher = std::fs::read(store_root.join(&prepared.manifest().pack_key)).unwrap();
    assert_eq!(cipher.len() as u64, prepared.manifest().ciphertext_bytes.unwrap());
    assert_eq!(delta::sha256_hex(&cipher), prepared.manifest().ciphertext_sha256.as_deref().unwrap());
    drop(winner_session);

    let (retry_report, retry_envelope) = super::put_pack_db_inner(&config, repo, pack_id, &opts, "hot").await.unwrap();
    assert_eq!(retry_envelope, receipt.envelope().clone());
    assert_eq!(retry_report.pack_sha256, prepared.manifest().pack_sha256);
    assert_eq!(std::fs::read(store_root.join(&prepared.manifest().pack_key)).unwrap(), cipher);

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_hook_like_receipt_rollback_and_commit_publish_only_after_authority() {
    let Some((config, root)) = config_for("hook-receipt") else {
        return;
    };
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    admin.execute("INSERT INTO pando_lab.repositories(id) VALUES($1)", &[&repo]).await.unwrap();
    let pack_id = Uuid::new_v4();
    write_fixture(&config.root.join("objects"), repo, pack_id, b"hook-receipt");
    let opts = options();
    let oid = "a".repeat(40);
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

    // Hook-like rollback: caller metadata and the publication receipt are in
    // one transaction, then a ref CHECK failure aborts it.
    let tx = session.client_mut().transaction().await.unwrap();
    tx.execute(
        "INSERT INTO pando_lab.manifests VALUES($1,$2,$3,$4)",
        &[&repo, &pack_id, &prepared.manifest().pack_sha256, &prepared.manifest().idx_sha256],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO pando_lab.objects VALUES($1,$2,$3)", &[&repo, &oid, &pack_id]).await.unwrap();
    let _rolled_back = prepared.publish_in(&tx).await.unwrap();
    assert!(
        tx.execute("INSERT INTO pando_lab.refs VALUES($1,$2,$3)", &[&repo, &"refs/heads/main", &"not-an-oid"])
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    assert_eq!(pair_count(&admin, repo).await, (0, 0));
    assert_eq!(table_count(&admin, "manifests", repo).await, 0);
    assert_eq!(table_count(&admin, "objects", repo).await, 0);
    assert_eq!(table_count(&admin, "refs", repo).await, 0);
    assert!(!lifecycle::envelope_file_path(&config.root, repo, pack_id).exists());

    // Successful hook-like transaction keeps the receipt until COMMIT.
    let tx = session.client_mut().transaction().await.unwrap();
    tx.execute(
        "INSERT INTO pando_lab.manifests VALUES($1,$2,$3,$4)",
        &[&repo, &pack_id, &prepared.manifest().pack_sha256, &prepared.manifest().idx_sha256],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO pando_lab.objects VALUES($1,$2,$3)", &[&repo, &oid, &pack_id]).await.unwrap();
    tx.execute("INSERT INTO pando_lab.refs VALUES($1,$2,$3)", &[&repo, &"refs/heads/main", &oid]).await.unwrap();
    let receipt = prepared.publish_in(&tx).await.unwrap();
    tx.commit().await.unwrap();
    receipt.refresh_mirrors();
    assert_eq!(pair_count(&admin, repo).await, (1, 1));
    assert_eq!(table_count(&admin, "manifests", repo).await, 1);
    assert_eq!(table_count(&admin, "objects", repo).await, 1);
    assert_eq!(table_count(&admin, "refs", repo).await, 1);
    assert!(lifecycle::envelope_file_path(&config.root, repo, pack_id).is_file());

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(&root);
}
