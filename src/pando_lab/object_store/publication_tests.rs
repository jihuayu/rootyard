use super::authority::{validate_envelope_record, validate_manifest_record};
use super::*;
use std::path::{Path, PathBuf};
use uuid::Uuid;

fn temp_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("pando-{label}-{}", Uuid::new_v4()))
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

fn write_fixture(objects_root: &Path, repo: Uuid, pack_id: Uuid, payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let dir = objects_root.join(repo.to_string());
    std::fs::create_dir_all(&dir).unwrap();
    let pack = fixture_pack(payload);
    let idx = format!("idx-{}", payload.len()).into_bytes();
    std::fs::write(dir.join(format!("{pack_id}.pack")), &pack).unwrap();
    std::fs::write(dir.join(format!("{pack_id}.idx")), &idx).unwrap();
    (pack, idx)
}

fn options(chunk_size: usize) -> ObjectStorePutOptions {
    ObjectStorePutOptions { bucket: "b1".into(), chunk_size, ..Default::default() }
}

#[tokio::test]
async fn preparation_stages_immutable_cas_without_envelope_mirror_and_retry_reuses_it() {
    let tmp = temp_root("staged");
    let objects_root = tmp.join("objects");
    let (repo, pack_id) = (Uuid::new_v4(), Uuid::new_v4());
    write_fixture(&objects_root, repo, pack_id, b"staged-secret");
    let opts = options(8);

    let prepared =
        prepare_pack_files_sealed(&tmp, &objects_root, repo, pack_id, &opts, "hot", None, None).await.unwrap();
    assert!(
        !lifecycle::envelope_file_path(&tmp, repo, pack_id).exists(),
        "preparation must not write an authority envelope mirror"
    );
    assert!(
        validate_manifest_record(
            prepared.manifest(),
            repo,
            pack_id,
            "b1",
            &prepared.manifest().pack_sha256,
            &prepared.manifest().idx_sha256,
        )
        .is_ok()
    );
    let cipher_before = std::fs::read(&prepared.report().bucket_pack_path).unwrap();

    // The raw file-only API has no DB pair, so its own post-prepare mirror is
    // the durable envelope. A retry must recover these exact bytes.
    prepared.write_mirror().unwrap();
    let retry = prepare_pack_files_sealed(&tmp, &objects_root, repo, pack_id, &opts, "hot", None, None).await.unwrap();
    assert_eq!(retry.envelope().envelope_id, prepared.envelope().envelope_id);
    assert_eq!(retry.report().pack_sha256, prepared.report().pack_sha256);
    assert_eq!(std::fs::read(&retry.report().bucket_pack_path).unwrap(), cipher_before);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn preparation_fails_closed_on_orphan_or_partial_immutable_artifacts() {
    let tmp = temp_root("orphan");
    let objects_root = tmp.join("objects");
    let (repo, pack_id) = (Uuid::new_v4(), Uuid::new_v4());
    write_fixture(&objects_root, repo, pack_id, b"orphan-secret");
    let opts = options(8);
    let prepared =
        prepare_pack_files_sealed(&tmp, &objects_root, repo, pack_id, &opts, "hot", None, None).await.unwrap();

    // No mirror exists yet: the immutable blob is an orphan, not authority.
    assert!(prepare_pack_files_sealed(&tmp, &objects_root, repo, pack_id, &opts, "hot", None, None).await.is_err());

    // A partial artifact set must never be resealed or overwritten.
    std::fs::remove_file(&prepared.report().bucket_idx_path).unwrap();
    assert!(prepare_pack_files_sealed(&tmp, &objects_root, repo, pack_id, &opts, "hot", None, None).await.is_err());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn raw_file_put_writes_verified_mirror_only_after_prepare() {
    let tmp = temp_root("raw");
    let objects_root = tmp.join("objects");
    let (repo, pack_id) = (Uuid::new_v4(), Uuid::new_v4());
    let (pack, idx) = write_fixture(&objects_root, repo, pack_id, b"raw-secret");
    let opts = options(8);
    let (report, manifest) = put_pack_files(&tmp, &objects_root, repo, pack_id, &opts).await.unwrap();
    assert!(lifecycle::envelope_file_path(&tmp, repo, pack_id).is_file());
    assert_eq!(manifest.pack_sha256, delta::sha256_hex(&pack));
    assert_eq!(manifest.idx_sha256, delta::sha256_hex(&idx));
    assert_eq!(report.status, "published");
    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn manifest_and_envelope_validation_rejects_conflicts_without_weakening_bindings() {
    let tmp = temp_root("validate");
    let objects_root = tmp.join("objects");
    let (repo, pack_id) = (Uuid::new_v4(), Uuid::new_v4());
    write_fixture(&objects_root, repo, pack_id, b"validate-secret");
    let opts = options(8);
    let prepared =
        prepare_pack_files_sealed(&tmp, &objects_root, repo, pack_id, &opts, "hot", None, None).await.unwrap();
    let manifest = prepared.manifest().clone();
    let envelope = prepared.envelope().clone();
    let (pack_sha, idx_sha) = (manifest.pack_sha256.clone(), manifest.idx_sha256.clone());
    assert!(validate_manifest_record(&manifest, repo, pack_id, "b1", &pack_sha, &idx_sha).is_ok());
    assert!(validate_envelope_record(&envelope, &manifest, repo, pack_id).is_ok());

    let mut wrong_repo = manifest.clone();
    wrong_repo.repo = Uuid::new_v4();
    assert!(validate_manifest_record(&wrong_repo, repo, pack_id, "b1", &pack_sha, &idx_sha).is_err());

    let mut wrong_pack = manifest.clone();
    wrong_pack.pack_sha256 = "00".repeat(32);
    assert!(validate_manifest_record(&wrong_pack, repo, pack_id, "b1", &pack_sha, &idx_sha).is_err());

    let mut wrong_key = manifest.clone();
    wrong_key.pack_key = "buckets/other/repos/x/packs/y.pack".into();
    assert!(validate_manifest_record(&wrong_key, repo, pack_id, "b1", &pack_sha, &idx_sha).is_err());

    let mut wrong_digest = manifest.clone();
    wrong_digest.manifest_sha256 = "11".repeat(32);
    assert!(validate_manifest_record(&wrong_digest, repo, pack_id, "b1", &pack_sha, &idx_sha).is_err());

    let mut wrong_envelope = envelope.clone();
    wrong_envelope.ciphertext_sha256 = Some("22".repeat(32));
    assert!(validate_envelope_record(&wrong_envelope, &manifest, repo, pack_id).is_err());

    let mut wrong_suite = manifest.clone();
    wrong_suite.cipher_suite = Some("CHACHA20-POLY1305-SHA256".into());
    assert!(validate_envelope_record(&envelope, &wrong_suite, repo, pack_id).is_err());
    let _ = std::fs::remove_dir_all(&tmp);
}
