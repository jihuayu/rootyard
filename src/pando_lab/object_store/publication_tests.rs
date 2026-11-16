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
    for installed in
        [&prepared.report().bucket_pack_path, &prepared.report().bucket_idx_path, &prepared.report().manifest_path]
    {
        assert_eq!(mode_of(Path::new(installed)), 0o444);
    }
    assert!(install_temp_files(&tmp).is_empty());

    // The raw file-only API has no DB pair, so its own post-prepare mirror is
    // the durable envelope. A retry must recover these exact bytes.
    prepared.write_file_only_mirror().unwrap();
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

fn install_temp_files(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.starts_with(".tmp-")))
        .collect()
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn immutable_install_two_real_threads_with_distinct_payloads_have_one_winner() {
    let dir = temp_root("install-race");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("artifact");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let payloads = [b"first-payload".to_vec(), b"second-payload".to_vec()];
    let runs = payloads
        .iter()
        .cloned()
        .map(|payload| {
            let target = target.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            let digest = delta::sha256_hex(&payload);
            std::thread::spawn(move || {
                super::write_immutable_cas_file_with_barrier(&target, &payload, &digest, &barrier)
            })
        })
        .collect::<Vec<_>>();
    let results = runs.into_iter().map(|run| run.join().unwrap()).collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let installed = std::fs::read(&target).unwrap();
    assert!(installed == payloads[0] || installed == payloads[1]);
    assert_eq!(results[0].is_ok(), installed == payloads[0]);
    assert_eq!(mode_of(&target), 0o444);
    assert!(install_temp_files(&dir).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn immutable_install_identical_payloads_both_succeed_without_replacement() {
    let dir = temp_root("install-identical");
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("artifact");
    let payload = b"same-payload".to_vec();
    let digest = delta::sha256_hex(&payload);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let runs = (0..2)
        .map(|_| {
            let target = target.clone();
            let payload = payload.clone();
            let digest = digest.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                super::write_immutable_cas_file_with_barrier(&target, &payload, &digest, &barrier)
            })
        })
        .collect::<Vec<_>>();
    for run in runs {
        run.join().unwrap().unwrap();
    }
    assert_eq!(std::fs::read(&target).unwrap(), payload);
    assert_eq!(mode_of(&target), 0o444);
    assert!(install_temp_files(&dir).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn immutable_install_conflicts_nonregular_and_link_failures_never_replace_or_leak_temp() {
    let dir = temp_root("install-failure");
    std::fs::create_dir_all(&dir).unwrap();

    let conflicting = dir.join("conflicting");
    std::fs::write(&conflicting, b"existing").unwrap();
    let new_payload = b"replacement";
    assert!(super::write_immutable_cas_file(&conflicting, new_payload, &delta::sha256_hex(new_payload)).is_err());
    assert_eq!(std::fs::read(&conflicting).unwrap(), b"existing");
    assert!(install_temp_files(&dir).is_empty());

    let nonregular = dir.join("directory-target");
    std::fs::create_dir(&nonregular).unwrap();
    assert!(super::write_immutable_cas_file(&nonregular, new_payload, &delta::sha256_hex(new_payload)).is_err());
    assert!(nonregular.is_dir());
    assert!(install_temp_files(&dir).is_empty());

    let symlink_target = dir.join("symlink-target");
    let symlink_destination = dir.join("symlink-destination");
    std::fs::write(&symlink_destination, b"symlink-existing").unwrap();
    std::os::unix::fs::symlink(&symlink_destination, &symlink_target).unwrap();
    assert!(super::write_immutable_cas_file(&symlink_target, new_payload, &delta::sha256_hex(new_payload)).is_err());
    assert_eq!(std::fs::read(&symlink_destination).unwrap(), b"symlink-existing");
    assert!(std::fs::symlink_metadata(&symlink_target).unwrap().file_type().is_symlink());
    assert!(install_temp_files(&dir).is_empty());

    // A genuine link(2) failure after the complete temp exists must clean the
    // caller's temp and leave no final name.
    let long_name = dir.join("x".repeat(300));
    assert!(super::write_immutable_cas_file(&long_name, new_payload, &delta::sha256_hex(new_payload)).is_err());
    assert!(!long_name.exists());
    assert!(install_temp_files(&dir).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

fn replace_immutable_file(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[tokio::test]
async fn physical_artifact_proof_rejects_missing_corrupt_or_different_manifest_files() {
    let tmp = temp_root("physical-proof");
    let objects_root = tmp.join("objects");
    let (repo, pack_id) = (Uuid::new_v4(), Uuid::new_v4());
    write_fixture(&objects_root, repo, pack_id, b"physical-proof-secret");
    let opts = options(8);
    let prepared =
        prepare_pack_files_sealed(&tmp, &objects_root, repo, pack_id, &opts, "hot", None, None).await.unwrap();
    let manifest = prepared.manifest().clone();
    let manifest_path = PathBuf::from(&prepared.report().manifest_path);
    let cipher_path = PathBuf::from(&prepared.report().bucket_pack_path);
    let idx_path = PathBuf::from(&prepared.report().bucket_idx_path);
    let original_manifest = std::fs::read(&manifest_path).unwrap();
    let original_cipher = std::fs::read(&cipher_path).unwrap();
    let original_idx = std::fs::read(&idx_path).unwrap();

    super::authority::verify_existing_cas_artifacts(&tmp, &manifest).unwrap();

    std::fs::remove_file(&manifest_path).unwrap();
    assert!(super::authority::verify_existing_cas_artifacts(&tmp, &manifest).is_err());
    replace_immutable_file(&manifest_path, &original_manifest);

    replace_immutable_file(&manifest_path, b"{");
    assert!(super::authority::verify_existing_cas_artifacts(&tmp, &manifest).is_err());
    replace_immutable_file(&manifest_path, &original_manifest);

    let mut different = manifest.clone();
    different.chunk_size += 1;
    different.manifest_sha256 = delta::sha256_hex(&serde_json::to_vec(&different).unwrap());
    replace_immutable_file(&manifest_path, &serde_json::to_vec_pretty(&different).unwrap());
    assert!(super::authority::verify_existing_cas_artifacts(&tmp, &manifest).is_err());
    replace_immutable_file(&manifest_path, &original_manifest);

    let mut corrupt_cipher = original_cipher.clone();
    corrupt_cipher[0] ^= 0xff;
    replace_immutable_file(&cipher_path, &corrupt_cipher);
    assert!(super::authority::verify_existing_cas_artifacts(&tmp, &manifest).is_err());
    replace_immutable_file(&cipher_path, &original_cipher);

    let mut corrupt_idx = original_idx.clone();
    corrupt_idx[0] ^= 0xff;
    replace_immutable_file(&idx_path, &corrupt_idx);
    assert!(super::authority::verify_existing_cas_artifacts(&tmp, &manifest).is_err());
    replace_immutable_file(&idx_path, &original_idx);

    super::authority::verify_existing_cas_artifacts(&tmp, &manifest).unwrap();
    assert_eq!(std::fs::read(&cipher_path).unwrap(), original_cipher);
    assert_eq!(std::fs::read(&idx_path).unwrap(), original_idx);
    let _ = std::fs::remove_dir_all(&tmp);
}
