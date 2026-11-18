//! W8-A unit tests: no process environment is mutated.
use std::collections::BTreeMap;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::encryption_config::BlobEncryptionConfig;
use crate::storage_lifecycle::models::Policy;

use super::deleter_fence::ensure_destructive_gc_disabled_with;
use super::manifest_key_ref::{
    W8aKeyReference, W8aPairedSidecarManifest, capture_key_reference_with, verify_key_reference_with,
};
use super::{W8aError, check};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn private_dir(path: &Path) {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(path).unwrap();
}

fn private_file(path: &Path) -> std::fs::File {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path).unwrap()
}

fn keyring(directory: &Path, current: &str, keys: &[(&str, [u8; 32])]) {
    let _ = std::fs::remove_dir_all(directory);
    private_dir(directory);
    let mut entries = Vec::new();
    for (id, key) in keys {
        private_file(&directory.join(format!("{id}.key"))).write_all(key).unwrap();
        entries.push(serde_json::json!({"key_id": id, "sha256": sha(key)}));
    }
    let manifest = serde_json::json!({"current": current, "keys": entries});
    write_mode(&directory.join("keyring.json"), &serde_json::to_vec(&manifest).unwrap());
}

fn write_mode(path: &Path, bytes: &[u8]) {
    private_file(path).write_all(bytes).unwrap();
}

#[test]
fn key_reference_round_trips_without_secret_material() {
    let temp = tempfile::tempdir().unwrap();
    let keys = temp.path().join("keys");
    let key = [7u8; 32];
    keyring(&keys, "k1", &[("k1", key)]);
    let config = BlobEncryptionConfig::local_envelope(&keys).unwrap();
    let backup = Uuid::new_v4();
    let reference = capture_key_reference_with(&config, Some(keys.as_path()), None, backup, "backend-a").unwrap();
    assert_eq!(reference.active_key_id.as_deref(), Some("k1"));
    assert_eq!(reference.known_key_ids, vec!["k1".to_string()]);
    assert!(reference.canary_wrapped_key_json.is_some());
    let rendered = serde_json::to_string(&reference).unwrap();
    assert!(!rendered.contains(keys.to_str().unwrap()));
    assert!(!rendered.contains(&hex::encode(key)));
    verify_key_reference_with(&config, Some(keys.as_path()), None, &reference, backup, "backend-a").unwrap();
    assert!(verify_key_reference_with(&config, Some(keys.as_path()), None, &reference, backup, "backend-b").is_err());
}

#[test]
fn key_reference_refuses_a_different_keyring_or_mode() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    keyring(&first, "k1", &[("k1", [1u8; 32])]);
    keyring(&second, "k1", &[("k1", [2u8; 32])]);
    let backup = Uuid::new_v4();
    let config = BlobEncryptionConfig::local_envelope(&first).unwrap();
    let reference = capture_key_reference_with(&config, Some(first.as_path()), None, backup, "b").unwrap();
    let other = BlobEncryptionConfig::local_envelope(&second).unwrap();
    assert!(matches!(
        verify_key_reference_with(&other, Some(second.as_path()), None, &reference, backup, "b"),
        Err(W8aError::KeyReferenceMismatch(_))
    ));
    keyring(&second, "k2", &[("k1", [1u8; 32]), ("k2", [3u8; 32])]);
    assert!(verify_key_reference_with(&other, Some(second.as_path()), None, &reference, backup, "b").is_err());
    let provider = BlobEncryptionConfig::provider_managed();
    assert!(matches!(
        verify_key_reference_with(&provider, None, None, &reference, backup, "b"),
        Err(W8aError::KeyReferenceMismatch(_))
    ));
}

#[test]
fn provider_managed_reference_is_the_kms_identity_only() {
    let config = BlobEncryptionConfig::provider_managed();
    let backup = Uuid::new_v4();
    let reference = capture_key_reference_with(&config, None, Some("kms://test/rootyard"), backup, "b").unwrap();
    assert_eq!(reference.kms_key_reference.as_deref(), Some("kms://test/rootyard"));
    assert!(reference.canary_wrapped_key_json.is_none());
    verify_key_reference_with(&config, None, Some("kms://test/rootyard"), &reference, backup, "b").unwrap();
    assert!(verify_key_reference_with(&config, None, Some("kms://other/key"), &reference, backup, "b").is_err());
    assert!(capture_key_reference_with(&config, None, Some("secret-token"), backup, "b").is_err());
}

#[test]
fn manifest_seal_covers_every_sidecar_field() {
    let mut sidecar = sample_sidecar();
    sidecar = sidecar.seal().unwrap();
    sidecar.verify_manifest_seal().unwrap();
    sidecar.blob_total_bytes += 1;
    assert!(matches!(sidecar.verify_manifest_seal(), Err(W8aError::MixedPointInTime(_))));
}

#[test]
fn format_version_is_frozen() {
    assert_eq!(super::W8A_FORMAT_VERSION, "rootyard-w8a-pg-blob-v1");
    assert_eq!(sample_sidecar().format, super::super::FORMAT_PAIRED);
}

#[test]
fn destructive_gc_switches_all_refuse() {
    let policy = |enabled| Policy {
        enabled,
        poll: std::time::Duration::from_secs(5),
        lease_seconds: 30,
        loose_threshold: 1024,
        pack_threshold: 8,
        stage_age_seconds: 3600,
        cache_max_age_seconds: 3600,
        tombstone_grace_seconds: 3600,
        scan_period_seconds: 3600,
        quiescence_seconds: 15,
        max_attempts: 5,
    };
    assert!(ensure_destructive_gc_disabled_with(&policy(false), false, None).is_ok());
    assert!(ensure_destructive_gc_disabled_with(&policy(true), false, None).is_err());
    assert!(ensure_destructive_gc_disabled_with(&policy(false), true, None).is_err());
    assert!(ensure_destructive_gc_disabled_with(&policy(false), false, Some("true")).is_err());
}

fn sample_sidecar() -> W8aPairedSidecarManifest {
    W8aPairedSidecarManifest {
        w8a_backup_id: Uuid::new_v4(),
        format: 30,
        schema_head: 151,
        schema_contract_sha256: "0".repeat(64),
        metadata_dump_sha256: "1".repeat(64),
        inner_manifest_sha256: "2".repeat(64),
        inner_complete_sha256: "3".repeat(64),
        inner_backup_id: Uuid::new_v4(),
        inner_volume_id: Uuid::new_v4(),
        blob_repository_count: 1,
        blob_artifact_count: 2,
        blob_total_bytes: 10,
        blob_closure_digest: "4".repeat(64),
        blob_backend_identity: "backend".into(),
        blob_provider: "opendal".into(),
        source_cluster_incarnation: Uuid::new_v4(),
        source_storage_authority_id: Uuid::new_v4(),
        source_storage_authority_epoch: 1,
        key_reference: W8aKeyReference {
            mode: "provider-managed".into(),
            active_key_id: None,
            known_key_ids: Vec::new(),
            key_ids_digest: None,
            kms_key_reference: Some("kms://test/rootyard".into()),
            canary_attempt_id: None,
            canary_wrapped_key_json: None,
        },
        single_node_w8a: true,
        raft_cut_supported: false,
        paired_restore_trusted: false,
        manifest_seal_sha256: String::new(),
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    manifest: super::super::Manifest,
    artifacts: Vec<super::super::ledger::Artifact>,
}

fn artifact(repo: Uuid, pack: Uuid, role: &str, bytes: &[u8]) -> super::super::ledger::Artifact {
    super::super::ledger::Artifact {
        repository_id: repo,
        registration_id: Uuid::new_v4(),
        pack_id: pack,
        role: role.into(),
        slot: 0,
        hold_id: Uuid::new_v4(),
        acquire_request_id: Uuid::new_v4(),
        consume_request_id: Uuid::new_v4(),
        provider: "opendal".into(),
        backend_identity: "backend".into(),
        sha256: sha(bytes),
        length: bytes.len() as u64,
        tenant_id: Uuid::new_v4(),
        authority_id: Uuid::new_v4(),
        generation: 1,
        attempt_id: Uuid::new_v4(),
        namespace: "w8a-test".into(),
        artifact_set_digest: None,
        declared_by: Vec::new(),
    }
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("archive");
    std::fs::create_dir(&root).unwrap();
    let repo = Uuid::new_v4();
    let pack = Uuid::new_v4();
    let files = [b"pack".to_vec(), b"idx".to_vec()];
    let artifacts = vec![artifact(repo, pack, "pack", &files[0]), artifact(repo, pack, "idx", &files[1])];
    let closure = super::super::ledger::closure_of(&artifacts, "backend", "opendal");
    let manifest = super::super::Manifest {
        format: 30,
        backup_id: Uuid::new_v4(),
        volume_id: Uuid::new_v4(),
        schema_contract_sha256: super::super::schema_contract_digest(30).unwrap(),
        boundary_unix_seconds: 0,
        rootyard_version: "w8a-test".into(),
        binary_sha256: "0".repeat(64),
        postgres_version: "17".into(),
        pg_dump_version: "17".into(),
        git_version: "2.43".into(),
        schema_versions: super::super::schema_versions(30).unwrap(),
        consistency: "test".into(),
        journal_record_files: 0,
        repositories: Vec::new(),
        lfs_objects: Vec::new(),
        blob_closure: Some(super::super::BlobClosure {
            backend_identity: closure.backend_identity,
            provider: closure.provider,
            repositories: closure.repositories,
            artifacts: closure.artifacts,
            bytes: closure.bytes,
            digest: closure.digest,
        }),
        blob_artifacts: artifacts.clone(),
        refstore: None,
        files: BTreeMap::new(),
    };
    let metadata = b"metadata";
    let inner = root.join("format30");
    std::fs::create_dir(&inner).unwrap();
    std::fs::write(inner.join("metadata.dump"), metadata).unwrap();
    for (index, artifact) in artifacts.iter().enumerate() {
        let path = inner.join(artifact.archive_path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, &files[index]).unwrap();
    }
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    std::fs::write(inner.join("manifest.json"), &manifest_bytes).unwrap();
    std::fs::write(inner.join("COMPLETE"), sha(&manifest_bytes)).unwrap();
    let mut sidecar = sample_sidecar();
    sidecar.format = 30;
    sidecar.schema_head = *super::super::schema_versions(30).unwrap().last().unwrap();
    sidecar.schema_contract_sha256 = manifest.schema_contract_sha256.clone();
    sidecar.metadata_dump_sha256 = sha(metadata);
    sidecar.inner_manifest_sha256 = sha(&manifest_bytes);
    sidecar.inner_complete_sha256 = sha(sha(&manifest_bytes).as_bytes());
    sidecar.inner_backup_id = manifest.backup_id;
    sidecar.inner_volume_id = manifest.volume_id;
    sidecar.blob_repository_count = 1;
    sidecar.blob_artifact_count = 2;
    sidecar.blob_total_bytes = 7;
    sidecar.blob_closure_digest = manifest.blob_closure.as_ref().unwrap().digest.clone();
    sidecar = sidecar.seal().unwrap();
    let sidecar_bytes = serde_json::to_vec(&sidecar).unwrap();
    std::fs::write(root.join("w8a-paired.json"), &sidecar_bytes).unwrap();
    std::fs::write(root.join("W8A_COMPLETE"), sha(&sidecar_bytes)).unwrap();
    Fixture { _temp: temp, root, manifest, artifacts }
}

#[test]
fn check_refuses_raft_manifest_and_unexpected_entries() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("paired-manifest.json"), b"{}").unwrap();
    assert!(matches!(check(temp.path()), Err(W8aError::RaftCutForbiddenInSingleNodeW8a(_))));
    let other = tempfile::tempdir().unwrap();
    std::fs::write(other.path().join("extra"), b"x").unwrap();
    assert!(check(other.path()).is_err());
}

#[test]
fn check_refuses_a_tampered_sidecar() {
    let fixture = fixture();
    let path = fixture.root.join("w8a-paired.json");
    let mut sidecar: W8aPairedSidecarManifest = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    sidecar.metadata_dump_sha256 = "f".repeat(64);
    let bytes = serde_json::to_vec(&sidecar).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    std::fs::write(fixture.root.join("W8A_COMPLETE"), sha(&bytes)).unwrap();
    assert!(matches!(check(&fixture.root), Err(W8aError::MixedPointInTime(_))));
}

#[test]
fn check_refuses_corrupt_swapped_or_missing_blob_members() {
    let corrupt = fixture();
    let path = corrupt.root.join("format30").join(corrupt.artifacts[0].archive_path());
    std::fs::write(&path, b"corrupt").unwrap();
    assert!(matches!(check(&corrupt.root), Err(W8aError::MissingOrCorruptBlobArtifact(_))));
    let swapped = fixture();
    std::fs::write(swapped.root.join("format30/metadata.dump"), b"swapped").unwrap();
    assert!(matches!(check(&swapped.root), Err(W8aError::MixedPointInTime(_))));
    let missing = fixture();
    std::fs::remove_file(missing.root.join("format30").join(missing.artifacts[1].archive_path())).unwrap();
    assert!(matches!(check(&missing.root), Err(W8aError::MissingOrCorruptBlobArtifact(_))));
    assert_eq!(missing.manifest.format, 30);
}

#[test]
fn check_accepts_the_sealed_envelope_up_to_inner_verification() {
    let fixture = fixture();
    std::fs::write(fixture.root.join("format30/metadata.dump"), b"changed").unwrap();
    assert!(matches!(check(&fixture.root), Err(W8aError::MixedPointInTime(_))));
}
