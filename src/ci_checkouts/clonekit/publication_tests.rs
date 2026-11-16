//! Source-only deterministic publication tests. These are authored but NOT executed in this change.

use std::{fs, path::Path};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use super::{CloneKitPublicationStore, publish_clonekit_versioned};
use crate::ci_checkouts::clonekit::{
    BuiltCloneKitArtifacts,
    manifest::{
        CLONEKIT_MANIFEST_SCHEMA, CloneKitArtifactDigest, CloneKitError, CloneKitManifest, CloneKitObjectFormat,
        CloneKitStatus,
    },
};

fn digest(bytes: &[u8]) -> CloneKitArtifactDigest {
    CloneKitArtifactDigest {
        sha256: hex::encode(Sha256::digest(bytes)),
        length: bytes.len() as u64,
        hold_id: None,
        blob_locator: None,
    }
}

fn manifest(
    repository_id: Uuid,
    kit_generation: u64,
    status: CloneKitStatus,
    pack: Option<CloneKitArtifactDigest>,
    idx: Option<CloneKitArtifactDigest>,
) -> CloneKitManifest {
    let active = status == CloneKitStatus::Active;
    CloneKitManifest {
        schema: CLONEKIT_MANIFEST_SCHEMA,
        tenant_id: Uuid::new_v4(),
        repository_id,
        owner_id: Uuid::new_v4(),
        history_id: Uuid::new_v4(),
        storage_generation: 1,
        object_format: CloneKitObjectFormat::Sha1,
        kit_generation,
        status,
        base_commit_oid: active.then(|| "a".repeat(40)),
        branch_ref: "refs/heads/main".into(),
        pack,
        idx,
        backend_identity_hex: None,
        retention_pin_id: Some(Uuid::new_v4()),
        created_unix: 1_750_000_000,
        expires_unix: 1_750_003_600,
        manifest_sha256: String::new(),
    }
    .sealed()
    .expect("valid test manifest")
}

fn empty_artifacts(repository_id: Uuid, kit_generation: u64) -> BuiltCloneKitArtifacts {
    BuiltCloneKitArtifacts {
        manifest: manifest(repository_id, kit_generation, CloneKitStatus::EmptyRepository, None, None),
        staged_pack_path: None,
        staged_idx_path: None,
    }
}

fn active_artifacts(
    td: &TempDir,
    repository_id: Uuid,
    kit_generation: u64,
    expected_pack: &[u8],
    expected_idx: &[u8],
    staged_pack: &[u8],
    staged_idx: &[u8],
) -> BuiltCloneKitArtifacts {
    let pack_path = td.path().join(format!("stage-{kit_generation}.pack"));
    let idx_path = td.path().join(format!("stage-{kit_generation}.idx"));
    fs::write(&pack_path, staged_pack).expect("staged pack");
    fs::write(&idx_path, staged_idx).expect("staged idx");
    BuiltCloneKitArtifacts {
        manifest: manifest(
            repository_id,
            kit_generation,
            CloneKitStatus::Active,
            Some(digest(expected_pack)),
            Some(digest(expected_idx)),
        ),
        staged_pack_path: Some(pack_path),
        staged_idx_path: Some(idx_path),
    }
}

fn attempt_names(store: &CloneKitPublicationStore, repository_id: Uuid) -> Vec<String> {
    fs::read_dir(store.repo_dir(repository_id))
        .expect("repo dir")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".publish-"))
        .collect()
}

#[test]
fn empty_publication_uses_whole_generation_layout() {
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    publish_clonekit_versioned(&store, &empty_artifacts(repository_id, 1), Path::new("/usr/bin/git"), None, None)
        .expect("empty publication");

    let vdir = store.version_dir(repository_id, 1);
    assert!(vdir.join("manifest.json").is_file());
    assert!(!vdir.join("clonekit.pack").exists());
    assert!(!vdir.join("clonekit.idx").exists());
    assert!(store.load_latest(repository_id).expect("latest").is_some());
}

#[test]
fn corrupt_candidate_preserves_existing_generation_and_current() {
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    publish_clonekit_versioned(&store, &empty_artifacts(repository_id, 1), Path::new("/usr/bin/git"), None, None)
        .expect("empty publication");

    let vdir = store.version_dir(repository_id, 1);
    let manifest_before = fs::read(vdir.join("manifest.json")).expect("manifest");
    let current_before = fs::read(store.current_pointer_path(repository_id)).expect("current");
    let candidate = active_artifacts(&td, repository_id, 2, b"expected-pack", b"expected-idx", b"wrong-pack", b"expected-idx");
    let error = publish_clonekit_versioned(&store, &candidate, Path::new("/usr/bin/git"), None, None).unwrap_err();

    assert!(matches!(error, CloneKitError::CorruptArtifact(_)));
    assert_eq!(fs::read(vdir.join("manifest.json")).expect("manifest"), manifest_before);
    assert_eq!(fs::read(store.current_pointer_path(repository_id)).expect("current"), current_before);
    assert!(attempt_names(&store, repository_id).is_empty());
    assert!(!store.version_dir(repository_id, 2).exists());
}

#[test]
fn failed_attempt_cleanup_removes_only_its_own_directory() {
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    let repo_dir = store.ensure_repo_dir(repository_id).expect("repo dir");
    let other_attempt = repo_dir.join(".publish-other-publisher");
    fs::create_dir(&other_attempt).expect("other attempt");
    fs::write(other_attempt.join("keep"), b"other").expect("other marker");
    let installed = store.version_dir(repository_id, 9);
    fs::create_dir(&installed).expect("installed generation");
    fs::write(installed.join("keep"), b"installed").expect("installed marker");

    let candidate = active_artifacts(&td, repository_id, 2, b"expected-pack", b"expected-idx", b"wrong-pack", b"expected-idx");
    assert!(publish_clonekit_versioned(&store, &candidate, Path::new("/usr/bin/git"), None, None).is_err());

    assert_eq!(fs::read(other_attempt.join("keep")).expect("other marker"), b"other");
    assert_eq!(fs::read(installed.join("keep")).expect("installed marker"), b"installed");
    assert_eq!(attempt_names(&store, repository_id), vec![".publish-other-publisher".to_owned()]);
}
