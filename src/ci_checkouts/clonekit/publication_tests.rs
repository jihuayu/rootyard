//! Source-only deterministic publication tests. These are authored but NOT executed in this change.

use std::{fs, path::Path};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use super::{CloneKitPublicationStore, PreparedGeneration, publish_clonekit_versioned, test_seam};
use crate::ci_checkouts::clonekit::{
    BuiltCloneKitArtifacts, RetentionPinGuard, RetentionPinLedger,
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
    let _serial = test_seam::serial();
    test_seam::reset();
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
    let _serial = test_seam::serial();
    test_seam::reset();
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
    let _serial = test_seam::serial();
    test_seam::reset();
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

fn prepare_empty(
    store: &CloneKitPublicationStore,
    repository_id: Uuid,
    kit_generation: u64,
) -> PreparedGeneration {
    PreparedGeneration::prepare(
        store,
        &empty_artifacts(repository_id, kit_generation),
        Path::new("/usr/bin/git"),
        None,
    )
    .expect("prepared empty generation")
}

#[test]
fn locked_recheck_rejects_candidate_prepared_before_newer_publication() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    let older = prepare_empty(&store, repository_id, 1);
    publish_clonekit_versioned(
        &store,
        &empty_artifacts(repository_id, 2),
        Path::new("/usr/bin/git"),
        None,
        None,
    )
    .expect("newer publication");
    let _guard = store.acquire_publication_lock(repository_id).expect("guard");
    let error = store.commit_prepared(older, None).unwrap_err();
    assert!(matches!(error, CloneKitError::StaleGeneration { expected_min: 3, actual: 1 }));
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present").kit_generation, 2);
    drop(_guard);

    let duplicate = publish_clonekit_versioned(
        &store,
        &empty_artifacts(repository_id, 2),
        Path::new("/usr/bin/git"),
        None,
        None,
    )
    .unwrap_err();
    assert!(matches!(duplicate, CloneKitError::StaleGeneration { expected_min: 3, actual: 2 }));
}

#[test]
fn busy_publication_lock_is_explicit_and_released_after_guard_drop() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    let guard = store.acquire_publication_lock(repository_id).expect("guard");
    let error = publish_clonekit_versioned(
        &store,
        &empty_artifacts(repository_id, 1),
        Path::new("/usr/bin/git"),
        None,
        None,
    )
    .unwrap_err();
    assert!(matches!(error, CloneKitError::GitFailed(ref message) if message.contains("busy")));
    drop(guard);
    publish_clonekit_versioned(
        &store,
        &empty_artifacts(repository_id, 1),
        Path::new("/usr/bin/git"),
        None,
        None,
    )
    .expect("publication after release");
    assert!(store.repo_dir(repository_id).join(".publication.lock").is_file());
}

#[test]
fn publication_lock_is_released_after_panic_unwind() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = store.acquire_publication_lock(repository_id).expect("guard");
        panic!("release the publication lock by unwinding");
    }));
    assert!(outcome.is_err());
    let _guard = store.acquire_publication_lock(repository_id).expect("lock reacquired");
}

#[test]
fn generation_u64_max_is_reported_as_exhausted_not_overflowed() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    store.ensure_repo_dir(repository_id).expect("repo dir");
    let maximum = manifest(repository_id, u64::MAX, CloneKitStatus::EmptyRepository, None, None);
    fs::write(store.current_pointer_path(repository_id), serde_json::to_vec_pretty(&maximum).expect("encode"))
        .expect("current");
    let error = publish_clonekit_versioned(
        &store,
        &empty_artifacts(repository_id, 1),
        Path::new("/usr/bin/git"),
        None,
        None,
    )
    .unwrap_err();
    assert!(matches!(error, CloneKitError::GitFailed(ref message) if message.contains("exhausted")));
}

#[test]
fn exact_unpublished_generation_recovers_and_conflicting_generation_rejects() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    publish_clonekit_versioned(
        &store,
        &empty_artifacts(repository_id, 1),
        Path::new("/usr/bin/git"),
        None,
        None,
    )
    .expect("baseline");

    let candidate = empty_artifacts(repository_id, 2);
    let vdir = store.version_dir(repository_id, 2);
    fs::create_dir(&vdir).expect("existing generation");
    fs::write(vdir.join("manifest.json"), serde_json::to_vec_pretty(&candidate.manifest).expect("encode"))
        .expect("manifest");
    let prepared = PreparedGeneration::prepare(&store, &candidate, Path::new("/usr/bin/git"), None).expect("prepare");
    let _guard = store.acquire_publication_lock(repository_id).expect("guard");
    store.commit_prepared(prepared, None).expect("exact recovery");
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present").kit_generation, 2);
    drop(_guard);

    let conflicting = empty_artifacts(repository_id, 3);
    let vdir = store.version_dir(repository_id, 3);
    fs::create_dir(&vdir).expect("conflicting generation");
    let differing = manifest(repository_id, 3, CloneKitStatus::EmptyRepository, None, None);
    let differing_bytes = serde_json::to_vec_pretty(&differing).expect("encode");
    fs::write(vdir.join("manifest.json"), &differing_bytes).expect("manifest");
    let prepared = PreparedGeneration::prepare(&store, &conflicting, Path::new("/usr/bin/git"), None).expect("prepare");
    let _guard = store.acquire_publication_lock(repository_id).expect("guard");
    let error = store.commit_prepared(prepared, None).unwrap_err();
    assert!(matches!(error, CloneKitError::CorruptArtifact(_)));
    assert_eq!(fs::read(vdir.join("manifest.json")).expect("manifest"), differing_bytes);
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present").kit_generation, 2);
}

#[test]
fn recovery_validates_active_manifest_pack_and_idx_without_git() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    publish_clonekit_versioned(
        &store,
        &empty_artifacts(repository_id, 1),
        Path::new("/usr/bin/git"),
        None,
        None,
    )
    .expect("baseline");
    let active = active_artifacts(&td, repository_id, 2, b"pack-bytes", b"idx-bytes", b"pack-bytes", b"idx-bytes");
    let vdir = store.version_dir(repository_id, 2);
    fs::create_dir(&vdir).expect("active generation");
    fs::write(vdir.join("manifest.json"), serde_json::to_vec_pretty(&active.manifest).expect("encode")).expect("manifest");
    fs::write(vdir.join("clonekit.pack"), b"pack-bytes").expect("pack");
    fs::write(vdir.join("clonekit.idx"), b"idx-bytes").expect("idx");
    let attempt = store.ensure_repo_dir(repository_id).expect("repo dir").join(".publish-owned-test");
    fs::create_dir(&attempt).expect("attempt");
    let prepared = PreparedGeneration {
        attempt_dir: attempt,
        manifest: active.manifest.clone(),
        encoded: serde_json::to_vec_pretty(&active.manifest).expect("encode"),
        committed: false,
    };
    let _guard = store.acquire_publication_lock(repository_id).expect("guard");
    store.commit_prepared(prepared, None).expect("active recovery");
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present").kit_generation, 2);
}

#[test]
fn gc_requires_publication_lock_strictly_older_current_and_held_pin_check() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let ledger = RetentionPinLedger::new();
    let repository_id = Uuid::new_v4();
    for generation in [1u64, 2u64] {
        publish_clonekit_versioned(
            &store,
            &empty_artifacts(repository_id, generation),
            Path::new("/usr/bin/git"),
            None,
            None,
        )
        .expect("baseline");
    }
    let future = store.version_dir(repository_id, 3);
    fs::create_dir(&future).expect("future generation");
    fs::write(future.join("keep"), b"future").expect("future marker");
    assert!(!store.try_gc_generation(repository_id, 3, &ledger).expect("future refused"));
    assert!(future.join("keep").is_file());
    assert!(matches!(
        store.try_gc_generation(repository_id, 2, &ledger),
        Err(CloneKitError::PinProtectionActive(_))
    ));

    let pin = RetentionPinGuard::acquire(&ledger, repository_id, 1).expect("pin");
    assert!(matches!(
        store.try_gc_generation(repository_id, 1, &ledger),
        Err(CloneKitError::PinProtectionActive(_))
    ));
    drop(pin);
    assert!(store.try_gc_generation(repository_id, 1, &ledger).expect("old unpinned collection"));
    assert!(!store.version_dir(repository_id, 1).exists());

    let absent = Uuid::new_v4();
    store.ensure_repo_dir(absent).expect("repo dir");
    let candidate = store.version_dir(absent, 1);
    fs::create_dir(&candidate).expect("candidate generation");
    fs::write(candidate.join("keep"), b"candidate").expect("candidate marker");
    assert!(!store.try_gc_generation(absent, 1, &ledger).expect("absent current refused"));
    assert!(candidate.join("keep").is_file());
}

#[test]
fn staged_git_verification_failure_cleans_attempt_before_shared_write() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    let candidate = active_artifacts(&td, repository_id, 2, b"pack-bytes", b"idx-bytes", b"pack-bytes", b"idx-bytes");
    let missing_git = Path::new("/nonexistent/rootyard-test-git");
    let error = publish_clonekit_versioned(&store, &candidate, missing_git, None, None).unwrap_err();
    assert!(matches!(error, CloneKitError::GitFailed(_)));
    assert!(!store.version_dir(repository_id, 2).exists());
    assert!(attempt_names(&store, repository_id).is_empty());
    assert!(store.load_latest(repository_id).expect("latest").is_none());
}
