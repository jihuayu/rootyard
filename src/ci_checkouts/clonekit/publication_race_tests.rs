//! Source-only deterministic publication race, cancellation, and crash-point tests.

use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    CP_AFTER_INSTALL, CP_AFTER_POINTER, CP_BEFORE_INSTALL, CP_BEFORE_LOCK, CP_BEFORE_POINTER, CloneKitPublicationStore,
    publish_clonekit_versioned, test_seam,
};
use crate::ci_checkouts::clonekit::{
    BuildFailurePoint, BuiltCloneKitArtifacts, RetentionPinGuard, RetentionPinLedger,
    manifest::{
        CLONEKIT_MANIFEST_SCHEMA, CloneKitArtifactDigest, CloneKitError, CloneKitManifest, CloneKitObjectFormat,
        CloneKitStatus,
    },
};

fn git() -> &'static Path {
    Path::new("/usr/bin/git")
}

fn base_manifest(repository_id: Uuid, kit_generation: u64) -> CloneKitManifest {
    CloneKitManifest {
        schema: CLONEKIT_MANIFEST_SCHEMA,
        tenant_id: Uuid::new_v4(),
        repository_id,
        owner_id: Uuid::new_v4(),
        history_id: Uuid::new_v4(),
        storage_generation: 1,
        object_format: CloneKitObjectFormat::Sha1,
        kit_generation,
        status: CloneKitStatus::EmptyRepository,
        base_commit_oid: None,
        branch_ref: "refs/heads/main".into(),
        pack: None,
        idx: None,
        backend_identity_hex: None,
        retention_pin_id: Some(Uuid::new_v4()),
        created_unix: 1_750_000_000,
        expires_unix: 1_750_003_600,
        manifest_sha256: String::new(),
    }
}

fn empty_artifacts(repository_id: Uuid, kit_generation: u64) -> BuiltCloneKitArtifacts {
    BuiltCloneKitArtifacts {
        manifest: base_manifest(repository_id, kit_generation).sealed().expect("valid empty manifest"),
        staged_pack_path: None,
        staged_idx_path: None,
    }
}

fn held_active_artifacts(repository_id: Uuid, kit_generation: u64, pin: Uuid) -> BuiltCloneKitArtifacts {
    let pack =
        CloneKitArtifactDigest { sha256: "a".repeat(64), length: 1, hold_id: Some(Uuid::new_v4()), blob_locator: None };
    let idx =
        CloneKitArtifactDigest { sha256: "b".repeat(64), length: 1, hold_id: Some(Uuid::new_v4()), blob_locator: None };
    let manifest = CloneKitManifest {
        schema: CLONEKIT_MANIFEST_SCHEMA,
        tenant_id: Uuid::new_v4(),
        repository_id,
        owner_id: Uuid::new_v4(),
        history_id: Uuid::new_v4(),
        storage_generation: 1,
        object_format: CloneKitObjectFormat::Sha1,
        kit_generation,
        status: CloneKitStatus::Active,
        base_commit_oid: Some("c".repeat(40)),
        branch_ref: "refs/heads/main".into(),
        pack: Some(pack),
        idx: Some(idx),
        backend_identity_hex: None,
        retention_pin_id: Some(pin),
        created_unix: 1_750_000_000,
        expires_unix: 1_750_003_600,
        manifest_sha256: String::new(),
    }
    .sealed()
    .expect("valid held manifest");
    BuiltCloneKitArtifacts { manifest, staged_pack_path: None, staged_idx_path: None }
}

fn attempt_names(store: &CloneKitPublicationStore, repository_id: Uuid) -> Vec<String> {
    fs::read_dir(store.repo_dir(repository_id))
        .expect("repo dir")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".publish-"))
        .collect()
}

fn store_and_repo(td: &TempDir) -> (CloneKitPublicationStore, Uuid) {
    (CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store"), Uuid::new_v4())
}

fn publish_baseline(store: &CloneKitPublicationStore, repository_id: Uuid) {
    publish_clonekit_versioned(store, &empty_artifacts(repository_id, 1), git(), None, None).expect("baseline");
    test_seam::reset();
}

#[test]
fn older_publisher_paused_before_lock_loses_to_newer_publication() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let (store, repository_id) = store_and_repo(&td);
    test_seam::pause_once_at(CP_BEFORE_LOCK);
    let older_store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("older store");
    let older = std::thread::spawn(move || {
        publish_clonekit_versioned(&older_store, &empty_artifacts(repository_id, 1), git(), None, None)
    });
    test_seam::wait_until(CP_BEFORE_LOCK, 1);
    let newer = publish_clonekit_versioned(&store, &empty_artifacts(repository_id, 2), git(), None, None)
        .expect("newer publication");
    test_seam::release(CP_BEFORE_LOCK);
    let older = older.join().expect("join");
    assert!(matches!(older, Err(CloneKitError::StaleGeneration { expected_min: 3, actual: 1 })));
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present"), newer);
    test_seam::reset();
}

#[test]
fn empty_same_generation_race_still_rejects_after_winner() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let (store, repository_id) = store_and_repo(&td);
    test_seam::pause_all_at(CP_BEFORE_LOCK);
    let first_store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("first store");
    let second_store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("second store");
    let first = std::thread::spawn(move || {
        publish_clonekit_versioned(&first_store, &empty_artifacts(repository_id, 1), git(), None, None)
    });
    let second = std::thread::spawn(move || {
        publish_clonekit_versioned(&second_store, &empty_artifacts(repository_id, 1), git(), None, None)
    });
    test_seam::wait_until(CP_BEFORE_LOCK, 2);
    test_seam::release(CP_BEFORE_LOCK);
    let first = first.join().expect("first join");
    let second = second.join().expect("second join");
    let loser_ok = |error: &CloneKitError| {
        matches!(error, CloneKitError::GitFailed(message) if message.contains("busy"))
            || matches!(error, CloneKitError::StaleGeneration { expected_min: 2, actual: 1 })
    };
    let winner = match (&first, &second) {
        (Ok(manifest), Err(error)) => {
            assert!(loser_ok(error));
            manifest.clone()
        }
        (Err(error), Ok(manifest)) => {
            assert!(loser_ok(error));
            manifest.clone()
        }
        _ => panic!("exactly one same-generation publisher must win"),
    };
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present"), winner);
    assert!(attempt_names(&store, repository_id).is_empty());
    test_seam::reset();
}

#[test]
fn cross_process_lock_excludes_and_releases_on_child_termination() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let root = td.path().join("catalog");
    let repository_id = Uuid::new_v4();
    let ready = td.path().join("child-ready");
    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .arg("--nocapture")
        .arg("publication_lock_child_helper")
        .env("ROOTYARD_CK_LOCK_ROOT", &root)
        .env("ROOTYARD_CK_LOCK_REPO", repository_id.to_string())
        .env("ROOTYARD_CK_LOCK_READY", &ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("child");
    let mut ready_seen = false;
    for _ in 0..1000 {
        if ready.exists() {
            ready_seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if !ready_seen {
        let _ = child.kill();
        let _ = child.wait();
        panic!("child publisher did not acquire the lock");
    }
    let store = CloneKitPublicationStore::open(&root).expect("store");
    let error = store.acquire_publication_lock(repository_id).unwrap_err();
    assert!(matches!(error, CloneKitError::GitFailed(ref message) if message.contains("busy")));
    child.kill().expect("kill child");
    child.wait().expect("reap child");
    let _guard = store.acquire_publication_lock(repository_id).expect("lock released on child death");
}

#[test]
fn publication_lock_child_helper() {
    let Some(root) = std::env::var_os("ROOTYARD_CK_LOCK_ROOT") else {
        return;
    };
    let Some(repository_id) = std::env::var("ROOTYARD_CK_LOCK_REPO").ok().and_then(|raw| Uuid::parse_str(&raw).ok())
    else {
        return;
    };
    let Some(ready) = std::env::var_os("ROOTYARD_CK_LOCK_READY") else {
        return;
    };
    let store = CloneKitPublicationStore::open(Path::new(&root)).expect("child store");
    let _guard = store.acquire_publication_lock(repository_id).expect("child lock");
    fs::write(Path::new(&ready), b"ready").expect("ready");
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
fn gc_cannot_acquire_lock_while_winner_is_paused_after_install() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let (store, repository_id) = store_and_repo(&td);
    let ledger = RetentionPinLedger::new();
    publish_baseline(&store, repository_id);
    test_seam::pause_all_at(CP_AFTER_INSTALL);
    let publisher_store = store.clone();
    let publisher = std::thread::spawn(move || {
        publish_clonekit_versioned(&publisher_store, &empty_artifacts(repository_id, 2), git(), None, None)
    });
    test_seam::wait_until(CP_AFTER_INSTALL, 1);
    assert!(matches!(
        store.try_gc_generation(repository_id, 2, &ledger),
        Err(CloneKitError::GitFailed(ref message)) if message.contains("busy")
    ));
    assert!(store.version_dir(repository_id, 2).exists());
    test_seam::release(CP_AFTER_INSTALL);
    publisher.join().expect("join").expect("publication");
    assert!(matches!(store.try_gc_generation(repository_id, 2, &ledger), Err(CloneKitError::PinProtectionActive(_))));
    test_seam::reset();
}

#[test]
fn interrupted_install_is_not_collected_and_exact_retry_completes() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let (store, repository_id) = store_and_repo(&td);
    let ledger = RetentionPinLedger::new();
    publish_baseline(&store, repository_id);
    let candidate = empty_artifacts(repository_id, 2);
    test_seam::fail_once_at(CP_AFTER_INSTALL, "injected after install before pointer");
    let error = publish_clonekit_versioned(&store, &candidate, git(), None, None).unwrap_err();
    assert!(matches!(error, CloneKitError::GitFailed(ref message) if message.contains("injected after install")));
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present").kit_generation, 1);
    assert!(store.version_dir(repository_id, 2).exists());
    assert!(!store.try_gc_generation(repository_id, 2, &ledger).expect("future refused"));
    assert!(store.version_dir(repository_id, 2).exists());
    publish_clonekit_versioned(&store, &candidate, git(), None, None).expect("exact retry");
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present").kit_generation, 2);
    test_seam::reset();
}

#[test]
fn injected_failure_before_install_cleans_attempt_and_keeps_old_current() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let (store, repository_id) = store_and_repo(&td);
    publish_baseline(&store, repository_id);
    test_seam::fail_once_at(CP_BEFORE_INSTALL, "injected before install");
    let error = publish_clonekit_versioned(&store, &empty_artifacts(repository_id, 2), git(), None, None).unwrap_err();
    assert!(matches!(error, CloneKitError::GitFailed(ref message) if message.contains("injected before install")));
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present").kit_generation, 1);
    assert!(!store.version_dir(repository_id, 2).exists());
    assert!(attempt_names(&store, repository_id).is_empty());
    test_seam::reset();
}

#[test]
fn injected_failure_after_pointer_rename_exposes_new_current() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let (store, repository_id) = store_and_repo(&td);
    publish_baseline(&store, repository_id);
    test_seam::fail_once_at(CP_AFTER_POINTER, "injected after pointer rename");
    let error = publish_clonekit_versioned(&store, &empty_artifacts(repository_id, 2), git(), None, None).unwrap_err();
    assert!(matches!(error, CloneKitError::GitFailed(ref message) if message.contains("outcome uncertain")));
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present").kit_generation, 2);
    assert!(store.version_dir(repository_id, 2).exists());
    test_seam::reset();
}

#[test]
fn cancellation_before_commit_never_advertises_candidate() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let (store, repository_id) = store_and_repo(&td);
    publish_baseline(&store, repository_id);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let error =
        publish_clonekit_versioned(&store, &empty_artifacts(repository_id, 2), git(), None, Some(&cancel)).unwrap_err();
    assert!(matches!(error, CloneKitError::TransferCancelled));
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present").kit_generation, 1);
    assert!(!store.version_dir(repository_id, 2).exists());
    test_seam::reset();
}

#[test]
fn cancellation_after_pointer_rename_cannot_report_uncommitted() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let (store, repository_id) = store_and_repo(&td);
    publish_baseline(&store, repository_id);
    test_seam::pause_all_at(CP_AFTER_POINTER);
    let publisher_store = store.clone();
    let cancel = CancellationToken::new();
    let thread_cancel = cancel.clone();
    let publisher = std::thread::spawn(move || {
        publish_clonekit_versioned(
            &publisher_store,
            &empty_artifacts(repository_id, 2),
            git(),
            None,
            Some(&thread_cancel),
        )
    });
    test_seam::wait_until(CP_AFTER_POINTER, 1);
    cancel.cancel();
    test_seam::release(CP_AFTER_POINTER);
    publisher.join().expect("join").expect("committed publication must not report cancellation");
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present").kit_generation, 2);
    test_seam::reset();
}

#[test]
fn cancellation_after_install_before_pointer_leaves_unadvertised_generation() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let (store, repository_id) = store_and_repo(&td);
    publish_baseline(&store, repository_id);
    test_seam::pause_all_at(CP_BEFORE_POINTER);
    let publisher_store = store.clone();
    let cancel = CancellationToken::new();
    let thread_cancel = cancel.clone();
    let publisher = std::thread::spawn(move || {
        publish_clonekit_versioned(
            &publisher_store,
            &empty_artifacts(repository_id, 2),
            git(),
            None,
            Some(&thread_cancel),
        )
    });
    test_seam::wait_until(CP_BEFORE_POINTER, 1);
    cancel.cancel();
    test_seam::release(CP_BEFORE_POINTER);
    let error = publisher.join().expect("join").unwrap_err();
    assert!(matches!(error, CloneKitError::TransferCancelled));
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present").kit_generation, 1);
    assert!(store.version_dir(repository_id, 2).exists());
    test_seam::reset();
}

#[test]
fn failed_publication_preserves_caller_pin_and_manifest_hold_fields() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let (store, repository_id) = store_and_repo(&td);
    let ledger = RetentionPinLedger::new();
    publish_baseline(&store, repository_id);
    let pin = RetentionPinGuard::acquire(&ledger, repository_id, 2).expect("pin");
    let candidate = held_active_artifacts(repository_id, 2, pin.pin_id());
    let before = candidate.manifest.clone();
    let error =
        publish_clonekit_versioned(&store, &candidate, git(), Some(BuildFailurePoint::AfterUploadBeforePublish), None)
            .unwrap_err();
    assert!(matches!(error, CloneKitError::GitFailed(_)));
    assert_eq!(candidate.manifest, before);
    assert_eq!(ledger.active_pin_for(repository_id, 2), Some(pin.pin_id()));
    assert_eq!(store.load_latest(repository_id).expect("latest").expect("present").kit_generation, 1);
    test_seam::reset();
}
