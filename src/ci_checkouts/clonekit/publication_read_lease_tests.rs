//! Source-only deterministic and independent-process tests for the local read lease.

use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use tempfile::TempDir;
use uuid::Uuid;

use super::publication_tests::empty_artifacts;
use super::{CloneKitPublicationStore, publish_clonekit_versioned, test_seam};
use crate::ci_checkouts::clonekit::{CloneKitError, RetentionPinLedger};

#[path = "publication_active_fixture.rs"]
mod fixture;

fn publish(store: &CloneKitPublicationStore, repository_id: Uuid, kit_generation: u64) {
    publish_clonekit_versioned(
        store,
        &empty_artifacts(repository_id, kit_generation),
        Path::new("/usr/bin/git"),
        None,
        None,
    )
    .expect("publish test generation");
}

fn publish_active(td: &TempDir, store: &CloneKitPublicationStore, ids: (Uuid, Uuid, Uuid), label: &str) {
    let candidate = fixture::build_active_candidate(td, ids, 1, label, b"active-generation-lease-payload")
        .expect("active candidate");
    publish_clonekit_versioned(store, &candidate, &fixture::git_binary(), None, None)
        .expect("publish active generation");
}

#[test]
fn leased_selection_blocks_gc_until_verified_copy_and_release() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let ids = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let repository_id = ids.1;
    let ledger = RetentionPinLedger::new();
    publish_active(&td, &store, ids, "lease-active");

    let leased = store.load_latest_leased(repository_id).expect("lease").expect("current generation");
    assert_eq!(leased.manifest().kit_generation, 1);
    let (pack_path, idx_path) = store.artifact_paths(repository_id, 1);
    assert!(!fs::read(&pack_path).expect("active pack under lease").is_empty());
    assert!(!fs::read(&idx_path).expect("active idx under lease").is_empty());
    publish(&store, repository_id, 2);
    let error = store.try_gc_generation(repository_id, 1, &ledger).expect_err("active read lease must defer gc");
    assert!(
        matches!(error, CloneKitError::GitFailed(ref message) if message.contains("read lease") && message.contains("busy"))
    );
    assert!(store.version_dir(repository_id, 1).is_dir());

    drop(leased);
    assert!(store.try_gc_generation(repository_id, 1, &ledger).expect("gc after lease release"));
    assert!(!store.version_dir(repository_id, 1).exists());
    test_seam::reset();
}

#[test]
fn vanished_or_symlinked_selected_generation_is_rejected() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");

    let vanished_repo = Uuid::new_v4();
    publish(&store, vanished_repo, 1);
    fs::rename(store.version_dir(vanished_repo, 1), store.version_dir(vanished_repo, 9)).expect("move generation");
    let error = store.load_latest_leased(vanished_repo).expect_err("vanished generation must fail");
    assert!(matches!(error, CloneKitError::CorruptArtifact(_)));

    let symlinked_repo = Uuid::new_v4();
    publish(&store, symlinked_repo, 1);
    let version_dir = store.version_dir(symlinked_repo, 1);
    let real_dir = store.version_dir(symlinked_repo, 9);
    fs::rename(&version_dir, &real_dir).expect("move generation");
    std::os::unix::fs::symlink(&real_dir, &version_dir).expect("symlink generation");
    let error = store.load_latest_leased(symlinked_repo).expect_err("symlinked generation must fail");
    assert!(matches!(error, CloneKitError::CorruptArtifact(_)));
    test_seam::reset();
}

#[test]
fn symlinked_read_lease_file_is_rejected() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    publish(&store, repository_id, 1);
    let target = td.path().join("not-a-lease");
    fs::write(&target, b"target").expect("lease target");
    std::os::unix::fs::symlink(&target, store.repo_dir(repository_id).join(".read.lock")).expect("lease symlink");
    let error = store.load_latest_leased(repository_id).expect_err("symlinked read lease must fail");
    assert!(matches!(error, CloneKitError::GitFailed(_)));
    test_seam::reset();
}

#[test]
fn cross_process_reader_lease_blocks_gc_and_releases_on_child_exit() {
    let _serial = test_seam::serial();
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let root = td.path().join("catalog");
    let store = CloneKitPublicationStore::open(&root).expect("store");
    let repository_id = Uuid::new_v4();
    publish(&store, repository_id, 1);
    publish(&store, repository_id, 2);
    let ready = td.path().join("reader-ready");
    let mut child = Command::new(std::env::current_exe().expect("current exe"))
        .arg("--nocapture")
        .arg("publication_read_lease_child_helper")
        .env("ROOTYARD_CK_READ_LEASE_ROOT", &root)
        .env("ROOTYARD_CK_READ_LEASE_REPO", repository_id.to_string())
        .env("ROOTYARD_CK_READ_LEASE_READY", &ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("child reader");
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
        panic!("child reader did not acquire the read lease");
    }

    let ledger = RetentionPinLedger::new();
    let error = store.try_gc_generation(repository_id, 1, &ledger).expect_err("child lease must defer gc");
    assert!(matches!(error, CloneKitError::GitFailed(ref message) if message.contains("busy")));
    assert!(store.version_dir(repository_id, 1).is_dir());

    child.kill().expect("kill child reader");
    child.wait().expect("reap child reader");
    assert!(store.try_gc_generation(repository_id, 1, &ledger).expect("gc after child death"));
    assert!(!store.version_dir(repository_id, 1).exists());
    test_seam::reset();
}

#[test]
fn publication_read_lease_child_helper() {
    let Some(root) = std::env::var_os("ROOTYARD_CK_READ_LEASE_ROOT") else {
        return;
    };
    let Some(repository_id) =
        std::env::var("ROOTYARD_CK_READ_LEASE_REPO").ok().and_then(|raw| Uuid::parse_str(&raw).ok())
    else {
        return;
    };
    let Some(ready) = std::env::var_os("ROOTYARD_CK_READ_LEASE_READY") else {
        return;
    };
    let store = CloneKitPublicationStore::open(Path::new(&root)).expect("child store");
    let leased = store.load_latest_leased(repository_id).expect("child lease").expect("child current");
    assert_eq!(leased.manifest().kit_generation, 2);
    fs::write(Path::new(&ready), b"ready").expect("ready");
    std::thread::sleep(Duration::from_secs(30));
}
