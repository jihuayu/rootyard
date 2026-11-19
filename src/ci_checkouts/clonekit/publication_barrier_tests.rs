//! Source-only negative tests for bounded publication barriers and abandoned observers.

use std::{fs, path::Path, time::Duration};

use tempfile::TempDir;
use uuid::Uuid;

use super::{
    CP_AFTER_INSTALL, CloneKitPublicationStore, publication_tests::empty_artifacts, publish_clonekit_versioned,
    test_seam,
};
use crate::ci_checkouts::clonekit::manifest::CloneKitError;

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else {
        "<non-string panic>".to_owned()
    }
}

fn attempt_names(store: &CloneKitPublicationStore, repository_id: Uuid) -> Vec<String> {
    fs::read_dir(store.repo_dir(repository_id))
        .expect("repo dir")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".publish-"))
        .collect()
}

fn lock_probe_class(err: &CloneKitError) -> &'static str {
    match err {
        CloneKitError::InvalidConfig(_) => "invalid-config",
        CloneKitError::GitFailed(message) if message.starts_with("open publication lock:") => "open",
        CloneKitError::GitFailed(message) if message.starts_with("secure publication lock:") => "secure",
        CloneKitError::GitFailed(message) if message.starts_with("stat publication lock:") => "stat",
        CloneKitError::GitFailed(message) if message.starts_with("clonekit publication busy:") => "busy",
        CloneKitError::GitFailed(message) if message.starts_with("publication lock failed:") => "flock",
        _ => "unknown",
    }
}

fn assert_lock_probe_classifier() {
    let cases = [
        (CloneKitError::InvalidConfig("arbitrary"), "invalid-config"),
        (CloneKitError::GitFailed("open publication lock: arbitrary".into()), "open"),
        (CloneKitError::GitFailed("secure publication lock: arbitrary".into()), "secure"),
        (CloneKitError::GitFailed("stat publication lock: arbitrary".into()), "stat"),
        (CloneKitError::GitFailed("clonekit publication busy: arbitrary".into()), "busy"),
        (CloneKitError::GitFailed("publication lock failed: arbitrary".into()), "flock"),
        (CloneKitError::GitFailed("open publication lock: clonekit publication busy: injected".into()), "open"),
        (CloneKitError::GitFailed("clonekit publication busy: publication lock failed: injected".into()), "busy"),
        (CloneKitError::GitFailed("publication lock failed: open publication lock: injected".into()), "flock"),
        (CloneKitError::GitFailed("untrusted busy text".into()), "unknown"),
    ];
    for (err, expected) in cases {
        assert_eq!(expected, lock_probe_class(&err), "lock probe classifier");
    }
}

#[test]
fn wait_until_times_out_with_checkpoint_and_count_diagnostic() {
    let _serial = test_seam::serial_with_deadline(Duration::from_millis(100));
    test_seam::reset();
    let panic = std::panic::catch_unwind(|| test_seam::wait_until("missing-checkpoint", 1)).unwrap_err();
    let message = panic_message(panic.as_ref());
    assert!(message.contains("missing-checkpoint"));
    assert!(message.contains("expected 1"));
    assert!(message.contains("observed 0"));
    assert!(message.contains("deadline"));
    test_seam::reset();
}

#[test]
fn abandoned_publisher_releases_lock_and_preserves_owned_generation() {
    let _serial = test_seam::serial_with_deadline(Duration::from_secs(10));
    test_seam::reset();
    assert_lock_probe_classifier();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    test_seam::pause_all_at(CP_AFTER_INSTALL);
    let publisher_store = store.clone();
    let candidate = empty_artifacts(repository_id, 1);
    let publisher = std::thread::spawn(move || {
        publish_clonekit_versioned(&publisher_store, &candidate, Path::new("/usr/bin/git"), None, None)
    });
    test_seam::wait_until(CP_AFTER_INSTALL, 1);
    test_seam::abandon();

    let publisher = publisher.join().expect("join abandoned publisher");
    assert!(matches!(
        publisher,
        Err(CloneKitError::GitFailed(ref message)) if message.contains("abandoned")
    ));
    assert!(store.version_dir(repository_id, 1).exists());
    assert!(store.load_latest(repository_id).expect("latest").is_none());
    assert!(attempt_names(&store, repository_id).is_empty());
    let _guard = match store.acquire_publication_lock(repository_id) {
        Ok(guard) => guard,
        Err(err) => panic!("clonekit_lock_probe class={}", lock_probe_class(&err)),
    };
    test_seam::reset();
}

#[test]
fn deadline_boundary_is_inclusive_only_on_or_before() {
    let _serial = test_seam::serial_with_deadline(Duration::from_millis(100));
    test_seam::reset();
    let deadline = test_seam::test_deadline();
    assert!(test_seam::is_timely_signal(deadline - Duration::from_nanos(1), deadline));
    assert!(test_seam::is_timely_signal(deadline, deadline));
    assert!(!test_seam::is_timely_signal(deadline + Duration::from_nanos(1), deadline));
    test_seam::reset();
}

#[test]
fn late_arrival_does_not_satisfy_wait_until() {
    let _serial = test_seam::serial_with_deadline(Duration::from_millis(100));
    test_seam::reset();
    let deadline = test_seam::test_deadline();
    test_seam::record_arrival_at("late-arrival", deadline + Duration::from_nanos(1));
    let panic = std::panic::catch_unwind(|| test_seam::wait_until("late-arrival", 1)).unwrap_err();
    let message = panic_message(panic.as_ref());
    assert!(message.contains("late-arrival"));
    assert!(message.contains("expected 1"));
    assert!(message.contains("observed 0"));
    assert!(message.contains("deadline"));
    test_seam::reset();
}

#[test]
fn late_release_does_not_satisfy_paused_checkpoint() {
    let _serial = test_seam::serial_with_deadline(Duration::from_secs(2));
    test_seam::reset();
    let td = TempDir::new().expect("tempdir");
    let store = CloneKitPublicationStore::open(&td.path().join("catalog")).expect("store");
    let repository_id = Uuid::new_v4();
    test_seam::pause_all_at(CP_AFTER_INSTALL);
    let publisher_store = store.clone();
    let candidate = empty_artifacts(repository_id, 1);
    let publisher = std::thread::spawn(move || {
        publish_clonekit_versioned(&publisher_store, &candidate, Path::new("/usr/bin/git"), None, None)
    });
    test_seam::wait_until(CP_AFTER_INSTALL, 1);
    let deadline = test_seam::test_deadline();
    test_seam::record_release_at(CP_AFTER_INSTALL, deadline + Duration::from_nanos(1));

    let publisher = publisher.join().expect("join late-release publisher");
    assert!(matches!(
        publisher,
        Err(CloneKitError::GitFailed(ref message)) if message.contains("deadline") && message.contains("after")
    ));
    assert!(store.version_dir(repository_id, 1).exists());
    assert!(store.load_latest(repository_id).expect("latest").is_none());
    assert!(attempt_names(&store, repository_id).is_empty());
    let _guard = store.acquire_publication_lock(repository_id).expect("lock released after late release");
    test_seam::reset();
}
