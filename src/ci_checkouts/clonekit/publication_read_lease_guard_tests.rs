//! Focused lock-ownership and backend-scope tests for the local read lease.

use std::fs;

use fs2::FileExt;
use tempfile::TempDir;
use uuid::Uuid;

use crate::ci_checkouts::clonekit::CloneKitError;
use crate::ci_checkouts::clonekit::builder::read_lease::{
    ReadLeaseExclusive, ReadLeaseLock, backend_uses_open_file_description_flock, require_supported_backend,
};

#[test]
fn flock_allowlist_refuses_process_scoped_targets() {
    assert!(backend_uses_open_file_description_flock("linux"));
    assert!(backend_uses_open_file_description_flock("macos"));
    assert!(backend_uses_open_file_description_flock("freebsd"));
    assert!(!backend_uses_open_file_description_flock("solaris"));
    assert!(!backend_uses_open_file_description_flock("illumos"));
    assert!(!backend_uses_open_file_description_flock("windows"));
    assert_eq!(require_supported_backend().is_ok(), backend_uses_open_file_description_flock(std::env::consts::OS));
}

#[test]
fn guarded_locks_unlock_on_validation_error_with_duplicate_fd() {
    let td = TempDir::new().expect("tempdir");
    let path = td.path().join(".read.lock");
    let repository_id = Uuid::new_v4();

    // Control: without an explicit unlock, a duplicate fd keeps the shared flock alive after
    // the original descriptor is closed.
    let file = fs::OpenOptions::new().read(true).write(true).create(true).open(&path).expect("lock file");
    file.try_lock_shared().expect("shared lock");
    let duplicate = file.try_clone().expect("duplicate shared fd");
    drop(file);
    let contender = fs::OpenOptions::new().read(true).write(true).open(&path).expect("contender");
    assert!(contender.try_lock_exclusive().is_err(), "duplicate fd shares the open-file-description flock");
    duplicate.unlock().expect("release duplicate lock");
    drop(contender);
    drop(duplicate);

    // Shared guard: a post-lock validation failure consumes the owner, whose explicit Drop
    // unlock must release the shared flock even though the duplicate fd remains open.
    let file = fs::OpenOptions::new().read(true).write(true).open(&path).expect("lock file");
    file.try_lock_shared().expect("shared lock");
    let duplicate = file.try_clone().expect("duplicate shared fd");
    let guard = ReadLeaseLock::from_locked_file_for_test(file, repository_id);
    let result = fail_shared_validation(guard);
    assert!(matches!(result, Err(CloneKitError::CorruptArtifact(_))));
    let contender = fs::OpenOptions::new().read(true).write(true).open(&path).expect("contender");
    contender.try_lock_exclusive().expect("guard drop unlocks shared flock despite duplicate fd");
    drop(contender);
    drop(duplicate);

    // Exclusive guard: the same ownership applies to the GC write-side lock.
    let file = fs::OpenOptions::new().read(true).write(true).open(&path).expect("lock file");
    file.try_lock_exclusive().expect("exclusive lock");
    let duplicate = file.try_clone().expect("duplicate exclusive fd");
    let guard = ReadLeaseExclusive::from_locked_file_for_test(file);
    let result = fail_exclusive_validation(guard);
    assert!(matches!(result, Err(CloneKitError::CorruptArtifact(_))));
    let contender = fs::OpenOptions::new().read(true).write(true).open(&path).expect("contender");
    contender.try_lock_exclusive().expect("guard drop unlocks exclusive flock despite duplicate fd");
    drop(contender);
    drop(duplicate);
}

fn fail_shared_validation(_guard: ReadLeaseLock) -> Result<(), CloneKitError> {
    Err(CloneKitError::CorruptArtifact("injected post-lock validation failure".into()))
}

fn fail_exclusive_validation(_guard: ReadLeaseExclusive) -> Result<(), CloneKitError> {
    Err(CloneKitError::CorruptArtifact("injected post-lock validation failure".into()))
}
