//! Owner-retention tests for the **actual** Blob transfer and staging-cleanup
//! wiring.
//!
//! These use the in-process `memory` backend and deterministic gates. They are
//! unit lifecycle/ownership tests, not provider qualification (real S3/Azure
//! behaviour stays in `tests/blob_provider_contract.rs`).

use super::{
    Keepalive, TransferGuard, clear_cleanup_stall, clear_readback_stall, install_cleanup_stall, install_readback_stall,
};
use crate::blob_store::{
    budget::{LEASE_UNIT_BYTES, ResourceLimits},
    test_support::{deadline, payload, store, upload, write_source},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

fn limits() -> ResourceLimits {
    ResourceLimits::new(1, 1, 2 * LEASE_UNIT_BYTES).expect("test limits")
}

/// Observable stand-in for a materialized-view lease.
struct DropCounter(Arc<AtomicUsize>);

impl Drop for DropCounter {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// One flow with both lifetimes gated independently: Gate A holds the **actual**
/// owned transfer task, Gate B holds its deferred `spawn_blocking(remove_file)`
/// cleanup. The caller-side wait is dropped first, so this proves the timeout,
/// the transfer task returning and the staging unlink are three different events.
#[tokio::test]
async fn caller_timeout_transfer_and_unlink_each_retain_the_owner_until_done() {
    let (blob, resources) = store(limits());
    let bytes = payload(2048);
    let dir = tempfile::tempdir().unwrap();
    let source = write_source(dir.path(), &bytes);
    let intent = upload(&blob, "owner-two-gates", &bytes);
    let object = intent.locator().clone();
    blob.put_file(intent, &source, deadline()).await.expect("publish");

    // A directory destination refuses the commit rename *after* the staging file
    // exists, so the real deferred unlink path runs.
    let destination = dir.path().join("blocked-destination");
    std::fs::create_dir(&destination).unwrap();
    let (entered_a, release_a) = install_readback_stall(destination.clone());
    let (entered_b, release_b) = install_cleanup_stall(dir.path().to_path_buf());
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = Arc::new(DropCounter(Arc::clone(&drops)));
    let task_destination = destination.clone();
    let caller = tokio::spawn(async move {
        // Caller-side absolute timeout of the public future: the owned transfer
        // task is detached, not aborted. The API's own `get_to_file` timeout is
        // covered separately by the pre-existing readback stall test.
        tokio::time::timeout(
            Duration::from_millis(150),
            blob.get_to_file_with_owner(&object, &task_destination, deadline(), owner),
        )
        .await
    });

    let _ = tokio::time::timeout(Duration::from_secs(1), entered_a.acquire())
        .await
        .expect("the actual owned task must reach Gate A")
        .expect("gate open");
    let waited = caller.await.expect("caller task");
    assert!(waited.is_err(), "the caller-side wait timed out");
    // Gate A: the waiter is gone, yet the actual owned task still holds the
    // owner, the reader slot and the staging unit.
    assert_eq!(drops.load(Ordering::SeqCst), 0, "the timeout released the owner");
    assert_eq!(resources.available_readers(), 0, "the owned task still owns the read lease");
    assert_eq!(resources.available_staging_bytes(), LEASE_UNIT_BYTES);

    release_a.add_permits(1);
    let _ = tokio::time::timeout(Duration::from_secs(5), entered_b.acquire())
        .await
        .expect("the deferred unlink must reach Gate B")
        .expect("gate open");
    // Gate B: the transfer body has finished (rename refused, staging dropped),
    // but its unlink is still outstanding, so nothing may be reclaimed yet.
    assert_eq!(drops.load(Ordering::SeqCst), 0, "transfer completion is not cleanup");
    assert_eq!(resources.available_readers(), 0, "the unlink still owns the read lease");

    release_b.send(()).expect("release the unlink gate");
    let mut settled = false;
    for _ in 0..200 {
        if drops.load(Ordering::SeqCst) == 1 && resources.available_readers() == 1 {
            settled = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(settled, "owner and reader slot return only after the unlink returned");
    assert_eq!(resources.available_staging_bytes(), 2 * LEASE_UNIT_BYTES);
    let leftovers = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".rootyard-blob-"))
        .count();
    assert_eq!(leftovers, 0, "the staging file is unlinked before capacity returns");
    clear_readback_stall(&destination);
    clear_cleanup_stall(dir.path());
}

/// The guard's own fail-closed semantics. This does **not** cover the detach
/// wiring of the real task (the two-gate test above does): it only proves that an
/// aborted task's guard retains the owner instead of claiming cleanup.
#[test]
fn an_unsettled_transfer_guard_retains_its_owner_until_settled() {
    let retained = Arc::new(AtomicUsize::new(0));
    let owner: Keepalive = Arc::new(DropCounter(Arc::clone(&retained)));
    drop(TransferGuard::new(Some(owner)));
    assert_eq!(retained.load(Ordering::SeqCst), 0, "an unsettled guard forgets its owner");

    let released = Arc::new(AtomicUsize::new(0));
    let owner: Keepalive = Arc::new(DropCounter(Arc::clone(&released)));
    let mut guard = TransferGuard::new(Some(owner));
    guard.settle();
    drop(guard);
    assert_eq!(released.load(Ordering::SeqCst), 1, "a settled guard releases its owner");
}
