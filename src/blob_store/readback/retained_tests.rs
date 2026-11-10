//! Owner-retention tests for the **actual** Blob transfer and staging-cleanup
//! wiring.
//!
//! These use the in-process `memory` backend and deterministic gates. They are
//! unit lifecycle/ownership tests, not provider qualification (real S3/Azure
//! behaviour stays in `tests/blob_provider_contract.rs`).

use super::{
    clear_cleanup_stall, clear_readback_stall, install_cleanup_stall, install_readback_stall,
    ownership::{Keepalive, TransferGuard, TransferResources, clear_transfer_completion, install_transfer_completion},
};
use crate::blob_store::{
    budget::{LEASE_UNIT_BYTES, ResourceLimits},
    test_support::{deadline, payload, store, upload, write_source},
};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

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

/// RAII cleanup for the keyed static gates: unblocks a parked Gate A and removes
/// this test's entries even when an assertion panics first.
struct GateCleanup {
    destination: PathBuf,
    parent: PathBuf,
    release_a: Arc<tokio::sync::Semaphore>,
}

impl Drop for GateCleanup {
    fn drop(&mut self) {
        // A parked Gate A would otherwise wait forever on a leaked permit.
        self.release_a.add_permits(1);
        clear_readback_stall(&self.destination);
        clear_cleanup_stall(&self.parent);
        clear_transfer_completion(&self.destination);
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
    let completed = install_transfer_completion(destination.clone());
    let _gates = GateCleanup {
        destination: destination.clone(),
        parent: dir.path().to_path_buf(),
        release_a: Arc::clone(&release_a),
    };
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
    // Gate B fires inside the deferred unlink, possibly before the transfer
    // future resumes. Wait until the actual owned task settled its guard while
    // B is still held: the remaining ownership must be the cleanup clone.
    let _ = tokio::time::timeout(Duration::from_secs(5), completed.acquire())
        .await
        .expect("the actual owned task must reach transfer completion")
        .expect("completion gate open");
    assert_eq!(drops.load(Ordering::SeqCst), 0, "transfer completion is not cleanup");
    assert_eq!(resources.available_readers(), 0, "the unlink still owns the read lease");
    assert_eq!(resources.available_staging_bytes(), LEASE_UNIT_BYTES, "the unlink still owns staging bytes");

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
}

/// Unit ownership test only (not an S3/provider qualification): an unsettled
/// shared-resources guard retains both halves of the read lease and the owner.
#[tokio::test]
async fn an_unsettled_shared_resources_guard_retains_read_lease_and_owner() {
    let (_, resources) = store(limits());
    let lease = resources.acquire_read(LEASE_UNIT_BYTES, deadline()).await.expect("read lease");
    let drops = Arc::new(AtomicUsize::new(0));
    let owner: Keepalive = Arc::new(DropCounter(Arc::clone(&drops)));
    drop(TransferGuard::new(Arc::new(TransferResources::new(lease, Some(owner)))));
    assert_eq!(resources.available_readers(), 0, "the unsettled guard keeps the reader slot");
    assert_eq!(resources.available_staging_bytes(), LEASE_UNIT_BYTES, "the unsettled guard keeps staging bytes");
    assert_eq!(drops.load(Ordering::SeqCst), 0, "the unsettled guard keeps the external owner");
}

/// A settled guard releases both halves once the last shared clone is gone.
#[tokio::test]
async fn a_settled_shared_resources_guard_releases_read_lease_and_owner() {
    let (_, resources) = store(limits());
    let lease = resources.acquire_read(LEASE_UNIT_BYTES, deadline()).await.expect("read lease");
    let drops = Arc::new(AtomicUsize::new(0));
    let owner: Keepalive = Arc::new(DropCounter(Arc::clone(&drops)));
    let mut guard = TransferGuard::new(Arc::new(TransferResources::new(lease, Some(owner))));
    guard.settle();
    drop(guard);
    assert_eq!(resources.available_readers(), 1, "a settled guard returns the reader slot");
    assert_eq!(resources.available_staging_bytes(), 2 * LEASE_UNIT_BYTES, "a settled guard returns staging bytes");
    assert_eq!(drops.load(Ordering::SeqCst), 1, "a settled guard releases the external owner");
}

/// Unit failure-path test only (not provider qualification): a real unlink error
/// (`EISDIR` on this platform) must quarantine the shared read lease and owner
/// instead of reporting capacity free. The leased budget is this test's private
/// `ResourceContext`, so the bounded leak cannot poison global/native capacity.
#[tokio::test]
async fn a_failed_staging_unlink_retains_read_lease_and_owner() {
    let (_, resources) = store(limits());
    let lease = resources.acquire_read(LEASE_UNIT_BYTES, deadline()).await.expect("read lease");
    let drops = Arc::new(AtomicUsize::new(0));
    let owner: Keepalive = Arc::new(DropCounter(Arc::clone(&drops)));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("staging-directory");
    std::fs::create_dir(&path).unwrap();
    super::StagingCleanup { path, shared: Some(Arc::new(TransferResources::new(lease, Some(owner)))) }.run();
    assert_eq!(resources.available_readers(), 0, "a failed unlink must not return the reader slot");
    assert_eq!(resources.available_staging_bytes(), LEASE_UNIT_BYTES, "a failed unlink must not return staging bytes");
    assert_eq!(drops.load(Ordering::SeqCst), 0, "a failed unlink must quarantine the owner");
}

/// Unit-only paired settle check: confirmed absence (`NotFound`) releases both.
#[tokio::test]
async fn a_not_found_staging_unlink_releases_read_lease_and_owner() {
    let (_, resources) = store(limits());
    let lease = resources.acquire_read(LEASE_UNIT_BYTES, deadline()).await.expect("read lease");
    let drops = Arc::new(AtomicUsize::new(0));
    let owner: Keepalive = Arc::new(DropCounter(Arc::clone(&drops)));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("already-gone");
    super::StagingCleanup { path, shared: Some(Arc::new(TransferResources::new(lease, Some(owner)))) }.run();
    assert_eq!(resources.available_readers(), 1, "confirmed absence returns the reader slot");
    assert_eq!(resources.available_staging_bytes(), 2 * LEASE_UNIT_BYTES, "confirmed absence returns staging bytes");
    assert_eq!(drops.load(Ordering::SeqCst), 1, "confirmed absence releases the owner");
}
