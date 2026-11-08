//! IO lifecycle tests over a `cfg(test)` in-process memory backend.
//!
//! These are unit-level lifecycle checks of the resource/deadline contract (slot
//! ownership, staging weight, queue deadlines, cancel cleanup). They are *not*
//! provider qualification: real S3/Azure behaviour stays in
//! `tests/blob_provider_contract.rs`.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use super::{
    BlobError,
    budget::{LEASE_UNIT_BYTES, ResourceLimits, ResourceRegistry},
    readback,
    test_support::{deadline, payload, short_deadline, store, upload, write_source},
    transfer,
    upload::UploadGuard,
};

fn limits(uploads: usize, readers: usize, units: u64) -> ResourceLimits {
    ResourceLimits::new(uploads, readers, units * LEASE_UNIT_BYTES).expect("test limits")
}

#[test]
fn private_registry_shares_identical_limits_and_refuses_conflicts() {
    let registry = ResourceRegistry::new();
    let first_limits = limits(1, 1, 4);
    let first = registry.context(first_limits).unwrap();
    let second = registry.context(first_limits).unwrap();
    assert!(Arc::ptr_eq(&first, &second), "identical limits must share one context, not clone capacity");

    let conflicting = limits(2, 1, 4);
    assert!(matches!(registry.context(conflicting), Err(BlobError::CapacityConflict)));
    // The production process-wide registry is one instance of this rule. A
    // separate test registry can initialize with other limits without mutating
    // process-global state or racing another test.
    let fresh = ResourceRegistry::new();
    assert!(fresh.context(conflicting).is_ok());
}

#[tokio::test]
async fn staging_is_weighted_never_overcommits_and_oversize_fails_before_waiting() {
    let configured = limits(1, 2, 4);
    let (_store, resources) = store(configured);
    let held = resources.acquire_read(2 * LEASE_UNIT_BYTES, deadline()).await.unwrap();
    assert_eq!(resources.available_staging_bytes(), 2 * LEASE_UNIT_BYTES);
    assert_eq!(held.staging_bytes(), 2 * LEASE_UNIT_BYTES);

    let started = Instant::now();
    let oversize = resources.acquire_read(4 * LEASE_UNIT_BYTES + 1, deadline()).await;
    assert!(matches!(oversize, Err(BlobError::StagingBudgetExceeded { .. })));
    assert!(started.elapsed() < Duration::from_secs(1), "an unfulfillable lease must not wait for capacity");

    let started = Instant::now();
    let queued = resources.acquire_read(3 * LEASE_UNIT_BYTES, Instant::now() + Duration::from_millis(50)).await;
    assert!(matches!(queued, Err(BlobError::DeadlineExceeded)));
    assert!(started.elapsed() >= Duration::from_millis(40));
    // The timed-out waiter was neither granted nor permanently leaked units.
    assert_eq!(resources.available_staging_bytes(), 2 * LEASE_UNIT_BYTES);
    drop(held);
    assert_eq!(resources.available_staging_bytes(), 4 * LEASE_UNIT_BYTES);
    assert_eq!(resources.available_readers(), 2);
}

#[tokio::test]
async fn verified_download_queue_deadline_grants_no_lease_or_destination() {
    let configured = limits(1, 1, 2);
    let (blob, resources) = store(configured);
    let bytes = payload(2 * LEASE_UNIT_BYTES as usize);
    let dir = tempfile::tempdir().unwrap();
    let source = write_source(dir.path(), &bytes);
    let intent = upload(&blob, "budget", &bytes);
    let object = intent.locator().clone();
    blob.put_file(intent, &source, deadline()).await.expect("test publish");

    let held = resources.acquire_read(configured.staging_bytes(), deadline()).await.unwrap();
    let destination = dir.path().join("download");
    assert!(matches!(
        blob.get_to_file(&object, &destination, short_deadline()).await,
        Err(BlobError::DeadlineExceeded)
    ));
    assert!(!destination.exists(), "a timed-out download must not create the destination");
    // The caller's lease is still charged: a failed operation invents no capacity.
    assert_eq!(resources.available_readers(), 0);
    assert_eq!(resources.available_staging_bytes(), 0);

    drop(held);
    blob.get_to_file(&object, &destination, deadline()).await.expect("download once capacity returns");
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    // The successful path committed the staging file and returned every permit.
    assert_eq!(resources.available_staging_bytes(), configured.staging_bytes());
    assert_eq!(resources.available_readers(), 1);
    assert_eq!(resources.available_uploads(), 1);
}

#[tokio::test]
async fn upload_slot_is_returned_before_read_back_and_never_leaks() {
    // One upload slot and one reader slot: a publish that held its upload slot
    // across the read-back, or leaked it, could not complete twice in a row.
    let configured = limits(1, 1, 4);
    let (blob, resources) = store(configured);
    let bytes = payload(3 * 1024);
    let dir = tempfile::tempdir().unwrap();
    let source = write_source(dir.path(), &bytes);
    let first = upload(&blob, "uploads", &bytes);
    let first_locator = first.locator().clone();
    let second = upload(&blob, "uploads", &bytes);
    let second_locator = second.locator().clone();
    for (intent, object) in [(first, &first_locator), (second, &second_locator)] {
        let receipt = blob.put_file(intent, &source, deadline()).await.expect("publish must not deadlock");
        assert!(receipt.matches(object));
    }
    blob.verify(&first_locator, deadline()).await.expect("independent read-back");
    assert_eq!(resources.available_uploads(), 1);
    assert_eq!(resources.available_readers(), 1);
    assert_eq!(resources.available_staging_bytes(), configured.staging_bytes());
}

#[tokio::test]
async fn cancelled_writer_keeps_its_upload_slot_until_the_bounded_abort_finishes() {
    let configured = limits(1, 1, 2);
    let (blob, resources) = store(configured);
    let lease = resources.acquire_upload(deadline()).await.unwrap();
    assert_eq!(resources.available_uploads(), 0);
    let writer = blob.operator().writer_with("cancelled-upload").await.expect("memory writer");
    let guard = UploadGuard::new_with_lease(writer, Duration::from_millis(100), lease);
    drop(guard); // cancellation: the abort task owns the writer *and* the slot
    let mut released = false;
    for _ in 0..200 {
        if resources.available_uploads() == 1 {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(released, "the background abort must return the upload slot once it finished");
}

#[tokio::test]
async fn put_file_refuses_symlink_and_fifo_sources_without_hanging() {
    let configured = limits(1, 1, 2);
    let (blob, resources) = store(configured);
    let bytes = payload(2048);
    let dir = tempfile::tempdir().unwrap();
    let real = write_source(dir.path(), &bytes);
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let symlink_intent = upload(&blob, "sources", &bytes);
    let symlink_locator = symlink_intent.locator().clone();
    assert!(blob.put_file(symlink_intent, &link, deadline()).await.is_err(), "symlink sources must not be followed");
    assert_eq!(blob.head(&symlink_locator, deadline()).await.unwrap(), None);

    let fifo = dir.path().join("fifo");
    let fifo_c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    let fifo_intent = upload(&blob, "sources", &bytes);
    let fifo_locator = fifo_intent.locator().clone();
    assert!(blob.put_file(fifo_intent, &fifo, deadline()).await.is_err(), "FIFO sources must not be streamed");
    assert_eq!(blob.head(&fifo_locator, deadline()).await.unwrap(), None);
    assert_eq!(resources.available_uploads(), 1);

    // The regular file still publishes: the refusal is about the source type.
    let regular_intent = upload(&blob, "sources", &bytes);
    let regular_locator = regular_intent.locator().clone();
    blob.put_file(regular_intent, &real, deadline()).await.expect("regular source publish");
    assert_eq!(blob.head(&regular_locator, deadline()).await.unwrap(), Some(bytes.len() as u64));
}

#[tokio::test]
async fn outer_timeout_detaches_readback_and_keeps_lease_until_inner_drains() {
    let configured = limits(1, 1, 2);
    let (blob, resources) = store(configured);
    let bytes = payload(2048);
    let dir = tempfile::tempdir().unwrap();
    let source = write_source(dir.path(), &bytes);
    let intent = upload(&blob, "stall", &bytes);
    let object = intent.locator().clone();
    blob.put_file(intent, &source, deadline()).await.expect("publish");

    let destination = dir.path().join("stalled");
    let (entered, release) = readback::install_readback_stall(destination.clone());
    let download = tokio::spawn(async move {
        blob.get_to_file(&object, &destination, Instant::now() + Duration::from_millis(150)).await
    });
    tokio::time::timeout(Duration::from_secs(1), entered.acquire())
        .await
        .expect("inner task must reach the gate")
        .expect("gate open");
    assert!(matches!(download.await.unwrap(), Err(BlobError::DeadlineExceeded)));

    // The public caller is gone, but the owned task still holds the one reader
    // slot and its staging unit while the local operation is outstanding.
    assert_eq!(resources.available_readers(), 0);
    assert_eq!(resources.available_staging_bytes(), LEASE_UNIT_BYTES);

    release.add_permits(1);
    let mut released = false;
    for _ in 0..200 {
        if resources.available_readers() == 1 {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(released, "the detached task must release the lease only after it drains");
    assert_eq!(resources.available_staging_bytes(), configured.staging_bytes());
    readback::clear_readback_stall();
}

#[tokio::test]
async fn outer_timeout_detaches_upload_and_keeps_slot_until_abort_finishes() {
    let configured = limits(1, 1, 2);
    let (blob, resources) = store(configured);
    let bytes = payload(4096);
    let dir = tempfile::tempdir().unwrap();
    let source = write_source(dir.path(), &bytes);
    let intent = upload(&blob, "upload-stall", &bytes);
    let (entered, release) = transfer::install_upload_read_stall(source.clone());
    let upload =
        tokio::spawn(async move { blob.put_file(intent, &source, Instant::now() + Duration::from_millis(150)).await });
    tokio::time::timeout(Duration::from_secs(1), entered.acquire())
        .await
        .expect("owned upload must reach the local read gate")
        .expect("gate open");
    assert!(matches!(upload.await.unwrap(), Err(BlobError::DeadlineExceeded)));

    // The public caller timed out, but the detached owned task still holds the
    // one upload slot until its local read and bounded abort settle.
    assert_eq!(resources.available_uploads(), 0);
    release.add_permits(1);
    let mut released = false;
    for _ in 0..200 {
        if resources.available_uploads() == 1 {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(released, "the detached upload must release its slot only after abort settles");
    assert_eq!(resources.available_staging_bytes(), configured.staging_bytes());
    assert_eq!(resources.available_readers(), 1);
    transfer::clear_upload_read_stall();
}
