//! Private unit tests for the process-wide resource budget.

use std::time::{Duration, Instant};

use super::{
    BlobError,
    budget::{
        DEFAULT_STAGING_BYTES, LEASE_UNIT_BYTES, MAX_ACTIVE_SLOTS, MAX_STAGING_BYTES, ResourceContext, ResourceLimits,
    },
    test_support::deadline,
};

#[test]
fn resource_limits_reject_zero_unbounded_and_oversized_capacity() {
    assert!(ResourceLimits::new(0, 1, DEFAULT_STAGING_BYTES).is_err());
    assert!(ResourceLimits::new(1, 0, DEFAULT_STAGING_BYTES).is_err());
    assert!(ResourceLimits::new(MAX_ACTIVE_SLOTS + 1, 1, DEFAULT_STAGING_BYTES).is_err());
    assert!(ResourceLimits::new(1, MAX_ACTIVE_SLOTS + 1, DEFAULT_STAGING_BYTES).is_err());
    assert!(ResourceLimits::new(1, 1, LEASE_UNIT_BYTES - 1).is_err());
    assert!(ResourceLimits::new(1, 1, MAX_STAGING_BYTES + 1).is_err());
    assert!(ResourceLimits::new(1, 1, MAX_STAGING_BYTES).is_ok());
    let defaults = ResourceLimits::new(2, 4, DEFAULT_STAGING_BYTES).unwrap();
    assert_eq!(defaults.active_uploads(), 2);
    assert_eq!(defaults.active_readers(), 4);
    assert_eq!(defaults.staging_bytes(), 256 * 1024 * 1024);
}

#[tokio::test]
async fn staging_lease_rounds_up_and_releases_on_drop() {
    let context = ResourceContext::new(ResourceLimits::new(1, 1, 3 * LEASE_UNIT_BYTES).unwrap());
    // One byte over a unit still needs two units: rounding never under-charges.
    let lease = context.acquire_read(LEASE_UNIT_BYTES + 1, deadline()).await.unwrap();
    assert_eq!(lease.staging_bytes(), LEASE_UNIT_BYTES + 1);
    assert_eq!(context.available_staging_bytes(), LEASE_UNIT_BYTES);
    drop(lease);
    assert_eq!(context.available_staging_bytes(), 3 * LEASE_UNIT_BYTES);

    // Stream-only verification (no staging file) leases no disk.
    let stream_only = context.acquire_read(0, deadline()).await.unwrap();
    assert_eq!(stream_only.staging_bytes(), 0);
    assert_eq!(context.available_staging_bytes(), 3 * LEASE_UNIT_BYTES);
    assert_eq!(context.available_readers(), 0);
}

#[tokio::test]
async fn reader_slots_are_bounded_independently_of_staging() {
    let context = ResourceContext::new(ResourceLimits::new(2, 1, 4 * LEASE_UNIT_BYTES).unwrap());
    let reader = context.acquire_read(0, deadline()).await.unwrap();
    assert_eq!(context.available_readers(), 0);
    assert_eq!(context.available_uploads(), 2);
    // Staging is free, yet the reader slot bounds queueing and honours a deadline.
    let started = Instant::now();
    let queued = context.acquire_read(0, Instant::now() + Duration::from_millis(40)).await;
    assert!(matches!(queued, Err(BlobError::DeadlineExceeded)));
    assert!(started.elapsed() >= Duration::from_millis(30));
    drop(reader);
    assert_eq!(context.available_readers(), 1);
}

#[tokio::test]
async fn upload_and_reader_slots_are_separate_budgets() {
    let context = ResourceContext::new(ResourceLimits::new(1, 1, 2 * LEASE_UNIT_BYTES).unwrap());
    let upload = context.acquire_upload(deadline()).await.unwrap();
    assert_eq!(context.available_uploads(), 0);
    // A read-back can still start while one upload is in flight.
    let read = context.acquire_read(LEASE_UNIT_BYTES, deadline()).await.unwrap();
    assert_eq!(context.available_readers(), 0);
    drop(read);
    drop(upload);
    assert_eq!(context.available_uploads(), 1);
    assert_eq!(context.available_staging_bytes(), 2 * LEASE_UNIT_BYTES);
}
