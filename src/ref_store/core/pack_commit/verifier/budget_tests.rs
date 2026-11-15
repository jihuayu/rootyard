use super::budget::{AdmissionClass, BudgetRegistry, VERIFIER_DISK_HEADROOM_BYTES, ensure_available_disk_bytes};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn bounded_registry() -> BudgetRegistry {
    BudgetRegistry::new(4, 2, 2, 1, 2, 1, 4 * 1024 * 1024, 2 * 1024 * 1024)
}

#[tokio::test]
async fn slow_download_pool_saturation_does_not_starve_native_slots() {
    let registry = bounded_registry();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut downloads = Vec::new();
    for _ in 0..4 {
        downloads.push(registry.acquire_download(AdmissionClass::Foreground, deadline).await.expect("download slot"));
    }
    let fifth_deadline = Instant::now() + Duration::from_millis(20);
    assert!(
        registry.acquire_download(AdmissionClass::Foreground, fifth_deadline).await.is_err(),
        "fifth concurrent download must hit backpressure at the download cap"
    );
    // Native Git CPU slots stay completely free even while all 4 download slots are pinned.
    let n1 = registry.acquire_native(AdmissionClass::Foreground, deadline).await.expect("native slot 1");
    let n2 = registry.acquire_native(AdmissionClass::Foreground, deadline).await.expect("native slot 2");
    let snap = registry.snapshot();
    assert_eq!(snap.download_in_flight, 4);
    assert_eq!(snap.native_in_flight, 2);
    assert!(snap.budget_timeouts >= 1);
    drop((n1, n2, downloads));
}

#[tokio::test]
async fn maintenance_subcaps_leave_foreground_admission_headroom() {
    let registry = bounded_registry();
    let deadline = Instant::now() + Duration::from_secs(5);
    // Saturate maintenance download (2/4), native (1/2), view (1/2), and staging (2 MiB / 4 MiB).
    let md1 = registry.acquire_download(AdmissionClass::Maintenance, deadline).await.expect("maint dl 1");
    let md2 = registry.acquire_download(AdmissionClass::Maintenance, deadline).await.expect("maint dl 2");
    let mn1 = registry.acquire_native(AdmissionClass::Maintenance, deadline).await.expect("maint native 1");
    let mv1 = registry.acquire_view(AdmissionClass::Maintenance, deadline).await.expect("maint view 1");
    let ms1 =
        registry.reserve_staging(2 * 1024 * 1024, AdmissionClass::Maintenance, deadline).await.expect("maint staging");

    let short = Instant::now() + Duration::from_millis(20);
    assert!(
        registry.acquire_download(AdmissionClass::Maintenance, short).await.is_err(),
        "maint dl sub-cap enforces 2"
    );
    assert!(
        registry.acquire_native(AdmissionClass::Maintenance, short).await.is_err(),
        "maint native sub-cap enforces 1"
    );
    assert!(registry.acquire_view(AdmissionClass::Maintenance, short).await.is_err(), "maint view sub-cap enforces 1");
    assert!(
        registry.reserve_staging(64 * 1024, AdmissionClass::Maintenance, short).await.is_err(),
        "maint staging sub-cap enforces 50%"
    );

    // Every foreground lane must still be immediately available without waiting on maintenance.
    let fd = registry.acquire_download(AdmissionClass::Foreground, deadline).await.expect("fg download");
    let fn_slot = registry.acquire_native(AdmissionClass::Foreground, deadline).await.expect("fg native");
    let fv_slot = registry.acquire_view(AdmissionClass::Foreground, deadline).await.expect("fg view");
    let fs_res =
        registry.reserve_staging(2 * 1024 * 1024, AdmissionClass::Foreground, deadline).await.expect("fg staging");

    let snap = registry.snapshot();
    assert_eq!(snap.download_maintenance_permits_acquired, 2);
    assert_eq!(snap.native_maintenance_permits_acquired, 1);
    assert_eq!(snap.staging_reserved_bytes_current, 4 * 1024 * 1024);
    drop((fd, fn_slot, fv_slot, fs_res, md1, md2, mn1, mv1, ms1));
}

#[tokio::test]
async fn staging_shrink_reclaims_bytes_and_maint_timeout_does_not_leak_subcap() {
    let registry = Arc::new(bounded_registry());
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut fg =
        registry.reserve_staging(3 * 1024 * 1024, AdmissionClass::Foreground, deadline).await.expect("fg 3 MiB");
    let short = Instant::now() + Duration::from_millis(25);
    // Maintenance request takes its maintenance sub-cap briefly, then times out on global staging (only 1 MiB free).
    assert!(
        registry.reserve_staging(2 * 1024 * 1024, AdmissionClass::Maintenance, short).await.is_err(),
        "maintenance staging waits on global pool and fails closed at deadline"
    );

    // Shrink foreground reservation from 3 MiB down to 1 MiB.
    fg.shrink_to_bytes(1024 * 1024);
    assert_eq!(fg.reserved_bytes(), 1024 * 1024);
    let snap = registry.snapshot();
    assert_eq!(snap.staging_reserved_bytes_current, 1024 * 1024);
    assert_eq!(snap.staging_reclaimed_bytes_total, 2 * 1024 * 1024);

    // Maintenance must now succeed with its full 2 MiB sub-cap (proving no sub-cap leak on timeout above).
    let maint = registry
        .reserve_staging(2 * 1024 * 1024, AdmissionClass::Maintenance, Instant::now() + Duration::from_secs(2))
        .await
        .expect("maint staging must not have leaked its sub-cap on timeout");
    drop((fg, maint));
    assert_eq!(registry.snapshot().staging_reserved_bytes_current, 0);
}

#[test]
fn disk_headroom_check_refuses_underprovisioned_or_overflowing_requests() {
    assert!(ensure_available_disk_bytes(32 * 1024 * 1024, 1024 * 1024, VERIFIER_DISK_HEADROOM_BYTES).is_ok());
    assert!(
        ensure_available_disk_bytes(VERIFIER_DISK_HEADROOM_BYTES, 1024, VERIFIER_DISK_HEADROOM_BYTES).is_err(),
        "exact headroom without required bytes must be refused"
    );
    assert!(
        ensure_available_disk_bytes(u64::MAX, u64::MAX, 1).is_err(),
        "overflowing required + headroom must fail closed"
    );
}
