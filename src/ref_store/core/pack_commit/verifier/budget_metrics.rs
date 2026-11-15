//! Atomic telemetry counters and snapshot model for the native verifier's
//! separated download, staging, view, and native Git budgets.
use super::budget::AdmissionClass;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifierMetricsSnapshot {
    pub(crate) download_permits_acquired: u64,
    pub(crate) download_queue_wait_micros: u64,
    pub(crate) download_in_flight: u64,
    pub(crate) download_in_flight_peak: u64,
    pub(crate) download_maintenance_permits_acquired: u64,
    pub(crate) native_permits_acquired: u64,
    pub(crate) native_queue_wait_micros: u64,
    pub(crate) native_in_flight: u64,
    pub(crate) native_in_flight_peak: u64,
    pub(crate) native_maintenance_permits_acquired: u64,
    pub(crate) view_permits_acquired: u64,
    pub(crate) view_queue_wait_micros: u64,
    pub(crate) view_in_flight: u64,
    pub(crate) view_in_flight_peak: u64,
    pub(crate) staging_reserved_bytes_current: u64,
    pub(crate) staging_reserved_bytes_peak: u64,
    pub(crate) staging_reclaimed_bytes_total: u64,
    pub(crate) blob_get_requests: u64,
    pub(crate) blob_get_bytes: u64,
    pub(crate) readback_bytes: u64,
    pub(crate) handoff_reflink_files: u64,
    pub(crate) handoff_stream_files: u64,
    pub(crate) handoff_stream_bytes: u64,
    pub(crate) handoff_fallback_count: u64,
    pub(crate) disk_headroom_refusals: u64,
    pub(crate) budget_timeouts: u64,
}

#[derive(Debug, Default)]
pub(super) struct SlotCounters {
    pub(super) acquired: AtomicU64,
    pub(super) maintenance_acquired: AtomicU64,
    pub(super) wait_micros: AtomicU64,
    pub(super) in_flight: AtomicU64,
    pub(super) in_flight_peak: AtomicU64,
}

impl SlotCounters {
    pub(super) fn enter(&self, class: AdmissionClass, wait_micros: u64) {
        self.acquired.fetch_add(1, Ordering::Relaxed);
        if class == AdmissionClass::Maintenance {
            self.maintenance_acquired.fetch_add(1, Ordering::Relaxed);
        }
        self.wait_micros.fetch_add(wait_micros, Ordering::Relaxed);
        let active = self.in_flight.fetch_add(1, Ordering::Relaxed) + 1;
        update_max(&self.in_flight_peak, active);
    }

    pub(super) fn leave(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
pub(super) struct StagingCounters {
    pub(super) current_bytes: AtomicU64,
    pub(super) peak_bytes: AtomicU64,
    pub(super) reclaimed_bytes: AtomicU64,
}

impl StagingCounters {
    pub(super) fn add_reserved(&self, bytes: u64) {
        let active = self.current_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        update_max(&self.peak_bytes, active);
    }
}

#[derive(Debug, Default)]
pub(super) struct GlobalCounters {
    pub(super) blob_get_requests: AtomicU64,
    pub(super) blob_get_bytes: AtomicU64,
    pub(super) readback_bytes: AtomicU64,
    pub(super) handoff_reflink_files: AtomicU64,
    pub(super) handoff_stream_files: AtomicU64,
    pub(super) handoff_stream_bytes: AtomicU64,
    pub(super) handoff_fallback_count: AtomicU64,
    pub(super) disk_headroom_refusals: AtomicU64,
    pub(super) budget_timeouts: AtomicU64,
}

pub(super) fn build_snapshot(
    download: &SlotCounters,
    native: &SlotCounters,
    view: &SlotCounters,
    staging: &StagingCounters,
    globals: &GlobalCounters,
) -> VerifierMetricsSnapshot {
    VerifierMetricsSnapshot {
        download_permits_acquired: download.acquired.load(Ordering::Relaxed),
        download_queue_wait_micros: download.wait_micros.load(Ordering::Relaxed),
        download_in_flight: download.in_flight.load(Ordering::Relaxed),
        download_in_flight_peak: download.in_flight_peak.load(Ordering::Relaxed),
        download_maintenance_permits_acquired: download.maintenance_acquired.load(Ordering::Relaxed),
        native_permits_acquired: native.acquired.load(Ordering::Relaxed),
        native_queue_wait_micros: native.wait_micros.load(Ordering::Relaxed),
        native_in_flight: native.in_flight.load(Ordering::Relaxed),
        native_in_flight_peak: native.in_flight_peak.load(Ordering::Relaxed),
        native_maintenance_permits_acquired: native.maintenance_acquired.load(Ordering::Relaxed),
        view_permits_acquired: view.acquired.load(Ordering::Relaxed),
        view_queue_wait_micros: view.wait_micros.load(Ordering::Relaxed),
        view_in_flight: view.in_flight.load(Ordering::Relaxed),
        view_in_flight_peak: view.in_flight_peak.load(Ordering::Relaxed),
        staging_reserved_bytes_current: staging.current_bytes.load(Ordering::Relaxed),
        staging_reserved_bytes_peak: staging.peak_bytes.load(Ordering::Relaxed),
        staging_reclaimed_bytes_total: staging.reclaimed_bytes.load(Ordering::Relaxed),
        blob_get_requests: globals.blob_get_requests.load(Ordering::Relaxed),
        blob_get_bytes: globals.blob_get_bytes.load(Ordering::Relaxed),
        readback_bytes: globals.readback_bytes.load(Ordering::Relaxed),
        handoff_reflink_files: globals.handoff_reflink_files.load(Ordering::Relaxed),
        handoff_stream_files: globals.handoff_stream_files.load(Ordering::Relaxed),
        handoff_stream_bytes: globals.handoff_stream_bytes.load(Ordering::Relaxed),
        handoff_fallback_count: globals.handoff_fallback_count.load(Ordering::Relaxed),
        disk_headroom_refusals: globals.disk_headroom_refusals.load(Ordering::Relaxed),
        budget_timeouts: globals.budget_timeouts.load(Ordering::Relaxed),
    }
}

fn update_max(slot: &AtomicU64, candidate: u64) {
    let mut observed = slot.load(Ordering::Relaxed);
    while candidate > observed {
        match slot.compare_exchange_weak(observed, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => observed = actual,
        }
    }
}
