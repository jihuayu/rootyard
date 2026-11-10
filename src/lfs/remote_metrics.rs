//! Process-local Prometheus-facing counters/gauge for LFS remote health (issue #71).
//!
//! This module records only fixed-cardinality aggregate values:
//!
//! - `remote_failures_total`: monotonically non-decreasing counter of failed
//!   LFS remote operations.
//! - `repair_backlog`: gauge of admitted / in-flight deferred repair tasks, i.e.
//!   repair tasks that currently hold a guard (concurrency permit).
//!
//! No labels, identifiers, OIDs, URLs, error text, or secrets are ever stored.
//! The module depends only on the standard library and is safe (`forbid(unsafe_code)`).

// State only. The private loopback Prometheus endpoint is wired up elsewhere;
// nothing here may attach labels, identifiers, OIDs, URLs, error text, or
// secrets to the recorded values.

// Section: imports

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

// Section: public snapshot

/// Point-in-time, label-free view of the LFS remote metrics.
///
/// `remote_failures_total` is cumulative for the process lifetime;
/// `repair_backlog` is the current number of live repair guards.
pub(crate) struct Snapshot {
    pub remote_failures_total: u64,
    pub repair_backlog: u64,
}

// Section: metrics handle

/// Process-local metric state.
///
/// All mutations use saturating atomic operations so that no value can wrap
/// around (counter) or underflow (gauge).
pub(crate) struct RemoteMetrics {
    remote_failures_total: AtomicU64,
    repair_backlog: AtomicU64,
}

impl Default for RemoteMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Saturating increment of a relaxed counter: `u64::MAX` stays `u64::MAX`.
fn saturating_increment(counter: &AtomicU64) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(1) else {
            return;
        };
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

/// Saturating decrement of a relaxed gauge: `0` stays `0` rather than wrapping.
fn saturating_decrement(counter: &AtomicU64) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_sub(1) else {
            return;
        };
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

impl RemoteMetrics {
    /// Creates a zeroed metrics value. Prefer [`counters`] in production code;
    /// this constructor exists for isolated use and tests.
    pub(crate) const fn new() -> Self {
        Self { remote_failures_total: AtomicU64::new(0), repair_backlog: AtomicU64::new(0) }
    }

    /// Records one failed LFS remote operation.
    ///
    /// Uses a saturating increment, so the counter never wraps.
    pub(crate) fn record_remote_failure(&self) {
        // Saturating: an eventual u64::MAX stays at u64::MAX rather than wrapping.
        saturating_increment(&self.remote_failures_total);
    }

    /// Reads a consistent-enough snapshot of both values.
    ///
    /// Relaxed ordering is sufficient: each value is independently meaningful
    /// and writers are unprotected by a common lock.
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            remote_failures_total: self.remote_failures_total.load(Ordering::Relaxed),
            repair_backlog: self.repair_backlog.load(Ordering::Relaxed),
        }
    }

    /// Admits one repair task: increments the backlog gauge and returns an RAII
    /// guard that decrements it exactly once when dropped (normal return, early
    /// return, or unwinding).
    ///
    /// The gauge increment is saturating; the matching decrement never
    /// underflows. Call this only after an LFS concurrency permit has been
    /// acquired (see `MAX_CONCURRENT_REPAIRS` in `hydration`), so the gauge is
    /// bounded by the number of permits.
    pub(crate) fn begin_repair(&self) -> RepairGuard<'_> {
        // Saturating increment: never wrap the backlog gauge.
        saturating_increment(&self.repair_backlog);
        RepairGuard { metrics: self }
    }

    /// Decrements the backlog gauge without underflow. Called only by
    /// [`RepairGuard::drop`].
    fn end_repair(&self) {
        // Saturating decrement: a stray extra release cannot wrap to u64::MAX.
        saturating_decrement(&self.repair_backlog);
    }
}

// Section: RAII repair guard

/// Scope guard for one admitted (in-flight) repair task.
///
/// Created by [`RemoteMetrics::begin_repair`]; dropping it releases the backlog
/// slot even on early return or panic unwinding. The guard is intentionally not
/// `Copy`/`Clone` so releases are exactly once.
pub(crate) struct RepairGuard<'a> {
    metrics: &'a RemoteMetrics,
}

impl std::fmt::Debug for RepairGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omits any handle identity or metric values.
        f.write_str("RepairGuard")
    }
}

impl Drop for RepairGuard<'_> {
    fn drop(&mut self) {
        self.metrics.end_repair();
    }
}

// Section: process-wide instance

/// Process-wide metrics instance, initialized lazily on first access.
static COUNTERS: LazyLock<RemoteMetrics> = LazyLock::new(RemoteMetrics::new);

/// Returns the process-wide metrics handle used by the LFS remote path.
pub(crate) fn counters() -> &'static RemoteMetrics {
    &COUNTERS
}

// Section: tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_failures_are_monotonic() {
        let metrics = RemoteMetrics::new();
        assert_eq!(metrics.snapshot().remote_failures_total, 0);

        metrics.record_remote_failure();
        assert_eq!(metrics.snapshot().remote_failures_total, 1);

        metrics.record_remote_failure();
        metrics.record_remote_failure();
        assert_eq!(metrics.snapshot().remote_failures_total, 3);

        // Further failures never decrease the counter.
        let before = metrics.snapshot().remote_failures_total;
        metrics.record_remote_failure();
        assert!(metrics.snapshot().remote_failures_total > before);
    }

    #[test]
    fn failure_counter_saturates_at_max() {
        let metrics = RemoteMetrics::new();
        metrics.remote_failures_total.store(u64::MAX - 1, Ordering::Relaxed);

        metrics.record_remote_failure();
        metrics.record_remote_failure();
        metrics.record_remote_failure();
        assert_eq!(metrics.snapshot().remote_failures_total, u64::MAX);
    }

    #[test]
    fn backlog_tracks_live_guards() {
        let metrics = RemoteMetrics::new();
        assert_eq!(metrics.snapshot().repair_backlog, 0);
        assert_eq!(metrics.snapshot().remote_failures_total, 0);

        let first = metrics.begin_repair();
        assert_eq!(metrics.snapshot().repair_backlog, 1);

        let second = metrics.begin_repair();
        assert_eq!(metrics.snapshot().repair_backlog, 2);

        // Guards holding a borrow do not disturb the failure counter.
        assert_eq!(metrics.snapshot().remote_failures_total, 0);

        drop(first);
        assert_eq!(metrics.snapshot().repair_backlog, 1);

        drop(second);
        assert_eq!(metrics.snapshot().repair_backlog, 0);

        // Re-admission after full drain still works.
        let third = metrics.begin_repair();
        assert_eq!(metrics.snapshot().repair_backlog, 1);
        drop(third);
        assert_eq!(metrics.snapshot().repair_backlog, 0);
    }

    #[test]
    fn backlog_decrements_on_drop_without_underflow() {
        let metrics = RemoteMetrics::new();

        {
            let _guard = metrics.begin_repair();
            assert_eq!(metrics.snapshot().repair_backlog, 1);
        }
        assert_eq!(metrics.snapshot().repair_backlog, 0);

        // A stray release (simulating an extra cleanup) cannot underflow.
        metrics.end_repair();
        assert_eq!(metrics.snapshot().repair_backlog, 0);
    }

    #[test]
    fn backlog_is_released_on_panic_unwind() {
        let metrics = RemoteMetrics::new();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = metrics.begin_repair();
            assert_eq!(metrics.snapshot().repair_backlog, 1);
            panic!("simulated repair failure");
        }));
        assert!(outcome.is_err());
        // Guard dropped during unwinding: backlog fully released, no underflow.
        assert_eq!(metrics.snapshot().repair_backlog, 0);
    }

    #[test]
    fn process_wide_counters_are_shared() {
        let a: *const RemoteMetrics = counters();
        let b: *const RemoteMetrics = counters();
        assert!(std::ptr::eq(a, b));

        // Small bounded check that the shared instance is usable through the
        // public API; values are not asserted absolutely because other tests
        // (or the application) may share this process-wide instance.
        let _guard = counters().begin_repair();
        assert!(counters().snapshot().repair_backlog >= 1);
    }
}
