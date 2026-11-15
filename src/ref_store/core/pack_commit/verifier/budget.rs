//! Separated resource budgets, backpressure, maintenance sub-caps, and scratch
//! filesystem headroom checks for the native verifier.
//!
//! Four independent pools (`DOWNLOAD_SLOTS`, `STAGING_BYTES`, `VIEW_SLOTS`,
//! `VERIFIER_SLOTS`) are acquired in a strict DAG order:
//! `View -> Staging -> Download -> (release Download) -> Native`.
//! Maintenance callers acquire a <= 50% sub-cap permit before entering each
//! global pool, guaranteeing maintenance saturation cannot starve foreground.
pub(crate) use super::budget_metrics::VerifierMetricsSnapshot;
use super::budget_metrics::{GlobalCounters, SlotCounters, StagingCounters, build_snapshot};
use super::refuse;
use crate::ref_store::core::pack_commit::contract::{VERIFIER_MAX_CONCURRENT, VERIFIER_VIEW_MAX_CONCURRENT};
use crate::ref_store::core::pack_commit::error::PackCommitError;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Process-wide concurrent Blob download/readback ceiling (decoupled from native CPU slots).
pub(crate) const VERIFIER_DOWNLOAD_MAX_CONCURRENT: usize = 4;
/// Maximum Blob download slots reserved for maintenance callers (<= 50%).
pub(crate) const VERIFIER_DOWNLOAD_MAINTENANCE_MAX: usize = 2;
/// Maximum native Git CPU/process slots available to maintenance callers (<= 50%).
pub(crate) const VERIFIER_NATIVE_MAINTENANCE_MAX: usize = 1;
/// Maximum long-lived materialized-view slots available to maintenance callers (<= 50%).
pub(crate) const VERIFIER_VIEW_MAINTENANCE_MAX: usize = 1;
/// Granularity unit (64 KiB) for bounded staging byte reservations.
pub(crate) const VERIFIER_STAGING_UNIT_BYTES: u64 = 64 * 1024;
/// Process-wide temporary workspace / staging byte budget (384 MiB).
pub(crate) const VERIFIER_STAGING_MAX_BYTES: u64 = 384 * 1024 * 1024;
/// Maintenance sub-cap inside the staging byte budget (192 MiB, <= 50%).
pub(crate) const VERIFIER_STAGING_MAINTENANCE_MAX_BYTES: u64 = 192 * 1024 * 1024;
/// Bounded per-call pair download fan-out inside Phase 1 staging.
pub(crate) const VERIFIER_PAIR_PREFETCH_CONCURRENCY: usize = 2;
/// Minimum free scratch filesystem headroom required above a call's byte budget.
pub(crate) const VERIFIER_DISK_HEADROOM_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionClass {
    Foreground,
    Maintenance,
}

#[derive(Debug)]
struct SlotPool {
    global: Arc<Semaphore>,
    maintenance: Arc<Semaphore>,
    counters: Arc<SlotCounters>,
    timeout_reason: &'static str,
}

impl SlotPool {
    fn new(global_cap: usize, maintenance_cap: usize, timeout_reason: &'static str) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global_cap)),
            maintenance: Arc::new(Semaphore::new(maintenance_cap)),
            counters: Arc::new(SlotCounters::default()),
            timeout_reason,
        }
    }

    async fn acquire(
        &self,
        class: AdmissionClass,
        deadline: Instant,
        timeouts: &AtomicU64,
    ) -> Result<SlotPermit, PackCommitError> {
        let started = Instant::now();
        let maint = if class == AdmissionClass::Maintenance {
            Some(acquire_permits(&self.maintenance, 1, deadline, self.timeout_reason, timeouts).await?)
        } else {
            None
        };
        let global = acquire_permits(&self.global, 1, deadline, self.timeout_reason, timeouts).await?;
        let waited = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.counters.enter(class, waited);
        Ok(SlotPermit { _global: global, _maintenance: maint, counters: Arc::clone(&self.counters) })
    }
}

#[derive(Debug)]
struct SlotPermit {
    _global: OwnedSemaphorePermit,
    _maintenance: Option<OwnedSemaphorePermit>,
    counters: Arc<SlotCounters>,
}

impl Drop for SlotPermit {
    fn drop(&mut self) {
        self.counters.leave();
    }
}

#[derive(Debug)]
pub(crate) struct DownloadPermit {
    _permit: SlotPermit,
}
#[derive(Debug)]
pub(crate) struct ViewPermit {
    _permit: SlotPermit,
}
#[derive(Debug)]
pub(crate) struct NativePermit {
    _permit: SlotPermit,
}

#[cfg(test)]
impl NativePermit {
    pub(super) fn from_test_permit(permit: OwnedSemaphorePermit) -> Self {
        Self {
            _permit: SlotPermit { _global: permit, _maintenance: None, counters: Arc::new(SlotCounters::default()) },
        }
    }
}

#[derive(Debug)]
pub(crate) struct StagingReservation {
    global_sem: Arc<Semaphore>,
    maint_sem: Option<Arc<Semaphore>>,
    counters: Arc<StagingCounters>,
    unit_bytes: u64,
    units: u32,
    maint_units: u32,
}

impl StagingReservation {
    /// Shrink this reservation down to `keep_bytes`, immediately returning excess capacity.
    pub(crate) fn shrink_to_bytes(&mut self, keep_bytes: u64) {
        let target =
            if keep_bytes == 0 { 0 } else { u32::try_from(keep_bytes.div_ceil(self.unit_bytes)).unwrap_or(self.units) }
                .min(self.units);
        if target >= self.units {
            return;
        }
        let freed = self.units - target;
        self.units = target;
        self.global_sem.add_permits(usize::try_from(freed).unwrap_or(usize::MAX));
        if let Some(maint) = &self.maint_sem {
            let maint_target = target.min(self.maint_units);
            let freed_maint = self.maint_units - maint_target;
            if freed_maint > 0 {
                self.maint_units = maint_target;
                maint.add_permits(usize::try_from(freed_maint).unwrap_or(usize::MAX));
            }
        }
        let freed_bytes = u64::from(freed).saturating_mul(self.unit_bytes);
        self.counters.current_bytes.fetch_sub(freed_bytes, Ordering::Relaxed);
        self.counters.reclaimed_bytes.fetch_add(freed_bytes, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn reserved_bytes(&self) -> u64 {
        u64::from(self.units).saturating_mul(self.unit_bytes)
    }
}

impl Drop for StagingReservation {
    fn drop(&mut self) {
        if self.units > 0 {
            let remaining = u64::from(self.units).saturating_mul(self.unit_bytes);
            self.global_sem.add_permits(usize::try_from(self.units).unwrap_or(usize::MAX));
            self.counters.current_bytes.fetch_sub(remaining, Ordering::Relaxed);
            self.units = 0;
        }
        if let Some(maint) = &self.maint_sem
            && self.maint_units > 0
        {
            maint.add_permits(usize::try_from(self.maint_units).unwrap_or(usize::MAX));
            self.maint_units = 0;
        }
    }
}

#[derive(Debug)]
pub(crate) struct BudgetRegistry {
    download: SlotPool,
    native: SlotPool,
    view: SlotPool,
    staging_global: Arc<Semaphore>,
    staging_maint: Arc<Semaphore>,
    staging_unit_bytes: u64,
    staging_max_units: u32,
    staging_maint_max_units: u32,
    staging_counters: Arc<StagingCounters>,
    globals: GlobalCounters,
}

impl BudgetRegistry {
    pub(crate) fn new(
        download_cap: usize,
        download_maint_cap: usize,
        native_cap: usize,
        native_maint_cap: usize,
        view_cap: usize,
        view_maint_cap: usize,
        staging_max_bytes: u64,
        staging_maint_bytes: u64,
    ) -> Self {
        let unit = VERIFIER_STAGING_UNIT_BYTES;
        let max_units = u32::try_from(staging_max_bytes.div_ceil(unit)).unwrap_or(u32::MAX);
        let maint_units = u32::try_from(staging_maint_bytes.div_ceil(unit)).unwrap_or(u32::MAX).min(max_units);
        Self {
            download: SlotPool::new(download_cap, download_maint_cap, "no verifier download slot before the deadline"),
            native: SlotPool::new(native_cap, native_maint_cap, "no verifier concurrency slot before the deadline"),
            view: SlotPool::new(view_cap, view_maint_cap, "no materialized-view budget before the deadline"),
            staging_global: Arc::new(Semaphore::new(usize::try_from(max_units).unwrap_or(usize::MAX))),
            staging_maint: Arc::new(Semaphore::new(usize::try_from(maint_units).unwrap_or(usize::MAX))),
            staging_unit_bytes: unit,
            staging_max_units: max_units,
            staging_maint_max_units: maint_units,
            staging_counters: Arc::new(StagingCounters::default()),
            globals: GlobalCounters::default(),
        }
    }

    pub(crate) async fn acquire_download(
        &self,
        class: AdmissionClass,
        deadline: Instant,
    ) -> Result<DownloadPermit, PackCommitError> {
        Ok(DownloadPermit { _permit: self.download.acquire(class, deadline, &self.globals.budget_timeouts).await? })
    }

    pub(crate) async fn acquire_native(
        &self,
        class: AdmissionClass,
        deadline: Instant,
    ) -> Result<NativePermit, PackCommitError> {
        Ok(NativePermit { _permit: self.native.acquire(class, deadline, &self.globals.budget_timeouts).await? })
    }

    pub(crate) async fn acquire_view(
        &self,
        class: AdmissionClass,
        deadline: Instant,
    ) -> Result<ViewPermit, PackCommitError> {
        Ok(ViewPermit { _permit: self.view.acquire(class, deadline, &self.globals.budget_timeouts).await? })
    }

    pub(crate) async fn reserve_staging(
        &self,
        bytes: u64,
        class: AdmissionClass,
        deadline: Instant,
    ) -> Result<StagingReservation, PackCommitError> {
        if bytes == 0 {
            return Ok(self.empty_staging());
        }
        let units = u32::try_from(bytes.div_ceil(self.staging_unit_bytes))
            .map_err(|_| refuse("verifier staging budget request overflowed"))?;
        if units > self.staging_max_units
            || (class == AdmissionClass::Maintenance && units > self.staging_maint_max_units)
        {
            return Err(refuse("verifier staging requirement exceeds process budget"));
        }
        let maint_sem = if class == AdmissionClass::Maintenance {
            let permit = acquire_permits(
                &self.staging_maint,
                units,
                deadline,
                "no verifier maintenance staging budget before the deadline",
                &self.globals.budget_timeouts,
            )
            .await?;
            permit.forget();
            Some(Arc::clone(&self.staging_maint))
        } else {
            None
        };
        let mut maint_guard = maint_sem.as_ref().map(|sem| StagingReservation {
            global_sem: Arc::clone(sem),
            maint_sem: None,
            counters: Arc::clone(&self.staging_counters),
            unit_bytes: 0,
            units,
            maint_units: 0,
        });
        let global_permit = acquire_permits(
            &self.staging_global,
            units,
            deadline,
            "no verifier staging byte budget before the deadline",
            &self.globals.budget_timeouts,
        )
        .await?;
        global_permit.forget();
        if let Some(guard) = maint_guard.as_mut() {
            guard.units = 0;
        }
        let reserved_bytes = u64::from(units).saturating_mul(self.staging_unit_bytes);
        self.staging_counters.add_reserved(reserved_bytes);
        Ok(StagingReservation {
            global_sem: Arc::clone(&self.staging_global),
            maint_sem,
            counters: Arc::clone(&self.staging_counters),
            unit_bytes: self.staging_unit_bytes,
            units,
            maint_units: if class == AdmissionClass::Maintenance { units } else { 0 },
        })
    }

    pub(crate) fn empty_staging(&self) -> StagingReservation {
        StagingReservation {
            global_sem: Arc::clone(&self.staging_global),
            maint_sem: None,
            counters: Arc::clone(&self.staging_counters),
            unit_bytes: self.staging_unit_bytes,
            units: 0,
            maint_units: 0,
        }
    }

    pub(crate) fn record_blob_get(&self, bytes: u64) {
        self.globals.blob_get_requests.fetch_add(1, Ordering::Relaxed);
        self.globals.blob_get_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn record_readback(&self, bytes: u64) {
        self.globals.readback_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn record_handoff_reflink(&self) {
        self.globals.handoff_reflink_files.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_handoff_stream(&self, bytes: u64) {
        self.globals.handoff_stream_files.fetch_add(1, Ordering::Relaxed);
        self.globals.handoff_stream_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn record_handoff_fallback(&self) {
        self.globals.handoff_fallback_count.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_disk_headroom_refusal(&self) {
        self.globals.disk_headroom_refusals.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> VerifierMetricsSnapshot {
        build_snapshot(
            &self.download.counters,
            &self.native.counters,
            &self.view.counters,
            &self.staging_counters,
            &self.globals,
        )
    }
}

static GLOBAL_BUDGETS: OnceLock<BudgetRegistry> = OnceLock::new();

pub(crate) fn budgets() -> &'static BudgetRegistry {
    GLOBAL_BUDGETS.get_or_init(|| {
        BudgetRegistry::new(
            VERIFIER_DOWNLOAD_MAX_CONCURRENT,
            VERIFIER_DOWNLOAD_MAINTENANCE_MAX,
            VERIFIER_MAX_CONCURRENT,
            VERIFIER_NATIVE_MAINTENANCE_MAX,
            VERIFIER_VIEW_MAX_CONCURRENT,
            VERIFIER_VIEW_MAINTENANCE_MAX,
            VERIFIER_STAGING_MAX_BYTES,
            VERIFIER_STAGING_MAINTENANCE_MAX_BYTES,
        )
    })
}

pub(crate) fn metrics_snapshot() -> VerifierMetricsSnapshot {
    budgets().snapshot()
}

pub(crate) fn check_disk_headroom(path: &Path, required_bytes: u64) -> Result<(), PackCommitError> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| refuse("scratch root path contains an interior NUL byte"))?;
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
        if unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) } != 0 {
            budgets().record_disk_headroom_refusal();
            return Err(refuse("could not query scratch filesystem free space"));
        }
        let stat = unsafe { stat.assume_init() };
        let block: u64 = if stat.f_frsize > 0 { stat.f_frsize } else { stat.f_bsize };
        let available = stat.f_bavail.saturating_mul(block);
        if let Err(err) = ensure_available_disk_bytes(available, required_bytes, VERIFIER_DISK_HEADROOM_BYTES) {
            budgets().record_disk_headroom_refusal();
            return Err(err);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, required_bytes);
    }
    Ok(())
}

pub(crate) fn ensure_available_disk_bytes(
    available_bytes: u64,
    required_bytes: u64,
    headroom_bytes: u64,
) -> Result<(), PackCommitError> {
    let minimum = required_bytes
        .checked_add(headroom_bytes)
        .ok_or_else(|| refuse("required scratch disk headroom overflowed"))?;
    if available_bytes < minimum {
        return Err(refuse("insufficient scratch filesystem headroom for pack verification"));
    }
    Ok(())
}

async fn acquire_permits(
    semaphore: &Arc<Semaphore>,
    units: u32,
    deadline: Instant,
    reason: &'static str,
    timeouts: &AtomicU64,
) -> Result<OwnedSemaphorePermit, PackCommitError> {
    match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        Arc::clone(semaphore).acquire_many_owned(units),
    )
    .await
    {
        Ok(Ok(permit)) => Ok(permit),
        _ => {
            timeouts.fetch_add(1, Ordering::Relaxed);
            Err(refuse(reason))
        }
    }
}
