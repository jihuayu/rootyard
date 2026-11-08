//! Process-wide resource accounting for the standalone Blob profile.
//!
//! Every new [`super::opendal::BlobStore`] in one process shares a single
//! [`ResourceContext`]: upload slots, verified-reader slots and weighted staging
//! bytes are process-wide budgets, never a fresh semaphore per operator or per
//! call. The context is created from explicit [`ResourceLimits`]; a later profile
//! that asks for different limits is rejected with [`BlobError::CapacityConflict`]
//! instead of silently inheriting the first one.
//!
//! Scope, stated honestly: these permits bound *concurrent Blob operations and
//! staging bytes this process has leased*. They are not an RSS, CPU, socket or
//! page-cache estimate, and SDK/HTTP buffers plus provider-side transfer sizes
//! are outside the accounting. The legacy `RemoteObjectStore` adapter is a
//! separate path with its own (unaccounted) behaviour; this is not an
//! application-wide quota system.
//!
//! Leases are owned values. A cancelled, failed or timed-out operation keeps its
//! slot and its staging bytes charged until the owner is actually dropped, so
//! cleanup that is still running can never present itself as freed capacity.

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant as TokioInstant, timeout_at},
};

use super::BlobError;

/// Staging bytes are leased in 64 KiB units so weighted accounting stays exact.
pub const LEASE_UNIT_BYTES: u64 = 64 * 1024;
pub const DEFAULT_ACTIVE_UPLOADS: usize = 2;
pub const DEFAULT_ACTIVE_READERS: usize = 4;
/// Weighted staging budget shared by every verified download of this process.
pub const DEFAULT_STAGING_BYTES: u64 = 256 * 1024 * 1024;
/// Hard upper bound; operators may raise the 256 MiB default only up to this.
pub const MAX_STAGING_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const MAX_ACTIVE_SLOTS: usize = 32;

/// Explicit, bounded capacity for one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    active_uploads: usize,
    active_readers: usize,
    staging_bytes: u64,
}

impl ResourceLimits {
    pub fn new(active_uploads: usize, active_readers: usize, staging_bytes: u64) -> Result<Self, BlobError> {
        if !(1..=MAX_ACTIVE_SLOTS).contains(&active_uploads) || !(1..=MAX_ACTIVE_SLOTS).contains(&active_readers) {
            return Err(BlobError::Config(format!("blob active slot limits must be 1..={MAX_ACTIVE_SLOTS}")));
        }
        if !(LEASE_UNIT_BYTES..=MAX_STAGING_BYTES).contains(&staging_bytes) {
            return Err(BlobError::Config(format!(
                "blob staging budget must be {LEASE_UNIT_BYTES}..={MAX_STAGING_BYTES} bytes"
            )));
        }
        Ok(Self { active_uploads, active_readers, staging_bytes })
    }

    pub fn active_uploads(&self) -> usize {
        self.active_uploads
    }
    pub fn active_readers(&self) -> usize {
        self.active_readers
    }
    pub fn staging_bytes(&self) -> u64 {
        self.staging_bytes
    }
    /// Whole 64 KiB units; a non-multiple budget rounds down (conservative).
    fn staging_units(&self) -> u32 {
        (self.staging_bytes / LEASE_UNIT_BYTES) as u32
    }
}

/// One process-wide budget. Cheap to clone the handle, never the semaphores.
pub struct ResourceContext {
    limits: ResourceLimits,
    upload_slots: Arc<Semaphore>,
    reader_slots: Arc<Semaphore>,
    staging_units: Arc<Semaphore>,
}

impl ResourceContext {
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            upload_slots: Arc::new(Semaphore::new(limits.active_uploads)),
            reader_slots: Arc::new(Semaphore::new(limits.active_readers)),
            staging_units: Arc::new(Semaphore::new(limits.staging_units() as usize)),
        }
    }

    pub fn limits(&self) -> ResourceLimits {
        self.limits
    }

    /// Sampling helper for tests and diagnostics; never a reservation.
    pub fn available_uploads(&self) -> usize {
        self.upload_slots.available_permits()
    }
    pub fn available_readers(&self) -> usize {
        self.reader_slots.available_permits()
    }
    pub fn available_staging_bytes(&self) -> u64 {
        self.staging_units.available_permits() as u64 * LEASE_UNIT_BYTES
    }

    /// One upload-wide slot. Held by the owning writer guard until close, abort
    /// or cancellation cleanup has actually finished.
    pub async fn acquire_upload(&self, deadline: Instant) -> Result<UploadLease, BlobError> {
        let permit = take(&self.upload_slots, 1, deadline).await?;
        Ok(UploadLease { permit: Some(permit), _private: () })
    }

    /// One verified-reader slot plus the weighted staging bytes for the full
    /// download this reader will stage (zero bytes for a stream-only verify).
    pub async fn acquire_read(&self, staging_bytes: u64, deadline: Instant) -> Result<ReadLease, BlobError> {
        let total = self.limits.staging_bytes;
        if staging_bytes > total {
            return Err(BlobError::StagingBudgetExceeded { requested: staging_bytes, limit: total });
        }
        let reader = take(&self.reader_slots, 1, deadline).await?;
        let units = staging_bytes.div_ceil(LEASE_UNIT_BYTES) as u32;
        let staging = if units == 0 {
            None
        } else {
            Some(take(&self.staging_units, units, deadline).await?)
        };
        Ok(ReadLease {
            reader: ReaderLease { permit: Some(reader), _private: () },
            staging: StagingLease { permit: staging, bytes: staging_bytes },
        })
    }
}

/// Owned upload slot; releasing it is dropping it.
pub struct UploadLease {
    permit: Option<OwnedSemaphorePermit>,
    _private: (),
}

impl UploadLease {
    /// Give the slot back exactly once, e.g. before the post-close read-back.
    pub fn release(&mut self) {
        self.permit.take();
    }
}

/// Owned verified-reader slot.
pub struct ReaderLease {
    permit: Option<OwnedSemaphorePermit>,
    _private: (),
}

impl ReaderLease {
    pub fn release(&mut self) {
        self.permit.take();
    }
}

/// Weighted staging-byte lease: `bytes` (in 64 KiB units) held until dropped.
pub struct StagingLease {
    permit: Option<OwnedSemaphorePermit>,
    bytes: u64,
}

impl StagingLease {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn release(&mut self) {
        self.permit.take();
    }
}

/// A verified read in progress: the reader slot and its staging bytes together,
/// so neither can be released before the other's owner is finished.
pub struct ReadLease {
    reader: ReaderLease,
    staging: StagingLease,
}

impl ReadLease {
    pub fn staging_bytes(&self) -> u64 {
        self.staging.bytes()
    }
    pub fn release(&mut self) {
        self.staging.release();
        self.reader.release();
    }
}

async fn take(slots: &Arc<Semaphore>, units: u32, deadline: Instant) -> Result<OwnedSemaphorePermit, BlobError> {
    let wait = slots.clone().acquire_many_owned(units);
    match timeout_at(TokioInstant::from_std(deadline), wait).await {
        Ok(Ok(permit)) => Ok(permit),
        // Cancelling the `acquire_many_owned` future removes this waiter from the
        // queue and grants it nothing, so a timed-out waiter never leaks a unit.
        Ok(Err(_closed)) => Err(BlobError::Provider("blob resource context was closed".into())),
        Err(_) => Err(BlobError::DeadlineExceeded),
    }
}

/// One registration cell. Production has a single process-wide instance; tests
/// can build private instances to exercise sharing/conflict rules without
/// mutating global state or racing another test.
pub(crate) struct ResourceRegistry {
    slot: Mutex<Option<Arc<ResourceContext>>>,
}

impl ResourceRegistry {
    pub(crate) fn new() -> Self {
        Self { slot: Mutex::new(None) }
    }

    /// Register, or reuse, the context for `limits`.
    ///
    /// The first successful call wins only when later callers agree with it; a
    /// differing limit set is refused (`CapacityConflict`) so two profiles can
    /// never believe they own different capacities over the same semaphores.
    pub(crate) fn context(&self, limits: ResourceLimits) -> Result<Arc<ResourceContext>, BlobError> {
        let mut slot = self.slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match slot.as_ref() {
            Some(existing) if existing.limits() == limits => Ok(Arc::clone(existing)),
            Some(_) => Err(BlobError::CapacityConflict),
            None => {
                let context = Arc::new(ResourceContext::new(limits));
                *slot = Some(Arc::clone(&context));
                Ok(context)
            }
        }
    }
}

static PROCESS_REGISTRY: OnceLock<ResourceRegistry> = OnceLock::new();

fn process_registry() -> &'static ResourceRegistry {
    PROCESS_REGISTRY.get_or_init(ResourceRegistry::new)
}

/// Register, or reuse, the single process-wide context for `limits`.
pub fn process_resources(limits: ResourceLimits) -> Result<Arc<ResourceContext>, BlobError> {
    process_registry().context(limits)
}
