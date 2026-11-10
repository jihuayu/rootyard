//! One shared ownership cell for an **actual** owned Blob readback task.
//!
//! The owned transfer/range task creates the `Arc<TransferResources>` at task
//! entry, before any filesystem work starts. The drop guard, the staging object
//! and the deferred staging cleanup hold clones of that same `Arc`, so the read
//! lease (reader slot plus staging bytes) and the opaque external keepalive have
//! exactly one release point: the last clone. An unsettled guard `mem::forget`s
//! its clone, so a runtime abort never reports capacity that local filesystem
//! work may still be using, even when deferred unlink finishes first.

use std::sync::Arc;

use crate::blob_store::budget::ReadLease;

/// Opaque external keepalive. Nothing in `blob_store` can interpret it; it is
/// only ever moved and dropped.
pub(super) type Keepalive = Arc<dyn Send + Sync + 'static>;

/// The read lease plus optional external owner for exactly one owned transfer.
pub(super) struct TransferResources {
    read_lease: ReadLease,
    owner: Option<Keepalive>,
}

impl TransferResources {
    pub(super) fn new(read_lease: ReadLease, owner: Option<Keepalive>) -> Self {
        Self { read_lease, owner }
    }
}

impl Drop for TransferResources {
    fn drop(&mut self) {
        // Last shared clone: return the reader slot and staging bytes, and
        // release the external owner together.
        self.read_lease.release();
        drop(self.owner.take());
    }
}

/// Owned drop guard for the shared transfer resources inside the **actual**
/// transfer task.
///
/// It is settled exactly once, after the future ran to normal completion (Ok or
/// typed error) and the staging-cleanup hand-off happened. If the owned task is
/// dropped early — runtime abort or a panic while a local `tokio::fs` operation
/// may still be running — the guard deliberately `mem::forget`s its `Arc`: the
/// reader/staging capacity and the external owner stay retained until process
/// exit instead of being released against a directory that may still be used.
pub(super) struct TransferGuard {
    resources: Option<Arc<TransferResources>>,
    settled: bool,
}

impl TransferGuard {
    pub(super) fn new(resources: Arc<TransferResources>) -> Self {
        Self { resources: Some(resources), settled: false }
    }

    /// Normal completion: every local await has returned and the staging object
    /// either committed or handed its shared resources to deferred cleanup.
    pub(super) fn settle(&mut self) {
        self.settled = true;
        self.resources = None;
    }
}

impl Drop for TransferGuard {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Some(resources) = self.resources.take() {
            std::mem::forget(resources);
        }
    }
}

/// Test-only keyed completion signal emitted by the **actual** owned transfer
/// task after `TransferGuard::settle()`, immediately before it returns.
///
/// Gate B fires from inside the deferred unlink, which can happen before the
/// transfer future resumes and settles its guard. Waiting for this signal while
/// Gate B is held therefore proves the cleanup clone — not the guard — retains
/// the shared read lease and owner.
#[cfg(test)]
type CompletionSignals = std::sync::OnceLock<std::sync::Mutex<Vec<(std::path::PathBuf, Arc<tokio::sync::Semaphore>)>>>;

#[cfg(test)]
static TRANSFER_COMPLETIONS: CompletionSignals = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn install_transfer_completion(destination: std::path::PathBuf) -> Arc<tokio::sync::Semaphore> {
    let completed = Arc::new(tokio::sync::Semaphore::new(0));
    TRANSFER_COMPLETIONS
        .get_or_init(|| std::sync::Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push((destination, Arc::clone(&completed)));
    completed
}

#[cfg(test)]
pub(crate) fn clear_transfer_completion(destination: &std::path::Path) {
    if let Some(slot) = TRANSFER_COMPLETIONS.get() {
        slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).retain(|(path, _)| path != destination);
    }
}

/// Keyed by destination so parallel unit tests cannot signal each other.
#[cfg(test)]
pub(crate) fn signal_transfer_completed(destination: &std::path::Path) {
    let signal = TRANSFER_COMPLETIONS.get().and_then(|slot| {
        let slot = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        slot.iter().find(|(path, _)| path == destination).map(|(_, signal)| Arc::clone(signal))
    });
    if let Some(signal) = signal {
        signal.add_permits(1);
    }
}
