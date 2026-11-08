//! Owned OpenDAL writer with bounded abort attempts.
//!
//! OpenDAL 0.57 has an explicit async `Writer::abort` and no abort-on-drop.
//! Every write/close/verification/deadline error attempts an explicitly awaited
//! abort with an independent cleanup budget. Dropping the guard (future
//! cancellation) schedules at most one bounded best-effort abort on the current
//! Tokio handle; it never blocks the runtime and never spawns unbounded tasks.
//! Abort after a process kill is not guaranteed, so orphan bytes may remain and
//! no receipt is ever issued for an unknown completion.
//!
//! New-profile uploads carry an optional [`UploadLease`]. The process-wide
//! upload slot stays owned by the guard until the writer is really gone: a
//! cancelled operation hands both the writer and the lease to the bounded abort
//! task, so a background abort never presents itself as released capacity.

use std::time::Duration;

use opendal::Writer;
use tokio::time::{Instant, timeout, timeout_at};

use super::{BlobError, budget::UploadLease, opendal::map_provider_error};

pub(crate) struct UploadGuard {
    writer: Option<Writer>,
    abort_timeout: Duration,
    /// `None` for the legacy adapter, which is not part of the process budget.
    lease: Option<UploadLease>,
}

impl UploadGuard {
    /// Legacy constructor: unchanged behaviour, no process-wide slot.
    pub(crate) fn new(writer: Writer, abort_timeout: Duration) -> Self {
        Self { writer: Some(writer), abort_timeout, lease: None }
    }

    /// New BlobStore constructor: the upload slot is owned until close/abort is
    /// finished and dropped with the guard.
    pub(crate) fn new_with_lease(writer: Writer, abort_timeout: Duration, lease: UploadLease) -> Self {
        Self { writer: Some(writer), abort_timeout, lease: Some(lease) }
    }

    pub(crate) fn writer(&mut self) -> &mut Writer {
        self.writer.as_mut().expect("upload guard exposes its writer until it is closed")
    }

    /// Close and disarm on success. Any close error or timeout attempts abort.
    pub(crate) async fn close(&mut self, deadline: Instant) -> Result<(), BlobError> {
        let Some(writer) = self.writer.as_mut() else {
            return Err(BlobError::Provider("upload writer was already closed".into()));
        };
        match timeout_at(deadline, writer.close()).await {
            Ok(Ok(_metadata)) => {
                self.writer.take();
                Ok(())
            }
            Ok(Err(error)) => {
                // Keep ownership in this guard while awaiting abort: cancelling
                // close must still let Drop schedule cleanup of the same writer.
                if let Some(writer) = self.writer.as_mut() {
                    let _ = timeout(self.abort_timeout, writer.abort()).await;
                }
                self.writer.take();
                Err(map_provider_error(error))
            }
            Err(_) => {
                let lease = self.lease.take();
                if let Some(writer) = self.writer.take() {
                    schedule_abort(writer, self.abort_timeout, lease);
                }
                Err(BlobError::DeadlineExceeded)
            }
        }
    }

    /// Explicitly awaited abort on an observed error. Consumes the guard.
    pub(crate) async fn abort_now(mut self) {
        if let Some(writer) = self.writer.as_mut() {
            let _ = timeout(self.abort_timeout, writer.abort()).await;
        }
        self.writer.take();
        self.lease = None;
    }

    /// Successful close already completed; drop must not abort and hands the
    /// upload slot back to the process.
    pub(crate) fn disarm(mut self) {
        self.writer = None;
        self.lease = None;
    }
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            let lease = self.lease.take();
            schedule_abort(writer, self.abort_timeout, lease);
        }
    }
}

/// Best-effort, bounded abort on cancellation. No-op outside a Tokio runtime.
/// The upload slot (`lease`) is dropped only after the abort future finished, so
/// a still-owned writer is never counted as free capacity.
fn schedule_abort(mut writer: Writer, budget: Duration, lease: Option<UploadLease>) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let _ = timeout(budget, writer.abort()).await;
        drop(lease);
    });
}
