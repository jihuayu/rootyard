//! Owned OpenDAL writer with bounded abort attempts.
//!
//! OpenDAL 0.57 has an explicit async `Writer::abort` and no abort-on-drop.
//! Every write/close/verification/deadline error attempts an explicitly awaited
//! abort with an independent cleanup budget. Dropping the guard (future
//! cancellation) schedules at most one bounded best-effort abort on the current
//! Tokio handle; it never blocks the runtime and never spawns unbounded tasks.
//! Abort after a process kill is not guaranteed, so orphan bytes may remain and
//! no receipt is ever issued for an unknown completion.

use std::time::Duration;

use opendal::Writer;
use tokio::time::{Instant, timeout, timeout_at};

use super::{BlobError, opendal::map_provider_error};

pub(crate) struct UploadGuard {
    writer: Option<Writer>,
    abort_timeout: Duration,
}

impl UploadGuard {
    pub(crate) fn new(writer: Writer, abort_timeout: Duration) -> Self {
        Self { writer: Some(writer), abort_timeout }
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
                if let Some(writer) = self.writer.take() {
                    schedule_abort(writer, self.abort_timeout);
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
    }

    /// Successful close already completed; drop must not abort.
    pub(crate) fn disarm(mut self) {
        self.writer = None;
    }
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        if let Some(writer) = self.writer.take() {
            schedule_abort(writer, self.abort_timeout);
        }
    }
}

/// Best-effort, bounded abort on cancellation. No-op outside a Tokio runtime.
fn schedule_abort(mut writer: Writer, budget: Duration) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let _ = timeout(budget, writer.abort()).await;
    });
}
