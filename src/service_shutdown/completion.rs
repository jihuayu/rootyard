//! Service terminal result and pending-owner retention.
use anyhow::{anyhow, bail};
use rootyard::workspaces::mounts::{StartupJoinError, StartupReconcile};
use std::time::Duration;
use tokio::time::Instant;

/// A cooperative startup stop before another row was admitted. This is not an
/// application failure; the service uses it to distinguish a signal-driven
/// stop from a real setup error.
#[derive(Debug)]
struct StartupStopped;

impl std::fmt::Display for StartupStopped {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("workspace startup reconcile stopped before admitting another row")
    }
}

impl std::error::Error for StartupStopped {}

pub(crate) fn startup_stopped() -> anyhow::Error {
    anyhow::Error::new(StartupStopped)
}

pub(crate) fn is_startup_stopped(error: &anyhow::Error) -> bool {
    error.is::<StartupStopped>()
}

pub(crate) fn startup_join_error_text(error: StartupJoinError) -> &'static str {
    match error {
        StartupJoinError::Panicked => "startup producer panicked",
        StartupJoinError::Cancelled => "startup producer was cancelled",
        StartupJoinError::Deadline => "startup producer remained pending at the deadline",
        StartupJoinError::AlreadyJoined => "startup producer was already joined",
    }
}

pub(crate) fn startup_join_failure(error: StartupJoinError) -> anyhow::Error {
    anyhow!("workspace startup reconcile join failed: {}", startup_join_error_text(error))
}

pub(crate) enum PendingStartup {
    Owned(StartupReconcile),
    #[cfg(test)]
    Test,
}

/// Result of one service run. The primary error and cleanup failures stay
/// separate: cleanup can never overwrite or relabel the original failure.
pub(crate) struct ServiceCompletion {
    primary: Option<anyhow::Error>,
    pub(super) cleanup_failures: Vec<String>,
    deadline: std::time::Instant,
    /// A startup producer that could not join by D stays owned here until the
    /// caller has finished bounded runtime termination. It is never treated as
    /// completed merely because the runtime stopped waiting for it.
    pending_startup: Option<PendingStartup>,
}

impl ServiceCompletion {
    pub(super) fn new(
        primary: Option<anyhow::Error>,
        cleanup_failures: Vec<String>,
        deadline: Instant,
        pending_startup: Option<PendingStartup>,
    ) -> Self {
        Self { primary, cleanup_failures, deadline: deadline.into_std(), pending_startup }
    }

    /// Only an unsuccessful/pending cleanup may consume the remaining product
    /// deadline through `Runtime::shutdown_timeout`. A clean terminal outcome
    /// keeps the ordinary runtime drop and makes no native-cleanup claim from
    /// process death.
    pub(crate) fn pending_runtime(&self) -> bool {
        self.pending_startup.is_some() || !self.cleanup_failures.is_empty()
    }

    pub(crate) fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(std::time::Instant::now())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_clean(&self) -> bool {
        self.primary.is_none() && self.cleanup_failures.is_empty() && self.pending_startup.is_none()
    }

    /// Preserve the original failure as the error and append cleanup failures
    /// as a separate, explicit incomplete classification.
    pub(crate) fn into_result(self) -> anyhow::Result<()> {
        let pending_startup = self.pending_startup;
        let mut cleanup_failures = self.cleanup_failures;
        if pending_startup.is_some() {
            cleanup_failures.push("startup reconcile owner remained pending at the shutdown deadline".to_owned());
        }
        match (self.primary, cleanup_failures.is_empty()) {
            (Some(primary), true) => Err(primary),
            (Some(primary), false) => {
                let cleanup = format!("service cleanup incomplete: {}", cleanup_failures.join("; "));
                Err(primary.context(cleanup))
            }
            (None, true) => Ok(()),
            (None, false) => bail!("normal shutdown incomplete: {}", cleanup_failures.join("; ")),
        }
    }
}
