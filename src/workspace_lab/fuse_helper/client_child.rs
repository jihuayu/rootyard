//! Explicit parent-side child lifecycle.
//!
//! Taking a `Child` out of the shared slot is not an exit. A taken handle means
//! the one reaper owns the process and must keep polling it; `wait_exit` may
//! only succeed from an `ExitStatus` observed by `Child::try_wait`/`wait`.
use std::process::{Child, ExitStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExitView {
    pub success: bool,
    pub description: String,
}

impl From<ExitStatus> for ExitView {
    fn from(status: ExitStatus) -> Self {
        Self { success: status.success(), description: status.to_string() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ExitObservation {
    Running,
    /// The reaper owns the only `Child`; no exit has been observed yet.
    Reaping,
    /// The handle vanished without an observed exit. This is never success.
    Missing,
    Exited(Result<ExitView, String>),
}

#[derive(Default)]
pub(super) struct ChildSlot {
    child: Option<Child>,
    reaping: bool,
    status: Option<Result<ExitView, String>>,
}

impl ChildSlot {
    pub(super) fn running(child: Child) -> Self {
        Self { child: Some(child), reaping: false, status: None }
    }

    /// Move the handle to the one reaper. Returns `None` if an exit is already
    /// recorded or another reaper already owns it.
    pub(super) fn take_for_reap(&mut self) -> Option<Child> {
        if self.status.is_some() || self.reaping {
            return None;
        }
        let child = self.child.take()?;
        self.reaping = true;
        Some(child)
    }

    /// Record a status obtained from the reaper's own `Child::try_wait`.
    pub(super) fn record_exit(&mut self, observed: Result<ExitView, String>) {
        if self.status.is_none() {
            self.status = Some(observed);
        }
        self.reaping = false;
    }

    /// One short observation. Never sleeps and never treats a missing handle as
    /// an exit; `wait_exit` owns the bounded sleep loop.
    pub(super) fn observe(&mut self) -> ExitObservation {
        if let Some(status) = self.status.as_ref() {
            return ExitObservation::Exited(status.clone());
        }
        let mut observed = None;
        if let Some(child) = self.child.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => observed = Some(Ok(ExitView::from(status))),
                Ok(None) => {}
                Err(error) => observed = Some(Err(error.to_string())),
            }
        }
        if let Some(result) = observed {
            self.child = None;
            self.reaping = false;
            self.status = Some(result.clone());
            return ExitObservation::Exited(result);
        }
        if self.reaping {
            ExitObservation::Reaping
        } else if self.child.is_some() {
            ExitObservation::Running
        } else {
            ExitObservation::Missing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_taken_handle_is_reaping_and_never_a_successful_exit() {
        let mut slot = ChildSlot { child: None, reaping: true, status: None };
        assert_eq!(slot.observe(), ExitObservation::Reaping);
        assert!(!matches!(slot.observe(), ExitObservation::Exited(Ok(_))));
    }

    #[test]
    fn a_missing_handle_is_never_an_exit() {
        let mut slot = ChildSlot::default();
        assert_eq!(slot.observe(), ExitObservation::Missing);
        assert!(!matches!(slot.observe(), ExitObservation::Exited(Ok(_))));
    }

    #[test]
    fn a_recorded_exit_blocks_a_second_reap_and_stays_observable() {
        let mut slot = ChildSlot::default();
        let success = ExitView { success: true, description: "exit status: 0".into() };
        slot.record_exit(Ok(success.clone()));
        assert!(slot.take_for_reap().is_none(), "an observed exit must not be reaped twice");
        assert_eq!(slot.observe(), ExitObservation::Exited(Ok(success)));
    }

    #[test]
    fn a_recorded_nonzero_exit_is_preserved_for_the_waiter() {
        let mut slot = ChildSlot::default();
        let failure = ExitView { success: false, description: "exit status: 7".into() };
        slot.record_exit(Ok(failure.clone()));
        assert_eq!(slot.observe(), ExitObservation::Exited(Ok(failure)));
    }
}
