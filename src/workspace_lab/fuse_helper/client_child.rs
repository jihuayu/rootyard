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

    #[test]
    fn a_real_taken_child_is_reaping_until_its_actual_exit_is_recorded() {
        use std::process::{Child, Command};
        use std::sync::{mpsc, Arc, Mutex};
        use std::thread;
        use std::time::Duration;

        struct KillWait(Option<Child>);
        impl Drop for KillWait {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        // If the test panics before the worker owns the handle, reclaim it from
        // the slot and kill/wait it. If the worker already took it, its
        // `KillWait` guard owns the cleanup instead.
        struct SlotCleanup(Arc<Mutex<ChildSlot>>);
        impl Drop for SlotCleanup {
            fn drop(&mut self) {
                let child = self.0.lock().ok().and_then(|mut slot| slot.take_for_reap());
                if let Some(mut child) = child {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        let child = Command::new("sleep").arg("30").spawn().expect("spawn controlled child");
        let pid = child.id();
        let slot = Arc::new(Mutex::new(ChildSlot::running(child)));
        let _cleanup = SlotCleanup(slot.clone());
        let (taken_tx, taken_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<ExitView>();
        let worker_slot = slot.clone();
        let worker = thread::spawn(move || {
            let child = worker_slot.lock().expect("slot lock").take_for_reap();
            let Some(child) = child else { panic!("test reaper did not receive the real child") };
            let mut guard = KillWait(Some(child));
            taken_tx.send(()).expect("announce taken child");
            release_rx.recv_timeout(Duration::from_secs(5)).expect("bounded reaper barrier");
            let status = {
                let child = guard.0.as_mut().expect("guarded child");
                let _ = child.kill();
                child.wait().expect("wait real child")
            };
            guard.0 = None;
            let view = ExitView::from(status);
            worker_slot.lock().expect("slot lock").record_exit(Ok(view.clone()));
            done_tx.send(view).expect("announce observed exit");
        });

        taken_rx.recv_timeout(Duration::from_secs(5)).expect("reaper barrier");
        assert_eq!(
            slot.lock().expect("slot lock").observe(),
            ExitObservation::Reaping,
            "a taken handle is not an exit even while the real process is alive"
        );
        // SAFETY: signal 0 only probes this test-owned child.
        assert!(unsafe { libc::kill(pid as libc::pid_t, 0) } == 0, "the real child is still alive");
        release_tx.send(()).expect("release reaper");
        let observed = done_rx.recv_timeout(Duration::from_secs(5)).expect("observed real exit");
        assert!(!observed.success, "SIGKILL must record a non-success exit");
        worker.join().expect("reaper thread");
        let first = slot.lock().expect("slot lock").observe();
        assert_eq!(first, ExitObservation::Exited(Ok(observed.clone())));
        assert_eq!(
            slot.lock().expect("slot lock").observe(),
            first,
            "repeat observation preserves the real exit status"
        );
    }
}
