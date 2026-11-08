//! Owned per-verification lease: capacity slot + private workspace, plus the
//! bounded cancellation reaper that retains both until physical quiescence.
//!
//! Invariants this module exists to guarantee:
//!
//! * the process-wide verifier permit and the 0700 workspace live in **one**
//!   `Arc<VerificationLease>`, so a third verification can only take a slot after
//!   every reference is gone — that is, after every owned child of the earlier
//!   verifications was confirmed reaped *and* its whole process group was
//!   physically quiescent, and after the workspace was removed;
//! * a child that is not confirmed therefore never releases capacity: on
//!   cancellation `GroupChild::drop` signals the group synchronously (no blocking,
//!   no sleeping on a Tokio worker) and hands the owned child plus its lease to one
//!   bounded reaper task;
//! * at most one reaper exists per lease and at most two leases exist process-wide
//!   (the frozen two permits), so retained cleanup can never fan out and is itself
//!   the bound on retained slots;
//! * if no Tokio runtime can drive the reaper (runtime already gone), the child
//!   handle and the lease are kept instead of releasing capacity for a process
//!   that may still be alive: cleanup fails closed and never "pretends" a reap.
//!
//! Only process groups this verifier spawned are ever signalled (`kill(-pid)` on
//! the id of a child that was started with `setpgid(0,0)` in this process); there
//! is no global OS process cleanup and no unowned PID is touched.
use super::refuse;
use super::scratch::TempRoot;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Child;
use tokio::sync::OwnedSemaphorePermit;

/// Foreground poll interval while a reaper owns cleanup.
const FAST_POLL: Duration = Duration::from_millis(10);
/// Back-off interval once cleanup is already known to be slow.
const SLOW_POLL: Duration = Duration::from_millis(250);
/// Polls before the reaper backs off (~5 s).
const SLOW_AFTER: u32 = 500;

/// One verification's capacity slot and private workspace.
pub(super) struct VerificationLease {
    /// The workspace goes before the slot: files only disappear after the last
    /// reference, which is also the point at which capacity returns.
    root: TempRoot,
    _permit: OwnedSemaphorePermit,
}

impl VerificationLease {
    /// Bind one already-acquired process-wide slot to a freshly created private
    /// workspace.
    pub(super) fn new(permit: OwnedSemaphorePermit) -> Result<Arc<Self>, PackCommitError> {
        let root = TempRoot::create()?;
        Ok(Arc::new(Self { root, _permit: permit }))
    }

    pub(super) fn root_path(&self) -> &Path {
        self.root.path()
    }

    pub(super) fn subdirectory(&self, name: &str) -> Result<PathBuf, PackCommitError> {
        self.root.subdirectory(name)
    }
}

/// Take ownership of a child that is *not* confirmed stopped.
///
/// Called from `GroupChild::drop` and from the bounded foreground cleanup path.
/// The whole group is signalled immediately (a single non-blocking syscall), then
/// one owned task polls until the leader is reaped and the group is quiescent. The
/// lease — permit plus workspace — is released only after that confirmation, so an
/// uncertain cleanup keeps its capacity reserved.
///
/// The child handle is optional so a state that already lost it can still keep the
/// lease reserved. The group is signalled **only** while this function still owns
/// the unreaped leader, because that zombie is what keeps the group id reserved;
/// without it no signal is sent to anything.
pub(super) fn retain_until_stopped(child: Option<Child>, pid: i32, lease: Option<Arc<VerificationLease>>) {
    if pid > 0 && child.is_some() {
        // SAFETY: `pid` is the id of a child this verifier spawned in its own
        // process group and still owns unreaped, so the group id cannot have been
        // reused and the signal cannot reach an unrelated process.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let retained = Retained { child, pid, lease };
    match tokio::runtime::Handle::try_current() {
        // Dropping the handle detaches the task; the task itself owns the child,
        // the lease and therefore the bound on retained capacity.
        Ok(handle) => std::mem::drop(handle.spawn(async move {
            let mut retained = retained;
            retained.settle().await;
        })),
        // No runtime can drive the reaper: `Retained::drop` keeps the child handle
        // and the lease reserved instead of releasing an uncertain stop.
        Err(_) => drop(retained),
    }
}

/// Owned cleanup state of one child whose stop is not yet confirmed.
struct Retained {
    child: Option<Child>,
    pid: i32,
    lease: Option<Arc<VerificationLease>>,
}

impl Drop for Retained {
    fn drop(&mut self) {
        // `settle` clears both fields only after the group is observed quiescent
        // and the leader is reaped. A runtime shutdown aborts the spawned task, so
        // reaching this point with either field still owned means the stop is
        // unconfirmed: keep the child handle (unreaped, already signalled) and the
        // lease (slot plus workspace) owned for the life of the process instead of
        // releasing capacity while a native child may still be alive. At most two
        // leases exist process-wide, so this leak is bounded and fail-closed.
        if self.child.is_some() {
            std::mem::forget(self.child.take());
        }
        if self.lease.is_some() {
            std::mem::forget(self.lease.take());
        }
    }
}

impl Retained {
    async fn settle(&mut self) {
        let mut ticks: u32 = 0;
        loop {
            let settled = if self.pid > 0 {
                // The leader is reaped only after the whole group was observed
                // quiescent: while it stays unreaped it reserves the group id, so
                // no later signal of `-pid` can reach an unrelated process.
                matches!(crate::git_http::group_quiescent(self.pid), Ok(true)) && self.leader_reaped()
            } else {
                // Unknown id: only this verifier's own leader is waited for. No
                // group is probed, no global/OS process scan and no signal is sent
                // to anything this verifier did not spawn.
                self.leader_reaped()
            };
            if settled {
                break;
            }
            ticks = ticks.saturating_add(1);
            let interval = if ticks > SLOW_AFTER { SLOW_POLL } else { FAST_POLL };
            tokio::time::sleep(interval).await;
        }
        // Confirmed stopped: drop the reaped handle, the workspace and finally the
        // process-wide slot.
        self.child = None;
        self.lease = None;
    }

    /// Reap the leader only when it has already exited.
    fn leader_reaped(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(Some(_))),
            None => true,
        }
    }
}

/// Fixed refusal for a retained cleanup that cannot be confirmed in the caller's
/// bounded foreground window. The lease stays reserved with the reaper.
pub(super) fn refuse_retained_cleanup() -> PackCommitError {
    refuse("native Git cleanup is retained and still owns the verifier slot")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;

    /// The slot and the workspace are released together and only with the last
    /// lease reference. No native child is involved, so this tests ownership only.
    #[tokio::test]
    async fn the_slot_and_workspace_live_until_the_last_reference_drops() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&slots).acquire_owned().await.expect("first slot");
        let lease = VerificationLease::new(permit).expect("lease");
        let workspace = lease.root_path().to_path_buf();
        assert!(workspace.is_dir(), "the workspace exists with the lease");
        assert!(Arc::clone(&slots).try_acquire_owned().is_err(), "the slot stays reserved");
        let second = Arc::clone(&lease);
        drop(lease);
        assert!(workspace.is_dir(), "the workspace survives while a reference is alive");
        assert!(Arc::clone(&slots).try_acquire_owned().is_err(), "a remaining reference still owns the slot");
        drop(second);
        assert!(workspace.symlink_metadata().is_err(), "the workspace is removed with the last reference");
        drop(Arc::clone(&slots).try_acquire_owned().expect("the slot returns with the last reference"));
    }

    /// An unconfirmed retained state must never release the slot or the workspace:
    /// this is the state a shutdown-aborted reaper leaves behind. The lease of this
    /// test is deliberately retained, which is exactly the bounded leak the
    /// fail-closed rule accepts.
    #[test]
    fn an_unconfirmed_retained_state_keeps_its_slot_and_workspace() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&slots).try_acquire_owned().expect("slot");
        let lease = VerificationLease::new(permit).expect("lease");
        let workspace = lease.root_path().to_path_buf();
        let watcher = Arc::downgrade(&lease);
        let retained = Retained { child: None, pid: 0, lease: Some(Arc::clone(&lease)) };
        drop(lease);
        drop(retained);
        assert!(watcher.upgrade().is_some(), "an unconfirmed retained lease is never released");
        assert!(workspace.symlink_metadata().is_ok(), "its workspace is never removed");
        assert!(Arc::clone(&slots).try_acquire_owned().is_err(), "its slot is never returned");
    }
}
