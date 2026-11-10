//! Owned verification leases: native process capacity, private workspace and the
//! separate materialized-view budget, plus the bounded cancellation reaper that
//! retains them until physical quiescence.
//!
//! Invariants this module exists to guarantee:
//!
//! * the process-wide native permit, the optional materialized-view budget and
//!   the 0700 workspace live in **one** `Arc<VerificationLease>`, so a third
//!   native verification can only take a slot after every owned child of the
//!   earlier verification was confirmed reaped *and* its whole process group was
//!   physically quiescent;
//! * A4 holds the native permit for the whole verification. A5b acquires a view
//!   budget first, admits the native permit only around native work, and takes
//!   it back once every child is confirmed quiescent; the view budget and
//!   workspace stay owned by the public materialized view;
//! * a child that is not confirmed therefore never releases capacity: on
//!   cancellation `GroupChild::drop` signals the group synchronously and hands
//!   the owned child plus its lease to one bounded reaper task;
//! * at most one reaper exists per lease and at most two native leases exist
//!   process-wide (the frozen two permits), so retained cleanup can never fan
//!   out and is itself the bound on retained slots;
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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::process::Child;
use tokio::sync::OwnedSemaphorePermit;

/// Foreground poll interval while a reaper owns cleanup.
const FAST_POLL: Duration = Duration::from_millis(10);
/// Back-off interval once cleanup is already known to be slow.
const SLOW_POLL: Duration = Duration::from_millis(250);
/// Polls before the reaper backs off (~5 s).
const SLOW_AFTER: u32 = 500;

/// One verification's capacity permits and private workspace.
pub(super) struct VerificationLease {
    /// The workspace goes before the permits: files only disappear after the
    /// last reference, which is also the point at which capacity returns.
    root: TempRoot,
    /// Materialized-view budget. `None` for an A4 native verification.
    _view_budget: Option<OwnedSemaphorePermit>,
    /// Native process permit. `None` before A5b native admission and after every
    /// native child is confirmed quiescent.
    native: Mutex<Option<OwnedSemaphorePermit>>,
}

impl VerificationLease {
    /// Bind one already-acquired process-wide native slot to a freshly created
    /// private workspace (A4 shape).
    pub(super) fn new(permit: OwnedSemaphorePermit) -> Result<Arc<Self>, PackCommitError> {
        let root = TempRoot::create()?;
        Ok(Arc::new(Self { root, _view_budget: None, native: Mutex::new(Some(permit)) }))
    }

    /// Bind one already-acquired materialized-view budget to a private workspace.
    /// No native permit is held until [`Self::admit_native`].
    pub(super) fn with_view_budget(budget: OwnedSemaphorePermit) -> Result<Arc<Self>, PackCommitError> {
        let root = TempRoot::create()?;
        Ok(Arc::new(Self { root, _view_budget: Some(budget), native: Mutex::new(None) }))
    }

    /// Test-only empty lease for unit cases that never run a native child (an
    /// owned workspace with no native permit and no view budget).
    #[cfg(test)]
    pub(super) fn for_test() -> Arc<Self> {
        Arc::new(Self {
            root: TempRoot::create().expect("test lease root"),
            _view_budget: None,
            native: Mutex::new(None),
        })
    }

    /// Install the one native permit for the pending native steps. Callers must
    /// have acquired the view budget first.
    pub(super) fn admit_native(&self, permit: OwnedSemaphorePermit) {
        if let Ok(mut native) = self.native.lock() {
            *native = Some(permit);
        } else {
            // A poisoned mutex still owns its permit. Keep it fail-closed; the
            // caller will observe the missing/quarantined state only through the
            // normal native error path.
            std::mem::forget(permit);
        }
    }

    /// Release native capacity only after every native child of this lease was
    /// confirmed quiescent and reaped. The workspace and view budget remain
    /// owned by the public materialized view.
    pub(super) fn release_native(&self) {
        // A poisoned mutex retains its permit until the lease itself drops.
        if let Ok(mut native) = self.native.lock() {
            native.take();
        }
    }

    pub(super) fn root_path(&self) -> &Path {
        self.root.path()
    }

    pub(super) fn subdirectory(&self, name: &str) -> Result<PathBuf, PackCommitError> {
        self.root.subdirectory(name)
    }

    /// Conservative aggregate logical bytes currently retained under the owned
    /// workspace. Every mutating native step checks this 160 MiB view bound.
    pub(super) fn retained_bytes(&self) -> Result<u64, PackCommitError> {
        directory_bytes(self.root.path())
    }
}

/// Sum regular-file lengths under one owned workspace, refusing anything that is
/// not a regular file or directory. Symlinks are never followed.
pub(super) fn directory_bytes(root: &Path) -> Result<u64, PackCommitError> {
    let mut total = 0u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let entries = std::fs::read_dir(&path).map_err(|_| refuse("owned verification workspace cannot be listed"))?;
        for entry in entries {
            let entry = entry.map_err(|_| refuse("owned verification workspace cannot be listed"))?;
            let metadata =
                entry.metadata().map_err(|_| refuse("owned verification workspace entry cannot be inspected"))?;
            if metadata.file_type().is_symlink() {
                return Err(refuse("owned verification workspace contains a symlink"));
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = total
                    .checked_add(metadata.len())
                    .ok_or_else(|| refuse("owned verification workspace byte count overflowed"))?;
            } else {
                return Err(refuse("owned verification workspace contains a special file"));
            }
        }
    }
    Ok(total)
}

/// Take ownership of a child that is *not* confirmed stopped.
///
/// Called from `GroupChild::drop` and from the bounded foreground cleanup path.
/// The whole group is signalled immediately, then one owned task polls until the
/// leader is reaped and the group is quiescent. The lease — native permit and
/// workspace/view budget — is released only after that confirmation, so an
/// uncertain cleanup keeps its capacity reserved.
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
        Ok(handle) => std::mem::drop(handle.spawn(async move {
            let mut retained = retained;
            retained.settle().await;
        })),
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
        // lease (slot, view budget and workspace) owned for the life of the process
        // instead of releasing capacity while a native child may still be alive.
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
                matches!(crate::git_http::group_quiescent(self.pid), Ok(true)) && self.leader_reaped()
            } else {
                self.leader_reaped()
            };
            if settled {
                break;
            }
            ticks = ticks.saturating_add(1);
            let interval = if ticks > SLOW_AFTER { SLOW_POLL } else { FAST_POLL };
            tokio::time::sleep(interval).await;
        }
        self.child = None;
        self.lease = None;
    }

    fn leader_reaped(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(Some(_))),
            None => true,
        }
    }
}

pub(super) fn refuse_retained_cleanup() -> PackCommitError {
    refuse("native Git cleanup is retained and still owns the verifier capacity")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;

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
