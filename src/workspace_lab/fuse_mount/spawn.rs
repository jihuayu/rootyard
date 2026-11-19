//! Mount entry points and the shared option list.

use super::fuse_dispatch::MountFs;
use super::ownership;
use super::{LegacySpawnFailure, MountHandle, Overlay};
use fuser::MountOption;
use std::io;
use std::path::{Path, PathBuf};

/// Mount options shared by every mount.
///
/// `AutoUnmount` is added only for the independent helper. The in-process
/// service mount and the lab mount keep the legacy option list so an
/// existing deployment is not switched onto the fusermount3 path by accident.
pub(crate) fn mount_options(auto_unmount: bool) -> Vec<MountOption> {
    let mut options = vec![MountOption::FSName("rootyard-vfs".into()), MountOption::DefaultPermissions];
    if auto_unmount {
        options.push(MountOption::AutoUnmount);
    }
    options
}

fn spawn_with(overlay: Overlay, mountpoint: &Path, auto_unmount: bool) -> Result<MountHandle, LegacySpawnFailure> {
    // Canonicalize before mounting: `/proc/self/mountinfo` publishes the
    // canonical path, and the teardown identity check compares it exactly.
    let mountpoint = mountpoint.canonicalize().map_err(LegacySpawnFailure::BeforeSession)?;
    let fs = MountFs::new(overlay).map_err(LegacySpawnFailure::BeforeSession)?;
    let dispatcher = fs.dispatcher().clone();
    let session = fuser::spawn_mount2(fs, &mountpoint, &mount_options(auto_unmount))
        .map_err(LegacySpawnFailure::BeforeSession)?;
    // Capture the kernel mount identity before anyone else can observe the
    // mount point. A missing or unreadable identity is not a pre-spawn failure:
    // the session already exists, so the owner must be returned intact.
    let mount_id = match ownership::mount_id_at_path(&mountpoint) {
        Ok(Some(mount_id)) => Some(mount_id),
        Ok(None) => {
            // The helper mount already succeeded. `AutoUnmount` removes the
            // mount when the last helper descriptor dies, so the helper exits
            // immediately and lock-free: no IO, no unmount guess, no
            // destructor that joins the session.
            if auto_unmount {
                // SAFETY: `_exit` is async-signal-safe and does not touch
                // Rust state or any lock; process death closes the owned FUSE
                // descriptor and lets `AutoUnmount` clean the mountpoint.
                unsafe { libc::_exit(1) }
            }
            let error = io::Error::other("owned FUSE mount is missing from /proc/self/mountinfo");
            let owner =
                MountHandle { session: Some(session), dispatcher, mountpoint, mount_id: None, session_join: None };
            return Err(LegacySpawnFailure::AfterSession { error, owner: Box::new(owner) });
        }
        Err(error) => {
            // Same fail-closed rule when the mount table cannot be read at
            // all. The legacy path returns the already-created owner, not just
            // an IO error.
            if auto_unmount {
                // SAFETY: as above; this path must not run any Rust teardown.
                unsafe { libc::_exit(1) }
            }
            let owner =
                MountHandle { session: Some(session), dispatcher, mountpoint, mount_id: None, session_join: None };
            return Err(LegacySpawnFailure::AfterSession { error, owner: Box::new(owner) });
        }
    };
    Ok(MountHandle { session: Some(session), dispatcher, mountpoint, mount_id, session_join: None })
}

/// Owner-bearing variant used by the in-process legacy registry. A
/// post-spawn identity failure returns the live owner so the caller can
/// transfer it before the pending admission guard is dropped.
pub(crate) fn spawn_legacy(overlay: Overlay, mountpoint: &Path) -> Result<MountHandle, LegacySpawnFailure> {
    spawn_with(overlay, mountpoint, false)
}

/// Spawn the bounded per-mount dispatcher and mount `overlay` in the background.
///
/// Every mount owns its own queue and actor, so a slow read on one mount cannot
/// stall another mount. Queue limits are shared per helper and per process.
///
/// This is the historical option list (no `AutoUnmount`): used by the in-process
/// service mount, whose unmount is driven by the owning API process.
pub fn spawn(overlay: Overlay, mountpoint: &Path) -> io::Result<MountHandle> {
    spawn_with(overlay, mountpoint, false).map_err(LegacySpawnFailure::into_error)
}

/// Spawn a mount owned by one independent FUSE helper process with
/// [`MountOption::AutoUnmount`].
///
/// The helper is the only owner of its `/dev/fuse` descriptors: the API parent
/// never receives them and nothing outside the helper unmounts on its behalf.
/// `AutoUnmount` therefore makes the helper's death the ownership boundary.
/// `fuser` takes the pure-Rust `fusermount3` path, keeps the fusermount monitor
/// socket inside its `Mount`, and passes `auto_unmount` to `fusermount3`. When
/// the helper is SIGKILLed the kernel closes its last FUSE fd and that socket
/// together, so `fusermount3` unmounts exactly the mount it created at that
/// path; no explicit `umount` from the harness or the API is involved.
///
/// Owner ACL is deliberately unchanged: `AutoUnmount` is the only option added
/// here. `fuser` injects `allow_other` on the *fusermount command line* when it
/// is needed for `auto_unmount`, but it derives `SessionACL` from the original
/// option list, so the session stays `SessionACL::Owner`. Do not add
/// `AllowOther`/`AllowRoot` here: that would widen the session ACL, and
/// `DefaultPermissions` keeps the kernel/userspace permission checks in place.
///
/// Qualification is the deployment's job, not this function's: the helper needs
/// a host policy where `fusermount3` exists and the caller may use
/// `auto_unmount`/`allow_other`. Where the host is conventionally non-root the
/// supported shape is a private user/mount namespace entered as namespace root
/// (`unshare -Urm`), which the lifecycle harness and CI already use; a
/// conventional non-root host without that wrapper may need `user_allow_other`
/// in the host `fuse.conf` and is *not* qualified by this change. This service
/// never edits a global `fuse.conf` or any LSM policy, and makes no implicit
/// rootless guarantee.
pub fn spawn_helper(overlay: Overlay, mountpoint: &Path) -> io::Result<MountHandle> {
    spawn_with(overlay, mountpoint, true).map_err(LegacySpawnFailure::into_error)
}

pub fn mount(lower: PathBuf, upper: PathBuf, mountpoint: PathBuf) -> io::Result<()> {
    let fs = MountFs::new(Overlay::new(lower, upper)?)?;
    fuser::mount2(fs, mountpoint, &mount_options(false))
}
