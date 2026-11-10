//! Transparent Linux FUSE overlay over an immutable snapshot and private CoW layer.
//!
//! Dispatch is bounded and per-mount: the kernel-facing shim in `fuse_ops` copies
//! each request into an owned operation, and exactly one actor thread in
//! `fuse_dispatch` owns this [`Overlay`] and the [`MutationGate`]. The actor is
//! the only caller of `MutationGate::mutation`, so a mutation is admitted once
//! and no thread-local `MutationGuard` is moved to another thread. Freeze,
//! thaw-drain, fence and queue limits are documented in `fuse_dispatch`.
//! Each queued mutation is stamped with the lease epoch observed at enqueue and
//! is rejected if the actor admits it under a different epoch, so a lease
//! handoff cannot replay an old write on the new authority.
use fuser::{FileAttr, FileType, MountOption};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr, OsString},
    fs::{self, File},
    io,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

const TTL: Duration = Duration::ZERO;

/// Verified local bytes for a lazily hydrated lower-layer file. Keeping this
/// boundary in `workspace_lab` lets the standalone lab binary compile without
/// the service-side workspace modules.
///
/// `Ok(None)` means the path is eagerly materialized metadata (`.git`). Lazy
/// worktree paths must return bytes or an error; the caller fails closed rather
/// than serving the zero-filled sparse placeholder.
pub trait LazySource: Send + Sync {
    fn file(&self, relative: &Path) -> io::Result<Option<File>>;
}

fn open_lower(lazy: Option<&dyn LazySource>, relative: &Path, source: &Entry) -> io::Result<File> {
    if let Some(lazy) = lazy {
        match lazy.file(relative)? {
            Some(file) => return Ok(file),
            None if relative.starts_with(".git") => {}
            None => return Err(io::Error::from_raw_os_error(libc::EIO)),
        }
    }
    source.open(libc::O_RDONLY, 0)
}

// The gate now lives in its own module; keep the historical path stable for
// `crate::workspace_lab::fuse_mount::MutationGate` callers.
pub use super::mutation_gate::{FreezeDecision, GatePhase, LeaseObservation, MutationGate, MutationGuard};

#[path = "fuse_dispatch.rs"]
mod fuse_dispatch;
#[path = "fuse_io.rs"]
mod fuse_io;
#[path = "fuse_ops.rs"]
mod fuse_ops;
#[path = "inner_ops.rs"]
mod inner_ops;
#[path = "owned_ops.rs"]
mod owned_ops;

use fuse_dispatch::MountFs;
use fuse_io::{Entry, safe_link_at, walk_dir};

pub use self::fuse_dispatch::QueueUsage as DispatchQueueUsage;

/// Identity of an owned mount, captured from `/proc/self/mountinfo`.
///
/// Mount IDs are unique in the kernel's mount-ID allocator, so comparing the
/// captured ID proves that a path still carries the mount this handle created
/// and not a newer mount stacked on top of it.
type MountId = u64;

/// Live kernel mount. Dropping the session unmounts and drops the shim, which
/// stops the actor and drains every queued reply.
///
/// The handle also remembers the canonical mount point and the kernel mount ID
/// captured when it mounted, so its owned teardown can unmount exactly this
/// mount instead of whichever mount happens to sit at that path by then.
pub struct MountHandle {
    session: fuser::BackgroundSession,
    dispatcher: Arc<fuse_dispatch::Dispatcher>,
    /// Canonical mount point the kernel published for this handle.
    mountpoint: PathBuf,
    /// Kernel mount ID captured for this handle when it mounted.
    mount_id: MountId,
}

impl MountHandle {
    pub fn queue_usage(&self) -> DispatchQueueUsage {
        self.dispatcher.usage()
    }

    /// Stop the per-mount actor before the session is unmounted. Every reply
    /// still sitting in a queue slot fails with `EIO`; an operation already
    /// admitted to the gate may still finish. Reads executing in the global
    /// read pool re-check the shutdown flag after I/O and reply `EIO`.
    ///
    /// This is the non-consuming half: it neither unmounts nor waits for the
    /// kernel session thread. Callers that own the handle and are about to
    /// exit (the helper teardown, unmount, cancel and publish-failure paths)
    /// must use [`MountHandle::shutdown_and_join`] instead.
    pub fn shutdown(&self) {
        self.dispatcher.shutdown();
    }

    /// Consuming teardown with a completion barrier.
    ///
    /// Stops the dispatcher, then consumes the `fuser::BackgroundSession` and
    /// calls its public `join()`: `join` drops the mount and blocks until
    /// the kernel session thread has actually ended. That is the difference
    /// from `shutdown()` + drop, where the background session detaches its join
    /// handle and a process exiting right afterwards can terminate before the
    /// unmount completed and leave an owned mount behind.
    ///
    /// The unmount itself is done here and is not delegated to `join`: on the
    /// pure-Rust `AutoUnmount` path, dropping `fuser`'s `Mount` only closes the
    /// fusermount monitor socket, while the session thread still owns its own
    /// `/dev/fuse` clone and sits in `read`. Closing the monitor alone cannot
    /// wake that read, so a join-first teardown would wait for a process exit
    /// that is itself waiting for the join. Unmounting this handle's exact
    /// mount with a normal (non-lazy) `umount2` while the session descriptor is
    /// still open makes the kernel fail the parked read with `ENODEV`; `join`
    /// is then a bounded completion barrier. `AutoUnmount` remains the crash
    /// path (SIGKILL closes the last descriptor and the monitor socket).
    ///
    /// A refused unmount is never papered over: the session is still joined in
    /// and the independent shutdown watchdog bounds and fails that exit with a
    /// non-zero code instead of claiming a graceful teardown.
    ///
    /// Returns only after every owned session teardown has completed, so an
    /// owner may exit successfully after this call. A session thread that
    /// panicked propagates here (fail closed) instead of being ignored.
    pub fn shutdown_and_join(self) {
        let Self { session, dispatcher, mountpoint, mount_id } = self;
        dispatcher.shutdown();
        // A refused unmount must fail this process, never be reported as a
        // graceful teardown: helper-only callers panic and exit non-zero, and
        // `AutoUnmount` still closes the descriptor on unwind.
        unmount_owned(&mountpoint, mount_id).expect("owned FUSE unmount failed");
        session.join();
    }
}

pub struct Overlay {
    lower: PathBuf,
    upper: PathBuf,
    paths: BTreeMap<u64, PathBuf>,
    ids: BTreeMap<PathBuf, u64>,
    next: u64,
    whiteouts: BTreeSet<PathBuf>,
    gate: Arc<MutationGate>,
    lazy: Option<Arc<dyn LazySource>>,
}
impl Overlay {
    pub fn new(lower: PathBuf, upper: PathBuf) -> io::Result<Self> {
        Self::new_with_gate(lower, upper, MutationGate::new_with_lease(1, i64::MAX)?)
    }
    pub fn new_with_gate(lower: PathBuf, upper: PathBuf, gate: Arc<MutationGate>) -> io::Result<Self> {
        Self::new_with_gate_and_lazy(lower, upper, gate, None)
    }
    pub(crate) fn new_with_gate_and_lazy(
        lower: PathBuf,
        upper: PathBuf,
        gate: Arc<MutationGate>,
        lazy: Option<Arc<dyn LazySource>>,
    ) -> io::Result<Self> {
        if !lower.is_dir() {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        fs::create_dir_all(&upper)?;
        let lower = lower.canonicalize()?;
        let upper = upper.canonicalize()?;
        if upper.starts_with(&lower) || lower.starts_with(&upper) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let mut paths = BTreeMap::new();
        paths.insert(1, PathBuf::new());
        let mut ids = BTreeMap::new();
        ids.insert(PathBuf::new(), 1);
        let whiteout_meta = match fs::symlink_metadata(upper.join(".rootyard-whiteouts.json")) {
            Ok(meta) if meta.is_file() => true,
            Ok(_) => return Err(io::Error::from_raw_os_error(libc::EPERM)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(e),
        };
        let whiteouts = if whiteout_meta {
            serde_json::from_slice::<Vec<String>>(&fs::read(upper.join(".rootyard-whiteouts.json"))?)
                .map_err(io::Error::other)?
                .into_iter()
                .map(PathBuf::from)
                .collect()
        } else {
            BTreeSet::new()
        };
        Ok(Self { lower, upper, paths, ids, next: 2, whiteouts, gate, lazy })
    }
    fn ino(&mut self, p: &Path) -> u64 {
        if let Some(n) = self.ids.get(p) {
            return *n;
        }
        let n = self.next;
        self.next += 1;
        self.ids.insert(p.to_path_buf(), n);
        self.paths.insert(n, p.to_path_buf());
        n
    }
    fn rel(&self, ino: u64) -> io::Result<PathBuf> {
        self.paths.get(&ino).cloned().ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
    }
    fn child(&self, parent: u64, name: &OsStr) -> io::Result<PathBuf> {
        if name.as_bytes().is_empty()
            || name.as_bytes().contains(&b'/')
            || name == "."
            || name == ".."
            || name.as_bytes().starts_with(b".rootyard-whiteouts.")
        {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        Ok(self.rel(parent)?.join(name))
    }
    fn hidden(&self, p: &Path) -> bool {
        self.whiteouts.iter().any(|w| p == w || p.starts_with(w))
    }
    fn host_entry(&self, path: &Path, create_parent: bool) -> io::Result<Entry> {
        if let Ok(rel) = path.strip_prefix(&self.upper) {
            Entry::new(&self.upper, rel, create_parent)
        } else if let Ok(rel) = path.strip_prefix(&self.lower) {
            Entry::new(&self.lower, rel, false)
        } else {
            Err(io::Error::from_raw_os_error(libc::EPERM))
        }
    }
    fn checked_entry(&self, root: &Path, p: &Path) -> io::Result<Entry> {
        let entry = Entry::new(root, p, false)?;
        let meta = entry.lstat()?;
        if meta.file_type().is_symlink() {
            safe_link_at(&entry.read_link()?, p)?;
        }
        Ok(entry)
    }
    fn selected(&self, p: &Path) -> io::Result<PathBuf> {
        if self.hidden(p) {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        if p.as_os_str().is_empty() {
            return Ok(self.upper.clone());
        }
        let up = self.upper.join(p);
        if self.checked_entry(&self.upper, p).is_ok() {
            return Ok(up);
        }
        let low = self.lower.join(p);
        self.checked_entry(&self.lower, p)?;
        Ok(low)
    }
    fn attr(&self, p: &Path, ino: u64) -> io::Result<FileAttr> {
        let path = self.selected(p)?;
        let m = if p.as_os_str().is_empty() {
            fs::symlink_metadata(path)?
        } else {
            self.host_entry(&path, false)?.lstat()?
        };
        let kind = if m.file_type().is_dir() {
            FileType::Directory
        } else if m.file_type().is_symlink() {
            FileType::Symlink
        } else if m.file_type().is_file() {
            FileType::RegularFile
        } else {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        };
        Ok(FileAttr {
            ino,
            size: m.len(),
            blocks: m.blocks(),
            atime: m.accessed().unwrap_or(SystemTime::UNIX_EPOCH),
            mtime: m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            ctime: m.created().unwrap_or(SystemTime::UNIX_EPOCH),
            crtime: SystemTime::UNIX_EPOCH,
            kind,
            perm: (m.permissions().mode() & 0o777) as u16,
            nlink: m.nlink() as u32,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            blksize: 4096,
            flags: 0,
        })
    }
    fn prepare(&mut self, p: &Path) -> io::Result<Entry> {
        let to = Entry::new(&self.upper, p, true)?;
        if to.lstat().is_err()
            && let Ok(from) = self.selected(p)
        {
            let source = self.host_entry(&from, false)?;
            let m = source.lstat()?;
            if m.is_file() {
                let mut input = if from.starts_with(&self.lower) {
                    open_lower(self.lazy.as_deref(), p, &source)?
                } else {
                    source.open(libc::O_RDONLY, 0)?
                };
                let mut output =
                    to.open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, m.permissions().mode() & 0o777)?;
                io::copy(&mut input, &mut output)?;
                output.sync_all()?;
            } else if m.file_type().is_symlink() {
                let target = source.read_link()?;
                safe_link_at(&target, p)?;
                to.symlink(&target)?;
            } else if m.is_dir() {
                to.mkdir(m.permissions().mode() & 0o777)?;
            }
        }
        Ok(to)
    }
    fn children(&self, p: &Path) -> io::Result<BTreeSet<OsString>> {
        let mut names = BTreeSet::new();
        for root in [&self.lower, &self.upper] {
            if let Ok(dir) = walk_dir(root, p, false) {
                for item in fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
                    let name = item?.file_name();
                    if !name.as_bytes().starts_with(b".rootyard-whiteouts.") {
                        names.insert(name);
                    }
                }
            }
        }
        Ok(names)
    }
    fn validate_move(&self, src: &Path, dst: &Path, depth: usize) -> io::Result<()> {
        if depth > 128 {
            return Err(io::Error::from_raw_os_error(libc::ELOOP));
        }
        let path = self.selected(src)?;
        let entry = self.host_entry(&path, false)?;
        let meta = entry.lstat()?;
        if meta.file_type().is_symlink() {
            return safe_link_at(&entry.read_link()?, dst);
        }
        if meta.is_dir() {
            for name in self.children(src)? {
                let child = src.join(&name);
                if !self.hidden(&child) && self.selected(&child).is_ok() {
                    self.validate_move(&child, &dst.join(name), depth + 1)?;
                }
            }
        }
        Ok(())
    }
    fn materialize_tree(&mut self, p: &Path, depth: usize) -> io::Result<()> {
        if depth > 128 {
            return Err(io::Error::from_raw_os_error(libc::ELOOP));
        }
        let path = self.selected(p)?;
        let is_dir = self.host_entry(&path, false)?.lstat()?.is_dir();
        self.prepare(p)?;
        if is_dir {
            for name in self.children(p)? {
                let child = p.join(name);
                if !self.hidden(&child) && self.selected(&child).is_ok() {
                    self.materialize_tree(&child, depth + 1)?;
                }
            }
        }
        Ok(())
    }
    fn save_whiteouts(&self) -> io::Result<()> {
        let names: Vec<String> = self.whiteouts.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        let tmp_name = format!(".rootyard-whiteouts.{}.tmp", uuid::Uuid::new_v4());
        let tmp = Entry::new(&self.upper, Path::new(&tmp_name), false)?;
        let target = Entry::new(&self.upper, Path::new(".rootyard-whiteouts.json"), false)?;
        let mut file = tmp.open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?;
        use io::Write;
        file.write_all(&serde_json::to_vec(&names)?)?;
        file.sync_all()?;
        tmp.rename_to(&target)?;
        File::open(&self.upper)?.sync_all()
    }
    fn err(e: io::Error) -> i32 {
        e.raw_os_error().unwrap_or(libc::EIO)
    }
}

/// Mount options shared by every mount.
///
/// `AutoUnmount` is added only for the independent helper. The in-process
/// service mount and the lab mount keep the historical option list so an
/// existing deployment is not switched onto the fusermount3 path by accident.
fn mount_options(auto_unmount: bool) -> Vec<MountOption> {
    let mut options = vec![MountOption::FSName("rootyard-vfs".into()), MountOption::DefaultPermissions];
    if auto_unmount {
        options.push(MountOption::AutoUnmount);
    }
    options
}

fn spawn_with(overlay: Overlay, mountpoint: &Path, auto_unmount: bool) -> io::Result<MountHandle> {
    // Canonicalize before mounting: `/proc/self/mountinfo` publishes the
    // canonical path, and the teardown identity check compares it exactly.
    let mountpoint = mountpoint.canonicalize()?;
    let fs = MountFs::new(overlay)?;
    let dispatcher = fs.dispatcher().clone();
    let session = fuser::spawn_mount2(fs, &mountpoint, &mount_options(auto_unmount))?;
    // Capture the kernel mount identity before anyone else can observe the
    // mount point. An unverifiable mount is not published: a later path-based
    // unmount could otherwise hit a different mount stacked at the same path.
    let mount_id = match mount_id_at_path(&mountpoint) {
        Ok(Some(mount_id)) => mount_id,
        Ok(None) => {
            // The helper mount already succeeded, so dropping the background
            // session would leave an untracked FUSE thread and a mount nobody
            // can prove ownership of. `AutoUnmount` removes the mount when the
            // last helper descriptor dies, so exit immediately and lock-free:
            // no IO, no unmount guess, no destructor that joins the session.
            if auto_unmount {
                // SAFETY: `_exit` is async-signal-safe and does not touch
                // Rust state or any lock; process death closes the owned FUSE
                // descriptor and lets `AutoUnmount` clean the mountpoint.
                unsafe { libc::_exit(1) }
            }
            drop(session);
            return Err(io::Error::other("owned FUSE mount is missing from /proc/self/mountinfo"));
        }
        Err(error) => {
            // Same fail-closed rule when the mount table cannot be read at
            // all. The legacy (non-`AutoUnmount`) caller keeps its previous
            // error propagation because it has no helper death cleanup.
            if auto_unmount {
                // SAFETY: as above; this path must not run any Rust teardown.
                unsafe { libc::_exit(1) }
            }
            drop(session);
            return Err(error);
        }
    };
    Ok(MountHandle { session, dispatcher, mountpoint, mount_id })
}

/// Normal (non-lazy) unmount of exactly the mount this handle captured.
///
/// Fails closed in every other case: an unreadable mount table and a path that
/// now holds a different mount (or an ambiguous stack of mounts) are reported
/// instead of guessed at; an already-unmounted path is a no-op. `MNT_DETACH`
/// and a `fusermount -u` fallback are deliberately not used: a lazy detach
/// leaves the session thread parked on its descriptor, and a blind path unmount
/// could remove a mount this handle does not own.
fn unmount_owned(mountpoint: &Path, mount_id: MountId) -> io::Result<()> {
    match mount_id_at_path(mountpoint)? {
        Some(current) if owns_current_mount(mount_id, Some(current)) => {
            let path = CString::new(mountpoint.as_os_str().as_bytes())
                .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
            // SAFETY: `path` is NUL-terminated, and flags 0 request a normal,
            // non-lazy unmount of the identity verified above.
            if unsafe { libc::umount2(path.as_ptr(), 0) } == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
        }
        // Already unmounted: nothing to remove, `join` still reaps the session.
        None => Ok(()),
        // A different mount owns the path now; never unmount a foreign mount.
        Some(_) => Err(io::Error::from_raw_os_error(libc::EBUSY)),
    }
}

/// True only for the exact mount this handle created.
fn owns_current_mount(captured: MountId, current: Option<MountId>) -> bool {
    current == Some(captured)
}

fn mount_id_at_path(mountpoint: &Path) -> io::Result<Option<MountId>> {
    mount_id_in(&fs::read_to_string("/proc/self/mountinfo")?, mountpoint)
}

/// The single mount recorded exactly at `mountpoint` in a `mountinfo` text.
///
/// Kernel mount IDs are opaque and may be reused, so numeric order says nothing
/// about which mount a path lookup sees. Two or more matching entries for the
/// same decoded mount point are therefore reported as ambiguous
/// (`InvalidData`) and never resolved to a "topmost" one. A private helper
/// mountpoint plus its per-workspace reservation rules out internal stacking, so
/// rejecting a stack is the conservative answer rather than a guess.
fn mount_id_in(mountinfo: &str, mountpoint: &Path) -> io::Result<Option<MountId>> {
    let target = mountpoint.as_os_str().as_bytes();
    let mut found: Option<MountId> = None;
    for line in mountinfo.lines() {
        let mut fields = line.split(' ');
        let Some(id) = fields.next().and_then(|field| field.parse::<MountId>().ok()) else {
            continue;
        };
        // Field 1 is the mount ID and field 5 the mount point. A short line is
        // not an error, it just cannot describe the mount asked about.
        let Some(point) = fields.nth(3) else { continue };
        if unescape_mountinfo(point).as_slice() != target {
            continue;
        }
        if found.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "multiple mounts recorded at the owned FUSE mountpoint",
            ));
        }
        found = Some(id);
    }
    Ok(found)
}

/// Undo the octal escapes mountinfo uses for spaces, tabs, newlines and
/// backslashes.
fn unescape_mountinfo(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let octal = index + 3 < bytes.len()
            && bytes[index] == b'\\'
            && bytes[index + 1..index + 4].iter().all(|byte| (b'0'..=b'7').contains(byte));
        if octal {
            // Widen to u32 so a maximal octal escape cannot overflow a byte.
            let value = u32::from(bytes[index + 1] - b'0') * 64
                + u32::from(bytes[index + 2] - b'0') * 8
                + u32::from(bytes[index + 3] - b'0');
            out.push(value as u8);
            index += 4;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

/// Spawn the bounded per-mount dispatcher and mount `overlay` in the background.
///
/// Every mount owns its own queue and actor, so a slow read on one mount cannot
/// stall another mount. Queue limits are shared per helper and per process.
///
/// This is the legacy option list (no `AutoUnmount`): used by the in-process
/// service mount, whose unmount is driven by the owning API process.
pub fn spawn(overlay: Overlay, mountpoint: &Path) -> io::Result<MountHandle> {
    spawn_with(overlay, mountpoint, false)
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
    spawn_with(overlay, mountpoint, true)
}

pub fn mount(lower: PathBuf, upper: PathBuf, mountpoint: PathBuf) -> io::Result<()> {
    let fs = MountFs::new(Overlay::new(lower, upper)?)?;
    fuser::mount2(fs, mountpoint, &mount_options(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NotManaged;

    impl LazySource for NotManaged {
        fn file(&self, _: &Path) -> io::Result<Option<File>> {
            Ok(None)
        }
    }

    #[test]
    fn unknown_lazy_path_fails_closed_but_git_is_eager() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("worktree.txt"), b"remote placeholder").unwrap();
        let entry = Entry::new(root.path(), Path::new("worktree.txt"), false).unwrap();
        let error = open_lower(Some(&NotManaged), Path::new("worktree.txt"), &entry).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));

        fs::create_dir(root.path().join(".git")).unwrap();
        fs::write(root.path().join(".git/config"), b"[core]").unwrap();
        let entry = Entry::new(root.path(), Path::new(".git/config"), false).unwrap();
        let file = open_lower(Some(&NotManaged), Path::new(".git/config"), &entry).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 6);
    }

    #[test]
    fn freeze_rejects_mutations_without_blocking_reads() {
        let root = tempfile::tempdir().unwrap();
        let lower = root.path().join("lower");
        let upper = root.path().join("upper");
        fs::create_dir_all(&lower).unwrap();
        fs::write(lower.join("file.txt"), b"readable").unwrap();
        let gate = MutationGate::new_with_lease(1, i64::MAX).unwrap();
        let overlay = Overlay::new_with_gate(lower, upper, gate.clone()).unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        std::thread::scope(|scope| {
            let freeze_gate = gate.clone();
            scope.spawn(move || {
                freeze_gate.freeze(|| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                });
            });
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let error = gate.mutation().err().and_then(|error| error.raw_os_error());
            assert_eq!(error, Some(libc::EAGAIN));
            let attr = overlay.attr(Path::new("file.txt"), 2).expect("read metadata ignores the freeze");
            assert_eq!(attr.size, 8);
            release_tx.send(()).unwrap();
        });
        drop(gate.mutation().expect("thaw admits mutations"));
    }

    #[test]
    fn helper_mount_options_add_auto_unmount_without_widening_the_owner_acl() {
        let legacy = mount_options(false);
        assert!(!legacy.contains(&MountOption::AutoUnmount), "the legacy mount keeps its option list");
        let helper = mount_options(true);
        assert!(helper.contains(&MountOption::AutoUnmount), "AutoUnmount is helper-only");
        assert!(helper.contains(&MountOption::DefaultPermissions), "permission checks stay enabled");
        // fuser derives SessionACL from the options it is given, so adding an
        // Allow* option here would widen the session ACL; AutoUnmount alone
        // keeps SessionACL::Owner while fusermount still gets its implicit
        // allow_other for auto_unmount.
        assert!(!helper.contains(&MountOption::AllowOther), "AllowOther must not be added explicitly");
        assert!(!helper.contains(&MountOption::AllowRoot), "AllowRoot must not be added explicitly");
        let stripped: Vec<MountOption> =
            helper.iter().filter(|option| **option != MountOption::AutoUnmount).cloned().collect();
        assert_eq!(stripped, legacy, "the helper adds exactly one option");
    }

    #[test]
    fn mount_handle_offers_a_consuming_joined_teardown_and_a_borrowable_stop() {
        // Compile-time contract only (no mount is created here): the owned
        // helper teardown consumes the handle and returns after the session
        // join, while the legacy non-consuming stop stays callable through a
        // shared borrow for existing callers.
        fn owning(handle: MountHandle) {
            handle.shutdown_and_join();
        }
        fn borrowed(handle: &MountHandle) {
            handle.shutdown();
        }
        let _: fn(MountHandle) = owning;
        let _: fn(&MountHandle) = borrowed;
    }

    #[test]
    fn mountinfo_identity_is_the_single_exact_mount_at_the_owned_path() {
        let mountinfo = "\
36 35 0:32 / /srv/rootyard/workspaces/a/mnt rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
37 35 0:33 / /srv/rootyard/workspaces/a/mnt rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
38 35 0:34 / /srv/rootyard/workspaces/a/mnt-extra rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
39 35 0:35 / /srv/rootyard/workspaces/with\\040space/mnt rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
";
        // Stacked mounts at one path are ambiguous: never pick one, and do not
        // assume the largest (or newest) opaque kernel ID is the visible mount.
        let err = mount_id_in(mountinfo, Path::new("/srv/rootyard/workspaces/a/mnt"))
            .expect_err("stacked mounts must not resolve to one identity");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // The same stack in the reverse ID order is just as ambiguous.
        let reversed = "\
37 35 0:33 / /srv/rootyard/workspaces/a/mnt rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
36 35 0:32 / /srv/rootyard/workspaces/a/mnt rw,relatime - fuse.rootyard-vfs rootyard-vfs rw,user_id=0
";
        assert_eq!(
            mount_id_in(reversed, Path::new("/srv/rootyard/workspaces/a/mnt"))
                .expect_err("stacked mounts are ambiguous in either ID order")
                .kind(),
            io::ErrorKind::InvalidData
        );
        // A single exact match is the owned identity.
        assert_eq!(mount_id_in(mountinfo, Path::new("/srv/rootyard/workspaces/a/mnt-extra")).unwrap(), Some(38));
        // An absent path has no identity at all.
        assert_eq!(mount_id_in(mountinfo, Path::new("/srv/rootyard/workspaces/a")).unwrap(), None);
        // mountinfo escapes whitespace octally; the comparison is on the path.
        assert_eq!(mount_id_in(mountinfo, Path::new("/srv/rootyard/workspaces/with space/mnt")).unwrap(), Some(39));
    }

    #[test]
    fn owned_unmount_requires_the_captured_mount_id() {
        assert!(owns_current_mount(37, Some(37)));
        assert!(!owns_current_mount(37, Some(38)), "a newer mount at the path is not owned");
        assert!(!owns_current_mount(37, None), "an already unmounted path needs no unmount");
    }
}
