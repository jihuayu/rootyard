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
    ffi::{OsStr, OsString},
    fmt,
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
    sync::{Arc, Mutex, OnceLock},
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

/// Identity of an owned mount, captured from `/proc/self/mountinfo`.
///
/// Mount IDs are unique in the kernel's mount-ID allocator, so comparing the
/// captured ID proves that a path still carries the mount this handle created
/// and not a newer mount stacked on top of it.
pub(crate) type MountId = u64;

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
#[path = "fuse_mount/ownership.rs"]
mod ownership;
#[path = "fuse_mount/whiteouts.rs"]
mod whiteouts;

use fuse_dispatch::MountFs;
use fuse_io::{Entry, safe_link_at, walk_dir};
use whiteouts::WhiteoutStore;

// The owned teardown implementation lives in `ownership`; only this module
// (and its tests, through `super`) uses it, so no wider re-export is needed.
use ownership::{UnmountOwnedError, unmount_owned_typed};

pub use self::fuse_dispatch::QueueUsage as DispatchQueueUsage;

/// Live kernel mount. Dropping the session unmounts and drops the shim, which
/// stops the actor and drains every queued reply.
///
/// The handle also remembers the canonical mount point and the kernel mount ID
/// captured when it mounted, so its owned teardown can unmount exactly this
/// mount instead of whichever mount happens to sit at that path by then.
///
/// `session` stays owned until an exact, non-lazy unmount of the captured
/// mount ID has succeeded. A typed teardown failure therefore leaves the live
/// `fuser` mount in this handle instead of dropping it through the path-based
/// destructor fallback.
pub struct MountHandle {
    session: Option<fuser::BackgroundSession>,
    dispatcher: Arc<fuse_dispatch::Dispatcher>,
    /// Canonical mount point the kernel published for this handle.
    mountpoint: PathBuf,
    /// Kernel mount ID captured for this handle when it mounted. `None` is an
    /// unproved post-spawn owner: the live session must be retained, never
    /// dropped through the path/lazy destructor fallback, and can never report
    /// clean teardown until a real exact identity is resolved.
    mount_id: Option<MountId>,
    /// Terminal session-join state. `None` means it has not been attempted.
    session_join: Option<Result<(), SessionJoinFailureKind>>,
}

/// Last-resort retention for an unproved owner that reached an API boundary
/// which can only return `io::Error`. The owner is never dropped here, because
/// `fuser`'s mount destructor may choose a path-only or lazy fallback.
static RETAINED_UNPROVED: OnceLock<Mutex<Vec<MountHandle>>> = OnceLock::new();

fn retain_unproved_owner(owner: MountHandle) {
    RETAINED_UNPROVED
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(owner);
}

/// A post-spawn failure can already own a live `fuser` session even though the
/// exact mount identity was not captured. Legacy callers must transfer that
/// owner, not treat the admission as a pre-spawn no-owner failure.
pub(crate) enum LegacySpawnFailure {
    /// No `BackgroundSession` was created; the pending admission may resolve
    /// without an owner.
    BeforeSession(io::Error),
    /// `spawn_mount2` succeeded, but exact identity could not be proven. The
    /// owner is retained with `mount_id = None` and is a permanent teardown
    /// failure until real ownership is resolved.
    AfterSession { error: io::Error, owner: Box<MountHandle> },
}

impl LegacySpawnFailure {
    /// Preserve the old `io::Result` API without dropping a post-spawn owner.
    fn into_error(self) -> io::Error {
        match self {
            Self::BeforeSession(error) => error,
            Self::AfterSession { error, owner } => {
                retain_unproved_owner(*owner);
                error
            }
        }
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        if self.mount_id.is_none()
            && let Some(session) = self.session.take()
        {
            // There is no exact authority to unmount. Dropping the background
            // session would let fuser's `Mount` destructor attempt a path-only
            // or lazy unmount, which this code cannot prove belongs to us.
            // Retain it instead; the registry/ticket paths do this explicitly,
            // and this is the last-resort boundary retention.
            std::mem::forget(session);
        }
    }
}

/// Small closed class of an owner-preserving teardown failure. It is derived
/// only from the exact stage and errno; it never carries text, paths or a
/// guessed root cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MountTeardownClass {
    /// Mount identity was not captured, the mount probe/mountpoint conversion
    /// refused before the syscall, or the captured ID no longer matched.
    IdentityOrProbe,
    /// The captured ID matched and `umount2(flags = 0)` returned exact `EBUSY`.
    MatchedIdBusy,
    /// The captured ID matched and the unmount syscall returned another error.
    OtherUnmount,
    /// Actor/session join or owner-state failure, before or after the unmount.
    JoinOrState,
}

/// Why the owner-preserving legacy teardown did not reach confirmed
/// quiescence. The handle, its live session and its retained reader stay owned
/// by the caller on every variant except a repeat of an already-recorded
/// session-join failure (the session has already been consumed in that case).
#[derive(Debug)]
pub(crate) enum MountTeardownError {
    ActorJoinPanicked,
    UnmountProbe(io::Error),
    UnmountIdentity,
    UnmountBusy(io::Error),
    UnmountOther(io::Error),
    SessionJoinPanicked,
    SessionJoin(io::Error),
    SessionJoinAlreadyFailed,
    SessionStateInvalid,
    IdentityUnproved,
}

impl MountTeardownError {
    pub(crate) fn class(&self) -> MountTeardownClass {
        match self {
            Self::IdentityUnproved | Self::UnmountProbe(_) | Self::UnmountIdentity => {
                MountTeardownClass::IdentityOrProbe
            }
            Self::UnmountBusy(_) => MountTeardownClass::MatchedIdBusy,
            Self::UnmountOther(_) => MountTeardownClass::OtherUnmount,
            Self::ActorJoinPanicked
            | Self::SessionJoinPanicked
            | Self::SessionJoin(_)
            | Self::SessionJoinAlreadyFailed
            | Self::SessionStateInvalid => MountTeardownClass::JoinOrState,
        }
    }
}

impl From<UnmountOwnedError> for MountTeardownError {
    fn from(error: UnmountOwnedError) -> Self {
        match error {
            UnmountOwnedError::Probe(error) => Self::UnmountProbe(error),
            UnmountOwnedError::Identity => Self::UnmountIdentity,
            UnmountOwnedError::Busy(error) => Self::UnmountBusy(error),
            UnmountOwnedError::Other(error) => Self::UnmountOther(error),
        }
    }
}

impl fmt::Display for MountTeardownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActorJoinPanicked => formatter.write_str("FUSE dispatcher actor panicked during join"),
            Self::UnmountProbe(error) | Self::UnmountBusy(error) | Self::UnmountOther(error) => {
                write!(formatter, "exact FUSE unmount failed: {error}")
            }
            Self::UnmountIdentity => {
                write!(formatter, "exact FUSE unmount failed: {}", io::Error::from_raw_os_error(libc::EBUSY))
            }
            Self::SessionJoinPanicked => formatter.write_str("FUSE session thread panicked during join"),
            Self::SessionJoin(error) => write!(formatter, "FUSE session join failed: {error}"),
            Self::SessionJoinAlreadyFailed => {
                formatter.write_str("FUSE session join previously failed after exact unmount")
            }
            Self::SessionStateInvalid => formatter.write_str("FUSE session ownership state is inconsistent"),
            Self::IdentityUnproved => {
                formatter.write_str("FUSE mount identity was not captured; exact unmount is unproved")
            }
        }
    }
}

impl std::error::Error for MountTeardownError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionJoinFailureKind {
    Panicked,
    Io,
}

enum SessionJoinFailure {
    Panicked,
    Io(io::Error),
}

/// Join the background session without using `BackgroundSession::join`, which
/// unwraps both the thread panic and the session I/O result. The public guard is
/// moved out while the session's remaining fields (including its live `Mount`)
/// stay alive through the join; they drop only after the join returns.
fn join_background_session(session: fuser::BackgroundSession) -> Result<(), SessionJoinFailure> {
    let guard = session.guard;
    match guard.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(SessionJoinFailure::Io(error)),
        Err(_) => Err(SessionJoinFailure::Panicked),
    }
}

impl MountHandle {
    pub fn queue_usage(&self) -> DispatchQueueUsage {
        self.dispatcher.usage()
    }

    /// Quick, non-blocking stop request: fence the mutation gate and close the
    /// per-mount queue. Every reply still sitting in a queue slot fails with
    /// `EIO`; an operation already admitted to the gate may still finish, and a
    /// lazy read already executing in the global read pool re-checks the
    /// shutdown flag after I/O and replies `EIO`.
    ///
    /// This is the non-consuming half: it neither joins the actor nor waits for
    /// the kernel session thread. Callers that own the handle and are about to
    /// exit must use [`MountHandle::teardown_owned_classified`] for normal
    /// shutdown or [`MountHandle::shutdown_and_join`] for explicit
    /// unmount/cancel/publish-failure paths. Neither may drop a live owner
    /// before its teardown completes.
    pub fn request_stop(&self) {
        self.dispatcher.request_stop();
    }

    /// Stop the actor and block until its thread exits.
    ///
    /// This preserves the historical public `shutdown()` behavior: unlike
    /// [`MountHandle::request_stop`], it waits for the actor join. It does not
    /// unmount or join the kernel session, so an owner that is exiting must
    /// still use [`MountHandle::shutdown_and_join`] (or the owner-preserving
    /// typed path).
    pub fn shutdown(&self) {
        self.dispatcher.shutdown();
    }

    /// Owner-preserving, non-panicking legacy teardown.
    ///
    /// The caller keeps this handle until every stage succeeds. The order is
    /// explicit: stop requests, join the actor (which drains admitted mutations
    /// and, while the current deferred-slot lock is held through `run`, waits
    /// for an active lazy read), unmount exactly the captured mount ID with
    /// normal `flags = 0`, and only then consume and join the background
    /// session. The caller keeps the lazy `Reader` alive until this returns.
    ///
    /// A failed actor join or an exact-unmount refusal returns a typed error and
    /// leaves `session` untouched. There is no path-only unmount, lazy fallback
    /// or destructor cleanup on that branch. A session-join panic or I/O error
    /// is terminal failure after the exact unmount and is cached so a retry
    /// cannot relabel it as success.
    pub(crate) fn teardown_owned(&mut self) -> Result<(), MountTeardownError> {
        let Some(mount_id) = self.mount_id else {
            // Stop new work, but no path-only or lazy unmount is permitted for
            // an unproved owner. The live session stays in `self.session`.
            self.request_stop();
            self.dispatcher.join_actor().map_err(|_| MountTeardownError::ActorJoinPanicked)?;
            return Err(MountTeardownError::IdentityUnproved);
        };
        if let Some(outcome) = self.session_join {
            return match outcome {
                Ok(()) => Ok(()),
                Err(SessionJoinFailureKind::Panicked) => Err(MountTeardownError::SessionJoinPanicked),
                Err(SessionJoinFailureKind::Io) => Err(MountTeardownError::SessionJoinAlreadyFailed),
            };
        }
        self.request_stop();
        self.dispatcher.join_actor().map_err(|_| MountTeardownError::ActorJoinPanicked)?;
        // The session is still owned here. A refusal or identity mismatch must
        // propagate without dropping the live `fuser` mount.
        unmount_owned_typed(&self.mountpoint, mount_id).map_err(MountTeardownError::from)?;
        let Some(session) = self.session.take() else {
            return Err(MountTeardownError::SessionStateInvalid);
        };
        match join_background_session(session) {
            Ok(()) => {
                self.session_join = Some(Ok(()));
                Ok(())
            }
            Err(SessionJoinFailure::Panicked) => {
                self.session_join = Some(Err(SessionJoinFailureKind::Panicked));
                Err(MountTeardownError::SessionJoinPanicked)
            }
            Err(SessionJoinFailure::Io(error)) => {
                self.session_join = Some(Err(SessionJoinFailureKind::Io));
                Err(MountTeardownError::SessionJoin(error))
            }
        }
    }

    /// Owner-preserving typed teardown for the normal-shutdown diagnostic.
    ///
    /// It executes the same fences, actor join, identity check, normal unmount
    /// and session join as [`MountHandle::teardown_owned`], and returns only the
    /// private failure class. The live handle remains owned by the caller on
    /// every error so the helper can fail-stop before any Drop.
    pub(crate) fn teardown_owned_classified(&mut self) -> Result<(), MountTeardownClass> {
        self.teardown_owned().map_err(|error| error.class())
    }

    /// Consuming teardown with a completion barrier.
    ///
    /// Stops the dispatcher, joins the actor, unmounts exactly this handle's
    /// captured mount with normal `flags = 0`, then consumes the
    /// `fuser::BackgroundSession` and joins its public guard. That is the
    /// difference from `request_stop()` + drop, where the background session
    /// detaches its join handle and a process exiting right afterwards can
    /// terminate before the unmount completed and leave an owned mount behind.
    ///
    /// The unmount itself is done explicitly and is not delegated to `join`: on
    /// the pure-Rust `AutoUnmount` path, dropping `fuser`'s `Mount` only closes
    /// the fusermount monitor socket, while the session thread still owns its
    /// own `/dev/fuse` clone and sits in `read`. Closing the monitor alone
    /// cannot wake that read, so a join-first teardown would wait for a process
    /// exit that is itself waiting for the join. Unmounting this handle's exact
    /// mount while the session descriptor is still open makes the kernel fail
    /// the parked read with `ENODEV`; the join is then a completion barrier.
    /// `AutoUnmount` remains the crash path (SIGKILL closes the last descriptor
    /// and the monitor socket).
    ///
    /// A refused unmount is never papered over: this consuming wrapper is
    /// fail-closed and panics for explicit unmount/abort and the other existing
    /// callers. The normal-shutdown path uses
    /// [`MountHandle::teardown_owned_classified`] to fail-stop with a reserved
    /// nonzero code before Drop; the owner-preserving registry path uses
    /// [`MountHandle::teardown_owned`] directly and retains the handle instead.
    pub fn shutdown_and_join(mut self) {
        if let Err(error) = self.teardown_owned() {
            panic!("owned FUSE teardown failed: {error}");
        }
    }
}

pub struct Overlay {
    lower: PathBuf,
    upper: PathBuf,
    paths: BTreeMap<u64, PathBuf>,
    ids: BTreeMap<PathBuf, u64>,
    next: u64,
    whiteouts: WhiteoutStore,
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
        let whiteouts = WhiteoutStore::load(upper.clone(), gate.epoch())?;
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
        self.whiteouts.is_hidden(p)
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
        self.whiteouts.sync(self.gate.epoch())?;
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
        self.whiteouts.sync(self.gate.epoch())?;
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
    fn err(e: io::Error) -> i32 {
        e.raw_os_error().unwrap_or(libc::EIO)
    }
}

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

#[cfg(test)]
#[path = "fuse_mount/tests.rs"]
mod tests;
