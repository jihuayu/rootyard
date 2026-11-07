//! Transparent Linux FUSE overlay over an immutable snapshot and private CoW layer.
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::{OsStr, OsString},
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
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
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

const READ_WORKERS: usize = 4;
const READ_QUEUE_BYTES: usize = 256;
type ReadJob = Box<dyn FnOnce() + Send + 'static>;

/// FUSE request dispatch is a single session thread. Hydration and pread for
/// lazy lower files run on this bounded pool so one unreachable blob cannot
/// block every other operation, and so distinct blobs hydrate concurrently.
struct ReadPool {
    queue: Mutex<VecDeque<ReadJob>>,
    ready: Condvar,
    capacity: usize,
    closed: AtomicBool,
}

impl ReadPool {
    fn new(workers: usize, capacity: usize) -> io::Result<Arc<Self>> {
        let pool = Arc::new(Self {
            queue: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            capacity,
            closed: AtomicBool::new(false),
        });
        for index in 0..workers {
            let worker = pool.clone();
            let result =
                std::thread::Builder::new().name(format!("rootyard-fuse-read-{index}")).spawn(move || worker.run());
            if let Err(error) = result {
                pool.close();
                return Err(error);
            }
        }
        Ok(pool)
    }

    fn execute(&self, job: ReadJob) -> Result<(), ReadJob> {
        let mut queue = self.queue.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.closed.load(Ordering::Acquire) || queue.len() >= self.capacity {
            return Err(job);
        }
        queue.push_back(job);
        drop(queue);
        self.ready.notify_one();
        Ok(())
    }

    fn run(&self) {
        loop {
            let job = {
                let mut queue = self.queue.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                while queue.is_empty() && !self.closed.load(Ordering::Acquire) {
                    queue = self.ready.wait(queue).unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                queue.pop_front()
            };
            match job {
                Some(job) => job(),
                None => return,
            }
        }
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.ready.notify_all();
    }
}

fn read_pool() -> io::Result<&'static ReadPool> {
    static POOL: OnceLock<Result<Arc<ReadPool>, String>> = OnceLock::new();
    POOL.get_or_init(|| ReadPool::new(READ_WORKERS, READ_QUEUE_BYTES).map_err(|e| e.to_string()))
        .as_ref()
        .map(|pool| pool.as_ref())
        .map_err(|error| io::Error::other(error.clone()))
}

fn submit_read(job: ReadJob) {
    match read_pool() {
        Ok(pool) => {
            if let Err(job) = pool.execute(job) {
                // The bounded queue is saturated: preserve correctness by
                // doing this one bounded read on the FUSE thread.
                job();
            }
        }
        Err(_) => job(),
    }
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
pub use super::mutation_gate::{GatePhase, MutationGate, MutationGuard};

#[path = "fuse_io.rs"]
mod fuse_io;
use fuse_io::{Entry, safe_link_at, walk_dir};

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
        Self::new_with_gate(lower, upper, MutationGate::new(i64::MAX))
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

#[path = "fuse_ops.rs"]
mod fuse_ops;

pub fn mount(lower: PathBuf, upper: PathBuf, mountpoint: PathBuf) -> io::Result<()> {
    let fs = Overlay::new(lower, upper)?;
    fuser::mount2(fs, mountpoint, &[MountOption::FSName("rootyard-vfs".into()), MountOption::DefaultPermissions])
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
        let gate = MutationGate::new(i64::MAX);
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
    fn read_pool_executes_distinct_jobs_concurrently() {
        let pool = ReadPool::new(2, 8).unwrap();
        let state = Arc::new((Mutex::new(0usize), Condvar::new()));
        let (sender, receiver) = std::sync::mpsc::channel();
        for _ in 0..2 {
            let state = state.clone();
            let sender = sender.clone();
            pool.execute(Box::new(move || {
                let (lock, ready) = &*state;
                let mut count = lock.lock().unwrap();
                *count += 1;
                ready.notify_all();
                let (count, timed_out) =
                    ready.wait_timeout_while(count, Duration::from_millis(500), |count| *count < 2).unwrap();
                sender.send(*count == 2 && !timed_out.timed_out()).unwrap();
            }))
            .ok()
            .expect("read pool rejected a test job");
        }
        let results: Vec<bool> = (0..2).map(|_| receiver.recv_timeout(Duration::from_secs(2)).unwrap()).collect();
        assert!(results.iter().all(|result| *result), "read pool serialized independent jobs");
    }
}
