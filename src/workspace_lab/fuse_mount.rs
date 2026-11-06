//! Transparent Linux FUSE overlay over an immutable snapshot and private CoW layer.
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use std::{
    collections::{BTreeMap, BTreeSet},
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
        Arc, RwLock,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, SystemTime},
};

const TTL: Duration = Duration::ZERO;

pub struct MutationGate {
    lock: RwLock<()>,
    writable_until: AtomicI64,
}
impl MutationGate {
    pub fn new(writable_until: i64) -> Arc<Self> {
        Arc::new(Self { lock: RwLock::new(()), writable_until: AtomicI64::new(writable_until) })
    }
    pub fn update(&self, until: i64) {
        self.writable_until.store(until, Ordering::Release);
    }
    pub fn freeze<T>(&self, work: impl FnOnce() -> T) -> T {
        let _guard = self.lock.write().unwrap_or_else(std::sync::PoisonError::into_inner);
        work()
    }
    fn mutation(&self) -> io::Result<std::sync::RwLockReadGuard<'_, ()>> {
        let guard = self.lock.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(io::Error::other)?.as_secs() as i64;
        if now >= self.writable_until.load(Ordering::Acquire) {
            return Err(io::Error::from_raw_os_error(libc::EROFS));
        }
        Ok(guard)
    }
}

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
}
impl Overlay {
    pub fn new(lower: PathBuf, upper: PathBuf) -> io::Result<Self> {
        Self::new_with_gate(lower, upper, MutationGate::new(i64::MAX))
    }
    pub fn new_with_gate(lower: PathBuf, upper: PathBuf, gate: Arc<MutationGate>) -> io::Result<Self> {
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
        Ok(Self { lower, upper, paths, ids, next: 2, whiteouts, gate })
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
        if to.lstat().is_err() {
            if let Ok(from) = self.selected(p) {
                let source = self.host_entry(&from, false)?;
                let m = source.lstat()?;
                if m.is_file() {
                    let mut input = source.open(libc::O_RDONLY, 0)?;
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
