//! Transparent Linux FUSE overlay over an immutable snapshot and private CoW layer.
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr, OsString},
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime},
};

const TTL: Duration = Duration::ZERO;

// Every host mutation is relative to a held directory descriptor. A FUSE client
// can rename an upper directory between two callbacks; path checks alone do
// not keep a later open below the upper root.
fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}
fn walk_dir(root: &Path, relative: &Path, create: bool) -> io::Result<File> {
    let mut dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        };
        let name = c_name(name)?;
        let mut fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 && create && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o755) } < 0 {
                return Err(io::Error::last_os_error());
            }
            fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
        }
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        dir = unsafe { File::from_raw_fd(fd) };
    }
    Ok(dir)
}
struct Entry {
    dir: File,
    name: CString,
}
impl Entry {
    fn new(root: &Path, path: &Path, create_parent: bool) -> io::Result<Self> {
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        Ok(Self {
            dir: walk_dir(root, path.parent().unwrap_or(Path::new("")), create_parent)?,
            name: c_name(name)?,
        })
    }
    fn lstat(&self) -> io::Result<fs::Metadata> {
        fs::symlink_metadata(self.proc_path())
    }
    fn proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.dir.as_raw_fd()))
            .join(OsStr::from_bytes(self.name.as_bytes()))
    }
    fn open(&self, flags: i32, mode: u32) -> io::Result<File> {
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                self.name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }
    fn mkdir(&self, mode: u32) -> io::Result<()> {
        if unsafe { libc::mkdirat(self.dir.as_raw_fd(), self.name.as_ptr(), mode) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn unlink(&self, is_dir: bool) -> io::Result<()> {
        let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), flags) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn rename_to(&self, to: &Entry) -> io::Result<()> {
        if unsafe {
            libc::renameat(
                self.dir.as_raw_fd(),
                self.name.as_ptr(),
                to.dir.as_raw_fd(),
                to.name.as_ptr(),
            )
        } < 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn read_link(&self) -> io::Result<PathBuf> {
        fs::read_link(self.proc_path())
    }
}
fn safe_link_at(target: &Path, path: &Path) -> io::Result<()> {
    if target.is_absolute() {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    let mut depth = path.parent().unwrap_or(Path::new("")).components().count();
    for part in target.components() {
        match part {
            Component::Normal(_) => depth += 1,
            Component::CurDir => {}
            Component::ParentDir => {
                if depth == 0 {
                    return Err(io::Error::from_raw_os_error(libc::EPERM));
                }
                depth -= 1;
            }
            _ => return Err(io::Error::from_raw_os_error(libc::EPERM)),
        }
    }
    Ok(())
}

pub struct Overlay {
    lower: PathBuf,
    upper: PathBuf,
    paths: BTreeMap<u64, PathBuf>,
    ids: BTreeMap<PathBuf, u64>,
    next: u64,
    whiteouts: BTreeSet<PathBuf>,
}
impl Overlay {
    pub fn new(lower: PathBuf, upper: PathBuf) -> io::Result<Self> {
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
        let whiteouts = if upper.join(".rootyard-whiteouts.json").exists() {
            serde_json::from_slice::<Vec<String>>(&fs::read(
                upper.join(".rootyard-whiteouts.json"),
            )?)
            .map_err(io::Error::other)?
            .into_iter()
            .map(PathBuf::from)
            .collect()
        } else {
            BTreeSet::new()
        };
        Ok(Self {
            lower,
            upper,
            paths,
            ids,
            next: 2,
            whiteouts,
        })
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
        self.paths
            .get(&ino)
            .cloned()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
    }
    fn child(&self, parent: u64, name: &OsStr) -> io::Result<PathBuf> {
        if name.as_bytes().is_empty()
            || name.as_bytes().contains(&b'/')
            || name == "."
            || name == ".."
            || name == ".rootyard-whiteouts.json"
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
                    let mut output = to.open(
                        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                        m.permissions().mode() & 0o777,
                    )?;
                    io::copy(&mut input, &mut output)?;
                    output.sync_all()?;
                } else if m.file_type().is_symlink() {
                    let target = source.read_link()?;
                    safe_link_at(&target, p)?;
                    let target = c_name(target.as_os_str())?;
                    if unsafe {
                        libc::symlinkat(target.as_ptr(), to.dir.as_raw_fd(), to.name.as_ptr())
                    } < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
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
                    if name != ".rootyard-whiteouts.json" && name != ".rootyard-whiteouts.tmp" {
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
        let names: Vec<String> = self
            .whiteouts
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let tmp = self.upper.join(".rootyard-whiteouts.tmp");
        fs::write(&tmp, serde_json::to_vec(&names)?)?;
        File::open(&tmp)?.sync_all()?;
        fs::rename(tmp, self.upper.join(".rootyard-whiteouts.json"))?;
        File::open(&self.upper)?.sync_all()
    }
    fn err(e: io::Error) -> i32 {
        e.raw_os_error().unwrap_or(libc::EIO)
    }
}

impl Filesystem for Overlay {
    fn lookup(&mut self, _: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let result = (|| {
            let p = self.child(parent, name)?;
            let ino = self.ino(&p);
            self.attr(&p, ino)
        })();
        match result {
            Ok(attr) => reply.entry(&TTL, &attr, 0),
            Err(e) => reply.error(Self::err(e)),
        }
    }
    fn getattr(&mut self, _: &Request<'_>, ino: u64, _: Option<u64>, reply: ReplyAttr) {
        let result = self.rel(ino).and_then(|p| self.attr(&p, ino));
        match result {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(Self::err(e)),
        }
    }
    fn readdir(
        &mut self,
        _: &Request<'_>,
        ino: u64,
        _: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let result = (|| -> io::Result<Vec<(u64, FileType, OsString)>> {
            let p = self.rel(ino)?;
            if self.attr(&p, ino)?.kind != FileType::Directory {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
            }
            let parent = p.parent().unwrap_or(&p).to_path_buf();
            let parent_ino = self.ino(&parent);
            let mut out = vec![
                (ino, FileType::Directory, OsString::from(".")),
                (parent_ino, FileType::Directory, OsString::from("..")),
            ];
            let names = self.children(&p)?;
            for name in names {
                if let Ok(child) = self.child(ino, &name) {
                    let child_ino = self.ino(&child);
                    if let Ok(attr) = self.attr(&child, child_ino) {
                        out.push((attr.ino, attr.kind, name));
                    }
                }
            }
            Ok(out)
        })();
        match result {
            Ok(rows) => {
                for (idx, (child, kind, name)) in
                    rows.into_iter().enumerate().skip(offset.max(0) as usize)
                {
                    if reply.add(child, (idx + 1) as i64, kind, name) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(e) => reply.error(Self::err(e)),
        }
    }
    fn readlink(&mut self, _: &Request<'_>, ino: u64, reply: ReplyData) {
        let result = self
            .rel(ino)
            .and_then(|p| self.selected(&p))
            .and_then(|path| self.host_entry(&path, false)?.read_link());
        match result {
            Ok(p) => reply.data(p.as_os_str().as_bytes()),
            Err(e) => reply.error(Self::err(e)),
        }
    }
    fn open(&mut self, _: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let result = (|| {
            let p = self.rel(ino)?;
            if flags & (libc::O_WRONLY | libc::O_RDWR) != 0 {
                self.prepare(&p)?;
            } else {
                self.selected(&p)?;
            }
            Ok::<_, io::Error>(())
        })();
        match result {
            Ok(()) => reply.opened(0, 0),
            Err(e) => reply.error(Self::err(e)),
        }
    }
    fn read(
        &mut self,
        _: &Request<'_>,
        ino: u64,
        _: u64,
        offset: i64,
        size: u32,
        _: i32,
        _: Option<u64>,
        reply: ReplyData,
    ) {
        let result = (|| {
            let p = self.rel(ino)?;
            let path = self.selected(&p)?;
            let file = self.host_entry(&path, false)?.open(libc::O_RDONLY, 0)?;
            let mut buf = vec![0; size.min(1024 * 1024) as usize];
            let count = file.read_at(&mut buf, offset.max(0) as u64)?;
            buf.truncate(count);
            Ok::<_, io::Error>(buf)
        })();
        match result {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(Self::err(e)),
        }
    }
    fn write(
        &mut self,
        _: &Request<'_>,
        ino: u64,
        _: u64,
        offset: i64,
        data: &[u8],
        _: u32,
        _: i32,
        _: Option<u64>,
        reply: ReplyWrite,
    ) {
        let result = (|| {
            let p = self.rel(ino)?;
            let file = self.prepare(&p)?.open(libc::O_WRONLY, 0)?;
            let count = file.write_at(data, offset.max(0) as u64)?;
            file.sync_data()?;
            Ok::<_, io::Error>(count)
        })();
        match result {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(Self::err(e)),
        }
    }
    fn setattr(
        &mut self,
        _: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        _: Option<u32>,
        _: Option<u32>,
        size: Option<u64>,
        _: Option<TimeOrNow>,
        _: Option<TimeOrNow>,
        _: Option<SystemTime>,
        _: Option<u64>,
        _: Option<SystemTime>,
        _: Option<SystemTime>,
        _: Option<SystemTime>,
        _: Option<u32>,
        reply: ReplyAttr,
    ) {
        let result = (|| {
            let p = self.rel(ino)?;
            if mode.is_some() || size.is_some() {
                let entry = self.prepare(&p)?;
                if let Some(mode) = mode {
                    entry
                        .open(libc::O_RDONLY, 0)?
                        .set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
                }
                if let Some(size) = size {
                    entry.open(libc::O_WRONLY, 0)?.set_len(size)?;
                }
            }
            self.attr(&p, ino)
        })();
        match result {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(Self::err(e)),
        }
    }
    fn create(
        &mut self,
        _: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _: u32,
        _: i32,
        reply: ReplyCreate,
    ) {
        let result = (|| {
            let p = self.child(parent, name)?;
            if self.selected(&p).is_ok() {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            let entry = Entry::new(&self.upper, &p, true)?;
            entry.open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode & 0o777)?;
            self.whiteouts.remove(&p);
            let ino = self.ino(&p);
            self.attr(&p, ino)
        })();
        match result {
            Ok(attr) => reply.created(&TTL, &attr, 0, 0, 0),
            Err(e) => reply.error(Self::err(e)),
        }
    }
    fn mkdir(
        &mut self,
        _: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _: u32,
        reply: ReplyEntry,
    ) {
        let result = (|| {
            let p = self.child(parent, name)?;
            if self.selected(&p).is_ok() {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
            Entry::new(&self.upper, &p, true)?.mkdir(mode & 0o777)?;
            self.whiteouts.remove(&p);
            let ino = self.ino(&p);
            self.attr(&p, ino)
        })();
        match result {
            Ok(attr) => reply.entry(&TTL, &attr, 0),
            Err(e) => reply.error(Self::err(e)),
        }
    }
    fn unlink(&mut self, _: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let result = (|| {
            let p = self.child(parent, name)?;
            let selected = self.selected(&p)?;
            if self.host_entry(&selected, false)?.lstat()?.is_dir() {
                return Err(io::Error::from_raw_os_error(libc::EISDIR));
            }
            if selected.starts_with(&self.upper) {
                self.host_entry(&selected, false)?.unlink(false)?;
            }
            if self.checked_entry(&self.lower, &p).is_ok() {
                self.whiteouts.insert(p);
                self.save_whiteouts()?;
            }
            Ok::<_, io::Error>(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(Self::err(e)),
        }
    }
    fn rmdir(&mut self, _: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let result = (|| {
            let p = self.child(parent, name)?;
            let selected = self.selected(&p)?;
            if !self.host_entry(&selected, false)?.lstat()?.is_dir() {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
            }
            if !self.children(&p)?.is_empty() {
                return Err(io::Error::from_raw_os_error(libc::ENOTEMPTY));
            }
            if selected.starts_with(&self.upper) {
                self.host_entry(&selected, false)?.unlink(true)?;
            }
            if self.checked_entry(&self.lower, &p).is_ok() {
                self.whiteouts.insert(p);
                self.save_whiteouts()?;
            }
            Ok::<_, io::Error>(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(Self::err(e)),
        }
    }
    fn rename(
        &mut self,
        _: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        let result = (|| {
            if flags != 0 {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            let src = self.child(parent, name)?;
            let dst = self.child(newparent, newname)?;
            if src == dst {
                return Ok(());
            }
            if dst.starts_with(&src) {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            self.validate_move(&src, &dst, 0)?;
            self.materialize_tree(&src, 0)?;
            let from = Entry::new(&self.upper, &src, false)?;
            let to = Entry::new(&self.upper, &dst, true)?;
            from.rename_to(&to)?;
            for (ino, old) in self.paths.clone() {
                if old == src || old.starts_with(&src) {
                    let suffix = old.strip_prefix(&src).unwrap();
                    let new = if suffix.as_os_str().is_empty() {
                        dst.clone()
                    } else {
                        dst.join(suffix)
                    };
                    self.ids.remove(&old);
                    self.ids.insert(new.clone(), ino);
                    self.paths.insert(ino, new);
                }
            }
            if self.checked_entry(&self.lower, &src).is_ok() {
                self.whiteouts.insert(src.clone());
            }
            self.whiteouts.remove(&dst);
            self.save_whiteouts()?;
            Ok::<_, io::Error>(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(Self::err(e)),
        }
    }
}

pub fn mount(lower: PathBuf, upper: PathBuf, mountpoint: PathBuf) -> io::Result<()> {
    let fs = Overlay::new(lower, upper)?;
    fuser::mount2(
        fs,
        mountpoint,
        &[
            MountOption::FSName("rootyard-vfs".into()),
            MountOption::DefaultPermissions,
        ],
    )
}
