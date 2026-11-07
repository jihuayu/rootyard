//! Overlay content operations with no `fuser::Request` and no kernel reply.
//!
//! The kernel-facing shim in `fuse_ops` only copies the request arguments into
//! an owned operation and hands it to the per-mount actor. The actor is the only
//! thread that owns [`Overlay`] and the only thread that asks the mutation gate
//! for admission, which is why these helpers take plain owned/borrowed
//! arguments instead of a `Request` or the thread-local `MutationGuard`.
use super::*;
use std::os::unix::fs::FileExt;

/// Where a read must be served from.
///
/// Lazy lower-layer files are hydrated on the global read pool instead of the
/// per-mount actor so one unreachable blob cannot stall unrelated mounts or the
/// gate thaw drain.
pub(super) enum ReadPlan {
    Local(PathBuf),
    Lazy { relative: PathBuf, source: Entry, lazy: Arc<dyn LazySource> },
}

impl Overlay {
    pub(super) fn op_lookup(&mut self, parent: u64, name: &OsStr) -> io::Result<FileAttr> {
        let p = self.child(parent, name)?;
        let ino = self.ino(&p);
        self.attr(&p, ino)
    }

    pub(super) fn op_getattr(&self, ino: u64) -> io::Result<FileAttr> {
        self.rel(ino).and_then(|p| self.attr(&p, ino))
    }

    pub(super) fn op_readdir(&mut self, ino: u64) -> io::Result<Vec<(u64, FileType, OsString)>> {
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
    }

    pub(super) fn op_readlink(&self, ino: u64) -> io::Result<Vec<u8>> {
        let p = self.rel(ino)?;
        let path = self.selected(&p)?;
        let target = self.host_entry(&path, false)?.read_link()?;
        Ok(target.as_os_str().as_bytes().to_vec())
    }

    /// CoW-materialize a writable open or verify a read-only target exists.
    pub(super) fn op_open(&mut self, ino: u64, flags: i32) -> io::Result<()> {
        let p = self.rel(ino)?;
        if flags & (libc::O_WRONLY | libc::O_RDWR) != 0 {
            self.prepare(&p)?;
        } else {
            self.selected(&p)?;
        }
        Ok(())
    }

    /// Resolve one read to an immediate host path or a deferred lazy source.
    pub(super) fn read_plan(&self, ino: u64) -> io::Result<ReadPlan> {
        let p = self.rel(ino)?;
        let path = self.selected(&p)?;
        if path.starts_with(&self.lower)
            && !p.starts_with(".git")
            && let Some(lazy) = self.lazy.clone()
        {
            let source = self.host_entry(&path, false)?;
            return Ok(ReadPlan::Lazy { relative: p, source, lazy });
        }
        Ok(ReadPlan::Local(path))
    }

    pub(super) fn read_local(&self, path: &Path, offset: i64, size: u32) -> io::Result<Vec<u8>> {
        let file = self.host_entry(path, false)?.open(libc::O_RDONLY, 0)?;
        read_at(&file, offset, size)
    }

    pub(super) fn op_write(&mut self, ino: u64, offset: i64, data: &[u8]) -> io::Result<u32> {
        let p = self.rel(ino)?;
        let file = self.prepare(&p)?.open(libc::O_WRONLY, 0)?;
        let count = file.write_at(data, offset.max(0) as u64)?;
        file.sync_data()?;
        Ok(count as u32)
    }

    pub(super) fn op_setattr(
        &mut self,
        ino: u64,
        mode: Option<u32>,
        size: Option<u64>,
    ) -> io::Result<FileAttr> {
        let p = self.rel(ino)?;
        if mode.is_some() || size.is_some() {
            let entry = self.prepare(&p)?;
            if let Some(mode) = mode {
                entry.open(libc::O_RDONLY, 0)?.set_permissions(fs::Permissions::from_mode(mode & 0o777))?;
            }
            if let Some(size) = size {
                entry.open(libc::O_WRONLY, 0)?.set_len(size)?;
            }
        }
        self.attr(&p, ino)
    }

    pub(super) fn op_create(&mut self, parent: u64, name: &OsStr, mode: u32) -> io::Result<FileAttr> {
        let p = self.child(parent, name)?;
        if self.selected(&p).is_ok() {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        let entry = Entry::new(&self.upper, &p, true)?;
        entry.open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode & 0o777)?;
        self.whiteouts.remove(&p);
        let ino = self.ino(&p);
        self.attr(&p, ino)
    }

    pub(super) fn op_mkdir(&mut self, parent: u64, name: &OsStr, mode: u32) -> io::Result<FileAttr> {
        let p = self.child(parent, name)?;
        if self.selected(&p).is_ok() {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        Entry::new(&self.upper, &p, true)?.mkdir(mode & 0o777)?;
        self.whiteouts.remove(&p);
        let ino = self.ino(&p);
        self.attr(&p, ino)
    }

    pub(super) fn op_unlink(&mut self, parent: u64, name: &OsStr) -> io::Result<()> {
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
        Ok(())
    }

    pub(super) fn op_rmdir(&mut self, parent: u64, name: &OsStr) -> io::Result<()> {
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
        Ok(())
    }

    pub(super) fn op_rename(
        &mut self,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
    ) -> io::Result<()> {
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
                let new = if suffix.as_os_str().is_empty() { dst.clone() } else { dst.join(suffix) };
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
        Ok(())
    }
}

/// Bounded pread shared by the actor's local path and the global read pool.
pub(super) fn read_at(file: &File, offset: i64, size: u32) -> io::Result<Vec<u8>> {
    let mut buf = vec![0; size.min(1024 * 1024) as usize];
    let count = file.read_at(&mut buf, offset.max(0) as u64)?;
    buf.truncate(count);
    Ok(buf)
}
