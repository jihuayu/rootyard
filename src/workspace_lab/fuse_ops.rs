//! Kernel FUSE operations over the confined overlay.
use super::*;
use std::os::unix::fs::FileExt;

macro_rules! mutation_guard {
    ($self:ident, $reply:ident) => {
        let gate_owner = $self.gate.clone();
        let _mutation_guard = match gate_owner.mutation() {
            Ok(guard) => guard,
            Err(error) => {
                $reply.error(Overlay::err(error));
                return;
            }
        };
    };
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
        let gate_owner = self.gate.clone();
        let _mutation_guard = if flags & (libc::O_WRONLY | libc::O_RDWR) != 0 {
            Some(match gate_owner.mutation() {
                Ok(guard) => guard,
                Err(error) => {
                    reply.error(Overlay::err(error));
                    return;
                }
            })
        } else {
            None
        };
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
        mutation_guard!(self, reply);
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
        mutation_guard!(self, reply);
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
        mutation_guard!(self, reply);
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
        mutation_guard!(self, reply);
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
        mutation_guard!(self, reply);
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
        mutation_guard!(self, reply);
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
        mutation_guard!(self, reply);
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
