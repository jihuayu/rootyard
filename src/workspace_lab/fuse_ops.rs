//! Kernel-facing FUSE shim: copy each request into an owned operation.
//!
//! Nothing here executes overlay work, asks the mutation gate or waits for a
//! queue slot. The shim owns no overlay; the per-mount actor does. Replies are
//! moved into the [`OwnedOp`] and sent by whichever thread ends up executing it.
use super::*;
use super::fuse_dispatch::MountFs;
use fuser::{Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow};
use super::owned_ops::OwnedOp;

impl Filesystem for MountFs {
    fn lookup(&mut self, _: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        self.dispatch(OwnedOp::Lookup { parent, name: name.to_os_string(), reply });
    }
    fn getattr(&mut self, _: &Request<'_>, ino: u64, _: Option<u64>, reply: ReplyAttr) {
        self.dispatch(OwnedOp::Getattr { ino, reply });
    }
    fn readdir(&mut self, _: &Request<'_>, ino: u64, _: u64, offset: i64, reply: ReplyDirectory) {
        self.dispatch(OwnedOp::Readdir { ino, offset, reply });
    }
    fn readlink(&mut self, _: &Request<'_>, ino: u64, reply: ReplyData) {
        self.dispatch(OwnedOp::Readlink { ino, reply });
    }
    fn open(&mut self, _: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        self.dispatch(OwnedOp::Open { ino, flags, reply });
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
        self.dispatch(OwnedOp::Read { ino, offset, size, reply });
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
        self.dispatch(OwnedOp::Write { ino, offset, data: data.to_vec(), reply });
    }
    #[allow(clippy::too_many_arguments)]
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
        self.dispatch(OwnedOp::Setattr { ino, mode, size, reply });
    }
    fn create(&mut self, _: &Request<'_>, parent: u64, name: &OsStr, mode: u32, _: u32, _: i32, reply: ReplyCreate) {
        self.dispatch(OwnedOp::Create { parent, name: name.to_os_string(), mode, reply });
    }
    fn mkdir(&mut self, _: &Request<'_>, parent: u64, name: &OsStr, mode: u32, _: u32, reply: ReplyEntry) {
        self.dispatch(OwnedOp::Mkdir { parent, name: name.to_os_string(), mode, reply });
    }
    fn unlink(&mut self, _: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.dispatch(OwnedOp::Unlink { parent, name: name.to_os_string(), reply });
    }
    fn rmdir(&mut self, _: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.dispatch(OwnedOp::Rmdir { parent, name: name.to_os_string(), reply });
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
        self.dispatch(OwnedOp::Rename {
            parent,
            name: name.to_os_string(),
            newparent,
            newname: newname.to_os_string(),
            flags,
            reply,
        });
    }
}
