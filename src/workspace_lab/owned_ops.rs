//! Owned kernel operations and owned replies crossing the shim → actor boundary.
//!
//! A FUSE shim callback runs on the session thread and must not execute overlay
//! work, wait for a gate, or hold a thread-local `MutationGuard`. It copies the
//! request payload into one of these variants and moves the reply with it. Every
//! `fuser` reply type is `Send`, so the actor and the deferred read jobs can own
//! the reply and send it exactly once from their own thread.
use super::*;
use fuser::{ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite};
use std::ffi::OsString;

/// One queue-provided operation with its reply and copied payload.
pub(super) enum OwnedOp {
    Lookup { parent: u64, name: OsString, reply: ReplyEntry },
    Getattr { ino: u64, reply: ReplyAttr },
    Readdir { ino: u64, offset: i64, reply: ReplyDirectory },
    Readlink { ino: u64, reply: ReplyData },
    Open { ino: u64, flags: i32, reply: ReplyOpen },
    Read { ino: u64, offset: i64, size: u32, reply: ReplyData },
    Write { ino: u64, offset: i64, data: Vec<u8>, reply: ReplyWrite },
    Setattr { ino: u64, mode: Option<u32>, size: Option<u64>, reply: ReplyAttr },
    Create { parent: u64, name: OsString, mode: u32, reply: ReplyCreate },
    Mkdir { parent: u64, name: OsString, mode: u32, reply: ReplyEntry },
    Unlink { parent: u64, name: OsString, reply: ReplyEmpty },
    Rmdir { parent: u64, name: OsString, reply: ReplyEmpty },
    Rename { parent: u64, name: OsString, newparent: u64, newname: OsString, flags: u32, reply: ReplyEmpty },
}

impl OwnedOp {
    /// Mutations are the operations that must be admitted by the gate exactly
    /// once. Write-flagged `open` is a mutation because it CoW-materializes the
    /// path; a read-only open is not.
    pub(super) fn is_mutation(&self) -> bool {
        match self {
            Self::Write { .. }
            | Self::Setattr { .. }
            | Self::Create { .. }
            | Self::Mkdir { .. }
            | Self::Unlink { .. }
            | Self::Rmdir { .. }
            | Self::Rename { .. } => true,
            Self::Open { flags, .. } => flags & (libc::O_WRONLY | libc::O_RDWR) != 0,
            Self::Lookup { .. } | Self::Getattr { .. } | Self::Readdir { .. } | Self::Readlink { .. } | Self::Read { .. } => {
                false
            }
        }
    }

    /// Bytes charged against the per-mount and global queue budgets. It counts
    /// the copied name/data payload plus a fixed per-operation bookkeeping cost,
    /// so a flood of tiny operations cannot bypass the operation cap.
    pub(super) fn payload_bytes(&self) -> usize {
        const OVERHEAD: usize = 192;
        let data = match self {
            Self::Write { data, .. } => data.len(),
            _ => 0,
        };
        let names = match self {
            Self::Lookup { name, .. }
            | Self::Create { name, .. }
            | Self::Mkdir { name, .. }
            | Self::Unlink { name, .. }
            | Self::Rmdir { name, .. } => name.as_bytes().len(),
            Self::Rename { name, newname, .. } => name.as_bytes().len() + newname.as_bytes().len(),
            _ => 0,
        };
        OVERHEAD + data + names
    }

    /// Consume the operation and reply with one errno. Used for queue saturation,
    /// shutdown, fence and freeze-drain paths; the reply is never dropped unsent.
    pub(super) fn fail(self, errno: i32) {
        match self {
            Self::Lookup { reply, .. }
            | Self::Mkdir { reply, .. } => reply.error(errno),
            Self::Getattr { reply, .. } | Self::Setattr { reply, .. } => reply.error(errno),
            Self::Readdir { reply, .. } => reply.error(errno),
            Self::Readlink { reply, .. } | Self::Read { reply, .. } => reply.error(errno),
            Self::Open { reply, .. } => reply.error(errno),
            Self::Write { reply, .. } => reply.error(errno),
            Self::Create { reply, .. } => reply.error(errno),
            Self::Unlink { reply, .. } | Self::Rmdir { reply, .. } | Self::Rename { reply, .. } => reply.error(errno),
        }
    }

    pub(super) fn fail_io(self, error: io::Error) {
        self.fail(Overlay::err(error));
    }
}
