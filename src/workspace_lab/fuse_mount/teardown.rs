//! Closed failure surface for owner-preserving FUSE teardown.
//!
//! The unmount identity check stays in `ownership`; this module only keeps the
//! typed stage/errno class and its exact human-readable diagnostics together.

use std::{fmt, io};

use super::ownership::UnmountOwnedError;

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
