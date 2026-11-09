//! OS resource limits for native Git children.
//!
//! Limits are installed in the child between `fork` and `exec` through
//! [`tokio::process::Command::pre_exec`]. Only async-signal-safe libc calls are
//! made there: `setpgid`, `setrlimit` and `prctl`. No allocation, no logging and
//! no environment/argument inspection happens in the child.
//!
//! These limits are per direct child. They bound that process and everything it
//! inherits (descendants share the same limits after `exec`), but they are not a
//! cgroup: the gateway does not claim to enforce total process-tree RSS beyond
//! each process's `RLIMIT_AS`. Process-group teardown is owned by
//! [`super::process_guard`].
use std::io;

use tokio::process::Command;

use super::config::BlobGitNativeLimits;
use crate::ref_store::core::pack_commit::RegisteredPack;

/// Install the process group and OS limits for one native child.
///
/// The same limits are installed even for short commands (`git init`,
/// `rev-parse`), so an unexpected child cannot opt out by being "small".
pub(super) fn apply_native_limits(command: &mut Command, limits: &BlobGitNativeLimits) {
    let cpu_seconds = limits.cpu_seconds;
    let address_space = limits.address_space_bytes;
    let max_file = limits.max_file_bytes;
    let max_open_files = limits.max_open_files;
    // Safety: the closure only calls async-signal-safe libc functions, performs
    // no allocation and never touches shared mutable state.
    unsafe {
        command.pre_exec(move || {
            // Put the child in its own session/process group so cancellation can
            // signal the whole tree, never the gateway's own group. This is also
            // set by `Command::process_group(0)`; repeating it here keeps the
            // guarantee if the platform ignores that builder.
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            set_limit(libc::RLIMIT_CPU as libc::c_int, cpu_seconds)?;
            set_limit(libc::RLIMIT_AS as libc::c_int, address_space)?;
            set_limit(libc::RLIMIT_FSIZE as libc::c_int, max_file)?;
            set_limit(libc::RLIMIT_NOFILE as libc::c_int, max_open_files)?;
            // Never write core files into the private scratch directory.
            set_limit(libc::RLIMIT_CORE as libc::c_int, 0)?;
            #[cfg(target_os = "linux")]
            {
                // If the gateway thread that spawned the child disappears, the
                // child must not outlive the service process.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

fn set_limit(resource: libc::c_int, value: u64) -> io::Result<()> {
    let value = value as libc::rlim_t;
    let limit = libc::rlimit { rlim_cur: value, rlim_max: value };
    // Safety: `limit` lives on the stack for the duration of the call and the
    // resource constant is one of the compile-time libc values.
    if unsafe { libc::setrlimit(resource as _, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Exact registered bytes of one pack pair, captured before a caller copies the
/// pack/index into a `Vec` or a temporary view.
///
/// This is intentionally a pure arithmetic helper: the caller must reserve the
/// returned amount through `BlobGitState::reserve_workspace` *before* asking the
/// materializer for `pack_bytes`/`idx_bytes`.
#[allow(dead_code)]
pub(super) fn registered_pack_workspace_bytes(pack: &RegisteredPack) -> u64 {
    pack.artifacts().iter().map(|artifact| artifact.verified_length()).fold(0u64, u64::saturating_add)
}

/// Conservative workspace reservation for a whole registered pack set, bound to
/// the actual verified artifact lengths rather than a per-request header.
#[allow(dead_code)]
pub(super) fn registered_packs_workspace_bytes(packs: &[RegisteredPack]) -> u64 {
    packs.iter().map(registered_pack_workspace_bytes).fold(0u64, u64::saturating_add)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pack_set_reservation_is_zero() {
        assert_eq!(registered_packs_workspace_bytes(&[]), 0);
    }
}
