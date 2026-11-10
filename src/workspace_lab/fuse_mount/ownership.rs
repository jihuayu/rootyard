//! Kernel mount identity for owned FUSE mounts.
//!
//! `/proc/self/mountinfo` is the only source consulted: an owned teardown must
//! unmount exactly the mount this process created, never whichever mount now
//! sits at the same path.
use std::{ffi::CString, fs, io, os::unix::ffi::OsStrExt, path::Path};

use super::MountId;

/// Normal (non-lazy) unmount of exactly the mount this handle captured.
///
/// Fails closed in every other case: an unreadable mount table and a path that
/// now holds a different mount (or an ambiguous stack of mounts) are reported
/// instead of guessed at; an already-unmounted path is a no-op. `MNT_DETACH`
/// and a `fusermount -u` fallback are deliberately not used: a lazy detach
/// leaves the session thread parked on its descriptor, and a blind path unmount
/// could remove a mount this handle does not own.
pub(crate) fn unmount_owned(mountpoint: &Path, mount_id: MountId) -> io::Result<()> {
    match mount_id_at_path(mountpoint)? {
        Some(current) if owns_current_mount(mount_id, Some(current)) => {
            let path = CString::new(mountpoint.as_os_str().as_bytes())
                .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
            // SAFETY: `path` is NUL-terminated, and flags 0 request a normal,
            // non-lazy unmount of the identity verified above.
            if unsafe { libc::umount2(path.as_ptr(), 0) } == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
        }
        // Already unmounted: nothing to remove, `join` still reaps the session.
        None => Ok(()),
        // A different mount owns the path now; never unmount a foreign mount.
        Some(_) => Err(io::Error::from_raw_os_error(libc::EBUSY)),
    }
}

/// True only for the exact mount this handle created.
pub(crate) fn owns_current_mount(captured: MountId, current: Option<MountId>) -> bool {
    current == Some(captured)
}

pub(crate) fn mount_id_at_path(mountpoint: &Path) -> io::Result<Option<MountId>> {
    mount_id_in(&fs::read_to_string("/proc/self/mountinfo")?, mountpoint)
}

/// The single mount recorded exactly at `mountpoint` in a `mountinfo` text.
///
/// Kernel mount IDs are opaque and may be reused, so numeric order says nothing
/// about which mount a path lookup sees. Two or more matching entries for the
/// same decoded mount point are therefore reported as ambiguous
/// (`InvalidData`) and never resolved to a "topmost" one. A private helper
/// mountpoint plus its per-workspace reservation rules out internal stacking, so
/// rejecting a stack is the conservative answer rather than a guess.
pub(super) fn mount_id_in(mountinfo: &str, mountpoint: &Path) -> io::Result<Option<MountId>> {
    let target = mountpoint.as_os_str().as_bytes();
    let mut found: Option<MountId> = None;
    for line in mountinfo.lines() {
        let mut fields = line.split(' ');
        let Some(id) = fields.next().and_then(|field| field.parse::<MountId>().ok()) else {
            continue;
        };
        // Field 1 is the mount ID and field 5 the mount point. A short line is
        // not an error, it just cannot describe the mount asked about.
        let Some(point) = fields.nth(3) else { continue };
        if unescape_mountinfo(point).as_slice() != target {
            continue;
        }
        if found.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "multiple mounts recorded at the owned FUSE mountpoint",
            ));
        }
        found = Some(id);
    }
    Ok(found)
}

/// Undo the octal escapes mountinfo uses for spaces, tabs, newlines and
/// backslashes.
fn unescape_mountinfo(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let octal = index + 3 < bytes.len()
            && bytes[index] == b'\\'
            && bytes[index + 1..index + 4].iter().all(|byte| (b'0'..=b'7').contains(byte));
        if octal {
            // Widen to u32 so a maximal octal escape cannot overflow a byte.
            let value = u32::from(bytes[index + 1] - b'0') * 64
                + u32::from(bytes[index + 2] - b'0') * 8
                + u32::from(bytes[index + 3] - b'0');
            out.push(value as u8);
            index += 4;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}
