//! Confined host filesystem access for the FUSE overlay.
use std::{
    ffi::{CString, OsStr},
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

// Every host mutation is relative to a held directory descriptor. A FUSE client
// can rename an upper directory between two callbacks; path checks alone do
// not keep a later open below the upper root.
pub(super) fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}
pub(super) fn walk_dir(root: &Path, relative: &Path, create: bool) -> io::Result<File> {
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
pub(super) struct Entry {
    dir: File,
    name: CString,
}
impl Entry {
    pub(super) fn new(root: &Path, path: &Path, create_parent: bool) -> io::Result<Self> {
        let name = path.file_name().ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        Ok(Self { dir: walk_dir(root, path.parent().unwrap_or(Path::new("")), create_parent)?, name: c_name(name)? })
    }
    pub(super) fn lstat(&self) -> io::Result<fs::Metadata> {
        fs::symlink_metadata(self.proc_path())
    }
    fn proc_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.dir.as_raw_fd())).join(OsStr::from_bytes(self.name.as_bytes()))
    }
    pub(super) fn open(&self, flags: i32, mode: u32) -> io::Result<File> {
        let fd = unsafe {
            libc::openat(self.dir.as_raw_fd(), self.name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC, mode)
        };
        if fd < 0 { Err(io::Error::last_os_error()) } else { Ok(unsafe { File::from_raw_fd(fd) }) }
    }
    pub(super) fn mkdir(&self, mode: u32) -> io::Result<()> {
        if unsafe { libc::mkdirat(self.dir.as_raw_fd(), self.name.as_ptr(), mode) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    pub(super) fn unlink(&self, is_dir: bool) -> io::Result<()> {
        let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), self.name.as_ptr(), flags) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    pub(super) fn rename_to(&self, to: &Entry) -> io::Result<()> {
        if unsafe { libc::renameat(self.dir.as_raw_fd(), self.name.as_ptr(), to.dir.as_raw_fd(), to.name.as_ptr()) } < 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    pub(super) fn symlink(&self, target: &Path) -> io::Result<()> {
        let target = c_name(target.as_os_str())?;
        if unsafe { libc::symlinkat(target.as_ptr(), self.dir.as_raw_fd(), self.name.as_ptr()) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    pub(super) fn read_link(&self) -> io::Result<PathBuf> {
        fs::read_link(self.proc_path())
    }
}
pub(super) fn safe_link_at(target: &Path, path: &Path) -> io::Result<()> {
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
