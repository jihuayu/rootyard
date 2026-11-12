//! Synchronized whiteout set backed by `upper/.rootyard-whiteouts.json`.
//!
//! Direct upper-layer rollbacks (`PutRollback` / `GitRollback`) may atomically
//! restore `.rootyard-whiteouts.json` while FUSE is fenced (`EROFS`). Tracking
//! the on-disk inode/timestamp/size stamp and observed lease epoch ensures
//! ungated reads and post-handoff mutations reload external whiteout updates
//! before consulting or rewriting `.rootyard-whiteouts.json`.
use super::fuse_io::Entry;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, PoisonError},
};

const WHITEOUT_FILE: &str = ".rootyard-whiteouts.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

impl FileStamp {
    fn from_meta(meta: &fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.len(),
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        }
    }
}

struct WhiteoutInner {
    entries: BTreeSet<PathBuf>,
    stamp: Option<FileStamp>,
    epoch: i64,
}

pub(super) struct WhiteoutStore {
    upper: PathBuf,
    inner: Mutex<WhiteoutInner>,
}

impl WhiteoutStore {
    pub(super) fn load(upper: PathBuf, epoch: i64) -> io::Result<Self> {
        let (entries, stamp) = read_disk(&upper)?;
        Ok(Self { upper, inner: Mutex::new(WhiteoutInner { entries, stamp, epoch }) })
    }

    fn lock(&self) -> MutexGuard<'_, WhiteoutInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn sync(&self, epoch: i64) -> io::Result<()> {
        let mut guard = self.lock();
        self.sync_locked(&mut guard, epoch)
    }

    pub(super) fn is_hidden(&self, p: &Path) -> bool {
        let guard = self.lock();
        guard.entries.iter().any(|w| p == w || p.starts_with(w))
    }

    pub(super) fn clear_path(&self, epoch: i64, p: &Path) -> io::Result<()> {
        let mut guard = self.lock();
        self.sync_locked(&mut guard, epoch)?;
        if guard.entries.remove(p) {
            self.save_locked(&mut guard, epoch)?;
        }
        Ok(())
    }

    pub(super) fn insert_path(&self, epoch: i64, p: PathBuf) -> io::Result<()> {
        let mut guard = self.lock();
        self.sync_locked(&mut guard, epoch)?;
        guard.entries.insert(p);
        self.save_locked(&mut guard, epoch)
    }

    pub(super) fn apply_rename(&self, epoch: i64, hide_src: Option<PathBuf>, dst: &Path) -> io::Result<()> {
        let mut guard = self.lock();
        self.sync_locked(&mut guard, epoch)?;
        if let Some(src) = hide_src {
            guard.entries.insert(src);
        }
        guard.entries.remove(dst);
        self.save_locked(&mut guard, epoch)
    }

    fn sync_locked(&self, guard: &mut WhiteoutInner, epoch: i64) -> io::Result<()> {
        let disk_stamp = match fs::symlink_metadata(self.upper.join(WHITEOUT_FILE)) {
            Ok(meta) if meta.is_file() => Some(FileStamp::from_meta(&meta)),
            Ok(_) => return Err(io::Error::from_raw_os_error(libc::EPERM)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };
        if disk_stamp == guard.stamp && epoch == guard.epoch {
            return Ok(());
        }
        let (entries, stamp) = read_disk(&self.upper)?;
        guard.entries = entries;
        guard.stamp = stamp;
        guard.epoch = epoch;
        Ok(())
    }

    fn save_locked(&self, guard: &mut WhiteoutInner, epoch: i64) -> io::Result<()> {
        let names: Vec<String> = guard.entries.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        let tmp_name = format!(".rootyard-whiteouts.{}.tmp", uuid::Uuid::new_v4());
        let tmp = Entry::new(&self.upper, Path::new(&tmp_name), false)?;
        let target = Entry::new(&self.upper, Path::new(WHITEOUT_FILE), false)?;
        let mut file = tmp.open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?;
        file.write_all(&serde_json::to_vec(&names)?)?;
        file.sync_all()?;
        tmp.rename_to(&target)?;
        let post_meta = target.lstat()?;
        File::open(&self.upper)?.sync_all()?;
        guard.stamp = Some(FileStamp::from_meta(&post_meta));
        guard.epoch = epoch;
        Ok(())
    }
}

fn read_disk(upper: &Path) -> io::Result<(BTreeSet<PathBuf>, Option<FileStamp>)> {
    match fs::symlink_metadata(upper.join(WHITEOUT_FILE)) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return Err(io::Error::from_raw_os_error(libc::EPERM)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok((BTreeSet::new(), None)),
        Err(err) => return Err(err),
    }
    let entry = Entry::new(upper, Path::new(WHITEOUT_FILE), false)?;
    let mut file = entry.open(libc::O_RDONLY, 0)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    let entries =
        serde_json::from_slice::<Vec<String>>(&raw).map_err(io::Error::other)?.into_iter().map(PathBuf::from).collect();
    Ok((entries, Some(FileStamp::from_meta(&meta))))
}
