//! Byte-exact `.pack` header, `.idx` v2 OID table, and raw `.pack` stream
//! `git index-pack --strict -o` bijection verifier (preventing unindexed gap/trailing bytes).

use std::{collections::HashSet, path::Path};
#[cfg(unix)]
use std::{
    ffi::CString,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::PathBuf,
};
#[cfg(unix)]
use uuid::Uuid;

use crate::cache_wake::replica_cache::error::is_lower_hex_exact;

#[cfg(unix)]
use super::cover_git::run_git_bounded;

use super::{
    cover_git::HelperResourceLimits,
    types::{PackObjectFormat, PackfileUriError},
};

const HANDLE_CONFINEMENT_REQUIRED: &str = "directory-handle confinement requires unix openat";

/// Parses and validates `.pack` v2 header + `.idx` v2 fanout/OID table/embedded checksums.
pub(super) fn parse_and_verify_idx_v2_oids(
    pack_bytes: &[u8],
    idx_bytes: &[u8],
    fmt: PackObjectFormat,
    max_objects: usize,
) -> Result<(usize, HashSet<String>), PackfileUriError> {
    let hash_bytes = fmt.oid_hex_len() / 2;
    if pack_bytes.len() < 12 + hash_bytes || &pack_bytes[..4] != b"PACK" {
        return Err(PackfileUriError::IntegrityMismatch("invalid PACK header".to_owned()));
    }
    let pack_ver = u32::from_be_bytes([pack_bytes[4], pack_bytes[5], pack_bytes[6], pack_bytes[7]]);
    if pack_ver != 2 {
        return Err(PackfileUriError::IntegrityMismatch("unsupported PACK version".to_owned()));
    }
    let pack_nr = u32::from_be_bytes([pack_bytes[8], pack_bytes[9], pack_bytes[10], pack_bytes[11]]) as usize;
    if pack_nr == 0 {
        return Err(PackfileUriError::IntegrityMismatch("empty pack candidate".to_owned()));
    }
    if pack_nr > max_objects {
        return Err(PackfileUriError::CapacityExceeded("pack object count exceeds bound".to_owned()));
    }
    let min_idx_len = 1032usize
        .checked_add(
            pack_nr
                .checked_mul(hash_bytes + 8)
                .ok_or_else(|| PackfileUriError::CapacityExceeded("idx overflow".to_owned()))?,
        )
        .and_then(|v| v.checked_add(2 * hash_bytes))
        .ok_or_else(|| PackfileUriError::CapacityExceeded("idx overflow".to_owned()))?;
    if idx_bytes.len() < min_idx_len || &idx_bytes[..8] != b"\xfftOc\x00\x00\x00\x02" {
        return Err(PackfileUriError::IntegrityMismatch("invalid v2 idx header or size".to_owned()));
    }
    let mut prev = 0u32;
    for i in 0..256 {
        let off = 8 + i * 4;
        let cur = u32::from_be_bytes([idx_bytes[off], idx_bytes[off + 1], idx_bytes[off + 2], idx_bytes[off + 3]]);
        if cur < prev {
            return Err(PackfileUriError::IntegrityMismatch("non-monotonic idx fanout".to_owned()));
        }
        prev = cur;
    }
    if prev as usize != pack_nr {
        return Err(PackfileUriError::IntegrityMismatch("idx fanout total mismatches pack header".to_owned()));
    }
    let pack_trailer = &pack_bytes[pack_bytes.len() - hash_bytes..];
    let idx_pack_cksum = &idx_bytes[idx_bytes.len() - 2 * hash_bytes..idx_bytes.len() - hash_bytes];
    if pack_trailer != idx_pack_cksum {
        return Err(PackfileUriError::IntegrityMismatch("idx embedded pack checksum mismatch".to_owned()));
    }
    let mut oids = HashSet::with_capacity(pack_nr);
    let table_start = 1032;
    for i in 0..pack_nr {
        let s = table_start + i * hash_bytes;
        oids.insert(hex::encode(&idx_bytes[s..s + hash_bytes]));
    }
    Ok((pack_nr, oids))
}

#[cfg(unix)]
struct ScratchDir(PathBuf);

#[cfg(unix)]
impl ScratchDir {
    fn create() -> Result<Self, PackfileUriError> {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("rootyard-pack-bij-{}", Uuid::new_v4().simple()));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(&path).map_err(|e| PackfileUriError::Internal(format!("scratch dir: {e}")))?;
        Ok(Self(path))
    }
}

#[cfg(unix)]
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[cfg(test)]
thread_local! {
    static FORCE_DISABLE_HANDLE_CONFINEMENT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
/// Test-only RAII guard simulating a platform without directory/file handle confinement on the current thread.
#[cfg(test)]
pub(super) struct ScopedDisableHandleConfinement {
    prev: bool,
}

#[cfg(test)]
impl ScopedDisableHandleConfinement {
    pub(super) fn new() -> Self {
        let prev = FORCE_DISABLE_HANDLE_CONFINEMENT.with(|c| c.replace(true));
        Self { prev }
    }
}
#[cfg(test)]
impl Drop for ScopedDisableHandleConfinement {
    fn drop(&mut self) {
        FORCE_DISABLE_HANDLE_CONFINEMENT.with(|c| c.set(self.prev));
    }
}
/// Returns `true` strictly when the host OS provides `unix` `openat` handle confinement (test-overridable).
pub(super) fn is_handle_confinement_available() -> bool {
    #[cfg(test)]
    if FORCE_DISABLE_HANDLE_CONFINEMENT.with(std::cell::Cell::get) {
        return false;
    }
    cfg!(unix)
}

/// Retained verified directory handle for `objects/pack` (or a private `ScratchDir`): Unix holds the
/// live `O_DIRECTORY | O_NOFOLLOW` descriptor + `(dev, ino)`; other platforms are uninhabited (`Infallible`).
pub(super) struct PinnedPackDir {
    #[cfg(unix)]
    dir_file: std::fs::File,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(not(unix))]
    _never: std::convert::Infallible,
}

impl PinnedPackDir {
    /// Opens one single-component child directory strictly relative to `parent` without symlink traversal.
    #[cfg(unix)]
    fn openat_subdir(parent: &std::fs::File, child_name: &str) -> Result<Option<std::fs::File>, PackfileUriError> {
        let c_name = CString::new(child_name)
            .map_err(|_| PackfileUriError::IntegrityMismatch("invalid subdir name".to_owned()))?;
        // SAFETY: `parent` is a live verified directory descriptor, `c_name` is a valid
        // single-component NUL-terminated string, and `O_DIRECTORY | O_NOFOLLOW` never follows symlinks.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(PackfileUriError::IntegrityMismatch(format!("refused opening subdir {child_name}: {err}")));
        }
        // SAFETY: `fd` is a fresh non-negative file descriptor owned exclusively here.
        let dir_file = unsafe { std::fs::File::from_raw_fd(fd) };
        let meta = dir_file
            .metadata()
            .map_err(|e| PackfileUriError::Internal(format!("fstat subdir {child_name}: {e}")))?;
        if !meta.is_dir() {
            return Err(PackfileUriError::IntegrityMismatch(format!("{child_name} is not a directory")));
        }
        Ok(Some(dir_file))
    }

    /// Opens a single directory `dir` directly as a `PinnedPackDir`, verifying `lstat`/`fstat` inode identity.
    #[cfg(any(unix, test))]
    pub(super) fn open_dir_direct(dir: &Path) -> Result<Self, PackfileUriError> {
        if !is_handle_confinement_available() {
            let _ = dir;
            return Err(PackfileUriError::IntegrityMismatch(HANDLE_CONFINEMENT_REQUIRED.to_owned()));
        }
        #[cfg(unix)]
        {
            let lmeta = std::fs::symlink_metadata(dir)
                .map_err(|e| PackfileUriError::IntegrityMismatch(format!("lstat dir failed: {e}")))?;
            if lmeta.file_type().is_symlink() || !lmeta.file_type().is_dir() {
                return Err(PackfileUriError::IntegrityMismatch("target is not a real directory".to_owned()));
            }
            let dir_file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(dir)
                .map_err(|e| PackfileUriError::IntegrityMismatch(format!("open dir failed: {e}")))?;
            let fmeta = dir_file.metadata().map_err(|e| PackfileUriError::Internal(format!("fstat dir failed: {e}")))?;
            if !fmeta.is_dir() || (fmeta.dev(), fmeta.ino()) != (lmeta.dev(), lmeta.ino()) {
                return Err(PackfileUriError::IntegrityMismatch("directory inode swapped during open".to_owned()));
            }
            Ok(Self { dir_file, dev: fmeta.dev(), ino: fmeta.ino() })
        }
        #[cfg(not(unix))]
        {
            let _ = dir;
            Err(PackfileUriError::IntegrityMismatch(HANDLE_CONFINEMENT_REQUIRED.to_owned()))
        }
    }

    /// Steps `repo_dir -> objects -> pack` with `openat(O_NOFOLLOW)` hops and retains only the final
    /// verified `objects/pack` descriptor; `Ok(None)` when handle confinement is unavailable or
    /// `objects`/`objects/pack` is absent (`ENOENT`).
    pub(super) fn open_confined_with_capability(
        repo_dir: &Path,
        allow_handle_confinement: bool,
    ) -> Result<Option<Self>, PackfileUriError> {
        if !allow_handle_confinement || !is_handle_confinement_available() {
            let _ = repo_dir;
            return Ok(None);
        }
        #[cfg(unix)]
        {
            let repo_pinned = Self::open_dir_direct(repo_dir)?;
            let Some(objects_file) = Self::openat_subdir(&repo_pinned.dir_file, "objects")? else {
                return Ok(None);
            };
            let Some(pack_file) = Self::openat_subdir(&objects_file, "pack")? else {
                return Ok(None);
            };
            let pack_meta = pack_file
                .metadata()
                .map_err(|e| PackfileUriError::Internal(format!("fstat objects/pack: {e}")))?;
            if !pack_meta.is_dir() {
                return Err(PackfileUriError::IntegrityMismatch("objects/pack is not a directory".to_owned()));
            }
            Ok(Some(Self { dir_file: pack_file, dev: pack_meta.dev(), ino: pack_meta.ino() }))
        }
        #[cfg(not(unix))]
        {
            let _ = repo_dir;
            Ok(None)
        }
    }

    /// Opens the pinned `objects/pack` directory with handle confinement required.
    #[cfg(test)]
    pub(super) fn open_confined(repo_dir: &Path) -> Result<Option<Self>, PackfileUriError> {
        Self::open_confined_with_capability(repo_dir, true)
    }

    /// Re-`fstat`s the retained handle so a swapped/replaced directory can never be re-resolved by path.
    pub(super) fn verify_handle_intact(&self) -> Result<(), PackfileUriError> {
        #[cfg(unix)]
        {
            let meta = self
                .dir_file
                .metadata()
                .map_err(|e| PackfileUriError::Internal(format!("fstat pinned pack dir: {e}")))?;
            if !meta.is_dir() || (meta.dev(), meta.ino()) != (self.dev, self.ino) {
                return Err(PackfileUriError::IntegrityMismatch(
                    "pinned pack directory handle identity mismatch".to_owned(),
                ));
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            match self._never {}
        }
    }

    /// Enumerates the pinned directory through its descriptor (`/proc/self/fd/<fd>`), never the parent path.
    pub(super) fn read_dir(&self) -> Result<std::fs::ReadDir, PackfileUriError> {
        #[cfg(unix)]
        {
            self.verify_handle_intact()?;
            #[cfg(target_os = "linux")]
            {
                std::fs::read_dir(format!("/proc/self/fd/{}", self.dir_file.as_raw_fd()))
                    .map_err(|e| PackfileUriError::Internal(format!("read_dir pinned fd failed: {e}")))
            }
            #[cfg(all(unix, not(target_os = "linux")))]
            {
                std::fs::read_dir(format!("/dev/fd/{}", self.dir_file.as_raw_fd()))
                    .map_err(|e| PackfileUriError::Internal(format!("read_dir pinned fd failed: {e}")))
            }
        }
        #[cfg(not(unix))]
        {
            match self._never {}
        }
    }

    /// Opens and reads one single-component regular file through the pinned descriptor (`openat` with
    /// `O_NOFOLLOW`/`O_NONBLOCK`), in bounded chunks under per-file and cumulative caps; `Ok(None)` on `ENOENT`.
    pub(super) fn read_regular_artifact(
        &self,
        file_name: &std::ffi::OsStr,
        max_file_bytes: u64,
        total_scanned: &mut u64,
        max_total_bytes: u64,
    ) -> Result<Option<bytes::Bytes>, PackfileUriError> {
        let mut comps = Path::new(file_name).components();
        match (comps.next(), comps.next()) {
            (Some(std::path::Component::Normal(_)), None) => {}
            _ => return Err(PackfileUriError::IntegrityMismatch("non-local pack artifact filename".to_owned())),
        }
        if file_name.to_string_lossy().contains(['/', '\\', '\0']) {
            return Err(PackfileUriError::IntegrityMismatch("invalid separator in pack artifact filename".to_owned()));
        }
        self.verify_handle_intact()?;
        #[cfg(unix)]
        {
            self.read_regular_artifact_unix(file_name, max_file_bytes, total_scanned, max_total_bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = (file_name, max_file_bytes, total_scanned, max_total_bytes);
            match self._never {}
        }
    }

    #[cfg(unix)]
    fn read_regular_artifact_unix(
        &self,
        file_name: &std::ffi::OsStr,
        max_file_bytes: u64,
        total_scanned: &mut u64,
        max_total_bytes: u64,
    ) -> Result<Option<bytes::Bytes>, PackfileUriError> {
        let c_name = CString::new(file_name.as_bytes())
            .map_err(|_| PackfileUriError::IntegrityMismatch("nul byte in pack artifact filename".to_owned()))?;
        // SAFETY: `self.dir_file` is a live verified directory descriptor, `c_name` is a
        // single-component NUL-terminated string, and `O_NOFOLLOW | O_NONBLOCK` never follows
        // symlinks or blocks on FIFOs.
        let fd = unsafe {
            libc::openat(
                self.dir_file.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(PackfileUriError::IntegrityMismatch(format!("refused opening pack artifact via dirfd: {err}")));
        }
        // SAFETY: `fd` is a fresh non-negative descriptor owned exclusively by `file`.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let fmeta = file
            .metadata()
            .map_err(|e| PackfileUriError::Internal(format!("fstat pack artifact failed: {e}")))?;
        if !fmeta.file_type().is_file() {
            return Err(PackfileUriError::IntegrityMismatch("opened pack artifact is not a regular file".to_owned()));
        }
        if fmeta.len() > max_file_bytes {
            return Err(PackfileUriError::CapacityExceeded("pack or idx file exceeds scan byte cap".to_owned()));
        }
        if total_scanned.checked_add(fmeta.len()).is_none_or(|sum| sum > max_total_bytes) {
            return Err(PackfileUriError::CapacityExceeded("cumulative scanned pack bytes exceed cap".to_owned()));
        }
        let cap_hint = usize::try_from(fmeta.len()).unwrap_or(0).min(8 * 1024 * 1024);
        let mut buf = Vec::with_capacity(cap_hint);
        let mut limited = std::io::Read::take(file, max_file_bytes.saturating_add(1));
        let mut chunk = [0u8; 64 * 1024];
        loop {
            let n = std::io::Read::read(&mut limited, &mut chunk)
                .map_err(|e| PackfileUriError::Internal(format!("read pack artifact failed: {e}")))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() as u64 > max_file_bytes {
                return Err(PackfileUriError::CapacityExceeded("pack or idx file grew past scan byte cap".to_owned()));
            }
            *total_scanned = total_scanned
                .checked_add(n as u64)
                .filter(|&sum| sum <= max_total_bytes)
                .ok_or_else(|| {
                    PackfileUriError::CapacityExceeded("cumulative scanned pack bytes exceed cap".to_owned())
                })?;
        }
        if buf.len() as u64 != fmeta.len() {
            return Err(PackfileUriError::IntegrityMismatch(
                "pack or idx length changed concurrently during read".to_owned(),
            ));
        }
        Ok(Some(bytes::Bytes::from(buf)))
    }
}

/// Parses bounded `git verify-pack -v` object lines into `(defined_oids, commits, is_standalone)`;
/// `None` unless the reported object set is exactly the `.idx` v2 OID table.
pub(super) fn parse_verify_pack_objects(
    vp_out: &[u8],
    object_count: usize,
    hex_len: usize,
    idx_oids: &HashSet<String>,
) -> Option<(HashSet<String>, Vec<String>, bool)> {
    let mut defined_oids = HashSet::with_capacity(object_count);
    let mut delta_bases = Vec::new();
    let mut commits = Vec::new();
    for line in String::from_utf8_lossy(vp_out).lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5
            && matches!(parts[1], "commit" | "tree" | "blob" | "tag")
            && is_lower_hex_exact(parts[0], hex_len)
        {
            defined_oids.insert(parts[0].to_owned());
            if parts[1] == "commit" {
                commits.push(parts[0].to_owned());
            }
            if parts.len() >= 7 && is_lower_hex_exact(parts[6], hex_len) {
                delta_bases.push(parts[6].to_owned());
            }
        }
    }
    if defined_oids.len() != object_count || *idx_oids != defined_oids {
        return None;
    }
    let is_standalone = delta_bases.iter().all(|base| defined_oids.contains(base));
    Some((defined_oids, commits, is_standalone))
}

/// Writes `pack_bytes` into a private `0o700` `ScratchDir`, runs bounded `git index-pack --strict -o`
/// to enforce byte-for-byte `.idx` bijection, then bounded `git verify-pack -v` on that exact scratch pair.
pub(super) async fn verify_raw_pack_stream_bijection(
    git_bin: &Path,
    repo_dir: &Path,
    pack_bytes: &[u8],
    expected_idx_bytes: &[u8],
    limits: &HelperResourceLimits,
) -> Result<Vec<u8>, PackfileUriError> {
    if !is_handle_confinement_available() {
        let _ = (git_bin, repo_dir, pack_bytes, expected_idx_bytes, limits);
        return Err(PackfileUriError::IntegrityMismatch(HANDLE_CONFINEMENT_REQUIRED.to_owned()));
    }
    #[cfg(unix)]
    {
        let scratch = ScratchDir::create()?;
        let scratch_pack = scratch.0.join("candidate.pack");
        let scratch_idx = scratch.0.join("candidate.idx");
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut p_opts = std::fs::OpenOptions::new();
            p_opts.write(true).create_new(true);
            p_opts.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let mut pf = p_opts
                .open(&scratch_pack)
                .map_err(|e| PackfileUriError::Internal(format!("create scratch pack: {e}")))?;
            std::io::Write::write_all(&mut pf, pack_bytes)
                .map_err(|e| PackfileUriError::Internal(format!("write scratch pack: {e}")))?;
        }
        let (Some(out_str), Some(pack_str)) = (scratch_idx.to_str(), scratch_pack.to_str()) else {
            return Err(PackfileUriError::IntegrityMismatch("non-utf8 scratch path".to_owned()));
        };
        let ip_args = ["index-pack", "--strict", "-o", out_str, pack_str];
        run_git_bounded(git_bin, repo_dir, &ip_args, None, 4096, limits.timeout).await?;
        let scratch_pinned = PinnedPackDir::open_dir_direct(&scratch.0)?;
        let mut fresh_total = 0u64;
        let Some(fresh_idx) = scratch_pinned.read_regular_artifact(
            std::ffi::OsStr::new("candidate.idx"),
            limits.max_single_idx_bytes,
            &mut fresh_total,
            limits.max_single_idx_bytes,
        )?
        else {
            return Err(PackfileUriError::IntegrityMismatch("missing scratch idx".to_owned()));
        };
        if &fresh_idx[..] != expected_idx_bytes {
            return Err(PackfileUriError::IntegrityMismatch("raw pack stream re-index mismatches idx bytes".to_owned()));
        }
        let vp_args = ["verify-pack", "-v", out_str];
        run_git_bounded(git_bin, repo_dir, &vp_args, None, limits.max_stdout_bytes, limits.timeout).await
    }
    #[cfg(not(unix))]
    {
        let _ = (git_bin, repo_dir, pack_bytes, expected_idx_bytes, limits);
        Err(PackfileUriError::IntegrityMismatch(HANDLE_CONFINEMENT_REQUIRED.to_owned()))
    }
}
