//! Byte-exact `.pack` header, `.idx` v2 OID table, and raw `.pack` stream
//! `git index-pack --strict -o` bijection verifier (preventing unindexed gap/trailing bytes).

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use uuid::Uuid;

use super::{
    cover_git::{HelperResourceLimits, run_git_bounded},
    types::{PackObjectFormat, PackfileUriError},
};

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

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn create() -> Result<Self, PackfileUriError> {
        let path = std::env::temp_dir().join(format!("rootyard-pack-bij-{}", Uuid::new_v4().simple()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        #[cfg(not(unix))]
        {
            let _ = &mut builder;
        }
        builder.create(&path).map_err(|e| PackfileUriError::Internal(format!("scratch dir: {e}")))?;
        Ok(Self(path))
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Verifies `repo_dir`, `repo_dir/objects`, and `repo_dir/objects/pack` are real non-symlink directories.
/// Returns `Ok(None)` cleanly when `objects` or `objects/pack` does not exist yet (`NotFound`).
pub(super) fn verify_confined_pack_dir(repo_dir: &Path) -> Result<Option<PathBuf>, PackfileUriError> {
    let repo_meta = std::fs::symlink_metadata(repo_dir)
        .map_err(|e| PackfileUriError::Internal(format!("stat repo_dir failed: {e}")))?;
    if repo_meta.file_type().is_symlink() || !repo_meta.file_type().is_dir() {
        return Err(PackfileUriError::IntegrityMismatch("repo_dir is not a real directory".to_owned()));
    }
    let objects_dir = repo_dir.join("objects");
    match std::fs::symlink_metadata(&objects_dir) {
        Ok(m) if !m.file_type().is_symlink() && m.file_type().is_dir() => {}
        Ok(_) => return Err(PackfileUriError::IntegrityMismatch("objects is not a real directory".to_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PackfileUriError::Internal(format!("stat objects dir failed: {e}"))),
    }
    let pack_dir = objects_dir.join("pack");
    let pack_lmeta = match std::fs::symlink_metadata(&pack_dir) {
        Ok(m) if !m.file_type().is_symlink() && m.file_type().is_dir() => m,
        Ok(_) => return Err(PackfileUriError::IntegrityMismatch("objects/pack is not a real directory".to_owned())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PackfileUriError::Internal(format!("stat objects/pack dir failed: {e}"))),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let dir_f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&pack_dir)
            .map_err(|e| PackfileUriError::IntegrityMismatch(format!("open objects/pack dir failed: {e}")))?;
        let dir_fmeta = dir_f
            .metadata()
            .map_err(|e| PackfileUriError::Internal(format!("fstat objects/pack dir failed: {e}")))?;
        if (dir_fmeta.dev(), dir_fmeta.ino()) != (pack_lmeta.dev(), pack_lmeta.ino()) {
            return Err(PackfileUriError::IntegrityMismatch("objects/pack dir inode swapped".to_owned()));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = &pack_lmeta;
    }
    Ok(Some(pack_dir))
}

/// Opens a single-component regular file inside `pack_dir` without following symlinks (`O_NOFOLLOW`)
/// and reads its bytes in bounded chunks while enforcing `max_file_bytes` and cumulative `max_total_bytes`.
/// Returns `Ok(None)` only when the file was concurrently unlinked (`NotFound`) before open.
pub(super) fn read_confined_regular_pack_artifact(
    pack_dir: &Path,
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
    let dir_meta = std::fs::symlink_metadata(pack_dir)
        .map_err(|e| PackfileUriError::Internal(format!("re-stat objects/pack failed: {e}")))?;
    if dir_meta.file_type().is_symlink() || !dir_meta.file_type().is_dir() {
        return Err(PackfileUriError::IntegrityMismatch("objects/pack ceased to be a real directory".to_owned()));
    }
    let path = pack_dir.join(file_name);
    let lmeta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PackfileUriError::Internal(format!("lstat pack artifact failed: {e}"))),
    };
    if lmeta.file_type().is_symlink() || !lmeta.file_type().is_file() {
        return Err(PackfileUriError::IntegrityMismatch("non-regular entry in objects/pack".to_owned()));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = match opts.open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PackfileUriError::IntegrityMismatch(format!("refused opening pack artifact: {e}"))),
    };
    let fmeta = file
        .metadata()
        .map_err(|e| PackfileUriError::Internal(format!("fstat pack artifact failed: {e}")))?;
    if !fmeta.file_type().is_file() {
        return Err(PackfileUriError::IntegrityMismatch("opened pack artifact is not a regular file".to_owned()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (fmeta.dev(), fmeta.ino()) != (lmeta.dev(), lmeta.ino()) {
            return Err(PackfileUriError::IntegrityMismatch("pack artifact inode swapped during open".to_owned()));
        }
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
            .ok_or_else(|| PackfileUriError::CapacityExceeded("cumulative scanned pack bytes exceed cap".to_owned()))?;
    }
    if buf.len() as u64 != fmeta.len() {
        return Err(PackfileUriError::IntegrityMismatch(
            "pack or idx length changed concurrently during read".to_owned(),
        ));
    }
    Ok(Some(bytes::Bytes::from(buf)))
}

/// Writes the exact already-read `pack_bytes` into a private `0o700` `ScratchDir`,
/// runs bounded `git index-pack --strict -o` to enforce byte-for-byte `.idx` bijection,
/// and runs bounded `git verify-pack -v` against that exact scratch pair (never re-reading `repo_dir`).
pub(super) async fn verify_raw_pack_stream_bijection(
    git_bin: &Path,
    repo_dir: &Path,
    pack_bytes: &[u8],
    expected_idx_bytes: &[u8],
    limits: &HelperResourceLimits,
) -> Result<Vec<u8>, PackfileUriError> {
    let scratch = ScratchDir::create()?;
    let scratch_pack = scratch.0.join("candidate.pack");
    let scratch_idx = scratch.0.join("candidate.idx");
    {
        let mut p_opts = std::fs::OpenOptions::new();
        p_opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            p_opts.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut pf = p_opts
            .open(&scratch_pack)
            .map_err(|e| PackfileUriError::Internal(format!("create scratch pack: {e}")))?;
        std::io::Write::write_all(&mut pf, pack_bytes)
            .map_err(|e| PackfileUriError::Internal(format!("write scratch pack: {e}")))?;
    }
    let (Some(out_str), Some(pack_str)) = (scratch_idx.to_str(), scratch_pack.to_str()) else {
        return Err(PackfileUriError::IntegrityMismatch("non-utf8 scratch path".to_owned()));
    };
    run_git_bounded(git_bin, repo_dir, &["index-pack", "--strict", "-o", out_str, pack_str], None, 4096, limits.timeout)
        .await?;
    let mut fresh_total = 0u64;
    let Some(fresh_idx) = read_confined_regular_pack_artifact(
        &scratch.0,
        std::ffi::OsStr::new("candidate.idx"),
        limits.max_single_idx_bytes,
        &mut fresh_total,
        limits.max_single_idx_bytes,
    )?
    else {
        return Err(PackfileUriError::IntegrityMismatch("missing scratch idx".to_owned()));
    };
    if &fresh_idx[..] != expected_idx_bytes {
        return Err(PackfileUriError::IntegrityMismatch(
            "raw pack stream re-index mismatches idx bytes".to_owned(),
        ));
    }
    run_git_bounded(git_bin, repo_dir, &["verify-pack", "-v", out_str], None, limits.max_stdout_bytes, limits.timeout)
        .await
}
