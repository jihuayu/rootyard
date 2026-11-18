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
        builder.create(&path).map_err(|e| PackfileUriError::Internal(format!("scratch dir: {e}")))?;
        Ok(Self(path))
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Sequentially indexes 100% of raw `.pack` stream bytes into a temporary `.idx` via
/// bounded `git index-pack --strict -o` and enforces byte-for-byte equality with `expected_idx_bytes`.
pub(super) async fn verify_raw_pack_stream_bijection(
    git_bin: &Path,
    repo_dir: &Path,
    pack_path: &Path,
    expected_idx_bytes: &[u8],
    limits: &HelperResourceLimits,
) -> Result<(), PackfileUriError> {
    let scratch = ScratchDir::create()?;
    let scratch_idx = scratch.0.join("bijection.idx");
    let (Some(out_str), Some(pack_str)) = (scratch_idx.to_str(), pack_path.to_str()) else {
        return Err(PackfileUriError::IntegrityMismatch("non-utf8 pack path".to_owned()));
    };
    run_git_bounded(
        git_bin,
        repo_dir,
        &["index-pack", "--strict", "-o", out_str, pack_str],
        None,
        4096,
        limits.timeout,
    )
    .await?;
    let meta = std::fs::metadata(&scratch_idx).map_err(|_| PackfileUriError::IntegrityMismatch("missing scratch idx".to_owned()))?;
    if meta.len() > limits.max_single_idx_bytes || meta.len() != expected_idx_bytes.len() as u64 {
        return Err(PackfileUriError::IntegrityMismatch("re-indexed idx length mismatch".to_owned()));
    }
    let fresh_idx = std::fs::read(&scratch_idx).map_err(|_| PackfileUriError::IntegrityMismatch("unreadable scratch idx".to_owned()))?;
    if fresh_idx != expected_idx_bytes {
        return Err(PackfileUriError::IntegrityMismatch(
            "raw pack stream re-index mismatches on-disk idx bytes".to_owned(),
        ));
    }
    Ok(())
}
