//! Wire-pack header/trailer extraction, `verify-pack` parser, and ancestor reachability helpers (#183).

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Instant;

use ring::digest::{Context as RingDigest, SHA1_FOR_LEGACY_USE_ONLY};
use sha2::{Digest, Sha256};

use crate::ref_store::core::types::GitObjectFormat;

use super::git_proc::{GitStdin, run_git_bin};
use super::types::{
    DEFAULT_MAX_DELTA_DEPTH, GitSubprocessLimits, PushCausalError, STREAM_CHUNK_BYTES, StreamIngestLimits,
};

pub(super) struct VerifyEntry {
    pub(super) oid: String,
    pub(super) offset: u64,
    pub(super) base_oid: Option<String>,
}

pub(super) struct VerifySummary {
    pub(super) entries: Vec<VerifyEntry>,
    pub(super) delta_count: u64,
    pub(super) max_depth: u32,
}

pub(super) fn extract_and_check_wire_pack(
    request_path: &Path,
    pack_offset: usize,
    dest_pack: &Path,
    format: GitObjectFormat,
) -> Result<Option<u32>, String> {
    let mut f = File::open(request_path).map_err(|e| e.to_string())?;
    let total_len = f.metadata().map_err(|e| e.to_string())?.len();
    if total_len <= pack_offset as u64 {
        return Ok(None);
    }
    let pack_len = total_len - pack_offset as u64;
    let hash_len = format.oid_hex_len() / 2;
    if pack_len < (12 + hash_len) as u64 {
        return Err("pack stream shorter than header + trailer".into());
    }
    f.seek(SeekFrom::Start(pack_offset as u64)).map_err(|e| e.to_string())?;
    let mut out = File::create(dest_pack).map_err(|e| e.to_string())?;
    let body_len = pack_len - hash_len as u64;
    let mut hdr = [0u8; 12];
    f.read_exact(&mut hdr).map_err(|e| e.to_string())?;
    if &hdr[0..4] != b"PACK" || u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) != 2 {
        return Err("invalid PACK magic or version".into());
    }
    let count = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    out.write_all(&hdr).map_err(|e| e.to_string())?;

    let mut sha1_h = RingDigest::new(&SHA1_FOR_LEGACY_USE_ONLY);
    let mut sha256_h = Sha256::new();
    sha1_h.update(&hdr);
    sha256_h.update(hdr);
    let mut rem = body_len - 12;
    let mut buf = [0u8; STREAM_CHUNK_BYTES];
    while rem > 0 {
        let step = (rem as usize).min(buf.len());
        f.read_exact(&mut buf[..step]).map_err(|e| e.to_string())?;
        out.write_all(&buf[..step]).map_err(|e| e.to_string())?;
        sha1_h.update(&buf[..step]);
        sha256_h.update(&buf[..step]);
        rem -= step as u64;
    }
    let mut trailer = vec![0u8; hash_len];
    f.read_exact(&mut trailer).map_err(|e| e.to_string())?;
    out.write_all(&trailer).map_err(|e| e.to_string())?;
    let expected = match format {
        GitObjectFormat::Sha1 => sha1_h.finish().as_ref().to_vec(),
        GitObjectFormat::Sha256 => sha256_h.finalize().to_vec(),
    };
    if trailer != expected {
        return Err("PACK trailer checksum mismatch".into());
    }
    Ok(Some(count))
}

pub(super) async fn inspect_verify_pack_bin(
    git_bin: &Path,
    repo_dir: &Path,
    idx_path: &Path,
    ingest_limits: &StreamIngestLimits,
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<VerifySummary, PushCausalError> {
    let idx_str = idx_path.to_str().ok_or_else(|| PushCausalError::Io("non-utf8 idx".into()))?;
    let raw =
        run_git_bin(git_bin, repo_dir, &["verify-pack", "-v", idx_str], GitStdin::Null, proc_limits, deadline).await?;
    let text = String::from_utf8(raw).map_err(|e| PushCausalError::CorruptPack(e.to_string()))?;
    let (mut entries, mut delta_count, mut max_depth) = (Vec::new(), 0u64, 0u32);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5
            || !parts[0].bytes().all(|b| b.is_ascii_hexdigit())
            || !matches!(parts[1], "commit" | "tree" | "blob" | "tag")
        {
            continue;
        }
        let unpacked: u64 = parts[2].parse().map_err(|_| PushCausalError::CorruptPack("bad size".into()))?;
        let offset: u64 = parts[4].parse().map_err(|_| PushCausalError::CorruptPack("bad offset".into()))?;
        if unpacked > ingest_limits.max_unpacked_object_bytes {
            return Err(PushCausalError::LimitExceeded("unpacked object exceeded limit"));
        }
        let mut base_oid = None;
        if parts.len() >= 7 {
            let depth: u32 = parts[5].parse().map_err(|_| PushCausalError::CorruptPack("bad depth".into()))?;
            if depth > DEFAULT_MAX_DELTA_DEPTH {
                return Err(PushCausalError::LimitExceeded("delta depth exceeded limit"));
            }
            delta_count = delta_count.saturating_add(1);
            max_depth = max_depth.max(depth);
            base_oid = Some(parts[6].to_owned());
        }
        entries.push(VerifyEntry { oid: parts[0].to_owned(), offset, base_oid });
    }
    entries.sort_by_key(|e| e.offset);
    Ok(VerifySummary { entries, delta_count, max_depth })
}

pub(super) async fn verify_reachability_and_ancestors(
    git_bin: &Path,
    repo_dir: &Path,
    targets: &[String],
    base_tips: &[String],
    base_oids: &BTreeSet<String>,
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<Vec<String>, PushCausalError> {
    let mut rev_in = String::new();
    for t in targets {
        rev_in.push_str(t);
        rev_in.push('\n');
    }
    for tip in base_tips {
        rev_in.push('^');
        rev_in.push_str(tip);
        rev_in.push('\n');
    }
    let out = run_git_bin(
        git_bin,
        repo_dir,
        &["rev-list", "--objects", "--stdin"],
        GitStdin::Bytes(rev_in.as_bytes()),
        proc_limits,
        deadline,
    )
    .await?;
    let text = String::from_utf8(out).map_err(|e| PushCausalError::CorruptPack(e.to_string()))?;
    let introduced: BTreeSet<String> =
        text.lines().filter_map(|l| l.split_whitespace().next().map(str::to_owned)).collect();

    let mut check_in = String::new();
    for t in targets {
        check_in.push_str(t);
        check_in.push('\n');
    }
    let chk_out = run_git_bin(
        git_bin,
        repo_dir,
        &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        GitStdin::Bytes(check_in.as_bytes()),
        proc_limits,
        deadline,
    )
    .await?;
    let chk_txt = String::from_utf8(chk_out).map_err(|e| PushCausalError::CorruptPack(e.to_string()))?;
    let mut commit_rev_in = String::new();
    let mut has_commit_target = false;
    for line in chk_txt.lines() {
        let mut sp = line.split_whitespace();
        let (Some(oid), Some(kind)) = (sp.next(), sp.next()) else { continue };
        if kind == "missing" {
            return Err(PushCausalError::MissingCausalObject(format!("target `{oid}` missing from closure")));
        }
        if matches!(kind, "commit" | "tag") {
            commit_rev_in.push_str(oid);
            commit_rev_in.push('\n');
            has_commit_target = true;
        }
    }
    for tip in base_tips {
        commit_rev_in.push('^');
        commit_rev_in.push_str(tip);
        commit_rev_in.push('\n');
    }
    let mut ancestors = BTreeSet::new();
    if has_commit_target {
        let p_out = run_git_bin(
            git_bin,
            repo_dir,
            &["rev-list", "--parents", "--stdin"],
            GitStdin::Bytes(commit_rev_in.as_bytes()),
            proc_limits,
            deadline,
        )
        .await?;
        let p_text = String::from_utf8(p_out).map_err(|e| PushCausalError::CorruptPack(e.to_string()))?;
        for line in p_text.lines() {
            for parent in line.split_whitespace().skip(1) {
                if !introduced.contains(parent) {
                    if !base_oids.contains(parent) {
                        return Err(PushCausalError::MissingCausalObject(format!(
                            "parent `{parent}` missing from verified base closure"
                        )));
                    }
                    ancestors.insert(parent.to_owned());
                }
            }
        }
    }
    Ok(ancestors.into_iter().collect())
}
