use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStringExt,
        fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

use super::{
    MAX_CHUNK_BYTES, MAX_SYMLINK_HOPS, MIN_CHUNK_BYTES, MerkleSyncError,
    git_state::IgnoreSnapshot,
    manifest::{ChunkRef, EmptyDirPolicy, MerkleChildKind, MerkleDirChild, UntrackedPolicy},
};
use crate::workspace_lab::core;

pub(crate) fn rel_path_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(OsString::from_vec(bytes.to_vec()))
}

pub(crate) fn should_include_leaf(ignore: &IgnoreSnapshot, rel: &[u8], excluded_ignored: &mut u64) -> bool {
    if ignore.tracked_paths.contains(rel) {
        return true;
    }
    let included = match ignore.policy.untracked_policy {
        UntrackedPolicy::TrackedOnly => false,
        UntrackedPolicy::IncludeAllExceptGit => true,
        UntrackedPolicy::IncludeNonIgnored => {
            let rel_path = rel_path_from_bytes(rel);
            ignore.git_untracked.contains(rel) && !ignore.rootyard_matcher.is_ignored(&rel_path, false)
        }
    };
    if !included {
        *excluded_ignored += 1;
    }
    included
}

pub(crate) fn is_empty_dir_retained(
    repo: &Path,
    ignore: &IgnoreSnapshot,
    git_ignored_dirs_cache: &mut BTreeSet<Vec<u8>>,
    rel: &[u8],
) -> Result<bool, MerkleSyncError> {
    match ignore.policy.empty_dir_policy {
        EmptyDirPolicy::IgnoreEmptyDirs => Ok(false),
        EmptyDirPolicy::RetainEmptyDirs => Ok(true),
        EmptyDirPolicy::RetainNonIgnoredEmptyDirs => {
            let rel_path = rel_path_from_bytes(rel);
            if ignore.policy.use_rootyardignore && ignore.rootyard_matcher.is_ignored(&rel_path, true) {
                return Ok(false);
            }
            if ignore.policy.use_gitignore {
                if git_ignored_dirs_cache.contains(rel) {
                    return Ok(false);
                }
                let mut child = std::process::Command::new(
                    std::env::var_os("ROOTYARD_WORKSPACE_GIT").unwrap_or_else(|| "git".into()),
                )
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("LC_ALL", "C")
                .arg("-C")
                .arg(repo)
                .args(["check-ignore", "-q", "--no-index", "--stdin", "-z"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(rel)?;
                    stdin.write_all(&[b'/', 0])?;
                }
                if child.wait()?.success() {
                    git_ignored_dirs_cache.insert(rel.to_vec());
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }
}

pub(crate) fn can_reuse_clean_leaf(meta: &fs::Metadata, prev: &MerkleDirChild) -> bool {
    if meta.file_type().is_symlink() {
        return prev.kind == MerkleChildKind::Symlink;
    }
    meta.is_file()
        && prev.kind == MerkleChildKind::File
        && meta.len() == prev.size
        && (meta.permissions().mode() & 0o777) == prev.mode
}

fn reserve_usize(cur: &mut usize, add: usize, max: usize, what: &str) -> Result<(), MerkleSyncError> {
    let next =
        cur.checked_add(add).ok_or_else(|| MerkleSyncError::InvalidManifest(format!("{what} count overflow")))?;
    if next > max {
        return Err(MerkleSyncError::InvalidManifest(format!("{what} limit exceeded")));
    }
    *cur = next;
    Ok(())
}

pub(crate) fn reserve_tree_entry(total_entries: &mut usize, max_entries: usize) -> Result<(), MerkleSyncError> {
    reserve_usize(total_entries, 1, max_entries, "manifest entry")
}

pub(crate) fn reserve_chunk_budget(total: &mut usize, add: usize, max: usize) -> Result<(), MerkleSyncError> {
    reserve_usize(total, add, max, "manifest chunk")
}

pub(crate) fn expected_chunk_count(file_len: u64, chunk_size: usize) -> Result<usize, MerkleSyncError> {
    if !(MIN_CHUNK_BYTES..=MAX_CHUNK_BYTES).contains(&chunk_size) {
        return Err(MerkleSyncError::InvalidInput("chunk_size_bytes out of bounds".into()));
    }
    let chunks = if file_len == 0 { 1 } else { file_len.div_ceil(chunk_size as u64) };
    usize::try_from(chunks).map_err(|_| MerkleSyncError::InvalidManifest("chunk count overflow".into()))
}

pub(crate) fn reserve_workspace_bytes(total_bytes: &mut u64, add: u64, max: u64) -> Result<(), MerkleSyncError> {
    let next = total_bytes
        .checked_add(add)
        .ok_or_else(|| MerkleSyncError::InvalidManifest("workspace size overflow".into()))?;
    if next > max {
        return Err(MerkleSyncError::InvalidManifest("workspace byte limit exceeded".into()));
    }
    *total_bytes = next;
    Ok(())
}

pub(crate) fn reserve_child_limits(
    total_entries: &mut usize,
    total_bytes: &mut u64,
    total_chunks: &mut usize,
    max_entries: usize,
    max_bytes: u64,
    max_chunks: usize,
    child: &MerkleDirChild,
) -> Result<(), MerkleSyncError> {
    reserve_tree_entry(total_entries, max_entries)?;
    if matches!(child.kind, MerkleChildKind::File | MerkleChildKind::Symlink) {
        reserve_workspace_bytes(total_bytes, child.size, max_bytes)?;
    }
    if child.kind == MerkleChildKind::File {
        reserve_chunk_budget(total_chunks, child.chunks.len(), max_chunks)?;
    }
    Ok(())
}

pub(crate) struct LeafMetricsOut<'a> {
    pub scanned_files: &'a mut u64,
    pub scanned_bytes: &'a mut u64,
    pub hashed_bytes: &'a mut u64,
    pub total_entries: &'a mut usize,
    pub total_bytes: &'a mut u64,
    pub total_chunks: &'a mut usize,
    pub max_entries: usize,
    pub max_bytes: u64,
    pub max_chunks: usize,
    pub chunk_sources: &'a mut BTreeMap<String, Vec<(u64, u64, Vec<u8>)>>,
}

pub(crate) fn build_leaf_child(
    repo: &Path,
    chunk_size: usize,
    child_raw: &[u8],
    name_bytes: &[u8],
    full_path: &Path,
    meta: &fs::Metadata,
    out: &mut LeafMetricsOut<'_>,
) -> Result<MerkleDirChild, MerkleSyncError> {
    if meta.permissions().mode() & 0o7000 != 0 {
        return Err(MerkleSyncError::UnsupportedGitState("special permission bits unsupported".into()));
    }
    let rel_path = rel_path_from_bytes(child_raw);
    if meta.file_type().is_symlink() {
        reserve_tree_entry(out.total_entries, out.max_entries)?;
        let target = fs::read_link(full_path)?;
        validate_symlink_safe(repo, &rel_path, &target)?;
        let target_bytes = target.into_os_string().into_vec();
        reserve_workspace_bytes(out.total_bytes, target_bytes.len() as u64, out.max_bytes)?;
        let sha = hex::encode(Sha256::digest(&target_bytes));
        *out.scanned_files += 1;
        *out.scanned_bytes += target_bytes.len() as u64;
        *out.hashed_bytes += target_bytes.len() as u64;
        return Ok(MerkleDirChild {
            name_base64: STANDARD.encode(name_bytes),
            kind: MerkleChildKind::Symlink,
            mode: 0o777,
            size: target_bytes.len() as u64,
            content_sha256: Some(sha),
            target_base64: Some(STANDARD.encode(&target_bytes)),
            chunks: Vec::new(),
            subtree_node_sha256: None,
            subtree_file_count: 1,
            subtree_total_bytes: target_bytes.len() as u64,
        });
    }
    if !meta.is_file() {
        return Err(MerkleSyncError::UnsupportedGitState("special file (FIFO/socket/device) unsupported".into()));
    }
    let expected_len = meta.len();
    let chunk_count = expected_chunk_count(expected_len, chunk_size)?;
    reserve_tree_entry(out.total_entries, out.max_entries)?;
    reserve_workspace_bytes(out.total_bytes, expected_len, out.max_bytes)?;
    reserve_chunk_budget(out.total_chunks, chunk_count, out.max_chunks)?;
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(full_path)?;
    let opened_meta = file.metadata()?;
    if !opened_meta.is_file() || opened_meta.len() != expected_len {
        return Err(MerkleSyncError::ConcurrentEdit("file changed while opening during scan".into()));
    }
    let mut buf = Vec::with_capacity(expected_len as usize);
    file.take(expected_len.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 != expected_len {
        return Err(MerkleSyncError::ConcurrentEdit("file length changed during read".into()));
    }
    if name_bytes == b".gitattributes" {
        core::check_gitattributes(&buf, true).map_err(|e| MerkleSyncError::UnsupportedGitState(e.to_string()))?;
    }
    *out.scanned_files += 1;
    *out.scanned_bytes += expected_len;
    *out.hashed_bytes += expected_len;
    let content_sha256 = hex::encode(Sha256::digest(&buf));
    let mut chunks = Vec::with_capacity(chunk_count);
    if buf.is_empty() {
        let empty_sha = hex::encode(Sha256::digest(b""));
        out.chunk_sources.entry(empty_sha.clone()).or_insert_with(|| vec![(0, 0, Vec::new())]);
        chunks.push(ChunkRef { index: 0, offset: 0, len: 0, sha256: empty_sha });
    } else {
        for (idx, slice) in buf.chunks(chunk_size).enumerate() {
            let offset = (idx * chunk_size) as u64;
            let chunk_sha = hex::encode(Sha256::digest(slice));
            out.chunk_sources
                .entry(chunk_sha.clone())
                .or_insert_with(|| vec![(offset, slice.len() as u64, slice.to_vec())]);
            chunks.push(ChunkRef { index: idx as u32, offset, len: slice.len() as u64, sha256: chunk_sha });
        }
    }
    Ok(MerkleDirChild {
        name_base64: STANDARD.encode(name_bytes),
        kind: MerkleChildKind::File,
        mode: meta.permissions().mode() & 0o777,
        size: expected_len,
        content_sha256: Some(content_sha256),
        target_base64: None,
        chunks,
        subtree_node_sha256: None,
        subtree_file_count: 1,
        subtree_total_bytes: expected_len,
    })
}

pub(crate) fn validate_symlink_safe(repo_root: &Path, rel: &Path, target: &Path) -> Result<(), MerkleSyncError> {
    if target.as_os_str().is_empty() || target.is_absolute() {
        return Err(MerkleSyncError::UnsupportedGitState("empty or absolute symlink target unsupported".into()));
    }
    let mut resolved: Vec<OsString> =
        rel.parent().map(|p| p.components().map(|c| c.as_os_str().to_owned()).collect()).unwrap_or_default();
    let mut pending: VecDeque<OsString> = target.components().map(|c| c.as_os_str().to_owned()).collect();
    let mut hops = 0usize;
    while let Some(comp) = pending.pop_front() {
        if comp == "." {
            continue;
        }
        if comp == ".." {
            if resolved.pop().is_none() {
                return Err(MerkleSyncError::UnsupportedGitState("symlink escapes workspace root".into()));
            }
            continue;
        }
        resolved.push(comp);
        if resolved.first().is_some_and(|x| x == ".git") {
            return Err(MerkleSyncError::UnsupportedGitState("symlink into .git unsupported".into()));
        }
        let loc: PathBuf = resolved.iter().collect();
        match fs::symlink_metadata(repo_root.join(loc)) {
            Ok(meta) if meta.file_type().is_symlink() => {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return Err(MerkleSyncError::UnsupportedGitState("symlink hop limit exceeded".into()));
                }
                let link_loc: PathBuf = resolved.iter().collect();
                let link = fs::read_link(repo_root.join(link_loc))?;
                if link.is_absolute() {
                    return Err(MerkleSyncError::UnsupportedGitState("symlink chain escapes root".into()));
                }
                resolved.pop();
                for part in link.components().rev() {
                    pending.push_front(part.as_os_str().to_owned());
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "scan_fs_tests.rs"]
mod tests;
