use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

use super::{
    MAX_TOTAL_CHUNKS, MAX_TREE_ENTRIES, MAX_WORKSPACE_BYTES, MERKLE_CODEC_VERSION, MERKLE_MANIFEST_SCHEMA,
    MerkleSyncError,
    manifest::{
        EmptyDirPolicy, HeadSnapshot, MerkleChangeKind, MerkleChildKind, MerkleDiffEntry, MerkleDirChild,
        MerkleStateManifest, compute_dir_node_sha256, compute_index_merkle_root, compute_state_merkle_root,
        decode_rel_bytes, encode_rel_bytes, is_valid_oid_hex, is_valid_sha256_hex, validate_rel_path_bytes,
    },
    scan_fs::{expected_chunk_count, reserve_chunk_budget, reserve_tree_entry, reserve_workspace_bytes},
};

pub fn validate_manifest(manifest: &MerkleStateManifest) -> Result<(), MerkleSyncError> {
    if manifest.schema != MERKLE_MANIFEST_SCHEMA || manifest.codec_version != MERKLE_CODEC_VERSION {
        return Err(MerkleSyncError::InvalidManifest("unsupported merkle manifest schema or codec version".into()));
    }
    if manifest.tenant_id.is_nil()
        || manifest.repo_id.is_nil()
        || manifest.history_id.is_nil()
        || manifest.workspace_id.is_nil()
        || manifest.checkpoint_id.is_nil()
    {
        return Err(MerkleSyncError::InvalidManifest("manifest identifiers must be non-nil".into()));
    }
    if !(super::MIN_CHUNK_BYTES..=super::MAX_CHUNK_BYTES).contains(&(manifest.chunk_size_bytes as usize)) {
        return Err(MerkleSyncError::InvalidManifest("invalid chunk_size_bytes".into()));
    }
    let fmt = manifest.git_state.object_format;
    match &manifest.git_state.head {
        HeadSnapshot::Attached { ref_name, commit_oid, tree_oid } => {
            if !ref_name.starts_with("refs/") || !is_valid_oid_hex(commit_oid, fmt) || !is_valid_oid_hex(tree_oid, fmt)
            {
                return Err(MerkleSyncError::InvalidManifest("invalid attached HEAD metadata".into()));
            }
        }
        HeadSnapshot::Detached { commit_oid, tree_oid } => {
            if !is_valid_oid_hex(commit_oid, fmt) || !is_valid_oid_hex(tree_oid, fmt) {
                return Err(MerkleSyncError::InvalidManifest("invalid detached HEAD metadata".into()));
            }
        }
        HeadSnapshot::Unborn { ref_name } => {
            if !ref_name.starts_with("refs/") {
                return Err(MerkleSyncError::InvalidManifest("invalid unborn HEAD ref".into()));
            }
        }
    }
    let mut prev_idx_key: Option<(&str, u8)> = None;
    for entry in &manifest.git_state.index_entries {
        let path_raw = STANDARD
            .decode(&entry.path_base64)
            .map_err(|_| MerkleSyncError::InvalidManifest("invalid index path_base64".into()))?;
        validate_rel_path_bytes(&path_raw)?;
        if encode_rel_bytes(&path_raw) != entry.path_base64 {
            return Err(MerkleSyncError::InvalidManifest("non-canonical index path_base64".into()));
        }
        if entry.stage > 3 || !is_valid_oid_hex(&entry.git_oid, fmt) {
            return Err(MerkleSyncError::InvalidManifest("invalid index entry stage or oid".into()));
        }
        let key = (entry.path_base64.as_str(), entry.stage);
        if let Some(prev) = prev_idx_key
            && prev >= key
        {
            return Err(MerkleSyncError::InvalidManifest("index_entries must be unique and sorted".into()));
        }
        prev_idx_key = Some(key);
    }
    for opt_head in
        [&manifest.git_state.merge_head, &manifest.git_state.cherry_pick_head, &manifest.git_state.rebase_head]
    {
        if let Some(h) = opt_head
            && !is_valid_oid_hex(h, fmt)
        {
            return Err(MerkleSyncError::InvalidManifest("invalid merge/cherry-pick/rebase head oid".into()));
        }
    }
    if !is_valid_sha256_hex(&manifest.git_state.index_raw_sha256)
        || !is_valid_sha256_hex(&manifest.ignore_policy.ignore_rules_digest)
    {
        return Err(MerkleSyncError::InvalidManifest("invalid sha256 metadata field".into()));
    }
    verify_manifest_integrity(manifest)
}

pub fn verify_manifest_integrity(manifest: &MerkleStateManifest) -> Result<(), MerkleSyncError> {
    let expected_index_root = compute_index_merkle_root(
        manifest.git_state.object_format,
        &manifest.git_state.index_entries,
        &manifest.git_state.index_raw_sha256,
        manifest.git_state.merge_head.as_deref(),
        manifest.git_state.cherry_pick_head.as_deref(),
        manifest.git_state.rebase_head.as_deref(),
    );
    if expected_index_root != manifest.git_state.index_merkle_root {
        return Err(MerkleSyncError::IntegrityMismatch("index_merkle_root mismatch".into()));
    }
    for k in manifest.nodes.keys() {
        if !k.is_empty() && encode_rel_bytes(&decode_rel_bytes(k)?) != *k {
            return Err(MerkleSyncError::InvalidManifest("non-canonical node key base64".into()));
        }
    }
    let root_node =
        manifest.nodes.get("").ok_or_else(|| MerkleSyncError::InvalidManifest("missing root directory node".into()))?;
    if root_node.node_sha256 != manifest.worktree_root_digest {
        return Err(MerkleSyncError::IntegrityMismatch("worktree_root_digest mismatch".into()));
    }
    let (mut visited_entries, mut total_bytes, mut total_chunks) = (0usize, 0u64, 0usize);
    reserve_tree_entry(&mut visited_entries, MAX_TREE_ENTRIES)?;
    let mut visited_nodes = BTreeSet::new();
    let _ = verify_node_recursive(
        manifest,
        "",
        &mut visited_entries,
        &mut total_bytes,
        &mut total_chunks,
        &mut visited_nodes,
    )?;
    if visited_nodes.len() != manifest.nodes.len() {
        return Err(MerkleSyncError::InvalidManifest("orphan directory node present in manifest".into()));
    }
    let expected_state_root = compute_state_merkle_root(
        &manifest.git_state,
        &manifest.ignore_policy,
        &manifest.worktree_root_digest,
        manifest.chunk_size_bytes,
    );
    if expected_state_root != manifest.merkle_root_digest {
        return Err(MerkleSyncError::IntegrityMismatch("merkle_root_digest mismatch".into()));
    }
    Ok(())
}

fn verify_node_recursive(
    manifest: &MerkleStateManifest,
    dir_b64: &str,
    visited_entries: &mut usize,
    total_bytes: &mut u64,
    total_chunks: &mut usize,
    visited_nodes: &mut BTreeSet<String>,
) -> Result<(u64, u64), MerkleSyncError> {
    if !visited_nodes.insert(dir_b64.to_owned()) {
        return Err(MerkleSyncError::InvalidManifest("cycle in directory manifest".into()));
    }
    let node = manifest
        .nodes
        .get(dir_b64)
        .ok_or_else(|| MerkleSyncError::InvalidManifest("missing referenced directory node".into()))?;
    if node.schema != MERKLE_MANIFEST_SCHEMA
        || node.codec_version != MERKLE_CODEC_VERSION
        || node.dir_path_base64 != dir_b64
        || (!dir_b64.is_empty() && node.children.is_empty())
    {
        return Err(MerkleSyncError::InvalidManifest("directory node header or emptiness invalid".into()));
    }
    if compute_dir_node_sha256(dir_b64, &node.children) != node.node_sha256 {
        return Err(MerkleSyncError::IntegrityMismatch("directory node_sha256 mismatch".into()));
    }
    let parent_raw = if dir_b64.is_empty() { Vec::new() } else { decode_rel_bytes(dir_b64)? };
    let mut prev_name: Option<Vec<u8>> = None;
    let (mut exp_files, mut exp_bytes) = (0u64, 0u64);
    for ch in &node.children {
        reserve_tree_entry(visited_entries, MAX_TREE_ENTRIES)?;
        let name_raw = STANDARD
            .decode(&ch.name_base64)
            .map_err(|_| MerkleSyncError::InvalidManifest("invalid child name_base64".into()))?;
        if STANDARD.encode(&name_raw) != ch.name_base64 {
            return Err(MerkleSyncError::InvalidManifest("non-canonical child name_base64".into()));
        }
        if let Some(prev) = &prev_name
            && *prev >= name_raw
        {
            return Err(MerkleSyncError::InvalidManifest("directory children not strictly sorted and unique".into()));
        }
        prev_name = Some(name_raw.clone());
        let mut child_raw = parent_raw.clone();
        if !child_raw.is_empty() {
            child_raw.push(b'/');
        }
        child_raw.extend_from_slice(&name_raw);
        validate_rel_path_bytes(&child_raw)?;
        let (add_files, add_bytes) = match ch.kind {
            MerkleChildKind::File => {
                if ch.mode > 0o777
                    || ch.mode & 0o7000 != 0
                    || ch.target_base64.is_some()
                    || ch.subtree_node_sha256.is_some()
                {
                    return Err(MerkleSyncError::InvalidManifest("invalid file child metadata".into()));
                }
                reserve_workspace_bytes(total_bytes, ch.size, MAX_WORKSPACE_BYTES)?;
                let sha = ch
                    .content_sha256
                    .as_deref()
                    .ok_or_else(|| MerkleSyncError::InvalidManifest("file missing content_sha256".into()))?;
                if !is_valid_sha256_hex(sha) || ch.chunks.is_empty() {
                    return Err(MerkleSyncError::InvalidManifest("invalid file content_sha256 or empty chunks".into()));
                }
                let exp_chunks = expected_chunk_count(ch.size, manifest.chunk_size_bytes as usize)?;
                reserve_chunk_budget(total_chunks, ch.chunks.len(), MAX_TOTAL_CHUNKS)?;
                if ch.chunks.len() != exp_chunks {
                    return Err(MerkleSyncError::InvalidManifest("unexpected chunk count for file size".into()));
                }
                let mut sum = 0u64;
                let chunk_sz = manifest.chunk_size_bytes as u64;
                for (i, chunk) in ch.chunks.iter().enumerate() {
                    let exp_len = if ch.size == 0 { 0 } else { (ch.size - sum).min(chunk_sz) };
                    if chunk.index as usize != i
                        || chunk.offset != sum
                        || chunk.len != exp_len
                        || !is_valid_sha256_hex(&chunk.sha256)
                    {
                        return Err(MerkleSyncError::InvalidManifest("invalid chunk layout".into()));
                    }
                    sum = sum
                        .checked_add(chunk.len)
                        .ok_or_else(|| MerkleSyncError::InvalidManifest("chunk offset overflow".into()))?;
                }
                if sum != ch.size {
                    return Err(MerkleSyncError::InvalidManifest("chunk lengths do not sum to file size".into()));
                }
                if ch.subtree_file_count != 1 || ch.subtree_total_bytes != ch.size {
                    return Err(MerkleSyncError::IntegrityMismatch("file subtree counters mismatch".into()));
                }
                (1u64, ch.size)
            }
            MerkleChildKind::Symlink => {
                reserve_workspace_bytes(total_bytes, ch.size, MAX_WORKSPACE_BYTES)?;
                let tgt_b64 = ch
                    .target_base64
                    .as_deref()
                    .ok_or_else(|| MerkleSyncError::InvalidManifest("symlink missing target".into()))?;
                let tgt_raw = STANDARD
                    .decode(tgt_b64)
                    .map_err(|_| MerkleSyncError::InvalidManifest("invalid symlink target_base64".into()))?;
                if STANDARD.encode(&tgt_raw) != tgt_b64
                    || tgt_raw.is_empty()
                    || tgt_raw.starts_with(b"/")
                    || tgt_raw.contains(&0)
                    || tgt_raw.len() as u64 != ch.size
                    || ch.mode != 0o777
                    || !ch.chunks.is_empty()
                    || ch.subtree_node_sha256.is_some()
                    || !ch.content_sha256.as_deref().is_some_and(|s| s == hex::encode(Sha256::digest(&tgt_raw)))
                    || ch.subtree_file_count != 1
                    || ch.subtree_total_bytes != ch.size
                {
                    return Err(MerkleSyncError::InvalidManifest("invalid symlink entry or counters".into()));
                }
                (1u64, ch.size)
            }
            MerkleChildKind::EmptyDir => {
                if matches!(manifest.ignore_policy.empty_dir_policy, EmptyDirPolicy::IgnoreEmptyDirs) {
                    return Err(MerkleSyncError::InvalidManifest(
                        "empty directory entry disallowed by IgnoreEmptyDirs policy".into(),
                    ));
                }
                if ch.mode != 0o755
                    || ch.size != 0
                    || !ch.chunks.is_empty()
                    || ch.content_sha256.is_some()
                    || ch.target_base64.is_some()
                    || ch.subtree_node_sha256.is_some()
                    || ch.subtree_file_count != 0
                    || ch.subtree_total_bytes != 0
                {
                    return Err(MerkleSyncError::InvalidManifest("invalid empty_dir metadata or counters".into()));
                }
                (0u64, 0u64)
            }
            MerkleChildKind::Subdir => {
                if ch.mode != 0o755
                    || ch.size != 0
                    || !ch.chunks.is_empty()
                    || ch.content_sha256.is_some()
                    || ch.target_base64.is_some()
                {
                    return Err(MerkleSyncError::InvalidManifest("invalid subdir entry metadata".into()));
                }
                let sub_b64 = encode_rel_bytes(&child_raw);
                let sub_sha = ch
                    .subtree_node_sha256
                    .as_deref()
                    .ok_or_else(|| MerkleSyncError::InvalidManifest("subdir missing subtree_node_sha256".into()))?;
                let sub_node = manifest
                    .nodes
                    .get(&sub_b64)
                    .ok_or_else(|| MerkleSyncError::InvalidManifest("missing child subdir node".into()))?;
                if sub_node.node_sha256 != sub_sha {
                    return Err(MerkleSyncError::IntegrityMismatch("subdir hash mismatch".into()));
                }
                let (sf, sb) = verify_node_recursive(
                    manifest,
                    &sub_b64,
                    visited_entries,
                    total_bytes,
                    total_chunks,
                    visited_nodes,
                )?;
                if ch.subtree_file_count != sf || ch.subtree_total_bytes != sb {
                    return Err(MerkleSyncError::IntegrityMismatch("subdir derived subtree counters mismatch".into()));
                }
                (sf, sb)
            }
        };
        exp_files = exp_files
            .checked_add(add_files)
            .ok_or_else(|| MerkleSyncError::InvalidManifest("node file count overflow".into()))?;
        exp_bytes = exp_bytes
            .checked_add(add_bytes)
            .ok_or_else(|| MerkleSyncError::InvalidManifest("node byte count overflow".into()))?;
    }
    if node.subtree_file_count != exp_files || node.subtree_total_bytes != exp_bytes {
        return Err(MerkleSyncError::IntegrityMismatch("directory node derived subtree counters mismatch".into()));
    }
    Ok((exp_files, exp_bytes))
}

#[derive(Clone)]
struct LeafEntry {
    path_bytes: Vec<u8>,
    child: MerkleDirChild,
}

fn join_child_rel(parent: &[u8], name: &[u8]) -> Vec<u8> {
    if parent.is_empty() {
        return name.to_vec();
    }
    [parent, b"/", name].concat()
}

fn collect_subtree_leaves(
    manifest: &MerkleStateManifest,
    dir_b64: &str,
    out: &mut Vec<LeafEntry>,
) -> Result<(), MerkleSyncError> {
    let Some(node) = manifest.nodes.get(dir_b64) else { return Ok(()) };
    let parent_raw = if dir_b64.is_empty() { Vec::new() } else { decode_rel_bytes(dir_b64)? };
    for ch in &node.children {
        let name_raw = STANDARD
            .decode(&ch.name_base64)
            .map_err(|_| MerkleSyncError::InvalidManifest("invalid child name_base64".into()))?;
        let child_raw = join_child_rel(&parent_raw, &name_raw);
        if ch.kind == MerkleChildKind::Subdir {
            collect_subtree_leaves(manifest, &encode_rel_bytes(&child_raw), out)?;
        } else {
            out.push(LeafEntry { path_bytes: child_raw, child: ch.clone() });
        }
    }
    Ok(())
}

fn diff_dir_recursive(
    prev: &MerkleStateManifest,
    next: &MerkleStateManifest,
    dir_b64: &str,
    prev_only: &mut Vec<LeafEntry>,
    next_only: &mut Vec<LeafEntry>,
    out: &mut Vec<MerkleDiffEntry>,
) -> Result<(), MerkleSyncError> {
    let prev_node = prev.nodes.get(dir_b64);
    let next_node = next.nodes.get(dir_b64);
    if let (Some(p), Some(n)) = (prev_node, next_node)
        && p.node_sha256 == n.node_sha256
    {
        return Ok(());
    }
    let parent_raw = if dir_b64.is_empty() { Vec::new() } else { decode_rel_bytes(dir_b64)? };
    fn node_children_map(opt: Option<&super::manifest::MerkleDirNode>) -> BTreeMap<Vec<u8>, &MerkleDirChild> {
        opt.map(|n| n.children.iter().filter_map(|c| STANDARD.decode(&c.name_base64).ok().map(|k| (k, c))).collect())
            .unwrap_or_default()
    }
    let (prev_map, next_map) = (node_children_map(prev_node), node_children_map(next_node));
    let names: BTreeSet<Vec<u8>> = prev_map.keys().chain(next_map.keys()).cloned().collect();
    for name in names {
        let child_raw = join_child_rel(&parent_raw, &name);
        match (prev_map.get(&name).copied(), next_map.get(&name).copied()) {
            (Some(p), Some(n)) if p.kind == MerkleChildKind::Subdir && n.kind == MerkleChildKind::Subdir => {
                if p.subtree_node_sha256 != n.subtree_node_sha256 {
                    diff_dir_recursive(prev, next, &encode_rel_bytes(&child_raw), prev_only, next_only, out)?;
                }
            }
            (Some(p), Some(n)) if p.kind == MerkleChildKind::Subdir => {
                collect_subtree_leaves(prev, &encode_rel_bytes(&child_raw), prev_only)?;
                next_only.push(LeafEntry { path_bytes: child_raw, child: n.clone() });
            }
            (Some(p), Some(n)) if n.kind == MerkleChildKind::Subdir => {
                prev_only.push(LeafEntry { path_bytes: child_raw.clone(), child: p.clone() });
                collect_subtree_leaves(next, &encode_rel_bytes(&child_raw), next_only)?;
            }
            (Some(p), Some(n)) => {
                let change = if p.kind != n.kind {
                    Some(MerkleChangeKind::TypeChanged)
                } else if p.content_sha256 != n.content_sha256 || p.target_base64 != n.target_base64 {
                    Some(MerkleChangeKind::Modified)
                } else if p.mode != n.mode {
                    Some(MerkleChangeKind::ModeChanged)
                } else {
                    None
                };
                if let Some(ch_kind) = change {
                    out.push(MerkleDiffEntry {
                        change: ch_kind,
                        path_base64: encode_rel_bytes(&child_raw),
                        old_path_base64: None,
                        kind: n.kind,
                        old_mode: Some(p.mode),
                        new_mode: Some(n.mode),
                        content_sha256: n.content_sha256.clone(),
                    });
                }
            }
            (Some(p), None) => {
                if p.kind == MerkleChildKind::Subdir {
                    collect_subtree_leaves(prev, &encode_rel_bytes(&child_raw), prev_only)?;
                } else {
                    prev_only.push(LeafEntry { path_bytes: child_raw, child: p.clone() });
                }
            }
            (None, Some(n)) => {
                if n.kind == MerkleChildKind::Subdir {
                    collect_subtree_leaves(next, &encode_rel_bytes(&child_raw), next_only)?;
                } else {
                    next_only.push(LeafEntry { path_bytes: child_raw, child: n.clone() });
                }
            }
            (None, None) => {}
        }
    }
    Ok(())
}

pub fn diff_manifests(
    prev: &MerkleStateManifest,
    next: &MerkleStateManifest,
) -> Result<Vec<MerkleDiffEntry>, MerkleSyncError> {
    let mut prev_only = Vec::new();
    let mut next_only = Vec::new();
    let mut out = Vec::new();
    diff_dir_recursive(prev, next, "", &mut prev_only, &mut next_only, &mut out)?;

    let mut matched_prev = vec![false; prev_only.len()];
    let mut matched_next = vec![false; next_only.len()];
    for (ni, n) in next_only.iter().enumerate() {
        if !matches!(n.child.kind, MerkleChildKind::File | MerkleChildKind::Symlink) {
            continue;
        }
        if let Some((pi, p)) = prev_only.iter().enumerate().find(|(pi, p)| {
            !matched_prev[*pi]
                && p.child.kind == n.child.kind
                && p.child.size == n.child.size
                && p.child.content_sha256 == n.child.content_sha256
        }) {
            matched_prev[pi] = true;
            matched_next[ni] = true;
            out.push(MerkleDiffEntry {
                change: MerkleChangeKind::Renamed,
                path_base64: encode_rel_bytes(&n.path_bytes),
                old_path_base64: Some(encode_rel_bytes(&p.path_bytes)),
                kind: n.child.kind,
                old_mode: Some(p.child.mode),
                new_mode: Some(n.child.mode),
                content_sha256: n.child.content_sha256.clone(),
            });
        }
    }
    let push_unmatched = |out: &mut Vec<MerkleDiffEntry>, leaf: LeafEntry, is_add: bool| {
        let is_empty = leaf.child.kind == MerkleChildKind::EmptyDir;
        let change = match (is_add, is_empty) {
            (false, true) => MerkleChangeKind::EmptyDirRemoved,
            (false, false) => MerkleChangeKind::Deleted,
            (true, true) => MerkleChangeKind::EmptyDirAdded,
            (true, false) => MerkleChangeKind::Added,
        };
        out.push(MerkleDiffEntry {
            change,
            path_base64: encode_rel_bytes(&leaf.path_bytes),
            old_path_base64: None,
            kind: leaf.child.kind,
            old_mode: (!is_add).then_some(leaf.child.mode),
            new_mode: is_add.then_some(leaf.child.mode),
            content_sha256: leaf.child.content_sha256,
        });
    };
    for (_pi, p) in prev_only.into_iter().enumerate().filter(|(i, _)| !matched_prev[*i]) {
        push_unmatched(&mut out, p, false);
    }
    for (_ni, n) in next_only.into_iter().enumerate().filter(|(i, _)| !matched_next[*i]) {
        push_unmatched(&mut out, n, true);
    }
    out.sort_by(|a, b| a.path_base64.cmp(&b.path_base64));
    Ok(out)
}
