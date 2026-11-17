use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::ffi::OsStrExt,
    path::Path,
    time::Instant,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    MAX_CHUNK_BYTES, MAX_TREE_ENTRIES, MAX_WORKSPACE_BYTES, MerkleSyncError,
    git_state::IgnoreSnapshot,
    manifest::{
        GitStateSnapshot, MerkleChildKind, MerkleDirChild, MerkleDirNode, MerkleStateManifest, build_dir_node,
        compute_state_merkle_root, decode_rel_bytes, encode_rel_bytes, validate_rel_path_bytes,
    },
    scan_fs::{
        LeafMetricsOut, build_leaf_child, can_reuse_clean_leaf, is_empty_dir_retained, rel_path_from_bytes,
        reserve_child_limits, reserve_tree_entry, should_include_leaf,
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirtyScope {
    FullRescan,
    Subtrees { dirty_dirs: BTreeSet<Vec<u8>>, dirty_paths: BTreeSet<Vec<u8>>, force_rehash_dirs: BTreeSet<Vec<u8>> },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanMetrics {
    pub full_scan: bool,
    pub scanned_dirs: u64,
    pub scanned_files: u64,
    pub scanned_bytes: u64,
    pub hashed_bytes: u64,
    pub recomputed_nodes: u64,
    pub reused_nodes: u64,
    pub excluded_ignored_entries: u64,
    pub retained_empty_dirs: u64,
    pub scan_duration_ms: f64,
}

#[derive(Clone, Debug)]
pub struct ScanRequest<'a> {
    pub repo_root: &'a Path,
    pub workspace_id: Uuid,
    pub checkpoint_id: Uuid,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub parent_checkpoint_id: Option<Uuid>,
    pub chunk_size_bytes: u32,
    pub git_state: &'a GitStateSnapshot,
    pub ignore: &'a IgnoreSnapshot,
    pub previous: Option<&'a MerkleStateManifest>,
    pub dirty_scope: DirtyScope,
}

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub manifest: MerkleStateManifest,
    pub metrics: ScanMetrics,
    pub chunk_sources: BTreeMap<String, Vec<(u64, u64, Vec<u8>)>>,
}

struct ScanState<'a> {
    repo: &'a Path,
    chunk_size: usize,
    ignore: &'a IgnoreSnapshot,
    previous: Option<&'a MerkleStateManifest>,
    full_scan: bool,
    descend_dirs: BTreeSet<Vec<u8>>,
    ancestor_dirs: BTreeSet<Vec<u8>>,
    dirty_paths: BTreeSet<Vec<u8>>,
    force_rehash_dirs: BTreeSet<Vec<u8>>,
    git_ignored_dirs_cache: BTreeSet<Vec<u8>>,
    nodes: BTreeMap<String, MerkleDirNode>,
    chunk_sources: BTreeMap<String, Vec<(u64, u64, Vec<u8>)>>,
    work_entries: usize,
    total_entries: usize,
    total_bytes: u64,
    max_entries: usize,
    max_bytes: u64,
    metrics: ScanMetrics,
}

pub struct MerkleWorkspaceScanner;

impl MerkleWorkspaceScanner {
    pub fn scan(req: ScanRequest<'_>) -> Result<ScanResult, MerkleSyncError> {
        Self::scan_with_limits(req, MAX_TREE_ENTRIES, MAX_WORKSPACE_BYTES)
    }

    pub(crate) fn scan_with_limits(
        req: ScanRequest<'_>,
        max_entries: usize,
        max_bytes: u64,
    ) -> Result<ScanResult, MerkleSyncError> {
        let started = Instant::now();
        if req.chunk_size_bytes == 0 || req.chunk_size_bytes as usize > MAX_CHUNK_BYTES {
            return Err(MerkleSyncError::InvalidInput("chunk_size_bytes out of bounds".into()));
        }
        let mut full_scan = matches!(req.dirty_scope, DirtyScope::FullRescan) || req.previous.is_none();
        if let Some(prev) = req.previous
            && (prev.chunk_size_bytes != req.chunk_size_bytes || prev.ignore_policy != req.ignore.policy)
        {
            full_scan = true;
        }
        let (mut descend_dirs, mut dirty_paths, force_rehash_dirs) = match req.dirty_scope {
            DirtyScope::FullRescan => (BTreeSet::new(), BTreeSet::new(), BTreeSet::new()),
            DirtyScope::Subtrees { dirty_dirs, dirty_paths, force_rehash_dirs } => {
                (dirty_dirs, dirty_paths, force_rehash_dirs)
            }
        };
        if !full_scan
            && let Some(prev) = req.previous
            && prev.git_state.index_merkle_root != req.git_state.index_merkle_root
        {
            let prev_idx: BTreeMap<&str, &str> =
                prev.git_state.index_entries.iter().map(|e| (e.path_base64.as_str(), e.git_oid.as_str())).collect();
            let curr_idx: BTreeMap<&str, &str> =
                req.git_state.index_entries.iter().map(|e| (e.path_base64.as_str(), e.git_oid.as_str())).collect();
            for p_b64 in prev_idx.keys().chain(curr_idx.keys()) {
                if prev_idx.get(p_b64) != curr_idx.get(p_b64)
                    && let Ok(raw) = decode_rel_bytes(p_b64)
                {
                    dirty_paths.insert(raw);
                }
            }
        }
        if full_scan {
            descend_dirs.clear();
            descend_dirs.insert(Vec::new());
        } else {
            for p in &dirty_paths {
                descend_dirs.insert(parent_dir_bytes(p));
            }
            if let Some(prev) = req.previous {
                // Any newly introduced directory path adds a child entry to its nearest pre-existing ancestor.
                let seed: Vec<Vec<u8>> = descend_dirs.iter().cloned().collect();
                for mut cur in seed {
                    while !cur.is_empty() {
                        let parent = parent_dir_bytes(&cur);
                        if !prev.nodes.contains_key(&encode_rel_bytes(&cur)) {
                            descend_dirs.insert(parent.clone());
                        }
                        cur = parent;
                    }
                }
            }
        }
        let mut ancestor_dirs = BTreeSet::new();
        for d in &descend_dirs {
            let mut cur = parent_dir_bytes(d);
            while !cur.is_empty() {
                ancestor_dirs.insert(cur.clone());
                cur = parent_dir_bytes(&cur);
            }
            if !d.is_empty() {
                ancestor_dirs.insert(Vec::new());
            }
        }
        let mut st = ScanState {
            repo: req.repo_root,
            chunk_size: req.chunk_size_bytes as usize,
            ignore: req.ignore,
            previous: if full_scan { None } else { req.previous },
            full_scan,
            descend_dirs,
            ancestor_dirs,
            dirty_paths,
            force_rehash_dirs,
            git_ignored_dirs_cache: BTreeSet::new(),
            nodes: BTreeMap::new(),
            chunk_sources: BTreeMap::new(),
            work_entries: 0,
            total_entries: 0,
            total_bytes: 0,
            max_entries,
            max_bytes,
            metrics: ScanMetrics {
                full_scan,
                scanned_dirs: 0,
                scanned_files: 0,
                scanned_bytes: 0,
                hashed_bytes: 0,
                recomputed_nodes: 0,
                reused_nodes: 0,
                excluded_ignored_entries: 0,
                retained_empty_dirs: 0,
                scan_duration_ms: 0.0,
            },
        };
        reserve_tree_entry(&mut st.total_entries, st.max_entries)?;
        let root_node = scan_dir_node(&mut st, &[])?
            .ok_or_else(|| MerkleSyncError::InvalidManifest("root directory missing".into()))?;
        let worktree_root_digest = root_node.node_sha256.clone();
        st.nodes.insert(String::new(), root_node);
        let merkle_root_digest =
            compute_state_merkle_root(req.git_state, &req.ignore.policy, &worktree_root_digest, req.chunk_size_bytes);
        st.metrics.scan_duration_ms = started.elapsed().as_secs_f64() * 1000.0;
        let manifest = MerkleStateManifest {
            schema: super::MERKLE_MANIFEST_SCHEMA,
            codec_version: super::MERKLE_CODEC_VERSION.to_owned(),
            workspace_id: req.workspace_id,
            checkpoint_id: req.checkpoint_id,
            tenant_id: req.tenant_id,
            repo_id: req.repo_id,
            history_id: req.history_id,
            parent_checkpoint_id: req.parent_checkpoint_id,
            chunk_size_bytes: req.chunk_size_bytes,
            git_state: req.git_state.clone(),
            ignore_policy: req.ignore.policy.clone(),
            worktree_root_digest,
            nodes: st.nodes,
            merkle_root_digest,
        };
        Ok(ScanResult { manifest, metrics: st.metrics, chunk_sources: st.chunk_sources })
    }
}

fn parent_dir_bytes(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|b| *b == b'/') {
        Some(idx) => path[..idx].to_vec(),
        None => Vec::new(),
    }
}

fn join_rel(parent: &[u8], name: &[u8]) -> Vec<u8> {
    if parent.is_empty() {
        return name.to_vec();
    }
    let mut out = Vec::with_capacity(parent.len() + 1 + name.len());
    out.extend_from_slice(parent);
    out.push(b'/');
    out.extend_from_slice(name);
    out
}

fn copy_clean_subtree(
    st: &mut ScanState<'_>,
    prev: &MerkleStateManifest,
    dir_b64: &str,
) -> Result<Option<MerkleDirNode>, MerkleSyncError> {
    let Some(node) = prev.nodes.get(dir_b64) else { return Ok(None) };
    let parent_raw = if dir_b64.is_empty() { Vec::new() } else { decode_rel_bytes(dir_b64)? };
    for ch in &node.children {
        let name = STANDARD.decode(&ch.name_base64).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
        let child_raw = join_rel(&parent_raw, &name);
        reserve_child_limits(&mut st.total_entries, &mut st.total_bytes, st.max_entries, st.max_bytes, ch)?;
        match ch.kind {
            MerkleChildKind::File | MerkleChildKind::Symlink => {}
            MerkleChildKind::EmptyDir => st.metrics.retained_empty_dirs += 1,
            MerkleChildKind::Subdir => {
                if copy_clean_subtree(st, prev, &encode_rel_bytes(&child_raw))?.is_none() {
                    return Err(MerkleSyncError::InvalidManifest("clean subtree missing node".into()));
                }
            }
        }
    }
    st.metrics.reused_nodes += 1;
    st.nodes.insert(dir_b64.to_owned(), node.clone());
    Ok(Some(node.clone()))
}

fn can_reuse_clean_dir(st: &ScanState<'_>, dir_raw: &[u8]) -> bool {
    if st.full_scan
        || st.descend_dirs.contains(dir_raw)
        || st.ancestor_dirs.contains(dir_raw)
        || st.force_rehash_dirs.contains(dir_raw)
    {
        return false;
    }
    if st
        .force_rehash_dirs
        .iter()
        .any(|d| d.is_empty() || (dir_raw.starts_with(d) && dir_raw.get(d.len()) == Some(&b'/')))
    {
        return false;
    }
    st.previous.is_some_and(|p| p.nodes.contains_key(&encode_rel_bytes(dir_raw)))
}

fn make_subdir_child(name_base64: String, sub_node: &MerkleDirNode) -> MerkleDirChild {
    MerkleDirChild {
        name_base64,
        kind: MerkleChildKind::Subdir,
        mode: 0o755,
        size: 0,
        content_sha256: None,
        target_base64: None,
        chunks: Vec::new(),
        subtree_node_sha256: Some(sub_node.node_sha256.clone()),
        subtree_file_count: sub_node.subtree_file_count,
        subtree_total_bytes: sub_node.subtree_total_bytes,
    }
}

fn make_empty_dir_child(name_base64: String) -> MerkleDirChild {
    MerkleDirChild {
        name_base64,
        kind: MerkleChildKind::EmptyDir,
        mode: 0o755,
        size: 0,
        content_sha256: None,
        target_base64: None,
        chunks: Vec::new(),
        subtree_node_sha256: None,
        subtree_file_count: 0,
        subtree_total_bytes: 0,
    }
}

fn scan_dir_node(st: &mut ScanState<'_>, dir_raw: &[u8]) -> Result<Option<MerkleDirNode>, MerkleSyncError> {
    let dir_b64 = encode_rel_bytes(dir_raw);
    if can_reuse_clean_dir(st, dir_raw)
        && let Some(prev) = st.previous
        && let Some(node) = copy_clean_subtree(st, prev, &dir_b64)?
    {
        return Ok(Some(node));
    }
    let disk_dir = if dir_raw.is_empty() { st.repo.to_path_buf() } else { st.repo.join(rel_path_from_bytes(dir_raw)) };
    let dir_meta = match fs::symlink_metadata(&disk_dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !dir_meta.is_dir() {
        return Ok(None);
    }
    let descend_here = st.full_scan
        || st.descend_dirs.contains(dir_raw)
        || st.previous.is_none_or(|p| !p.nodes.contains_key(&dir_b64));
    if !descend_here
        && let Some(prev) = st.previous
        && let Some(prev_node) = prev.nodes.get(&dir_b64)
    {
        return update_ancestor_dir_only(st, dir_raw, &dir_b64, prev_node);
    }
    st.metrics.scanned_dirs += 1;
    let force_rehash_dir = st.full_scan || st.force_rehash_dirs.contains(dir_raw);
    let prev_children: BTreeMap<Vec<u8>, MerkleDirChild> = st
        .previous
        .and_then(|p| p.nodes.get(&dir_b64))
        .map(|n| {
            n.children.iter().filter_map(|c| STANDARD.decode(&c.name_base64).ok().map(|k| (k, c.clone()))).collect()
        })
        .unwrap_or_default();
    let max_work = st.max_entries.saturating_mul(2).max(32);
    let mut entries = Vec::new();
    for item in fs::read_dir(&disk_dir)? {
        let item = item?;
        let name_bytes = item.file_name().as_bytes().to_vec();
        if name_bytes == b".git" {
            if !dir_raw.is_empty() {
                return Err(MerkleSyncError::UnsupportedGitState("nested .git directory unsupported".into()));
            }
            continue;
        }
        reserve_tree_entry(&mut st.work_entries, max_work)?;
        entries.push((name_bytes, item.path()));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut children = Vec::new();
    for (name_bytes, full_path) in entries {
        let child_raw = join_rel(dir_raw, &name_bytes);
        validate_rel_path_bytes(&child_raw)?;
        let meta = fs::symlink_metadata(&full_path)?;
        let name_b64 = STANDARD.encode(&name_bytes);
        if meta.is_dir() {
            if let Some(sub_node) = scan_dir_node(st, &child_raw)? {
                reserve_tree_entry(&mut st.total_entries, st.max_entries)?;
                children.push(make_subdir_child(name_b64, &sub_node));
                st.nodes.insert(encode_rel_bytes(&child_raw), sub_node);
            } else if is_empty_dir_retained(st.repo, st.ignore, &mut st.git_ignored_dirs_cache, &child_raw)? {
                reserve_tree_entry(&mut st.total_entries, st.max_entries)?;
                st.metrics.retained_empty_dirs += 1;
                children.push(make_empty_dir_child(name_b64));
            }
            continue;
        }
        if !should_include_leaf(st.ignore, &child_raw, &mut st.metrics.excluded_ignored_entries) {
            continue;
        }
        if !force_rehash_dir
            && !st.dirty_paths.contains(&child_raw)
            && let Some(prev_ch) = prev_children.get(&name_bytes)
            && can_reuse_clean_leaf(&meta, prev_ch)
        {
            reserve_child_limits(&mut st.total_entries, &mut st.total_bytes, st.max_entries, st.max_bytes, prev_ch)?;
            st.metrics.reused_nodes += 1;
            children.push(prev_ch.clone());
            continue;
        }
        let mut metrics_out = LeafMetricsOut {
            scanned_files: &mut st.metrics.scanned_files,
            scanned_bytes: &mut st.metrics.scanned_bytes,
            hashed_bytes: &mut st.metrics.hashed_bytes,
            total_entries: &mut st.total_entries,
            total_bytes: &mut st.total_bytes,
            max_entries: st.max_entries,
            max_bytes: st.max_bytes,
            chunk_sources: &mut st.chunk_sources,
        };
        let leaf =
            build_leaf_child(st.repo, st.chunk_size, &child_raw, &name_bytes, &full_path, &meta, &mut metrics_out)?;
        st.metrics.recomputed_nodes += 1;
        children.push(leaf);
    }
    if !dir_raw.is_empty() && children.is_empty() {
        return Ok(None);
    }
    st.metrics.recomputed_nodes += 1;
    Ok(Some(build_dir_node(dir_b64, children)?))
}

fn update_ancestor_dir_only(
    st: &mut ScanState<'_>,
    dir_raw: &[u8],
    dir_b64: &str,
    prev_node: &MerkleDirNode,
) -> Result<Option<MerkleDirNode>, MerkleSyncError> {
    let mut children = Vec::new();
    for ch in &prev_node.children {
        let name = STANDARD.decode(&ch.name_base64).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
        if ch.kind == MerkleChildKind::Subdir {
            let child_raw = join_rel(dir_raw, &name);
            if let Some(sub_node) = scan_dir_node(st, &child_raw)? {
                reserve_tree_entry(&mut st.total_entries, st.max_entries)?;
                children.push(make_subdir_child(ch.name_base64.clone(), &sub_node));
                st.nodes.insert(encode_rel_bytes(&child_raw), sub_node);
            } else if is_empty_dir_retained(st.repo, st.ignore, &mut st.git_ignored_dirs_cache, &child_raw)? {
                reserve_tree_entry(&mut st.total_entries, st.max_entries)?;
                st.metrics.retained_empty_dirs += 1;
                children.push(make_empty_dir_child(ch.name_base64.clone()));
            }
        } else {
            reserve_child_limits(&mut st.total_entries, &mut st.total_bytes, st.max_entries, st.max_bytes, ch)?;
            if ch.kind == MerkleChildKind::EmptyDir {
                st.metrics.retained_empty_dirs += 1;
            } else {
                st.metrics.reused_nodes += 1;
            }
            children.push(ch.clone());
        }
    }
    if !dir_raw.is_empty() && children.is_empty() {
        return Ok(None);
    }
    st.metrics.recomputed_nodes += 1;
    Ok(Some(build_dir_node(dir_b64.to_owned(), children)?))
}
