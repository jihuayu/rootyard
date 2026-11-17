use std::collections::BTreeSet;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{MERKLE_CODEC_VERSION, MERKLE_MANIFEST_SCHEMA, MerkleSyncError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MerkleObjectFormat {
    Sha1,
    Sha256,
}

impl MerkleObjectFormat {
    pub fn oid_hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    pub fn oid_byte_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmptyDirPolicy {
    IgnoreEmptyDirs,
    RetainEmptyDirs,
    RetainNonIgnoredEmptyDirs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UntrackedPolicy {
    IncludeNonIgnored,
    TrackedOnly,
    IncludeAllExceptGit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnorePolicySpec {
    pub untracked_policy: UntrackedPolicy,
    pub empty_dir_policy: EmptyDirPolicy,
    pub use_gitignore: bool,
    pub use_rootyardignore: bool,
    pub ignore_rules_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkRef {
    pub index: u32,
    pub offset: u64,
    pub len: u64,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MerkleChildKind {
    File,
    Symlink,
    Subdir,
    EmptyDir,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerkleDirChild {
    pub name_base64: String,
    pub kind: MerkleChildKind,
    pub mode: u32,
    pub size: u64,
    pub content_sha256: Option<String>,
    pub target_base64: Option<String>,
    pub chunks: Vec<ChunkRef>,
    pub subtree_node_sha256: Option<String>,
    pub subtree_file_count: u64,
    pub subtree_total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerkleDirNode {
    pub schema: u32,
    pub codec_version: String,
    pub dir_path_base64: String,
    pub children: Vec<MerkleDirChild>,
    pub node_sha256: String,
    pub subtree_file_count: u64,
    pub subtree_total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HeadSnapshot {
    Attached { ref_name: String, commit_oid: String, tree_oid: String },
    Detached { commit_oid: String, tree_oid: String },
    Unborn { ref_name: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitIndexEntryRecord {
    pub path_base64: String,
    pub stage: u8,
    pub mode: u32,
    pub git_oid: String,
    pub size: u64,
    pub intent_to_add: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitStateSnapshot {
    pub object_format: MerkleObjectFormat,
    pub head: HeadSnapshot,
    pub index_entries: Vec<GitIndexEntryRecord>,
    pub index_raw_sha256: String,
    pub index_merkle_root: String,
    pub merge_head: Option<String>,
    pub cherry_pick_head: Option<String>,
    pub rebase_head: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerkleStateManifest {
    pub schema: u32,
    pub codec_version: String,
    pub workspace_id: Uuid,
    pub checkpoint_id: Uuid,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub parent_checkpoint_id: Option<Uuid>,
    pub chunk_size_bytes: u32,
    pub git_state: GitStateSnapshot,
    pub ignore_policy: IgnorePolicySpec,
    pub worktree_root_digest: String,
    pub nodes: std::collections::BTreeMap<String, MerkleDirNode>,
    pub merkle_root_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MerkleChangeKind {
    Added,
    Modified,
    Deleted,
    ModeChanged,
    TypeChanged,
    Renamed,
    EmptyDirAdded,
    EmptyDirRemoved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerkleDiffEntry {
    pub change: MerkleChangeKind,
    pub path_base64: String,
    pub old_path_base64: Option<String>,
    pub kind: MerkleChildKind,
    pub old_mode: Option<u32>,
    pub new_mode: Option<u32>,
    pub content_sha256: Option<String>,
}

pub fn is_valid_sha256_hex(hex_str: &str) -> bool {
    hex_str.len() == 64 && hex_str.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn is_valid_oid_hex(hex_str: &str, format: MerkleObjectFormat) -> bool {
    hex_str.len() == format.oid_hex_len() && hex_str.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn validate_rel_path_bytes(bytes: &[u8]) -> Result<(), MerkleSyncError> {
    if bytes.is_empty() || bytes.contains(&0) || bytes.ends_with(b"/") || bytes.starts_with(b"/") {
        return Err(MerkleSyncError::InvalidManifest("invalid relative path bytes".into()));
    }
    for segment in bytes.split(|b| *b == b'/') {
        if segment.is_empty() || segment == b"." || segment == b".." || segment == b".git" {
            return Err(MerkleSyncError::InvalidManifest("unsafe or forbidden relative path component".into()));
        }
    }
    Ok(())
}

pub fn encode_rel_bytes(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn decode_rel_bytes(encoded: &str) -> Result<Vec<u8>, MerkleSyncError> {
    let raw =
        STANDARD.decode(encoded).map_err(|e| MerkleSyncError::InvalidManifest(format!("invalid base64 path: {e}")))?;
    if !raw.is_empty() {
        validate_rel_path_bytes(&raw)?;
    }
    Ok(raw)
}

fn feed_field(hasher: &mut Sha256, key: &str, value: &[u8]) {
    hasher.update(key.as_bytes());
    hasher.update(b"=");
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(value);
    hasher.update(b"\n");
}

pub fn compute_dir_node_sha256(dir_path_base64: &str, children: &[MerkleDirChild]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rootyard.merkle-sync.v1:dir-node\0");
    feed_field(&mut hasher, "schema", &MERKLE_MANIFEST_SCHEMA.to_string().into_bytes());
    feed_field(&mut hasher, "dir", dir_path_base64.as_bytes());
    feed_field(&mut hasher, "count", &children.len().to_string().into_bytes());
    for child in children {
        feed_field(&mut hasher, "name", child.name_base64.as_bytes());
        let kind_str = match child.kind {
            MerkleChildKind::File => "file",
            MerkleChildKind::Symlink => "symlink",
            MerkleChildKind::Subdir => "subdir",
            MerkleChildKind::EmptyDir => "empty_dir",
        };
        feed_field(&mut hasher, "kind", kind_str.as_bytes());
        feed_field(&mut hasher, "mode", &child.mode.to_string().into_bytes());
        feed_field(&mut hasher, "size", &child.size.to_string().into_bytes());
        if let Some(sha) = child.content_sha256.as_deref() {
            feed_field(&mut hasher, "content_sha256", sha.as_bytes());
        }
        if let Some(tgt) = child.target_base64.as_deref() {
            feed_field(&mut hasher, "target_base64", tgt.as_bytes());
        }
        if let Some(sub) = child.subtree_node_sha256.as_deref() {
            feed_field(&mut hasher, "subtree_node_sha256", sub.as_bytes());
        }
        for chunk in &child.chunks {
            feed_field(&mut hasher, "chunk_idx", &chunk.index.to_string().into_bytes());
            feed_field(&mut hasher, "chunk_off", &chunk.offset.to_string().into_bytes());
            feed_field(&mut hasher, "chunk_len", &chunk.len.to_string().into_bytes());
            feed_field(&mut hasher, "chunk_sha", chunk.sha256.as_bytes());
        }
    }
    hex::encode(hasher.finalize())
}

pub fn compute_index_merkle_root(
    object_format: MerkleObjectFormat,
    entries: &[GitIndexEntryRecord],
    index_raw_sha256: &str,
    merge_head: Option<&str>,
    cherry_pick_head: Option<&str>,
    rebase_head: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rootyard.merkle-sync.v1:git-index\0");
    feed_field(&mut hasher, "format", object_format.as_str().as_bytes());
    feed_field(&mut hasher, "raw_sha256", index_raw_sha256.as_bytes());
    if let Some(m) = merge_head {
        feed_field(&mut hasher, "merge_head", m.as_bytes());
    }
    if let Some(c) = cherry_pick_head {
        feed_field(&mut hasher, "cherry_pick_head", c.as_bytes());
    }
    if let Some(r) = rebase_head {
        feed_field(&mut hasher, "rebase_head", r.as_bytes());
    }
    for e in entries {
        feed_field(&mut hasher, "path", e.path_base64.as_bytes());
        feed_field(&mut hasher, "stage", &e.stage.to_string().into_bytes());
        feed_field(&mut hasher, "mode", &e.mode.to_string().into_bytes());
        feed_field(&mut hasher, "oid", e.git_oid.as_bytes());
        feed_field(&mut hasher, "size", &e.size.to_string().into_bytes());
        feed_field(&mut hasher, "ita", if e.intent_to_add { b"1" } else { b"0" });
    }
    hex::encode(hasher.finalize())
}

pub fn compute_state_merkle_root(
    git_state: &GitStateSnapshot,
    ignore_policy: &IgnorePolicySpec,
    worktree_root_digest: &str,
    chunk_size_bytes: u32,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"rootyard.merkle-sync.v1:state-root\0");
    feed_field(&mut hasher, "schema", &MERKLE_MANIFEST_SCHEMA.to_string().into_bytes());
    feed_field(&mut hasher, "codec", MERKLE_CODEC_VERSION.as_bytes());
    feed_field(&mut hasher, "chunk_size", &chunk_size_bytes.to_string().into_bytes());
    feed_field(&mut hasher, "format", git_state.object_format.as_str().as_bytes());
    match &git_state.head {
        HeadSnapshot::Attached { ref_name, commit_oid, tree_oid } => {
            feed_field(&mut hasher, "head_kind", b"attached");
            feed_field(&mut hasher, "head_ref", ref_name.as_bytes());
            feed_field(&mut hasher, "head_commit", commit_oid.as_bytes());
            feed_field(&mut hasher, "head_tree", tree_oid.as_bytes());
        }
        HeadSnapshot::Detached { commit_oid, tree_oid } => {
            feed_field(&mut hasher, "head_kind", b"detached");
            feed_field(&mut hasher, "head_commit", commit_oid.as_bytes());
            feed_field(&mut hasher, "head_tree", tree_oid.as_bytes());
        }
        HeadSnapshot::Unborn { ref_name } => {
            feed_field(&mut hasher, "head_kind", b"unborn");
            feed_field(&mut hasher, "head_ref", ref_name.as_bytes());
        }
    }
    feed_field(&mut hasher, "index_root", git_state.index_merkle_root.as_bytes());
    feed_field(&mut hasher, "index_raw", git_state.index_raw_sha256.as_bytes());
    let up = match ignore_policy.untracked_policy {
        UntrackedPolicy::IncludeNonIgnored => "include_non_ignored",
        UntrackedPolicy::TrackedOnly => "tracked_only",
        UntrackedPolicy::IncludeAllExceptGit => "include_all_except_git",
    };
    let ed = match ignore_policy.empty_dir_policy {
        EmptyDirPolicy::IgnoreEmptyDirs => "ignore_empty_dirs",
        EmptyDirPolicy::RetainEmptyDirs => "retain_empty_dirs",
        EmptyDirPolicy::RetainNonIgnoredEmptyDirs => "retain_non_ignored_empty_dirs",
    };
    feed_field(&mut hasher, "untracked_policy", up.as_bytes());
    feed_field(&mut hasher, "empty_dir_policy", ed.as_bytes());
    feed_field(&mut hasher, "use_gitignore", if ignore_policy.use_gitignore { b"1" } else { b"0" });
    feed_field(&mut hasher, "use_rootyardignore", if ignore_policy.use_rootyardignore { b"1" } else { b"0" });
    feed_field(&mut hasher, "ignore_rules_digest", ignore_policy.ignore_rules_digest.as_bytes());
    feed_field(&mut hasher, "worktree_root", worktree_root_digest.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn build_dir_node(
    dir_path_base64: String,
    mut children: Vec<MerkleDirChild>,
) -> Result<MerkleDirNode, MerkleSyncError> {
    let mut seen = BTreeSet::new();
    let mut keys = Vec::with_capacity(children.len());
    for (idx, ch) in children.iter().enumerate() {
        let name = STANDARD
            .decode(&ch.name_base64)
            .map_err(|e| MerkleSyncError::InvalidManifest(format!("invalid child name_base64: {e}")))?;
        if name.is_empty() || name.contains(&b'/') || name.contains(&0) || name == b"." || name == b".." {
            return Err(MerkleSyncError::InvalidManifest("invalid child component name".into()));
        }
        if !seen.insert(name.clone()) {
            return Err(MerkleSyncError::InvalidManifest("duplicate child component in directory".into()));
        }
        keys.push((name, idx));
    }
    keys.sort_by(|a, b| a.0.cmp(&b.0));
    children = keys.into_iter().map(|(_, idx)| children[idx].clone()).collect();
    let mut subtree_file_count = 0u64;
    let mut subtree_total_bytes = 0u64;
    for ch in &children {
        subtree_file_count = subtree_file_count
            .checked_add(ch.subtree_file_count)
            .ok_or_else(|| MerkleSyncError::InvalidManifest("subtree file count overflow".into()))?;
        subtree_total_bytes = subtree_total_bytes
            .checked_add(ch.subtree_total_bytes)
            .ok_or_else(|| MerkleSyncError::InvalidManifest("subtree byte count overflow".into()))?;
    }
    let node_sha256 = compute_dir_node_sha256(&dir_path_base64, &children);
    Ok(MerkleDirNode {
        schema: MERKLE_MANIFEST_SCHEMA,
        codec_version: MERKLE_CODEC_VERSION.to_owned(),
        dir_path_base64,
        children,
        node_sha256,
        subtree_file_count,
        subtree_total_bytes,
    })
}
