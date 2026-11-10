use super::{
    core::{
        Entry, MAX_BYTES, MAX_MANIFEST, SCHEMA, Store, decode_path, display_path, encode_path, entry_for_path, new_id,
        private_dir, publish, read_regular, relative_path, sync_tree, text_arg, valid_id, write_new,
    },
    ignore,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
    path::{Path, PathBuf},
};

pub use super::sync::{ApplyReport, SyncDirtyReport, cmd_apply, cmd_sync_dirty};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirtyEntry {
    pub path: String,
    pub path_base64: String,
    pub change: String,
    pub kind: Option<String>,
    pub mode: Option<u32>,
    pub size: Option<u64>,
    pub sha256: Option<String>,
    pub staged: bool,
    pub unstaged: bool,
    pub untracked: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceStatus {
    pub schema: u32,
    pub workspace_id: String,
    pub agent_id: String,
    pub base_oid: String,
    pub head_oid: String,
    pub detached_head: bool,
    pub parent_checkpoint_id: Option<String>,
    pub is_dirty: bool,
    pub clean: bool,
    pub managed_entries_count: usize,
    pub ignored_entries_count: usize,
    pub untracked_entries_count: usize,
    pub dirty_entries_count: usize,
    pub staged_paths: Vec<String>,
    pub unstaged_paths: Vec<String>,
    pub untracked_paths: Vec<String>,
    pub unmerged_paths: Vec<String>,
    pub managed_paths: Vec<String>,
    pub ignored_paths: Vec<String>,
    pub dirty_entries: Vec<DirtyEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangesetEntry {
    pub path: String,
    pub path_base64: String,
    pub change: String,
    pub before: Option<Entry>,
    pub after: Option<Entry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Changeset {
    pub schema: u32,
    pub changeset_id: String,
    pub state: String,
    pub base_oid: String,
    pub base_checkpoint_id: String,
    pub source_checkpoint_id: String,
    pub added: usize,
    pub modified: usize,
    pub deleted: usize,
    pub mode_changed: usize,
    pub type_changed: usize,
    pub entries: Vec<ChangesetEntry>,
}

pub(crate) fn entries_equivalent(a: &Entry, b: &Entry, exact_mode: bool) -> bool {
    if a.kind != b.kind || a.size != b.size || a.sha256 != b.sha256 {
        return false;
    }
    if exact_mode { a.mode == b.mode } else { (a.mode & 0o111 != 0) == (b.mode & 0o111 != 0) }
}

pub(crate) fn read_head_tree_entries(store: &Store, repo: &Path) -> Result<BTreeMap<PathBuf, Entry>> {
    let mut entries = BTreeMap::new();
    let output = store.git(repo, &["ls-tree", "-rz", "--full-tree", "HEAD"])?;
    for record in output.split(|b| *b == 0).filter(|x| !x.is_empty()) {
        ensure!(!record.starts_with(b"160000 "), "submodules/gitlinks are unsupported");
        let tab = record.iter().position(|b| *b == b'\t').context("invalid Git ls-tree record")?;
        let header = std::str::from_utf8(&record[..tab])?;
        let mut parts = header.split_whitespace();
        let mode_str = parts.next().context("missing tree entry mode")?;
        let _kind_str = parts.next().context("missing tree entry kind")?;
        let oid_str = parts.next().context("missing tree entry oid")?;
        let path = relative_path(&record[tab + 1..])?;
        let (kind, mode) = match mode_str {
            "120000" => ("symlink", 0o777),
            "100755" => ("file", 0o755),
            _ => ("file", 0o644),
        };
        let bytes = store.git(repo, &["cat-file", "blob", oid_str])?;
        entries.insert(
            path.clone(),
            Entry {
                path_base64: encode_path(&path),
                kind: kind.into(),
                mode,
                size: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(&bytes)),
            },
        );
    }
    Ok(entries)
}

pub(crate) fn manifest_worktree_map(entries: &[Entry]) -> Result<BTreeMap<PathBuf, Entry>> {
    let mut map = BTreeMap::new();
    for entry in entries {
        let path = decode_path(&entry.path_base64)?;
        if path.starts_with(".git") {
            continue;
        }
        map.insert(path, entry.clone());
    }
    Ok(map)
}

pub(crate) fn compute_entries_delta(
    base_map: &BTreeMap<PathBuf, Entry>,
    source_map: &BTreeMap<PathBuf, Entry>,
    exact_mode: bool,
) -> (Vec<ChangesetEntry>, usize, usize, usize, usize, usize) {
    let all_paths: BTreeSet<PathBuf> = base_map.keys().chain(source_map.keys()).cloned().collect();
    let mut entries = Vec::new();
    let mut added = 0usize;
    let mut modified = 0usize;
    let mut deleted = 0usize;
    let mut mode_changed = 0usize;
    let mut type_changed = 0usize;

    for path in all_paths {
        let before = base_map.get(&path).cloned();
        let after = source_map.get(&path).cloned();
        match (&before, &after) {
            (None, None) => continue,
            (Some(b), Some(a)) if entries_equivalent(b, a, exact_mode) => continue,
            _ => {}
        }
        let change = match (&before, &after) {
            (None, Some(_)) => {
                added += 1;
                "added"
            }
            (Some(_), None) => {
                deleted += 1;
                "deleted"
            }
            (Some(b), Some(a)) => {
                if b.kind != a.kind {
                    type_changed += 1;
                    "type_changed"
                } else if b.sha256 != a.sha256 {
                    modified += 1;
                    "modified"
                } else {
                    mode_changed += 1;
                    "mode_changed"
                }
            }
            (None, None) => unreachable!(),
        };
        entries.push(ChangesetEntry {
            path: display_path(&path),
            path_base64: encode_path(&path),
            change: change.into(),
            before,
            after,
        });
    }
    (entries, added, modified, deleted, mode_changed, type_changed)
}

fn parse_nul_paths(bytes: &[u8]) -> Result<BTreeSet<PathBuf>> {
    let mut out = BTreeSet::new();
    for record in bytes.split(|b| *b == 0).filter(|x| !x.is_empty()) {
        out.insert(relative_path(record)?);
    }
    Ok(out)
}

fn intent_to_add_paths(repo: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut out = BTreeSet::new();
    let index_path = repo.join(".git/index");
    if !index_path.try_exists()? {
        return Ok(out);
    }
    let bytes = read_regular(&index_path, MAX_MANIFEST)?;
    if bytes.len() < 32 || &bytes[..4] != b"DIRC" {
        return Ok(out);
    }
    let version = u32::from_be_bytes(bytes[4..8].try_into()?);
    let count = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
    let end = bytes.len() - 20;
    let mut cursor = 12usize;
    for _ in 0..count {
        let start = cursor;
        if cursor + 62 > end {
            break;
        }
        let flags = u16::from_be_bytes(bytes[cursor + 60..cursor + 62].try_into()?);
        cursor += 62;
        let mut is_ita = false;
        if flags & 0x4000 != 0 && version == 3 && cursor + 2 <= end {
            let ext = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into()?);
            if ext & 0x2000 != 0 {
                is_ita = true;
            }
            cursor += 2;
        }
        let Some(nul) = bytes[cursor..end].iter().position(|b| *b == 0) else {
            break;
        };
        if is_ita && let Ok(p) = relative_path(&bytes[cursor..cursor + nul]) {
            out.insert(p);
        }
        cursor += nul + 1;
        cursor = start + (cursor - start).div_ceil(8) * 8;
    }
    Ok(out)
}

/// Computes unstaged paths by comparing stage-0 index entries directly against worktree bytes
/// and modes (avoiding false positives from copied inodes in `.git/index`).
fn compute_unstaged_paths(store: &Store, repo: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut unstaged = intent_to_add_paths(repo)?;
    let ls_stage = store.git(repo, &["ls-files", "--stage", "-z"])?;
    for record in ls_stage.split(|b| *b == 0).filter(|x| !x.is_empty()) {
        let Some(tab) = record.iter().position(|b| *b == b'\t') else {
            continue;
        };
        let header = std::str::from_utf8(&record[..tab])?;
        let mut parts = header.split_whitespace();
        let mode_str = parts.next().unwrap_or("");
        let oid_str = parts.next().unwrap_or("");
        let stage_str = parts.next().unwrap_or("0");
        let path = relative_path(&record[tab + 1..])?;
        if stage_str != "0" {
            unstaged.insert(path);
            continue;
        }
        let full = repo.join(&path);
        let Ok(meta) = fs::symlink_metadata(&full) else {
            unstaged.insert(path);
            continue;
        };
        let expected_blob = store.git(repo, &["cat-file", "blob", oid_str])?;
        if mode_str == "120000" {
            if !meta.file_type().is_symlink() {
                unstaged.insert(path);
                continue;
            }
            let target = fs::read_link(&full)?.into_os_string().into_vec();
            if target != expected_blob {
                unstaged.insert(path);
            }
        } else {
            if !meta.is_file() {
                unstaged.insert(path);
                continue;
            }
            let disk_exec = (meta.permissions().mode() & 0o111) != 0;
            let idx_exec = mode_str == "100755";
            if disk_exec != idx_exec {
                unstaged.insert(path);
                continue;
            }
            let bytes = read_regular(&full, MAX_BYTES)?;
            if bytes != expected_blob {
                unstaged.insert(path);
            }
        }
    }
    Ok(unstaged)
}

pub fn cmd_status(store: &Store, workspace_arg: &OsStr) -> Result<serde_json::Value> {
    let id = text_arg(workspace_arg)?;
    valid_id(&id)?;
    let workspace = store.read_workspace(&id)?;
    let repo = store.root.join("workspaces").join(&id).join("repo");
    store.validate_repo(&repo, &workspace.base_oid)?;

    let classification = ignore::classify_workspace(store, &repo)?;
    let head_oid = store.git_text(&repo, &["rev-parse", "--verify", "HEAD"])?;
    let detached_head = !store.git_output(&repo, &["symbolic-ref", "-q", "HEAD"])?.status.success();

    let mut unmerged_set = BTreeSet::new();
    for record in store.git(&repo, &["ls-files", "--unmerged", "-z"])?.split(|b| *b == 0).filter(|x| !x.is_empty()) {
        if let Some(tab) = record.iter().position(|b| *b == b'\t') {
            unmerged_set.insert(relative_path(&record[tab + 1..])?);
        }
    }

    let staged_set = parse_nul_paths(&store.git(&repo, &["diff-index", "--cached", "--name-only", "-z", "HEAD"])?)?;
    let unstaged_set = compute_unstaged_paths(store, &repo)?;

    let head_map = read_head_tree_entries(store, &repo)?;
    let (base_map, exact_mode) = if let Some(cp_id) = &workspace.parent_checkpoint_id {
        if store.root.join("checkpoints").join(cp_id).is_dir() {
            let (_, cp_manifest) = store.read_checkpoint(cp_id)?;
            (manifest_worktree_map(&cp_manifest.entries)?, true)
        } else {
            (head_map.clone(), false)
        }
    } else {
        (head_map.clone(), false)
    };

    let mut current_map = BTreeMap::new();
    for path in &classification.managed_paths {
        if let Some(entry) = entry_for_path(&repo, path)? {
            current_map.insert(path.clone(), entry);
        }
    }

    let candidate_paths: BTreeSet<PathBuf> = base_map
        .keys()
        .chain(head_map.keys())
        .chain(current_map.keys())
        .chain(staged_set.iter())
        .chain(unstaged_set.iter())
        .chain(classification.untracked_paths.iter())
        .chain(unmerged_set.iter())
        .cloned()
        .collect();

    let mut dirty_entries = Vec::new();
    for path in candidate_paths {
        let before = base_map.get(&path).or_else(|| head_map.get(&path));
        let after = current_map.get(&path);
        let staged = staged_set.contains(&path);
        let unstaged = unstaged_set.contains(&path) || unmerged_set.contains(&path);
        let untracked = classification.untracked_paths.contains(&path);

        let same_as_before = match (before, after) {
            (None, None) => true,
            (Some(b), Some(a)) => entries_equivalent(b, a, exact_mode),
            _ => false,
        };
        if same_as_before && !staged && !unstaged && !untracked {
            continue;
        }
        let change = match (before, after) {
            (None, Some(_)) => "added",
            (Some(_), None) => "deleted",
            (Some(b), Some(a)) => {
                if b.kind != a.kind {
                    "type_changed"
                } else if b.sha256 != a.sha256 {
                    "modified"
                } else if b.mode != a.mode {
                    "mode_changed"
                } else {
                    "modified"
                }
            }
            (None, None) => "deleted",
        };
        dirty_entries.push(DirtyEntry {
            path: display_path(&path),
            path_base64: encode_path(&path),
            change: change.into(),
            kind: after.map(|e| e.kind.clone()),
            mode: after.map(|e| e.mode),
            size: after.map(|e| e.size),
            sha256: after.map(|e| e.sha256.clone()),
            staged,
            unstaged,
            untracked,
        });
    }

    let is_dirty = !dirty_entries.is_empty();
    let status = WorkspaceStatus {
        schema: SCHEMA,
        workspace_id: workspace.workspace_id,
        agent_id: workspace.agent_id,
        base_oid: workspace.base_oid,
        head_oid,
        detached_head,
        parent_checkpoint_id: workspace.parent_checkpoint_id,
        is_dirty,
        clean: !is_dirty,
        managed_entries_count: current_map.len(),
        ignored_entries_count: classification.ignored_paths.len(),
        untracked_entries_count: classification.untracked_paths.len(),
        dirty_entries_count: dirty_entries.len(),
        staged_paths: staged_set.iter().map(|p| display_path(p)).collect(),
        unstaged_paths: unstaged_set.iter().map(|p| display_path(p)).collect(),
        untracked_paths: classification.untracked_paths.iter().map(|p| display_path(p)).collect(),
        unmerged_paths: unmerged_set.iter().map(|p| display_path(p)).collect(),
        managed_paths: current_map.keys().map(|p| display_path(p)).collect(),
        ignored_paths: classification.ignored_paths.iter().map(|p| display_path(p)).collect(),
        dirty_entries,
    };
    Ok(serde_json::to_value(status)?)
}

pub fn cmd_changeset(store: &Store, base_cp_arg: &OsStr, source_cp_arg: &OsStr) -> Result<serde_json::Value> {
    let base_id = text_arg(base_cp_arg)?;
    let source_id = text_arg(source_cp_arg)?;
    let (_, base_manifest) = store.read_checkpoint(&base_id)?;
    let (source_dir, source_manifest) = store.read_checkpoint(&source_id)?;
    ensure!(
        base_manifest.workspace.base_oid == source_manifest.workspace.base_oid,
        "cannot compute changeset across different base OIDs"
    );

    let base_map = manifest_worktree_map(&base_manifest.entries)?;
    let source_map = manifest_worktree_map(&source_manifest.entries)?;
    let (entries, added, modified, deleted, mode_changed, type_changed) =
        compute_entries_delta(&base_map, &source_map, true);

    let changeset_id = new_id();
    let staging = store.stage()?;
    let files_dir = staging.0.join("files");
    private_dir(&files_dir)?;
    let mut total_copied = 0u64;
    let source_repo = source_dir.join("repo");
    for entry in &entries {
        if entry.after.is_some() {
            let rel = decode_path(&entry.path_base64)?;
            super::core::copy_single_entry(&source_repo, &files_dir, &rel, &mut total_copied)?;
        }
    }

    let changeset = Changeset {
        schema: SCHEMA,
        changeset_id: changeset_id.clone(),
        state: "local_complete".into(),
        base_oid: source_manifest.workspace.base_oid,
        base_checkpoint_id: base_id,
        source_checkpoint_id: source_id,
        added,
        modified,
        deleted,
        mode_changed,
        type_changed,
        entries,
    };
    let bytes = serde_json::to_vec_pretty(&changeset)?;
    ensure!(bytes.len() as u64 <= MAX_MANIFEST, "changeset manifest limit exceeded");
    write_new(&staging.0.join("changeset.json"), &bytes, 0o600)?;
    write_new(&staging.0.join("changeset.sha256"), hex::encode(Sha256::digest(&bytes)).as_bytes(), 0o600)?;
    sync_tree(&staging.0)?;
    publish(&staging.0, &store.root.join("changesets").join(&changeset_id))?;
    Ok(serde_json::to_value(changeset)?)
}
