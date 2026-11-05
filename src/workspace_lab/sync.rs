use super::{
    core::{
        Entry, MAX_ENTRIES, MAX_MANIFEST, SCHEMA, Store, Workspace, copy_all, copy_single_entry,
        decode_path, entry_for_path, read_regular, require_directory, text_arg, valid_id,
        valid_oid, write_new,
    },
    ignore,
    manifest::{
        Changeset, ChangesetEntry, compute_entries_delta, entries_equivalent,
        manifest_worktree_map, read_head_tree_entries,
    },
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyReport {
    pub schema: u32,
    pub workspace_id: String,
    pub changeset_id: String,
    pub base_checkpoint_id: String,
    pub source_checkpoint_id: String,
    pub applied_entries: usize,
    pub added: usize,
    pub modified: usize,
    pub deleted: usize,
    pub mode_changed: usize,
    pub type_changed: usize,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncDirtyReport {
    pub schema: u32,
    pub source_workspace_id: String,
    pub target_workspace_id: Option<String>,
    pub workspace_id: String,
    pub checkpoint_id: String,
    pub base_oid: String,
    pub state: String,
    pub synced_entries: usize,
    pub added: usize,
    pub modified: usize,
    pub deleted: usize,
    pub mode_changed: usize,
    pub type_changed: usize,
    pub excluded_ignored_entries: usize,
    pub dirty_entries: Vec<ChangesetEntry>,
}

fn read_changeset(store: &Store, id: &str) -> Result<(std::path::PathBuf, Changeset)> {
    valid_id(id)?;
    let dir = store.root.join("changesets").join(id);
    require_directory(&dir)?;
    let bytes = read_regular(&dir.join("changeset.json"), MAX_MANIFEST)?;
    let digest = read_regular(&dir.join("changeset.sha256"), 128)?;
    let digest_trimmed = std::str::from_utf8(&digest)
        .unwrap_or("")
        .trim()
        .as_bytes();
    ensure!(
        digest_trimmed == hex::encode(Sha256::digest(&bytes)).as_bytes(),
        "changeset manifest checksum mismatch"
    );
    let changeset: Changeset =
        serde_json::from_slice(&bytes).context("invalid changeset manifest")?;
    ensure!(
        changeset.schema == SCHEMA
            && changeset.changeset_id == id
            && changeset.state == "local_complete",
        "unsupported or incomplete changeset"
    );
    valid_oid(&changeset.base_oid)?;
    valid_id(&changeset.base_checkpoint_id)?;
    valid_id(&changeset.source_checkpoint_id)?;
    ensure!(
        changeset.entries.len() <= MAX_ENTRIES,
        "changeset entry limit exceeded"
    );

    let files_dir = dir.join("files");
    require_directory(&files_dir)?;
    let mut seen_paths = BTreeSet::new();
    for entry in &changeset.entries {
        let rel = decode_path(&entry.path_base64)?;
        ensure!(
            !rel.starts_with(".git"),
            "changeset may not directly mutate .git paths"
        );
        ensure!(seen_paths.insert(rel.clone()), "duplicate path in changeset");
        match entry.change.as_str() {
            "added" => ensure!(
                entry.before.is_none() && entry.after.is_some(),
                "invalid added changeset entry"
            ),
            "deleted" => ensure!(
                entry.before.is_some() && entry.after.is_none(),
                "invalid deleted changeset entry"
            ),
            "modified" | "mode_changed" | "type_changed" => ensure!(
                entry.before.is_some() && entry.after.is_some(),
                "invalid modified changeset entry"
            ),
            other => bail!("unsupported changeset change type {other}"),
        }
        if let Some(expected_after) = &entry.after {
            let actual = entry_for_path(&files_dir, &rel)?
                .with_context(|| format!("missing changeset payload file {}", entry.path))?;
            ensure!(
                &actual == expected_after,
                "corrupt changeset payload file {}",
                entry.path
            );
        }
    }
    Ok((dir, changeset))
}

fn check_target_no_conflicts(
    target_repo: &Path,
    entries: &[ChangesetEntry],
    exact_mode: bool,
    context_label: &str,
) -> Result<()> {
    for entry in entries {
        let rel = decode_path(&entry.path_base64)?;
        let full = target_repo.join(&rel);
        match &entry.before {
            None => {
                if fs::symlink_metadata(&full).is_ok() {
                    bail!(
                        "conflict in {context_label}: target path {} already exists",
                        entry.path
                    );
                }
                let mut parent = target_repo.to_path_buf();
                if let Some(rel_parent) = rel.parent() {
                    for comp in rel_parent.components() {
                        parent.push(comp);
                        if let Ok(meta) = fs::symlink_metadata(&parent) {
                            ensure!(
                                meta.file_type().is_dir(),
                                "conflict in {context_label}: ancestor of {} is not a directory",
                                entry.path
                            );
                        }
                    }
                }
            }
            Some(expected_before) => {
                let Some(current) = entry_for_path(target_repo, &rel)? else {
                    bail!(
                        "conflict in {context_label}: path {} missing on target",
                        entry.path
                    );
                };
                let check_exact = exact_mode || entry.change == "mode_changed";
                if !entries_equivalent(&current, expected_before, check_exact) {
                    bail!(
                        "conflict in {context_label}: path {} modified since base checkpoint",
                        entry.path
                    );
                }
            }
        }
    }
    Ok(())
}

fn remove_empty_parents(mut dir: &Path, stop_at: &Path) {
    while dir != stop_at && dir.starts_with(stop_at) {
        let Ok(mut iter) = fs::read_dir(dir) else {
            break;
        };
        if iter.next().is_none() {
            let _ = fs::remove_dir(dir);
            if let Some(parent) = dir.parent() {
                dir = parent;
            } else {
                break;
            }
        } else {
            break;
        }
    }
}

fn apply_entries_to_workspace(
    store: &Store,
    mut target_ws: Workspace,
    source_files_root: &Path,
    entries: &[ChangesetEntry],
    new_parent_checkpoint_id: String,
) -> Result<()> {
    let target_ws_dir = store.root.join("workspaces").join(&target_ws.workspace_id);
    let target_repo = target_ws_dir.join("repo");

    let staging = store.stage()?;
    let staging_repo = staging.0.join("repo");
    copy_all(&target_repo, &staging_repo)?;

    // Apply deletions and type replacements first.
    for entry in entries {
        let rel = decode_path(&entry.path_base64)?;
        if entry.after.is_none() || entry.change == "type_changed" {
            let to_remove = staging_repo.join(&rel);
            if fs::symlink_metadata(&to_remove).is_ok() {
                fs::remove_file(&to_remove)?;
                if let Some(parent) = to_remove.parent() {
                    remove_empty_parents(parent, &staging_repo);
                }
            }
        }
    }

    // Copy added/modified/mode_changed/type_changed entries.
    let mut total_copied = 0u64;
    for entry in entries {
        if let Some(expected_after) = &entry.after {
            let rel = decode_path(&entry.path_base64)?;
            copy_single_entry(source_files_root, &staging_repo, &rel, &mut total_copied)?;
            let actual = entry_for_path(&staging_repo, &rel)?
                .with_context(|| format!("applied file {} missing after copy", entry.path))?;
            ensure!(
                &actual == expected_after,
                "applied file {} checksum or mode mismatch",
                entry.path
            );
        }
    }

    store.validate_repo(&staging_repo, &target_ws.base_oid)?;
    target_ws.parent_checkpoint_id = Some(new_parent_checkpoint_id);
    write_new(
        &staging.0.join("workspace.json"),
        &serde_json::to_vec_pretty(&target_ws)?,
        0o600,
    )?;
    store.replace_dir_atomic(&staging.0, &target_ws_dir)?;
    Ok(())
}

pub fn cmd_apply(
    store: &Store,
    workspace_arg: &OsStr,
    changeset_arg: &OsStr,
) -> Result<serde_json::Value> {
    let ws_id = text_arg(workspace_arg)?;
    valid_id(&ws_id)?;
    let cs_id = text_arg(changeset_arg)?;
    valid_id(&cs_id)?;

    let target_ws = store.read_workspace(&ws_id)?;
    let target_repo = store.root.join("workspaces").join(&ws_id).join("repo");
    store.validate_repo(&target_repo, &target_ws.base_oid)?;

    let (cs_dir, changeset) = read_changeset(store, &cs_id)?;
    ensure!(
        changeset.base_oid == target_ws.base_oid,
        "changeset base_oid does not match workspace base_oid"
    );

    check_target_no_conflicts(
        &target_repo,
        &changeset.entries,
        true,
        &format!("apply changeset {cs_id} to workspace {ws_id}"),
    )?;

    apply_entries_to_workspace(
        store,
        target_ws,
        &cs_dir.join("files"),
        &changeset.entries,
        changeset.source_checkpoint_id.clone(),
    )?;

    let report = ApplyReport {
        schema: SCHEMA,
        workspace_id: ws_id,
        changeset_id: cs_id,
        base_checkpoint_id: changeset.base_checkpoint_id,
        source_checkpoint_id: changeset.source_checkpoint_id,
        applied_entries: changeset.entries.len(),
        added: changeset.added,
        modified: changeset.modified,
        deleted: changeset.deleted,
        mode_changed: changeset.mode_changed,
        type_changed: changeset.type_changed,
        state: "applied".into(),
    };
    Ok(serde_json::to_value(report)?)
}

pub fn cmd_sync_dirty(
    store: &Store,
    source_ws_arg: &OsStr,
    target_ws_arg: Option<&OsStr>,
) -> Result<serde_json::Value> {
    let source_id = text_arg(source_ws_arg)?;
    valid_id(&source_id)?;
    let mut source_ws = store.read_workspace(&source_id)?;
    let source_ws_dir = store.root.join("workspaces").join(&source_id);
    let source_repo = source_ws_dir.join("repo");
    store.validate_repo(&source_repo, &source_ws.base_oid)?;

    let classification = ignore::classify_workspace(store, &source_repo)?;
    let (base_map, exact_mode) = if let Some(cp_id) = &source_ws.parent_checkpoint_id {
        if store.root.join("checkpoints").join(cp_id).is_dir() {
            let (_, cp_manifest) = store.read_checkpoint(cp_id)?;
            (manifest_worktree_map(&cp_manifest.entries)?, true)
        } else {
            (read_head_tree_entries(store, &source_repo)?, false)
        }
    } else {
        (read_head_tree_entries(store, &source_repo)?, false)
    };

    let mut source_map: BTreeMap<std::path::PathBuf, Entry> = BTreeMap::new();
    for path in &classification.managed_paths {
        if let Some(entry) = entry_for_path(&source_repo, path)? {
            source_map.insert(path.clone(), entry);
        }
    }

    let (dirty_entries, added, modified, deleted, mode_changed, type_changed) =
        compute_entries_delta(&base_map, &source_map, exact_mode);

    let target_ws_opt = if let Some(t_arg) = target_ws_arg {
        let target_id = text_arg(t_arg)?;
        valid_id(&target_id)?;
        ensure!(
            target_id != source_id,
            "source and target workspaces must be distinct"
        );
        let target_ws = store.read_workspace(&target_id)?;
        let target_repo = store.root.join("workspaces").join(&target_id).join("repo");
        store.validate_repo(&target_repo, &target_ws.base_oid)?;
        ensure!(
            target_ws.base_oid == source_ws.base_oid,
            "source and target workspaces have different base OIDs"
        );
        check_target_no_conflicts(
            &target_repo,
            &dirty_entries,
            exact_mode,
            &format!("sync-dirty {source_id} -> {target_id}"),
        )?;
        Some(target_ws)
    } else {
        None
    };

    let cp_value = store.cmd_checkpoint(source_ws_arg)?;
    let checkpoint_id = cp_value["checkpoint_id"]
        .as_str()
        .context("missing checkpoint_id from checkpoint")?
        .to_owned();

    // Update source workspace parent_checkpoint_id atomically.
    {
        let staging = store.stage()?;
        copy_all(&source_repo, &staging.0.join("repo"))?;
        source_ws.parent_checkpoint_id = Some(checkpoint_id.clone());
        write_new(
            &staging.0.join("workspace.json"),
            &serde_json::to_vec_pretty(&source_ws)?,
            0o600,
        )?;
        store.replace_dir_atomic(&staging.0, &source_ws_dir)?;
    }

    let target_workspace_id = if let Some(target_ws) = target_ws_opt {
        let tid = target_ws.workspace_id.clone();
        apply_entries_to_workspace(
            store,
            target_ws,
            &source_repo,
            &dirty_entries,
            checkpoint_id.clone(),
        )?;
        Some(tid)
    } else {
        None
    };

    let workspace_id = target_workspace_id
        .clone()
        .unwrap_or_else(|| source_id.clone());
    let report = SyncDirtyReport {
        schema: SCHEMA,
        source_workspace_id: source_id,
        target_workspace_id,
        workspace_id,
        checkpoint_id,
        base_oid: source_ws.base_oid,
        state: "synced".into(),
        synced_entries: dirty_entries.len(),
        added,
        modified,
        deleted,
        mode_changed,
        type_changed,
        excluded_ignored_entries: classification.ignored_paths.len(),
        dirty_entries,
    };
    Ok(serde_json::to_value(report)?)
}
