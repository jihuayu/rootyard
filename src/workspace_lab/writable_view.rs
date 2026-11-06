use super::{
    core::*,
    ignore,
    manifest::{Changeset, compute_entries_delta, manifest_worktree_map},
    namespace::{BaseVectorEntry, NamespaceManifest},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentLeaseEntry {
    pub lease_id: String, pub target_id: String, pub target_kind: String, pub agent_id: String, pub prefix: String,
    pub lease_epoch: u64, pub ttl_secs: u64, pub acquired_at: u64, pub expires_at: u64, pub state: String,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentLeaseTable {
    pub schema: u32, pub target_id: String, pub target_kind: String, pub lease_epoch: u64, pub leases: Vec<AgentLeaseEntry>,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentLeaseReport {
    pub schema: u32, pub lease_id: String, pub target_id: String, pub target_kind: String, pub agent_id: String,
    pub action: String, pub prefix: String, pub lease_epoch: u64, pub ttl_secs: u64, pub acquired_at: u64,
    pub expires_at: u64, pub state: String, pub active_leases: usize, pub leases: Vec<AgentLeaseEntry>,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamespacePendingWrite {
    pub path: String, pub path_base64: String, pub mount_path: String, pub repo_rel_path: String,
    pub repo_rel_path_base64: String, pub base_checkpoint_id: String, pub workspace_id: String, pub base_oid: String,
    pub base_namespace_revision: u32, pub agent_id: String, pub operation: String, pub change: String,
    pub mode: u32, pub size: Option<u64>, pub sha256: Option<String>, pub lease_epoch: Option<u64>,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamespacePendingWriteTable {
    pub schema: u32, pub namespace_id: String, pub namespace_revision: u32, pub writes: Vec<NamespacePendingWrite>,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NamespaceWriteReport {
    pub schema: u32, pub namespace_id: String, pub namespace_revision: u32, pub agent_id: String, pub path: String,
    pub path_base64: String, pub mount_path: String, pub repo_rel_path: String, pub repo_rel_path_base64: String,
    pub base_checkpoint_id: String, pub workspace_id: String, pub base_oid: String, pub operation: String,
    pub change: String, pub size: Option<u64>, pub sha256: Option<String>, pub lease_epoch: Option<u64>,
    pub pending_writes_count: usize, pub state: String,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrossRepoMountCommit {
    pub mount_path: String, pub workspace_id: String, pub base_oid: String, pub previous_checkpoint_id: String,
    pub new_checkpoint_id: String, pub changeset_id: String, pub added: usize, pub modified: usize,
    pub deleted: usize, pub mode_changed: usize, pub type_changed: usize, pub entries_count: usize,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrossRepoCommitReceipt {
    pub schema: u32, pub commit_id: String, pub namespace_id: String, pub name: String, pub agent_id: String,
    pub previous_revision: u32, pub namespace_revision: u32, pub lease_epoch: Option<u64>, pub phase: String,
    pub state: String, pub touched_mounts_count: usize, pub total_writes_committed: usize,
    pub mount_commits: Vec<CrossRepoMountCommit>, pub previous_base_vector: Vec<BaseVectorEntry>,
    pub base_vector: Vec<BaseVectorEntry>, pub receipt_path: String,
}
#[rustfmt::skip]
fn now_secs() -> Result<u64> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()) }
#[rustfmt::skip]
fn write_atomic_checked(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> Result<PathBuf> {
    if !dir.exists() { fs::create_dir_all(dir)?; fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?; }
    require_directory(dir)?;
    let tmp = dir.join(format!(".tmp-{}", Uuid::new_v4()));
    let res = (|| -> Result<PathBuf> {
        let mut f = OpenOptions::new().write(true).create_new(true).mode(mode).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
        f.write_all(bytes)?; f.set_permissions(fs::Permissions::from_mode(mode))?; f.sync_all()?; drop(f);
        let dest = dir.join(name); fs::rename(&tmp, &dest)?; File::open(dir)?.sync_all()?; Ok(dest)
    })();
    if res.is_err() { let _ = fs::remove_file(&tmp); }
    res
}
#[rustfmt::skip]
fn normalize_rel_segments(raw: &str, allow_empty: bool) -> Result<String> {
    ensure!(!raw.contains('\0') && !raw.starts_with('/'), "invalid path: leading '/' or NUL forbidden");
    let trimmed = raw.trim_end_matches('/');
    if allow_empty && (trimmed.is_empty() || trimmed == "." || trimmed == "*") { return Ok(String::new()); }
    let mut segs = Vec::new();
    for seg in trimmed.split('/').filter(|s| !s.is_empty() && *s != ".") {
        ensure!(seg != ".." && seg != ".git", "unsafe or .git path segment '{seg}'");
        segs.push(seg);
    }
    if allow_empty && segs.is_empty() { return Ok(String::new()); }
    ensure!(!segs.is_empty() && segs.join("/") != ".rootyard-namespace.json", "invalid or reserved relative path");
    Ok(segs.join("/"))
}
#[rustfmt::skip]
fn prefixes_overlap(a: &str, b: &str) -> bool {
    a.is_empty() || b.is_empty() || a == b || a.strip_prefix(b).is_some_and(|r| r.starts_with('/')) || b.strip_prefix(a).is_some_and(|r| r.starts_with('/'))
}
#[rustfmt::skip]
fn prefix_covers(prefix: &str, path: &str) -> bool {
    prefix.is_empty() || prefix == path || path.strip_prefix(prefix).is_some_and(|r| r.starts_with('/'))
}
#[rustfmt::skip]
fn load_lease_table(store: &Store, target_id: &str, target_kind: &str) -> Result<AgentLeaseTable> {
    let leases_dir = store.root.join("leases");
    if !leases_dir.exists() { private_dir(&leases_dir)?; }
    require_directory(&leases_dir)?;
    let path = leases_dir.join(format!("{target_id}.json"));
    if !path.exists() { return Ok(AgentLeaseTable { schema: SCHEMA, target_id: target_id.into(), target_kind: target_kind.into(), lease_epoch: 0, leases: Vec::new() }); }
    let (raw, sha_path) = (read_regular(&path, MAX_MANIFEST)?, leases_dir.join(format!("{target_id}.sha256")));
    if sha_path.exists() {
        ensure!(hex::encode(Sha256::digest(&raw)) == String::from_utf8(read_regular(&sha_path, 256)?)?.trim(), "lease table checksum mismatch");
    }
    let table: AgentLeaseTable = serde_json::from_slice(&raw)?;
    ensure!(table.schema == SCHEMA && table.target_id == target_id, "invalid lease table");
    Ok(table)
}
#[rustfmt::skip]
fn save_lease_table(store: &Store, table: &AgentLeaseTable) -> Result<()> {
    let (leases_dir, raw) = (store.root.join("leases"), serde_json::to_vec_pretty(table)?);
    write_atomic_checked(&leases_dir, &format!("{}.json", table.target_id), &raw, 0o600)?;
    write_atomic_checked(&leases_dir, &format!("{}.sha256", table.target_id), hex::encode(Sha256::digest(&raw)).as_bytes(), 0o600)?;
    Ok(())
}
#[rustfmt::skip]
pub fn cmd_agent_lease(store: &Store, target_arg: &OsStr, agent_arg: &OsStr, action_arg: &OsStr, rest: &[OsString]) -> Result<Json> {
    let (target_id, agent_id, action) = (text_arg(target_arg)?, text_arg(agent_arg)?, text_arg(action_arg)?);
    valid_id(&target_id)?; valid_agent(&agent_id)?;
    let target_kind = if store.root.join("namespaces").join(&target_id).is_dir() { "namespace" }
        else if store.root.join("workspaces").join(&target_id).is_dir() { "workspace" }
        else { bail!("unknown namespace or workspace id: {target_id}"); };
    let (mut prefix, mut ttl_secs, mut req_epoch, mut idx) = (String::new(), 300u64, None, 0usize);
    while idx < rest.len() {
        match text_arg(&rest[idx])?.as_str() {
            "--prefix" => { idx += 1; ensure!(idx < rest.len(), "missing --prefix"); prefix = normalize_rel_segments(&text_arg(&rest[idx])?, true)?; }
            "--ttl-secs" => { idx += 1; ensure!(idx < rest.len(), "missing --ttl-secs"); ttl_secs = text_arg(&rest[idx])?.parse::<u64>().context("invalid --ttl-secs")?; ensure!(ttl_secs <= 86_400 * 30, "ttl_secs exceeds maximum"); }
            "--epoch" | "--lease-epoch" => { idx += 1; ensure!(idx < rest.len(), "missing --epoch"); req_epoch = Some(text_arg(&rest[idx])?.parse::<u64>().context("invalid --epoch")?); }
            other => bail!("unknown agent-lease flag: {other}"),
        }
        idx += 1;
    }
    let (now, mut table) = (now_secs()?, load_lease_table(store, &target_id, target_kind)?);
    for l in &mut table.leases { if l.state == "active" && now >= l.expires_at { l.state = "expired".into(); } }
    let primary = match action.as_str() {
        "acquire" => {
            for l in &table.leases {
                if l.state == "active" && prefixes_overlap(&l.prefix, &prefix) && l.agent_id != agent_id {
                    save_lease_table(store, &table)?;
                    bail!("conflict: prefix '{}' overlaps active lease held by '{}' on '{}' (epoch {})", prefix, l.agent_id, l.prefix, l.lease_epoch);
                }
            }
            if let Some(ep) = req_epoch { ensure!(ep >= table.lease_epoch, "conflict: stale lease_epoch {ep} < {}", table.lease_epoch); }
            table.leases.retain(|l| !(prefixes_overlap(&l.prefix, &prefix) && (l.state != "active" || l.agent_id == agent_id)));
            table.lease_epoch += 1;
            let entry = AgentLeaseEntry { lease_id: new_id(), target_id: target_id.clone(), target_kind: target_kind.into(), agent_id: agent_id.clone(), prefix: prefix.clone(), lease_epoch: table.lease_epoch, ttl_secs, acquired_at: now, expires_at: now.saturating_add(ttl_secs), state: "active".into() };
            table.leases.push(entry.clone());
            table.leases.sort_by(|a, b| (&a.prefix, a.lease_epoch).cmp(&(&b.prefix, b.lease_epoch)));
            save_lease_table(store, &table)?;
            AgentLeaseEntry { state: "acquired".into(), ..entry }
        }
        "renew" => {
            let Some(pos) = table.leases.iter().position(|l| l.agent_id == agent_id && l.prefix == prefix) else {
                save_lease_table(store, &table)?; bail!("conflict: no lease found for agent '{agent_id}' on prefix '{prefix}' (stale lease_epoch)");
            };
            let cur_ep = table.leases[pos].lease_epoch;
            if let Some(ep) = req_epoch && (ep != cur_ep || (cur_ep < table.lease_epoch && table.leases[pos].state != "active")) {
                save_lease_table(store, &table)?; bail!("conflict: stale lease_epoch {ep} (current lease epoch {cur_ep})");
            }
            if table.leases[pos].state != "active" { save_lease_table(store, &table)?; bail!("conflict: lease expired for agent '{agent_id}' on prefix '{prefix}' (epoch {cur_ep})"); }
            table.leases[pos].ttl_secs = ttl_secs; table.leases[pos].expires_at = now.saturating_add(ttl_secs);
            let entry = table.leases[pos].clone(); save_lease_table(store, &table)?;
            AgentLeaseEntry { state: "renewed".into(), ..entry }
        }
        "release" => {
            let Some(pos) = table.leases.iter().position(|l| l.agent_id == agent_id && l.prefix == prefix && l.state == "active") else {
                save_lease_table(store, &table)?; bail!("conflict: no active lease for agent '{agent_id}' on prefix '{prefix}'");
            };
            if let Some(ep) = req_epoch { ensure!(ep == table.leases[pos].lease_epoch, "conflict: stale lease_epoch {ep}"); }
            table.leases[pos].state = "released".into();
            let entry = table.leases[pos].clone(); save_lease_table(store, &table)?; entry
        }
        "status" => {
            save_lease_table(store, &table)?;
            AgentLeaseEntry { lease_id: String::new(), target_id: target_id.clone(), target_kind: target_kind.into(), agent_id: agent_id.clone(), prefix: prefix.clone(), lease_epoch: table.lease_epoch, ttl_secs: 0, acquired_at: now, expires_at: now, state: "status".into() }
        }
        other => bail!("unsupported agent-lease action '{other}'"),
    };
    let active_count = table.leases.iter().filter(|l| l.state == "active").count();
    Ok(serde_json::to_value(AgentLeaseReport {
        schema: SCHEMA, lease_id: primary.lease_id, target_id, target_kind: target_kind.into(), agent_id, action, prefix: primary.prefix,
        lease_epoch: primary.lease_epoch, ttl_secs: primary.ttl_secs, acquired_at: primary.acquired_at, expires_at: primary.expires_at,
        state: primary.state, active_leases: active_count, leases: table.leases,
    })?)
}

#[rustfmt::skip]
fn read_namespace_manifest_any_rev(store: &Store, namespace_id: &str) -> Result<(PathBuf, NamespaceManifest)> {
    valid_id(namespace_id)?;
    let ns_dir = store.root.join("namespaces").join(namespace_id);
    require_directory(&ns_dir)?;
    let (bytes, sha_raw) = (read_regular(&ns_dir.join("namespace.json"), MAX_MANIFEST)?, String::from_utf8(read_regular(&ns_dir.join("namespace.sha256"), 256)?)?);
    ensure!(hex::encode(Sha256::digest(&bytes)) == sha_raw.trim(), "namespace manifest checksum mismatch");
    let manifest: NamespaceManifest = serde_json::from_slice(&bytes)?;
    ensure!(manifest.schema == SCHEMA && manifest.namespace_id == namespace_id && manifest.namespace_revision >= 1 && manifest.state == "mounted" && !manifest.base_vector.is_empty(), "invalid namespace manifest");
    valid_agent(&manifest.name)?;
    Ok((ns_dir, manifest))
}

#[rustfmt::skip]
fn enforce_write_lease(store: &Store, namespace_id: &str, agent_id: &str, rel_path: &str, req_epoch: Option<u64>) -> Result<Option<u64>> {
    if !store.root.join("leases").join(format!("{namespace_id}.json")).exists() {
        ensure!(req_epoch.is_none(), "conflict: lease_epoch specified but no active lease exists");
        return Ok(None);
    }
    let (now, mut table) = (now_secs()?, load_lease_table(store, namespace_id, "namespace")?);
    for l in &mut table.leases { if l.state == "active" && now >= l.expires_at { l.state = "expired".into(); } }
    save_lease_table(store, &table)?;
    for l in &table.leases {
        if l.state == "active" && prefixes_overlap(&l.prefix, rel_path) && l.agent_id != agent_id {
            bail!("conflict: path '{}' is locked by active lease of agent '{}' on prefix '{}' (epoch {})", rel_path, l.agent_id, l.prefix, l.lease_epoch);
        }
    }
    if let Some(active) = table.leases.iter().find(|l| l.state == "active" && l.agent_id == agent_id && prefix_covers(&l.prefix, rel_path)) {
        if let Some(ep) = req_epoch { ensure!(ep == active.lease_epoch, "conflict: stale or mismatched lease_epoch {ep} (active epoch is {})", active.lease_epoch); }
        return Ok(Some(active.lease_epoch));
    }
    if let Some(ep) = req_epoch { bail!("conflict: stale or inactive lease_epoch {ep} for agent '{agent_id}' on '{rel_path}'"); }
    if table.leases.iter().any(|l| l.agent_id == agent_id && l.state == "expired" && prefix_covers(&l.prefix, rel_path)) {
        bail!("conflict: lease for agent '{agent_id}' covering '{rel_path}' has expired");
    }
    Ok(None)
}

#[rustfmt::skip]
fn map_virtual_path<'a>(manifest: &'a NamespaceManifest, raw_path: &str) -> Result<(&'a BaseVectorEntry, PathBuf, PathBuf)> {
    let norm = normalize_rel_segments(raw_path, false)?;
    let rel = relative_path(norm.as_bytes())?;
    for bv in &manifest.base_vector {
        if let Ok(sub) = rel.strip_prefix(Path::new(&bv.mount_path)) && !sub.as_os_str().is_empty() { return Ok((bv, rel.clone(), relative_path(sub.as_os_str().as_bytes())?)); }
    }
    bail!("unmapped namespace path '{}': does not fall under any mounted repository prefix", display_path(&rel))
}

#[rustfmt::skip]
fn load_pending_writes(ns_dir: &Path, namespace_id: &str, rev: u32) -> Result<NamespacePendingWriteTable> {
    let (w_dir, p_file) = (ns_dir.join("writable"), ns_dir.join("writable/pending.json"));
    if !p_file.exists() { return Ok(NamespacePendingWriteTable { schema: SCHEMA, namespace_id: namespace_id.into(), namespace_revision: rev, writes: Vec::new() }); }
    let (raw, sha) = (read_regular(&p_file, MAX_MANIFEST)?, String::from_utf8(read_regular(&w_dir.join("pending.sha256"), 256)?)?);
    ensure!(hex::encode(Sha256::digest(&raw)) == sha.trim(), "pending writes checksum mismatch");
    Ok(serde_json::from_slice(&raw)?)
}

#[rustfmt::skip]
fn save_pending_writes(ns_dir: &Path, table: &NamespacePendingWriteTable) -> Result<()> {
    let (w_dir, raw) = (ns_dir.join("writable"), serde_json::to_vec_pretty(table)?);
    write_atomic_checked(&w_dir, "pending.json", &raw, 0o600)?;
    write_atomic_checked(&w_dir, "pending.sha256", hex::encode(Sha256::digest(&raw)).as_bytes(), 0o600)?;
    Ok(())
}

#[rustfmt::skip]
pub fn cmd_namespace_write(store: &Store, ns_arg: &OsStr, agent_arg: &OsStr, path_arg: &OsStr, content_arg: &OsStr, rest: &[OsString]) -> Result<Json> {
    let (ns_id, agent_id, raw_path, content_str) = (text_arg(ns_arg)?, text_arg(agent_arg)?, text_arg(path_arg)?, text_arg(content_arg)?);
    valid_agent(&agent_id)?;
    let (mut req_epoch, mut i) = (None, 0usize);
    while i < rest.len() {
        match text_arg(&rest[i])?.as_str() {
            "--lease-epoch" | "--epoch" => { i += 1; ensure!(i < rest.len(), "missing --lease-epoch"); req_epoch = Some(text_arg(&rest[i])?.parse::<u64>().context("invalid --lease-epoch")?); }
            other => bail!("unknown namespace-write flag: {other}"),
        }
        i += 1;
    }
    let (ns_dir, manifest) = read_namespace_manifest_any_rev(store, &ns_id)?;
    let (bv, rel_path, repo_rel) = map_virtual_path(&manifest, &raw_path)?;
    let (rel_str, repo_rel_str) = (display_path(&rel_path), display_path(&repo_rel));
    let active_epoch = enforce_write_lease(store, &ns_id, &agent_id, &rel_str, req_epoch)?;
    let (_, cp_manifest) = store.read_checkpoint(&bv.checkpoint_id)?;
    let base_map = manifest_worktree_map(&cp_manifest.entries)?;
    let (base_entry, mut table) = (base_map.get(&repo_rel), load_pending_writes(&ns_dir, &ns_id, manifest.namespace_revision)?);
    let (staged_files_dir, view_target) = (ns_dir.join("writable/files"), ns_dir.join("tree").join(&rel_path));
    let (operation, change, mode, size, sha256) = if content_str == "--delete" || content_str == "DELETE" {
        ensure!(base_entry.is_some() || table.writes.iter().any(|w| w.path == rel_str && w.operation == "write"), "cannot delete non-existent path '{rel_str}'");
        if staged_files_dir.join(&rel_path).exists() { let _ = fs::remove_file(staged_files_dir.join(&rel_path)); }
        if view_target.exists() || fs::symlink_metadata(&view_target).is_ok() { let _ = fs::remove_file(&view_target); }
        ("delete".to_owned(), "deleted".to_owned(), 0o644, None, None)
    } else {
        let candidate = Path::new(&content_str);
        let bytes = if candidate.is_file() && !fs::symlink_metadata(candidate)?.file_type().is_symlink() && !fs::canonicalize(candidate)?.starts_with(&store.root) { read_regular(candidate, MAX_BYTES)? } else { content_str.as_bytes().to_vec() };
        let (sha, sz, file_mode) = (hex::encode(Sha256::digest(&bytes)), bytes.len() as u64, base_entry.map_or(0o644, |e| if e.mode & 0o111 != 0 { 0o755 } else { 0o644 }));
        let staged_dest = staged_files_dir.join(&rel_path);
        write_atomic_checked(staged_dest.parent().context("parent")?, staged_dest.file_name().context("name")?.to_str().context("utf8")?, &bytes, file_mode)?;
        write_atomic_checked(view_target.parent().context("parent")?, view_target.file_name().context("name")?.to_str().context("utf8")?, &bytes, (file_mode & 0o555) | 0o400)?;
        ("write".to_owned(), if base_entry.is_some() { "modified" } else { "added" }.to_owned(), file_mode, Some(sz), Some(sha))
    };
    table.writes.retain(|w| w.path != rel_str);
    table.writes.push(NamespacePendingWrite {
        path: rel_str.clone(), path_base64: encode_path(&rel_path), mount_path: bv.mount_path.clone(), repo_rel_path: repo_rel_str.clone(), repo_rel_path_base64: encode_path(&repo_rel),
        base_checkpoint_id: bv.checkpoint_id.clone(), workspace_id: bv.workspace_id.clone(), base_oid: bv.base_oid.clone(), base_namespace_revision: manifest.namespace_revision,
        agent_id: agent_id.clone(), operation: operation.clone(), change: change.clone(), mode, size, sha256: sha256.clone(), lease_epoch: active_epoch,
    });
    table.writes.sort_by(|a, b| a.path.cmp(&b.path));
    save_pending_writes(&ns_dir, &table)?;
    Ok(serde_json::to_value(NamespaceWriteReport {
        schema: SCHEMA, namespace_id: ns_id, namespace_revision: manifest.namespace_revision, agent_id, path: rel_str, path_base64: encode_path(&rel_path),
        mount_path: bv.mount_path.clone(), repo_rel_path: repo_rel_str, repo_rel_path_base64: encode_path(&repo_rel), base_checkpoint_id: bv.checkpoint_id.clone(),
        workspace_id: bv.workspace_id.clone(), base_oid: bv.base_oid.clone(), operation, change, size, sha256, lease_epoch: active_epoch, pending_writes_count: table.writes.len(), state: "staged".into(),
    })?)
}

#[rustfmt::skip]
fn rebuild_namespace_tree(store: &Store, ns_dir: &Path, base_vector: &[BaseVectorEntry]) -> Result<usize> {
    let staging = store.stage()?;
    let staging_tree = staging.0.join("tree");
    private_dir(&staging_tree)?;
    let mut total_entries = 0usize;
    for bv in base_vector {
        let (cp_dir, cp_man) = store.read_checkpoint(&bv.checkpoint_id)?;
        let (cp_repo, mount_dest) = (cp_dir.join("repo"), staging_tree.join(decode_path(&bv.mount_path_base64)?));
        fs::create_dir_all(&mount_dest)?;
        let mut bytes_copied = 0u64;
        for entry in &cp_man.entries {
            let rel = decode_path(&entry.path_base64)?;
            if rel.starts_with(".git") { continue; }
            copy_single_entry(&cp_repo, &mount_dest, &rel, &mut bytes_copied)?;
            if entry.kind == "file" { fs::set_permissions(mount_dest.join(&rel), fs::Permissions::from_mode((entry.mode & 0o555) | 0o400))?; }
            total_entries += 1;
        }
    }
    let tree_dir = ns_dir.join("tree");
    if tree_dir.exists() { store.replace_dir_atomic(&staging_tree, &tree_dir)?; } else { sync_tree(&staging_tree)?; publish(&staging_tree, &tree_dir)?; }
    Ok(total_entries)
}

#[rustfmt::skip]
pub fn cmd_namespace_commit_back(store: &Store, ns_arg: &OsStr, agent_arg: &OsStr, rest: &[OsString]) -> Result<Json> {
    let (ns_id, agent_id) = (text_arg(ns_arg)?, text_arg(agent_arg)?);
    valid_agent(&agent_id)?;
    let (mut req_epoch, mut idx) = (None, 0usize);
    while idx < rest.len() {
        match text_arg(&rest[idx])?.as_str() {
            "--quiescent" => {}
            "--lease-epoch" | "--epoch" => { idx += 1; ensure!(idx < rest.len(), "missing --lease-epoch"); req_epoch = Some(text_arg(&rest[idx])?.parse::<u64>().context("invalid --lease-epoch")?); }
            other => bail!("unknown namespace-commit-back flag: {other}"),
        }
        idx += 1;
    }
    let (ns_dir, manifest) = read_namespace_manifest_any_rev(store, &ns_id)?;
    let pending = load_pending_writes(&ns_dir, &ns_id, manifest.namespace_revision)?;
    ensure!(!pending.writes.is_empty(), "no pending namespace writes to commit back");
    let mut active_epoch = req_epoch;
    for w in &pending.writes {
        let ep = enforce_write_lease(store, &ns_id, &agent_id, &w.path, req_epoch)?;
        if active_epoch.is_none() { active_epoch = ep; }
    }
    let mut writes_by_mount: BTreeMap<String, Vec<NamespacePendingWrite>> = BTreeMap::new();
    for w in &pending.writes { writes_by_mount.entry(w.mount_path.clone()).or_default().push(w.clone()); }

    let prep_result = (|| -> Result<_> {
        ensure!(pending.namespace_revision == manifest.namespace_revision, "conflict: namespace revision drifted");
        let mut prepared = Vec::new();
        for bv in &manifest.base_vector {
            let (cp_dir, cp_man) = store.read_checkpoint(&bv.checkpoint_id)?;
            let cp_repo = cp_dir.join("repo");
            let (actual_sha, actual_head) = (String::from_utf8(read_regular(&cp_dir.join("manifest.sha256"), 256)?)?, store.git_text(&cp_repo, &["rev-parse", "--verify", "HEAD"])?);
            ensure!(bv.base_oid == cp_man.workspace.base_oid && bv.head_oid == actual_head && bv.manifest_sha256 == actual_sha.trim(), "conflict: BaseVector drift on mount '{}'", bv.mount_path);
            let Some(m_writes) = writes_by_mount.get(&bv.mount_path) else { continue; };
            for w in m_writes { ensure!(w.base_checkpoint_id == bv.checkpoint_id && w.base_namespace_revision == manifest.namespace_revision, "conflict: staged write base checkpoint drifted on mount '{}'", bv.mount_path); }
            let (base_map, ws_dir) = (manifest_worktree_map(&cp_man.entries)?, store.root.join("workspaces").join(&bv.workspace_id));
            if ws_dir.is_dir() {
                let (ws, ws_repo) = (store.read_workspace(&bv.workspace_id)?, ws_dir.join("repo"));
                let ws_head = store.git_text(&ws_repo, &["rev-parse", "--verify", "HEAD"])?;
                ensure!(ws.base_oid == bv.base_oid && ws_head == bv.head_oid && ws.parent_checkpoint_id.as_deref().is_none_or(|p| p == bv.checkpoint_id), "conflict: constituent workspace '{}' drifted from BaseVector checkpoint", bv.workspace_id);
                let cls = ignore::classify_workspace(store, &ws_repo)?;
                let mut curr_ws_map = BTreeMap::new();
                for p in &cls.managed_paths { if let Some(e) = entry_for_path(&ws_repo, p)? { curr_ws_map.insert(p.clone(), e); } }
                let (drift_delta, ..) = compute_entries_delta(&base_map, &curr_ws_map, true);
                ensure!(drift_delta.is_empty(), "conflict: constituent workspace '{}' has uncommitted base drift", bv.workspace_id);
            }
            let stage_cp = store.stage()?;
            let stage_repo = stage_cp.0.join("repo");
            copy_all(&cp_repo, &stage_repo)?;
            for w in m_writes {
                let target = stage_repo.join(decode_path(&w.repo_rel_path_base64)?);
                if w.operation == "delete" {
                    if target.exists() || fs::symlink_metadata(&target).is_ok() { fs::remove_file(&target)?; }
                } else {
                    let bytes = read_regular(&ns_dir.join("writable/files").join(decode_path(&w.path_base64)?), MAX_BYTES)?;
                    write_atomic_checked(target.parent().context("parent")?, target.file_name().context("name")?.to_str().context("utf8")?, &bytes, w.mode)?;
                }
            }
            store.validate_repo(&stage_repo, &bv.base_oid)?;
            let (new_entries, new_cp_id, mut new_ws_meta) = (inventory(&stage_repo)?, new_id(), cp_man.workspace.clone());
            new_ws_meta.parent_checkpoint_id = Some(bv.checkpoint_id.clone());
            let new_cp_man = Manifest { schema: SCHEMA, checkpoint_id: new_cp_id.clone(), state: "local_complete".into(), workspace: new_ws_meta, excluded_ignored_entries: cp_man.excluded_ignored_entries, entries: new_entries.clone() };
            let cp_bytes = serde_json::to_vec_pretty(&new_cp_man)?;
            let cp_sha = hex::encode(Sha256::digest(&cp_bytes));
            write_new(&stage_cp.0.join("manifest.json"), &cp_bytes, 0o600)?;
            write_new(&stage_cp.0.join("manifest.sha256"), cp_sha.as_bytes(), 0o600)?;
            sync_tree(&stage_cp.0)?;

            let new_map = manifest_worktree_map(&new_entries)?;
            let (cs_entries, added, modified, deleted, mode_changed, type_changed) = compute_entries_delta(&base_map, &new_map, true);
            let (cs_id, stage_cs) = (new_id(), store.stage()?);
            let cs_files = stage_cs.0.join("files");
            private_dir(&cs_files)?;
            let mut copied = 0u64;
            for ce in &cs_entries { if ce.after.is_some() { copy_single_entry(&stage_repo, &cs_files, &decode_path(&ce.path_base64)?, &mut copied)?; } }
            let cs_obj = Changeset { schema: SCHEMA, changeset_id: cs_id, state: "local_complete".into(), base_oid: bv.base_oid.clone(), base_checkpoint_id: bv.checkpoint_id.clone(), source_checkpoint_id: new_cp_id.clone(), added, modified, deleted, mode_changed, type_changed, entries: cs_entries };
            let cs_bytes = serde_json::to_vec_pretty(&cs_obj)?;
            write_new(&stage_cs.0.join("changeset.json"), &cs_bytes, 0o600)?;
            write_new(&stage_cs.0.join("changeset.sha256"), hex::encode(Sha256::digest(&cs_bytes)).as_bytes(), 0o600)?;
            sync_tree(&stage_cs.0)?;
            prepared.push((bv.clone(), stage_cp, new_cp_id, cp_sha, new_map.len(), stage_cs, cs_obj));
        }
        Ok(prepared)
    })();

    let prepared = match prep_result {
        Ok(p) => p,
        Err(err) => { let _ = rebuild_namespace_tree(store, &ns_dir, &manifest.base_vector); let _ = fs::remove_dir_all(ns_dir.join("writable")); return Err(err); }
    };

    let (mut new_cp_by_mount, mut mount_commits) = (BTreeMap::new(), Vec::with_capacity(prepared.len()));
    for (bv, stage_cp, new_cp_id, cp_sha, worktree_cnt, stage_cs, cs_obj) in prepared {
        publish(&stage_cp.0, &store.root.join("checkpoints").join(&new_cp_id))?;
        publish(&stage_cs.0, &store.root.join("changesets").join(&cs_obj.changeset_id))?;
        let ws_dir = store.root.join("workspaces").join(&bv.workspace_id);
        if ws_dir.is_dir() {
            let (mut ws, ws_repo, cp_repo) = (store.read_workspace(&bv.workspace_id)?, ws_dir.join("repo"), store.root.join("checkpoints").join(&new_cp_id).join("repo"));
            let mut copied = 0u64;
            for ce in &cs_obj.entries {
                let (rel, dst) = (decode_path(&ce.path_base64)?, ws_repo.join(decode_path(&ce.path_base64)?));
                if ce.after.is_none() && (dst.exists() || fs::symlink_metadata(&dst).is_ok()) { fs::remove_file(&dst)?; }
                else if ce.after.is_some() { copy_single_entry(&cp_repo, &ws_repo, &rel, &mut copied)?; }
            }
            ws.parent_checkpoint_id = Some(new_cp_id.clone());
            write_atomic_checked(&ws_dir, "workspace.json", &serde_json::to_vec_pretty(&ws)?, 0o600)?;
        }
        new_cp_by_mount.insert(bv.mount_path.clone(), (new_cp_id.clone(), cp_sha, worktree_cnt));
        mount_commits.push(CrossRepoMountCommit {
            mount_path: bv.mount_path, workspace_id: bv.workspace_id, base_oid: bv.base_oid, previous_checkpoint_id: bv.checkpoint_id,
            new_checkpoint_id: new_cp_id, changeset_id: cs_obj.changeset_id, added: cs_obj.added, modified: cs_obj.modified,
            deleted: cs_obj.deleted, mode_changed: cs_obj.mode_changed, type_changed: cs_obj.type_changed, entries_count: worktree_cnt,
        });
    }

    let (previous_base_vector, mut new_base_vector) = (manifest.base_vector.clone(), Vec::with_capacity(manifest.base_vector.len()));
    for mut bv in manifest.base_vector {
        if let Some((new_cp_id, cp_sha, cnt)) = new_cp_by_mount.get(&bv.mount_path) { bv.checkpoint_id = new_cp_id.clone(); bv.manifest_sha256 = cp_sha.clone(); bv.entries_count = *cnt; }
        new_base_vector.push(bv);
    }

    let (total_entries, new_rev) = (rebuild_namespace_tree(store, &ns_dir, &new_base_vector)?, manifest.namespace_revision + 1);
    let updated_manifest = NamespaceManifest {
        schema: SCHEMA, namespace_id: ns_id.clone(), name: manifest.name.clone(), namespace_revision: new_rev,
        view_path: manifest.view_path, mount_count: new_base_vector.len(), total_entries, state: "mounted".into(), base_vector: new_base_vector.clone(),
    };
    let ns_bytes = serde_json::to_vec_pretty(&updated_manifest)?;
    write_atomic_checked(&ns_dir, "namespace.json", &ns_bytes, 0o600)?;
    write_atomic_checked(&ns_dir, "namespace.sha256", hex::encode(Sha256::digest(&ns_bytes)).as_bytes(), 0o600)?;

    let (commit_id, commits_dir) = (new_id(), ns_dir.join("commits"));
    let receipt_path = commits_dir.join(format!("{commit_id}.json"));
    let receipt = CrossRepoCommitReceipt {
        schema: SCHEMA, commit_id: commit_id.clone(), namespace_id: ns_id, name: manifest.name, agent_id,
        previous_revision: manifest.namespace_revision, namespace_revision: new_rev, lease_epoch: active_epoch,
        phase: "committed".into(), state: "committed".into(), touched_mounts_count: mount_commits.len(),
        total_writes_committed: pending.writes.len(), mount_commits, previous_base_vector, base_vector: new_base_vector,
        receipt_path: receipt_path.to_string_lossy().into_owned(),
    };
    let rec_bytes = serde_json::to_vec_pretty(&receipt)?;
    write_atomic_checked(&commits_dir, &format!("{commit_id}.json"), &rec_bytes, 0o600)?;
    write_atomic_checked(&commits_dir, &format!("{commit_id}.sha256"), hex::encode(Sha256::digest(&rec_bytes)).as_bytes(), 0o600)?;
    let _ = fs::remove_dir_all(ns_dir.join("writable"));

    Ok(serde_json::to_value(receipt)?)
}
