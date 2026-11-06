use super::{
    core::*,
    ignore::IgnoreMatcher,
    manifest::entries_equivalent,
    remote::{RemoteCheckpointManifest, RemoteDirtyManifest},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::{
        ffi::OsStringExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VfsCatalogEntry {
    pub path: String, pub path_base64: String, pub kind: String, pub mode: u32,
    pub size: u64, pub sha256: String, pub hydrated: bool, pub state: String,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VfsMountManifest {
    pub schema: u32, pub vfs_id: String, pub checkpoint_id: String, pub workspace_id: String,
    pub agent_id: String, pub base_oid: String, pub head_oid: String, pub remote_cas_path: Option<String>,
    pub inline_threshold: u64, pub hydrate_patterns: Vec<String>, pub mount_path: String, pub state: String,
    pub total_entries: usize, pub hydrated_entries: usize, pub dehydrated_entries: usize, pub dirty_entries: usize,
    pub total_bytes: u64, pub hydrated_bytes: u64, pub unhydrated_bytes: u64, pub catalog: Vec<VfsCatalogEntry>,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VfsHydrateReport {
    pub schema: u32, pub vfs_id: String, pub checkpoint_id: String, pub mount_path: String, pub state: String,
    pub prewarm: bool, pub cow_write: bool, pub newly_hydrated: usize, pub already_hydrated: usize,
    pub bytes_hydrated: u64, pub hydrated_paths: Vec<String>, pub total_entries: usize,
    pub hydrated_entries: usize, pub dehydrated_entries: usize, pub dirty_entries: usize,
    pub hydrated_bytes: u64, pub unhydrated_bytes: u64,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VfsDirtyEntry {
    pub path: String, pub path_base64: String, pub change: String, pub state: String,
    pub kind: Option<String>, pub mode: Option<u32>, pub size: Option<u64>, pub sha256: Option<String>,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VfsStatusReport {
    pub schema: u32, pub vfs_id: String, pub checkpoint_id: String, pub workspace_id: String,
    pub agent_id: String, pub base_oid: String, pub head_oid: String, pub mount_path: String, pub state: String,
    pub is_dirty: bool, pub clean: bool, pub total_entries: usize, pub hydrated_entries: usize,
    pub hydrated_clean_entries: usize, pub dehydrated_entries: usize, pub dirty_entries: usize,
    pub ignored_entries: usize, pub total_bytes: u64, pub hydrated_bytes: u64, pub unhydrated_bytes: u64,
    pub dehydrated_paths: Vec<String>, pub hydrated_clean_paths: Vec<String>,
    pub hydrated_dirty_paths: Vec<String>, pub ignored_paths: Vec<String>, pub dirty_details: Vec<VfsDirtyEntry>,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VfsEvictReport {
    pub schema: u32, pub vfs_id: String, pub checkpoint_id: String, pub mount_path: String, pub state: String,
    pub evicted_entries: usize, pub already_dehydrated_entries: usize, pub skipped_dirty_entries: usize,
    pub reclaimed_bytes: u64, pub evicted_paths: Vec<String>, pub skipped_dirty_paths: Vec<String>,
    pub total_entries: usize, pub hydrated_entries: usize, pub dehydrated_entries: usize,
    pub dirty_entries: usize, pub hydrated_bytes: u64, pub unhydrated_bytes: u64,
}

struct TempGuard(PathBuf, bool);
impl Drop for TempGuard {
    fn drop(&mut self) {
        if !self.1 {
            let _ = fs::remove_file(&self.0);
        }
    }
}

fn ensure_vfs_root(store: &Store) -> Result<PathBuf> {
    let vfs_root = store.root.join("vfs");
    if !vfs_root.exists() {
        private_dir(&vfs_root)?;
    }
    require_directory(&vfs_root)?;
    Ok(vfs_root)
}

fn validate_pattern(pat: &str) -> Result<()> {
    ensure!(
        !pat.is_empty() && !pat.contains('\0') && !pat.starts_with('/'),
        "invalid VFS pattern"
    );
    for seg in pat.split('/') {
        ensure!(
            !matches!(seg, "." | ".." | ".git"),
            "unsafe VFS pattern segment"
        );
    }
    Ok(())
}

pub(crate) fn matches_query(pattern: &str, rel_path: &str) -> bool {
    let pat = pattern.trim_end_matches('/');
    if pat == "*" || pat == "**" || pat == rel_path {
        return true;
    }
    if rel_path
        .strip_prefix(pat)
        .is_some_and(|r| r.starts_with('/'))
    {
        return true;
    }
    if !pat.contains('/') {
        let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
        return glob_seg(pat.as_bytes(), name.as_bytes())
            || glob_seg(pat.as_bytes(), rel_path.as_bytes());
    }
    let (p_segs, t_segs): (Vec<_>, Vec<_>) =
        (pat.split('/').collect(), rel_path.split('/').collect());
    match_segs(&p_segs, &t_segs)
}

fn match_segs(pat: &[&str], txt: &[&str]) -> bool {
    if pat.is_empty() {
        return txt.is_empty();
    }
    if pat[0] == "**" {
        return match_segs(&pat[1..], txt) || (!txt.is_empty() && match_segs(pat, &txt[1..]));
    }
    !txt.is_empty()
        && glob_seg(pat[0].as_bytes(), txt[0].as_bytes())
        && match_segs(&pat[1..], &txt[1..])
}

fn glob_seg(pat: &[u8], txt: &[u8]) -> bool {
    match (pat.first(), txt.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            glob_seg(&pat[1..], txt) || (!txt.is_empty() && glob_seg(pat, &txt[1..]))
        }
        (Some(b'?'), Some(_)) => glob_seg(&pat[1..], &txt[1..]),
        (Some(a), Some(b)) if a == b => glob_seg(&pat[1..], &txt[1..]),
        _ => false,
    }
}

fn open_remote_cas(store: &Store, cas_arg: &OsStr) -> Result<PathBuf> {
    let req = Path::new(cas_arg);
    let abs = if req.is_absolute() {
        req.to_path_buf()
    } else {
        std::env::current_dir()?.join(req)
    };
    no_symlink_components(&abs)?;
    require_directory(&abs)?;
    let cas_root = fs::canonicalize(&abs)?;
    ensure!(
        fs::metadata(&cas_root)?.permissions().mode() & 0o077 == 0,
        "remote CAS must be 0700"
    );
    ensure!(
        !cas_root.starts_with(&store.root) && !store.root.starts_with(&cas_root),
        "CAS overlaps store"
    );
    require_directory(&cas_root.join("blobs"))?;
    require_directory(&cas_root.join("checkpoints"))?;
    Ok(cas_root)
}

#[rustfmt::skip]
fn fetch_blob(store: &Store, cp_id: &str, cas: Option<&Path>, rel: &Path, kind: &str, size: u64, sha: &str) -> Result<Vec<u8>> {
    ensure!(sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "invalid sha256");
    ensure!(size <= MAX_BYTES, "blob exceeds size limit");
    if let Some(cas_root) = cas {
        let p = cas_root.join("blobs").join(&sha[0..2]).join(sha);
        let meta = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&p)
            .with_context(|| format!("missing CAS blob {}", p.display()))?.metadata()?;
        ensure!(meta.is_file() && meta.permissions().mode() & 0o7000 == 0 && meta.len() == size, "CAS blob size/mode mismatch");
        let bytes = read_regular(&p, MAX_BYTES)?;
        ensure!(bytes.len() as u64 == size && hex::encode(Sha256::digest(&bytes)) == sha, "CAS blob SHA-256 mismatch");
        return Ok(bytes);
    }
    let cp_repo = store.root.join("checkpoints").join(cp_id).join("repo");
    let full = cp_repo.join(rel);
    let bytes = if kind == "symlink" {
        let target = fs::read_link(&full)?; validate_symlink(&cp_repo, rel, &target)?;
        target.into_os_string().into_vec()
    } else { read_regular(&full, MAX_BYTES)? };
    ensure!(bytes.len() as u64 == size && hex::encode(Sha256::digest(&bytes)) == sha, "checkpoint blob digest mismatch");
    Ok(bytes)
}

fn write_atomic(dir: &Path, name: &OsStr, bytes: &[u8], mode: u32) -> Result<PathBuf> {
    if !dir.exists() {
        private_dir(dir)?;
    }
    require_directory(dir)?;
    let tmp = dir.join(format!(".tmp-{}", Uuid::new_v4()));
    let mut guard = TempGuard(tmp.clone(), false);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    drop(file);
    let dest = dir.join(name);
    fs::rename(&tmp, &dest)?;
    File::open(dir)?.sync_all()?;
    guard.1 = true;
    Ok(dest)
}

#[rustfmt::skip]
fn materialize_entry(mount: &Path, rel: &Path, kind: &str, mode: u32, bytes: &[u8], cp_src: Option<&Path>) -> Result<()> {
    let dest = mount.join(rel);
    let parent = dest.parent().context("missing parent")?;
    if !parent.exists() { private_dir(parent)?; }
    require_directory(parent)?;
    if fs::symlink_metadata(&dest).is_ok() { fs::remove_file(&dest)?; }
    if kind == "symlink" {
        ensure!(!rel.starts_with(".git"), "symlink in .git unsupported");
        let target = PathBuf::from(OsString::from_vec(bytes.to_vec()));
        symlink(&target, &dest)?; validate_symlink(mount, rel, &target)?; File::open(parent)?.sync_all()?;
    } else {
        let perm = if mode & 0o777 != 0 { mode & 0o777 } else { 0o644 };
        let written = write_atomic(parent, dest.file_name().context("name")?, bytes, perm)?;
        if let Some(src_p) = cp_src.filter(|p| p.exists()) {
            let (m1, m2) = (fs::symlink_metadata(&written)?, fs::symlink_metadata(src_p)?);
            ensure!((m1.dev(), m1.ino()) != (m2.dev(), m2.ino()), "hardlink shared with store");
        }
    }
    Ok(())
}

fn save_vfs_manifest(vfs_dir: &Path, man: &mut VfsMountManifest, extra_dirty: usize) -> Result<()> {
    man.total_entries = man.catalog.len();
    man.hydrated_entries = man.catalog.iter().filter(|e| e.hydrated).count();
    man.dehydrated_entries = man.total_entries - man.hydrated_entries;
    man.dirty_entries = man
        .catalog
        .iter()
        .filter(|e| e.state == "hydrated_dirty")
        .count()
        + extra_dirty;
    man.total_bytes = man.catalog.iter().map(|e| e.size).sum();
    man.hydrated_bytes = man
        .catalog
        .iter()
        .filter(|e| e.hydrated)
        .map(|e| e.size)
        .sum();
    man.unhydrated_bytes = man.total_bytes - man.hydrated_bytes;
    let raw = serde_json::to_vec_pretty(man)?;
    let sha = hex::encode(Sha256::digest(&raw));
    write_atomic(vfs_dir, OsStr::new("vfs.json"), &raw, 0o600)?;
    write_atomic(vfs_dir, OsStr::new("vfs.sha256"), sha.as_bytes(), 0o600)?;
    Ok(())
}

fn read_vfs_manifest(store: &Store, vfs_arg: &OsStr) -> Result<(PathBuf, VfsMountManifest)> {
    ensure_vfs_root(store)?;
    let vfs_id = text_arg(vfs_arg)?;
    valid_id(&vfs_id)?;
    let vfs_dir = store.root.join("vfs").join(&vfs_id);
    require_directory(&vfs_dir).with_context(|| format!("unknown VFS mount {vfs_id}"))?;
    let raw = read_regular(&vfs_dir.join("vfs.json"), MAX_MANIFEST)?;
    let exp_sha = String::from_utf8(read_regular(&vfs_dir.join("vfs.sha256"), 256)?)?;
    ensure!(
        hex::encode(Sha256::digest(&raw)) == exp_sha.trim(),
        "VFS manifest checksum mismatch"
    );
    let man: VfsMountManifest = serde_json::from_slice(&raw)?;
    ensure!(
        man.schema == SCHEMA && man.vfs_id == vfs_id,
        "invalid VFS manifest"
    );
    valid_id(&man.checkpoint_id)?;
    valid_agent(&man.agent_id)?;
    require_directory(&vfs_dir.join("mount"))?;
    Ok((vfs_dir, man))
}

#[rustfmt::skip]
fn dirty_item(path: &str, b64: &str, change: &str, actual: Option<Entry>) -> VfsDirtyEntry {
    VfsDirtyEntry {
        path: path.into(), path_base64: b64.into(), change: change.into(), state: "hydrated_dirty".into(),
        kind: actual.as_ref().map(|e| e.kind.clone()), mode: actual.as_ref().map(|e| e.mode),
        size: actual.as_ref().map(|e| e.size), sha256: actual.map(|e| e.sha256),
    }
}

fn match_targets(
    catalog: &[VfsCatalogEntry],
    added: &BTreeSet<String>,
    patterns: &[String],
) -> Result<(BTreeSet<usize>, BTreeSet<String>)> {
    let (mut matched_cat, mut matched_added) = (BTreeSet::new(), BTreeSet::new());
    for pat in patterns {
        let mut found = false;
        for (i, e) in catalog.iter().enumerate() {
            if matches_query(pat, &e.path) {
                matched_cat.insert(i);
                found = true;
            }
        }
        for add_p in added {
            if matches_query(pat, add_p) {
                matched_added.insert(add_p.clone());
                found = true;
            }
        }
        if !pat.contains(['*', '?', '[']) {
            ensure!(found, "no VFS entry matched path: {pat}");
        }
    }
    ensure!(
        !matched_cat.is_empty() || !matched_added.is_empty() || catalog.is_empty(),
        "no VFS entries matched"
    );
    Ok((matched_cat, matched_added))
}

#[rustfmt::skip]
fn evaluate_vfs_status(store: &Store, vfs_dir: &Path, man: &mut VfsMountManifest) -> Result<VfsStatusReport> {
    let mount_dir = vfs_dir.join("mount");
    let cas = man.remote_cas_path.as_deref().map(|s| open_remote_cas(store, OsStr::new(s))).transpose()?;
    let (mut git_m, mut ry_m) = (IgnoreMatcher::default(), IgnoreMatcher::default());
    let excl = mount_dir.join(".git/info/exclude");
    if excl.is_file() { git_m.add_patterns(Path::new(""), &String::from_utf8_lossy(&read_regular(&excl, MAX_MANIFEST)?)); }
    let (mut cat_paths, mut ignore_rules) = (BTreeSet::new(), Vec::new());
    for c in &man.catalog {
        let rel = decode_path(&c.path_base64)?; cat_paths.insert(rel.clone());
        if let Some(f @ (".gitignore" | ".rootyardignore")) = rel.file_name().and_then(|s| s.to_str()) {
            let p = mount_dir.join(&rel);
            let b = if p.is_file() { read_regular(&p, MAX_MANIFEST)? }
                else { fetch_blob(store, &man.checkpoint_id, cas.as_deref(), &rel, &c.kind, c.size, &c.sha256)? };
            ignore_rules.push((rel.components().count(), rel.clone(), f == ".gitignore", b));
        }
    }
    let disk_walk = walk(&mount_dir)?;
    for (rel, meta) in &disk_walk {
        if !rel.starts_with(".git") && !cat_paths.contains(rel) && meta.is_file()
            && let Some(f @ (".gitignore" | ".rootyardignore")) = rel.file_name().and_then(|s| s.to_str())
        {
            ignore_rules.push((rel.components().count(), rel.clone(), f == ".gitignore", read_regular(&mount_dir.join(rel), MAX_MANIFEST)?));
        }
    }
    ignore_rules.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    for (_, rel, is_git, bytes) in ignore_rules {
        let (base, text) = (rel.parent().unwrap_or(Path::new("")), String::from_utf8_lossy(&bytes));
        if is_git { git_m.add_patterns(base, &text); } else { ry_m.add_patterns(base, &text); }
    }

    let (mut dehyd, mut clean_p, mut dirty_p, mut ign_p, mut details) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for c in &mut man.catalog {
        let rel = decode_path(&c.path_base64)?;
        let base_e = Entry { path_base64: c.path_base64.clone(), kind: c.kind.clone(), mode: c.mode, size: c.size, sha256: c.sha256.clone() };
        match entry_for_path(&mount_dir, &rel)? {
            None if !c.hydrated => { c.state = "dehydrated".into(); dehyd.push(c.path.clone()); }
            None => { c.state = "hydrated_dirty".into(); dirty_p.push(c.path.clone()); details.push(dirty_item(&c.path, &c.path_base64, "deleted", None)); }
            Some(act) => {
                c.hydrated = true;
                if entries_equivalent(&act, &base_e, true) { c.state = "hydrated_clean".into(); clean_p.push(c.path.clone()); }
                else {
                    c.state = "hydrated_dirty".into();
                    let chg = if act.kind != c.kind { "type_changed" } else if act.sha256 != c.sha256 || act.size != c.size { "modified" } else { "mode_changed" };
                    dirty_p.push(c.path.clone()); details.push(dirty_item(&c.path, &c.path_base64, chg, Some(act)));
                }
            }
        }
    }
    for rel in disk_walk.keys() {
        if rel.starts_with(".git") || cat_paths.contains(rel) { continue; }
        let p_str = display_path(rel);
        if git_m.is_ignored(rel, false) || ry_m.is_ignored(rel, false) { ign_p.push(p_str); }
        else if let Some(act) = entry_for_path(&mount_dir, rel)? {
            dirty_p.push(p_str.clone()); details.push(dirty_item(&p_str, &encode_path(rel), "added", Some(act)));
        }
    }
    dirty_p.sort(); details.sort_by(|a, b| a.path.cmp(&b.path));
    save_vfs_manifest(vfs_dir, man, details.iter().filter(|d| d.change == "added").count())?;

    Ok(VfsStatusReport {
        schema: SCHEMA, vfs_id: man.vfs_id.clone(), checkpoint_id: man.checkpoint_id.clone(), workspace_id: man.workspace_id.clone(),
        agent_id: man.agent_id.clone(), base_oid: man.base_oid.clone(), head_oid: man.head_oid.clone(),
        mount_path: display_path(&mount_dir), state: "mounted".into(), is_dirty: !details.is_empty(), clean: details.is_empty(),
        total_entries: man.total_entries, hydrated_entries: man.hydrated_entries, hydrated_clean_entries: clean_p.len(),
        dehydrated_entries: man.dehydrated_entries, dirty_entries: details.len(), ignored_entries: ign_p.len(),
        total_bytes: man.total_bytes, hydrated_bytes: man.hydrated_bytes, unhydrated_bytes: man.unhydrated_bytes,
        dehydrated_paths: dehyd, hydrated_clean_paths: clean_p, hydrated_dirty_paths: dirty_p, ignored_paths: ign_p, dirty_details: details,
    })
}

#[rustfmt::skip]
pub fn cmd_vfs_mount(store: &Store, cp_arg: &OsStr, agent_arg: &OsStr, rest: &[OsString]) -> Result<Json> {
    let vfs_root = ensure_vfs_root(store)?;
    let (cp_id, agent) = (text_arg(cp_arg)?, text_arg(agent_arg)?);
    valid_id(&cp_id)?; valid_agent(&agent)?;

    let (mut cas_os, mut inline_thresh, mut has_thresh, mut patterns, mut i) = (None, 0u64, false, Vec::new(), 0);
    while i < rest.len() {
        match text_arg(&rest[i])?.as_str() {
            "--remote-cas" => { i += 1; ensure!(i < rest.len(), "missing --remote-cas"); cas_os = Some(rest[i].clone()); }
            "--inline-threshold" => {
                i += 1; ensure!(i < rest.len(), "missing --inline-threshold");
                inline_thresh = text_arg(&rest[i])?.parse::<u64>().context("invalid threshold")?;
                ensure!(inline_thresh <= MAX_BYTES, "inline threshold too large"); has_thresh = true;
            }
            "--hydrate-pattern" => {
                i += 1; ensure!(i < rest.len(), "missing --hydrate-pattern");
                let pat = text_arg(&rest[i])?; validate_pattern(&pat)?; patterns.push(pat);
            }
            other => bail!("unknown vfs-mount flag: {other}"),
        }
        i += 1;
    }

    let cas = cas_os.as_deref().map(|a| open_remote_cas(store, a)).transpose()?;
    let (ws, entries, head_oid): (Workspace, Vec<Entry>, String) = match &cas {
        Some(cas_root) if cas_root.join("checkpoints").join(&cp_id).join("manifest.json").exists() => {
            let r_cp = cas_root.join("checkpoints").join(&cp_id);
            let raw = read_regular(&r_cp.join("manifest.json"), MAX_MANIFEST)?;
            let sha = String::from_utf8(read_regular(&r_cp.join("manifest.sha256"), 256)?)?;
            ensure!(hex::encode(Sha256::digest(&raw)) == sha.trim(), "remote manifest checksum mismatch");
            let r_man: RemoteCheckpointManifest = serde_json::from_slice(&raw)?;
            ensure!(r_man.schema == SCHEMA && r_man.checkpoint_id == cp_id && r_man.state == "COMMITTED" && r_man.durability == "remote_cas_committed", "remote checkpoint not COMMITTED");
            store.validate_workspace(&r_man.workspace)?; validate_entries(&r_man.entries)?;
            let d_raw = read_regular(&r_cp.join("dirty_manifest.json"), MAX_MANIFEST)?;
            let d_sha = String::from_utf8(read_regular(&r_cp.join("dirty_manifest.sha256"), 256)?)?;
            let act_d = hex::encode(Sha256::digest(&d_raw));
            ensure!(act_d == d_sha.trim() && act_d == r_man.dirty_manifest_sha256, "dirty manifest checksum mismatch");
            let d_man: RemoteDirtyManifest = serde_json::from_slice(&d_raw)?;
            ensure!(d_man.checkpoint_id == cp_id && d_man.entries.len() == r_man.dirty_entries_count, "dirty manifest mismatch");
            (r_man.workspace, r_man.entries, d_man.head_oid)
        }
        _ => {
            let (cp_dir, man) = store.read_checkpoint(&cp_id)?;
            let head = store.git_text(&cp_dir.join("repo"), &["rev-parse", "--verify", "HEAD"])?;
            (man.workspace, man.entries, head)
        }
    };

    let (vfs_id, staging) = (new_id(), store.stage()?);
    let (vfs_dir, stage_mount) = (vfs_root.join(&vfs_id), staging.0.join("mount"));
    for req in [".git", ".git/objects", ".git/refs"] { private_dir(&stage_mount.join(req))?; }
    let cp_repo = store.root.join("checkpoints").join(&cp_id).join("repo");
    let mut catalog = Vec::new();
    for e in &entries {
        let rel = decode_path(&e.path_base64)?;
        if rel.starts_with(".git") {
            let b = fetch_blob(store, &cp_id, cas.as_deref(), &rel, &e.kind, e.size, &e.sha256)?;
            materialize_entry(&stage_mount, &rel, &e.kind, e.mode, &b, None)?;
            continue;
        }
        let rel_str = display_path(&rel);
        let hydrate = (has_thresh && e.size <= inline_thresh) || (!has_thresh && inline_thresh > 0 && e.size <= inline_thresh)
            || patterns.iter().any(|p| matches_query(p, &rel_str));
        if hydrate {
            let b = fetch_blob(store, &cp_id, cas.as_deref(), &rel, &e.kind, e.size, &e.sha256)?;
            materialize_entry(&stage_mount, &rel, &e.kind, e.mode, &b, Some(&cp_repo.join(&rel)))?;
        }
        catalog.push(VfsCatalogEntry {
            path: rel_str, path_base64: e.path_base64.clone(), kind: e.kind.clone(), mode: e.mode, size: e.size,
            sha256: e.sha256.clone(), hydrated: hydrate, state: if hydrate { "hydrated_clean" } else { "dehydrated" }.into(),
        });
    }
    store.validate_repo(&stage_mount, &ws.base_oid)?;
    let mut manifest = VfsMountManifest {
        schema: SCHEMA, vfs_id, checkpoint_id: cp_id, workspace_id: ws.workspace_id, agent_id: agent, base_oid: ws.base_oid,
        head_oid, remote_cas_path: cas.as_ref().map(|p| display_path(p)), inline_threshold: inline_thresh, hydrate_patterns: patterns,
        mount_path: display_path(&vfs_dir.join("mount")), state: "mounted".into(), total_entries: 0, hydrated_entries: 0,
        dehydrated_entries: 0, dirty_entries: 0, total_bytes: 0, hydrated_bytes: 0, unhydrated_bytes: 0, catalog,
    };
    save_vfs_manifest(&staging.0, &mut manifest, 0)?; sync_tree(&staging.0)?; publish(&staging.0, &vfs_dir)?;
    Ok(serde_json::to_value(manifest)?)
}

#[rustfmt::skip]
pub fn cmd_vfs_hydrate(store: &Store, vfs_arg: &OsStr, rest: &[OsString]) -> Result<Json> {
    let (vfs_dir, mut man) = read_vfs_manifest(store, vfs_arg)?;
    let mount_dir = vfs_dir.join("mount");
    let (mut patterns, mut cow_arg, mut prewarm, mut idx) = (Vec::new(), None, false, 0);
    while idx < rest.len() {
        let arg = text_arg(&rest[idx])?;
        if arg == "--prewarm" { prewarm = true; }
        else if arg == "--cow-write" { idx += 1; ensure!(idx < rest.len(), "missing value for --cow-write"); cow_arg = Some(text_arg(&rest[idx])?); }
        else if arg.starts_with("--") { bail!("unknown vfs-hydrate flag: {arg}"); }
        else { validate_pattern(&arg)?; patterns.push(arg); }
        idx += 1;
    }
    if prewarm && patterns.is_empty() { patterns.push("**".into()); }
    ensure!(!patterns.is_empty(), "at least one path or glob pattern is required");

    let (matched, _) = match_targets(&man.catalog, &BTreeSet::new(), &patterns)?;
    ensure!(cow_arg.is_none() || matched.len() == 1, "--cow-write requires a single matched file");

    let cas = man.remote_cas_path.as_deref().map(|s| open_remote_cas(store, OsStr::new(s))).transpose()?;
    let mut staged = BTreeMap::new();
    for &i in &matched {
        let c = &man.catalog[i];
        let rel = decode_path(&c.path_base64)?;
        if cow_arg.is_some() || !c.hydrated || !mount_dir.join(&rel).exists() {
            let b = fetch_blob(store, &man.checkpoint_id, cas.as_deref(), &rel, &c.kind, c.size, &c.sha256)?;
            staged.insert(i, (rel, b));
        }
    }

    let cp_repo = store.root.join("checkpoints").join(&man.checkpoint_id).join("repo");
    let (mut newly_hydrated, mut already_hydrated, mut bytes_hydrated, mut hydrated_paths) = (0, 0, 0u64, Vec::new());
    for &i in &matched {
        let c = &mut man.catalog[i];
        let rel = decode_path(&c.path_base64)?;
        if !c.hydrated || fs::symlink_metadata(mount_dir.join(&rel)).is_err() {
            let (_, ref b) = staged[&i];
            materialize_entry(&mount_dir, &rel, &c.kind, c.mode, b, Some(&cp_repo.join(&rel)))?;
            c.hydrated = true; c.state = "hydrated_clean".into(); newly_hydrated += 1; bytes_hydrated += c.size;
        } else { already_hydrated += 1; }
        if let Some(ref val) = cow_arg {
            let p = Path::new(val);
            let cow_b = if p.is_file() && !p.starts_with(&mount_dir) { read_regular(p, MAX_BYTES)? } else { val.as_bytes().to_vec() };
            materialize_entry(&mount_dir, &rel, "file", c.mode, &cow_b, None)?;
            c.hydrated = true; c.state = "hydrated_dirty".into();
        }
        hydrated_paths.push(c.path.clone());
    }
    evaluate_vfs_status(store, &vfs_dir, &mut man)?; sync_tree(&mount_dir)?;
    Ok(serde_json::to_value(VfsHydrateReport {
        schema: SCHEMA, vfs_id: man.vfs_id, checkpoint_id: man.checkpoint_id, mount_path: display_path(&mount_dir),
        state: "hydrated".into(), prewarm, cow_write: cow_arg.is_some(), newly_hydrated, already_hydrated, bytes_hydrated,
        hydrated_paths, total_entries: man.total_entries, hydrated_entries: man.hydrated_entries,
        dehydrated_entries: man.dehydrated_entries, dirty_entries: man.dirty_entries,
        hydrated_bytes: man.hydrated_bytes, unhydrated_bytes: man.unhydrated_bytes,
    })?)
}

pub fn cmd_vfs_status(store: &Store, vfs_arg: &OsStr) -> Result<Json> {
    let (vfs_dir, mut man) = read_vfs_manifest(store, vfs_arg)?;
    Ok(serde_json::to_value(evaluate_vfs_status(
        store, &vfs_dir, &mut man,
    )?)?)
}

#[rustfmt::skip]
pub fn cmd_vfs_evict(store: &Store, vfs_arg: &OsStr, rest: &[OsString]) -> Result<Json> {
    let (vfs_dir, mut man) = read_vfs_manifest(store, vfs_arg)?;
    let mount_dir = vfs_dir.join("mount");
    let (mut patterns, mut skip_dirty) = (Vec::new(), false);
    for arg_os in rest {
        let arg = text_arg(arg_os)?;
        if arg == "--quiescent" { continue; }
        else if arg == "--skip-dirty" { skip_dirty = true; }
        else if arg.starts_with("--") { bail!("unknown vfs-evict flag: {arg}"); }
        else { validate_pattern(&arg)?; patterns.push(arg); }
    }
    ensure!(!patterns.is_empty(), "at least one path or glob pattern is required");

    let status = evaluate_vfs_status(store, &vfs_dir, &mut man)?;
    let added_dirty: BTreeSet<String> = status.dirty_details.iter().filter(|d| d.change == "added").map(|d| d.path.clone()).collect();
    let (matched_cat, matched_added) = match_targets(&man.catalog, &added_dirty, &patterns)?;

    let mut dirty_targets = BTreeSet::new();
    for &i in &matched_cat { if man.catalog[i].state == "hydrated_dirty" { dirty_targets.insert(man.catalog[i].path.clone()); } }
    dirty_targets.extend(matched_added);
    if !dirty_targets.is_empty() && !skip_dirty {
        let list: Vec<_> = dirty_targets.into_iter().collect();
        bail!("conflict: refusing to evict dirty VFS entries without --skip-dirty: {}", list.join(", "));
    }

    let (mut evicted_entries, mut already_dehydrated_entries, mut reclaimed_bytes, mut evicted_paths) = (0, 0, 0u64, Vec::new());
    for &i in &matched_cat {
        let c = &mut man.catalog[i];
        if c.state == "hydrated_dirty" { continue; }
        if !c.hydrated || c.state == "dehydrated" { already_dehydrated_entries += 1; continue; }
        let rel = decode_path(&c.path_base64)?;
        let full = mount_dir.join(&rel);
        if fs::symlink_metadata(&full).is_ok() { fs::remove_file(&full)?; }
        let mut cur = full.parent();
        while let Some(dir) = cur {
            if dir == mount_dir || !dir.starts_with(&mount_dir) || fs::remove_dir(dir).is_err() { break; }
            cur = dir.parent();
        }
        c.hydrated = false; c.state = "dehydrated".into();
        evicted_entries += 1; reclaimed_bytes += c.size; evicted_paths.push(c.path.clone());
    }
    let skipped_dirty_paths: Vec<String> = dirty_targets.into_iter().collect();
    save_vfs_manifest(&vfs_dir, &mut man, added_dirty.len())?; sync_tree(&mount_dir)?;

    Ok(serde_json::to_value(VfsEvictReport {
        schema: SCHEMA, vfs_id: man.vfs_id, checkpoint_id: man.checkpoint_id, mount_path: display_path(&mount_dir),
        state: "evicted".into(), evicted_entries, already_dehydrated_entries, skipped_dirty_entries: skipped_dirty_paths.len(),
        reclaimed_bytes, evicted_paths, skipped_dirty_paths, total_entries: man.total_entries,
        hydrated_entries: man.hydrated_entries, dehydrated_entries: man.dehydrated_entries,
        dirty_entries: man.dirty_entries, hydrated_bytes: man.hydrated_bytes, unhydrated_bytes: man.unhydrated_bytes,
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_query_and_pattern_validation() {
        assert!(matches_query("README.md", "README.md"));
        assert!(matches_query("*.md", "README.md") && matches_query("*.md", "docs/guide.md"));
        assert!(matches_query("bin/*", "bin/run.sh") && !matches_query("bin/*", "README.md"));
        assert!(matches_query("src/**", "src/nested/lib.rs") && matches_query("*", "a/b.bin"));
        assert!(validate_pattern("src/*.rs").is_ok());
        assert!(validate_pattern("../escape").is_err() && validate_pattern(".git/config").is_err());
    }

    #[test]
    fn test_deny_unknown_fields_on_vfs_catalog_entry() {
        let bad = serde_json::json!({"path":"a","unexpected":1});
        assert!(serde_json::from_value::<VfsCatalogEntry>(bad).is_err());
    }
}
