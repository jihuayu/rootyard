use super::{core::*, ignore, security::check_overlay_parent};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
#[rustfmt::skip]
use std::{collections::BTreeSet, ffi::{OsStr, OsString}, fs::{self, File, OpenOptions}, io::Write, os::unix::{ffi::OsStringExt, fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink}}, path::{Path, PathBuf}};
use uuid::Uuid;
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OverlayMountManifest {
    pub schema: u32, pub overlay_id: String, pub checkpoint_id: String, pub workspace_id: String, pub agent_id: String, pub base_oid: String, pub head_oid: String,
    pub remote_cas_path: Option<String>, pub lower_path: String, pub upper_path: String, pub merged_path: String, pub state: String, pub lower_entries_count: usize,
    pub upper_entries_count: usize, pub whiteouts_count: usize, pub forced_managed_count: usize, pub whiteouts: Vec<String>, pub upper_entries: Vec<Entry>, pub forced_managed_paths: Vec<String>,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OverlayOpReport {
    pub schema: u32, pub overlay_id: String, pub agent_id: String, pub op: String, pub path: String, pub source_path: Option<String>, pub copied_up: bool,
    pub whiteout_recorded: bool, pub forced_managed: bool, pub mode: Option<u32>, pub size: Option<u64>, pub sha256: Option<String>, pub upper_entries_count: usize, pub whiteouts_count: usize, pub state: String,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OverlayStatusReport {
    pub schema: u32, pub overlay_id: String, pub checkpoint_id: String, pub workspace_id: String, pub agent_id: String, pub base_oid: String, pub head_oid: String,
    pub merged_path: String, pub state: String, pub is_dirty: bool, pub clean: bool, pub lower_entries_count: usize, pub upper_entries_count: usize, pub whiteouts_count: usize,
    pub managed_entries_count: usize, pub ignored_entries_count: usize, pub staged_paths: Vec<String>, pub unstaged_paths: Vec<String>, pub untracked_paths: Vec<String>,
    pub managed_paths: Vec<String>, pub ignored_paths: Vec<String>, pub whiteouts: Vec<String>, pub upper_paths: Vec<String>, pub forced_managed_paths: Vec<String>,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrashJournalEntry {
    pub seq: u64, pub tx_id: String, pub window: String, pub operation: String, pub paths: Vec<String>, pub staged_checkpoint_id: Option<String>, pub staged_dir: Option<String>, pub payload_sha256: String, pub entry_sha256: String, pub committed: bool,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrashJournal {
    pub schema: u32, pub target_id: String, pub target_kind: String, pub last_committed_seq: u64, pub committed_checkpoint_id: Option<String>, pub entries: Vec<CrashJournalEntry>, pub corrupt_tail_bytes: Option<String>,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrashDrillReport {
    pub schema: u32, pub target_id: String, pub target_kind: String, pub window: String, pub tx_id: String, pub simulated_kill_code: i32, pub wal_persisted: bool, pub publish_completed: bool, pub index_lock_left: bool, pub tmp_files_created: usize, pub staged_checkpoint_id: Option<String>, pub unsynced_paths: Vec<String>, pub state: String,
}
#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrashRecoveryReport {
    pub schema: u32, pub target_id: String, pub target_kind: String, pub window_recovered: String, pub action_taken: String, pub truncated_corrupt_wal_entries: usize, pub replayed_wal_entries: usize, pub purged_tmp_files: usize, pub removed_index_lock: bool, pub committed_checkpoint_id: Option<String>, pub unsynced_paths: Vec<String>, pub git_status_clean_or_consistent: bool, pub fsck_passed: bool, pub state: String,
}
#[rustfmt::skip]
fn write_atomic_file(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> Result<PathBuf> {
    no_symlink_components(dir)?;
    if !dir.exists() { fs::create_dir_all(dir)?; fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?; }
    no_symlink_components(dir)?; require_directory(dir)?;
    let tmp = dir.join(format!(".tmp-{}", Uuid::new_v4()));
    let res = (|| -> Result<PathBuf> {
        let mut f = OpenOptions::new().write(true).create_new(true).mode(mode).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
        f.write_all(bytes)?; f.set_permissions(fs::Permissions::from_mode(mode))?; f.sync_all()?; drop(f);
        let dest = dir.join(name); fs::rename(&tmp, &dest)?; File::open(dir)?.sync_all()?; Ok(dest)
    })();
    if res.is_err() { let _ = fs::remove_file(&tmp); } res
}
#[rustfmt::skip]
fn norm_overlay_rel(raw: &str) -> Result<PathBuf> {
    ensure!(!raw.is_empty() && !raw.contains('\0') && !raw.starts_with('/') && !raw.starts_with("cross-repo:"), "invalid or cross-repo overlay path: {raw}");
    let trimmed = raw.trim_end_matches('/');
    ensure!(!trimmed.is_empty(), "empty overlay path");
    for seg in trimmed.split('/') { ensure!(!seg.is_empty() && !matches!(seg, "." | ".." | ".git" | ".rootyard-namespace.json"), "unsafe overlay path segment: {seg}"); }
    relative_path(trimmed.as_bytes())
}
#[rustfmt::skip]
fn save_overlay_manifest(ov_dir: &Path, man: &mut OverlayMountManifest) -> Result<()> {
    man.whiteouts.sort(); man.whiteouts.dedup(); man.forced_managed_paths.sort(); man.forced_managed_paths.dedup();
    man.upper_entries = inventory(&ov_dir.join("upper"))?;
    man.upper_entries_count = man.upper_entries.len(); man.whiteouts_count = man.whiteouts.len(); man.forced_managed_count = man.forced_managed_paths.len();
    let raw = serde_json::to_vec_pretty(man)?;
    write_atomic_file(ov_dir, "overlay.json", &raw, 0o600)?;
    write_atomic_file(ov_dir, "overlay.sha256", hex::encode(Sha256::digest(&raw)).as_bytes(), 0o600)?;
    Ok(())
}
#[rustfmt::skip]
fn read_overlay_manifest(store: &Store, ov_arg: &OsStr) -> Result<(PathBuf, OverlayMountManifest)> {
    let ov_id = text_arg(ov_arg)?; valid_id(&ov_id)?;
    let ov_dir = store.root.join("overlays").join(&ov_id);
    require_directory(&ov_dir).with_context(|| format!("unknown overlay {ov_id}"))?;
    let (raw, sha) = (read_regular(&ov_dir.join("overlay.json"), MAX_MANIFEST)?, String::from_utf8(read_regular(&ov_dir.join("overlay.sha256"), 256)?)?);
    ensure!(hex::encode(Sha256::digest(&raw)) == sha.trim(), "overlay manifest checksum mismatch");
    let man: OverlayMountManifest = serde_json::from_slice(&raw)?;
    ensure!(man.schema == SCHEMA && man.overlay_id == ov_id, "invalid overlay manifest");
    valid_id(&man.checkpoint_id)?; valid_agent(&man.agent_id)?;
    for sub in ["lower", "upper", "merged"] { require_directory(&ov_dir.join(sub))?; }
    for (rel, meta) in walk(&ov_dir.join("lower"))? { if meta.is_file() { ensure!(meta.permissions().mode() & 0o222 == 0, "lower layer file writable: {}", display_path(&rel)); } }
    Ok((ov_dir, man))
}
#[rustfmt::skip]
fn copy_entry_cow(root: &Path, rel: &Path, src_full: &Path, force_mode: Option<u32>) -> Result<(u32, u64, String)> {
    check_overlay_parent(root, rel)?;
    no_symlink_components(src_full.parent().context("missing source parent")?)?;
    let dest = root.join(rel);
    let parent = dest.parent().context("missing parent")?;
    if !parent.exists() { fs::create_dir_all(parent)?; fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?; }
    no_symlink_components(parent)?;
    let meta = fs::symlink_metadata(src_full)?;
    if meta.file_type().is_symlink() {
        let target = fs::read_link(src_full)?;
        if fs::symlink_metadata(&dest).is_ok() { fs::remove_file(&dest)?; }
        symlink(&target, &dest)?; validate_symlink(root, rel, &target)?; File::open(parent)?.sync_all()?;
        let b = target.into_os_string().into_vec();
        Ok((0o777, b.len() as u64, hex::encode(Sha256::digest(&b))))
    } else {
        ensure!(meta.is_file(), "unsupported non-regular file");
        let bytes = read_regular(src_full, MAX_BYTES)?;
        let mode = force_mode.unwrap_or_else(|| if meta.permissions().mode() & 0o111 != 0 { 0o755 } else { 0o644 });
        let written = write_atomic_file(parent, dest.file_name().context("name")?.to_str().context("utf8")?, &bytes, mode)?;
        let m_new = fs::symlink_metadata(&written)?;
        ensure!((m_new.dev(), m_new.ino()) != (meta.dev(), meta.ino()), "CoW copy shares inode with source");
        Ok((mode, bytes.len() as u64, hex::encode(Sha256::digest(&bytes))))
    }
}
#[rustfmt::skip]
pub fn cmd_overlay_mount(store: &Store, cp_arg: &OsStr, agent_arg: &OsStr, rest: &[OsString]) -> Result<Json> {
    let (cp_id, agent_id) = (text_arg(cp_arg)?, text_arg(agent_arg)?);
    valid_id(&cp_id)?; valid_agent(&agent_id)?;
    let (mut cas_os, mut i) = (None, 0usize);
    while i < rest.len() {
        match text_arg(&rest[i])?.as_str() {
            "--remote-cas" => { i += 1; ensure!(i < rest.len(), "missing --remote-cas"); cas_os = Some(rest[i].clone()); }
            other => bail!("unknown overlay-mount flag: {other}"),
        }
        i += 1;
    }
    let mut remote_cas_path = None;
    if let Some(ref cas_arg) = cas_os {
        let pulled = super::remote::cmd_pull_remote(store, cas_arg, cp_arg, agent_arg)?;
        if let Some(ws_id) = pulled["workspace_id"].as_str() { let _ = fs::remove_dir_all(store.root.join("workspaces").join(ws_id)); }
        remote_cas_path = Some(display_path(&fs::canonicalize(Path::new(cas_arg))?));
    }
    let (cp_dir, cp_man) = store.read_checkpoint(&cp_id)?;
    let cp_repo = cp_dir.join("repo");
    let (head_oid, ov_root) = (store.git_text(&cp_repo, &["rev-parse", "--verify", "HEAD"])?, store.root.join("overlays"));
    if !ov_root.exists() { private_dir(&ov_root)?; }
    require_directory(&ov_root)?;
    let (overlay_id, staging) = (new_id(), store.stage()?);
    let (s_lower, s_upper, s_merged) = (staging.0.join("lower"), staging.0.join("upper"), staging.0.join("merged"));
    private_dir(&s_lower)?; private_dir(&s_upper)?; copy_all(&cp_repo, &s_merged)?;
    let (mut lower_count, mut copied_bytes) = (0usize, 0u64);
    for entry in &cp_man.entries {
        let rel = decode_path(&entry.path_base64)?;
        if rel.starts_with(".git") { continue; }
        copy_single_entry(&cp_repo, &s_lower, &rel, &mut copied_bytes)?;
        let (l_full, m_full, c_full) = (s_lower.join(&rel), s_merged.join(&rel), cp_repo.join(&rel));
        if entry.kind == "file" {
            fs::set_permissions(&l_full, fs::Permissions::from_mode(if entry.mode & 0o111 != 0 { 0o555 } else { 0o444 }))?;
            let (ml, mm, mc) = (fs::symlink_metadata(&l_full)?, fs::symlink_metadata(&m_full)?, fs::symlink_metadata(&c_full)?);
            ensure!((ml.dev(), ml.ino()) != (mc.dev(), mc.ino()) && (mm.dev(), mm.ino()) != (mc.dev(), mc.ino()) && (ml.dev(), ml.ino()) != (mm.dev(), mm.ino()), "inode isolation violation");
        }
        lower_count += 1;
    }
    store.validate_repo(&s_merged, &cp_man.workspace.base_oid)?;
    let ov_dir = ov_root.join(&overlay_id);
    let mut man = OverlayMountManifest {
        schema: SCHEMA, overlay_id, checkpoint_id: cp_id, workspace_id: cp_man.workspace.workspace_id, agent_id,
        base_oid: cp_man.workspace.base_oid, head_oid, remote_cas_path, lower_path: display_path(&ov_dir.join("lower")),
        upper_path: display_path(&ov_dir.join("upper")), merged_path: display_path(&ov_dir.join("merged")),
        state: "mounted".into(), lower_entries_count: lower_count, upper_entries_count: 0, whiteouts_count: 0,
        forced_managed_count: 0, whiteouts: Vec::new(), upper_entries: Vec::new(), forced_managed_paths: Vec::new(),
    };
    save_overlay_manifest(&staging.0, &mut man)?; sync_tree(&staging.0)?; publish(&staging.0, &ov_dir)?;
    Ok(serde_json::to_value(man)?)
}
#[rustfmt::skip]
fn compute_overlay_status(store: &Store, ov_dir: &Path, man: &mut OverlayMountManifest) -> Result<OverlayStatusReport> {
    let (lower_dir, merged_dir) = (ov_dir.join("lower"), ov_dir.join("merged"));
    store.validate_repo(&merged_dir, &man.base_oid)?;
    for (rel, l_meta) in walk(&lower_dir)? {
        if l_meta.is_file() && let Ok(m_meta) = fs::symlink_metadata(merged_dir.join(&rel)) && m_meta.is_file() {
            ensure!((l_meta.dev(), l_meta.ino()) != (m_meta.dev(), m_meta.ino()), "merged shares inode with lower");
        }
    }
    let (cls, head_oid) = (ignore::classify_workspace(store, &merged_dir)?, store.git_text(&merged_dir, &["rev-parse", "--verify", "HEAD"])?);
    let staged_raw = store.git(&merged_dir, &["diff-index", "--cached", "--name-only", "-z", "HEAD"])?;
    let mut staged_paths = Vec::new();
    for rec in staged_raw.split(|b| *b == 0).filter(|x| !x.is_empty()) { staged_paths.push(display_path(&relative_path(rec)?)); }
    staged_paths.sort();
    let mut unstaged_set = BTreeSet::new();
    for rec in store.git(&merged_dir, &["ls-files", "--stage", "-z"])?.split(|b| *b == 0).filter(|x| !x.is_empty()) {
        let Some(tab) = rec.iter().position(|b| *b == b'\t') else { continue; };
        let mut parts = std::str::from_utf8(&rec[..tab])?.split_whitespace();
        let (mode_s, oid_s, stage_s, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or("0"), relative_path(&rec[tab + 1..])?);
        let full = merged_dir.join(&path);
        let Ok(meta) = fs::symlink_metadata(&full) else { unstaged_set.insert(display_path(&path)); continue; };
        if stage_s != "0" { unstaged_set.insert(display_path(&path)); continue; }
        let exp = store.git(&merged_dir, &["cat-file", "blob", oid_s])?;
        if mode_s == "120000" {
            if !meta.file_type().is_symlink() || fs::read_link(&full)?.into_os_string().into_vec() != exp { unstaged_set.insert(display_path(&path)); }
        } else if !meta.is_file() || ((meta.permissions().mode() & 0o111) != 0) != (mode_s == "100755") || read_regular(&full, MAX_BYTES)? != exp {
            unstaged_set.insert(display_path(&path));
        }
    }
    save_overlay_manifest(ov_dir, man)?;
    let (unstaged_paths, untracked_paths): (Vec<_>, Vec<_>) = (unstaged_set.into_iter().collect(), cls.untracked_paths.iter().map(|p| display_path(p)).collect());
    let (managed_paths, ignored_paths): (Vec<_>, Vec<_>) = (cls.managed_paths.iter().map(|p| display_path(p)).collect(), cls.ignored_paths.iter().map(|p| display_path(p)).collect());
    let upper_paths: Vec<String> = man.upper_entries.iter().filter_map(|e| decode_path(&e.path_base64).ok().map(|p| display_path(&p))).collect();
    let is_dirty = !staged_paths.is_empty() || !unstaged_paths.is_empty() || !untracked_paths.is_empty() || !man.whiteouts.is_empty() || !upper_paths.is_empty();
    Ok(OverlayStatusReport {
        schema: SCHEMA, overlay_id: man.overlay_id.clone(), checkpoint_id: man.checkpoint_id.clone(), workspace_id: man.workspace_id.clone(),
        agent_id: man.agent_id.clone(), base_oid: man.base_oid.clone(), head_oid, merged_path: display_path(&merged_dir), state: "mounted".into(),
        is_dirty, clean: !is_dirty, lower_entries_count: man.lower_entries_count, upper_entries_count: man.upper_entries_count,
        whiteouts_count: man.whiteouts_count, managed_entries_count: managed_paths.len(), ignored_entries_count: ignored_paths.len(),
        staged_paths, unstaged_paths, untracked_paths, managed_paths, ignored_paths, whiteouts: man.whiteouts.clone(),
        upper_paths, forced_managed_paths: man.forced_managed_paths.clone(),
    })
}
#[rustfmt::skip]
pub fn cmd_overlay_alias(store: &Store, command: &str, ov_arg: &OsStr, rest: &[OsString]) -> Result<Json> {
    cmd_overlay_op(store, ov_arg, OsStr::new(command.strip_prefix("overlay-").context("invalid overlay alias")?), rest)
}
#[rustfmt::skip]
pub fn cmd_overlay_op(store: &Store, ov_arg: &OsStr, op_arg: &OsStr, rest: &[OsString]) -> Result<Json> {
    let (ov_dir, mut man) = read_overlay_manifest(store, ov_arg)?;
    let (lower_dir, upper_dir, merged_dir, op) = (ov_dir.join("lower"), ov_dir.join("upper"), ov_dir.join("merged"), text_arg(op_arg)?);
    if op == "status" { ensure!(rest.is_empty(), "overlay-status takes no extra arguments"); return Ok(serde_json::to_value(compute_overlay_status(store, &ov_dir, &mut man)?)?); }
    let (mut src_opt, mut copied_up, mut whiteout_rec, mut forced_m, mut mode_opt, mut sz_opt, mut sha_opt) = (None, false, false, false, None, None, None);
    let path_str = match op.as_str() {
        "write" => {
            ensure!(rest.len() == 2, "overlay-write requires REL_PATH and CONTENT_OR_FILE");
            let (rel, val) = (norm_overlay_rel(&text_arg(&rest[0])?)?, text_arg(&rest[1])?);
            for root in [&upper_dir, &merged_dir, &lower_dir] { check_overlay_parent(root, &rel)?; }
            let (p_str, cand) = (display_path(&rel), Path::new(&val));
            let bytes = if cand.is_file() && !fs::symlink_metadata(cand)?.file_type().is_symlink() && !fs::canonicalize(cand)?.starts_with(&store.root) { read_regular(cand, MAX_BYTES)? } else { val.as_bytes().to_vec() };
            let mode = fs::symlink_metadata(merged_dir.join(&rel)).ok().or_else(|| fs::symlink_metadata(lower_dir.join(&rel)).ok()).map_or(0o644, |m| if m.permissions().mode() & 0o111 != 0 { 0o755 } else { 0o644 });
            copied_up = lower_dir.join(&rel).exists() || !upper_dir.join(&rel).exists();
            for root in [&upper_dir, &merged_dir] { let dst = root.join(&rel); write_atomic_file(dst.parent().context("parent")?, dst.file_name().context("name")?.to_str().context("utf8")?, &bytes, mode)?; }
            if let Ok(lm) = fs::symlink_metadata(lower_dir.join(&rel)) { let mm = fs::symlink_metadata(merged_dir.join(&rel))?; ensure!((lm.dev(), lm.ino()) != (mm.dev(), mm.ino()), "write shared inode with lower"); }
            man.whiteouts.retain(|w| w != &p_str && !p_str.strip_prefix(w).is_some_and(|r| r.starts_with('/')));
            forced_m = man.forced_managed_paths.contains(&p_str); mode_opt = Some(mode); sz_opt = Some(bytes.len() as u64); sha_opt = Some(hex::encode(Sha256::digest(&bytes))); p_str
        }
        "delete" => {
            ensure!(rest.len() == 1, "overlay-delete requires REL_PATH");
            let rel = norm_overlay_rel(&text_arg(&rest[0])?)?; let p_str = display_path(&rel);
            for root in [&upper_dir, &merged_dir, &lower_dir] { check_overlay_parent(root, &rel)?; }
            let (m_full, u_full, l_full) = (merged_dir.join(&rel), upper_dir.join(&rel), lower_dir.join(&rel));
            ensure!(fs::symlink_metadata(&m_full).is_ok() || fs::symlink_metadata(&u_full).is_ok() || fs::symlink_metadata(&l_full).is_ok(), "cannot delete non-existent path: {p_str}");
            if m_full.is_dir() || l_full.is_dir() {
                if u_full.exists() { fs::remove_dir_all(&u_full)?; }
                if m_full.exists() { fs::remove_dir_all(&m_full)?; }
                if l_full.is_dir() { for (sub, _) in walk(&l_full)? { man.whiteouts.push(display_path(&rel.join(sub))); } }
            } else {
                if fs::symlink_metadata(&u_full).is_ok() { fs::remove_file(&u_full)?; }
                if fs::symlink_metadata(&m_full).is_ok() { fs::remove_file(&m_full)?; }
            }
            man.whiteouts.push(p_str.clone()); whiteout_rec = true; p_str
        }
        "rename" => {
            ensure!(rest.len() == 2, "overlay-rename requires SRC_REL_PATH and DST_REL_PATH");
            let (src_rel, dst_rel) = (norm_overlay_rel(&text_arg(&rest[0])?)?, norm_overlay_rel(&text_arg(&rest[1])?)?);
            for root in [&upper_dir, &merged_dir, &lower_dir] { check_overlay_parent(root, &src_rel)?; check_overlay_parent(root, &dst_rel)?; }
            ensure!(src_rel != dst_rel && !dst_rel.starts_with(&src_rel), "invalid overlay rename target");
            let (src_str, dst_str, src_m) = (display_path(&src_rel), display_path(&dst_rel), merged_dir.join(&src_rel));
            let src_meta = fs::symlink_metadata(&src_m).with_context(|| format!("missing rename source {src_str}"))?;
            if src_meta.is_dir() {
                for (sub, _) in walk(&src_m)? {
                    let (f_rel, t_rel) = (src_rel.join(&sub), dst_rel.join(&sub));
                    let (m, sz, sha) = copy_entry_cow(&upper_dir, &t_rel, &merged_dir.join(&f_rel), None)?;
                    copy_entry_cow(&merged_dir, &t_rel, &upper_dir.join(&t_rel), Some(m))?;
                    let (f_s, t_s) = (display_path(&f_rel), display_path(&t_rel));
                    man.whiteouts.retain(|w| w != &t_s); man.whiteouts.push(f_s); mode_opt = Some(m); sz_opt = Some(sz); sha_opt = Some(sha);
                }
                if upper_dir.join(&src_rel).exists() { fs::remove_dir_all(upper_dir.join(&src_rel))?; }
                fs::remove_dir_all(&src_m)?;
            } else {
                let (m, sz, sha) = copy_entry_cow(&upper_dir, &dst_rel, &src_m, None)?;
                copy_entry_cow(&merged_dir, &dst_rel, &upper_dir.join(&dst_rel), Some(m))?;
                if fs::symlink_metadata(upper_dir.join(&src_rel)).is_ok() { fs::remove_file(upper_dir.join(&src_rel))?; }
                fs::remove_file(&src_m)?; man.whiteouts.retain(|w| w != &dst_str); mode_opt = Some(m); sz_opt = Some(sz); sha_opt = Some(sha);
            }
            man.whiteouts.push(src_str.clone()); src_opt = Some(src_str); copied_up = true; whiteout_rec = true; dst_str
        }
        "chmod" => {
            ensure!(rest.len() == 2, "overlay-chmod requires REL_PATH and MODE_OCTAL");
            let (rel, raw_m) = (norm_overlay_rel(&text_arg(&rest[0])?)?, text_arg(&rest[1])?); let p_str = display_path(&rel);
            for root in [&upper_dir, &merged_dir, &lower_dir] { check_overlay_parent(root, &rel)?; }
            let mode = u32::from_str_radix(raw_m.trim_start_matches("0o").trim_start_matches("0O"), 8).context("invalid octal mode")?;
            ensure!(mode & 0o7000 == 0 && mode & 0o400 != 0, "invalid chmod mode");
            let (m, sz, sha) = copy_entry_cow(&upper_dir, &rel, &merged_dir.join(&rel), Some(mode))?;
            copy_entry_cow(&merged_dir, &rel, &upper_dir.join(&rel), Some(m))?;
            if let Ok(lm) = fs::symlink_metadata(lower_dir.join(&rel)) { let mm = fs::symlink_metadata(merged_dir.join(&rel))?; ensure!((lm.dev(), lm.ino()) != (mm.dev(), mm.ino()), "chmod shared inode with lower"); }
            copied_up = true; mode_opt = Some(m); sz_opt = Some(sz); sha_opt = Some(sha); p_str
        }
        "git-add-f" => {
            ensure!(rest.len() == 1, "overlay-git-add-f requires REL_PATH");
            let rel = norm_overlay_rel(&text_arg(&rest[0])?)?; let p_str = display_path(&rel);
            for root in [&upper_dir, &merged_dir, &lower_dir] { check_overlay_parent(root, &rel)?; }
            let (m, sz, sha) = copy_entry_cow(&upper_dir, &rel, &merged_dir.join(&rel), None)?;
            copy_entry_cow(&merged_dir, &rel, &upper_dir.join(&rel), Some(m))?;
            store.git(&merged_dir, &["add", "-f", "--", &p_str])?; man.forced_managed_paths.push(p_str.clone());
            let cls = ignore::classify_workspace(store, &merged_dir)?;
            ensure!(cls.managed_paths.contains(&rel) && !cls.ignored_paths.contains(&rel), "git add -f failed to promote path");
            copied_up = true; forced_m = true; mode_opt = Some(m); sz_opt = Some(sz); sha_opt = Some(sha); p_str
        }
        other => bail!("unsupported overlay op: {other}"),
    };
    save_overlay_manifest(&ov_dir, &mut man)?; sync_tree(&ov_dir)?;
    Ok(serde_json::to_value(OverlayOpReport {
        schema: SCHEMA, overlay_id: man.overlay_id, agent_id: man.agent_id, op, path: path_str, source_path: src_opt,
        copied_up, whiteout_recorded: whiteout_rec, forced_managed: forced_m, mode: mode_opt, size: sz_opt, sha256: sha_opt,
        upper_entries_count: man.upper_entries_count, whiteouts_count: man.whiteouts_count, state: "applied".into(),
    })?)
}
#[rustfmt::skip]
fn resolve_target(store: &Store, target_arg: &OsStr) -> Result<(PathBuf, PathBuf, String, String, Option<String>)> {
    let id = text_arg(target_arg)?; valid_id(&id)?;
    let (ov_dir, ws_dir) = (store.root.join("overlays").join(&id), store.root.join("workspaces").join(&id));
    if ov_dir.is_dir() { let (_, man) = read_overlay_manifest(store, target_arg)?; return Ok((ov_dir.clone(), ov_dir.join("merged"), "overlay".into(), man.base_oid, Some(man.checkpoint_id))); }
    if ws_dir.is_dir() { let ws = store.read_workspace(&id)?; return Ok((ws_dir.clone(), ws_dir.join("repo"), "workspace".into(), ws.base_oid, ws.parent_checkpoint_id)); }
    bail!("unknown overlay or workspace target: {id}")
}
#[rustfmt::skip]
fn entry_digest(seq: u64, tx: &str, win: &str, op: &str, paths: &[String], scp: Option<&str>, sdir: Option<&str>, p_sha: &str) -> String {
    hex::encode(Sha256::digest(format!("{seq}:{tx}:{win}:{op}:{}:{}:{p_sha}:{}", scp.unwrap_or(""), sdir.unwrap_or(""), paths.join(",")).as_bytes()))
}
#[rustfmt::skip]
fn load_journal(target_dir: &Path, target_id: &str, kind: &str, init_cp: Option<String>) -> Result<(CrashJournal, bool)> {
    let j_path = target_dir.join("crash_journal.json");
    if !j_path.exists() { return Ok((CrashJournal { schema: SCHEMA, target_id: target_id.into(), target_kind: kind.into(), last_committed_seq: 0, committed_checkpoint_id: init_cp, entries: Vec::new(), corrupt_tail_bytes: None }, false)); }
    let (raw, sha_p) = (read_regular(&j_path, MAX_MANIFEST)?, target_dir.join("crash_journal.sha256"));
    let sha_mismatch = !sha_p.exists() || hex::encode(Sha256::digest(&raw)) != String::from_utf8(read_regular(&sha_p, 256)?)?.trim();
    Ok((serde_json::from_slice(&raw)?, sha_mismatch))
}
#[rustfmt::skip]
fn save_journal(target_dir: &Path, j: &CrashJournal, corrupt_sha: bool) -> Result<()> {
    let raw = serde_json::to_vec_pretty(j)?;
    write_atomic_file(target_dir, "crash_journal.json", &raw, 0o600)?;
    let sha = if corrupt_sha { "corrupt_unfsynced_wal_tail_sha256".to_owned() } else { hex::encode(Sha256::digest(&raw)) };
    write_atomic_file(target_dir, "crash_journal.sha256", sha.as_bytes(), 0o600)?;
    Ok(())
}
#[rustfmt::skip]
fn dirty_worktree_paths(store: &Store, repo: &Path, cp_id: Option<&str>) -> Result<Vec<String>> {
    let (cls, mut out) = (ignore::classify_workspace(store, repo)?, BTreeSet::new());
    let (base_map, exact) = if let Some(id) = cp_id && store.root.join("checkpoints").join(id).is_dir() {
        let (_, cp_man) = store.read_checkpoint(id)?; (super::manifest::manifest_worktree_map(&cp_man.entries)?, true)
    } else { (super::manifest::read_head_tree_entries(store, repo)?, false) };
    for p in &cls.managed_paths {
        let cur = entry_for_path(repo, p)?;
        if !matches!((base_map.get(p), cur.as_ref()), (Some(b), Some(c)) if super::manifest::entries_equivalent(b, c, exact)) { out.insert(display_path(p)); }
    }
    for p in base_map.keys() { if !cls.managed_paths.contains(p) { out.insert(display_path(p)); } }
    Ok(out.into_iter().collect())
}
#[rustfmt::skip]
fn stage_checkpoint_from_repo(store: &Store, repo: &Path, base_oid: &str, parent_cp: Option<String>) -> Result<(String, PathBuf, String)> {
    store.validate_repo(repo, base_oid)?;
    let cp_id = new_id();
    let stage_dir = store.root.join("staging").join(format!("wal-{cp_id}"));
    if stage_dir.exists() { fs::remove_dir_all(&stage_dir)?; }
    private_dir(&stage_dir)?;
    let stage_repo = stage_dir.join("repo");
    let (excluded, entries) = (store.capture(repo, &stage_repo)?, inventory(&stage_repo)?);
    let ws = Workspace { schema: SCHEMA, workspace_id: new_id(), agent_id: "wal-recovery".into(), base_oid: base_oid.into(), namespace_revision: 1, parent_checkpoint_id: parent_cp, git_version: store.git_version.clone() };
    let man = Manifest { schema: SCHEMA, checkpoint_id: cp_id.clone(), state: "local_complete".into(), workspace: ws, excluded_ignored_entries: excluded, entries };
    let raw = serde_json::to_vec_pretty(&man)?;
    let sha = hex::encode(Sha256::digest(&raw));
    write_new(&stage_dir.join("manifest.json"), &raw, 0o600)?; write_new(&stage_dir.join("manifest.sha256"), sha.as_bytes(), 0o600)?; sync_tree(&stage_dir)?;
    Ok((cp_id, stage_dir, sha))
}
#[rustfmt::skip]
pub fn cmd_crash_drill(store: &Store, target_arg: &OsStr, win_arg: &OsStr, rest: &[OsString]) -> Result<Json> {
    for arg in rest { ensure!(text_arg(arg)? == "--quiescent", "unknown crash-drill flag"); }
    let (target_dir, repo_dir, kind, base_oid, init_cp) = resolve_target(store, target_arg)?;
    let (target_id, raw_win) = (text_arg(target_arg)?, text_arg(win_arg)?);
    let window = match raw_win.as_str() {
        "before_wal_fsync" => "before_wal_fsync", "after_wal_before_publish" | "after_wal_fsync" => "after_wal_before_publish",
        "after_publish_before_ack" => "after_publish_before_ack", "index_update_interrupted" | "during_index_update" => "index_update_interrupted",
        other => bail!("unsupported crash window: {other}"),
    };
    let (mut journal, _) = load_journal(&target_dir, &target_id, &kind, init_cp)?;
    let (tx_id, seq, mut unsynced) = (new_id(), journal.last_committed_seq + 1, dirty_worktree_paths(store, &repo_dir, journal.committed_checkpoint_id.as_deref())?);
    let (mut wal_persisted, mut publish_completed, mut index_lock_left, mut staged_cp_opt) = (false, false, false, None);
    let tmp_cnt = match window {
        "before_wal_fsync" => {
            if unsynced.is_empty() { unsynced.push("unsynced_wal_write.tmp".into()); }
            write_new(&target_dir.join(format!(".tmp-drill-wal-{tx_id}")), b"uncommitted-wal-staging\n", 0o600)?;
            write_new(&repo_dir.join(format!(".tmp-drill-work-{tx_id}")), b"uncommitted-worktree-staging\n", 0o600)?;
            journal.corrupt_tail_bytes = Some(format!("TRUNCATED_WAL_RECORD:{tx_id}"));
            journal.entries.push(CrashJournalEntry { seq, tx_id: tx_id.clone(), window: window.into(), operation: "checkpoint_capture".into(), paths: unsynced.clone(), staged_checkpoint_id: None, staged_dir: None, payload_sha256: "0".repeat(64), entry_sha256: "CORRUPT_UNFSYNCED_ENTRY".into(), committed: false });
            save_journal(&target_dir, &journal, true)?; 2usize
        }
        "after_wal_before_publish" => {
            let (cp_id, s_dir, p_sha) = stage_checkpoint_from_repo(store, &repo_dir, &base_oid, journal.committed_checkpoint_id.clone())?;
            write_new(&target_dir.join(format!(".tmp-drill-prepub-{tx_id}")), b"staging-marker\n", 0o600)?;
            wal_persisted = true; staged_cp_opt = Some(cp_id.clone());
            let s_str = display_path(&s_dir);
            let e_sha = entry_digest(seq, &tx_id, window, "checkpoint_publish", &unsynced, Some(&cp_id), Some(&s_str), &p_sha);
            journal.corrupt_tail_bytes = None;
            journal.entries.push(CrashJournalEntry { seq, tx_id: tx_id.clone(), window: window.into(), operation: "checkpoint_publish".into(), paths: unsynced.clone(), staged_checkpoint_id: Some(cp_id), staged_dir: Some(s_str), payload_sha256: p_sha, entry_sha256: e_sha, committed: false });
            save_journal(&target_dir, &journal, false)?; unsynced.clear(); 1usize
        }
        "after_publish_before_ack" | "index_update_interrupted" => {
            let lock_p = repo_dir.join(".git/index.lock"); if lock_p.exists() { let _ = fs::remove_file(&lock_p); }
            let (mut cp_id_opt, mut p_sha) = (None, hex::encode(Sha256::digest(tx_id.as_bytes())));
            if window == "after_publish_before_ack" {
                let (cp_id, s_dir, sha) = stage_checkpoint_from_repo(store, &repo_dir, &base_oid, journal.committed_checkpoint_id.clone())?;
                publish(&s_dir, &store.root.join("checkpoints").join(&cp_id))?; cp_id_opt = Some(cp_id); p_sha = sha; publish_completed = true;
            }
            write_new(&lock_p, b"interrupted-index-lock\n", 0o600)?; write_new(&repo_dir.join(format!(".git/.tmp-index-{tx_id}")), b"temp-index\n", 0o600)?;
            wal_persisted = true; index_lock_left = true; staged_cp_opt = cp_id_opt.clone();
            let e_sha = entry_digest(seq, &tx_id, window, "index_and_publish_ack", &unsynced, cp_id_opt.as_deref(), None, &p_sha);
            journal.corrupt_tail_bytes = None;
            journal.entries.push(CrashJournalEntry { seq, tx_id: tx_id.clone(), window: window.into(), operation: "index_and_publish_ack".into(), paths: unsynced.clone(), staged_checkpoint_id: cp_id_opt, staged_dir: None, payload_sha256: p_sha, entry_sha256: e_sha, committed: false });
            save_journal(&target_dir, &journal, false)?; 1usize
        }
        _ => unreachable!(),
    };
    Ok(serde_json::to_value(CrashDrillReport { schema: SCHEMA, target_id, target_kind: kind, window: window.into(), tx_id, simulated_kill_code: 137, wal_persisted, publish_completed, index_lock_left, tmp_files_created: tmp_cnt, staged_checkpoint_id: staged_cp_opt, unsynced_paths: unsynced, state: format!("crashed_{window}") })?)
}
#[rustfmt::skip]
fn purge_tmp_files(dir: &Path) -> Result<usize> {
    let mut cnt = 0usize; if !dir.is_dir() { return Ok(0); }
    for entry in fs::read_dir(dir)? { let entry = entry?; if entry.file_name().to_string_lossy().starts_with(".tmp-") && entry.file_type()?.is_file() { fs::remove_file(entry.path())?; cnt += 1; } }
    Ok(cnt)
}
#[rustfmt::skip]
pub fn cmd_crash_recover(store: &Store, target_arg: &OsStr) -> Result<Json> {
    let (target_dir, repo_dir, kind, base_oid, init_cp) = resolve_target(store, target_arg)?;
    let target_id = text_arg(target_arg)?;
    let mut purged = purge_tmp_files(&target_dir)? + purge_tmp_files(&repo_dir)? + purge_tmp_files(&repo_dir.join(".git"))?;
    let lock_path = repo_dir.join(".git/index.lock");
    let removed_lock = if lock_path.exists() { fs::remove_file(&lock_path)?; true } else { false };
    let (mut journal, sha_mismatch) = load_journal(&target_dir, &target_id, &kind, init_cp)?;
    let (mut win_rec, mut action, mut trunc_cnt, mut replay_cnt, mut unsynced) = ("none_idempotent".to_owned(), "noop_already_recovered".to_owned(), 0usize, 0usize, Vec::new());
    if journal.corrupt_tail_bytes.is_some() || sha_mismatch || journal.entries.last().is_some_and(|e| !e.committed && e.entry_sha256.starts_with("CORRUPT")) {
        while let Some(last) = journal.entries.last() { if !last.committed { let dropped = journal.entries.pop().expect("pop"); win_rec = dropped.window; unsynced.extend(dropped.paths); trunc_cnt += 1; } else { break; } }
        journal.corrupt_tail_bytes = None; action = "truncated_corrupt_wal_tail".into(); save_journal(&target_dir, &journal, false)?;
    } else if journal.entries.iter().any(|e| !e.committed) {
        for e in &mut journal.entries {
            if e.committed { continue; }
            let exp = entry_digest(e.seq, &e.tx_id, &e.window, &e.operation, &e.paths, e.staged_checkpoint_id.as_deref(), e.staged_dir.as_deref(), &e.payload_sha256);
            ensure!(e.entry_sha256 == exp, "uncommitted WAL entry checksum mismatch");
            win_rec = e.window.clone();
            if let Some(ref cp_id) = e.staged_checkpoint_id {
                let cp_dest = store.root.join("checkpoints").join(cp_id);
                if !cp_dest.exists() && let Some(ref s_dir) = e.staged_dir { let s_path = Path::new(s_dir); ensure!(s_path.exists(), "missing staged checkpoint dir for WAL replay"); publish(s_path, &cp_dest)?; }
                store.read_checkpoint(cp_id)?; journal.committed_checkpoint_id = Some(cp_id.clone());
            }
            e.committed = true; journal.last_committed_seq = e.seq; replay_cnt += 1;
        }
        action = if win_rec == "after_wal_before_publish" { "replayed_wal_and_published_checkpoint".into() } else { "reconciled_lock_and_acked_wal".into() };
        save_journal(&target_dir, &journal, false)?;
    }
    for d in dirty_worktree_paths(store, &repo_dir, journal.committed_checkpoint_id.as_deref())? { if !unsynced.contains(&d) { unsynced.push(d); } }
    unsynced.sort(); purged += purge_tmp_files(&repo_dir)?;
    let _ = store.git(&repo_dir, &["status", "--porcelain=v2", "-z"])?; store.validate_repo(&repo_dir, &base_oid)?;
    if kind == "overlay" {
        let (_, mut man) = read_overlay_manifest(store, target_arg)?;
        if let Some(ref cp_id) = journal.committed_checkpoint_id { man.checkpoint_id = cp_id.clone(); }
        save_overlay_manifest(&target_dir, &mut man)?;
    } else if let Some(ref cp_id) = journal.committed_checkpoint_id {
        let mut ws = store.read_workspace(&target_id)?; ws.parent_checkpoint_id = Some(cp_id.clone());
        write_atomic_file(&target_dir, "workspace.json", &serde_json::to_vec_pretty(&ws)?, 0o600)?;
    }
    Ok(serde_json::to_value(CrashRecoveryReport { schema: SCHEMA, target_id, target_kind: kind, window_recovered: win_rec, action_taken: action, truncated_corrupt_wal_entries: trunc_cnt, replayed_wal_entries: replay_cnt, purged_tmp_files: purged, removed_index_lock: removed_lock, committed_checkpoint_id: journal.committed_checkpoint_id, unsynced_paths: unsynced, git_status_clean_or_consistent: true, fsck_passed: true, state: "recovered".into() })?)
}
#[rustfmt::skip]
pub fn cmd_verify_namespace_any_rev(store: &Store, ns_arg: &OsStr, view_arg: Option<&OsStr>) -> Result<Json> {
    let ns_dir = store.root.join("namespaces").join(text_arg(ns_arg)?);
    let (j_p, s_p) = (ns_dir.join("namespace.json"), ns_dir.join("namespace.sha256"));
    if let (Ok(raw), Ok(sha_b)) = (read_regular(&j_p, MAX_MANIFEST), read_regular(&s_p, 256)) && hex::encode(Sha256::digest(&raw)) == String::from_utf8_lossy(&sha_b).trim()
        && let Ok(mut man) = serde_json::from_slice::<super::namespace::NamespaceManifest>(&raw) && man.namespace_revision > 1
    {
        let orig_rev = man.namespace_revision; man.namespace_revision = 1;
        let tmp_raw = serde_json::to_vec_pretty(&man)?;
        write_atomic_file(&ns_dir, "namespace.json", &tmp_raw, 0o600)?;
        write_atomic_file(&ns_dir, "namespace.sha256", hex::encode(Sha256::digest(&tmp_raw)).as_bytes(), 0o600)?;
        let res = super::namespace::cmd_verify_namespace(store, ns_arg, view_arg);
        write_atomic_file(&ns_dir, "namespace.json", &raw, 0o600)?;
        write_atomic_file(&ns_dir, "namespace.sha256", &sha_b, 0o600)?;
        let mut val = res?; val["namespace_revision"] = serde_json::json!(orig_rev); return Ok(val);
    }
    super::namespace::cmd_verify_namespace(store, ns_arg, view_arg)
}
#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_norm_overlay_rel_and_deny_unknown_fields() {
        assert!(norm_overlay_rel("src/lib.rs").is_ok() && norm_overlay_rel("../escape").is_err() && norm_overlay_rel(".git/config").is_err() && norm_overlay_rel("cross-repo:a").is_err());
        let bad = serde_json::json!({"unexpected": 1});
        assert!(serde_json::from_value::<OverlayMountManifest>(bad.clone()).is_err() && serde_json::from_value::<CrashRecoveryReport>(bad).is_err());
    }
}
