use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    MAX_MANIFEST_JSON_BYTES, MerkleSyncError,
    git_state::{git_bytes, validate_git_compat},
    manifest::{
        HeadSnapshot, MerkleChildKind, MerkleDirChild, MerkleObjectFormat, MerkleStateManifest, decode_rel_bytes,
        encode_rel_bytes,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitBundleFile {
    pub rel_path_base64: String,
    pub mode: u32,
    pub content_base64: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitBundleSnapshot {
    pub schema: u32,
    pub object_format: MerkleObjectFormat,
    pub files: Vec<GitBundleFile>,
    pub bundle_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadIndexWorktreeComparison {
    pub head_oid: Option<String>,
    pub head_tree_oid: Option<String>,
    pub staged_paths_b64: Vec<String>,
    pub unstaged_paths_b64: Vec<String>,
    pub partial_staged_paths_b64: Vec<String>,
    pub unmerged_conflict_paths_b64: Vec<String>,
    pub untracked_managed_paths_b64: Vec<String>,
    pub merkle_root_differs_from_git_tree: bool,
}

pub(crate) fn read_regular_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, MerkleSyncError> {
    let mut file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > limit as u64 {
        return Err(MerkleSyncError::UnsupportedGitState("unexpected non-regular or oversized Git file".into()));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    std::io::Read::read_to_end(&mut file, &mut buf)?;
    Ok(buf)
}

pub(crate) fn collect_git_files(
    dot_git: &Path,
    rel: &Path,
    out: &mut Vec<(PathBuf, fs::Metadata)>,
) -> Result<(), MerkleSyncError> {
    for entry in fs::read_dir(dot_git.join(rel))? {
        let entry = entry?;
        let child_rel = rel.join(entry.file_name());
        let meta = fs::symlink_metadata(entry.path())?;
        if meta.file_type().is_symlink() {
            return Err(MerkleSyncError::UnsupportedGitState("symlink inside .git is unsupported".into()));
        }
        if meta.is_dir() {
            collect_git_files(dot_git, &child_rel, out)?;
        } else {
            if !meta.is_file() {
                return Err(MerkleSyncError::UnsupportedGitState("special file inside .git is unsupported".into()));
            }
            if child_rel.as_os_str().as_bytes().ends_with(b".lock") {
                return Err(MerkleSyncError::NotQuiescent("active .git lock file detected".into()));
            }
            out.push((child_rel, meta));
        }
    }
    Ok(())
}

pub(crate) fn build_git_bundle_snapshot(
    repo: &Path,
    fmt: MerkleObjectFormat,
) -> Result<GitBundleSnapshot, MerkleSyncError> {
    let mut dot_git_files = Vec::new();
    collect_git_files(&repo.join(".git"), Path::new(""), &mut dot_git_files)?;
    dot_git_files.sort_by(|a, b| a.0.as_os_str().as_bytes().cmp(b.0.as_os_str().as_bytes()));
    let mut bundle_files = Vec::with_capacity(dot_git_files.len());
    for (rel, meta) in dot_git_files {
        let bytes = read_regular_bounded(&repo.join(".git").join(&rel), MAX_MANIFEST_JSON_BYTES)?;
        bundle_files.push(GitBundleFile {
            rel_path_base64: STANDARD.encode(rel.as_os_str().as_bytes()),
            mode: meta.permissions().mode() & 0o777,
            content_base64: STANDARD.encode(&bytes),
        });
    }
    let body_hash =
        hex::encode(Sha256::digest(serde_json::to_vec(&bundle_files).map_err(|e| MerkleSyncError::Io(e.to_string()))?));
    Ok(GitBundleSnapshot { schema: 1, object_format: fmt, files: bundle_files, bundle_sha256: body_hash })
}

pub fn materialize_git_bundle(target_repo: &Path, bundle: &GitBundleSnapshot) -> Result<(), MerkleSyncError> {
    let raw_files = serde_json::to_vec(&bundle.files).map_err(|e| MerkleSyncError::Io(e.to_string()))?;
    if hex::encode(Sha256::digest(&raw_files)) != bundle.bundle_sha256 {
        return Err(MerkleSyncError::IntegrityMismatch("git bundle checksum mismatch".into()));
    }
    let dot_git = target_repo.join(".git");
    fs::create_dir_all(&dot_git)?;
    for req in ["objects", "refs", "refs/heads", "refs/tags"] {
        fs::create_dir_all(dot_git.join(req))?;
    }
    for file in &bundle.files {
        let rel_raw =
            STANDARD.decode(&file.rel_path_base64).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
        let rel_path = PathBuf::from(OsString::from_vec(rel_raw));
        if rel_path.components().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(MerkleSyncError::InvalidManifest("unsafe .git bundle path".into()));
        }
        let dest = dot_git.join(&rel_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw = STANDARD.decode(&file.content_base64).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
        let mut out = fs::OpenOptions::new().write(true).create_new(true).mode(file.mode & 0o777).open(&dest)?;
        std::io::Write::write_all(&mut out, &raw)?;
        out.sync_all()?;
    }
    Ok(())
}

fn flatten_manifest_worktree(
    manifest: &MerkleStateManifest,
) -> Result<BTreeMap<Vec<u8>, MerkleDirChild>, MerkleSyncError> {
    let mut out = BTreeMap::new();
    for (dir_b64, node) in &manifest.nodes {
        let dir_raw = if dir_b64.is_empty() { Vec::new() } else { decode_rel_bytes(dir_b64)? };
        for ch in &node.children {
            if matches!(ch.kind, MerkleChildKind::File | MerkleChildKind::Symlink) {
                let name =
                    STANDARD.decode(&ch.name_base64).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
                let mut full = dir_raw.clone();
                if !full.is_empty() {
                    full.push(b'/');
                }
                full.extend_from_slice(&name);
                out.insert(full, ch.clone());
            }
        }
    }
    Ok(out)
}

pub fn compare_head_index_worktree(
    repo: &Path,
    manifest: &MerkleStateManifest,
) -> Result<HeadIndexWorktreeComparison, MerkleSyncError> {
    let _ = validate_git_compat(repo)?;
    let (head_oid, head_tree_oid) = match &manifest.git_state.head {
        HeadSnapshot::Attached { commit_oid, tree_oid, .. } | HeadSnapshot::Detached { commit_oid, tree_oid } => {
            (Some(commit_oid.clone()), Some(tree_oid.clone()))
        }
        HeadSnapshot::Unborn { .. } => (None, None),
    };
    let mut head_blobs: BTreeMap<Vec<u8>, (u32, String)> = BTreeMap::new();
    if head_oid.is_some() {
        for rec in
            git_bytes(repo, &["ls-tree", "-rz", "--full-tree", "HEAD"])?.split(|b| *b == 0).filter(|x| !x.is_empty())
        {
            let tab =
                rec.iter().position(|b| *b == b'\t').ok_or_else(|| MerkleSyncError::GitFailed("ls-tree".into()))?;
            let mut parts = std::str::from_utf8(&rec[..tab])
                .map_err(|_| MerkleSyncError::GitFailed("hdr".into()))?
                .split_whitespace();
            let mode = u32::from_str_radix(parts.next().unwrap_or("100644"), 8).unwrap_or(0o100644);
            let _kind = parts.next();
            let oid = parts.next().unwrap_or("");
            let raw = git_bytes(repo, &["cat-file", "blob", oid])?;
            head_blobs.insert(rec[tab + 1..].to_vec(), (mode & 0o777, hex::encode(Sha256::digest(&raw))));
        }
    }
    let worktree_map = flatten_manifest_worktree(manifest)?;
    let mut index_stage0: BTreeMap<Vec<u8>, (u32, String, bool)> = BTreeMap::new();
    let mut unmerged = BTreeSet::new();
    for entry in &manifest.git_state.index_entries {
        let p = decode_rel_bytes(&entry.path_base64)?;
        if entry.stage != 0 {
            unmerged.insert(p);
            continue;
        }
        let sha = if entry.intent_to_add {
            String::new()
        } else {
            let raw = git_bytes(repo, &["cat-file", "blob", &entry.git_oid])?;
            hex::encode(Sha256::digest(&raw))
        };
        index_stage0.insert(p, (entry.mode & 0o777, sha, entry.intent_to_add));
    }
    let mut staged = BTreeSet::new();
    for path in head_blobs.keys().chain(index_stage0.keys()).chain(unmerged.iter()) {
        if unmerged.contains(path)
            || head_blobs.get(path) != index_stage0.get(path).map(|(m, s, _)| (*m, s.clone())).as_ref()
        {
            staged.insert(path.clone());
        }
    }
    let mut unstaged = BTreeSet::new();
    for (path, (idx_mode, idx_sha, ita)) in &index_stage0 {
        if *ita {
            unstaged.insert(path.clone());
            continue;
        }
        match worktree_map.get(path) {
            None => {
                unstaged.insert(path.clone());
            }
            Some(wt) => {
                let wt_exec = (wt.mode & 0o111) != 0;
                let idx_exec = (*idx_mode & 0o111) != 0;
                let wt_is_sym = wt.kind == MerkleChildKind::Symlink;
                let idx_is_sym = *idx_mode == 0o120000 || (*idx_mode & 0o170000) == 0o120000;
                if wt_is_sym != idx_is_sym
                    || (!wt_is_sym && wt_exec != idx_exec)
                    || wt.content_sha256.as_deref() != Some(idx_sha.as_str())
                {
                    unstaged.insert(path.clone());
                }
            }
        }
    }
    for path in &unmerged {
        unstaged.insert(path.clone());
    }
    let partial: BTreeSet<Vec<u8>> = staged.intersection(&unstaged).cloned().collect();
    let untracked: BTreeSet<Vec<u8>> = worktree_map
        .keys()
        .filter(|p| !head_blobs.contains_key(*p) && !index_stage0.contains_key(*p) && !unmerged.contains(*p))
        .cloned()
        .collect();
    let to_b64 = |set: BTreeSet<Vec<u8>>| set.into_iter().map(|p| encode_rel_bytes(&p)).collect::<Vec<_>>();
    let merkle_root_differs_from_git_tree = head_tree_oid.as_deref() != Some(manifest.merkle_root_digest.as_str());
    Ok(HeadIndexWorktreeComparison {
        head_oid,
        head_tree_oid,
        staged_paths_b64: to_b64(staged),
        unstaged_paths_b64: to_b64(unstaged),
        partial_staged_paths_b64: to_b64(partial),
        unmerged_conflict_paths_b64: to_b64(unmerged),
        untracked_managed_paths_b64: to_b64(untracked),
        merkle_root_differs_from_git_tree,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::ffi::OsStringExt,
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;
    use crate::workspace_lab::merkle_sync::{
        git_state::read_git_state_and_bundle,
        manifest::{EmptyDirPolicy, MerkleChangeKind, UntrackedPolicy},
        manifest_verify::diff_manifests,
        scanner::{DirtyScope, MerkleWorkspaceScanner, ScanRequest},
    };

    fn git(repo: &Path, args: &[&str]) -> std::process::Output {
        Command::new("git")
            .args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C"])
            .arg(repo)
            .args(args)
            .envs([
                ("GIT_CONFIG_NOSYSTEM", "1"),
                ("GIT_CONFIG_GLOBAL", "/dev/null"),
                ("GIT_AUTHOR_NAME", "r"),
                ("GIT_AUTHOR_EMAIL", "r@e"),
                ("GIT_COMMITTER_NAME", "r"),
                ("GIT_COMMITTER_EMAIL", "r@e"),
            ])
            .output()
            .expect("run git")
    }

    fn git_ok(repo: &Path, args: &[&str]) {
        let out = git(repo, args);
        assert!(out.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn manifest_sha1_sha256_git_states_ignore_non_utf8_empty_dirs() -> Result<(), Box<dyn std::error::Error>> {
        for fmt in [MerkleObjectFormat::Sha1, MerkleObjectFormat::Sha256] {
            let dir = TempDir::new()?;
            let repo = dir.path().join("repo");
            fs::create_dir_all(&repo)?;
            git_ok(&repo, &["init", &format!("--object-format={}", fmt.as_str()), "--initial-branch=main"]);
            fs::write(repo.join(".gitignore"), "*.log\nignored_dir/\n")?;
            fs::write(repo.join("app.txt"), b"v1\n")?;
            fs::write(repo.join("tool.sh"), b"#!/bin/sh\necho ok\n")?;
            fs::set_permissions(repo.join("tool.sh"), fs::Permissions::from_mode(0o755))?;
            symlink("app.txt", repo.join("link.txt"))?;
            git_ok(&repo, &["add", "--all"]);
            git_ok(&repo, &["commit", "-m", "init"]);

            fs::create_dir_all(repo.join("kept_empty"))?;
            fs::create_dir_all(repo.join("ignored_dir"))?;
            fs::write(repo.join(OsString::from_vec(b"nonutf-\xff\xfe.bin".to_vec())), b"raw\n")?;
            fs::write(repo.join("app.log"), b"ignored\n")?;
            fs::write(repo.join("temp.dat"), b"untracked\n")?;

            let (t, r, h, ws) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
            let scan_with = |pol: EmptyDirPolicy| -> Result<MerkleStateManifest, MerkleSyncError> {
                let (gs, ig, _) =
                    read_git_state_and_bundle(&repo, UntrackedPolicy::IncludeNonIgnored, pol, true, true)?;
                Ok(MerkleWorkspaceScanner::scan(ScanRequest {
                    repo_root: &repo,
                    workspace_id: ws,
                    checkpoint_id: Uuid::new_v4(),
                    tenant_id: t,
                    repo_id: r,
                    history_id: h,
                    parent_checkpoint_id: None,
                    chunk_size_bytes: 16 * 1024,
                    git_state: &gs,
                    ignore: &ig,
                    previous: None,
                    dirty_scope: DirtyScope::FullRescan,
                })?
                .manifest)
            };
            let m1 = scan_with(EmptyDirPolicy::RetainNonIgnoredEmptyDirs)?;
            let m1_ign = scan_with(EmptyDirPolicy::IgnoreEmptyDirs)?;
            assert_ne!(m1.merkle_root_digest, m1_ign.merkle_root_digest);
            assert_ne!(m1.merkle_root_digest, m1.worktree_root_digest);

            fs::write(repo.join("app.txt"), b"staged-v2\n")?;
            git_ok(&repo, &["add", "app.txt"]);
            fs::write(repo.join("app.txt"), b"unstaged-v3\n")?;
            fs::rename(repo.join("temp.dat"), repo.join("renamed.dat"))?;
            fs::set_permissions(repo.join("tool.sh"), fs::Permissions::from_mode(0o644))?;
            fs::write(repo.join(".gitignore"), "*.log\nignored_dir/\n*.dat\n")?;
            let m2 = scan_with(EmptyDirPolicy::RetainNonIgnoredEmptyDirs)?;
            assert_ne!(m2.ignore_policy.ignore_rules_digest, m1.ignore_policy.ignore_rules_digest);
            let cmp = compare_head_index_worktree(&repo, &m2)?;
            assert!(!cmp.partial_staged_paths_b64.is_empty() && cmp.merkle_root_differs_from_git_tree);
            assert!(diff_manifests(&m1, &m2)?.iter().any(|d| d.change == MerkleChangeKind::ModeChanged));

            fs::write(repo.join(".gitignore"), "*.log\nignored_dir/\n")?;
            let m3 = scan_with(EmptyDirPolicy::RetainNonIgnoredEmptyDirs)?;
            assert!(diff_manifests(&m1, &m3)?.iter().any(|d| d.change == MerkleChangeKind::Renamed));

            git_ok(&repo, &["reset", "--hard", "HEAD"]);
            git_ok(&repo, &["checkout", "-b", "side"]);
            fs::write(repo.join("app.txt"), b"side\n")?;
            git_ok(&repo, &["commit", "-am", "side"]);
            git_ok(&repo, &["checkout", "main"]);
            fs::write(repo.join("app.txt"), b"main\n")?;
            git_ok(&repo, &["commit", "-am", "main"]);
            let _ = git(&repo, &["merge", "side"]);
            let m_conf = scan_with(EmptyDirPolicy::IgnoreEmptyDirs)?;
            assert!(!compare_head_index_worktree(&repo, &m_conf)?.unmerged_conflict_paths_b64.is_empty());

            fs::write(repo.join(".git/index.lock"), b"busy")?;
            assert!(matches!(
                read_git_state_and_bundle(
                    &repo,
                    UntrackedPolicy::IncludeNonIgnored,
                    EmptyDirPolicy::IgnoreEmptyDirs,
                    true,
                    true
                ),
                Err(MerkleSyncError::NotQuiescent(_))
            ));
            fs::remove_file(repo.join(".git/index.lock"))?;
            fs::write(repo.join(".gitattributes"), "*.bin filter=custom\n")?;
            assert!(matches!(scan_with(EmptyDirPolicy::IgnoreEmptyDirs), Err(MerkleSyncError::UnsupportedGitState(_))));
        }
        Ok(())
    }

    #[test]
    fn scanner_limits_and_manifest_canonical_verification() -> Result<(), Box<dyn std::error::Error>> {
        use super::super::{
            MAX_TOTAL_CHUNKS, MAX_WORKSPACE_BYTES,
            manifest::{compute_dir_node_sha256, compute_index_merkle_root, compute_state_merkle_root},
            manifest_verify::validate_manifest,
        };
        let dir = TempDir::new()?;
        let repo = dir.path().join("lim");
        fs::create_dir_all(&repo)?;
        git_ok(&repo, &["init", "--initial-branch=main"]);
        for i in 0..5 {
            fs::create_dir_all(repo.join(format!("e{i}")))?;
        }
        let (t, r, h, ws) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let scan_lim = |max_e: usize, pol: EmptyDirPolicy| -> Result<MerkleStateManifest, MerkleSyncError> {
            let (gs, ig, _) = read_git_state_and_bundle(&repo, UntrackedPolicy::IncludeNonIgnored, pol, true, true)?;
            Ok(MerkleWorkspaceScanner::scan_with_limits(
                ScanRequest {
                    repo_root: &repo,
                    workspace_id: ws,
                    checkpoint_id: Uuid::new_v4(),
                    tenant_id: t,
                    repo_id: r,
                    history_id: h,
                    parent_checkpoint_id: None,
                    chunk_size_bytes: 16 * 1024,
                    git_state: &gs,
                    ignore: &ig,
                    previous: None,
                    dirty_scope: DirtyScope::FullRescan,
                },
                max_e,
                MAX_WORKSPACE_BYTES,
                MAX_TOTAL_CHUNKS,
            )?
            .manifest)
        };
        assert!(matches!(scan_lim(4, EmptyDirPolicy::RetainEmptyDirs), Err(MerkleSyncError::InvalidManifest(_))));
        let big = fs::OpenOptions::new().write(true).create_new(true).open(repo.join("huge.bin"))?;
        big.set_len(MAX_WORKSPACE_BYTES + 4096)?;
        drop(big);
        assert!(matches!(scan_lim(100, EmptyDirPolicy::IgnoreEmptyDirs), Err(MerkleSyncError::InvalidManifest(_))));
        fs::remove_file(repo.join("huge.bin"))?;

        fs::create_dir_all(repo.join("sub"))?;
        fs::write(repo.join("a.txt"), b"aa\n")?;
        fs::write(repo.join("sub/b.txt"), b"bb\n")?;
        git_ok(&repo, &["add", "--all"]);
        git_ok(&repo, &["commit", "-m", "m"]);
        let valid = scan_lim(100, EmptyDirPolicy::IgnoreEmptyDirs)?;
        validate_manifest(&valid)?;

        let mut bad_cnt = valid.clone();
        bad_cnt.nodes.get_mut("").unwrap().subtree_file_count += 1;
        assert!(matches!(validate_manifest(&bad_cnt), Err(MerkleSyncError::IntegrityMismatch(_))));

        let rehash = |m: &mut MerkleStateManifest| {
            let root = m.nodes.get_mut("").unwrap();
            root.node_sha256 = compute_dir_node_sha256("", &root.children);
            m.worktree_root_digest = root.node_sha256.clone();
            m.merkle_root_digest =
                compute_state_merkle_root(&m.git_state, &m.ignore_policy, &m.worktree_root_digest, m.chunk_size_bytes);
        };
        let mut bad_child = valid.clone();
        bad_child.nodes.get_mut("").unwrap().children[0].subtree_total_bytes += 1;
        assert!(matches!(validate_manifest(&bad_child), Err(MerkleSyncError::IntegrityMismatch(_))));
        let (mut unsort, mut dup, mut bad_idx) = (valid.clone(), valid.clone(), valid);
        unsort.nodes.get_mut("").unwrap().children.reverse();
        rehash(&mut unsort);
        assert!(matches!(validate_manifest(&unsort), Err(MerkleSyncError::InvalidManifest(_))));

        let first = dup.nodes[""].children[0].clone();
        let root_d = dup.nodes.get_mut("").unwrap();
        root_d.subtree_file_count += first.subtree_file_count;
        root_d.subtree_total_bytes += first.subtree_total_bytes;
        root_d.children.insert(0, first);
        rehash(&mut dup);
        assert!(matches!(validate_manifest(&dup), Err(MerkleSyncError::InvalidManifest(_))));

        bad_idx.git_state.index_entries.reverse();
        bad_idx.git_state.index_merkle_root = compute_index_merkle_root(
            bad_idx.git_state.object_format,
            &bad_idx.git_state.index_entries,
            &bad_idx.git_state.index_raw_sha256,
            None,
            None,
            None,
        );
        rehash(&mut bad_idx);
        assert!(matches!(validate_manifest(&bad_idx), Err(MerkleSyncError::InvalidManifest(_))));
        Ok(())
    }
}
