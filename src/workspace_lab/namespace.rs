use super::core::{
    Entry, MAX_BYTES, MAX_MANIFEST, SCHEMA, Store, copy_single_entry, decode_path, display_path,
    encode_path, new_id, no_symlink_components, private_dir, publish, read_regular, relative_path,
    require_directory, sync_tree, text_arg, valid_agent, valid_id, validate_symlink, walk,
    write_new,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    os::unix::{
        ffi::OsStringExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BaseVectorEntry {
    pub mount_path: String,
    pub mount_path_base64: String,
    pub checkpoint_id: String,
    pub workspace_id: String,
    pub agent_id: String,
    pub base_oid: String,
    pub head_oid: String,
    pub manifest_sha256: String,
    pub entries_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceManifest {
    pub schema: u32,
    pub namespace_id: String,
    pub name: String,
    pub namespace_revision: u32,
    pub view_path: String,
    pub mount_count: usize,
    pub total_entries: usize,
    pub state: String,
    pub base_vector: Vec<BaseVectorEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceViewReport {
    pub schema: u32,
    pub namespace_id: String,
    pub name: String,
    pub namespace_revision: u32,
    pub view_path: String,
    pub mount_count: usize,
    pub total_entries: usize,
    pub readonly: bool,
    pub verified: bool,
    pub base_vector: Vec<BaseVectorEntry>,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceGitViewReport {
    pub schema: u32,
    pub namespace_id: String,
    pub name: String,
    pub namespace_revision: u32,
    pub history_strategy: String,
    pub view_repo_path: String,
    pub projected_commit_oid: String,
    pub projected_tree_oid: String,
    pub mount_count: usize,
    pub projected_files: usize,
    pub readonly: bool,
    pub fsck_passed: bool,
    pub base_vector: Vec<BaseVectorEntry>,
    pub state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NamespaceProvenance {
    schema: u32,
    name: String,
    namespace_revision: u32,
    history_strategy: String,
    base_vector: Vec<BaseVectorEntry>,
}

fn parse_and_validate_mount_path(raw: &str) -> Result<PathBuf> {
    let path = relative_path(raw.as_bytes())?;
    let has_git = path
        .components()
        .any(|c| c.as_os_str() == OsStr::new(".git"));
    ensure!(
        !has_git && path != Path::new(".rootyard-namespace.json"),
        "mount path cannot contain .git or reserved metadata name"
    );
    Ok(path)
}

fn validate_non_overlapping_mounts(mounts: &[(PathBuf, String)]) -> Result<()> {
    ensure!(!mounts.is_empty(), "namespace requires at least one mount");
    for i in 0..mounts.len() {
        for j in (i + 1)..mounts.len() {
            let (a, b) = (&mounts[i].0, &mounts[j].0);
            ensure!(
                a != b && !a.starts_with(b) && !b.starts_with(a),
                "overlapping namespace mount paths: {} and {}",
                display_path(a),
                display_path(b)
            );
        }
    }
    Ok(())
}

fn ensure_no_git_anywhere(root: &Path) -> Result<()> {
    require_directory(root)?;
    for child in fs::read_dir(root)? {
        let child = child?;
        ensure!(
            child.file_name() != OsStr::new(".git"),
            ".git metadata forbidden inside virtual namespace tree"
        );
        if fs::symlink_metadata(child.path())?.is_dir() {
            ensure_no_git_anywhere(&child.path())?;
        }
    }
    Ok(())
}

fn copy_worktree_entries(
    cp_repo: &Path,
    entries: &[Entry],
    mount_dest: &Path,
    make_readonly: bool,
) -> Result<usize> {
    if !mount_dest.exists() {
        let mut cur = PathBuf::new();
        for comp in mount_dest.components() {
            cur.push(comp);
            if !cur.exists() {
                private_dir(&cur)?;
            }
        }
    }
    require_directory(mount_dest)?;
    let (mut total, mut count) = (0u64, 0usize);
    for entry in entries {
        let rel = decode_path(&entry.path_base64)?;
        if rel.starts_with(".git") {
            continue;
        }
        copy_single_entry(cp_repo, mount_dest, &rel, &mut total)?;
        if entry.kind == "file" {
            let mode = if make_readonly {
                (entry.mode & 0o555) | 0o400
            } else if entry.mode & 0o111 != 0 {
                0o755
            } else {
                0o644
            };
            fs::set_permissions(mount_dest.join(&rel), fs::Permissions::from_mode(mode))?;
        }
        count += 1;
    }
    Ok(count)
}

fn read_namespace(store: &Store, namespace_id: &str) -> Result<(PathBuf, NamespaceManifest)> {
    valid_id(namespace_id)?;
    let ns_dir = store.root.join("namespaces").join(namespace_id);
    require_directory(&ns_dir)?;
    let bytes = read_regular(&ns_dir.join("namespace.json"), MAX_MANIFEST)?;
    let sha_raw = read_regular(&ns_dir.join("namespace.sha256"), 256)?;
    let expected_sha = String::from_utf8(sha_raw)?.trim().to_owned();
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == expected_sha,
        "namespace manifest checksum mismatch"
    );
    let manifest: NamespaceManifest = serde_json::from_slice(&bytes)?;
    ensure!(
        manifest.schema == SCHEMA
            && manifest.namespace_id == namespace_id
            && manifest.namespace_revision == 1
            && manifest.state == "mounted"
            && !manifest.base_vector.is_empty(),
        "invalid namespace manifest"
    );
    valid_agent(&manifest.name)?;
    let mut pairs = Vec::with_capacity(manifest.base_vector.len());
    for bv in &manifest.base_vector {
        let mp = parse_and_validate_mount_path(&bv.mount_path)?;
        ensure!(
            decode_path(&bv.mount_path_base64)? == mp,
            "mount_path_base64 mismatch"
        );
        valid_id(&bv.checkpoint_id)?;
        pairs.push((mp, bv.checkpoint_id.clone()));
    }
    validate_non_overlapping_mounts(&pairs)?;
    Ok((ns_dir, manifest))
}

fn resolve_view_target(
    store: &Store,
    view_arg: Option<&OsStr>,
    default_path: PathBuf,
    forbid_extra: Option<&Path>,
) -> Result<PathBuf> {
    let Some(arg) = view_arg else {
        return Ok(default_path);
    };
    let req = Path::new(arg);
    let abs = if req.is_absolute() {
        req.to_path_buf()
    } else {
        std::env::current_dir()?.join(req)
    };
    no_symlink_components(&abs)?;
    let cp_root = store.root.join("checkpoints");
    let ws_root = store.root.join("workspaces");
    ensure!(
        !abs.starts_with(&cp_root)
            && !abs.starts_with(&ws_root)
            && forbid_extra.is_none_or(|p| !abs.starts_with(p)),
        "namespace view path must not overlap checkpoints, workspaces, or namespace tree"
    );
    Ok(abs)
}

pub fn cmd_namespace_mount(
    store: &Store,
    name_arg: &OsStr,
    mount_args: &[OsString],
) -> Result<serde_json::Value> {
    let name = text_arg(name_arg)?;
    valid_agent(&name)?;
    ensure!(
        !mount_args.is_empty(),
        "namespace-mount requires at least one mount"
    );

    let mut parsed_mounts: Vec<(PathBuf, String)> = Vec::with_capacity(mount_args.len());
    for raw_arg in mount_args {
        let text = text_arg(raw_arg)?;
        let (m_raw, cp_raw) = text
            .split_once('=')
            .context("mount must be PATH=CHECKPOINT_ID")?;
        let mount_path = parse_and_validate_mount_path(m_raw)?;
        valid_id(cp_raw)?;
        parsed_mounts.push((mount_path, cp_raw.to_owned()));
    }
    parsed_mounts.sort_by(|a, b| a.0.cmp(&b.0));
    validate_non_overlapping_mounts(&parsed_mounts)?;

    let namespace_id = new_id();
    let ns_dir = store.root.join("namespaces").join(&namespace_id);
    let staging = store.stage()?;
    let staging_tree = staging.0.join("tree");
    private_dir(&staging_tree)?;

    let mut base_vector = Vec::with_capacity(parsed_mounts.len());
    let mut total_entries = 0usize;

    for (mount_path, checkpoint_id) in &parsed_mounts {
        let (cp_dir, cp_manifest) = store.read_checkpoint(checkpoint_id)?;
        let cp_repo = cp_dir.join("repo");
        let head_oid = store.git_text(&cp_repo, &["rev-parse", "--verify", "HEAD"])?;
        let sha_raw = read_regular(&cp_dir.join("manifest.sha256"), 256)?;
        let manifest_sha256 = String::from_utf8(sha_raw)?.trim().to_owned();
        let mount_dest = staging_tree.join(mount_path);
        let count = copy_worktree_entries(&cp_repo, &cp_manifest.entries, &mount_dest, true)?;
        total_entries += count;
        base_vector.push(BaseVectorEntry {
            mount_path: display_path(mount_path),
            mount_path_base64: encode_path(mount_path),
            checkpoint_id: checkpoint_id.clone(),
            workspace_id: cp_manifest.workspace.workspace_id,
            agent_id: cp_manifest.workspace.agent_id,
            base_oid: cp_manifest.workspace.base_oid,
            head_oid,
            manifest_sha256,
            entries_count: count,
        });
    }

    let manifest = NamespaceManifest {
        schema: SCHEMA,
        namespace_id: namespace_id.clone(),
        name,
        namespace_revision: 1,
        view_path: ns_dir.join("tree").to_string_lossy().into_owned(),
        mount_count: base_vector.len(),
        total_entries,
        state: "mounted".into(),
        base_vector,
    };
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST,
        "namespace manifest limit exceeded"
    );
    write_new(&staging.0.join("namespace.json"), &bytes, 0o600)?;
    let digest = hex::encode(Sha256::digest(&bytes));
    write_new(
        &staging.0.join("namespace.sha256"),
        digest.as_bytes(),
        0o600,
    )?;
    sync_tree(&staging.0)?;
    publish(&staging.0, &ns_dir)?;

    Ok(serde_json::to_value(manifest)?)
}

pub fn cmd_verify_namespace(
    store: &Store,
    namespace_arg: &OsStr,
    view_arg: Option<&OsStr>,
) -> Result<serde_json::Value> {
    let namespace_id = text_arg(namespace_arg)?;
    let (ns_dir, manifest) = read_namespace(store, &namespace_id)?;
    let view_root = resolve_view_target(store, view_arg, ns_dir.join("tree"), None)?;

    if !view_root.exists() {
        ensure!(
            fs::symlink_metadata(&view_root).is_err(),
            "dangling symlink view path"
        );
        if let Some(parent) = view_root.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
            require_directory(parent)?;
        }
        let staging = store.stage()?;
        let staging_tree = staging.0.join("tree");
        private_dir(&staging_tree)?;
        for bv in &manifest.base_vector {
            let (cp_dir, cp_man) = store.read_checkpoint(&bv.checkpoint_id)?;
            let mount_rel = decode_path(&bv.mount_path_base64)?;
            let dest = staging_tree.join(&mount_rel);
            copy_worktree_entries(&cp_dir.join("repo"), &cp_man.entries, &dest, true)?;
        }
        sync_tree(&staging_tree)?;
        publish(&staging_tree, &view_root)?;
    }

    ensure_no_git_anywhere(&view_root)?;
    let view_files = walk(&view_root)?;

    let mut expected_map: BTreeMap<PathBuf, (PathBuf, PathBuf, PathBuf, Entry)> = BTreeMap::new();
    for bv in &manifest.base_vector {
        let (cp_dir, cp_manifest) = store.read_checkpoint(&bv.checkpoint_id)?;
        let cp_repo = cp_dir.join("repo");
        let sha_raw = read_regular(&cp_dir.join("manifest.sha256"), 256)?;
        let actual_cp_sha = String::from_utf8(sha_raw)?.trim().to_owned();
        let actual_head = store.git_text(&cp_repo, &["rev-parse", "--verify", "HEAD"])?;
        ensure!(
            bv.base_oid == cp_manifest.workspace.base_oid
                && bv.head_oid == actual_head
                && bv.manifest_sha256 == actual_cp_sha,
            "pinned BaseVector metadata mismatch for mount {}",
            bv.mount_path
        );
        let mount_rel = decode_path(&bv.mount_path_base64)?;
        require_directory(&view_root.join(&mount_rel))?;
        let mut mount_entries = 0usize;
        for entry in &cp_manifest.entries {
            let rel = decode_path(&entry.path_base64)?;
            if rel.starts_with(".git") {
                continue;
            }
            mount_entries += 1;
            let full_rel = mount_rel.join(&rel);
            expected_map.insert(
                full_rel,
                (mount_rel.clone(), rel, cp_repo.clone(), entry.clone()),
            );
        }
        ensure!(
            mount_entries == bv.entries_count,
            "BaseVector entry count mismatch"
        );
    }

    for path in view_files.keys() {
        if !expected_map.contains_key(path) {
            bail!("unexpected file in namespace view: {}", display_path(path));
        }
    }
    for path in expected_map.keys() {
        if !view_files.contains_key(path) {
            bail!("missing file in namespace view: {}", display_path(path));
        }
    }

    for (path, meta) in &view_files {
        let (mount_rel, rel_in_mount, cp_repo, expected) = &expected_map[path];
        let full = view_root.join(path);
        let cp_meta = fs::symlink_metadata(cp_repo.join(rel_in_mount))?;
        let dp = display_path(path);

        if meta.file_type().is_symlink() {
            ensure!(
                expected.kind == "symlink",
                "file kind mismatch in namespace view: {dp}"
            );
            let target = fs::read_link(&full)?;
            validate_symlink(&view_root.join(mount_rel), rel_in_mount, &target)?;
            let bytes = target.into_os_string().into_vec();
            let sha = hex::encode(Sha256::digest(&bytes));
            ensure!(
                bytes.len() as u64 == expected.size && sha == expected.sha256,
                "symlink target tampered in namespace view: {dp}"
            );
        } else {
            ensure!(
                meta.is_file() && expected.kind == "file",
                "file kind mismatch in namespace view: {dp}"
            );
            ensure!(
                (meta.dev(), meta.ino()) != (cp_meta.dev(), cp_meta.ino()),
                "namespace view shares hardlink inode with checkpoint: {dp}"
            );
            let mode = meta.permissions().mode();
            ensure!(
                mode & 0o7000 == 0,
                "special permission bits in namespace view: {dp}"
            );
            ensure!(
                mode & 0o222 == 0,
                "writable file detected in namespace view: {dp}"
            );
            ensure!(mode & 0o444 != 0, "unreadable file in namespace view: {dp}");
            ensure!(
                (mode & 0o111) == (expected.mode & 0o111),
                "executable permission bit mismatch in namespace view: {dp}"
            );
            let bytes = read_regular(&full, MAX_BYTES)?;
            let sha = hex::encode(Sha256::digest(&bytes));
            ensure!(
                bytes.len() as u64 == expected.size && sha == expected.sha256,
                "file content tampered in namespace view: {dp}"
            );
        }
    }

    let canonical_view = fs::canonicalize(&view_root)?;
    let report = NamespaceViewReport {
        schema: SCHEMA,
        namespace_id: manifest.namespace_id,
        name: manifest.name,
        namespace_revision: manifest.namespace_revision,
        view_path: canonical_view.to_string_lossy().into_owned(),
        mount_count: manifest.mount_count,
        total_entries: expected_map.len(),
        readonly: true,
        verified: true,
        base_vector: manifest.base_vector,
        state: "verified".into(),
    };
    Ok(serde_json::to_value(report)?)
}

fn run_git_deterministic(store: &Store, repo: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new(&store.git)
        .env_clear()
        .envs([
            ("LC_ALL", "C"),
            ("LANG", "C"),
            ("TZ", "UTC"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_ATTR_NOSYSTEM", "1"),
            ("GIT_OPTIONAL_LOCKS", "0"),
            ("GIT_NO_REPLACE_OBJECTS", "1"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_AUTHOR_NAME", "Rootyard Namespace View"),
            ("GIT_AUTHOR_EMAIL", "namespace@rootyard.invalid"),
            ("GIT_AUTHOR_DATE", "2026-11-03T00:00:00Z"),
            ("GIT_COMMITTER_NAME", "Rootyard Namespace View"),
            ("GIT_COMMITTER_EMAIL", "namespace@rootyard.invalid"),
            ("GIT_COMMITTER_DATE", "2026-11-03T00:00:00Z"),
        ])
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.excludesFile=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "protocol.file.allow=never",
            "--no-replace-objects",
            "-C",
        ])
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    ensure!(
        output.status.success(),
        "git {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(output.stdout)
}

pub fn cmd_namespace_git_view(
    store: &Store,
    namespace_arg: &OsStr,
    view_arg: Option<&OsStr>,
) -> Result<serde_json::Value> {
    cmd_verify_namespace(store, namespace_arg, None)?;
    let namespace_id = text_arg(namespace_arg)?;
    let (ns_dir, manifest) = read_namespace(store, &namespace_id)?;

    let gv_parent = ns_dir.join("git-view");
    if view_arg.is_none() && !gv_parent.exists() {
        private_dir(&gv_parent)?;
    }
    let view_repo = resolve_view_target(
        store,
        view_arg,
        gv_parent.join("repo"),
        Some(&ns_dir.join("tree")),
    )?;

    let staging = store.stage()?;
    let staging_repo = staging.0.join("repo");
    let repo_str = staging_repo
        .to_str()
        .context("staging path must be UTF-8")?;
    run_git_deterministic(store, &staging.0, &["init", "-q", "-b", "main", repo_str])?;
    for (k, v) in [
        ("user.name", "Rootyard Namespace View"),
        ("user.email", "namespace@rootyard.invalid"),
        ("receive.denyCurrentBranch", "refuse"),
        ("http.receivepack", "false"),
    ] {
        run_git_deterministic(store, &staging_repo, &["config", k, v])?;
    }

    let mut projected_files = 0usize;
    for bv in &manifest.base_vector {
        let (cp_dir, cp_manifest) = store.read_checkpoint(&bv.checkpoint_id)?;
        let mount_rel = decode_path(&bv.mount_path_base64)?;
        let dest = staging_repo.join(&mount_rel);
        projected_files +=
            copy_worktree_entries(&cp_dir.join("repo"), &cp_manifest.entries, &dest, false)?;
    }

    let provenance = NamespaceProvenance {
        schema: SCHEMA,
        name: manifest.name.clone(),
        namespace_revision: manifest.namespace_revision,
        history_strategy: "task_snapshot".into(),
        base_vector: manifest.base_vector.clone(),
    };
    let prov_bytes = serde_json::to_vec_pretty(&provenance)?;
    let prov_path = staging_repo.join(".rootyard-namespace.json");
    write_new(&prov_path, &prov_bytes, 0o644)?;
    fs::set_permissions(&prov_path, fs::Permissions::from_mode(0o644))?;
    projected_files += 1;

    run_git_deterministic(store, &staging_repo, &["add", "--all", "--force"])?;
    let msg = format!(
        "rootyard namespace task_snapshot: {} (rev {})",
        manifest.name, manifest.namespace_revision
    );
    run_git_deterministic(store, &staging_repo, &["commit", "-q", "-m", &msg])?;

    let projected_commit_oid = store.git_text(&staging_repo, &["rev-parse", "--verify", "HEAD"])?;
    let projected_tree_oid =
        store.git_text(&staging_repo, &["rev-parse", "--verify", "HEAD^{tree}"])?;
    store.git(&staging_repo, &["fsck", "--full", "--strict"])?;

    for (rel, meta) in walk(&staging_repo)? {
        if !rel.starts_with(".git") && meta.is_file() {
            let ro_mode = (meta.permissions().mode() & 0o555) | 0o400;
            fs::set_permissions(staging_repo.join(&rel), fs::Permissions::from_mode(ro_mode))?;
        }
    }

    if let Some(parent) = view_repo.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
        require_directory(parent)?;
    }
    if view_repo.exists() {
        store.replace_dir_atomic(&staging_repo, &view_repo)?;
    } else {
        sync_tree(&staging_repo)?;
        publish(&staging_repo, &view_repo)?;
    }

    let canonical_repo = fs::canonicalize(&view_repo)?;
    let report = NamespaceGitViewReport {
        schema: SCHEMA,
        namespace_id: manifest.namespace_id,
        name: manifest.name,
        namespace_revision: manifest.namespace_revision,
        history_strategy: "task_snapshot".into(),
        view_repo_path: canonical_repo.to_string_lossy().into_owned(),
        projected_commit_oid,
        projected_tree_oid,
        mount_count: manifest.mount_count,
        projected_files,
        readonly: true,
        fsck_passed: true,
        base_vector: manifest.base_vector,
        state: "projected".into(),
    };
    Ok(serde_json::to_value(report)?)
}
