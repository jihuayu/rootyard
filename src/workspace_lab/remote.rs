use super::{
    core::{
        Entry, MAX_BYTES, MAX_MANIFEST, Manifest, SCHEMA, Store, Workspace, decode_path, inventory,
        no_symlink_components, private_dir, publish, read_regular, require_directory, sync_tree,
        text_arg, valid_agent, valid_id, validate_entries, validate_symlink, write_new,
    },
    manifest::{self, ChangesetEntry},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStringExt,
        fs::{OpenOptionsExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteDirtyManifest {
    pub schema: u32,
    pub checkpoint_id: String,
    pub workspace_id: String,
    pub base_oid: String,
    pub head_oid: String,
    pub added: usize,
    pub modified: usize,
    pub deleted: usize,
    pub mode_changed: usize,
    pub type_changed: usize,
    pub excluded_ignored_entries: usize,
    pub entries: Vec<ChangesetEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCheckpointManifest {
    pub schema: u32,
    pub checkpoint_id: String,
    pub state: String,
    pub durability: String,
    pub consistency: String,
    pub workspace: Workspace,
    pub excluded_ignored_entries: usize,
    pub entries: Vec<Entry>,
    pub dirty_entries_count: usize,
    pub dirty_manifest_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemotePushReport {
    pub schema: u32,
    pub checkpoint_id: String,
    pub workspace_id: String,
    pub base_oid: String,
    pub remote_cas_path: String,
    pub state: String,
    pub durability: String,
    pub total_entries: usize,
    pub blobs_uploaded: usize,
    pub blobs_reused: usize,
    pub bytes_uploaded: u64,
    pub dirty_entries_count: usize,
    pub excluded_ignored_entries: usize,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemotePullReport {
    pub schema: u32,
    pub checkpoint_id: String,
    pub workspace_id: String,
    pub agent_id: String,
    pub base_oid: String,
    pub repo_path: String,
    pub state: String,
    pub durability: String,
    pub entries_restored: usize,
    pub blobs_verified: usize,
    pub dirty_entries_count: usize,
}

struct StagingFileGuard {
    path: PathBuf,
    committed: bool,
}

impl StagingFileGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn disarm(&mut self) {
        self.committed = true;
    }
}

impl Drop for StagingFileGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn validate_sha256_hex(digest: &str) -> Result<()> {
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid SHA-256 hex digest"
    );
    Ok(())
}

fn open_remote_cas(store: &Store, cas_arg: &OsStr, create: bool) -> Result<PathBuf> {
    let requested = Path::new(cas_arg);
    let absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()?.join(requested)
    };
    no_symlink_components(&absolute)?;
    if !absolute.exists() {
        ensure!(create, "remote CAS directory does not exist");
        private_dir(&absolute)?;
    }
    require_directory(&absolute)?;
    let cas_root = fs::canonicalize(&absolute)?;
    ensure!(
        fs::metadata(&cas_root)?.permissions().mode() & 0o077 == 0,
        "remote CAS must be private (mode 0700)"
    );
    ensure!(
        !cas_root.starts_with(&store.root) && !store.root.starts_with(&cas_root),
        "remote CAS and store must not overlap"
    );
    for sub in ["blobs", "checkpoints"] {
        let dir = cas_root.join(sub);
        if !dir.exists() {
            ensure!(create, "remote CAS missing {sub} directory");
            private_dir(&dir)?;
        }
        require_directory(&dir)?;
    }
    Ok(cas_root)
}

fn cas_blob_path(cas_root: &Path, sha256: &str) -> Result<PathBuf> {
    validate_sha256_hex(sha256)?;
    Ok(cas_root.join("blobs").join(&sha256[0..2]).join(sha256))
}

fn verify_cas_file(path: &Path, expected_sha256: &str, expected_size: u64) -> Result<()> {
    validate_sha256_hex(expected_sha256)?;
    ensure!(expected_size <= MAX_BYTES, "CAS blob exceeds size limit");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("missing or inaccessible CAS blob {}", path.display()))?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file(),
        "CAS blob is not a regular file: {}",
        path.display()
    );
    ensure!(
        meta.permissions().mode() & 0o7000 == 0,
        "CAS blob has special permission bits: {}",
        path.display()
    );
    ensure!(
        meta.len() == expected_size,
        "CAS blob size mismatch for {}: expected {}, got {}",
        expected_sha256,
        expected_size,
        meta.len()
    );
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(total <= expected_size, "CAS blob grew during verification");
        hasher.update(&buf[..n]);
    }
    ensure!(total == expected_size, "CAS blob short read");
    let actual_sha = hex::encode(hasher.finalize());
    ensure!(
        actual_sha == expected_sha256,
        "CAS blob SHA-256 mismatch for {}: expected {}, got {}",
        path.display(),
        expected_sha256,
        actual_sha
    );
    Ok(())
}

fn write_atomic_file(dir: &Path, filename: &str, bytes: &[u8], mode: u32) -> Result<String> {
    if !dir.exists() {
        private_dir(dir)?;
    }
    require_directory(dir)?;
    let expected_sha = hex::encode(Sha256::digest(bytes));
    let temp_path = dir.join(format!(".tmp-{}", Uuid::new_v4()));
    let mut guard = StagingFileGuard::new(temp_path.clone());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp_path)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    drop(file);
    verify_cas_file(&temp_path, &expected_sha, bytes.len() as u64)?;
    let final_path = dir.join(filename);
    fs::rename(&temp_path, &final_path)?;
    File::open(dir)?.sync_all()?;
    guard.disarm();
    Ok(expected_sha)
}

fn put_cas_blob(
    cas_root: &Path,
    bytes: &[u8],
    expected_sha256: &str,
    expected_size: u64,
) -> Result<bool> {
    validate_sha256_hex(expected_sha256)?;
    ensure!(
        bytes.len() as u64 == expected_size,
        "entry byte size mismatch before CAS upload"
    );
    let actual_sha = hex::encode(Sha256::digest(bytes));
    ensure!(
        actual_sha == expected_sha256,
        "entry SHA-256 mismatch before CAS upload"
    );
    let shard_dir = cas_root.join("blobs").join(&expected_sha256[0..2]);
    if !shard_dir.exists() {
        private_dir(&shard_dir)?;
    }
    require_directory(&shard_dir)?;
    let final_path = shard_dir.join(expected_sha256);
    if final_path.try_exists()? || fs::symlink_metadata(&final_path).is_ok() {
        verify_cas_file(&final_path, expected_sha256, expected_size)?;
        return Ok(false);
    }
    write_atomic_file(&shard_dir, expected_sha256, bytes, 0o600)?;
    verify_cas_file(&final_path, expected_sha256, expected_size)?;
    Ok(true)
}

fn read_verified_cas_blob(
    cas_root: &Path,
    expected_sha256: &str,
    expected_size: u64,
) -> Result<Vec<u8>> {
    let path = cas_blob_path(cas_root, expected_sha256)?;
    verify_cas_file(&path, expected_sha256, expected_size)?;
    let bytes = read_regular(&path, MAX_BYTES)?;
    ensure!(
        bytes.len() as u64 == expected_size
            && hex::encode(Sha256::digest(&bytes)) == expected_sha256,
        "CAS blob verification failed on read-back"
    );
    Ok(bytes)
}

pub fn cmd_push_remote(
    store: &Store,
    target_arg: &OsStr,
    cas_arg: &OsStr,
    quiescent: bool,
) -> Result<serde_json::Value> {
    let id = text_arg(target_arg)?;
    valid_id(&id)?;
    let cas_root = open_remote_cas(store, cas_arg, true)?;

    let checkpoint_id = if store.root.join("checkpoints").join(&id).exists() {
        id
    } else if store.root.join("workspaces").join(&id).exists() {
        ensure!(
            quiescent,
            "stop ALL writers and explicitly pass --quiescent when pushing a live workspace"
        );
        let cp_val = store.cmd_checkpoint(target_arg)?;
        cp_val["checkpoint_id"]
            .as_str()
            .context("missing checkpoint_id from local checkpoint")?
            .to_owned()
    } else {
        bail!("unknown workspace or checkpoint id: {id}");
    };

    let (cp_dir, manifest) = store.read_checkpoint(&checkpoint_id)?;
    let cp_repo = cp_dir.join("repo");
    let head_oid = store.git_text(&cp_repo, &["rev-parse", "--verify", "HEAD"])?;
    let head_map = manifest::read_head_tree_entries(store, &cp_repo)?;
    let worktree_map = manifest::manifest_worktree_map(&manifest.entries)?;
    let (dirty_entries, added, modified, deleted, mode_changed, type_changed) =
        manifest::compute_entries_delta(&head_map, &worktree_map, false);

    let dirty_manifest = RemoteDirtyManifest {
        schema: SCHEMA,
        checkpoint_id: checkpoint_id.clone(),
        workspace_id: manifest.workspace.workspace_id.clone(),
        base_oid: manifest.workspace.base_oid.clone(),
        head_oid,
        added,
        modified,
        deleted,
        mode_changed,
        type_changed,
        excluded_ignored_entries: manifest.excluded_ignored_entries,
        entries: dirty_entries,
    };

    let mut blobs_uploaded = 0usize;
    let mut blobs_reused = 0usize;
    let mut bytes_uploaded = 0u64;

    for entry in &manifest.entries {
        let rel = decode_path(&entry.path_base64)?;
        let full = cp_repo.join(&rel);
        let bytes = if entry.kind == "symlink" {
            let target = fs::read_link(&full)?;
            validate_symlink(&cp_repo, &rel, &target)?;
            target.into_os_string().into_vec()
        } else {
            read_regular(&full, MAX_BYTES)?
        };
        if put_cas_blob(&cas_root, &bytes, &entry.sha256, entry.size)? {
            blobs_uploaded += 1;
            bytes_uploaded = bytes_uploaded
                .checked_add(entry.size)
                .context("bytes_uploaded overflow")?;
        } else {
            blobs_reused += 1;
        }
    }

    let remote_cp_dir = cas_root.join("checkpoints").join(&checkpoint_id);
    if !remote_cp_dir.exists() {
        private_dir(&remote_cp_dir)?;
    }
    require_directory(&remote_cp_dir)?;

    let dirty_bytes = serde_json::to_vec_pretty(&dirty_manifest)?;
    ensure!(
        dirty_bytes.len() as u64 <= MAX_MANIFEST,
        "remote dirty manifest limit exceeded"
    );
    let dirty_sha = write_atomic_file(&remote_cp_dir, "dirty_manifest.json", &dirty_bytes, 0o600)?;
    write_atomic_file(
        &remote_cp_dir,
        "dirty_manifest.sha256",
        dirty_sha.as_bytes(),
        0o600,
    )?;
    let _ = put_cas_blob(
        &cas_root,
        &dirty_bytes,
        &dirty_sha,
        dirty_bytes.len() as u64,
    )?;

    let remote_manifest = RemoteCheckpointManifest {
        schema: SCHEMA,
        checkpoint_id: checkpoint_id.clone(),
        state: "COMMITTED".into(),
        durability: "remote_cas_committed".into(),
        consistency: "caller_quiescent".into(),
        workspace: manifest.workspace.clone(),
        excluded_ignored_entries: manifest.excluded_ignored_entries,
        entries: manifest.entries.clone(),
        dirty_entries_count: dirty_manifest.entries.len(),
        dirty_manifest_sha256: dirty_sha,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&remote_manifest)?;
    ensure!(
        manifest_bytes.len() as u64 <= MAX_MANIFEST,
        "remote checkpoint manifest limit exceeded"
    );
    let manifest_sha256 =
        write_atomic_file(&remote_cp_dir, "manifest.json", &manifest_bytes, 0o600)?;
    write_atomic_file(
        &remote_cp_dir,
        "manifest.sha256",
        manifest_sha256.as_bytes(),
        0o600,
    )?;

    let report = RemotePushReport {
        schema: SCHEMA,
        checkpoint_id,
        workspace_id: manifest.workspace.workspace_id,
        base_oid: manifest.workspace.base_oid,
        remote_cas_path: cas_root.to_string_lossy().into_owned(),
        state: "COMMITTED".into(),
        durability: "remote_cas_committed".into(),
        total_entries: manifest.entries.len(),
        blobs_uploaded,
        blobs_reused,
        bytes_uploaded,
        dirty_entries_count: dirty_manifest.entries.len(),
        excluded_ignored_entries: manifest.excluded_ignored_entries,
        manifest_sha256,
    };
    Ok(serde_json::to_value(report)?)
}

pub fn cmd_pull_remote(
    store: &Store,
    cas_arg: &OsStr,
    checkpoint_arg: &OsStr,
    agent_arg: &OsStr,
) -> Result<serde_json::Value> {
    let checkpoint_id = text_arg(checkpoint_arg)?;
    valid_id(&checkpoint_id)?;
    let agent_id = text_arg(agent_arg)?;
    valid_agent(&agent_id)?;
    let cas_root = open_remote_cas(store, cas_arg, false)?;

    let remote_cp_dir = cas_root.join("checkpoints").join(&checkpoint_id);
    require_directory(&remote_cp_dir)?;
    let manifest_bytes = read_regular(&remote_cp_dir.join("manifest.json"), MAX_MANIFEST)?;
    let manifest_sha_expected =
        String::from_utf8(read_regular(&remote_cp_dir.join("manifest.sha256"), 256)?)?
            .trim()
            .to_owned();
    validate_sha256_hex(&manifest_sha_expected)?;
    let actual_manifest_sha = hex::encode(Sha256::digest(&manifest_bytes));
    ensure!(
        actual_manifest_sha == manifest_sha_expected,
        "remote checkpoint manifest checksum mismatch"
    );

    let remote_manifest: RemoteCheckpointManifest = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        remote_manifest.schema == SCHEMA,
        "unsupported remote checkpoint schema"
    );
    ensure!(
        remote_manifest.checkpoint_id == checkpoint_id,
        "remote checkpoint_id mismatch"
    );
    ensure!(
        remote_manifest.state == "COMMITTED"
            && remote_manifest.durability == "remote_cas_committed",
        "remote checkpoint is not COMMITTED"
    );
    store.validate_workspace(&remote_manifest.workspace)?;
    validate_entries(&remote_manifest.entries)?;

    let dirty_bytes = read_regular(&remote_cp_dir.join("dirty_manifest.json"), MAX_MANIFEST)?;
    let dirty_sha_expected = String::from_utf8(read_regular(
        &remote_cp_dir.join("dirty_manifest.sha256"),
        256,
    )?)?
    .trim()
    .to_owned();
    validate_sha256_hex(&dirty_sha_expected)?;
    let actual_dirty_sha = hex::encode(Sha256::digest(&dirty_bytes));
    ensure!(
        actual_dirty_sha == dirty_sha_expected
            && actual_dirty_sha == remote_manifest.dirty_manifest_sha256,
        "remote dirty manifest checksum mismatch"
    );
    let dirty_manifest: RemoteDirtyManifest = serde_json::from_slice(&dirty_bytes)?;
    ensure!(
        dirty_manifest.schema == SCHEMA
            && dirty_manifest.checkpoint_id == checkpoint_id
            && dirty_manifest.entries.len() == remote_manifest.dirty_entries_count,
        "remote dirty manifest metadata mismatch"
    );

    let mut blobs_verified = 0usize;
    for entry in &remote_manifest.entries {
        let blob_path = cas_blob_path(&cas_root, &entry.sha256)?;
        verify_cas_file(&blob_path, &entry.sha256, entry.size)?;
        blobs_verified += 1;
    }

    let local_cp_dir = store.root.join("checkpoints").join(&checkpoint_id);
    if !local_cp_dir.exists() {
        let staging = store.stage()?;
        let staging_repo = staging.0.join("repo");
        private_dir(&staging_repo)?;
        for req in [".git", ".git/objects", ".git/refs"] {
            let p = staging_repo.join(req);
            if !p.exists() {
                private_dir(&p)?;
            }
        }
        let mut symlinks_to_validate: Vec<(PathBuf, PathBuf)> = Vec::new();
        for entry in &remote_manifest.entries {
            let rel = decode_path(&entry.path_base64)?;
            let mut parent_dir = staging_repo.clone();
            if let Some(parent) = rel.parent() {
                for comp in parent.components() {
                    parent_dir.push(comp);
                    if !parent_dir.exists() {
                        private_dir(&parent_dir)?;
                    }
                    require_directory(&parent_dir)?;
                }
            }
            let bytes = read_verified_cas_blob(&cas_root, &entry.sha256, entry.size)?;
            let full = staging_repo.join(&rel);
            if entry.kind == "symlink" {
                ensure!(!rel.starts_with(".git"), "symlink in .git unsupported");
                let target = PathBuf::from(OsString::from_vec(bytes));
                symlink(&target, &full)?;
                symlinks_to_validate.push((rel, target));
            } else {
                write_new(&full, &bytes, entry.mode & 0o777)?;
                fs::set_permissions(&full, fs::Permissions::from_mode(entry.mode & 0o777))?;
            }
        }
        for (rel, target) in &symlinks_to_validate {
            validate_symlink(&staging_repo, rel, target)?;
        }
        ensure!(
            inventory(&staging_repo)? == remote_manifest.entries,
            "reconstructed checkpoint inventory mismatch"
        );
        store.validate_repo(&staging_repo, &remote_manifest.workspace.base_oid)?;

        let local_manifest = Manifest {
            schema: SCHEMA,
            checkpoint_id: checkpoint_id.clone(),
            state: "local_complete".into(),
            workspace: remote_manifest.workspace.clone(),
            excluded_ignored_entries: remote_manifest.excluded_ignored_entries,
            entries: remote_manifest.entries.clone(),
        };
        let local_bytes = serde_json::to_vec_pretty(&local_manifest)?;
        write_new(&staging.0.join("manifest.json"), &local_bytes, 0o600)?;
        write_new(
            &staging.0.join("manifest.sha256"),
            hex::encode(Sha256::digest(&local_bytes)).as_bytes(),
            0o600,
        )?;
        sync_tree(&staging.0)?;
        publish(&staging.0, &local_cp_dir)?;
    }

    let restored = store.cmd_restore(OsStr::new(&checkpoint_id), OsStr::new(&agent_id))?;
    let workspace_id = restored["workspace_id"]
        .as_str()
        .context("missing restored workspace_id")?
        .to_owned();
    let repo_path = restored["repo_path"]
        .as_str()
        .context("missing restored repo_path")?
        .to_owned();

    let report = RemotePullReport {
        schema: SCHEMA,
        checkpoint_id,
        workspace_id,
        agent_id,
        base_oid: remote_manifest.workspace.base_oid,
        repo_path,
        state: "restored_from_remote".into(),
        durability: "remote_cas_committed".into(),
        entries_restored: remote_manifest.entries.len(),
        blobs_verified,
        dirty_entries_count: remote_manifest.dirty_entries_count,
    };
    Ok(serde_json::to_value(report)?)
}
