use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{
        ffi::OsStringExt,
        fs::{OpenOptionsExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    time::Instant,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    MERKLE_CODEC_VERSION, MERKLE_MANIFEST_SCHEMA, MerkleSyncError,
    authz::{AccessContext, HoldPurpose, PinHoldRegistry, ScopedHoldGuard, WorkspaceAuthAction, WorkspaceAuthorizer},
    blob_sync::{StageDirGuard, ensure_private_dir},
    git_compare::{GitBundleSnapshot, materialize_git_bundle},
    git_state::read_git_state_and_bundle,
    ledger::{MerkleBlobCheckpointManifest, MerkleCheckpointLedger},
    manifest::{
        MerkleChildKind, MerkleDirNode, MerkleStateManifest, compute_dir_node_sha256, decode_rel_bytes,
        is_valid_sha256_hex,
    },
    manifest_verify::validate_manifest,
    scan_fs::validate_symlink_safe,
    scanner::{DirtyScope, MerkleWorkspaceScanner, ScanRequest},
};
use crate::blob_store::{
    BlobLocator,
    closure::{BlobClosureEncryption, BlobClosureSpec, ClosureArtifactRole, ClosureEntrySpec},
    opendal::BlobStore,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreReport {
    pub checkpoint_id: Uuid,
    pub new_workspace_id: Uuid,
    pub agent_id: String,
    pub merkle_root_digest: String,
    pub downloaded_bytes: u64,
    pub verified_objects: usize,
    pub restored_files: usize,
    pub restored_symlinks: usize,
    pub restored_empty_dirs: usize,
    pub target_dir: String,
}

pub struct RestoreRequest<'a> {
    pub ctx: &'a AccessContext,
    pub authorizer: &'a dyn WorkspaceAuthorizer,
    pub store: &'a BlobStore,
    pub ledger: &'a MerkleCheckpointLedger,
    pub holds: &'a PinHoldRegistry,
    pub checkpoint_id: Uuid,
    pub target_empty_dir: &'a Path,
    pub new_workspace_id: Uuid,
    pub agent_id: &'a str,
    pub staging_parent: &'a Path,
    pub deadline: Instant,
}

pub async fn restore_or_fork_from_blob(req: RestoreRequest<'_>) -> Result<RestoreReport, MerkleSyncError> {
    req.authorizer.authorize(req.ctx, WorkspaceAuthAction::RestoreFork)?;
    let rec = req.ledger.get_committed(req.ctx, req.checkpoint_id)?;
    if rec.backend_identity_hex != req.store.backend_identity().as_hex() {
        return Err(MerkleSyncError::ForeignBackend);
    }
    let manifest_entry =
        rec.manifest_locator.ok_or_else(|| MerkleSyncError::MissingArtifact("manifest locator absent".into()))?;
    let manifest_loc = manifest_entry.to_locator()?;
    if req.target_empty_dir.exists() && fs::read_dir(req.target_empty_dir)?.next().is_some() {
        return Err(MerkleSyncError::InvalidInput("target restore directory must be empty".into()));
    }
    ensure_private_dir(req.staging_parent)?;
    let stage = req.staging_parent.join(format!("restore-{}", Uuid::new_v4()));
    ensure_private_dir(&stage)?;
    let _stage_guard = StageDirGuard(stage.clone());
    restore_into_stage(&req, &manifest_loc, &stage).await
}

async fn restore_into_stage(
    req: &RestoreRequest<'_>,
    manifest_loc: &BlobLocator,
    stage: &Path,
) -> Result<RestoreReport, MerkleSyncError> {
    let m_path = stage.join("manifest.json");
    req.store.get_to_file(manifest_loc, &m_path, req.deadline).await?;
    let m_bytes = fs::read(&m_path)?;
    let mut downloaded_bytes = m_bytes.len() as u64;
    let remote: MerkleBlobCheckpointManifest =
        serde_json::from_slice(&m_bytes).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
    if remote.schema != MERKLE_MANIFEST_SCHEMA
        || remote.codec_version != MERKLE_CODEC_VERSION
        || remote.checkpoint_id != req.checkpoint_id
        || remote.tenant_id != req.ctx.tenant_id
        || remote.repo_id != req.ctx.repo_id
        || remote.history_id != req.ctx.history_id
        || remote.backend_identity_hex != req.store.backend_identity().as_hex()
    {
        return Err(MerkleSyncError::TenantScopeMismatch("remote checkpoint manifest binding mismatch".into()));
    }
    validate_manifest(&remote.state_manifest)?;

    let mut closure_entries = vec![
        ClosureEntrySpec::provider_managed(ClosureArtifactRole::Manifest, manifest_loc.clone()),
        ClosureEntrySpec::provider_managed(ClosureArtifactRole::Archive, remote.git_bundle_locator.to_locator()?),
    ];
    let mut held_paths = BTreeSet::new();
    held_paths.insert(manifest_loc.path());
    held_paths.insert(remote.git_bundle_locator.to_locator()?.path());
    for entry in remote.chunk_locators.values().chain(remote.node_locators.values()) {
        let loc = entry.to_locator()?;
        held_paths.insert(loc.path());
        closure_entries.push(ClosureEntrySpec::provider_managed(ClosureArtifactRole::Checkpoint, loc));
    }
    let closure_spec = BlobClosureSpec::new(
        req.ctx.tenant_id,
        req.ctx.repo_id,
        manifest_loc.generation(),
        BlobClosureEncryption::ProviderManaged,
        closure_entries,
    )?;
    let proof = req.store.verify_closure(&closure_spec, None, None, req.deadline).await?;
    let verified_objects = proof.artifacts().len();
    let hold = req.holds.acquire_hold(
        HoldPurpose::ActiveRestore,
        req.ctx.tenant_id,
        req.ctx.repo_id,
        req.ctx.history_id,
        req.checkpoint_id,
        held_paths,
    )?;
    let hold_guard = ScopedHoldGuard::new(req.holds, hold);

    let bundle_path = stage.join("git-bundle.json");
    let bundle_loc = remote.git_bundle_locator.to_locator()?;
    req.store.get_to_file(&bundle_loc, &bundle_path, req.deadline).await?;
    let b_raw = fs::read(&bundle_path)?;
    downloaded_bytes += b_raw.len() as u64;
    let git_bundle: GitBundleSnapshot =
        serde_json::from_slice(&b_raw).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;

    let chunk_cache = stage.join("chunks");
    ensure_private_dir(&chunk_cache)?;
    for (sha, entry) in &remote.chunk_locators {
        if !is_valid_sha256_hex(sha) {
            return Err(MerkleSyncError::InvalidManifest("bad chunk sha".into()));
        }
        let loc = entry.to_locator()?;
        let dst = chunk_cache.join(sha);
        req.store.get_to_file(&loc, &dst, req.deadline).await?;
        downloaded_bytes += loc.length();
    }
    for (sha, entry) in &remote.node_locators {
        let loc = entry.to_locator()?;
        let n_path = stage.join(format!("node-{sha}.json"));
        req.store.get_to_file(&loc, &n_path, req.deadline).await?;
        let n_raw = fs::read(&n_path)?;
        downloaded_bytes += n_raw.len() as u64;
        let node: MerkleDirNode =
            serde_json::from_slice(&n_raw).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
        if &node.node_sha256 != sha
            || compute_dir_node_sha256(&node.dir_path_base64, &node.children) != node.node_sha256
        {
            return Err(MerkleSyncError::IntegrityMismatch("downloaded node_sha256 mismatch".into()));
        }
    }

    let repo_dir = stage.join("repo");
    ensure_private_dir(&repo_dir)?;
    materialize_git_bundle(&repo_dir, &git_bundle)?;
    let (mut files, mut symlinks, mut empty_dirs) = (0usize, 0usize, 0usize);
    reconstruct_tree(&remote.state_manifest, &repo_dir, &chunk_cache, &mut files, &mut symlinks, &mut empty_dirs)?;

    let (git_state, ignore, _) = read_git_state_and_bundle(
        &repo_dir,
        remote.state_manifest.ignore_policy.untracked_policy,
        remote.state_manifest.ignore_policy.empty_dir_policy,
        remote.state_manifest.ignore_policy.use_gitignore,
        remote.state_manifest.ignore_policy.use_rootyardignore,
    )?;
    let verified = MerkleWorkspaceScanner::scan(ScanRequest {
        repo_root: &repo_dir,
        workspace_id: req.new_workspace_id,
        checkpoint_id: req.checkpoint_id,
        tenant_id: req.ctx.tenant_id,
        repo_id: req.ctx.repo_id,
        history_id: req.ctx.history_id,
        parent_checkpoint_id: Some(req.checkpoint_id),
        chunk_size_bytes: remote.state_manifest.chunk_size_bytes,
        git_state: &git_state,
        ignore: &ignore,
        previous: None,
        dirty_scope: DirtyScope::FullRescan,
    })?;
    if verified.manifest.merkle_root_digest != remote.merkle_root_digest {
        return Err(MerkleSyncError::IntegrityMismatch("restored tree merkle_root_digest mismatch".into()));
    }
    if req.target_empty_dir.exists() {
        fs::remove_dir(req.target_empty_dir)?;
    } else if let Some(parent) = req.target_empty_dir.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::rename(&repo_dir, req.target_empty_dir)?;
    drop(hold_guard);

    Ok(RestoreReport {
        checkpoint_id: req.checkpoint_id,
        new_workspace_id: req.new_workspace_id,
        agent_id: req.agent_id.to_owned(),
        merkle_root_digest: remote.merkle_root_digest,
        downloaded_bytes,
        verified_objects,
        restored_files: files,
        restored_symlinks: symlinks,
        restored_empty_dirs: empty_dirs,
        target_dir: req.target_empty_dir.to_string_lossy().into_owned(),
    })
}

pub(crate) fn reconstruct_tree(
    manifest: &MerkleStateManifest,
    repo_dir: &Path,
    chunk_cache: &Path,
    files: &mut usize,
    symlinks: &mut usize,
    empty_dirs: &mut usize,
) -> Result<(), MerkleSyncError> {
    let mut dirs_sorted: Vec<_> = manifest.nodes.keys().collect();
    dirs_sorted.sort();
    for dir_b64 in dirs_sorted {
        let node = &manifest.nodes[dir_b64];
        let dir_raw = if dir_b64.is_empty() { Vec::new() } else { decode_rel_bytes(dir_b64)? };
        let dir_path = if dir_raw.is_empty() {
            repo_dir.to_path_buf()
        } else {
            repo_dir.join(OsString::from_vec(dir_raw.clone()))
        };
        fs::create_dir_all(&dir_path)?;
        for ch in &node.children {
            let name = STANDARD.decode(&ch.name_base64).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
            let mut rel = dir_raw.clone();
            if !rel.is_empty() {
                rel.push(b'/');
            }
            rel.extend_from_slice(&name);
            let rel_path = PathBuf::from(OsString::from_vec(rel));
            let full = repo_dir.join(&rel_path);
            match ch.kind {
                MerkleChildKind::Subdir => fs::create_dir_all(&full)?,
                MerkleChildKind::EmptyDir => {
                    fs::create_dir_all(&full)?;
                    *empty_dirs += 1;
                }
                MerkleChildKind::Symlink => {
                    let tgt_raw = STANDARD
                        .decode(ch.target_base64.as_deref().unwrap_or(""))
                        .map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
                    let tgt = PathBuf::from(OsString::from_vec(tgt_raw));
                    validate_symlink_safe(repo_dir, &rel_path, &tgt)?;
                    symlink(&tgt, &full)?;
                    *symlinks += 1;
                }
                MerkleChildKind::File => {
                    let mut out = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&full)?;
                    let mut hasher = Sha256::new();
                    for c in &ch.chunks {
                        let bytes = fs::read(chunk_cache.join(&c.sha256))?;
                        if bytes.len() as u64 != c.len {
                            return Err(MerkleSyncError::IntegrityMismatch("restored chunk length mismatch".into()));
                        }
                        out.write_all(&bytes)?;
                        hasher.update(&bytes);
                    }
                    out.sync_all()?;
                    fs::set_permissions(&full, fs::Permissions::from_mode(ch.mode & 0o777))?;
                    if Some(hex::encode(hasher.finalize())) != ch.content_sha256 {
                        return Err(MerkleSyncError::IntegrityMismatch("restored file sha256 mismatch".into()));
                    }
                    *files += 1;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::workspace_lab::merkle_sync::backup_restore::{
        BackupArtifactEntry, MerkleBackupBundle, compute_bundle_digest, validate_backup_bundle_and_artifacts,
    };
    use crate::workspace_lab::merkle_sync::ledger::RemoteObjectLocatorEntry;
    use crate::workspace_lab::merkle_sync::manifest::{
        EmptyDirPolicy, GitStateSnapshot, IgnorePolicySpec, MerkleObjectFormat, UntrackedPolicy, build_dir_node,
        compute_index_merkle_root, compute_state_merkle_root, encode_rel_bytes,
    };

    #[test]
    fn backup_bundle_rejects_missing_or_mismatched_artifacts_and_inner_scope() -> Result<(), MerkleSyncError> {
        let (t, r, h, ws, cp) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let ctx = AccessContext {
            tenant_id: t,
            repo_id: r,
            user_id: Uuid::new_v4(),
            history_id: h,
            workspace_id: ws,
            lease_epoch: 1,
            request_id: Uuid::new_v4(),
        };
        let payload = b"hello-chunk";
        let c_sha = hex::encode(Sha256::digest(payload));
        let f_child = super::super::manifest::MerkleDirChild {
            name_base64: encode_rel_bytes(b"a.txt"),
            kind: MerkleChildKind::File,
            mode: 0o644,
            size: payload.len() as u64,
            content_sha256: Some(c_sha.clone()),
            target_base64: None,
            chunks: vec![super::super::manifest::ChunkRef {
                index: 0,
                offset: 0,
                len: payload.len() as u64,
                sha256: c_sha.clone(),
            }],
            subtree_node_sha256: None,
            subtree_file_count: 1,
            subtree_total_bytes: payload.len() as u64,
        };
        let root_node = build_dir_node(String::new(), vec![f_child])?;
        let zero_sha = "0".repeat(64);
        let idx_root = compute_index_merkle_root(MerkleObjectFormat::Sha1, &[], &zero_sha, None, None, None);
        let git_state = GitStateSnapshot {
            object_format: MerkleObjectFormat::Sha1,
            head: super::super::manifest::HeadSnapshot::Unborn { ref_name: "refs/heads/main".into() },
            index_entries: Vec::new(),
            index_raw_sha256: zero_sha.clone(),
            index_merkle_root: idx_root,
            merge_head: None,
            cherry_pick_head: None,
            rebase_head: None,
        };
        let ig = IgnorePolicySpec {
            untracked_policy: UntrackedPolicy::IncludeNonIgnored,
            empty_dir_policy: EmptyDirPolicy::IgnoreEmptyDirs,
            use_gitignore: true,
            use_rootyardignore: true,
            ignore_rules_digest: zero_sha.clone(),
        };
        let state_root = compute_state_merkle_root(&git_state, &ig, &root_node.node_sha256, 16384);
        let mut nodes = BTreeMap::new();
        nodes.insert(String::new(), root_node.clone());
        let state = MerkleStateManifest {
            schema: MERKLE_MANIFEST_SCHEMA,
            codec_version: MERKLE_CODEC_VERSION.into(),
            workspace_id: ws,
            checkpoint_id: cp,
            tenant_id: t,
            repo_id: r,
            history_id: h,
            parent_checkpoint_id: None,
            chunk_size_bytes: 16384,
            git_state,
            ignore_policy: ig,
            worktree_root_digest: root_node.node_sha256.clone(),
            nodes,
            merkle_root_digest: state_root.clone(),
        };
        let dummy_loc = RemoteObjectLocatorEntry {
            tenant_id: t,
            authority_id: r,
            generation: 1,
            attempt_id: Uuid::new_v4(),
            namespace: "merkle-git".into(),
            sha256: zero_sha.clone(),
            length: 2,
        };
        let remote = MerkleBlobCheckpointManifest {
            schema: MERKLE_MANIFEST_SCHEMA,
            codec_version: MERKLE_CODEC_VERSION.into(),
            checkpoint_id: cp,
            tenant_id: t,
            repo_id: r,
            history_id: h,
            workspace_id: ws,
            backend_identity_hex: "b".into(),
            merkle_root_digest: state_root.clone(),
            state_manifest: state,
            git_bundle_locator: dummy_loc,
            chunk_locators: BTreeMap::new(),
            node_locators: BTreeMap::new(),
        };
        let node_bytes = serde_json::to_vec(&root_node).unwrap();
        let gb_bytes = br#"{"object_format":"sha1","files":[]}"#;
        let arts = vec![
            BackupArtifactEntry {
                kind: "chunk".into(),
                key_digest: c_sha.clone(),
                sha256: c_sha,
                length: payload.len() as u64,
                payload_base64: STANDARD.encode(payload),
            },
            BackupArtifactEntry {
                kind: "node".into(),
                key_digest: root_node.node_sha256.clone(),
                sha256: hex::encode(Sha256::digest(&node_bytes)),
                length: node_bytes.len() as u64,
                payload_base64: STANDARD.encode(&node_bytes),
            },
            BackupArtifactEntry {
                kind: "git_bundle".into(),
                key_digest: zero_sha,
                sha256: hex::encode(Sha256::digest(gb_bytes)),
                length: gb_bytes.len() as u64,
                payload_base64: STANDARD.encode(gb_bytes),
            },
        ];
        let mut bundle = MerkleBackupBundle {
            schema: MERKLE_MANIFEST_SCHEMA,
            codec_version: MERKLE_CODEC_VERSION.into(),
            backup_id: Uuid::new_v4(),
            source_checkpoint_id: cp,
            tenant_id: t,
            repo_id: r,
            history_id: h,
            source_backend_identity_hex: "b".into(),
            merkle_root_digest: state_root,
            manifest_bytes_base64: String::new(),
            artifacts: arts,
            bundle_sha256: String::new(),
        };
        bundle.bundle_sha256 = compute_bundle_digest(&bundle)?;
        assert!(validate_backup_bundle_and_artifacts(&ctx, &bundle, &remote).is_ok());

        let mut bad_remote = remote.clone();
        bad_remote.checkpoint_id = Uuid::new_v4();
        assert!(validate_backup_bundle_and_artifacts(&ctx, &bundle, &bad_remote).is_err());

        let mut bad_key = bundle.clone();
        bad_key.artifacts[0].key_digest = "f".repeat(64);
        assert!(validate_backup_bundle_and_artifacts(&ctx, &bad_key, &remote).is_err());

        let mut miss_git = bundle.clone();
        miss_git.artifacts.pop();
        assert!(validate_backup_bundle_and_artifacts(&ctx, &miss_git, &remote).is_err());

        let mut miss_chunk = bundle;
        miss_chunk.artifacts.remove(0);
        assert!(validate_backup_bundle_and_artifacts(&ctx, &miss_chunk, &remote).is_err());
        Ok(())
    }
}
