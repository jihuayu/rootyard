use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    time::Instant,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    MERKLE_CODEC_VERSION, MERKLE_MANIFEST_SCHEMA, MerkleSyncError,
    authz::{
        AccessContext, HoldPurpose, PinHoldRegistry, TenantRepoScopeKey, WorkspaceAuthAction, WorkspaceAuthorizer,
    },
    blob_sync::{ensure_private_dir, upload_bytes_verified},
    ledger::{
        BlobUploadDriver, CheckpointCommitRecord, CheckpointCommitState, MerkleBlobCheckpointManifest,
        MerkleCheckpointLedger, RemoteObjectLocatorEntry,
    },
    manifest_verify::validate_manifest,
    restore::{RestoreReport, RestoreRequest, restore_or_fork_from_blob},
};
use crate::blob_store::{
    closure::{BlobClosureEncryption, BlobClosureSpec, ClosureArtifactRole, ClosureEntrySpec},
    opendal::BlobStore,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupArtifactEntry {
    pub kind: String,
    pub key_digest: String,
    pub sha256: String,
    pub length: u64,
    pub payload_base64: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MerkleBackupBundle {
    pub schema: u32,
    pub codec_version: String,
    pub backup_id: Uuid,
    pub source_checkpoint_id: Uuid,
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub source_backend_identity_hex: String,
    pub merkle_root_digest: String,
    pub manifest_bytes_base64: String,
    pub artifacts: Vec<BackupArtifactEntry>,
    pub bundle_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRestoreReport {
    pub backup_id: Uuid,
    pub restored_checkpoint_id: Uuid,
    pub hold_id: Uuid,
    pub uploaded_artifacts: usize,
    pub restore_report: RestoreReport,
}

fn compute_bundle_digest(
    source_checkpoint_id: Uuid,
    tenant_id: Uuid,
    repo_id: Uuid,
    history_id: Uuid,
    merkle_root_digest: &str,
    manifest_bytes_base64: &str,
    artifacts: &[BackupArtifactEntry],
) -> Result<String, MerkleSyncError> {
    let body = serde_json::to_vec(&(
        source_checkpoint_id,
        tenant_id,
        repo_id,
        history_id,
        merkle_root_digest,
        manifest_bytes_base64,
        artifacts,
    ))
    .map_err(|e| MerkleSyncError::Io(e.to_string()))?;
    Ok(hex::encode(Sha256::digest(&body)))
}

pub async fn export_checkpoint_backup(
    ctx: &AccessContext,
    authorizer: &dyn WorkspaceAuthorizer,
    store: &BlobStore,
    ledger: &MerkleCheckpointLedger,
    holds: &PinHoldRegistry,
    checkpoint_id: Uuid,
    staging_parent: &Path,
    deadline: Instant,
) -> Result<(MerkleBackupBundle, Uuid), MerkleSyncError> {
    authorizer.authorize(ctx, WorkspaceAuthAction::BackupExport)?;
    let rec = ledger.get_committed(ctx, checkpoint_id)?;
    if rec.backend_identity_hex != store.backend_identity().as_hex() {
        return Err(MerkleSyncError::ForeignBackend);
    }
    let manifest_entry =
        rec.manifest_locator.ok_or_else(|| MerkleSyncError::MissingArtifact("manifest missing".into()))?;
    let manifest_loc = manifest_entry.to_locator()?;
    ensure_private_dir(staging_parent)?;
    let stage = staging_parent.join(format!("backup-exp-{}", Uuid::new_v4()));
    ensure_private_dir(&stage)?;

    let m_path = stage.join("manifest.json");
    store.get_to_file(&manifest_loc, &m_path, deadline).await?;
    let m_bytes = fs::read(&m_path)?;
    let remote: MerkleBlobCheckpointManifest =
        serde_json::from_slice(&m_bytes).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
    if remote.tenant_id != ctx.tenant_id || remote.repo_id != ctx.repo_id || remote.history_id != ctx.history_id {
        let _ = fs::remove_dir_all(&stage);
        return Err(MerkleSyncError::TenantScopeMismatch("backup manifest scope mismatch".into()));
    }
    validate_manifest(&remote.state_manifest)?;

    let mut held_paths = BTreeSet::new();
    held_paths.insert(manifest_loc.path());
    held_paths.insert(remote.git_bundle_locator.to_locator()?.path());
    for entry in remote.chunk_locators.values().chain(remote.node_locators.values()) {
        held_paths.insert(entry.to_locator()?.path());
    }
    let hold = holds.acquire_hold(
        HoldPurpose::BackupArchive,
        ctx.tenant_id,
        ctx.repo_id,
        ctx.history_id,
        checkpoint_id,
        held_paths,
    )?;

    let mut artifacts = Vec::new();
    let bundle_loc = remote.git_bundle_locator.to_locator()?;
    let b_path = stage.join("git-bundle.json");
    store.get_to_file(&bundle_loc, &b_path, deadline).await?;
    let b_bytes = fs::read(&b_path)?;
    artifacts.push(BackupArtifactEntry {
        kind: "git_bundle".into(),
        key_digest: bundle_loc.sha256().to_owned(),
        sha256: hex::encode(Sha256::digest(&b_bytes)),
        length: b_bytes.len() as u64,
        payload_base64: STANDARD.encode(&b_bytes),
    });
    for (sha, entry) in &remote.chunk_locators {
        let loc = entry.to_locator()?;
        let dst = stage.join(format!("chunk-{sha}"));
        store.get_to_file(&loc, &dst, deadline).await?;
        let data = fs::read(&dst)?;
        artifacts.push(BackupArtifactEntry {
            kind: "chunk".into(),
            key_digest: sha.clone(),
            sha256: hex::encode(Sha256::digest(&data)),
            length: data.len() as u64,
            payload_base64: STANDARD.encode(&data),
        });
    }
    for (sha, entry) in &remote.node_locators {
        let loc = entry.to_locator()?;
        let dst = stage.join(format!("node-{sha}"));
        store.get_to_file(&loc, &dst, deadline).await?;
        let data = fs::read(&dst)?;
        artifacts.push(BackupArtifactEntry {
            kind: "node".into(),
            key_digest: sha.clone(),
            sha256: hex::encode(Sha256::digest(&data)),
            length: data.len() as u64,
            payload_base64: STANDARD.encode(&data),
        });
    }
    let _ = fs::remove_dir_all(&stage);

    let manifest_bytes_base64 = STANDARD.encode(&m_bytes);
    let bundle_sha256 = compute_bundle_digest(
        checkpoint_id,
        ctx.tenant_id,
        ctx.repo_id,
        ctx.history_id,
        &remote.merkle_root_digest,
        &manifest_bytes_base64,
        &artifacts,
    )?;
    Ok((
        MerkleBackupBundle {
            schema: MERKLE_MANIFEST_SCHEMA,
            codec_version: MERKLE_CODEC_VERSION.to_owned(),
            backup_id: Uuid::new_v4(),
            source_checkpoint_id: checkpoint_id,
            tenant_id: ctx.tenant_id,
            repo_id: ctx.repo_id,
            history_id: ctx.history_id,
            source_backend_identity_hex: store.backend_identity().as_hex().to_owned(),
            merkle_root_digest: remote.merkle_root_digest,
            manifest_bytes_base64,
            artifacts,
            bundle_sha256,
        },
        hold.hold_id,
    ))
}

pub struct RestoreBackupParams<'a> {
    pub target_ctx: &'a AccessContext,
    pub authorizer: &'a dyn WorkspaceAuthorizer,
    pub target_store: &'a BlobStore,
    pub driver: &'a dyn BlobUploadDriver,
    pub target_ledger: &'a MerkleCheckpointLedger,
    pub target_holds: &'a PinHoldRegistry,
    pub bundle: &'a MerkleBackupBundle,
    pub target_empty_dir: &'a Path,
    pub new_workspace_id: Uuid,
    pub agent_id: &'a str,
    pub staging_parent: &'a Path,
    pub generation: i64,
    pub deadline: Instant,
}

pub async fn restore_checkpoint_backup(
    params: RestoreBackupParams<'_>,
) -> Result<BackupRestoreReport, MerkleSyncError> {
    params.authorizer.authorize(params.target_ctx, WorkspaceAuthAction::BackupRestore)?;
    let b = params.bundle;
    if b.schema != MERKLE_MANIFEST_SCHEMA || b.codec_version != MERKLE_CODEC_VERSION {
        return Err(MerkleSyncError::InvalidManifest("unsupported backup schema".into()));
    }
    if b.tenant_id != params.target_ctx.tenant_id || b.repo_id != params.target_ctx.repo_id {
        return Err(MerkleSyncError::TenantScopeMismatch("backup tenant/repo does not match target context".into()));
    }
    let expected_digest = compute_bundle_digest(
        b.source_checkpoint_id,
        b.tenant_id,
        b.repo_id,
        b.history_id,
        &b.merkle_root_digest,
        &b.manifest_bytes_base64,
        &b.artifacts,
    )?;
    if expected_digest != b.bundle_sha256 {
        return Err(MerkleSyncError::IntegrityMismatch("backup bundle checksum mismatch".into()));
    }
    let m_raw =
        STANDARD.decode(&b.manifest_bytes_base64).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
    let mut remote: MerkleBlobCheckpointManifest =
        serde_json::from_slice(&m_raw).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
    validate_manifest(&remote.state_manifest)?;

    ensure_private_dir(params.staging_parent)?;
    let stage = params.staging_parent.join(format!("backup-rest-{}", Uuid::new_v4()));
    ensure_private_dir(&stage)?;

    let backend_hex = params.target_store.backend_identity().as_hex().to_owned();
    let mut chunk_locators = BTreeMap::new();
    let mut node_locators = BTreeMap::new();
    let mut git_bundle_locator = None;
    let mut closure_entries = Vec::new();
    let mut uploaded_artifacts = 0usize;

    for art in &b.artifacts {
        let data = STANDARD.decode(&art.payload_base64).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
        if data.len() as u64 != art.length || hex::encode(Sha256::digest(&data)) != art.sha256 {
            let _ = fs::remove_dir_all(&stage);
            return Err(MerkleSyncError::IntegrityMismatch("backup artifact integrity mismatch".into()));
        }
        let ns = match art.kind.as_str() {
            "chunk" => "merkle-chunk",
            "node" => "merkle-node",
            "git_bundle" => "merkle-git",
            _ => {
                let _ = fs::remove_dir_all(&stage);
                return Err(MerkleSyncError::InvalidManifest("unknown backup artifact kind".into()));
            }
        };
        let receipt = upload_bytes_verified(
            params.target_store,
            params.driver,
            params.target_ledger,
            &stage,
            params.target_ctx,
            params.generation,
            ns,
            &data,
            params.deadline,
        )
        .await?;
        let entry = RemoteObjectLocatorEntry::from_locator(receipt.locator());
        uploaded_artifacts += 1;
        if art.kind == "git_bundle" {
            closure_entries
                .push(ClosureEntrySpec::provider_managed(ClosureArtifactRole::Archive, receipt.locator().clone()));
            git_bundle_locator = Some(entry);
        } else {
            let key = TenantRepoScopeKey::new(
                params.target_ctx.tenant_id,
                params.target_ctx.repo_id,
                params.target_ctx.history_id,
                &backend_hex,
                &art.key_digest,
            )?;
            params.target_ledger.record_scoped_object(key, entry.clone());
            closure_entries
                .push(ClosureEntrySpec::provider_managed(ClosureArtifactRole::Checkpoint, receipt.locator().clone()));
            if art.kind == "chunk" {
                chunk_locators.insert(art.key_digest.clone(), entry);
            } else {
                node_locators.insert(art.key_digest.clone(), entry);
            }
        }
    }
    remote.history_id = params.target_ctx.history_id;
    remote.backend_identity_hex = backend_hex.clone();
    remote.state_manifest.history_id = params.target_ctx.history_id;
    let rebuilt_root = super::manifest::compute_state_merkle_root(
        &remote.state_manifest.git_state,
        &remote.state_manifest.ignore_policy,
        &remote.state_manifest.worktree_root_digest,
        remote.state_manifest.chunk_size_bytes,
    );
    remote.state_manifest.merkle_root_digest = rebuilt_root.clone();
    remote.merkle_root_digest = rebuilt_root;
    remote.git_bundle_locator =
        git_bundle_locator.ok_or_else(|| MerkleSyncError::MissingArtifact("backup missing git_bundle".into()))?;
    remote.chunk_locators = chunk_locators;
    remote.node_locators = node_locators;

    let new_m_bytes = serde_json::to_vec(&remote).map_err(|e| MerkleSyncError::Io(e.to_string()))?;
    let m_receipt = upload_bytes_verified(
        params.target_store,
        params.driver,
        params.target_ledger,
        &stage,
        params.target_ctx,
        params.generation,
        "merkle-manifest",
        &new_m_bytes,
        params.deadline,
    )
    .await?;
    let m_entry = RemoteObjectLocatorEntry::from_locator(m_receipt.locator());
    closure_entries
        .push(ClosureEntrySpec::provider_managed(ClosureArtifactRole::Manifest, m_receipt.locator().clone()));
    uploaded_artifacts += 1;
    let closure_spec = BlobClosureSpec::new(
        params.target_ctx.tenant_id,
        params.target_ctx.repo_id,
        params.generation,
        BlobClosureEncryption::ProviderManaged,
        closure_entries.clone(),
    )?;
    let _proof = params.target_store.verify_closure(&closure_spec, None, None, params.deadline).await?;
    let held_paths: BTreeSet<String> = closure_entries.iter().map(|e| e.locator().path()).collect();
    let hold = params.target_holds.acquire_hold(
        HoldPurpose::ActiveCheckpoint,
        params.target_ctx.tenant_id,
        params.target_ctx.repo_id,
        params.target_ctx.history_id,
        remote.checkpoint_id,
        held_paths,
    )?;
    params.target_ledger.begin_staging(CheckpointCommitRecord {
        checkpoint_id: remote.checkpoint_id,
        tenant_id: params.target_ctx.tenant_id,
        repo_id: params.target_ctx.repo_id,
        history_id: params.target_ctx.history_id,
        workspace_id: params.new_workspace_id,
        backend_identity_hex: backend_hex,
        merkle_root_digest: remote.merkle_root_digest.clone(),
        state: CheckpointCommitState::Staging,
        manifest_locator: None,
        hold_id: None,
    })?;
    params.target_ledger.commit_atomic(remote.checkpoint_id, m_entry, hold.hold_id)?;
    let _ = fs::remove_dir_all(&stage);

    let restore_report = restore_or_fork_from_blob(RestoreRequest {
        ctx: params.target_ctx,
        authorizer: params.authorizer,
        store: params.target_store,
        ledger: params.target_ledger,
        holds: params.target_holds,
        checkpoint_id: remote.checkpoint_id,
        target_empty_dir: params.target_empty_dir,
        new_workspace_id: params.new_workspace_id,
        agent_id: params.agent_id,
        staging_parent: params.staging_parent,
        deadline: params.deadline,
    })
    .await?;

    Ok(BackupRestoreReport {
        backup_id: b.backup_id,
        restored_checkpoint_id: remote.checkpoint_id,
        hold_id: hold.hold_id,
        uploaded_artifacts,
        restore_report,
    })
}
