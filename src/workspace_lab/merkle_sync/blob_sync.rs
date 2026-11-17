use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{
        ffi::OsStringExt,
        fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::Instant,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    MAX_MANIFEST_JSON_BYTES, MERKLE_CODEC_VERSION, MERKLE_MANIFEST_SCHEMA, MerkleSyncError,
    authz::{
        AccessContext, HoldPurpose, PinHoldRegistry, TenantRepoScopeKey, WorkspaceAuthAction, WorkspaceAuthorizer,
    },
    git_compare::GitBundleSnapshot,
    ledger::{
        BlobUploadDriver, CheckpointCommitRecord, CheckpointCommitState, MerkleBlobCheckpointManifest,
        MerkleCheckpointLedger, RemoteObjectLocatorEntry, SyncUploadReport, UploadFailpoint, UploadVerifiedArgs,
    },
    manifest::{MerkleChildKind, MerkleStateManifest, decode_rel_bytes},
    manifest_verify::validate_manifest,
    scanner::ScanResult,
};
use crate::blob_store::{
    BlobReceipt,
    closure::{BlobClosureEncryption, BlobClosureSpec, ClosureArtifactRole, ClosureEntrySpec},
    opendal::BlobStore,
};

pub struct UploadParams<'a> {
    pub ctx: &'a AccessContext,
    pub authorizer: &'a dyn WorkspaceAuthorizer,
    pub store: &'a BlobStore,
    pub driver: &'a dyn BlobUploadDriver,
    pub ledger: &'a MerkleCheckpointLedger,
    pub holds: &'a PinHoldRegistry,
    pub repo_root: &'a Path,
    pub scan: &'a ScanResult,
    pub git_bundle: &'a GitBundleSnapshot,
    pub staging_dir: &'a Path,
    pub generation: i64,
    pub deadline: Instant,
    pub failpoint: Option<UploadFailpoint>,
}

pub async fn sync_incremental_to_blob(params: UploadParams<'_>) -> Result<SyncUploadReport, MerkleSyncError> {
    params.authorizer.authorize(params.ctx, WorkspaceAuthAction::Checkpoint)?;
    let manifest = &params.scan.manifest;
    if manifest.tenant_id != params.ctx.tenant_id
        || manifest.repo_id != params.ctx.repo_id
        || manifest.history_id != params.ctx.history_id
    {
        return Err(MerkleSyncError::TenantScopeMismatch("manifest scope disagrees with access context".into()));
    }
    validate_manifest(manifest)?;
    let backend_hex = params.store.backend_identity().as_hex().to_owned();
    ensure_private_dir(params.staging_dir)?;
    params.ledger.begin_staging(CheckpointCommitRecord {
        checkpoint_id: manifest.checkpoint_id,
        tenant_id: manifest.tenant_id,
        repo_id: manifest.repo_id,
        history_id: manifest.history_id,
        workspace_id: manifest.workspace_id,
        backend_identity_hex: backend_hex.clone(),
        merkle_root_digest: manifest.merkle_root_digest.clone(),
        state: CheckpointCommitState::Staging,
        manifest_locator: None,
        hold_id: None,
    })?;
    match upload_staging_body(&params, &backend_hex).await {
        Ok(report) => Ok(report),
        Err(err) => {
            params.ledger.abort_staging(manifest.checkpoint_id);
            Err(err)
        }
    }
}

async fn upload_staging_body(
    params: &UploadParams<'_>,
    backend_hex: &str,
) -> Result<SyncUploadReport, MerkleSyncError> {
    let manifest = &params.scan.manifest;
    let (mut chunk_locators, mut node_locators) = (BTreeMap::new(), BTreeMap::new());
    let (mut uploaded_chunks, mut reused_chunks, mut uploaded_nodes, mut reused_nodes) =
        (0usize, 0usize, 0usize, 0usize);
    let (mut uploaded_bytes, mut reused_bytes) = (0u64, 0u64);
    let mut closure_entries = Vec::new();
    for (chunk_sha, (rel_path, offset, len)) in collect_file_chunk_locations(manifest)? {
        let key = TenantRepoScopeKey::new(
            params.ctx.tenant_id,
            params.ctx.repo_id,
            params.ctx.history_id,
            backend_hex,
            &chunk_sha,
        )?;
        if let Some(existing) = try_reuse_verified(params.store, params.ledger, &key, params.deadline).await? {
            reused_chunks += 1;
            reused_bytes += len;
            closure_entries
                .push(ClosureEntrySpec::provider_managed(ClosureArtifactRole::Checkpoint, existing.to_locator()?));
            chunk_locators.insert(chunk_sha, existing);
            continue;
        }
        let chunk_bytes = if let Some(list) = params.scan.chunk_sources.get(&chunk_sha)
            && let Some((_, _, data)) = list.first()
        {
            data.clone()
        } else {
            read_file_slice(&params.repo_root.join(rel_path), offset, len)?
        };
        let receipt = upload_bytes_verified(UploadBytesReq {
            store: params.store,
            driver: params.driver,
            ledger: params.ledger,
            staging_dir: params.staging_dir,
            ctx: params.ctx,
            generation: params.generation,
            namespace: "merkle-chunk",
            bytes: &chunk_bytes,
            deadline: params.deadline,
        })
        .await?;
        let entry = RemoteObjectLocatorEntry::from_locator(receipt.locator());
        params.ledger.record_scoped_object(key, entry.clone());
        uploaded_chunks += 1;
        uploaded_bytes += len;
        closure_entries
            .push(ClosureEntrySpec::provider_managed(ClosureArtifactRole::Checkpoint, receipt.locator().clone()));
        chunk_locators.insert(chunk_sha, entry);
        if params.failpoint == Some(UploadFailpoint::AfterFirstChunk) {
            return Err(MerkleSyncError::NotQuiescent("simulated crash after first chunk".into()));
        }
    }
    for node in manifest.nodes.values() {
        let key = TenantRepoScopeKey::new(
            params.ctx.tenant_id,
            params.ctx.repo_id,
            params.ctx.history_id,
            backend_hex,
            &node.node_sha256,
        )?;
        if let Some(existing) = try_reuse_verified(params.store, params.ledger, &key, params.deadline).await? {
            reused_nodes += 1;
            reused_bytes += existing.length;
            closure_entries
                .push(ClosureEntrySpec::provider_managed(ClosureArtifactRole::Checkpoint, existing.to_locator()?));
            node_locators.insert(node.node_sha256.clone(), existing);
            continue;
        }
        let node_bytes = serde_json::to_vec(node).map_err(|e| MerkleSyncError::Io(e.to_string()))?;
        let receipt = upload_bytes_verified(UploadBytesReq {
            store: params.store,
            driver: params.driver,
            ledger: params.ledger,
            staging_dir: params.staging_dir,
            ctx: params.ctx,
            generation: params.generation,
            namespace: "merkle-node",
            bytes: &node_bytes,
            deadline: params.deadline,
        })
        .await?;
        let entry = RemoteObjectLocatorEntry::from_locator(receipt.locator());
        params.ledger.record_scoped_object(key, entry.clone());
        uploaded_nodes += 1;
        uploaded_bytes += node_bytes.len() as u64;
        closure_entries
            .push(ClosureEntrySpec::provider_managed(ClosureArtifactRole::Checkpoint, receipt.locator().clone()));
        node_locators.insert(node.node_sha256.clone(), entry);
    }
    let bundle_bytes = serde_json::to_vec(params.git_bundle).map_err(|e| MerkleSyncError::Io(e.to_string()))?;
    let bundle_receipt = upload_bytes_verified(UploadBytesReq {
        store: params.store,
        driver: params.driver,
        ledger: params.ledger,
        staging_dir: params.staging_dir,
        ctx: params.ctx,
        generation: params.generation,
        namespace: "merkle-git",
        bytes: &bundle_bytes,
        deadline: params.deadline,
    })
    .await?;
    uploaded_bytes += bundle_bytes.len() as u64;
    let git_bundle_locator = RemoteObjectLocatorEntry::from_locator(bundle_receipt.locator());
    closure_entries
        .push(ClosureEntrySpec::provider_managed(ClosureArtifactRole::Archive, bundle_receipt.locator().clone()));
    if params.failpoint == Some(UploadFailpoint::BeforeManifestUpload) {
        return Err(MerkleSyncError::NotQuiescent("simulated crash before manifest upload".into()));
    }
    let remote_manifest = MerkleBlobCheckpointManifest {
        schema: MERKLE_MANIFEST_SCHEMA,
        codec_version: MERKLE_CODEC_VERSION.to_owned(),
        checkpoint_id: manifest.checkpoint_id,
        tenant_id: manifest.tenant_id,
        repo_id: manifest.repo_id,
        history_id: manifest.history_id,
        workspace_id: manifest.workspace_id,
        backend_identity_hex: backend_hex.to_owned(),
        merkle_root_digest: manifest.merkle_root_digest.clone(),
        state_manifest: manifest.clone(),
        git_bundle_locator,
        chunk_locators,
        node_locators,
    };
    let manifest_bytes = serde_json::to_vec(&remote_manifest).map_err(|e| MerkleSyncError::Io(e.to_string()))?;
    if manifest_bytes.len() > MAX_MANIFEST_JSON_BYTES {
        return Err(MerkleSyncError::InvalidManifest("remote manifest exceeds limit".into()));
    }
    let manifest_receipt = upload_bytes_verified(UploadBytesReq {
        store: params.store,
        driver: params.driver,
        ledger: params.ledger,
        staging_dir: params.staging_dir,
        ctx: params.ctx,
        generation: params.generation,
        namespace: "merkle-manifest",
        bytes: &manifest_bytes,
        deadline: params.deadline,
    })
    .await?;
    uploaded_bytes += manifest_bytes.len() as u64;
    let manifest_entry = RemoteObjectLocatorEntry::from_locator(manifest_receipt.locator());
    closure_entries
        .push(ClosureEntrySpec::provider_managed(ClosureArtifactRole::Manifest, manifest_receipt.locator().clone()));
    let closure_spec = BlobClosureSpec::new(
        params.ctx.tenant_id,
        params.ctx.repo_id,
        params.generation,
        BlobClosureEncryption::ProviderManaged,
        closure_entries.clone(),
    )?;
    let _proof = params.store.verify_closure(&closure_spec, None, None, params.deadline).await?;
    if params.failpoint == Some(UploadFailpoint::BeforeAtomicCommit) {
        return Err(MerkleSyncError::NotQuiescent("simulated crash before atomic commit".into()));
    }
    params.authorizer.verify_history_live(params.ctx.tenant_id, params.ctx.repo_id, params.ctx.history_id)?;
    let held_paths: BTreeSet<String> = closure_entries.iter().map(|e| e.locator().path()).collect();
    let hold = params.holds.acquire_hold(
        HoldPurpose::ActiveCheckpoint,
        params.ctx.tenant_id,
        params.ctx.repo_id,
        params.ctx.history_id,
        manifest.checkpoint_id,
        held_paths,
    )?;
    params.ledger.commit_atomic(manifest.checkpoint_id, manifest_entry.clone(), hold.hold_id)?;
    Ok(SyncUploadReport {
        checkpoint_id: manifest.checkpoint_id,
        merkle_root_digest: manifest.merkle_root_digest.clone(),
        uploaded_chunks,
        reused_chunks,
        uploaded_nodes,
        reused_nodes,
        uploaded_bytes,
        reused_bytes,
        closure_verified: true,
        manifest_locator: manifest_entry,
        hold_id: hold.hold_id,
    })
}

pub(crate) async fn try_reuse_verified(
    store: &BlobStore,
    ledger: &MerkleCheckpointLedger,
    key: &TenantRepoScopeKey,
    deadline: Instant,
) -> Result<Option<RemoteObjectLocatorEntry>, MerkleSyncError> {
    let Some(entry) = ledger.lookup_scoped_object(key) else { return Ok(None) };
    let loc = entry.to_locator()?;
    if loc.tenant_id() != key.tenant_id || loc.authority_id() != key.repo_id {
        return Err(MerkleSyncError::TenantScopeMismatch("cached locator scope mismatch".into()));
    }
    match store.verify(&loc, deadline).await {
        Ok(receipt) if receipt.backend_identity().as_hex() == store.backend_identity().as_hex() => Ok(Some(entry)),
        _ => Ok(None),
    }
}

#[derive(Clone, Copy)]
pub(crate) struct UploadBytesReq<'a> {
    pub(crate) store: &'a BlobStore,
    pub(crate) driver: &'a dyn BlobUploadDriver,
    pub(crate) ledger: &'a MerkleCheckpointLedger,
    pub(crate) staging_dir: &'a Path,
    pub(crate) ctx: &'a AccessContext,
    pub(crate) generation: i64,
    pub(crate) namespace: &'a str,
    pub(crate) bytes: &'a [u8],
    pub(crate) deadline: Instant,
}

pub(crate) async fn upload_bytes_verified(req: UploadBytesReq<'_>) -> Result<BlobReceipt, MerkleSyncError> {
    let sha = hex::encode(Sha256::digest(req.bytes));
    let tmp = req.staging_dir.join(format!("upload-{}.bin", Uuid::new_v4()));
    {
        let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        f.write_all(req.bytes)?;
        f.sync_all()?;
    }
    let res = req
        .driver
        .upload_verified(UploadVerifiedArgs {
            store: req.store,
            tenant_id: req.ctx.tenant_id,
            authority_id: req.ctx.repo_id,
            generation: req.generation,
            namespace: req.namespace,
            sha256: &sha,
            length: req.bytes.len() as u64,
            source_path: &tmp,
            deadline: req.deadline,
        })
        .await;
    let _ = fs::remove_file(&tmp);
    let receipt = res?;
    if receipt.backend_identity().as_hex() != req.store.backend_identity().as_hex() {
        return Err(MerkleSyncError::ForeignBackend);
    }
    req.ledger.record_issued_locator(receipt.locator());
    Ok(receipt)
}

fn collect_file_chunk_locations(
    manifest: &MerkleStateManifest,
) -> Result<BTreeMap<String, (PathBuf, u64, u64)>, MerkleSyncError> {
    let mut map = BTreeMap::new();
    for (dir_b64, node) in &manifest.nodes {
        let dir_raw = if dir_b64.is_empty() { Vec::new() } else { decode_rel_bytes(dir_b64)? };
        for ch in &node.children {
            if ch.kind == MerkleChildKind::File {
                let name =
                    STANDARD.decode(&ch.name_base64).map_err(|e| MerkleSyncError::InvalidManifest(e.to_string()))?;
                let mut rel = dir_raw.clone();
                if !rel.is_empty() {
                    rel.push(b'/');
                }
                rel.extend_from_slice(&name);
                let rel_path = PathBuf::from(OsString::from_vec(rel));
                for chunk in &ch.chunks {
                    map.entry(chunk.sha256.clone()).or_insert_with(|| (rel_path.clone(), chunk.offset, chunk.len));
                }
            }
        }
    }
    Ok(map)
}

fn read_file_slice(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, MerkleSyncError> {
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len as usize];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

pub(crate) fn ensure_private_dir(path: &Path) -> Result<(), MerkleSyncError> {
    if !path.exists() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
