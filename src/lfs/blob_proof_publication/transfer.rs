//! Remote-Blob-only LFS Batch and verified streaming transfer (`Refs #145`).

use std::collections::BTreeMap;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant as StdInstant};

use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

use crate::blob_store::{
    BlobError, BlobReceipt,
    protected::{ProtectedUploadError, ProtectedUploader, UploadSource},
};
use crate::lfs::models::{
    BatchActionLink, BatchActions, BatchObjectError, BatchObjectResult, BatchRequest, BatchResponse, LFS_HASH_ALGO,
    MAX_BATCH_OBJECTS, valid_lfs_oid,
};

use super::authz::{AuthorizedRepoAccess, LfsBlobRuntimeGate};
pub use super::hydration_view::{
    ComputeViewHydrationReport, delete_or_retire_lfs_object, hydrate_clean_compute_view, resolve_and_verify_remote_blob,
};
use super::pg_store::{LfsRepoRealm, PgLfsBlobStore};
use super::types::{CommittedLfsBlobRecord, LfsBlobError, LfsProofRejectCode, StoredBlobLocatorRef};

struct EphemeralScratchGuard(PathBuf);

impl Drop for EphemeralScratchGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[derive(Clone, Copy)]
pub struct LfsTransferContext<'a> {
    pub gate: &'a LfsBlobRuntimeGate,
    pub pg: &'a PgLfsBlobStore,
    pub realm: &'a LfsRepoRealm,
    pub access: &'a AuthorizedRepoAccess,
    pub scratch_dir: &'a Path,
    pub timeout: Duration,
}

/// Executes Git LFS Batch (`upload` / `download`) purely against OpenDAL `BlobStore` + PostgreSQL.
/// Never ACKs an upload from local disk; remote verified byte presence is mandatory for idempotent ACK.
pub async fn process_batch_request(
    ctx: &LfsTransferContext<'_>,
    base_url: &str,
    auth_header_value: &str,
    req: &BatchRequest,
) -> Result<BatchResponse, LfsBlobError> {
    let store = ctx.gate.require_store()?;
    if req.objects.len() > MAX_BATCH_OBJECTS {
        return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "batch exceeded MAX_BATCH_OBJECTS"));
    }
    if let Some(algo) = req.hash_algo.as_deref()
        && algo != LFS_HASH_ALGO
    {
        return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "unsupported LFS hash_algo"));
    }
    let is_upload = match req.operation.as_str() {
        "upload" => {
            if !ctx.access.role.allows_write() {
                return Err(LfsBlobError::new(
                    LfsProofRejectCode::UnauthorizedCollaborator,
                    "write permission required for LFS batch upload",
                ));
            }
            true
        }
        "download" => false,
        _ => return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "unsupported LFS batch operation")),
    };

    let mut auth_hdr = BTreeMap::new();
    auth_hdr.insert("Authorization".to_owned(), auth_header_value.to_owned());
    let prefix = format!("{}/{}/{}", base_url.trim_end_matches('/'), ctx.realm.owner_username, ctx.realm.repo_name);
    let mut results = Vec::with_capacity(req.objects.len());

    for spec in &req.objects {
        if !valid_lfs_oid(&spec.oid) || spec.size < 0 {
            results.push(BatchObjectResult {
                oid: spec.oid.clone(),
                size: spec.size,
                authenticated: Some(true),
                actions: None,
                error: Some(BatchObjectError { code: 422, message: "invalid LFS oid or size".into() }),
            });
            continue;
        }
        let dl = StdInstant::now() + ctx.timeout;
        if is_upload {
            match ctx.pg.load_committed_blob(ctx.realm.owner_tenant_id, ctx.realm.repository_id, &spec.oid).await? {
                Some(existing) if !existing.retired => {
                    if existing.size_bytes != spec.size {
                        results.push(BatchObjectResult {
                            oid: spec.oid.clone(),
                            size: spec.size,
                            authenticated: Some(true),
                            actions: None,
                            error: Some(BatchObjectError {
                                code: 422,
                                message: "size mismatch against committed remote blob".into(),
                            }),
                        });
                        continue;
                    }
                    let locator = existing.locator.to_locator()?;
                    match store.verify_receipt(&locator, &spec.oid, spec.size as u64, dl).await {
                        Ok(rcpt) if rcpt.backend_identity().as_hex() == store.backend_identity().as_hex() => {
                            results.push(BatchObjectResult {
                                oid: spec.oid.clone(),
                                size: spec.size,
                                authenticated: Some(true),
                                actions: None,
                                error: None,
                            });
                            continue;
                        }
                        Ok(_) => {
                            return Err(LfsBlobError::new(
                                LfsProofRejectCode::ForeignBackendMismatch,
                                "committed locator backend mismatch",
                            ));
                        }
                        Err(BlobError::NotFound) => {}
                        Err(other) => return Err(LfsBlobError::from_blob_error(other)),
                    }
                }
                _ => {}
            }
            results.push(BatchObjectResult {
                oid: spec.oid.clone(),
                size: spec.size,
                authenticated: Some(true),
                actions: Some(BatchActions {
                    upload: Some(BatchActionLink {
                        href: format!("{prefix}/info/lfs/objects/{}/{}", spec.oid, spec.size),
                        header: auth_hdr.clone(),
                        expires_in: Some(900),
                    }),
                    download: None,
                    verify: Some(BatchActionLink {
                        href: format!("{prefix}/info/lfs/verify"),
                        header: auth_hdr.clone(),
                        expires_in: Some(900),
                    }),
                }),
                error: None,
            });
        } else {
            match resolve_and_verify_remote_blob(
                store,
                ctx.pg,
                ctx.realm,
                ctx.access.actor_id,
                &spec.oid,
                spec.size,
                dl,
            )
            .await
            {
                Ok(_) => results.push(BatchObjectResult {
                    oid: spec.oid.clone(),
                    size: spec.size,
                    authenticated: Some(true),
                    actions: Some(BatchActions {
                        upload: None,
                        download: Some(BatchActionLink {
                            href: format!("{prefix}/info/lfs/objects/{}", spec.oid),
                            header: auth_hdr.clone(),
                            expires_in: Some(900),
                        }),
                        verify: None,
                    }),
                    error: None,
                }),
                Err(e) if e.code == LfsProofRejectCode::RemoteBlobUnreachable => return Err(e),
                Err(e) => results.push(BatchObjectResult {
                    oid: spec.oid.clone(),
                    size: spec.size,
                    authenticated: Some(true),
                    actions: None,
                    error: Some(BatchObjectError { code: e.code.http_status().as_u16(), message: e.message }),
                }),
            }
        }
    }

    Ok(BatchResponse { transfer: "basic", objects: results, hash_algo: LFS_HASH_ALGO })
}

/// Streams an LFS object upload into an ephemeral scratch file (unlinked immediately upon return),
/// reserves a permanent `ArtifactHold`, publishes via `ProtectedUploader` with full remote read-back
/// verification, and records the monotonic locator without touching any concurrent uploader's object.
pub async fn upload_lfs_object_to_remote(
    ctx: &LfsTransferContext<'_>,
    oid_sha256: &str,
    expected_size: i64,
    payload: &[u8],
) -> Result<CommittedLfsBlobRecord, LfsBlobError> {
    let store = ctx.gate.require_store()?;
    if !ctx.access.role.allows_write() {
        return Err(LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "write role required"));
    }
    if !valid_lfs_oid(oid_sha256) || expected_size < 0 {
        return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "invalid LFS oid or negative size"));
    }
    let attempt_id = Uuid::new_v4();
    ctx.pg
        .record_upload_attempt_start(
            attempt_id,
            ctx.realm.owner_tenant_id,
            ctx.realm.repository_id,
            ctx.access.actor_id,
            oid_sha256,
            expected_size,
        )
        .await?;

    if payload.len() as i64 != expected_size {
        let _ = ctx.pg.mark_upload_attempt_aborted(attempt_id, "upload byte length mismatch").await;
        return Err(LfsBlobError::new(
            LfsProofRejectCode::SizeOrDigestMismatch,
            format!("upload size mismatch: expected {expected_size}, got {}", payload.len()),
        ));
    }
    let actual_sha = hex::encode(Sha256::digest(payload));
    if actual_sha != oid_sha256 {
        let _ = ctx.pg.mark_upload_attempt_aborted(attempt_id, "upload SHA-256 mismatch").await;
        return Err(LfsBlobError::new(LfsProofRejectCode::SizeOrDigestMismatch, "upload SHA-256 digest mismatch"));
    }

    let std_dl = StdInstant::now() + ctx.timeout;
    if let Some(existing) =
        ctx.pg.load_committed_blob(ctx.realm.owner_tenant_id, ctx.realm.repository_id, oid_sha256).await?
        && !existing.retired
        && existing.size_bytes == expected_size
        && let Ok(loc) = existing.locator.to_locator()
        && let Ok(rcpt) = store.verify_receipt(&loc, oid_sha256, expected_size as u64, std_dl).await
        && rcpt.backend_identity().as_hex() == store.backend_identity().as_hex()
    {
        return ctx.pg.record_committed_blob(attempt_id, &existing).await;
    }

    fs::create_dir_all(ctx.scratch_dir)
        .await
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    let scratch_path = ctx.scratch_dir.join(format!(".lfs-upload-{attempt_id}.tmp"));
    let _guard = EphemeralScratchGuard(scratch_path.clone());
    {
        let std_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&scratch_path)
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let mut f = fs::File::from_std(std_file);
        f.write_all(payload)
            .await
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        f.sync_all().await.map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    }

    let pg_dl = TokioInstant::now() + ctx.timeout;
    let grant = match ctx.pg.acquire_lfs_upload_hold(store, ctx.realm, oid_sha256, expected_size as u64, pg_dl).await {
        Ok(g) => g,
        Err(e) => {
            let _ = ctx.pg.mark_upload_attempt_aborted(attempt_id, &e.message).await;
            return Err(e);
        }
    };
    let uploader = ProtectedUploader::new(store.clone());
    let pub_res = uploader
        .consume_and_upload(ctx.pg.pool(), grant, &[UploadSource::new(&scratch_path)], std_dl)
        .await
        .map_err(|err| match err {
            ProtectedUploadError::ForeignBackend => {
                LfsBlobError::new(LfsProofRejectCode::ForeignBackendMismatch, err.to_string())
            }
            ProtectedUploadError::Blob { error, .. } => LfsBlobError::from_blob_error(error),
            other => LfsBlobError::new(LfsProofRejectCode::RemoteBlobUnreachable, other.to_string()),
        });
    let publication = match pub_res {
        Ok(p) => p,
        Err(e) => {
            let _ = ctx.pg.mark_upload_attempt_aborted(attempt_id, &e.message).await;
            return Err(e);
        }
    };
    let pr = publication
        .receipts()
        .first()
        .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::RemoteBlobUnreachable, "missing ProtectedReceipt"))?;
    let rec = CommittedLfsBlobRecord {
        tenant_id: ctx.realm.owner_tenant_id,
        repository_id: ctx.realm.repository_id,
        oid_sha256: oid_sha256.to_owned(),
        size_bytes: expected_size,
        locator: StoredBlobLocatorRef::from_locator(pr.receipt().locator()),
        hold_id: pr.hold_id(),
        acquire_request_id: publication.acquire_request_id(),
        consume_request_id: publication.consume_request_id(),
        backend_identity_hex: pr.receipt().backend_identity().as_hex().to_owned(),
        uploader_actor_id: ctx.access.actor_id,
        retired: false,
    };
    ctx.pg.record_committed_blob(attempt_id, &rec).await
}

pub async fn verify_lfs_object_remote(
    ctx: &LfsTransferContext<'_>,
    oid_sha256: &str,
    expected_size: i64,
) -> Result<BlobReceipt, LfsBlobError> {
    let store = ctx.gate.require_store()?;
    if !ctx.access.role.allows_write() {
        return Err(LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "write role required"));
    }
    let dl = StdInstant::now() + ctx.timeout;
    let (_, _, rcpt) =
        resolve_and_verify_remote_blob(store, ctx.pg, ctx.realm, ctx.access.actor_id, oid_sha256, expected_size, dl)
            .await?;
    Ok(rcpt)
}

pub async fn download_lfs_object_from_remote(
    ctx: &LfsTransferContext<'_>,
    oid_sha256: &str,
) -> Result<Vec<u8>, LfsBlobError> {
    let store = ctx.gate.require_store()?;
    let dl = StdInstant::now() + ctx.timeout;
    let size_hint =
        if let Some(own) = ctx.pg.load_committed_blob(ctx.realm.owner_tenant_id, ctx.realm.repository_id, oid_sha256).await?
        {
            own.size_bytes
        } else {
            ctx.pg
                .find_shared_holds_for_target(ctx.realm.owner_tenant_id, ctx.realm.repository_id, oid_sha256)
                .await?
                .first()
                .map(|g| g.size_bytes)
                .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::MissingRemoteBlob, "LFS object not found"))?
        };
    let (rec, _, _) =
        resolve_and_verify_remote_blob(store, ctx.pg, ctx.realm, ctx.access.actor_id, oid_sha256, size_hint, dl)
            .await?;
    fs::create_dir_all(ctx.scratch_dir)
        .await
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    let tmp = ctx.scratch_dir.join(format!(".lfs-dl-{}.tmp", Uuid::new_v4()));
    let _guard = EphemeralScratchGuard(tmp.clone());
    let loc = rec.locator.to_locator()?;
    store.get_to_file(&loc, &tmp, dl).await.map_err(LfsBlobError::from_blob_error)?;
    fs::read(&tmp).await.map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))
}
