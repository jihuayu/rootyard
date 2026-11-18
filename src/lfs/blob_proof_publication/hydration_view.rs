//! Streaming locator readback verification, bounded transfer concurrency, policy-gated retirement,
//! clean compute-view hydration, and tenant-isolated default upload operation tracking (`Refs #145`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant as StdInstant};

use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::blob_store::{BlobReceipt, opendal::BlobStore};
use crate::lfs::models::valid_lfs_oid;

use super::authz::{derive_default_upload_operation_id, verify_shared_hold_grant};
use super::locks_store::run_git_quarantined;
use super::pg_store::{PgLfsBlobStore, UploadOpSpec, pg_err};
use super::prod_auth_tx::ProdCommitAuthCheck;
use super::transfer::LfsTransferContext;
use super::types::{
    CommittedLfsBlobRecord, LfsBlobError, LfsProofRejectCode, PointerInspection, PointerResolutionSource,
    inspect_candidate_lfs_pointer,
};

pub const MAX_CONCURRENT_S4_TRANSFERS: usize = 16;

static S4_TRANSFER_SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn transfer_semaphore() -> &'static Arc<Semaphore> {
    S4_TRANSFER_SEMAPHORE.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_S4_TRANSFERS)))
}

/// Acquires a bounded S4 streaming I/O concurrency permit; released automatically via RAII on drop
/// or mid-stream client cancellation.
pub async fn acquire_transfer_permit(timeout: Duration) -> Result<OwnedSemaphorePermit, LfsBlobError> {
    tokio::time::timeout(timeout, Arc::clone(transfer_semaphore()).acquire_owned())
        .await
        .map_err(|_| {
            LfsBlobError::new(LfsProofRejectCode::RemoteBlobUnreachable, "S4 LFS transfer concurrency budget exhausted")
        })?
        .map_err(|_| LfsBlobError::new(LfsProofRejectCode::RemoteBlobUnreachable, "S4 LFS transfer semaphore closed"))
}

pub(crate) struct EphemeralScratchGuard(pub PathBuf);

impl Drop for EphemeralScratchGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComputeViewHydrationReport {
    pub commit_oid: String,
    pub hydrated_files: usize,
    pub total_hydrated_bytes: u64,
}

pub(crate) async fn stream_file_sha256_and_len(path: &Path) -> Result<(String, u64), LfsBlobError> {
    let mut file =
        fs::File::open(path).await.map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

async fn verify_locator_and_stage_file(
    store: &BlobStore,
    scratch_dir: &Path,
    rec: &CommittedLfsBlobRecord,
    expected_oid: &str,
    expected_size: i64,
    deadline: StdInstant,
) -> Result<(BlobReceipt, PathBuf, EphemeralScratchGuard), LfsBlobError> {
    if rec.retired {
        return Err(LfsBlobError::new(LfsProofRejectCode::MissingRemoteBlob, "LFS object has been retired"));
    }
    if rec.oid_sha256 != expected_oid || rec.size_bytes != expected_size {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::SizeOrDigestMismatch,
            format!(
                "LFS metadata mismatch: expected ({expected_oid}, {expected_size}), got ({}, {})",
                rec.oid_sha256, rec.size_bytes
            ),
        ));
    }
    if rec.backend_identity_hex != store.backend_identity().as_hex() {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::ForeignBackendMismatch,
            "committed LFS object belongs to a foreign OpenDAL backend",
        ));
    }
    let locator = rec.locator.to_locator()?;
    let receipt = store
        .verify_receipt(&locator, expected_oid, expected_size as u64, deadline)
        .await
        .map_err(LfsBlobError::from_blob_error)?;
    if receipt.backend_identity().as_hex() != store.backend_identity().as_hex() {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::ForeignBackendMismatch,
            "verified receipt backend identity mismatch",
        ));
    }
    fs::create_dir_all(scratch_dir)
        .await
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    let verify_tmp = scratch_dir.join(format!(".lfs-readback-{}.tmp", Uuid::new_v4()));
    let guard = EphemeralScratchGuard(verify_tmp.clone());
    store.get_to_file(&locator, &verify_tmp, deadline).await.map_err(LfsBlobError::from_blob_error)?;
    let (actual_hex, actual_len) = stream_file_sha256_and_len(&verify_tmp).await?;
    if actual_len as i64 != expected_size || actual_hex != expected_oid {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::SizeOrDigestMismatch,
            "remote BlobLocator streamed read-back SHA-256 or byte length mismatch",
        ));
    }
    Ok((receipt, verify_tmp, guard))
}

/// Verifies the **final persisted remote `BlobLocator`** via both `BlobStore::verify_receipt`
/// and chunk-streamed provider byte read-back (`get_to_file` + streamed SHA-256 + byte length).
pub async fn verify_committed_locator_bytes(
    store: &BlobStore,
    scratch_dir: &Path,
    rec: &CommittedLfsBlobRecord,
    expected_oid: &str,
    expected_size: i64,
    deadline: StdInstant,
) -> Result<BlobReceipt, LfsBlobError> {
    let (receipt, _path, _guard) =
        verify_locator_and_stage_file(store, scratch_dir, rec, expected_oid, expected_size, deadline).await?;
    Ok(receipt)
}

async fn resolve_authorized_blob_record(
    ctx: &LfsTransferContext<'_>,
    oid_sha256: &str,
    expected_size: i64,
) -> Result<(CommittedLfsBlobRecord, PointerResolutionSource), LfsBlobError> {
    if !valid_lfs_oid(oid_sha256) || expected_size < 0 {
        return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "invalid LFS OID or negative size"));
    }
    if let Some(own) = ctx.pg.load_committed_blob(ctx.realm.owner_tenant_id, ctx.realm.repository_id, oid_sha256).await?
    {
        if own.retired {
            return Err(LfsBlobError::new(LfsProofRejectCode::MissingRemoteBlob, "LFS object has been retired"));
        }
        if own.size_bytes != expected_size {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::SizeOrDigestMismatch,
                format!("LFS size mismatch: pointer expects {expected_size}, committed is {}", own.size_bytes),
            ));
        }
        return Ok((own, PointerResolutionSource::RepositoryBlob));
    }
    let candidates =
        ctx.pg.find_shared_holds_for_target(ctx.realm.owner_tenant_id, ctx.realm.repository_id, oid_sha256).await?;
    if candidates.is_empty() {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::MissingRemoteBlob,
            format!("LFS object {oid_sha256} is absent from current tenant inventory"),
        ));
    }
    let mut last_err = None;
    for grant in candidates {
        let Some(src_rec) =
            ctx.pg.load_committed_blob(grant.source_tenant_id, grant.source_repository_id, oid_sha256).await?
        else {
            last_err = Some(LfsBlobError::new(
                LfsProofRejectCode::UnauthorizedSharedHold,
                "shared hold source object missing",
            ));
            continue;
        };
        match verify_shared_hold_grant(
            &grant,
            &src_rec,
            ctx.realm.owner_tenant_id,
            ctx.realm.repository_id,
            ctx.access.actor_id,
            oid_sha256,
            expected_size,
        ) {
            Ok(()) => {
                return Ok((
                    src_rec,
                    PointerResolutionSource::SharedHold {
                        grant_id: grant.grant_id,
                        source_tenant_id: grant.source_tenant_id,
                        source_repository_id: grant.source_repository_id,
                    },
                ));
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        LfsBlobError::new(LfsProofRejectCode::UnauthorizedSharedHold, "no valid shared hold grant")
    }))
}

/// Resolves an LFS object record under the current relational `owner_tenant_id` (or active
/// cross-owner `SharedLfsHoldGrant`) and proves live byte integrity on its final `BlobLocator`.
pub async fn resolve_and_verify_remote_blob(
    ctx: &LfsTransferContext<'_>,
    oid_sha256: &str,
    expected_size: i64,
    deadline: StdInstant,
) -> Result<(CommittedLfsBlobRecord, PointerResolutionSource, BlobReceipt), LfsBlobError> {
    let store = ctx.gate.require_store()?;
    let (rec, source) = resolve_authorized_blob_record(ctx, oid_sha256, expected_size).await?;
    let receipt =
        verify_committed_locator_bytes(store, ctx.scratch_dir, &rec, oid_sha256, expected_size, deadline).await?;
    Ok((rec, source, receipt))
}

pub(crate) async fn open_verified_remote_download_file(
    ctx: &LfsTransferContext<'_>,
    oid_sha256: &str,
    expected_size_param: Option<i64>,
) -> Result<(fs::File, EphemeralScratchGuard, u64), LfsBlobError> {
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
    if let Some(req_sz) = expected_size_param
        && req_sz != size_hint
    {
        return Err(LfsBlobError::new(LfsProofRejectCode::MissingRemoteBlob, "LFS object size mismatch"));
    }
    let (rec, _) = resolve_authorized_blob_record(ctx, oid_sha256, size_hint).await?;
    let (_, tmp_path, guard) =
        verify_locator_and_stage_file(store, ctx.scratch_dir, &rec, oid_sha256, size_hint, dl).await?;
    let file = fs::File::open(&tmp_path)
        .await
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    Ok((file, guard, size_hint as u64))
}

pub async fn download_lfs_object_from_remote(
    ctx: &LfsTransferContext<'_>,
    oid_sha256: &str,
    expected_size_param: Option<i64>,
) -> Result<Vec<u8>, LfsBlobError> {
    let _permit = acquire_transfer_permit(ctx.timeout).await?;
    let (mut file, _guard, _) = open_verified_remote_download_file(ctx, oid_sha256, expected_size_param).await?;
    let mut out = Vec::new();
    file.read_to_end(&mut out).await.map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    Ok(out)
}

pub async fn delete_or_retire_lfs_object(
    ctx: &LfsTransferContext<'_>,
    oid_sha256: &str,
    allow_logical_retire: bool,
) -> Result<(), LfsBlobError> {
    let store = ctx.gate.require_store()?;
    if !ctx.access.role.allows_admin() {
        return Err(LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "admin role required"));
    }
    let rec = ctx
        .pg
        .load_committed_blob(ctx.realm.owner_tenant_id, ctx.realm.repository_id, oid_sha256)
        .await?
        .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::MissingRemoteBlob, "LFS object not found"))?;
    let loc = rec.locator.to_locator()?;
    if !allow_logical_retire {
        return store.delete(&loc, StdInstant::now() + ctx.timeout).await.map_err(LfsBlobError::from_blob_error);
    }
    let client = ctx.pg.pool().get().await.map_err(pg_err)?;
    client
        .execute(
            "UPDATE lfs_blob_objects SET retired=TRUE WHERE tenant_id=$1 AND repository_id=$2 AND oid_sha256=$3",
            &[&ctx.realm.owner_tenant_id, &ctx.realm.repository_id, &oid_sha256],
        )
        .await
        .map_err(pg_err)?;
    Ok(())
}

pub async fn hydrate_clean_compute_view(
    ctx: &LfsTransferContext<'_>,
    commit_oid: &str,
    view_dir: &Path,
) -> Result<ComputeViewHydrationReport, LfsBlobError> {
    let store = ctx.gate.require_store()?;
    let _permit = acquire_transfer_permit(ctx.timeout).await?;
    fs::create_dir_all(view_dir)
        .await
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    let bare = Path::new(&ctx.realm.bare_git_dir);
    let ls_raw = run_git_quarantined(bare, None, None, ctx.timeout, &["ls-tree", "-r", "-z", commit_oid], &[]).await?;
    let mut hydrated_files = 0usize;
    let mut total_hydrated_bytes = 0u64;

    for entry in ls_raw.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let text = std::str::from_utf8(entry)
            .map_err(|_| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "non-UTF8 tree entry"))?;
        let Some((meta, rel_path)) = text.split_once('\t') else {
            continue;
        };
        if rel_path.starts_with('/') || rel_path.split('/').any(|p| p.is_empty() || p == "." || p == "..") {
            return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "unsafe tree path in compute view"));
        }
        let parts: Vec<&str> = meta.split_whitespace().collect();
        if parts.len() != 3 || parts[1] != "blob" {
            continue;
        }
        let blob_oid = parts[2];
        let dest = view_dir.join(rel_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        }
        let raw_blob = run_git_quarantined(bare, None, None, ctx.timeout, &["cat-file", "blob", blob_oid], &[]).await?;
        match inspect_candidate_lfs_pointer(&raw_blob) {
            PointerInspection::NonPointer => {
                fs::write(&dest, &raw_blob)
                    .await
                    .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
            }
            PointerInspection::Malformed(reason) => {
                return Err(LfsBlobError::new(LfsProofRejectCode::MalformedLfsPointer, reason));
            }
            PointerInspection::Valid(spec) => {
                let dl = StdInstant::now() + ctx.timeout;
                let (rec, _) = resolve_authorized_blob_record(ctx, &spec.oid, spec.size).await?;
                let (_, staged_path, _guard) =
                    verify_locator_and_stage_file(store, view_dir, &rec, &spec.oid, spec.size, dl).await?;
                fs::rename(&staged_path, &dest)
                    .await
                    .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
                hydrated_files += 1;
                total_hydrated_bytes += spec.size as u64;
            }
        }
    }
    Ok(ComputeViewHydrationReport { commit_oid: commit_oid.to_owned(), hydrated_files, total_hydrated_bytes })
}

impl PgLfsBlobStore {
    /// Resolves or creates a tenant-isolated default upload `operation_id` in `lfs_blob_upload_operations`
    /// for unmodified `git-lfs` clients, ignoring custom `X-Rootyard-Operation-Id` rows and stale tenants.
    pub async fn ensure_default_upload_operation(
        &self,
        repository_id: Uuid,
        tenant_id: Uuid,
        actor_id: Uuid,
        oid_sha256: &str,
        size_bytes: i64,
        force_new_repair_epoch: bool,
    ) -> Result<Uuid, LfsBlobError> {
        self.ensure_default_upload_operation_with_auth(
            UploadOpSpec { repository_id, tenant_id, actor_id, oid_sha256, size_bytes },
            force_new_repair_epoch,
            None,
        )
        .await
    }

    pub async fn ensure_default_upload_operation_with_auth(
        &self,
        spec: UploadOpSpec<'_>,
        force_new_repair_epoch: bool,
        commit_auth: Option<&ProdCommitAuthCheck>,
    ) -> Result<Uuid, LfsBlobError> {
        let UploadOpSpec { repository_id, tenant_id, actor_id, oid_sha256, size_bytes } = spec;
        let rows = self
            .pool()
            .get()
            .await
            .map_err(pg_err)?
            .query(
                "SELECT operation_id, state FROM lfs_blob_upload_operations
                 WHERE repository_id=$1 AND tenant_id=$2 AND actor_id=$3 AND oid_sha256=$4 AND size_bytes=$5",
                &[&repository_id, &tenant_id, &actor_id, &oid_sha256, &size_bytes],
            )
            .await
            .map_err(pg_err)?;
        let by_id: HashMap<Uuid, String> = rows.into_iter().map(|r| (r.get(0), r.get(1))).collect();
        let max_ep = by_id.len() as u64;
        for ep in 0..=max_ep {
            let cand =
                derive_default_upload_operation_id(repository_id, tenant_id, actor_id, oid_sha256, size_bytes, ep);
            match by_id.get(&cand).map(String::as_str) {
                Some(state @ ("pending" | "aborted_failed" | "aborted_cancelled")) => {
                    if commit_auth.is_some() || state.starts_with("aborted_") {
                        let _ = self.begin_or_load_upload_operation_with_auth(cand, spec, commit_auth).await?;
                    }
                    return Ok(cand);
                }
                Some("committed") => continue,
                _ => {
                    if !force_new_repair_epoch && ep > 0 {
                        return Ok(derive_default_upload_operation_id(
                            repository_id,
                            tenant_id,
                            actor_id,
                            oid_sha256,
                            size_bytes,
                            ep - 1,
                        ));
                    }
                    let _ = self.begin_or_load_upload_operation_with_auth(cand, spec, commit_auth).await?;
                    return Ok(cand);
                }
            }
        }
        Err(LfsBlobError::new(LfsProofRejectCode::PgDatabase, "default upload epoch search exhausted"))
    }
}
