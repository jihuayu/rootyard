//! Remote-Blob resolution, policy-gated retirement, and clean compute-view hydration (`Refs #145`).

use std::path::Path;
use std::time::Instant as StdInstant;

use tokio::fs;
use uuid::Uuid;

use crate::blob_store::{BlobReceipt, opendal::BlobStore};
use crate::lfs::models::valid_lfs_oid;

use super::authz::verify_shared_hold_grant;
use super::locks_store::run_git_quarantined;
use super::pg_store::{LfsRepoRealm, PgLfsBlobStore, pg_err};
use super::transfer::LfsTransferContext;
use super::types::{
    CommittedLfsBlobRecord, LfsBlobError, LfsProofRejectCode, PointerInspection, PointerResolutionSource,
    inspect_candidate_lfs_pointer,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComputeViewHydrationReport {
    pub commit_oid: String,
    pub hydrated_files: usize,
    pub total_hydrated_bytes: u64,
}

/// Resolves an LFS object record and proves live byte presence on the remote OpenDAL `BlobStore`
/// (either directly owned by `realm` or authorized via an active cross-owner `SharedLfsHoldGrant`).
pub async fn resolve_and_verify_remote_blob(
    store: &BlobStore,
    pg: &PgLfsBlobStore,
    realm: &LfsRepoRealm,
    actor_id: Uuid,
    oid_sha256: &str,
    expected_size: i64,
    deadline: StdInstant,
) -> Result<(CommittedLfsBlobRecord, PointerResolutionSource, BlobReceipt), LfsBlobError> {
    if !valid_lfs_oid(oid_sha256) || expected_size < 0 {
        return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "invalid LFS OID or negative size"));
    }
    let (rec, source) =
        if let Some(own) = pg.load_committed_blob(realm.owner_tenant_id, realm.repository_id, oid_sha256).await? {
            if own.retired {
                return Err(LfsBlobError::new(LfsProofRejectCode::MissingRemoteBlob, "LFS object has been retired"));
            }
            if own.size_bytes != expected_size {
                return Err(LfsBlobError::new(
                    LfsProofRejectCode::SizeOrDigestMismatch,
                    format!("LFS size mismatch: pointer expects {expected_size}, committed is {}", own.size_bytes),
                ));
            }
            (own, PointerResolutionSource::RepositoryBlob)
        } else {
            let candidates =
                pg.find_shared_holds_for_target(realm.owner_tenant_id, realm.repository_id, oid_sha256).await?;
            if candidates.is_empty() {
                return Err(LfsBlobError::new(
                    LfsProofRejectCode::MissingRemoteBlob,
                    format!("LFS object {oid_sha256} is absent from remote repository inventory"),
                ));
            }
            let mut matched = None;
            let mut last_err = None;
            for grant in candidates {
                let Some(src_rec) =
                    pg.load_committed_blob(grant.source_tenant_id, grant.source_repository_id, oid_sha256).await?
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
                    realm.owner_tenant_id,
                    realm.repository_id,
                    actor_id,
                    oid_sha256,
                    expected_size,
                ) {
                    Ok(()) => {
                        matched = Some((
                            src_rec,
                            PointerResolutionSource::SharedHold {
                                grant_id: grant.grant_id,
                                source_tenant_id: grant.source_tenant_id,
                                source_repository_id: grant.source_repository_id,
                            },
                        ));
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            match matched {
                Some(pair) => pair,
                None => {
                    return Err(last_err.unwrap_or_else(|| {
                        LfsBlobError::new(LfsProofRejectCode::UnauthorizedSharedHold, "no valid shared hold grant")
                    }));
                }
            }
        };

    if rec.backend_identity_hex != store.backend_identity().as_hex() {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::ForeignBackendMismatch,
            "committed LFS object belongs to a foreign OpenDAL backend",
        ));
    }
    let locator = rec.locator.to_locator()?;
    let receipt = store
        .verify_receipt(&locator, oid_sha256, expected_size as u64, deadline)
        .await
        .map_err(LfsBlobError::from_blob_error)?;
    if receipt.backend_identity().as_hex() != store.backend_identity().as_hex() {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::ForeignBackendMismatch,
            "verified receipt backend identity mismatch",
        ));
    }
    Ok((rec, source, receipt))
}

/// Refuses physical remote blob deletion via `BlobStore::delete` (`DeleteDisabledByPolicy`) while
/// allowing explicit admin logical retirement (`retired = true`) when `allow_logical_retire` is set.
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

/// Materializes an isolated clean compute view at `commit_oid`, hydrating every LFS pointer directly
/// from the remote OpenDAL `BlobStore` without any node-local LFS cache.
pub async fn hydrate_clean_compute_view(
    ctx: &LfsTransferContext<'_>,
    commit_oid: &str,
    view_dir: &Path,
) -> Result<ComputeViewHydrationReport, LfsBlobError> {
    let store = ctx.gate.require_store()?;
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
                let (rec, _, _) = resolve_and_verify_remote_blob(
                    store,
                    ctx.pg,
                    ctx.realm,
                    ctx.access.actor_id,
                    &spec.oid,
                    spec.size,
                    dl,
                )
                .await?;
                let loc = rec.locator.to_locator()?;
                store.get_to_file(&loc, &dest, dl).await.map_err(LfsBlobError::from_blob_error)?;
                hydrated_files += 1;
                total_hydrated_bytes += spec.size as u64;
            }
        }
    }
    Ok(ComputeViewHydrationReport { commit_oid: commit_oid.to_owned(), hydrated_files, total_hydrated_bytes })
}
