//! Local/Blob CloneKit artifact staging under the selected generation read lease.

use std::path::{Path, PathBuf};

use super::{
    builder::CloneKitReadLease,
    checkout::CheckoutRequest,
    manifest::{CloneKitError, CloneKitManifest, compute_file_sha256, default_git_timeout, ensure_not_cancelled},
};

pub(super) async fn download_and_verify_kit_files(
    req: &CheckoutRequest<'_>,
    manifest: &CloneKitManifest,
    stage_dir: &Path,
    mut read_lease: Option<CloneKitReadLease>,
) -> Result<(PathBuf, PathBuf, u64, u64), CloneKitError> {
    ensure_not_cancelled(req.cancel.as_ref())?;
    let pack_meta = manifest.pack.as_ref().ok_or(CloneKitError::MissingKit)?;
    let idx_meta = manifest.idx.as_ref().ok_or(CloneKitError::MissingKit)?;
    let dest_pack = stage_dir.join(format!("kit-{}.pack", pack_meta.sha256));
    let dest_idx = stage_dir.join(format!("kit-{}.idx", idx_meta.sha256));
    let mut gets = 0u64;

    if let Some(blob_store) = req.blob_store {
        if let Some(expected_backend) = manifest.backend_identity_hex.as_deref()
            && expected_backend != blob_store.backend_identity().as_hex()
        {
            return Err(CloneKitError::ForeignBackend);
        }
        if let (Some(p_loc), Some(i_loc)) = (&pack_meta.blob_locator, &idx_meta.blob_locator) {
            // Blob bytes are not read from the local generation; release before provider I/O.
            drop(read_lease.take());
            let deadline = std::time::Instant::now() + default_git_timeout();
            blob_store.get_to_file(&p_loc.to_blob_locator()?, &dest_pack, deadline).await?;
            gets += 1;
            ensure_not_cancelled(req.cancel.as_ref())?;
            blob_store.get_to_file(&i_loc.to_blob_locator()?, &dest_idx, deadline).await?;
            gets += 1;
        }
    }
    if gets == 0 {
        let pub_store = req.pub_store.ok_or(CloneKitError::MissingKit)?;
        let lease = match read_lease.take() {
            Some(lease) => lease,
            None => pub_store.acquire_generation_read_lease(manifest.repository_id, manifest)?,
        };
        lease.copy_pack_to(&dest_pack, pack_meta.length)?;
        ensure_not_cancelled(req.cancel.as_ref())?;
        lease.copy_idx_to(&dest_idx, idx_meta.length)?;
        // Release immediately after the final protected cross-root source copy. Scratch
        // hashing, authority checks, Blob/provider I/O, and Git handoff must not prolong it.
        drop(lease);
        gets = 2;
    }

    let ((p_sha, p_len), (i_sha, i_len)) = (compute_file_sha256(&dest_pack)?, compute_file_sha256(&dest_idx)?);
    if p_sha != pack_meta.sha256 || p_len != pack_meta.length || i_sha != idx_meta.sha256 || i_len != idx_meta.length {
        return Err(CloneKitError::CorruptArtifact("downloaded clonekit pack/idx digest or size mismatch".into()));
    }
    Ok((dest_pack, dest_idx, p_len + i_len, gets))
}
