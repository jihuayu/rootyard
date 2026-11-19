//! Local/Blob CloneKit artifact staging under the selected generation read lease.

use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use super::{
    builder::CloneKitReadLease,
    checkout::CheckoutRequest,
    manifest::{
        CloneKitError, CloneKitManifest, compute_file_sha256, default_git_timeout, ensure_not_cancelled,
        write_atomic_private_file,
    },
};

fn copy_verified_local_artifact(src: &Path, dest: &Path, expected_len: u64) -> Result<(), CloneKitError> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(src)
        .map_err(|err| CloneKitError::CorruptArtifact(format!("open published clonekit artifact: {err}")))?;
    let meta = input
        .metadata()
        .map_err(|err| CloneKitError::CorruptArtifact(format!("stat published clonekit artifact: {err}")))?;
    if !meta.is_file() || meta.len() != expected_len {
        return Err(CloneKitError::CorruptArtifact(
            "published clonekit artifact is not the expected regular file".into(),
        ));
    }
    let mut bytes = Vec::new();
    input
        .read_to_end(&mut bytes)
        .map_err(|err| CloneKitError::CorruptArtifact(format!("read published clonekit artifact: {err}")))?;
    write_atomic_private_file(dest, &bytes)
}

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
    let local_lease = if gets == 0 {
        let pub_store = req.pub_store.ok_or(CloneKitError::MissingKit)?;
        let lease = match read_lease.take() {
            Some(lease) => lease,
            None => pub_store.acquire_generation_read_lease(manifest.repository_id, manifest)?,
        };
        let (src_pack, src_idx) = pub_store.artifact_paths(manifest.repository_id, manifest.kit_generation);
        copy_verified_local_artifact(&src_pack, &dest_pack, pack_meta.length)?;
        ensure_not_cancelled(req.cancel.as_ref())?;
        copy_verified_local_artifact(&src_idx, &dest_idx, idx_meta.length)?;
        gets = 2;
        Some(lease)
    } else {
        None
    };

    let ((p_sha, p_len), (i_sha, i_len)) = (compute_file_sha256(&dest_pack)?, compute_file_sha256(&dest_idx)?);
    drop(local_lease);
    if p_sha != pack_meta.sha256 || p_len != pack_meta.length || i_sha != idx_meta.sha256 || i_len != idx_meta.length {
        return Err(CloneKitError::CorruptArtifact("downloaded clonekit pack/idx digest or size mismatch".into()));
    }
    Ok((dest_pack, dest_idx, p_len + i_len, gets))
}
