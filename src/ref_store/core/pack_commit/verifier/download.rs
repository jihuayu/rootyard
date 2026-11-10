//! Verified download of the exact registered artifacts.
//!
//! Every byte that native Git later validates is the result of a real
//! retained `BlobStore::get_to_file` GET of the *registered* locator (tenant,
//! authority, generation, attempt, namespace, sha256, length), which itself
//! streams the provider object into a private staging file and verifies SHA-256
//! and length before the atomic rename. The verifier then re-reads the local
//! copy and independently recomputes SHA-256 and length, so the values native Git
//! sees are the values the registration recorded and the plan planned.
//!
//! The caller's owned `Arc<VerificationLease>` is threaded into the **actual**
//! Blob transfer task and into its deferred staging unlink, so a timeout or
//! cancellation in the materializer can never release the workspace, the view
//! budget or the native permit while provider/local writes, the rename or the
//! cleanup are still running. The independent SHA-256/length/header re-read also
//! runs in one owned blocking task holding a lease clone: a timed-out join
//! detaches it without releasing capacity until the blocking read has exited.
//!
//! Nothing here uses `head`/`stat`/`ETag`/`LIST` as evidence, and nothing here
//! opens a caller-supplied path: the destination names are generated inside the
//! verifier's own 0700 view.
//!
//! Admission reads exactly the fixed 12-byte pack header (magic, version, object
//! count) to enforce the frozen total-object bound. The verifier never parses
//! further: native Git remains the content validator.
use super::lease::VerificationLease;
use super::refuse;
use super::validate::artifact_of;
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::core::pack_commit::artifact::{RegisteredArtifact, RegisteredPack};
use crate::ref_store::core::pack_commit::contract::PackArtifactRole;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// Fixed native pack header size. Nothing beyond this is interpreted here.
const PACK_HEADER_BYTES: usize = 12;
/// Read-back chunk; the local copy is bounded by the registered length.
const READBACK_CHUNK: usize = 64 * 1024;

/// One verified pack/idx pair materialised in the owned view.
pub(super) struct PairInput {
    pub(super) pack: PathBuf,
    pub(super) idx: PathBuf,
    /// Content digest of the pack bytes actually downloaded and re-read.
    pub(super) sha256: String,
    /// Object count declared by the pack header (admission only).
    pub(super) objects: u64,
}

/// The live Blob store must be the exact physical backend of *every* registered
/// artifact, checked before any Blob or local IO.
pub(super) fn check_live_backend(store: &BlobStore, packs: &[&RegisteredPack]) -> Result<(), PackCommitError> {
    let provider = store.provider().as_str();
    let backend = store.backend_identity().as_hex();
    for pack in packs {
        for role in [PackArtifactRole::Pack, PackArtifactRole::Idx] {
            let artifact = artifact_of(pack, role)?;
            if artifact.provider() != provider || artifact.backend_identity() != backend {
                return Err(refuse("the live Blob backend is not the registered artifact backend"));
            }
        }
    }
    Ok(())
}

/// Fetch one registered pair into the owned view and independently re-verify it.
///
/// `lease` is the caller's owned verification lease. It travels into the actual
/// Blob GET task (and through staging cleanup) and into the independent read-back
/// blocking task, so no capacity is released while this pair may still be
/// written, renamed, read or unlinked.
pub(super) async fn fetch_pair(
    store: &BlobStore,
    pack: &RegisteredPack,
    incoming: &Path,
    index: usize,
    lease: &Arc<VerificationLease>,
    deadline: Instant,
) -> Result<PairInput, PackCommitError> {
    let pack_artifact = artifact_of(pack, PackArtifactRole::Pack)?;
    let idx_artifact = artifact_of(pack, PackArtifactRole::Idx)?;
    let stem = format!("pair-{index:02}");
    let pack_path = incoming.join(format!("{stem}.pack"));
    let idx_path = incoming.join(format!("{stem}.idx"));

    let pack_locator =
        pack_artifact.locator().blob_locator().map_err(|_| refuse("registered locator cannot be reconstructed"))?;
    store
        .get_to_file_with_owner(&pack_locator, &pack_path, deadline, Arc::clone(lease))
        .await
        .map_err(|_| refuse("verified Blob read of a registered artifact failed"))?;
    // Independent SHA-256 + length re-read of exactly the registered pack bytes,
    // plus the fixed 12-byte admission header, in one owned blocking task.
    let objects = readback(&pack_path, pack_artifact, true, Arc::clone(lease), deadline)
        .await?
        .ok_or_else(|| refuse("registered pack header was not read back"))?;

    let idx_locator =
        idx_artifact.locator().blob_locator().map_err(|_| refuse("registered locator cannot be reconstructed"))?;
    store
        .get_to_file_with_owner(&idx_locator, &idx_path, deadline, Arc::clone(lease))
        .await
        .map_err(|_| refuse("verified Blob read of a registered artifact failed"))?;
    readback(&idx_path, idx_artifact, false, Arc::clone(lease), deadline).await?;

    let sha256 = pack_artifact.verified_sha256().as_str().to_owned();
    Ok(PairInput { pack: pack_path, idx: idx_path, sha256, objects })
}

/// Independent SHA-256 + length (and, for the pack role, fixed-header) re-read
/// of the downloaded copy in one owned blocking task.
///
/// The task owns a clone of the caller's `Arc<VerificationLease>` until the
/// closure actually returns, so a timed-out or cancelled join detaches it
/// without releasing the workspace, the view budget or the native permit while
/// these local reads may still run. Memory stays bounded by one
/// [`READBACK_CHUNK`] buffer and the deadline is checked before every chunk.
async fn readback(
    path: &Path,
    artifact: &RegisteredArtifact,
    header: bool,
    lease: Arc<VerificationLease>,
    deadline: Instant,
) -> Result<Option<u64>, PackCommitError> {
    if deadline <= Instant::now() {
        return Err(refuse("verifier deadline elapsed during artifact read-back"));
    }
    let path = path.to_path_buf();
    let expected_length = artifact.verified_length();
    let expected_sha = artifact.verified_sha256().as_str().to_owned();
    let task = tokio::task::spawn_blocking(move || {
        let _lease = lease;
        readback_blocking(&path, expected_length, &expected_sha, header, deadline)
    });
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(refuse("verified artifact read-back task failed")),
        Err(_) => Err(refuse("verified artifact read-back is retained until it exits")),
    }
}

/// Streaming synchronous re-read: bounded memory, one deadline check per chunk.
/// The digest/length checks keep the exact refusal wording of the previous
/// Tokio-FS implementation.
fn readback_blocking(
    path: &Path,
    expected_length: u64,
    expected_sha: &str,
    header: bool,
    deadline: Instant,
) -> Result<Option<u64>, PackCommitError> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|_| refuse("verified artifact copy cannot be reopened"))?;
    let mut hasher = Sha256::new();
    let mut length = 0u64;
    let mut buffer = vec![0u8; READBACK_CHUNK];
    let mut head = [0u8; PACK_HEADER_BYTES];
    loop {
        if Instant::now() >= deadline {
            return Err(refuse("verifier deadline elapsed during artifact read-back"));
        }
        let read = file.read(&mut buffer).map_err(|_| refuse("verified artifact copy cannot be read back"))?;
        if read == 0 {
            break;
        }
        if length < PACK_HEADER_BYTES as u64 {
            let offset = length as usize;
            let take = read.min(PACK_HEADER_BYTES - offset);
            head[offset..offset + take].copy_from_slice(&buffer[..take]);
        }
        length = length.checked_add(read as u64).ok_or_else(|| refuse("artifact read-back length overflowed"))?;
        if length > expected_length {
            return Err(refuse("artifact read-back is longer than the registered length"));
        }
        hasher.update(&buffer[..read]);
    }
    if length != expected_length {
        return Err(refuse("artifact read-back is shorter than the registered length"));
    }
    if hex::encode(hasher.finalize()) != expected_sha {
        return Err(refuse("artifact read-back digest is not the registered digest"));
    }
    if !header {
        return Ok(None);
    }
    if length < PACK_HEADER_BYTES as u64 {
        return Err(refuse("registered pack is shorter than a pack header"));
    }
    parse_pack_header(&head).map(Some)
}

/// Fixed 12-byte admission: magic, version 2/3, declared object count.
fn parse_pack_header(header: &[u8; PACK_HEADER_BYTES]) -> Result<u64, PackCommitError> {
    if &header[..4] != b"PACK" {
        return Err(refuse("registered artifact is not a native pack file"));
    }
    let version = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    if version != 2 && version != 3 {
        return Err(refuse("registered pack uses an unsupported pack version"));
    }
    Ok(u64::from(u32::from_be_bytes([header[8], header[9], header[10], header[11]])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_pack_v2_and_v3_headers_are_admitted() {
        let mut header = [0u8; PACK_HEADER_BYTES];
        header[..4].copy_from_slice(b"PACK");
        header[4..8].copy_from_slice(&2u32.to_be_bytes());
        header[8..12].copy_from_slice(&7u32.to_be_bytes());
        assert_eq!(parse_pack_header(&header).expect("v2 header"), 7);
        header[4..8].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(parse_pack_header(&header).expect("v3 header"), 7);
        header[4..8].copy_from_slice(&4u32.to_be_bytes());
        assert!(parse_pack_header(&header).is_err());
        header[4..8].copy_from_slice(&2u32.to_be_bytes());
        header[..4].copy_from_slice(b"pack");
        assert!(parse_pack_header(&header).is_err());
    }
}
