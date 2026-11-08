//! Verified download of the exact registered artifacts.
//!
//! Every byte that native Git later validates is the result of a real
//! `BlobStore::get_to_file` GET of the *registered* locator (tenant, authority,
//! generation, attempt, namespace, sha256, length), which itself streams the
//! provider object into a private staging file and verifies SHA-256 and length
//! before the atomic rename. The verifier then re-reads the local copy and
//! independently recomputes SHA-256 and length, so the values native Git sees are
//! the values the registration recorded and the plan planned.
//!
//! Nothing here uses `head`/`stat`/`ETag`/`LIST` as evidence, and nothing here
//! opens a caller-supplied path: the destination names are generated inside the
//! verifier's own 0700 view.
//!
//! Admission reads exactly the fixed 12-byte pack header (magic, version, object
//! count) to enforce the frozen total-object bound. The verifier never parses
//! further: native Git remains the content validator.
use super::refuse;
use super::validate::artifact_of;
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::core::pack_commit::artifact::{RegisteredArtifact, RegisteredPack};
use crate::ref_store::core::pack_commit::contract::PackArtifactRole;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::io::AsyncReadExt;

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
pub(super) async fn fetch_pair(
    store: &BlobStore,
    pack: &RegisteredPack,
    incoming: &Path,
    index: usize,
    deadline: Instant,
) -> Result<PairInput, PackCommitError> {
    let pack_artifact = artifact_of(pack, PackArtifactRole::Pack)?;
    let idx_artifact = artifact_of(pack, PackArtifactRole::Idx)?;
    let stem = format!("pair-{index:02}");
    let pack_path = incoming.join(format!("{stem}.pack"));
    let idx_path = incoming.join(format!("{stem}.idx"));
    for (artifact, destination) in [(pack_artifact, &pack_path), (idx_artifact, &idx_path)] {
        let locator =
            artifact.locator().blob_locator().map_err(|_| refuse("registered locator cannot be reconstructed"))?;
        store
            .get_to_file(&locator, destination, deadline)
            .await
            .map_err(|_| refuse("verified Blob read of a registered artifact failed"))?;
        readback(destination, artifact, deadline).await?;
    }
    // Admission only: the fixed pack header supplies the declared object count.
    let objects = pack_objects(&pack_path).await?;
    let sha256 = pack_artifact.verified_sha256().as_str().to_owned();
    Ok(PairInput { pack: pack_path, idx: idx_path, sha256, objects })
}

/// Independent SHA-256 + length re-read of the downloaded copy.
async fn readback(path: &Path, artifact: &RegisteredArtifact, deadline: Instant) -> Result<(), PackCommitError> {
    let mut file =
        tokio::fs::File::open(path).await.map_err(|_| refuse("verified artifact copy cannot be reopened"))?;
    let mut hasher = Sha256::new();
    let mut length = 0u64;
    let mut buffer = vec![0u8; READBACK_CHUNK];
    loop {
        if Instant::now() >= deadline {
            return Err(refuse("verifier deadline elapsed during artifact read-back"));
        }
        let read = file.read(&mut buffer).await.map_err(|_| refuse("verified artifact copy cannot be read back"))?;
        if read == 0 {
            break;
        }
        length = length.checked_add(read as u64).ok_or_else(|| refuse("artifact read-back length overflowed"))?;
        if length > artifact.verified_length() {
            return Err(refuse("artifact read-back is longer than the registered length"));
        }
        hasher.update(&buffer[..read]);
    }
    if length != artifact.verified_length() {
        return Err(refuse("artifact read-back is shorter than the registered length"));
    }
    if hex::encode(hasher.finalize()) != artifact.verified_sha256().as_str() {
        return Err(refuse("artifact read-back digest is not the registered digest"));
    }
    Ok(())
}

/// Read only the fixed pack header for admission; Git validates the content.
async fn pack_objects(path: &Path) -> Result<u64, PackCommitError> {
    let mut file = tokio::fs::File::open(path).await.map_err(|_| refuse("verified pack copy cannot be reopened"))?;
    let mut header = [0u8; PACK_HEADER_BYTES];
    file.read_exact(&mut header).await.map_err(|_| refuse("registered pack is shorter than a pack header"))?;
    parse_pack_header(&header)
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
