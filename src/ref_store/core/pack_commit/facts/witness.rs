//! Durable LFS byte witness boundary and native byte verification.
//!
//! The decisions/integration owner implements [`LfsByteWitness`] from the real
//! durable `lfs_objects(state = 'ready')` row plus the local LFS object path. The
//! witness carries **facts**, never a verdict: the native facts engine opens the
//! file itself, streams it once with a fixed buffer and recomputes SHA-256 and
//! length. A caller-supplied `true` is never enough, and a missing witness fact
//! fails the ref closed (it is not "allow all").
//!
//! This local availability evidence is honest: it is not a durable Blob receipt
//! or remote hold. The facts API reports that limitation and never promotes it to
//! a publication guarantee.
use crate::ref_store::core::pack_commit::error::PackCommitError;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Largest single LFS object the native engine will re-hash inline. A larger
/// declared size cannot be verified under the fixed native deadline, so the
/// pointer-bearing ref fails closed instead of being allowed unverified.
pub(crate) const LFS_MAX_OBJECT_BYTES: u64 = 256 * 1024 * 1024;

/// One owned LOCAL byte location for a pointer.
///
/// This is not a durable remote Blob receipt and never becomes one: it only lets
/// the native engine re-hash bytes that happen to exist locally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LfsByteLocation {
    path: PathBuf,
}

impl LfsByteLocation {
    /// Only an absolute path is accepted: the native engine never resolves a
    /// caller-supplied relative path against its own workspace.
    #[cfg(test)]
    fn new(path: PathBuf) -> Result<Self, PackCommitError> {
        if !path.is_absolute() {
            return Err(PackCommitError::Invalid("durable LFS byte location must be an absolute path"));
        }
        Ok(Self { path })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// A real immutable remote Blob receipt/hold would attest these exact bytes.
    /// This slice wires no such attestation, so an owned local LFS path can never
    /// mint durability; local re-hash evidence stays local-only.
    pub(crate) fn remote_attested(&self) -> bool {
        false
    }
}

/// Durable LFS byte facts. Implemented by the decisions/integration owner.
pub(crate) trait LfsByteWitness: Send + Sync {
    /// `Ok(None)` is a missing durable fact, never an implicit allow.
    fn locate(&self, oid_hex: &str, size: u64) -> Result<Option<LfsByteLocation>, PackCommitError>;
}

/// Fail-closed witness used when no durable LFS byte facts are wired yet: every
/// pointer has a missing fact, so every pointer-bearing ref is rejected.
pub(crate) struct NoDurableLfsBytes;

impl LfsByteWitness for NoDurableLfsBytes {
    fn locate(&self, _oid_hex: &str, _size: u64) -> Result<Option<LfsByteLocation>, PackCommitError> {
        Ok(None)
    }
}

/// Native verification of exactly one durable local object against the pointer's
/// own `oid sha256:<hex>` and `size`. Returns `true` only when the file opened, its
/// length equalled the declared size and its recomputed SHA-256 equalled the
/// declared oid. Every other outcome is `false` (fail closed). The caller runs
/// this on a blocking task that owns a verification-lease clone.
pub(crate) fn verify_local_bytes(location: &Path, oid_hex: &str, size: u64) -> bool {
    if size > LFS_MAX_OBJECT_BYTES {
        return false;
    }
    let Ok(metadata) = std::fs::symlink_metadata(location) else {
        return false;
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != size {
        return false;
    }
    let Ok(mut file) = std::fs::File::open(location) else {
        return false;
    };
    let mut buffer = vec![0u8; 64 * 1024];
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                total = match total.checked_add(read as u64) {
                    Some(total) if total <= size => total,
                    _ => return false,
                };
                hasher.update(&buffer[..read]);
            }
            Err(_) => return false,
        }
    }
    if total != size {
        return false;
    }
    hex::encode(hasher.finalize()) == oid_hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn local_bytes_must_match_oid_size_and_regular_file() {
        let root = std::env::temp_dir().join(format!("subset-lfs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("object");
        let bytes = b"hello lfs bytes";
        std::fs::File::create(&path).unwrap().write_all(bytes).unwrap();
        let oid = hex::encode(Sha256::digest(bytes));
        assert!(verify_local_bytes(&path, &oid, bytes.len() as u64));
        assert!(!verify_local_bytes(&path, &oid, bytes.len() as u64 + 1));
        assert!(!verify_local_bytes(&path, &"0".repeat(64), bytes.len() as u64));
        assert!(!verify_local_bytes(&root.join("missing"), &oid, bytes.len() as u64));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn relative_byte_locations_are_refused() {
        assert!(LfsByteLocation::new(PathBuf::from("relative/path")).is_err());
        assert!(LfsByteLocation::new(PathBuf::from("/absolute/path")).is_ok());
        assert!(NoDurableLfsBytes.locate(&"a".repeat(64), 1).unwrap().is_none());
    }
}
