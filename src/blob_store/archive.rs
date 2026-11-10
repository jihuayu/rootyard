//! Sealed content-transfer surface for the offline paired backup/restore (#120).
//!
//! The paired workflow is the only subsystem besides the protected uploader
//! that touches v1 Blob bytes directly, and it needs two capabilities the
//! ordinary surfaces deliberately do not offer:
//!
//! * **export**: stream the exact bytes at an already published attempt
//!   locator into a private local file, because the archive must carry the
//!   provider bytes while the source repository is stopped and must not depend
//!   on the source provider afterwards;
//! * **same-coordinate rebuild**: publish a missing object back at its *exact*
//!   original locator (same tenant, authority, generation, attempt id,
//!   namespace, digest and length) so a restored PostgreSQL snapshot keeps its
//!   immutable registered-artifact, hold and ACK metadata verbatim.
//!
//! Both are only reachable through the opaque [`OfflineRestorePermit`] defined
//! by the backup module. It has private fields and a constructor visible only
//! inside `crate::backup`, and the backup code issues one only after the
//! archive manifest/inventory, the isolated empty target and the real
//! PostgreSQL restore locks were verified. No route, worker or other subsystem
//! can construct one, so `archive` never becomes a general write surface.
//!
//! Rebuilding uses the ordinary single-use [`UploadIntent`] minted here from
//! the locator carried inside the permit (the normal [`BlobStore::new_upload`]
//! still only ever mints a fresh random attempt), the sealed raw writer and
//! its provider read-back verifier. Presence is a length-only stat: an object
//! with the archived length must read back exactly and is then reused, an
//! object with another length or different bytes is refused, and only a
//! confirmed absence is published. Nothing is ever overwritten or deleted.
use std::path::Path;
use std::time::Instant;

use sha2::{Digest, Sha256};

use super::{BlobError, BlobLocator, opendal::BlobStore};

/// Outcome of one same-coordinate rebuild attempt. It is a claim made only
/// from provider bytes actually read back, never from a stat/ETag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rebuild {
    /// The exact locator already held the exact bytes; nothing was written.
    AlreadyExact,
    /// The object was absent and was published through the sealed writer at
    /// its exact original locator.
    Rebuilt,
}

/// Sealed byte-transfer handle over one opened v1 Blob store.
pub(crate) struct ArchiveTransfer {
    store: BlobStore,
}

impl ArchiveTransfer {
    /// The same-coordinate restore surface. The handle itself carries no
    /// permission: every rebuild is checked against a borrowed
    /// [`crate::backup::OfflineRestorePermit`] before any provider IO.
    pub(crate) fn new(store: BlobStore) -> Self {
        Self { store }
    }

    /// The offline export surface (stream/verify exact locators only). It has
    /// no rebuild method, so the borrowed read witness cannot reach a write.
    pub(crate) fn for_export(read: &crate::backup::ArchiveRead, store: BlobStore) -> Self {
        let _ = read.admit();
        Self { store }
    }

    /// Non-secret physical backend identity of the opened store.
    pub(crate) fn backend_identity_hex(&self) -> &str {
        self.store.backend_identity().as_hex()
    }

    pub(crate) fn provider(&self) -> &'static str {
        self.store.provider().as_str()
    }

    /// Absolute deadline admission; no provider IO.
    pub(crate) fn live(&self, deadline: Instant) -> bool {
        Instant::now() < deadline
    }

    /// Stream exactly the expected content of `locator` into a new private
    /// file. The provider bytes are verified against the expected SHA-256 and
    /// length before the private rename; a length-only stat is never accepted.
    /// The committed member is returned with the exact length.
    pub(crate) async fn export(
        &self,
        read: &crate::backup::ArchiveRead,
        locator: &BlobLocator,
        expected_sha256: &str,
        expected_length: u64,
        destination: &Path,
        deadline: Instant,
    ) -> Result<u64, BlobError> {
        let _ = read.admit();
        if locator.sha256() != expected_sha256 || locator.length() != expected_length {
            return Err(BlobError::DigestMismatch {
                expected: expected_sha256.to_owned(),
                actual: locator.sha256().to_owned(),
            });
        }
        self.store.get_to_file(locator, destination, deadline).await?;
        let length = std::fs::symlink_metadata(destination).map_err(|_| BlobError::NotFound)?.len();
        if length != expected_length {
            let _ = std::fs::remove_file(destination);
            return Err(BlobError::LengthMismatch { expected: expected_length, actual: length });
        }
        Ok(length)
    }

    /// Full verified read-back of one exact locator (SHA-256 + length).
    pub(crate) async fn verify_for_export(
        &self,
        read: &crate::backup::ArchiveRead,
        locator: &BlobLocator,
        deadline: Instant,
    ) -> Result<(), BlobError> {
        let _ = read.admit();
        self.store.verify(locator, deadline).await.map(|_| ())
    }

    /// Make `locator` hold the archive bytes, at that exact locator.
    ///
    /// 1. An exact readable copy is reused (nothing is written).
    /// 2. Otherwise a confirmed absence is published through the sealed writer
    ///    at the exact locator, with the archive's digest and length only.
    /// 3. A present-but-different object, an unreadable provider or an unknown
    ///    outcome is refused; nothing is overwritten or deleted.
    pub(crate) async fn rebuild(
        &self,
        permit: &crate::backup::OfflineRestorePermit,
        locator: &BlobLocator,
        archive: &Path,
        archive_sha256: &str,
        deadline: Instant,
    ) -> Result<Rebuild, BlobError> {
        // Permit first, before any local or provider IO: the locator must be
        // exactly the one issued for this artifact, on this physical backend.
        if !permit.verify(locator, self.store.backend_identity().as_hex()) {
            return Err(BlobError::ForeignBackend);
        }
        if locator.sha256() != archive_sha256 {
            return Err(BlobError::DigestMismatch {
                expected: archive_sha256.to_owned(),
                actual: locator.sha256().to_owned(),
            });
        }
        // Cheap local admission and a local digest of exactly the bytes that
        // will be published, before any provider request.
        let expected_sha256 = archive_sha256.to_owned();
        let path = archive.to_path_buf();
        let declared = expected_sha256.clone();
        // The local hash is a bounded blocking task; the caller's absolute
        // deadline bounds the wait, and the task itself releases its slot even
        // if it finishes late.
        let local = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            tokio::task::spawn_blocking(move || local_digest(&path, &declared)),
        )
        .await
        .map_err(|_| BlobError::DeadlineExceeded)?
        .map_err(|_| BlobError::Provider("archive digest task failed".into()))??;
        if local != expected_sha256 {
            return Err(BlobError::DigestMismatch { expected: expected_sha256, actual: local });
        }
        // Presence is decided by a length-only stat first: an object that exists
        // with a different length is a hard refusal (never overwritten), an
        // object with the archive length must read back exactly, and only a
        // confirmed absence may be rebuilt.
        match self.store.head(locator, deadline).await? {
            Some(length) if length == locator.length() => {
                return match self.store.verify(locator, deadline).await {
                    Ok(receipt) if receipt.verified_sha256() == locator.sha256() => Ok(Rebuild::AlreadyExact),
                    Ok(_) => Err(BlobError::Provider("existing object read back different bytes".into())),
                    Err(BlobError::DigestMismatch { .. }) => {
                        Err(BlobError::Provider("existing object at the archive locator differs".into()))
                    }
                    Err(error) => Err(error),
                };
            }
            Some(_) => {
                return Err(BlobError::Provider(
                    "existing object at the archive locator has another length; refusing to overwrite".into(),
                ));
            }
            None => {}
        }
        // Absent: mint the one-use intent at the exact original locator through
        // the private constructor, then the ordinary sealed writer + read-back.
        let intent = self.store.intent_for_locator(locator.clone()).ok_or(BlobError::ForeignBackend)?;
        let receipt = self.store.put_file(intent, archive, deadline).await?;
        if receipt.locator() != locator
            || receipt.backend_identity().as_hex() != self.store.backend_identity().as_hex()
            || receipt.verified_sha256() != locator.sha256()
            || receipt.verified_length() != locator.length()
        {
            return Err(BlobError::ForeignBackend);
        }
        Ok(Rebuild::Rebuilt)
    }
}

/// SHA-256 of a private archive member. Opened once with
/// `O_NOFOLLOW|O_NONBLOCK` so a swapped symlink or FIFO can never block or
/// redirect the digest of the bytes about to be published.
fn local_digest(path: &Path, expected: &str) -> Result<String, BlobError> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| BlobError::NotFound)?;
    if !file.metadata().map_err(|_| BlobError::NotFound)?.is_file() {
        return Err(BlobError::Config("expected a regular archive file".into()));
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 128 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|_| BlobError::Provider("archive read failed".into()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hex::encode(hasher.finalize());
    if actual != expected {
        return Err(BlobError::DigestMismatch { expected: expected.to_owned(), actual });
    }
    Ok(actual)
}
