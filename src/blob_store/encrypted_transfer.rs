//! Encrypted Blob transfer and verified read-back helpers on [`BlobStore`].
//!
//! Raw single-object publishing stays sealed behind `pub(super)`:
//! [`BlobStore::put_encrypted_file`] inherits the exact same `blob_store`-only
//! boundary as [`BlobStore::put_file`], while public methods cover verified
//! read-back, decryption, and [`EncryptedBlobReceipt`] minting.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use deadpool_postgres::Pool;
use uuid::Uuid;

use super::{
    BlobBackendIdentity, BlobError, BlobLocator, BlobReceipt, UploadIntent,
    envelope::{
        EnvelopeError, EnvelopeMetadata, PreparedCiphertext, SealedCiphertext, create_private_temp_file,
        ensure_local_envelope_provider, open_ciphertext_file_to_path, verify_ciphertext_file, verify_staging_dir,
    },
    key_provider::{KeyId, KeyProvider},
    opendal::BlobStore,
    protected::{ProtectedUploadError, ProtectedUploader},
};
use crate::ref_store::core::artifact_hold::ArtifactGrant;

/// Read-only acknowledgement combining a verified provider ciphertext
/// [`BlobReceipt`] with local AEAD envelope authentication against a live
/// [`KeyProvider`]. There is no public constructor or `Deserialize`.
#[derive(Debug, Clone)]
pub struct EncryptedBlobReceipt {
    receipt: BlobReceipt,
    backend_identity: BlobBackendIdentity,
    key_id: KeyId,
    envelope_id: Uuid,
    plaintext_sha256: String,
    plaintext_length: u64,
}

impl EncryptedBlobReceipt {
    pub fn receipt(&self) -> &BlobReceipt {
        &self.receipt
    }

    pub fn locator(&self) -> &BlobLocator {
        self.receipt.locator()
    }

    pub fn backend_identity(&self) -> &BlobBackendIdentity {
        &self.backend_identity
    }

    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    pub fn envelope_id(&self) -> Uuid {
        self.envelope_id
    }

    pub fn plaintext_sha256(&self) -> &str {
        &self.plaintext_sha256
    }

    pub fn plaintext_length(&self) -> u64 {
        self.plaintext_length
    }
}

impl BlobStore {
    /// Subtree-private sealed publish of a prepared, wrapped ciphertext staging
    /// file. Enforces backend binding and store encryption policy before IO.
    pub(super) async fn put_encrypted_file(
        &self,
        intent: UploadIntent,
        sealed: SealedCiphertext,
        deadline: Instant,
    ) -> Result<(BlobReceipt, EnvelopeMetadata), EnvelopeError> {
        ensure_store_allows_local_envelope(self, deadline)?;
        if intent.backend_identity().as_hex() != self.backend_identity().as_hex() {
            return Err(EnvelopeError::ForeignBackend);
        }
        if !sealed.metadata().matches_locator(intent.locator()) {
            return Err(EnvelopeError::MetadataCorrupt("envelope metadata does not match upload intent"));
        }
        let locator = intent.locator().clone();
        let receipt = self.put_file(intent, sealed.ciphertext_path(), deadline).await?;
        if !receipt.matches(&locator)
            || receipt.provider() != self.provider()
            || receipt.backend_identity().as_hex() != self.backend_identity().as_hex()
        {
            return Err(EnvelopeError::ForeignBackend);
        }
        let (_guard, metadata) = sealed.into_parts();
        Ok((receipt, metadata))
    }

    /// Download, provider-verify, decrypt and authenticate an encrypted Blob
    /// object into `destination`, returning a read-only [`EncryptedBlobReceipt`].
    pub async fn get_decrypted_to_file(
        &self,
        locator: &BlobLocator,
        metadata: &EnvelopeMetadata,
        key_provider: &Arc<dyn KeyProvider>,
        destination: &Path,
        deadline: Instant,
    ) -> Result<EncryptedBlobReceipt, EnvelopeError> {
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or(EnvelopeError::Io("destination path lacks a parent directory"))?;
        if destination.file_name().is_none() {
            return Err(EnvelopeError::Io("destination path lacks a file name"));
        }
        self.fetch_and_open_inner(locator, metadata, key_provider, parent, Some(destination), deadline).await
    }

    /// Perform full provider read-back plus local chunked AEAD & key-unwrap
    /// verification using `staging_dir` for temporary ciphertext, leaving no
    /// plaintext file behind.
    pub async fn verify_encrypted_blob(
        &self,
        locator: &BlobLocator,
        metadata: &EnvelopeMetadata,
        key_provider: &Arc<dyn KeyProvider>,
        staging_dir: &Path,
        deadline: Instant,
    ) -> Result<EncryptedBlobReceipt, EnvelopeError> {
        self.fetch_and_open_inner(locator, metadata, key_provider, staging_dir, None, deadline).await
    }

    async fn fetch_and_open_inner(
        &self,
        locator: &BlobLocator,
        metadata: &EnvelopeMetadata,
        key_provider: &Arc<dyn KeyProvider>,
        staging_dir: &Path,
        destination: Option<&Path>,
        deadline: Instant,
    ) -> Result<EncryptedBlobReceipt, EnvelopeError> {
        ensure_store_allows_local_envelope(self, deadline)?;
        ensure_local_envelope_provider(key_provider.as_ref())?;
        metadata.validate()?;
        if !metadata.matches_locator(locator) {
            return Err(EnvelopeError::MetadataCorrupt("envelope metadata does not match requested locator"));
        }
        verify_staging_dir(staging_dir)?;

        let label = if destination.is_some() { "dl" } else { "vf" };
        let (ct_guard, ct_file) = create_private_temp_file(staging_dir, label)?;
        drop(ct_file);
        self.get_to_file(locator, ct_guard.path(), deadline).await?;
        let receipt =
            self.verify_receipt(locator, metadata.ciphertext_sha256(), metadata.ciphertext_length(), deadline).await?;
        if receipt.backend_identity().as_hex() != self.backend_identity().as_hex() {
            return Err(EnvelopeError::ForeignBackend);
        }

        let meta_owned = metadata.clone();
        let kp = Arc::clone(key_provider);
        let ct_path = ct_guard.path().to_path_buf();
        let dest_owned: Option<PathBuf> = destination.map(Path::to_path_buf);
        let digest = tokio::task::spawn_blocking(move || match dest_owned.as_deref() {
            Some(dest) => open_ciphertext_file_to_path(&meta_owned, kp.as_ref(), &ct_path, dest),
            None => verify_ciphertext_file(&meta_owned, kp.as_ref(), &ct_path),
        })
        .await
        .map_err(|_| EnvelopeError::Io("envelope verification task failed"))??;

        let key_id = metadata.key_id()?;
        Ok(EncryptedBlobReceipt {
            backend_identity: receipt.backend_identity().clone(),
            receipt,
            key_id,
            envelope_id: metadata.envelope_id(),
            plaintext_sha256: digest.sha256().to_owned(),
            plaintext_length: digest.length(),
        })
    }
}

pub(super) fn ensure_store_allows_local_envelope(store: &BlobStore, deadline: Instant) -> Result<(), EnvelopeError> {
    if Instant::now() >= deadline {
        return Err(EnvelopeError::Blob(BlobError::DeadlineExceeded));
    }
    let enc = store.profile().encryption();
    if enc.is_explicit() && !enc.is_local_envelope() {
        return Err(EnvelopeError::EncryptionPolicyMismatch);
    }
    Ok(())
}

/// Immutable per-slot proof returned by [`ProtectedUploader::consume_and_upload_encrypted`].
#[derive(Clone, Debug)]
pub struct ProtectedEncryptedReceipt {
    hold_id: Uuid,
    slot: i32,
    receipt: BlobReceipt,
    metadata: EnvelopeMetadata,
}

impl ProtectedEncryptedReceipt {
    pub fn hold_id(&self) -> Uuid {
        self.hold_id
    }

    pub fn slot(&self) -> i32 {
        self.slot
    }

    pub fn receipt(&self) -> &BlobReceipt {
        &self.receipt
    }

    pub fn metadata(&self) -> &EnvelopeMetadata {
        &self.metadata
    }
}

/// Immutable batch publication proof pairing durable hold IDs, verified
/// ciphertext receipts, and wrapped `EnvelopeMetadata`.
#[derive(Clone, Debug)]
pub struct ProtectedEncryptedPublication {
    acquire_request_id: Uuid,
    consume_request_id: Uuid,
    receipts: Vec<ProtectedEncryptedReceipt>,
}

impl ProtectedEncryptedPublication {
    pub fn acquire_request_id(&self) -> Uuid {
        self.acquire_request_id
    }

    pub fn consume_request_id(&self) -> Uuid {
        self.consume_request_id
    }

    pub fn receipts(&self) -> &[ProtectedEncryptedReceipt] {
        &self.receipts
    }

    pub fn is_complete(&self) -> bool {
        !self.receipts.is_empty()
    }
}

/// Typed failures of grant-gated encrypted uploads. Errors with `slot: None`
/// occur before consuming the PostgreSQL grant; errors with `slot: Some(_)`
/// retain the consumed hold and surface the underlying envelope/upload failure.
pub enum ProtectedEncryptedUploadError {
    Grant(ProtectedUploadError),
    Envelope { slot: Option<i32>, error: EnvelopeError },
}

impl From<ProtectedUploadError> for ProtectedEncryptedUploadError {
    fn from(error: ProtectedUploadError) -> Self {
        Self::Grant(error)
    }
}

impl fmt::Display for ProtectedEncryptedUploadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grant(error) => write!(formatter, "{error}"),
            Self::Envelope { slot: Some(slot), error } => {
                write!(formatter, "protected encrypted upload of slot {slot} failed; the hold stays retained: {error}")
            }
            Self::Envelope { slot: None, error } => {
                write!(formatter, "protected encrypted upload preflight refused before consume: {error}")
            }
        }
    }
}

impl fmt::Debug for ProtectedEncryptedUploadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ProtectedEncryptedUploadError {}

impl ProtectedUploader {
    /// Grant-gated local-envelope publish: verifies store encryption mode and
    /// `key_provider` capabilities *before* checking out a PostgreSQL
    /// connection, consumes `grant` on one short-lived connection, drops the
    /// lease before wrapping or IO, binds each DEK to the consumed upload
    /// intent locator, and publishes via the sealed [`BlobStore::put_encrypted_file`].
    pub async fn consume_and_upload_encrypted(
        &self,
        pool: &Pool,
        grant: ArtifactGrant,
        prepared: Vec<PreparedCiphertext>,
        key_provider: &Arc<dyn KeyProvider>,
        deadline: Instant,
    ) -> Result<ProtectedEncryptedPublication, ProtectedEncryptedUploadError> {
        ensure_store_allows_local_envelope(self.store(), deadline)
            .map_err(|error| ProtectedEncryptedUploadError::Envelope { slot: None, error })?;
        ensure_local_envelope_provider(key_provider.as_ref())
            .map_err(|error| ProtectedEncryptedUploadError::Envelope { slot: None, error })?;
        let count = prepared.len();
        let (acquire_request_id, consume_request_id, uploads) =
            self.consume_grant_for_count(pool, grant, count, deadline).await?;
        let mut prep_iter = prepared.into_iter();
        let mut receipts = Vec::with_capacity(uploads.len());
        for upload in uploads {
            let slot = upload.slot;
            let Some(prep) = prep_iter.next() else {
                return Err(ProtectedUploadError::MissingSource { slot }.into());
            };
            let locator = upload.intent.locator().clone();
            let sealed = prep
                .bind_and_wrap(key_provider.as_ref(), &locator)
                .map_err(|error| ProtectedEncryptedUploadError::Envelope { slot: Some(slot), error })?;
            let (receipt, metadata) = self
                .store()
                .put_encrypted_file(upload.intent, sealed, deadline)
                .await
                .map_err(|error| ProtectedEncryptedUploadError::Envelope { slot: Some(slot), error })?;
            receipts.push(ProtectedEncryptedReceipt { hold_id: upload.hold_id, slot, receipt, metadata });
        }
        Ok(ProtectedEncryptedPublication { acquire_request_id, consume_request_id, receipts })
    }
}
