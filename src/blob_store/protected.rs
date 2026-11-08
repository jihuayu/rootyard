//! Protected uploader: the only production caller of the sealed raw Blob write.
//!
//! This module is a child of `blob_store`, so it can reach
//! [`BlobStore::put_file`](super::opendal::BlobStore::put_file) (`pub(super)`).
//! It never exposes that writer: callers hand it an opaque
//! [`ArtifactGrant`](crate::ref_store::core::artifact_hold::ArtifactGrant), and
//! the uploader returns only an immutable publication receipt:
//!
//! 1. the grant is checked against this uploader's *actually opened* store
//!    before anything else: its immutable ACK and every granted hold must name
//!    this store's physical backend identity hex and provider, otherwise the
//!    upload is refused as `ForeignBackend` - no pool checkout, no durable
//!    consume, no provider IO. This rejects the same provider with another
//!    bucket/container, root prefix, region, endpoint or account just as it
//!    rejects another provider;
//! 2. the caller's source list is checked against the grant's stable slot
//!    count *before* any pool checkout or consumption, so an obviously
//!    malformed call burns nothing and takes no connection;
//! 3. one pooled PostgreSQL connection is checked out under the same absolute
//!    deadline, and `PgArtifactHoldStore::consume` moves the grant and opens
//!    one owned short PostgreSQL transaction on that connection. Only a
//!    positive consume `COMMIT` acknowledgement yields the private one-shot
//!    token; any error, timeout or unknown completion drops the intents and
//!    uploads nothing;
//! 4. that pooled connection is explicitly dropped (returned to the pool)
//!    *before* any Blob/provider IO, so no PostgreSQL client, transaction or
//!    pool lease is alive while a provider upload or read-back is pending;
//! 5. **after** the acknowledgement and the connection return (never inside
//!    the transaction) each opaque intent is passed by value to the sealed raw
//!    writer. The writer streams the local file, refuses a length/digest
//!    mismatch, and mints a [`BlobReceipt`](super::BlobReceipt) only after a
//!    full provider read-back reproduced the exact length and SHA-256. The
//!    receipt must also name this store's provider and physical backend
//!    identity; a receipt from any other target is a hard mismatch.
//!
//! The resulting receipt is therefore the only byte proof in this slice. A
//! successful acquire/consume ACK is never treated as proof that provider bytes
//! exist, and a reboot can only read-verify a recorded locator - it can never
//! reconstruct an upload intent or retry the same attempt path.
//!
//! No route, runtime profile or service entry point is added here, and there is
//! no release/delete of a hold or a remote object.
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use deadpool_postgres::Pool;
use uuid::Uuid;

use super::opendal::BlobStore;
use super::{BlobError, BlobReceipt};
use crate::ref_store::core::artifact_hold::{
    ArtifactGrant, ArtifactHoldError, ConsumedArtifacts, ConsumedUpload, PgArtifactHoldStore,
};

/// One caller-provided local source. The bytes must hash/length-match the
/// artifact specification that produced the corresponding granted intent, and
/// only a regular file is accepted (the raw writer enforces that).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadSource {
    path: PathBuf,
}

impl UploadSource {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Immutable per-artifact publication proof.
#[derive(Clone, Debug)]
pub struct ProtectedReceipt {
    hold_id: Uuid,
    slot: i32,
    receipt: BlobReceipt,
}

impl ProtectedReceipt {
    pub fn hold_id(&self) -> Uuid {
        self.hold_id
    }
    pub fn slot(&self) -> i32 {
        self.slot
    }
    /// A verified provider read-back receipt (not a `stat`/ACK/ETag).
    pub fn receipt(&self) -> &BlobReceipt {
        &self.receipt
    }
}

/// Immutable result of one protected upload. It is created only after every
/// artifact was consumed and fully read back, so it can never be assembled from
/// database metadata alone.
#[derive(Clone, Debug)]
pub struct ProtectedPublication {
    consume_request_id: Uuid,
    receipts: Vec<ProtectedReceipt>,
}

impl ProtectedPublication {
    pub fn consume_request_id(&self) -> Uuid {
        self.consume_request_id
    }
    pub fn receipts(&self) -> &[ProtectedReceipt] {
        &self.receipts
    }
    pub fn is_complete(&self) -> bool {
        !self.receipts.is_empty()
    }
}

/// Typed failures of the protected uploader. A `Checkout` or `Consume` error
/// means the grant was moved in and burned without any provider IO, so the
/// permanent holds stay retained and caller code must not try to remint the
/// grant. A `Blob` error after a consume ACK means the hold is permanently
/// retained and no further IO is attempted for that batch.
pub enum ProtectedUploadError {
    /// The deadline expired (or the pool refused) while checking out the one
    /// short-lived PostgreSQL connection. Deliberately carries no pool error
    /// text, so connection details/credentials are never surfaced.
    Checkout,
    Consume(ArtifactHoldError),
    /// The grant names a different physical Blob backend or provider than this
    /// uploader's opened store. Raised before the pool checkout, the durable
    /// consume and any provider IO, so nothing was consumed and the permanent
    /// hold stays retained.
    ForeignBackend,
    SourceCount {
        expected: usize,
        actual: usize,
    },
    MissingSource {
        slot: i32,
    },
    Blob {
        slot: i32,
        error: BlobError,
    },
    ReceiptMismatch {
        slot: i32,
    },
}

impl fmt::Display for ProtectedUploadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Checkout => formatter.write_str(
                "protected upload could not check out a PostgreSQL connection before the deadline; no hold was consumed and the grant is burned",
            ),
            Self::Consume(error) => write!(formatter, "protected upload was not consumed: {error}"),
            Self::ForeignBackend => formatter.write_str(
                "protected upload grant belongs to a different physical Blob backend or provider; no connection was checked out, no hold was consumed and nothing was opened",
            ),
            Self::SourceCount { expected, actual } => write!(
                formatter,
                "protected upload needs exactly {expected} local sources (stable slot order), got {actual}; nothing was consumed"
            ),
            Self::MissingSource { slot } => {
                write!(formatter, "protected upload has no source for granted slot {slot}; the hold stays retained")
            }
            Self::Blob { slot, error } => {
                write!(formatter, "protected upload of slot {slot} failed; the hold stays retained: {error}")
            }
            Self::ReceiptMismatch { slot } => {
                write!(formatter, "protected upload slot {slot} returned a receipt that does not match its locator")
            }
        }
    }
}

impl fmt::Debug for ProtectedUploadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for ProtectedUploadError {}

/// Protected uploader over one Blob store. It owns no grant, holds no
/// PostgreSQL connection between calls and keeps no state between calls, so a
/// dropped future cannot leave upload authority or a pool lease behind.
#[derive(Clone)]
pub struct ProtectedUploader {
    store: BlobStore,
}

impl ProtectedUploader {
    pub fn new(store: BlobStore) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &BlobStore {
        &self.store
    }

    /// Consume `grant` durably on one short-lived pooled connection, return that
    /// connection to `pool` before any provider IO, then publish each intent
    /// exactly once through the sealed raw writer and return the full read-back
    /// receipts.
    ///
    /// The same absolute `deadline` covers the pool checkout, the consume
    /// transaction and every upload. The PostgreSQL client/transaction/pool
    /// lease is dropped before [`Self::publish`] runs, so a parked or slow
    /// provider upload cannot occupy a connection. A timeout or error leaves
    /// the consumed holds and any remote bytes retained, returns no receipt for
    /// an unknown completion, and never mints another grant.
    pub async fn consume_and_upload(
        &self,
        pool: &Pool,
        grant: ArtifactGrant,
        sources: &[UploadSource],
        deadline: Instant,
    ) -> Result<ProtectedPublication, ProtectedUploadError> {
        // Physical binding first: the grant's immutable ACK and every granted
        // hold must name this exact store, before a connection or the consume
        // transaction is even attempted.
        self.ensure_grant_backend(&grant)?;
        let expected = grant.artifact_count();
        if sources.len() != expected {
            return Err(ProtectedUploadError::SourceCount { expected, actual: sources.len() });
        }
        let tokio_deadline = tokio::time::Instant::from_std(deadline);
        let consumed = {
            let mut client = tokio::time::timeout_at(tokio_deadline, pool.get())
                .await
                .map_err(|_| ProtectedUploadError::Checkout)?
                .map_err(|_| ProtectedUploadError::Checkout)?;
            let consumed = PgArtifactHoldStore
                .consume(&mut client, grant, tokio_deadline)
                .await
                .map_err(ProtectedUploadError::Consume)?;
            // The consume transaction has committed and been dropped; return
            // the pooled connection before any Blob/provider IO starts.
            drop(client);
            consumed
        };
        self.publish(consumed, sources, deadline).await
    }

    /// Prove that the grant was minted against this opened store: the immutable
    /// ACK's physical backend identity hex and the provider recorded on every
    /// granted hold must equal this store's. Both values are non-secret data;
    /// the comparison yields a typed refusal and no detail.
    fn ensure_grant_backend(&self, grant: &ArtifactGrant) -> Result<(), ProtectedUploadError> {
        let ack = grant.ack();
        if ack.backend_identity != self.store.backend_identity().as_hex() {
            return Err(ProtectedUploadError::ForeignBackend);
        }
        let provider = self.store.provider().as_str();
        if ack.holds().iter().any(|hold| hold.artifact.provider != provider) {
            return Err(ProtectedUploadError::ForeignBackend);
        }
        Ok(())
    }

    /// Publish an already-consumed token. This is reachable only after a
    /// positive consume ACK; the token is not constructible anywhere else.
    async fn publish(
        &self,
        consumed: ConsumedArtifacts,
        sources: &[UploadSource],
        deadline: Instant,
    ) -> Result<ProtectedPublication, ProtectedUploadError> {
        let consume_request_id = consumed.consume_request_id();
        let mut uploads: Vec<ConsumedUpload> = consumed.into_uploads();
        uploads.sort_by_key(|upload| upload.slot);
        let mut receipts = Vec::with_capacity(uploads.len());
        for (index, upload) in uploads.into_iter().enumerate() {
            let source = sources.get(index).ok_or(ProtectedUploadError::MissingSource { slot: upload.slot })?;
            let locator = upload.intent.locator().clone();
            let receipt = self
                .store
                .put_file(upload.intent, source.path(), deadline)
                .await
                .map_err(|error| ProtectedUploadError::Blob { slot: upload.slot, error })?;
            // The proof must name the exact locator *and* this store's provider
            // and physical backend, so a receipt from another bucket/root/account
            // (or another provider) is never accepted as this publication.
            if !receipt.matches(&locator)
                || receipt.provider() != self.store.provider()
                || receipt.backend_identity().as_hex() != self.store.backend_identity().as_hex()
            {
                return Err(ProtectedUploadError::ReceiptMismatch { slot: upload.slot });
            }
            receipts.push(ProtectedReceipt { hold_id: upload.hold_id, slot: upload.slot, receipt });
        }
        Ok(ProtectedPublication { consume_request_id, receipts })
    }
}

impl fmt::Debug for ProtectedUploader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ProtectedUploader").field("store", &"<sealed>").finish()
    }
}
