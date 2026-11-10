//! Private minting surface for the verified Blob receipt.
//!
//! [`BlobReceipt`] is *defined* in this nested private module so its only
//! constructor is unreachable from the rest of the crate. `BlobReceipt::new` is
//! `pub(super)`, i.e. visible only inside `crate::blob_store::transfer` (and its
//! descendants). The single caller is the bounded verifier in
//! `BlobStore::verify_receipt_bounded`, which reaches it only after a
//! provider `stat` plus a full streamed provider read-back reproduced the
//! expected length and SHA-256 locally.
//!
//! The type is re-exported read-only (`transfer::BlobReceipt` ->
//! `blob_store::BlobReceipt`) so readers keep the stable public name, the
//! getters, `clone` and `matches`. What stays unavailable is the *mint*:
//! there is no `serde`/`Deserialize`, no public, `pub(crate)` or module-level
//! factory and no other `blob_store` child gets access, so no adapter, service
//! handler, checkpoint or ingestion path can forge provider-held bytes.
//!
//! A receipt binds both the provider and the exact physical
//! [`BlobBackendIdentity`] of the store that read the bytes back. `matches` is
//! deliberately locator-only metadata equality for compatibility; callers that
//! must know the bytes came from a particular backend compare
//! `receipt.backend_identity()` with the live store's identity and treat a
//! mismatch as foreign.

use std::fmt;

use crate::blob_store::{BLOB_LOCATOR_SCHEMA, BlobBackendIdentity, BlobLocator, BlobProvider};

/// Durable acknowledgement of provider-held bytes. It is issued only after a
/// fresh provider read-back (not a `stat`, not an ETag, not the local file)
/// reproduced `sha256` and `length` exactly, and it records the physical
/// backend identity of the store that performed that read-back.
#[derive(Clone, PartialEq, Eq)]
pub struct BlobReceipt {
    schema: u32,
    locator: BlobLocator,
    provider: BlobProvider,
    backend_identity: BlobBackendIdentity,
    verified_sha256: String,
    verified_length: u64,
}

impl BlobReceipt {
    /// Only the transfer verifier can mint a receipt, and only after a provider
    /// read-back: `pub(super)` limits this to `blob_store::transfer`, so no
    /// other module - not a sibling `blob_store` child, not a legacy adapter -
    /// can name it. There is no `Deserialize`/public constructor, so an
    /// untrusted receipt cannot be forged into verification.
    pub(super) fn new(
        locator: BlobLocator,
        provider: BlobProvider,
        backend_identity: BlobBackendIdentity,
        verified_sha256: String,
        verified_length: u64,
    ) -> Self {
        Self { schema: BLOB_LOCATOR_SCHEMA, locator, provider, backend_identity, verified_sha256, verified_length }
    }

    pub fn schema(&self) -> u32 {
        self.schema
    }
    pub fn locator(&self) -> &BlobLocator {
        &self.locator
    }
    pub fn provider(&self) -> BlobProvider {
        self.provider
    }
    /// Physical backend that performed the verifying read-back. Read-only data;
    /// it is not a write capability and cannot be constructed from stored hex.
    pub fn backend_identity(&self) -> &BlobBackendIdentity {
        &self.backend_identity
    }
    pub fn verified_sha256(&self) -> &str {
        &self.verified_sha256
    }
    pub fn verified_length(&self) -> u64 {
        self.verified_length
    }

    /// Metadata equality only: schema, locator and the verified digest/length.
    /// It deliberately does **not** compare the backend identity, so a receipt
    /// reloaded from an untrusted store must still pass
    /// `BlobStore::verify_receipt` against the provider, and callers that care
    /// about the physical target must also compare `backend_identity()` with
    /// the live store's identity before treating it as proof.
    pub fn matches(&self, locator: &BlobLocator) -> bool {
        self.schema == BLOB_LOCATOR_SCHEMA
            && &self.locator == locator
            && self.verified_sha256 == locator.sha256
            && self.verified_length == locator.length
    }
}

impl fmt::Debug for BlobReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobReceipt")
            .field("schema", &self.schema)
            .field("locator", &self.locator)
            .field("provider", &self.provider)
            .field("backend_identity", &self.backend_identity)
            .field("verified_sha256", &"<redacted>")
            .field("verified_length", &self.verified_length)
            .finish()
    }
}
