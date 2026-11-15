//! Unified immutable Blob layer for design §4.1/§12/§17 (W1-B / W1-C).
//!
//! Owns the provider-independent contract (`BlobLocator`, `UploadIntent`,
//! `BlobReceipt`, `BlobBackendIdentity`), OpenDAL driver (`opendal`, `transfer`,
//! `readback`), sealed write gate (`protected`), explicit encryption policy &
//! authenticated `KeyProvider` envelopes (`encryption_config`, `envelope`,
//! `encrypted_transfer`, `key_provider`), closure read-back proofs (`closure`),
//! and bounded disposable scratch Git view isolation (`disposable_view`).

pub(crate) mod archive;
mod backend_identity;
pub mod budget;
pub mod closure;
pub mod config;
pub mod disposable_view;
pub mod encrypted_transfer;
pub mod encryption_config;
pub mod envelope;
pub mod key_provider;
pub mod opendal;
pub mod protected;
pub mod readback;
pub mod transfer;
mod types;
pub mod upload;

pub use backend_identity::BlobBackendIdentity;
pub use transfer::BlobReceipt;
pub use types::{
    BLOB_LOCATOR_SCHEMA, BlobDeletePolicy, BlobError, BlobLocator, BlobProvider, MAX_NAMESPACE_BYTES, MAX_OBJECT_BYTES,
    UploadIntent,
};

#[cfg(test)]
mod budget_tests;
#[cfg(test)]
mod closure_view_tests;
#[cfg(test)]
mod envelope_tests;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod provider_contract_tests;
#[cfg(test)]
pub(crate) mod test_support;
