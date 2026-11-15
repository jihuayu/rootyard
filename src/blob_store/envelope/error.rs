//! Typed fail-closed errors for authenticated Blob envelopes.

use std::fmt;

use crate::blob_store::{BlobError, key_provider::KeyProviderError};

#[derive(Debug)]
pub enum EnvelopeError {
    Io(&'static str),
    Config(String),
    Blob(BlobError),
    KeyProvider(KeyProviderError),
    ForeignBackend,
    EncryptionPolicyMismatch,
    UnsupportedFormat(String),
    MetadataCorrupt(&'static str),
    CiphertextCorrupt(&'static str),
    PlaintextMismatch(&'static str),
}

impl From<BlobError> for EnvelopeError {
    fn from(value: BlobError) -> Self {
        match value {
            BlobError::ForeignBackend => Self::ForeignBackend,
            other => Self::Blob(other),
        }
    }
}

impl From<KeyProviderError> for EnvelopeError {
    fn from(value: KeyProviderError) -> Self {
        Self::KeyProvider(value)
    }
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(reason) => write!(f, "blob envelope IO error: {reason}"),
            Self::Config(msg) => write!(f, "blob envelope config error: {msg}"),
            Self::Blob(err) => write!(f, "{err}"),
            Self::KeyProvider(err) => write!(f, "key provider failure: {err}"),
            Self::ForeignBackend => f.write_str("blob envelope target belongs to a different physical backend"),
            Self::EncryptionPolicyMismatch => f.write_str("blob store encryption policy conflicts with request"),
            Self::UnsupportedFormat(msg) => write!(f, "unsupported envelope format: {msg}"),
            Self::MetadataCorrupt(reason) => write!(f, "corrupt envelope metadata: {reason}"),
            Self::CiphertextCorrupt(reason) => write!(f, "corrupt envelope ciphertext: {reason}"),
            Self::PlaintextMismatch(reason) => write!(f, "decrypted plaintext verification failed: {reason}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}
