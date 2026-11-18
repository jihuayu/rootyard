use std::fmt;

use crate::blob_store::{BlobError, disposable_view::DisposableViewError};

#[derive(Debug)]
pub enum SafeGcError {
    DestructiveGcDisabledByDefault,
    InvalidInput(String),
    ArmingRejected(&'static str),
    IncompleteProof(&'static str),
    ProofDigestMismatch,
    ProtectionOverlap(String),
    ReaderQuiescenceUnverified(&'static str),
    DistributedPrereqsMissing(&'static str),
    StaleIncarnation(&'static str),
    StaleDeleterFenced(&'static str),
    ConcurrentRetentionRace(&'static str),
    MembershipOrRootDrift(String),
    AbaKeyReuseDetected(String),
    CompactionVerificationFailed(String),
    BlobDeleteDisabled,
    DeleteOutcomeUnknown(String),
    PartialDeleteFailure(String),
    Serialization(String),
    Blob(BlobError),
    DisposableView(DisposableViewError),
    Io(String),
}

impl From<BlobError> for SafeGcError {
    fn from(value: BlobError) -> Self {
        match value {
            BlobError::DeleteDisabled => Self::BlobDeleteDisabled,
            other => Self::Blob(other),
        }
    }
}

impl From<DisposableViewError> for SafeGcError {
    fn from(value: DisposableViewError) -> Self {
        Self::DisposableView(value)
    }
}

impl fmt::Display for SafeGcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DestructiveGcDisabledByDefault => f.write_str("destructive GC is disabled by default (#122)"),
            Self::InvalidInput(msg) => write!(f, "invalid safe-gc input: {msg}"),
            Self::ArmingRejected(reason) => write!(f, "destructive GC arming rejected: {reason}"),
            Self::IncompleteProof(reason) => write!(f, "deletion proof incomplete: {reason}"),
            Self::ProofDigestMismatch => f.write_str("deletion proof digest mismatch"),
            Self::ProtectionOverlap(msg) => write!(f, "candidate overlaps retained closure: {msg}"),
            Self::ReaderQuiescenceUnverified(msg) => write!(f, "reader quiescence unverified: {msg}"),
            Self::DistributedPrereqsMissing(msg) => {
                write!(f, "distributed GC prerequisites missing (#151/#153): {msg}")
            }
            Self::StaleIncarnation(msg) => write!(f, "stale incarnation fenced: {msg}"),
            Self::StaleDeleterFenced(msg) => write!(f, "stale deleter fenced: {msg}"),
            Self::ConcurrentRetentionRace(msg) => {
                write!(f, "concurrent retention race aborted delete: {msg}")
            }
            Self::MembershipOrRootDrift(msg) => write!(f, "membership or root drift: {msg}"),
            Self::AbaKeyReuseDetected(msg) => write!(f, "anti-ABA key reuse refused: {msg}"),
            Self::CompactionVerificationFailed(msg) => {
                write!(f, "two-phase compaction readback verification failed: {msg}")
            }
            Self::BlobDeleteDisabled => f.write_str("BlobStore physical delete stays disabled on this backend"),
            Self::DeleteOutcomeUnknown(msg) => write!(f, "provider delete outcome unknown: {msg}"),
            Self::PartialDeleteFailure(msg) => write!(f, "partial physical delete failure: {msg}"),
            Self::Serialization(msg) => write!(f, "safe-gc serialization error: {msg}"),
            Self::Blob(err) => write!(f, "blob error: {err}"),
            Self::DisposableView(err) => write!(f, "disposable view error: {err}"),
            Self::Io(msg) => write!(f, "safe-gc IO error: {msg}"),
        }
    }
}

impl std::error::Error for SafeGcError {}
