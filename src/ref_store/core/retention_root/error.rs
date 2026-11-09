//! Typed roots error surface.
//!
//! Roots never widen [`RefStoreError`] (a common, non-owned file). This module adds only the root-specific
//! refusals: released/never-reused root ids, generation CAS, changed source snapshot, selector/object/proof
//! failures, retained-quota backpressure, bounded receipt, realm and current-authority requirements.
//!
//! No variant carries Blob bytes, a private workspace path, a locator value, a token digest or Git output.
use super::usage::RootQuotaResource;
use crate::ref_store::contract::RefStoreError;
use std::fmt;
use uuid::Uuid;

/// One typed roots refusal.
#[derive(Debug)]
pub enum RootError {
    /// A shared ref-store/lifetime/postgres refusal (timeout, commit-unknown, pin state, ...).
    Store(RefStoreError),
    /// No retained capture exists for this (repository, root id, generation).
    RootNotFound { repository_id: Uuid, root_id: Uuid },
    /// The root id is released (or was released before the register reached PostgreSQL). A root id is never
    /// reopened and never reused.
    RootReleased { repository_id: Uuid, root_id: Uuid, generation: i64 },
    /// An active capture already exists for this root id; a second capture needs a different root id.
    RootAlreadyActive { repository_id: Uuid, root_id: Uuid },
    /// Release CAS failed: the caller's expected generation/register digest is stale.
    RootGenerationConflict { root_id: Uuid, expected_generation: i64, actual_generation: i64 },
    /// The source snapshot/pin/realm/pack identity changed between `prepare` and `register`.
    RootSourceChanged(&'static str),
    /// The caller-supplied selector is empty, too large, duplicated, non-canonical or the wrong width.
    RootSelectorInvalid(String),
    /// A selected root object id is not present/connected in the captured registered packs.
    RootObjectMissing { ordinal: usize },
    /// A retained admission counter would exceed its fixed ceiling. Backpressure only: never a prune/release.
    RootQuotaExceeded { resource: RootQuotaResource, actual: i64, bound: i64 },
    /// The canonical receipt body would exceed the fixed 64 KiB bound (never truncated).
    RootReceiptTooLarge { bytes: usize, max: usize },
    /// The stored root/scope realm disagrees with the requested scope or the live gate realm.
    RootRealmMismatch(&'static str),
    /// A byte read requires current repository authority (a live matching core gate row) at T2.
    RootAuthorityRequired(&'static str),
    /// Same request/root identity with a different canonical digest.
    RootDigestConflict(&'static str),
    /// The private native engine could not prove the requested object closure.
    RootClosureUnproven(&'static str),
}

impl From<RefStoreError> for RootError {
    fn from(error: RefStoreError) -> Self {
        Self::Store(error)
    }
}

impl fmt::Display for RootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "roots ref-store refusal: {error}"),
            Self::RootNotFound { repository_id, root_id } => {
                write!(f, "root {root_id} of repository {repository_id} has no retained capture")
            }
            Self::RootReleased { repository_id, root_id, generation } => write!(
                f,
                "root {root_id} of repository {repository_id} is released at generation {generation}; a root id is never reused"
            ),
            Self::RootAlreadyActive { repository_id, root_id } => {
                write!(f, "root {root_id} of repository {repository_id} already has an active capture")
            }
            Self::RootGenerationConflict { root_id, expected_generation, actual_generation } => write!(
                f,
                "root {root_id} generation conflict: expected {expected_generation}, actual {actual_generation}"
            ),
            Self::RootSourceChanged(field) => write!(f, "root source changed during preparation: {field}"),
            Self::RootSelectorInvalid(reason) => write!(f, "root selector is invalid: {reason}"),
            Self::RootObjectMissing { ordinal } => {
                write!(f, "root object at ordinal {ordinal} is not present in the captured packs")
            }
            Self::RootQuotaExceeded { resource, actual, bound } => {
                write!(f, "retained roots quota exceeded for {}: {actual} > {bound}", resource.as_str())
            }
            Self::RootReceiptTooLarge { bytes, max } => {
                write!(f, "root receipt body is {bytes} bytes, above the {max} byte bound")
            }
            Self::RootRealmMismatch(what) => write!(f, "root realm mismatch: {what}"),
            Self::RootAuthorityRequired(what) => write!(f, "root access requires current authority: {what}"),
            Self::RootDigestConflict(what) => write!(f, "root digest conflict: {what}"),
            Self::RootClosureUnproven(what) => write!(f, "root object closure is unproven: {what}"),
        }
    }
}

impl std::error::Error for RootError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            _ => None,
        }
    }
}

/// Map the private native/registered-pack refusal into the roots vocabulary without ever promoting Git text,
/// argv, a path, a locator or provider text.
impl From<crate::ref_store::core::pack_commit::PackCommitError> for RootError {
    fn from(error: crate::ref_store::core::pack_commit::PackCommitError) -> Self {
        use crate::ref_store::core::pack_commit::{PackCommitError, PackCommitRejectCode};
        match error {
            PackCommitError::RefStore(error) => Self::Store(error),
            PackCommitError::Invalid(_) => Self::RootClosureUnproven("the captured pack/blob identity is not valid"),
            PackCommitError::Capacity { .. } => Self::RootClosureUnproven("the capture exceeds a fixed verifier bound"),
            PackCommitError::Rejected(rejection) => match rejection.code {
                PackCommitRejectCode::TenantMismatch
                | PackCommitRejectCode::ObjectFormatMismatch
                | PackCommitRejectCode::HistoryIncarnationMismatch
                | PackCommitRejectCode::AuthorityEpochMismatch
                | PackCommitRejectCode::GroupEpochMismatch => Self::RootRealmMismatch("native root closure realm"),
                _ => Self::RootClosureUnproven("the private native ledger refused the root closure"),
            },
            PackCommitError::ProofUnavailable(_) => {
                Self::RootClosureUnproven("native object verification is unavailable")
            }
            PackCommitError::CommitUnknown { .. } => Self::RootClosureUnproven("a native read never commits"),
        }
    }
}
