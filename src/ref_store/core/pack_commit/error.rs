//! Typed refusals of the A4a pack commit slice.
//!
//! `PackCommitError` deliberately wraps, never replaces, [`RefStoreError`]: the
//! shared migration-138 registry keeps its own error vocabulary and terminal
//! replay semantics. Only refusals that are specific to pack registration,
//! closure capture and verified commit are added here. None of these variants
//! carries bytes, a locator, a Git argv/exit text or anything an unauthenticated
//! caller could turn into a capability.
use crate::ref_store::contract::RefStoreError;
use std::fmt;
use uuid::Uuid;

/// Stable machine-readable reason for a refused pack commit step. Codes are
/// fixed literals: they are part of the persisted rejection terminal and must
/// never be derived from SQL text, Git output or caller strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PackCommitRejectCode {
    GateNotFound,
    TenantMismatch,
    ObjectFormatMismatch,
    HistoryIncarnationMismatch,
    AuthorityEpochMismatch,
    GroupEpochMismatch,
    RevisionMismatch,
    GateDigestMismatch,
    ModeMismatch,
    OldOidMismatch,
    PrefixConflict,
    HeadDeletedWithoutRetarget,
    HeadTargetMissing,
    /// Active membership set changed since the plan captured it.
    OldMembershipMismatch,
    /// One planned registration id/pack id is not durable for this parent.
    RegistrationMissing,
    /// A colliding id belongs to a different repo/tenant/owner/parent/content.
    RegistrationConflict,
    /// Same acquire/consume/hold id was already used by another registration.
    RegistrationReuse,
    /// The publication does not match the planned content/roles/scope.
    PublicationMismatch,
    /// The closure context was captured at another revision or mode.
    ContextMismatch,
    /// The verifier proof does not bind this plan/context/result.
    ClosureMismatch,
    /// The operation has no durable pending row under this exact digest.
    PendingMissing,
    /// A durable cancellation tombstone won; no pack write may be recorded.
    Cancelled,
    /// A retained repo/tenant budget would be exceeded.
    QuotaExceeded,
    /// The capture exceeded a fixed bound; nothing is truncated.
    CaptureOverflow,
    /// The gate is already `pack_verified` and cannot be activated again by a
    /// different plan.
    AlreadyVerified,
    /// A stored registration row/body/hold set is partial, rewritten or
    /// internally inconsistent. Never treated as `Found`.
    LedgerIntegrity,
    NoRefApplied,
    DecisionRejected,
}

impl PackCommitRejectCode {
    /// Reverse of [`Self::as_str`] for persisted terminal bodies. An unknown
    /// literal is a database integrity problem, never a new public code.
    pub fn parse(value: &str) -> Result<Self, RefStoreError> {
        let code = match value {
            "gate_not_found" => Self::GateNotFound,
            "tenant_mismatch" => Self::TenantMismatch,
            "object_format_mismatch" => Self::ObjectFormatMismatch,
            "history_incarnation_mismatch" => Self::HistoryIncarnationMismatch,
            "authority_epoch_mismatch" => Self::AuthorityEpochMismatch,
            "group_epoch_mismatch" => Self::GroupEpochMismatch,
            "revision_mismatch" => Self::RevisionMismatch,
            "gate_digest_mismatch" => Self::GateDigestMismatch,
            "pack_mode_mismatch" => Self::ModeMismatch,
            "old_oid_mismatch" => Self::OldOidMismatch,
            "prefix_conflict" => Self::PrefixConflict,
            "head_deleted_without_retarget" => Self::HeadDeletedWithoutRetarget,
            "head_target_missing" => Self::HeadTargetMissing,
            "old_membership_mismatch" => Self::OldMembershipMismatch,
            "registration_missing" => Self::RegistrationMissing,
            "registration_conflict" => Self::RegistrationConflict,
            "registration_reuse" => Self::RegistrationReuse,
            "publication_mismatch" => Self::PublicationMismatch,
            "context_mismatch" => Self::ContextMismatch,
            "closure_mismatch" => Self::ClosureMismatch,
            "pending_missing" => Self::PendingMissing,
            "cancelled" => Self::Cancelled,
            "quota_exceeded" => Self::QuotaExceeded,
            "capture_overflow" => Self::CaptureOverflow,
            "already_verified" => Self::AlreadyVerified,
            "ledger_integrity" => Self::LedgerIntegrity,
            "no_ref_applied" => Self::NoRefApplied,
            "decision_rejected" => Self::DecisionRejected,
            _ => return Err(RefStoreError::Database("stored pack reject code is not recognized".into())),
        };
        Ok(code)
    }
}

impl PackCommitRejectCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GateNotFound => "gate_not_found",
            Self::TenantMismatch => "tenant_mismatch",
            Self::ObjectFormatMismatch => "object_format_mismatch",
            Self::HistoryIncarnationMismatch => "history_incarnation_mismatch",
            Self::AuthorityEpochMismatch => "authority_epoch_mismatch",
            Self::GroupEpochMismatch => "group_epoch_mismatch",
            Self::RevisionMismatch => "revision_mismatch",
            Self::GateDigestMismatch => "gate_digest_mismatch",
            Self::ModeMismatch => "pack_mode_mismatch",
            Self::OldOidMismatch => "old_oid_mismatch",
            Self::PrefixConflict => "prefix_conflict",
            Self::HeadDeletedWithoutRetarget => "head_deleted_without_retarget",
            Self::HeadTargetMissing => "head_target_missing",
            Self::OldMembershipMismatch => "old_membership_mismatch",
            Self::RegistrationMissing => "registration_missing",
            Self::RegistrationConflict => "registration_conflict",
            Self::RegistrationReuse => "registration_reuse",
            Self::PublicationMismatch => "publication_mismatch",
            Self::ContextMismatch => "context_mismatch",
            Self::ClosureMismatch => "closure_mismatch",
            Self::PendingMissing => "pending_missing",
            Self::Cancelled => "cancelled",
            Self::QuotaExceeded => "quota_exceeded",
            Self::CaptureOverflow => "capture_overflow",
            Self::AlreadyVerified => "already_verified",
            Self::LedgerIntegrity => "ledger_integrity",
            Self::NoRefApplied => "no_ref_applied",
            Self::DecisionRejected => "decision_rejected",
        }
    }
}

/// A refused pack step. `detail` is a fixed, bounded label supplied by this
/// component only (never SQL/Git text, never caller bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackCommitRejection {
    pub code: PackCommitRejectCode,
    pub detail: &'static str,
}

impl PackCommitRejection {
    pub const fn new(code: PackCommitRejectCode, detail: &'static str) -> Self {
        Self { code, detail }
    }
}

#[derive(Debug)]
pub enum PackCommitError {
    /// The shared registry/ref engine refused the step; semantics unchanged.
    RefStore(RefStoreError),
    /// A plan/context/request value violates a fixed bound or is malformed.
    Invalid(&'static str),
    /// A fixed logical budget would be exceeded.
    Capacity { limit: &'static str, bound: i64, actual: i64 },
    /// A domain refusal with a stable code.
    Rejected(PackCommitRejection),
    /// The closure proof is missing, expired or binds another plan.
    ProofUnavailable(&'static str),
    /// `COMMIT` was issued and no acknowledgement was observed. The effects may
    /// still be durable; resolve with the same operation identity.
    CommitUnknown { repository_id: Uuid, operation_id: Uuid },
}

impl PackCommitError {
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::CommitUnknown { .. })
    }

    pub fn rejection(&self) -> Option<&PackCommitRejection> {
        match self {
            Self::Rejected(rejection) => Some(rejection),
            _ => None,
        }
    }
}

impl From<RefStoreError> for PackCommitError {
    fn from(error: RefStoreError) -> Self {
        Self::RefStore(error)
    }
}

impl From<PackCommitRejection> for PackCommitError {
    fn from(rejection: PackCommitRejection) -> Self {
        Self::Rejected(rejection)
    }
}

impl fmt::Display for PackCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RefStore(error) => write!(formatter, "ref store: {error}"),
            Self::Invalid(detail) => write!(formatter, "invalid pack commit: {detail}"),
            Self::Capacity { limit, bound, actual } => {
                write!(formatter, "pack commit capacity {limit}: bound {bound}, actual {actual}")
            }
            Self::Rejected(rejection) => write!(formatter, "pack commit rejected: {}", rejection.code.as_str()),
            Self::ProofUnavailable(detail) => write!(formatter, "pack closure proof unavailable: {detail}"),
            Self::CommitUnknown { operation_id, .. } => {
                write!(formatter, "pack commit COMMIT unacknowledged for operation {operation_id}")
            }
        }
    }
}

impl std::error::Error for PackCommitError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_codes_are_distinct_fixed_literals() {
        let codes = [
            PackCommitRejectCode::GateNotFound,
            PackCommitRejectCode::ModeMismatch,
            PackCommitRejectCode::OldMembershipMismatch,
            PackCommitRejectCode::ClosureMismatch,
            PackCommitRejectCode::AlreadyVerified,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for code in codes {
            assert!(seen.insert(code.as_str()), "duplicate code literal {}", code.as_str());
        }
        assert_eq!(PackCommitRejectCode::Cancelled.as_str(), "cancelled");
    }

    #[test]
    fn ref_store_errors_keep_their_identity() {
        let error = PackCommitError::from(RefStoreError::RepositoryNotFound);
        assert!(!error.is_unknown());
        assert!(error.rejection().is_none());
        assert!(error.to_string().contains("ref store"));
    }
}
