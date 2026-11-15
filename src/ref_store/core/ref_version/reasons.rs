//! Closed §2.5.2 canonical rejection reason table and decision refinements.
//!
//! Only literals in this closed table may ever enter a canonical terminal `T`.
//! Unrepresentable storage or internal errors never invent or alias a code;
//! callers fail closed as unknown/pending or return a typed non-terminal error.
use super::contract::RefVersionCodecError;
use super::limits::MAX_REASON_BYTES;
use crate::ref_store::core::pack_commit::PackCommitRejectCode;
use crate::ref_store::core::terminal::CommitRejectCode;

/// Closed canonical rejection codes defined by `docs/ref-version-pack-contract.md` §2.5.2.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CausalRejectCode {
    BaseVersionMismatch,
    OldOidMismatch,
    PrefixConflict,
    HeadDeletedWithoutRetarget,
    HeadTargetMissing,
    MissingTarget,
    BadObjectType,
    PolicyDenied,
    ProtectedBranch,
    MissingApprovals,
    RequiredCheckFailed,
    LfsLocked,
    RefNotWritable,
    HeadDependencyMissing,
    NoRefApplied,
    ObjectFormatMismatch,
    GateNotFound,
    TenantMismatch,
    HistoryIncarnationMismatch,
    AuthorityEpochMismatch,
    GroupEpochMismatch,
    GateDigestMismatch,
    RevisionMismatch,
    ModeMismatch,
    OldMembershipMismatch,
    DependencyMissing,
    DependencyCorrupt,
    DependencyRealmMismatch,
    DependencyCycleIntegrity,
    ClosureTooLarge,
    RefGenerationExhausted,
    VersionIdRecordConflict,
}

impl CausalRejectCode {
    /// Complete closed list in §2.5.2 ordinal order (`1..=32`).
    pub const ALL: [Self; 32] = [
        Self::BaseVersionMismatch,
        Self::OldOidMismatch,
        Self::PrefixConflict,
        Self::HeadDeletedWithoutRetarget,
        Self::HeadTargetMissing,
        Self::MissingTarget,
        Self::BadObjectType,
        Self::PolicyDenied,
        Self::ProtectedBranch,
        Self::MissingApprovals,
        Self::RequiredCheckFailed,
        Self::LfsLocked,
        Self::RefNotWritable,
        Self::HeadDependencyMissing,
        Self::NoRefApplied,
        Self::ObjectFormatMismatch,
        Self::GateNotFound,
        Self::TenantMismatch,
        Self::HistoryIncarnationMismatch,
        Self::AuthorityEpochMismatch,
        Self::GroupEpochMismatch,
        Self::GateDigestMismatch,
        Self::RevisionMismatch,
        Self::ModeMismatch,
        Self::OldMembershipMismatch,
        Self::DependencyMissing,
        Self::DependencyCorrupt,
        Self::DependencyRealmMismatch,
        Self::DependencyCycleIntegrity,
        Self::ClosureTooLarge,
        Self::RefGenerationExhausted,
        Self::VersionIdRecordConflict,
    ];

    /// Stable API/log ordinal (`1..=32`); never encoded inside terminal `T`.
    pub const fn ordinal(self) -> u8 {
        match self {
            Self::BaseVersionMismatch => 1,
            Self::OldOidMismatch => 2,
            Self::PrefixConflict => 3,
            Self::HeadDeletedWithoutRetarget => 4,
            Self::HeadTargetMissing => 5,
            Self::MissingTarget => 6,
            Self::BadObjectType => 7,
            Self::PolicyDenied => 8,
            Self::ProtectedBranch => 9,
            Self::MissingApprovals => 10,
            Self::RequiredCheckFailed => 11,
            Self::LfsLocked => 12,
            Self::RefNotWritable => 13,
            Self::HeadDependencyMissing => 14,
            Self::NoRefApplied => 15,
            Self::ObjectFormatMismatch => 16,
            Self::GateNotFound => 17,
            Self::TenantMismatch => 18,
            Self::HistoryIncarnationMismatch => 19,
            Self::AuthorityEpochMismatch => 20,
            Self::GroupEpochMismatch => 21,
            Self::GateDigestMismatch => 22,
            Self::RevisionMismatch => 23,
            Self::ModeMismatch => 24,
            Self::OldMembershipMismatch => 25,
            Self::DependencyMissing => 26,
            Self::DependencyCorrupt => 27,
            Self::DependencyRealmMismatch => 28,
            Self::DependencyCycleIntegrity => 29,
            Self::ClosureTooLarge => 30,
            Self::RefGenerationExhausted => 31,
            Self::VersionIdRecordConflict => 32,
        }
    }

    /// Exact canonical lowercase ASCII literal encoded into `T`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BaseVersionMismatch => "base_version_mismatch",
            Self::OldOidMismatch => "old_oid_mismatch",
            Self::PrefixConflict => "prefix_conflict",
            Self::HeadDeletedWithoutRetarget => "head_deleted_without_retarget",
            Self::HeadTargetMissing => "head_target_missing",
            Self::MissingTarget => "missing_target",
            Self::BadObjectType => "bad_object_type",
            Self::PolicyDenied => "policy_denied",
            Self::ProtectedBranch => "protected_branch",
            Self::MissingApprovals => "missing_approvals",
            Self::RequiredCheckFailed => "required_check_failed",
            Self::LfsLocked => "lfs_locked",
            Self::RefNotWritable => "ref_not_writable",
            Self::HeadDependencyMissing => "head_dependency_missing",
            Self::NoRefApplied => "no_ref_applied",
            Self::ObjectFormatMismatch => "object_format_mismatch",
            Self::GateNotFound => "gate_not_found",
            Self::TenantMismatch => "tenant_mismatch",
            Self::HistoryIncarnationMismatch => "history_incarnation_mismatch",
            Self::AuthorityEpochMismatch => "authority_epoch_mismatch",
            Self::GroupEpochMismatch => "group_epoch_mismatch",
            Self::GateDigestMismatch => "gate_digest_mismatch",
            Self::RevisionMismatch => "revision_mismatch",
            Self::ModeMismatch => "mode_mismatch",
            Self::OldMembershipMismatch => "old_membership_mismatch",
            Self::DependencyMissing => "dependency_missing",
            Self::DependencyCorrupt => "dependency_corrupt",
            Self::DependencyRealmMismatch => "dependency_realm_mismatch",
            Self::DependencyCycleIntegrity => "dependency_cycle_integrity",
            Self::ClosureTooLarge => "closure_too_large",
            Self::RefGenerationExhausted => "ref_generation_exhausted",
            Self::VersionIdRecordConflict => "version_id_record_conflict",
        }
    }

    /// Verify syntax (`^[a-z][a-z0-9_]{0,63}`) and parse against the closed table.
    pub fn parse(value: &str) -> Result<Self, RefVersionCodecError> {
        if !is_valid_reason_syntax(value) {
            return Err(RefVersionCodecError::InvalidReasonCode);
        }
        Self::ALL.into_iter().find(|code| code.as_str() == value).ok_or(RefVersionCodecError::InvalidReasonCode)
    }

    /// Map a policy/decision refinement before encoding `T` (§2.5.2 rules).
    pub fn refine_decision_reason(value: &str) -> Result<Self, RefVersionCodecError> {
        if !is_valid_reason_syntax(value) {
            return Err(RefVersionCodecError::InvalidReasonCode);
        }
        match value {
            "force_push_denied" | "pull_flow_violation" => Ok(Self::PolicyDenied),
            "self_approval_denied" => Ok(Self::MissingApprovals),
            "check_untrusted" => Ok(Self::RequiredCheckFailed),
            other => Self::parse(other),
        }
    }

    /// Map every [`CommitRejectCode`] 1-to-1 onto the canonical causal table.
    pub const fn from_commit_reject_code(code: CommitRejectCode) -> Self {
        match code {
            CommitRejectCode::GateNotFound => Self::GateNotFound,
            CommitRejectCode::TenantMismatch => Self::TenantMismatch,
            CommitRejectCode::ObjectFormatMismatch => Self::ObjectFormatMismatch,
            CommitRejectCode::HistoryIncarnationMismatch => Self::HistoryIncarnationMismatch,
            CommitRejectCode::AuthorityEpochMismatch => Self::AuthorityEpochMismatch,
            CommitRejectCode::GroupEpochMismatch => Self::GroupEpochMismatch,
            CommitRejectCode::RevisionMismatch => Self::RevisionMismatch,
            CommitRejectCode::OldOidMismatch => Self::OldOidMismatch,
            CommitRejectCode::PrefixConflict => Self::PrefixConflict,
            CommitRejectCode::HeadDeletedWithoutRetarget => Self::HeadDeletedWithoutRetarget,
            CommitRejectCode::HeadTargetMissing => Self::HeadTargetMissing,
            CommitRejectCode::PolicyDenied => Self::PolicyDenied,
            CommitRejectCode::ProtectedBranch => Self::ProtectedBranch,
            CommitRejectCode::MissingApprovals => Self::MissingApprovals,
            CommitRejectCode::RequiredCheckFailed => Self::RequiredCheckFailed,
            CommitRejectCode::LfsLocked => Self::LfsLocked,
            CommitRejectCode::RefNotWritable => Self::RefNotWritable,
            CommitRejectCode::HeadDependencyMissing => Self::HeadDependencyMissing,
            CommitRejectCode::NoRefApplied => Self::NoRefApplied,
            CommitRejectCode::MissingTarget => Self::MissingTarget,
            CommitRejectCode::BadObjectType => Self::BadObjectType,
        }
    }

    /// Map a [`PackCommitRejectCode`] if it corresponds to a terminal reason.
    ///
    /// Storage/ledger/unknown conditions return `None`: callers must fail
    /// closed as pending/unknown or a typed non-terminal error, never invent a code.
    pub const fn from_pack_commit_reject_code(code: PackCommitRejectCode) -> Option<Self> {
        match code {
            PackCommitRejectCode::GateNotFound => Some(Self::GateNotFound),
            PackCommitRejectCode::TenantMismatch => Some(Self::TenantMismatch),
            PackCommitRejectCode::ObjectFormatMismatch => Some(Self::ObjectFormatMismatch),
            PackCommitRejectCode::HistoryIncarnationMismatch => Some(Self::HistoryIncarnationMismatch),
            PackCommitRejectCode::AuthorityEpochMismatch => Some(Self::AuthorityEpochMismatch),
            PackCommitRejectCode::GroupEpochMismatch => Some(Self::GroupEpochMismatch),
            PackCommitRejectCode::RevisionMismatch => Some(Self::RevisionMismatch),
            PackCommitRejectCode::GateDigestMismatch => Some(Self::GateDigestMismatch),
            PackCommitRejectCode::ModeMismatch => Some(Self::ModeMismatch),
            PackCommitRejectCode::OldOidMismatch => Some(Self::OldOidMismatch),
            PackCommitRejectCode::PrefixConflict => Some(Self::PrefixConflict),
            PackCommitRejectCode::HeadDeletedWithoutRetarget => Some(Self::HeadDeletedWithoutRetarget),
            PackCommitRejectCode::HeadTargetMissing => Some(Self::HeadTargetMissing),
            PackCommitRejectCode::OldMembershipMismatch => Some(Self::OldMembershipMismatch),
            PackCommitRejectCode::NoRefApplied => Some(Self::NoRefApplied),
            PackCommitRejectCode::DecisionRejected => Some(Self::PolicyDenied),
            PackCommitRejectCode::RegistrationMissing
            | PackCommitRejectCode::RegistrationConflict
            | PackCommitRejectCode::RegistrationReuse
            | PackCommitRejectCode::PublicationMismatch
            | PackCommitRejectCode::ContextMismatch
            | PackCommitRejectCode::ClosureMismatch
            | PackCommitRejectCode::PendingMissing
            | PackCommitRejectCode::Cancelled
            | PackCommitRejectCode::QuotaExceeded
            | PackCommitRejectCode::CaptureOverflow
            | PackCommitRejectCode::AlreadyVerified
            | PackCommitRejectCode::LedgerIntegrity => None,
        }
    }
}

/// Canonical syntax rule `^[a-z][a-z0-9_]{0,63}` (1..=64 ASCII bytes).
pub fn is_valid_reason_syntax(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_REASON_BYTES {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..].iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}
