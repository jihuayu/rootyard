//! Stable literal vocabularies of the publication-decision slice.
//!
//! Both vocabularies are fixed machine-readable literals: they are persisted in the decision rows and
//! reported in terminals, and they are never derived from SQL text, Git output or a caller string. The
//! per-ref codes are the shared core/subset vocabulary; the refinements document their public map in
//! `docs/ref-store-roots-decisions.md`.
use super::contract::DecisionError;

/// Per-ref policy verdict code. The first ten values are the shared core/subset vocabulary; the last
/// four are policy refinements persisted with their exact literal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecisionRejectCode {
    PolicyDenied,
    ProtectedBranch,
    MissingApprovals,
    RequiredCheckFailed,
    LfsLocked,
    OldOidMismatch,
    PrefixConflict,
    HeadDependencyMissing,
    ObjectFormatMismatch,
    RefNotWritable,
    ForcePushDenied,
    PullFlowViolation,
    SelfApprovalDenied,
    CheckUntrusted,
    MissingTarget,
    BadObjectType,
}

impl DecisionRejectCode {
    pub(crate) const ALL: [Self; 16] = [
        Self::PolicyDenied,
        Self::ProtectedBranch,
        Self::MissingApprovals,
        Self::RequiredCheckFailed,
        Self::LfsLocked,
        Self::OldOidMismatch,
        Self::PrefixConflict,
        Self::HeadDependencyMissing,
        Self::ObjectFormatMismatch,
        Self::RefNotWritable,
        Self::ForcePushDenied,
        Self::PullFlowViolation,
        Self::SelfApprovalDenied,
        Self::CheckUntrusted,
        Self::MissingTarget,
        Self::BadObjectType,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyDenied => "policy_denied",
            Self::ProtectedBranch => "protected_branch",
            Self::MissingApprovals => "missing_approvals",
            Self::RequiredCheckFailed => "required_check_failed",
            Self::LfsLocked => "lfs_locked",
            Self::OldOidMismatch => "old_oid_mismatch",
            Self::PrefixConflict => "prefix_conflict",
            Self::HeadDependencyMissing => "head_dependency_missing",
            Self::ObjectFormatMismatch => "object_format_mismatch",
            Self::RefNotWritable => "ref_not_writable",
            Self::ForcePushDenied => "force_push_denied",
            Self::PullFlowViolation => "pull_flow_violation",
            Self::SelfApprovalDenied => "self_approval_denied",
            Self::CheckUntrusted => "check_untrusted",
            Self::MissingTarget => "missing_target",
            Self::BadObjectType => "bad_object_type",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, DecisionError> {
        Self::ALL
            .into_iter()
            .find(|code| code.as_str() == value)
            .ok_or(DecisionError::Ledger("unknown per-ref verdict code stored in the decision row"))
    }
}

/// Whole-operation refusal code (a decision is rejected/cancelled, or nothing is written at all).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DenialCode {
    TokenInvalid,
    TokenExpired,
    TokenReadOnly,
    BrowserTokenUnsupported,
    ScopeDenied,
    RoleDenied,
    RepositoryNotFound,
    RepositoryUnserved,
    GateNotFound,
    TenantMismatch,
    ObjectFormatMismatch,
    HistoryIncarnationMismatch,
    AuthorityEpochMismatch,
    GroupEpochMismatch,
    GateDigestMismatch,
    RevisionMismatch,
    ProtocolStateMissing,
    FactsUnverifiable,
    ProofMismatch,
    AuthorizationChanged,
    PolicyChanged,
    DependencyChanged,
    SelectionChanged,
    Expired,
    RejectedBatch,
    AllRejected,
    Cancelled,
    ScopeClosing,
    UnsupportedAction,
    LedgerIntegrity,
}

impl DenialCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::TokenInvalid => "token_invalid",
            Self::TokenExpired => "token_expired",
            Self::TokenReadOnly => "token_read_only",
            Self::BrowserTokenUnsupported => "browser_token_unsupported",
            Self::ScopeDenied => "scope_denied",
            Self::RoleDenied => "role_denied",
            Self::RepositoryNotFound => "repository_not_found",
            Self::RepositoryUnserved => "repository_unserved",
            Self::GateNotFound => "gate_not_found",
            Self::TenantMismatch => "tenant_mismatch",
            Self::ObjectFormatMismatch => "object_format_mismatch",
            Self::HistoryIncarnationMismatch => "history_incarnation_mismatch",
            Self::AuthorityEpochMismatch => "authority_epoch_mismatch",
            Self::GroupEpochMismatch => "group_epoch_mismatch",
            Self::GateDigestMismatch => "gate_digest_mismatch",
            Self::RevisionMismatch => "revision_mismatch",
            Self::ProtocolStateMissing => "protocol_state_missing",
            Self::FactsUnverifiable => "facts_unverifiable",
            Self::ProofMismatch => "proof_mismatch",
            Self::AuthorizationChanged => "authorization_changed",
            Self::PolicyChanged => "policy_changed",
            Self::DependencyChanged => "dependency_changed",
            Self::SelectionChanged => "selection_changed",
            Self::Expired => "expired",
            Self::RejectedBatch => "rejected_batch",
            Self::AllRejected => "all_rejected",
            Self::Cancelled => "cancelled",
            Self::ScopeClosing => "scope_closing",
            Self::UnsupportedAction => "unsupported_action",
            Self::LedgerIntegrity => "ledger_integrity",
        }
    }
}

/// One stable dependency scope. Declaration order *is* the frozen lock order of the scope rows.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum ScopeKind {
    Token,
    ParentToken,
    Session,
    User,
    OrgMembership,
    OrgTeam,
    RepoAccess,
    RepoLifecycle,
    BranchRules,
    Pull,
    Checks,
    Reviews,
    LfsLocks,
    Authority,
}

impl ScopeKind {
    pub(crate) const ALL: [Self; 14] = [
        Self::Token,
        Self::ParentToken,
        Self::Session,
        Self::User,
        Self::OrgMembership,
        Self::OrgTeam,
        Self::RepoAccess,
        Self::RepoLifecycle,
        Self::BranchRules,
        Self::Pull,
        Self::Checks,
        Self::Reviews,
        Self::LfsLocks,
        Self::Authority,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::ParentToken => "parent_token",
            Self::Session => "session",
            Self::User => "user",
            Self::OrgMembership => "org_membership",
            Self::OrgTeam => "org_team",
            Self::RepoAccess => "repo_access",
            Self::RepoLifecycle => "repo_lifecycle",
            Self::BranchRules => "branch_rules",
            Self::Pull => "pull",
            Self::Checks => "checks",
            Self::Reviews => "reviews",
            Self::LfsLocks => "lfs_locks",
            Self::Authority => "authority",
        }
    }
}
