//! Fixed-safe diagnostics at the two root error-mapping information-loss boundaries.
//!
//! This module accepts only closed root/native error types and maps them to finite
//! labels before the original error is converted. It never formats an error,
//! static string, identifier, SQL, provider value, path or request value.
use crate::ref_store::core::pack_commit::{PackCommitError, PackCommitRejectCode};
use crate::ref_store::core::retention_root::RootError;
use serde_json::{Map, Value, json};

use super::enqueue_event;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Boundary {
    NativeToRoot,
    RootToService,
}

impl Boundary {
    fn as_str(self) -> &'static str {
        match self {
            Self::NativeToRoot => "native_to_root",
            Self::RootToService => "root_to_service",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootErrorVariant {
    Store,
    RootNotFound,
    RootReleased,
    RootAlreadyActive,
    RootGenerationConflict,
    RootSourceChanged,
    RootSelectorInvalid,
    RootObjectMissing,
    RootQuotaExceeded,
    RootReceiptTooLarge,
    RootRealmMismatch,
    RootAuthorityRequired,
    RootDigestConflict,
    RootClosureUnproven,
}

impl RootErrorVariant {
    fn as_str(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::RootNotFound => "root_not_found",
            Self::RootReleased => "root_released",
            Self::RootAlreadyActive => "root_already_active",
            Self::RootGenerationConflict => "root_generation_conflict",
            Self::RootSourceChanged => "root_source_changed",
            Self::RootSelectorInvalid => "root_selector_invalid",
            Self::RootObjectMissing => "root_object_missing",
            Self::RootQuotaExceeded => "root_quota_exceeded",
            Self::RootReceiptTooLarge => "root_receipt_too_large",
            Self::RootRealmMismatch => "root_realm_mismatch",
            Self::RootAuthorityRequired => "root_authority_required",
            Self::RootDigestConflict => "root_digest_conflict",
            Self::RootClosureUnproven => "root_closure_unproven",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClosureReasonId {
    CapturedIdentityInvalid,
    CaptureCapacity,
    NativeLedgerRejected,
    NativeVerificationUnavailable,
    NativeReadNeverCommits,
    NativeBindingSealed,
    NativeCoverageSealed,
    WorkspaceBound,
    NativeBindingRetained,
    NativeCoverageRetained,
    VerifiedCopyLength,
    VerifiedCopyDigest,
    Unknown,
}

impl ClosureReasonId {
    fn as_str(self) -> &'static str {
        match self {
            Self::CapturedIdentityInvalid => "captured_identity_invalid",
            Self::CaptureCapacity => "capture_capacity",
            Self::NativeLedgerRejected => "native_ledger_rejected",
            Self::NativeVerificationUnavailable => "native_verification_unavailable",
            Self::NativeReadNeverCommits => "native_read_never_commits",
            Self::NativeBindingSealed => "native_binding_sealed",
            Self::NativeCoverageSealed => "native_coverage_sealed",
            Self::WorkspaceBound => "workspace_bound",
            Self::NativeBindingRetained => "native_binding_retained",
            Self::NativeCoverageRetained => "native_coverage_retained",
            Self::VerifiedCopyLength => "verified_copy_length",
            Self::VerifiedCopyDigest => "verified_copy_digest",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackErrorVariant {
    RefStore,
    Invalid,
    Capacity,
    Rejected,
    ProofUnavailable,
    CommitUnknown,
    NotApplicable,
}

impl PackErrorVariant {
    fn as_str(self) -> &'static str {
        match self {
            Self::RefStore => "ref_store",
            Self::Invalid => "invalid",
            Self::Capacity => "capacity",
            Self::Rejected => "rejected",
            Self::ProofUnavailable => "proof_unavailable",
            Self::CommitUnknown => "commit_unknown",
            Self::NotApplicable => "not_applicable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeDiagnostic {
    variant: PackErrorVariant,
    reject_code: Option<PackCommitRejectCode>,
}

pub(crate) fn native_diagnostic(error: &PackCommitError) -> NativeDiagnostic {
    match error {
        PackCommitError::RefStore(_) => NativeDiagnostic { variant: PackErrorVariant::RefStore, reject_code: None },
        PackCommitError::Invalid(_) => NativeDiagnostic { variant: PackErrorVariant::Invalid, reject_code: None },
        PackCommitError::Capacity { .. } => NativeDiagnostic { variant: PackErrorVariant::Capacity, reject_code: None },
        PackCommitError::Rejected(rejection) => {
            NativeDiagnostic { variant: PackErrorVariant::Rejected, reject_code: Some(rejection.code) }
        }
        PackCommitError::ProofUnavailable(_) => {
            NativeDiagnostic { variant: PackErrorVariant::ProofUnavailable, reject_code: None }
        }
        PackCommitError::CommitUnknown { .. } => {
            NativeDiagnostic { variant: PackErrorVariant::CommitUnknown, reject_code: None }
        }
    }
}

fn root_error_variant(error: &RootError) -> RootErrorVariant {
    match error {
        RootError::Store(_) => RootErrorVariant::Store,
        RootError::RootNotFound { .. } => RootErrorVariant::RootNotFound,
        RootError::RootReleased { .. } => RootErrorVariant::RootReleased,
        RootError::RootAlreadyActive { .. } => RootErrorVariant::RootAlreadyActive,
        RootError::RootGenerationConflict { .. } => RootErrorVariant::RootGenerationConflict,
        RootError::RootSourceChanged(_) => RootErrorVariant::RootSourceChanged,
        RootError::RootSelectorInvalid(_) => RootErrorVariant::RootSelectorInvalid,
        RootError::RootObjectMissing { .. } => RootErrorVariant::RootObjectMissing,
        RootError::RootQuotaExceeded { .. } => RootErrorVariant::RootQuotaExceeded,
        RootError::RootReceiptTooLarge { .. } => RootErrorVariant::RootReceiptTooLarge,
        RootError::RootRealmMismatch(_) => RootErrorVariant::RootRealmMismatch,
        RootError::RootAuthorityRequired(_) => RootErrorVariant::RootAuthorityRequired,
        RootError::RootDigestConflict(_) => RootErrorVariant::RootDigestConflict,
        RootError::RootClosureUnproven(_) => RootErrorVariant::RootClosureUnproven,
    }
}

fn closure_reason_id(error: &RootError) -> ClosureReasonId {
    let RootError::RootClosureUnproven(reason) = error else {
        return ClosureReasonId::Unknown;
    };
    match *reason {
        "the captured pack/blob identity is not valid" => ClosureReasonId::CapturedIdentityInvalid,
        "the capture exceeds a fixed verifier bound" => ClosureReasonId::CaptureCapacity,
        "the private native ledger refused the root closure" => ClosureReasonId::NativeLedgerRejected,
        "native object verification is unavailable" => ClosureReasonId::NativeVerificationUnavailable,
        "a native read never commits" => ClosureReasonId::NativeReadNeverCommits,
        "native closure binding differs from the sealed source" => ClosureReasonId::NativeBindingSealed,
        "native closure did not cover every registered pack" => ClosureReasonId::NativeCoverageSealed,
        "materialized root view exceeds the workspace bound" => ClosureReasonId::WorkspaceBound,
        "native closure binding differs from the retained root" => ClosureReasonId::NativeBindingRetained,
        "native closure did not cover every retained pack" => ClosureReasonId::NativeCoverageRetained,
        "verified local copy changed its length" => ClosureReasonId::VerifiedCopyLength,
        "verified local copy changed its digest" => ClosureReasonId::VerifiedCopyDigest,
        _ => ClosureReasonId::Unknown,
    }
}

pub(crate) fn observe_native_to_root(diagnostic: NativeDiagnostic, mapped: &RootError) {
    emit(
        Boundary::NativeToRoot,
        root_error_variant(mapped),
        closure_reason_id(mapped),
        diagnostic.variant,
        diagnostic.reject_code,
    );
}

pub(crate) fn observe_root_to_service(error: &RootError) {
    emit(
        Boundary::RootToService,
        root_error_variant(error),
        closure_reason_id(error),
        PackErrorVariant::NotApplicable,
        None,
    );
}

fn emit(
    boundary: Boundary,
    root_variant: RootErrorVariant,
    closure_reason: ClosureReasonId,
    pack_variant: PackErrorVariant,
    reject_code: Option<PackCommitRejectCode>,
) {
    enqueue_event(event_json(boundary, root_variant, closure_reason, pack_variant, reject_code));
}

fn event_json(
    boundary: Boundary,
    root_variant: RootErrorVariant,
    closure_reason: ClosureReasonId,
    pack_variant: PackErrorVariant,
    reject_code: Option<PackCommitRejectCode>,
) -> String {
    let mut event = Map::new();
    event.insert("event".to_owned(), json!("root_prepare_refusal"));
    event.insert("boundary".to_owned(), json!(boundary.as_str()));
    event.insert("root_error_variant".to_owned(), json!(root_variant.as_str()));
    event.insert("closure_reason_id".to_owned(), json!(closure_reason.as_str()));
    event.insert("pack_error_variant".to_owned(), json!(pack_variant.as_str()));
    if let Some(code) = reject_code {
        event.insert("pack_reject_code".to_owned(), json!(code.as_str()));
    }
    serde_json::to_string(&Value::Object(event)).unwrap_or_else(|_| {
        r#"{"event":"root_prepare_refusal","boundary":"root_to_service","root_error_variant":"store","closure_reason_id":"unknown","pack_error_variant":"not_applicable"}"#
            .to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const REASONS: [&str; 12] = [
        "the captured pack/blob identity is not valid",
        "the capture exceeds a fixed verifier bound",
        "the private native ledger refused the root closure",
        "native object verification is unavailable",
        "a native read never commits",
        "native closure binding differs from the sealed source",
        "native closure did not cover every registered pack",
        "materialized root view exceeds the workspace bound",
        "native closure binding differs from the retained root",
        "native closure did not cover every retained pack",
        "verified local copy changed its length",
        "verified local copy changed its digest",
    ];

    #[test]
    fn fixed_schema_and_closed_vocabulary_do_not_accept_payloads() {
        let with_code = event_json(
            Boundary::NativeToRoot,
            RootErrorVariant::RootClosureUnproven,
            ClosureReasonId::NativeBindingSealed,
            PackErrorVariant::Rejected,
            Some(PackCommitRejectCode::ClosureMismatch),
        );
        let value: Value = serde_json::from_str(&with_code).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 6);
        assert_eq!(value["event"].as_str(), Some("root_prepare_refusal"));
        assert_eq!(value["boundary"].as_str(), Some("native_to_root"));
        assert_eq!(value["root_error_variant"].as_str(), Some("root_closure_unproven"));
        assert_eq!(value["closure_reason_id"].as_str(), Some("native_binding_sealed"));
        assert_eq!(value["pack_error_variant"].as_str(), Some("rejected"));
        assert_eq!(value["pack_reject_code"].as_str(), Some("closure_mismatch"));
        assert!(!with_code.contains("SECRET"));
        assert!(!with_code.contains("://"));

        let without_code = event_json(
            Boundary::RootToService,
            RootErrorVariant::Store,
            ClosureReasonId::Unknown,
            PackErrorVariant::NotApplicable,
            None,
        );
        let value: Value = serde_json::from_str(&without_code).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert!(value.get("pack_reject_code").is_none());

        for reason in REASONS {
            let error = RootError::RootClosureUnproven(reason);
            assert_ne!(closure_reason_id(&error), ClosureReasonId::Unknown);
        }
        assert_eq!(
            closure_reason_id(&RootError::RootClosureUnproven("unlisted static reason")),
            ClosureReasonId::Unknown
        );
    }
}
