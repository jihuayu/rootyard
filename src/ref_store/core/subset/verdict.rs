//! Shared, deterministic per-ref outcome vocabulary for accepted-subset
//! publication (feature 3).
//!
//! Exactly six reject reasons exist. They are the persisted/observable subset
//! vocabulary and must stay stable: a caller can only use these literals, never a
//! free-form string derived from SQL or Git output. A verdict is *data*: it grants
//! no authority. The only way to turn selection data into a committable capability
//! is [`super::SelectedPackPlan::seal`], which requires opaque native facts bound
//! to the original whole-batch plan.
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::types::RefName;

/// Fixed bound for a persisted verdict detail label.
pub const MAX_DETAIL_BYTES: usize = 96;

/// One stable per-ref reject reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefRejectReason {
    /// The captured old object id / absence does not satisfy the plan.
    Cas,
    /// PG auth/policy/RBAC/branch-rule/review/check/LFS-lock denial, or a native
    /// LFS byte fact that fails closed.
    Policy,
    /// The NEW target object id does not exist in the verified pack set (per-ref,
    /// not a global closure failure yet).
    MissingTarget,
    /// A `refs/heads/*` target exists but is not a commit object.
    BadObjectType,
    /// A strict `a` vs `a/b` relationship with another final ref name.
    PrefixConflict,
    /// An accepted update would leave HEAD dangling or delete the kept HEAD branch.
    HeadDependency,
}

impl RefRejectReason {
    pub const ALL: [Self; 6] =
        [Self::Cas, Self::Policy, Self::MissingTarget, Self::BadObjectType, Self::PrefixConflict, Self::HeadDependency];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cas => "cas",
            Self::Policy => "policy",
            Self::MissingTarget => "missing_target",
            Self::BadObjectType => "bad_object_type",
            Self::PrefixConflict => "prefix_conflict",
            Self::HeadDependency => "head_dependency",
        }
    }

    pub fn parse(value: &str) -> Result<Self, PackCommitError> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.as_str() == value)
            .ok_or(PackCommitError::Invalid("subset reject reason is not one of the shared six"))
    }
}

/// Validate a persisted detail label: bounded, printable ASCII, no separator.
fn validate_detail(detail: &'static str) -> Result<(), PackCommitError> {
    if detail.is_empty() || detail.len() > MAX_DETAIL_BYTES {
        return Err(PackCommitError::Invalid("subset verdict detail must be 1..=96 bytes"));
    }
    if detail.bytes().any(|byte| byte.is_ascii_control() || !(0x20..=0x7e).contains(&byte) || byte == b':') {
        return Err(PackCommitError::Invalid("subset verdict detail must be printable ASCII without ':'"));
    }
    Ok(())
}

/// One final per-ref verdict, in original plan order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefVerdict {
    name: RefName,
    reason: Option<RefRejectReason>,
    detail: &'static str,
}

impl RefVerdict {
    pub fn accepted(name: RefName) -> Self {
        Self { name, reason: None, detail: "" }
    }

    pub fn rejected(name: RefName, reason: RefRejectReason, detail: &'static str) -> Result<Self, PackCommitError> {
        validate_detail(detail)?;
        Ok(Self { name, reason: Some(reason), detail })
    }

    pub fn name(&self) -> &RefName {
        &self.name
    }

    pub fn is_accepted(&self) -> bool {
        self.reason.is_none()
    }

    pub fn reason(&self) -> Option<RefRejectReason> {
        self.reason
    }

    pub fn detail(&self) -> &'static str {
        self.detail
    }

    /// Persistence row value: `accepted` or `rejected:<reason>:<detail>`.
    pub fn canonical(&self) -> String {
        match self.reason {
            None => "accepted".to_owned(),
            Some(reason) => format!("rejected:{}:{}", reason.as_str(), self.detail),
        }
    }
}

/// Policy input from the decisions owner. A policy verdict can only accept (when
/// the native facts also accept) or reject; it can never resurrect a
/// deterministic rejection, fabricate a target or bypass a byte fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyVerdict {
    name: RefName,
    reason: Option<RefRejectReason>,
    detail: &'static str,
}

impl PolicyVerdict {
    pub fn accept(name: RefName) -> Self {
        Self { name, reason: None, detail: "" }
    }

    /// Reject one ref with a shared-vocabulary reason plus a bounded refinement
    /// label (for example the decisions owner's public reject code).
    pub fn reject(name: RefName, reason: RefRejectReason, detail: &'static str) -> Result<Self, PackCommitError> {
        validate_detail(detail)?;
        Ok(Self { name, reason: Some(reason), detail })
    }

    pub fn name(&self) -> &RefName {
        &self.name
    }

    pub fn rejects(&self) -> bool {
        self.reason.is_some()
    }

    pub fn reason(&self) -> Option<RefRejectReason> {
        self.reason
    }

    pub fn detail(&self) -> Option<&'static str> {
        self.reason.map(|_| self.detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vocabulary_is_stable_and_parses_both_ways() {
        for reason in RefRejectReason::ALL {
            assert_eq!(RefRejectReason::parse(reason.as_str()).unwrap(), reason);
        }
        assert!(RefRejectReason::parse("force_push_denied").is_err());
    }

    #[test]
    fn verdicts_are_bounded_and_canonical() {
        let name = RefName::new("refs/heads/main").unwrap();
        let accepted = RefVerdict::accepted(name.clone());
        assert!(accepted.is_accepted());
        assert_eq!(accepted.canonical(), "accepted");
        let rejected =
            RefVerdict::rejected(name.clone(), RefRejectReason::MissingTarget, "new-target-missing").unwrap();
        assert_eq!(rejected.canonical(), "rejected:missing_target:new-target-missing");
        assert!(RefVerdict::rejected(name.clone(), RefRejectReason::Policy, "").is_err());
        assert!(RefVerdict::rejected(name.clone(), RefRejectReason::Policy, "a:b").is_err());
        assert!(RefVerdict::rejected(name, RefRejectReason::Policy, "line\nbreak").is_err());
        assert!(PolicyVerdict::reject(RefName::new("refs/heads/x").unwrap(), RefRejectReason::Policy, "").is_err());
    }
}
