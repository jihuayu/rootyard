//! Frozen value types of the publication-decision slice.
//!
//! Two vocabularies are deliberately separate: [`DecisionRejectCode`] is a *per-ref* policy verdict
//! code, [`DenialCode`] is a *whole-operation* refusal code. Both are stable literals; neither is ever
//! derived from SQL text, Git output or a caller string. No type here carries a raw token, a token
//! digest, a receipt body or a routable locator.
//!
//! [`DecisionKind`] is the **commit mode** (`Atomic` | `AcceptedSubset`). The **semantic publication
//! action** is the separate [`PublicationAction`] (`Push` | `Merge{..}`). A merge is never inferred
//! from the presence of a `head_ref`; it must be requested explicitly and is bound to the exact pull
//! number/version/head/base facts.
use super::capability::DecisionCapability;
pub(crate) use super::codes::{DecisionRejectCode, DenialCode, ScopeKind};
use super::subset::SelectedPackPlan;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::types::RefUpdate;
use std::fmt;
use uuid::Uuid;

/// Maximum refs in one decision (`MAX_REFS_PER_COMMIT` is 128; the verdict table is bounded too).
pub(crate) const MAX_DECISION_REFS: usize = 128;
/// Retained ceilings per repository; the tenant ceiling is 4x each (existing convention).
pub(crate) const REPO_MAX_DECISIONS: i64 = 2048;
pub(crate) const REPO_MAX_REF_VERDICTS: i64 = 4096;
pub(crate) const REPO_MAX_LOGICAL_BYTES: i64 = 32 * 1024 * 1024;
pub(crate) const TENANT_MAX_DECISIONS: i64 = 4 * REPO_MAX_DECISIONS;
pub(crate) const TENANT_MAX_REF_VERDICTS: i64 = 4 * REPO_MAX_REF_VERDICTS;
pub(crate) const TENANT_MAX_LOGICAL_BYTES: i64 = 4 * REPO_MAX_LOGICAL_BYTES;
/// Maximum admitted lifetime of one decision (`not_after` is capped by this).
pub(crate) const MAX_DECISION_WINDOW_MILLIS: i64 = 30_000;
/// Explicit clock-uncertainty budget for the final admission point.
pub(crate) const CLOCK_UNCERTAINTY_MILLIS: i64 = 250;
/// Maximum reason bytes of a cancellation tombstone.
pub(crate) const MAX_CANCEL_REASON_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecisionKind {
    Atomic,
    AcceptedSubset,
}

impl DecisionKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Atomic => "atomic",
            Self::AcceptedSubset => "accepted_subset",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, DecisionError> {
        match value {
            "atomic" => Ok(Self::Atomic),
            "accepted_subset" => Ok(Self::AcceptedSubset),
            _ => Err(DecisionError::Ledger("unknown decision mode stored in the decision row")),
        }
    }
}

/// Exact pull-request facts a merge action is bound to. Constructing this grants nothing: the live
/// `forge_pulls` row must still match every field under the write-capable table lock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MergeBinding {
    pull_number: i64,
    version: i64,
    head_oid: String,
    base_oid: String,
}

impl MergeBinding {
    pub(crate) fn new(
        pull_number: i64,
        version: i64,
        head_oid: impl Into<String>,
        base_oid: impl Into<String>,
    ) -> Result<Self, DecisionError> {
        let head_oid = head_oid.into();
        let base_oid = base_oid.into();
        if pull_number <= 0 || version <= 0 {
            return Err(DecisionError::Denied(DenialCode::UnsupportedAction));
        }
        if !valid_oid_hex(&head_oid) || !valid_oid_hex(&base_oid) {
            return Err(DecisionError::Denied(DenialCode::UnsupportedAction));
        }
        Ok(Self { pull_number, version, head_oid, base_oid })
    }

    pub(crate) fn pull_number(&self) -> i64 {
        self.pull_number
    }
    pub(crate) fn version(&self) -> i64 {
        self.version
    }
    pub(crate) fn head_oid(&self) -> &str {
        &self.head_oid
    }
    pub(crate) fn base_oid(&self) -> &str {
        &self.base_oid
    }
}

fn valid_oid_hex(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64)
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Semantic action of one publication. It is independent of [`DecisionKind`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PublicationAction {
    /// Direct ref publication with the exact current `ContentsWrite` semantics.
    Push,
    /// Pull-request merge: exact `PullsWrite`, the bound PR facts, current reviews/checks and the
    /// atomic `forge_pulls` finalizer.
    Merge(MergeBinding),
}

impl PublicationAction {
    pub(crate) const fn is_merge(&self) -> bool {
        matches!(self, Self::Merge(_))
    }

    pub(crate) fn merge_binding(&self) -> Option<&MergeBinding> {
        match self {
            Self::Push => None,
            Self::Merge(binding) => Some(binding),
        }
    }

    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Merge(_) => "merge",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecisionState {
    Open,
    Consumed,
    Cancelled,
    Rejected,
}

impl DecisionState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Consumed => "CONSUMED",
            Self::Cancelled => "CANCELLED",
            Self::Rejected => "REJECTED",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, DecisionError> {
        match value {
            "OPEN" => Ok(Self::Open),
            "CONSUMED" => Ok(Self::Consumed),
            "CANCELLED" => Ok(Self::Cancelled),
            "REJECTED" => Ok(Self::Rejected),
            _ => Err(DecisionError::Ledger("unknown decision state stored in the decision row")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DependencyObservation {
    pub kind: ScopeKind,
    pub id: Uuid,
    pub version: i64,
    pub digest: RequestDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuotaScope {
    Repository,
    Tenant,
}

impl QuotaScope {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Repository => "repository",
            Self::Tenant => "tenant",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum QuotaResource {
    Decisions,
    RefVerdicts,
    LogicalBytes,
}

impl QuotaResource {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Decisions => "decisions",
            Self::RefVerdicts => "ref_verdicts",
            Self::LogicalBytes => "logical_bytes",
        }
    }
}

#[derive(Debug)]
pub(crate) enum DecisionError {
    /// The shared migration-138 registry refused (registration, lane, terminal or cancellation).
    RefStore(RefStoreError),
    /// Live authorization refused the subject; nothing was written.
    Denied(DenialCode),
    /// A required fact/row could not be verified; fail closed, never "allow".
    Unverifiable(&'static str),
    /// A dependency-table `SHARE` lock was unavailable (`NOWAIT`). Nothing was written; retry the
    /// whole short transaction under the same operation identity.
    Contended(&'static str),
    /// The expected decision/operation row is missing.
    DecisionNotFound(Uuid),
    /// The decision is already terminal; `state` is what durably won.
    DecisionConflict {
        decision_id: Uuid,
        state: DecisionState,
    },
    /// A cancel-before-install tombstone won; no ref write may be recorded.
    Cancelled {
        operation_id: Uuid,
        decision_id: Option<Uuid>,
    },
    /// The decision was already consumed by this receipt.
    Consumed {
        decision_id: Uuid,
        receipt_id: Uuid,
    },
    QuotaExceeded {
        scope: QuotaScope,
        resource: QuotaResource,
        bound: i64,
        actual: i64,
    },
    /// Persisted rows are partial, rewritten or inconsistent with each other.
    Ledger(&'static str),
    Database(String),
    Timeout,
}

impl fmt::Display for DecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RefStore(error) => write!(formatter, "ref-store registry refused: {error:?}"),
            Self::Denied(code) => write!(formatter, "publication decision denied: {}", code.as_str()),
            Self::Unverifiable(detail) => write!(formatter, "publication decision unverifiable: {detail}"),
            Self::Contended(detail) => write!(formatter, "publication decision lock contended: {detail}"),
            Self::DecisionNotFound(id) => write!(formatter, "publication decision not found: {id}"),
            Self::DecisionConflict { decision_id, state } => {
                write!(formatter, "publication decision {decision_id} is {}", state.as_str())
            }
            Self::Cancelled { operation_id, decision_id } => {
                write!(formatter, "publication operation {operation_id} was cancelled (decision {decision_id:?})")
            }
            Self::Consumed { decision_id, receipt_id } => {
                write!(formatter, "publication decision {decision_id} already consumed by {receipt_id}")
            }
            Self::QuotaExceeded { scope, resource, bound, actual } => write!(
                formatter,
                "publication decision quota {} {}: bound {bound}, would be {actual}",
                scope.as_str(),
                resource.as_str()
            ),
            Self::Ledger(detail) => write!(formatter, "publication decision ledger integrity: {detail}"),
            Self::Database(detail) => write!(formatter, "publication decision database error: {detail}"),
            Self::Timeout => formatter.write_str("publication decision deadline expired"),
        }
    }
}

impl std::error::Error for DecisionError {}

impl From<RefStoreError> for DecisionError {
    fn from(error: RefStoreError) -> Self {
        match error {
            RefStoreError::Timeout => Self::Timeout,
            other => Self::RefStore(other),
        }
    }
}

/// Outcome of the final, in-commit re-check. `Rejected` means **no ref row may be written**.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ConsumptionRecord {
    Consumed {
        decision_id: Uuid,
        receipt_id: Uuid,
        selection_digest: RequestDigest,
        dependencies_digest: RequestDigest,
    },
    Rejected {
        decision_id: Uuid,
        code: DenialCode,
    },
}

/// Exactly one of these outcomes is durable for one operation, in either race order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CancelOutcome {
    Cancelled { operation_id: Uuid, decision_id: Option<Uuid>, tombstone_created: bool },
    AlreadyCancelled { operation_id: Uuid, decision_id: Option<Uuid> },
    AlreadyConsumed { operation_id: Uuid, decision_id: Uuid, receipt_id: Uuid },
    AlreadyRejected { operation_id: Uuid, decision_id: Option<Uuid> },
}

/// The private selected decision. Private fields, no `Clone`, no serde, no public constructor: only
/// [`super::install::select_and_install`] can mint one, and it is the only value
/// [`super::consume::authorized_final_check`] accepts.
///
/// It holds the sealed [`SelectedPackPlan`] derived by `subset::SelectedPackPlan::seal` from the
/// **original whole-batch plan**, the concrete native facts and one policy verdict per original ref.
/// The persisted selection digest and every per-ref verdict are read back from that sealed projection,
/// never from a second decision-owned selection domain.
pub(crate) struct SelectedDecision {
    capability: DecisionCapability,
    projection: SelectedPackPlan,
    verdict_rows: Vec<(String, String)>,
}

impl SelectedDecision {
    pub(super) fn mint(capability: DecisionCapability, projection: SelectedPackPlan) -> Self {
        let verdict_rows = projection.selection().canonical_rows();
        Self { capability, projection, verdict_rows }
    }

    pub(crate) fn capability(&self) -> &DecisionCapability {
        &self.capability
    }
    /// The sealed selected plan. This is the only value a final closure proof may verify.
    pub(crate) fn selected_plan(&self) -> &SelectedPackPlan {
        &self.projection
    }
    pub(crate) fn accepted(&self) -> &[RefUpdate] {
        self.projection.accepted()
    }
    pub(crate) fn accepted_is_empty(&self) -> bool {
        self.projection.is_all_rejected()
    }
    /// The sealed projection digest: original parent + selection digest + accepted set + exact
    /// resulting full ref map.
    pub(crate) fn selection_digest(&self) -> &RequestDigest {
        self.projection.selection_digest()
    }
    pub(crate) fn decision_id(&self) -> Uuid {
        self.capability.decision_id()
    }
    pub(crate) fn operation_id(&self) -> Uuid {
        self.capability.operation_id()
    }
    pub(crate) fn kind(&self) -> DecisionKind {
        self.capability.kind()
    }
    pub(crate) fn action(&self) -> &PublicationAction {
        self.capability.action()
    }
}

impl fmt::Debug for SelectedDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedDecision")
            .field("decision_id", &self.decision_id())
            .field("operation_id", &self.operation_id())
            .field("kind", &self.kind())
            .field("action", &self.action().as_str())
            .field("accepted", &self.accepted().len())
            .field("verdicts", &self.verdict_rows.len())
            .finish()
    }
}
