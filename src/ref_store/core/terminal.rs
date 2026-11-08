//! Immutable commit terminal, per-ref results and the pre-write size budget.
//!
//! The migration-138 registry stores one `TerminalResult` per operation, whose
//! canonical JSON body is bounded to 64 KiB. A core commit of up to 128 refs
//! with 1024-byte names can produce a larger body, so the aggregate worst case
//! of *both* the committed and the rejected terminal is serialized exactly
//! before the registry is touched. This keeps every fallible terminal
//! conversion ahead of the first write: a short transaction never has to choose
//! between a Rust error and already-written refs/revision/events.
use super::super::contract::{OperationRecord, OperationState, RefStoreError, TerminalResult};
use super::types::RefUpdate;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Widest object id this core can ever store (SHA-256, lowercase hex).
const WORST_CASE_OID: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const BRANCH_PREFIX: &str = "refs/heads/";
const MAX_HEAD_BYTES: usize = 1024;
const MAX_REF_NAME_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitRejectCode {
    GateNotFound,
    TenantMismatch,
    ObjectFormatMismatch,
    HistoryIncarnationMismatch,
    AuthorityEpochMismatch,
    GroupEpochMismatch,
    RevisionMismatch,
    OldOidMismatch,
    PrefixConflict,
    HeadDeletedWithoutRetarget,
    HeadTargetMissing,
}

impl CommitRejectCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GateNotFound => "gate_not_found",
            Self::TenantMismatch => "tenant_mismatch",
            Self::ObjectFormatMismatch => "object_format_mismatch",
            Self::HistoryIncarnationMismatch => "history_incarnation_mismatch",
            Self::AuthorityEpochMismatch => "authority_epoch_mismatch",
            Self::GroupEpochMismatch => "group_epoch_mismatch",
            Self::RevisionMismatch => "revision_mismatch",
            Self::OldOidMismatch => "old_oid_mismatch",
            Self::PrefixConflict => "prefix_conflict",
            Self::HeadDeletedWithoutRetarget => "head_deleted_without_retarget",
            Self::HeadTargetMissing => "head_target_missing",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitRejection {
    pub code: CommitRejectCode,
    pub ref_name: Option<String>,
    pub expected: Option<String>,
    pub actual: Option<String>,
}

#[cfg(test)]
impl CommitRejection {
    fn new(code: CommitRejectCode) -> Self {
        Self { code, ref_name: None, expected: None, actual: None }
    }

    fn with_ref(mut self, ref_name: impl Into<String>, expected: Option<String>, actual: Option<String>) -> Self {
        self.ref_name = Some(ref_name.into());
        self.expected = expected;
        self.actual = actual;
        self
    }
}

/// Deterministic per-ref result. Atomic mode is all `applied` or all
/// `not_applied`; it never reports a mixed committed batch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RefCommitResult {
    Applied { name: String, old_oid: Option<String>, new_oid: Option<String> },
    NotApplied { name: String, reason: CommitRejectCode },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalKind {
    Committed,
    Rejected,
}

/// Persisted once as the operation terminal and replayed byte-for-byte.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CommitTerminal {
    pub kind: TerminalKind,
    pub repository_id: Uuid,
    pub revision: i64,
    pub head_ref: Option<String>,
    pub refs: Vec<RefCommitResult>,
    pub rejection: Option<CommitRejection>,
}

impl CommitTerminal {
    pub(crate) fn committed(
        repository_id: Uuid,
        revision: i64,
        head_ref: String,
        refs: Vec<RefCommitResult>,
    ) -> Self {
        Self { kind: TerminalKind::Committed, repository_id, revision, head_ref: Some(head_ref), refs, rejection: None }
    }

    pub(crate) fn rejected(
        repository_id: Uuid,
        revision: i64,
        head_ref: Option<String>,
        refs: Vec<RefCommitResult>,
        rejection: CommitRejection,
    ) -> Self {
        Self { kind: TerminalKind::Rejected, repository_id, revision, head_ref, refs, rejection: Some(rejection) }
    }

    pub fn is_committed(&self) -> bool {
        self.kind == TerminalKind::Committed
    }

    /// Canonical conversion into the bounded registry result. Every field that
    /// reaches this function was already accepted by [`ensure_terminal_budget`]
    /// for the whole request, so a real commit cannot fail here.
    pub(crate) fn to_terminal_result(&self) -> Result<TerminalResult, RefStoreError> {
        let value = serde_json::to_value(self)
            .map_err(|_| RefStoreError::InvalidIdentity("commit terminal is not serializable".into()))?;
        TerminalResult::json(value)
    }

    pub(crate) fn from_terminal_result(result: &TerminalResult) -> Result<Self, RefStoreError> {
        serde_json::from_value(result.value().clone())
            .map_err(|_| RefStoreError::Database("stored core terminal is not a commit terminal".into()))
    }
}

/// Refuse a request whose worst-case committed *or* rejected terminal would
/// exceed the unchanged 64 KiB registry `TerminalResult` body.
///
/// This runs before `PgRefStore::begin`, so an oversized batch can never leave a
/// pending operation, a ref row, a gate revision or an event behind. The bound
/// serializes the exact canonical JSON shape with the actual ref names of this
/// request, the widest object id, the longest branch HEAD, the largest revision
/// and the largest rejection detail. `i64::MAX` is conservative because a real
/// gate revision only has fewer decimal digits; a max-length extra ref name in
/// the rejection is larger than any real conflicting row name.
pub(crate) fn ensure_terminal_budget(repository_id: Uuid, refs: &[RefUpdate]) -> Result<(), RefStoreError> {
    let head = worst_case_branch();
    let committed = CommitTerminal::committed(
        repository_id,
        i64::MAX,
        head.clone(),
        refs.iter()
            .map(|update| RefCommitResult::Applied {
                name: update.name().as_str().to_owned(),
                old_oid: Some(WORST_CASE_OID.to_owned()),
                new_oid: Some(WORST_CASE_OID.to_owned()),
            })
            .collect(),
    );
    committed.to_terminal_result()?;
    let rejection = CommitRejection {
        code: CommitRejectCode::PrefixConflict,
        ref_name: Some(worst_case_ref_name()),
        expected: Some(WORST_CASE_OID.to_owned()),
        actual: Some(WORST_CASE_OID.to_owned()),
    };
    let rejected = CommitTerminal::rejected(
        repository_id,
        i64::MAX,
        Some(head),
        refs.iter()
            .map(|update| RefCommitResult::NotApplied {
                name: update.name().as_str().to_owned(),
                reason: CommitRejectCode::OldOidMismatch,
            })
            .collect(),
        rejection,
    );
    rejected.to_terminal_result()?;
    Ok(())
}

/// A max-length ref name is valid Git and fits the gate/ref name checks.
fn worst_case_ref_name() -> String {
    let filler = MAX_REF_NAME_BYTES - BRANCH_PREFIX.len();
    format!("{BRANCH_PREFIX}{}", "a".repeat(filler))
}

/// A max-length branch name is valid Git and fits the gate/ref/HEAD checks.
fn worst_case_branch() -> String {
    let filler = MAX_HEAD_BYTES - BRANCH_PREFIX.len();
    format!("{BRANCH_PREFIX}{}", "z".repeat(filler))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitRefsReceipt {
    pub record: OperationRecord,
    /// True only when an identical terminal was already durable. The exact
    /// saved `TerminalResult` remains in `record`.
    pub replayed: bool,
    pub terminal: CommitTerminal,
}

impl CommitRefsReceipt {
    pub fn is_committed(&self) -> bool {
        self.terminal.is_committed() && self.record.state() == OperationState::Committed
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::{GitOid, RefName, RefPrecondition, RefTarget};
    use super::*;

    fn oid(byte: u8) -> GitOid {
        GitOid::Sha1([byte; 20])
    }

    fn update(name: &str) -> RefUpdate {
        RefUpdate::new(RefName::new(name).unwrap(), RefPrecondition::Absent, RefTarget::Oid(oid(1)))
    }

    fn long_name(index: usize) -> String {
        format!("refs/heads/{index:03}{}", "a".repeat(MAX_REF_NAME_BYTES - BRANCH_PREFIX.len() - 3))
    }

    #[test]
    fn terminal_serialization_round_trips_exactly() {
        let terminal = CommitTerminal::committed(
            Uuid::new_v4(),
            7,
            "refs/heads/main".into(),
            vec![RefCommitResult::Applied {
                name: "refs/heads/main".into(),
                old_oid: None,
                new_oid: Some(oid(1).as_hex()),
            }],
        );
        let stored = terminal.to_terminal_result().unwrap();
        assert_eq!(CommitTerminal::from_terminal_result(&stored).unwrap(), terminal);
        assert!(terminal.is_committed());

        let rejected = CommitTerminal::rejected(
            Uuid::new_v4(),
            7,
            Some("refs/heads/main".into()),
            vec![RefCommitResult::NotApplied {
                name: "refs/heads/main".into(),
                reason: CommitRejectCode::OldOidMismatch,
            }],
            CommitRejection::new(CommitRejectCode::OldOidMismatch).with_ref(
                "refs/heads/main",
                Some(oid(1).as_hex()),
                None,
            ),
        );
        let stored = rejected.to_terminal_result().unwrap();
        assert_eq!(CommitTerminal::from_terminal_result(&stored).unwrap(), rejected);
        assert!(!rejected.is_committed());
    }

    #[test]
    fn terminal_budget_accepts_one_max_length_valid_name() {
        // Exactly 128 refs with 1024-byte names cannot fit, but a single
        // maximum-length ref must not be over-rejected.
        let name = long_name(0);
        assert_eq!(name.len(), MAX_REF_NAME_BYTES);
        ensure_terminal_budget(Uuid::new_v4(), std::slice::from_ref(&update(&name))).unwrap();
    }

    #[test]
    fn terminal_budget_rejects_128_max_length_names_before_any_write() {
        let refs = (0..128).map(|index| update(&long_name(index))).collect::<Vec<_>>();
        let error = ensure_terminal_budget(Uuid::new_v4(), &refs).expect_err("oversized terminal was accepted");
        assert!(
            matches!(error, RefStoreError::InvalidIdentity(ref message) if message.contains("64 KiB")),
            "unexpected {error}"
        );
    }

    #[test]
    fn terminal_budget_rejects_only_aggregate_overflow() {
        // 60 max-length names overflow the committed bound (about 71 KiB), so
        // they are rejected; 40 fit in both the committed and rejected shape.
        let oversized = (0..60).map(|index| update(&long_name(index))).collect::<Vec<_>>();
        assert!(ensure_terminal_budget(Uuid::new_v4(), &oversized).is_err());
        let fitting = (0..40).map(|index| update(&long_name(index))).collect::<Vec<_>>();
        assert!(ensure_terminal_budget(Uuid::new_v4(), &fitting).is_ok());
    }
}
