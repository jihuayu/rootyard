//! Typed domain contracts, canonical digest bindings, and errors for remote-authz PR merges (`Refs #156`).

use std::collections::{BTreeSet, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ref_store::core::state_machine::ScopeLifecycle;
use crate::ref_store::core::types::GitObjectFormat;
use crate::ref_store::projector::{GrantExpectedRealm, SignedDecisionGrant};

pub use super::validation::{
    MergeBindingInputs, compute_merge_binding_digest, compute_observed_checks_digest, compute_required_checks_digest,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteMergeError {
    StaleRequiredChecks { expected_head_oid: String, reason: String },
    StaleHeadOid { pull_number: i64, expected_head_oid: String, actual_head_oid: String },
    TargetRefMoved { ref_name: String, expected_base_oid: String, actual_base_oid: Option<String> },
    RevokedAuthorization(String),
    RemoteAuthzDenied(String),
    AlreadyMerged { pull_number: i64, committed_oid: String, commit_log_index: u64 },
    Equivocation(String),
    ReceiptRegression(String),
    FastForwardNotPossible(String),
    MergeConflict(String),
    UnknownOutcome(String),
    GitFailed { command: String, detail: String },
    PgDatabase(String),
    InvalidInput(String),
    Io(String),
}

impl fmt::Display for RemoteMergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleRequiredChecks { expected_head_oid, reason } => {
                write!(f, "stale or failing required checks for head {expected_head_oid}: {reason}")
            }
            Self::StaleHeadOid { pull_number, expected_head_oid, actual_head_oid } => write!(
                f,
                "stale pull #{pull_number} head OID: expected {expected_head_oid}, observed {actual_head_oid}"
            ),
            Self::TargetRefMoved { ref_name, expected_base_oid, actual_base_oid } => write!(
                f,
                "target ref {ref_name} moved from expected {expected_base_oid} to {actual_base_oid:?}"
            ),
            Self::RevokedAuthorization(msg) => write!(f, "revoked remote authorization: {msg}"),
            Self::RemoteAuthzDenied(msg) => write!(f, "remote authorization denied: {msg}"),
            Self::AlreadyMerged { pull_number, committed_oid, commit_log_index } => write!(
                f,
                "pull #{pull_number} already merged at {committed_oid} (log_index={commit_log_index})"
            ),
            Self::Equivocation(msg) => write!(f, "ref-cas projection equivocation detected: {msg}"),
            Self::ReceiptRegression(msg) => write!(f, "monotonic merge receipt regression rejected: {msg}"),
            Self::FastForwardNotPossible(msg) => write!(f, "fast-forward not possible: {msg}"),
            Self::MergeConflict(msg) => write!(f, "merge conflict detected: {msg}"),
            Self::UnknownOutcome(msg) => write!(f, "merge commit outcome unknown pending recovery: {msg}"),
            Self::GitFailed { command, detail } => write!(f, "git {command} failed: {detail}"),
            Self::PgDatabase(msg) => write!(f, "postgres merge store error: {msg}"),
            Self::InvalidInput(msg) => write!(f, "invalid remote merge input: {msg}"),
            Self::Io(msg) => write!(f, "remote merge I/O error: {msg}"),
        }
    }
}

impl std::error::Error for RemoteMergeError {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MergeStrategy {
    FastForward,
    MergeCommit,
}

impl MergeStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FastForward => "fast_forward",
            Self::MergeCommit => "merge_commit",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PullMergeState {
    PendingMerge,
    CommittedMerge,
    RejectedMerge,
    AbortedBeforeCas,
}

impl PullMergeState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingMerge => "pending_merge",
            Self::CommittedMerge => "committed_merge",
            Self::RejectedMerge => "rejected_merge",
            Self::AbortedBeforeCas => "aborted_before_cas",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, RemoteMergeError> {
        match raw {
            "pending_merge" => Ok(Self::PendingMerge),
            "committed_merge" => Ok(Self::CommittedMerge),
            "rejected_merge" => Ok(Self::RejectedMerge),
            "aborted_before_cas" => Ok(Self::AbortedBeforeCas),
            other => Err(RemoteMergeError::InvalidInput(format!("unknown pull merge state `{other}`"))),
        }
    }

    pub fn is_terminal(self) -> bool {
        self != Self::PendingMerge
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRunSnapshot {
    pub context: String,
    pub commit_oid: String,
    pub base_oid: Option<String>,
    pub status: String,
    pub conclusion: Option<String>,
    pub sequence: i64,
    pub attempt: i64,
    pub trusted: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveAuthzScopeState {
    pub scope_kind: String,
    pub scope_id: Uuid,
    pub lifecycle: ScopeLifecycle,
    pub authz_floor: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergePullSnapshot {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pull_number: i64,
    pub state: String,
    pub head_ref: String,
    pub base_ref: String,
    pub head_oid: String,
    pub base_oid: String,
    pub merge_commit_oid: Option<String>,
    pub version: i64,
    pub storage_generation: i64,
    pub object_format: GitObjectFormat,
    pub live_head_ref_oid: String,
    pub live_base_ref_oid: String,
    pub require_fast_forward: bool,
    pub required_checks: Vec<String>,
    pub min_check_sequence: i64,
    pub observed_checks: Vec<CheckRunSnapshot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergeAttemptSpec {
    pub attempt_id: Uuid,
    pub operation_id: Uuid,
    pub decision_id: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub actor_id: Uuid,
    pub lane: String,
    pub sequence: i64,
    pub pull_number: i64,
    pub base_ref: String,
    pub expected_head_oid: String,
    pub expected_base_oid: String,
    pub candidate_target_oid: String,
    pub expected_version: i64,
    pub expected_storage_generation: i64,
    pub expected_base_revision: i64,
    pub strategy: MergeStrategy,
    pub object_format: GitObjectFormat,
    pub realm: GrantExpectedRealm,
    pub expected_service_san: String,
    pub grant: SignedDecisionGrant,
    pub current_logical_tick: u64,
    pub live_scopes: Vec<LiveAuthzScopeState>,
    pub cancelled_operations: BTreeSet<Uuid>,
    pub pack_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingMergeRecord {
    pub attempt_id: Uuid,
    pub operation_id: Uuid,
    pub decision_id: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pull_number: i64,
    pub base_ref: String,
    pub expected_head_oid: String,
    pub expected_base_oid: String,
    pub candidate_target_oid: String,
    pub expected_version: i64,
    pub expected_storage_generation: i64,
    pub strategy: MergeStrategy,
    pub authz_epoch: i64,
    pub pack_sha256: String,
    pub facts_digest: String,
    pub state: PullMergeState,
    pub commit_log_index: Option<u64>,
    pub commit_log_term: Option<u64>,
    pub merged_oid: Option<String>,
    pub terminal_digest: Option<String>,
    pub reject_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedMergeReceipt {
    pub attempt_id: Uuid,
    pub operation_id: Uuid,
    pub decision_id: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pull_number: i64,
    pub base_ref: String,
    pub previous_base_oid: String,
    pub expected_head_oid: String,
    pub merged_oid: String,
    pub pack_sha256: String,
    pub binding_digest: String,
    pub commit_log_index: u64,
    pub commit_log_term: u64,
    pub gate_revision: i64,
    pub terminal_digest: String,
    pub replayed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedMergeReceipt {
    pub attempt_id: Uuid,
    pub operation_id: Uuid,
    pub decision_id: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pull_number: i64,
    pub base_ref: String,
    pub expected_base_oid: String,
    pub expected_head_oid: String,
    pub candidate_target_oid: String,
    pub pack_sha256: String,
    pub binding_digest: String,
    pub commit_log_index: Option<u64>,
    pub commit_log_term: Option<u64>,
    pub state: PullMergeState,
    pub reason: String,
    pub terminal_digest: Option<String>,
}

impl PendingMergeRecord {
    pub fn into_committed_receipt(
        &self,
        merged_oid: String,
        commit_log_index: u64,
        commit_log_term: u64,
        gate_revision: i64,
        terminal_digest: String,
        replayed: bool,
    ) -> CommittedMergeReceipt {
        CommittedMergeReceipt {
            attempt_id: self.attempt_id,
            operation_id: self.operation_id,
            decision_id: self.decision_id,
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            pull_number: self.pull_number,
            base_ref: self.base_ref.clone(),
            previous_base_oid: self.expected_base_oid.clone(),
            expected_head_oid: self.expected_head_oid.clone(),
            merged_oid,
            pack_sha256: self.pack_sha256.clone(),
            binding_digest: self.facts_digest.clone(),
            commit_log_index,
            commit_log_term,
            gate_revision,
            terminal_digest,
            replayed,
        }
    }

    pub fn into_rejected_receipt(
        &self,
        commit_log_index: Option<u64>,
        commit_log_term: Option<u64>,
        reason: String,
        terminal_digest: Option<String>,
    ) -> RejectedMergeReceipt {
        RejectedMergeReceipt {
            attempt_id: self.attempt_id,
            operation_id: self.operation_id,
            decision_id: self.decision_id,
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            pull_number: self.pull_number,
            base_ref: self.base_ref.clone(),
            expected_base_oid: self.expected_base_oid.clone(),
            expected_head_oid: self.expected_head_oid.clone(),
            candidate_target_oid: self.candidate_target_oid.clone(),
            pack_sha256: self.pack_sha256.clone(),
            binding_digest: self.facts_digest.clone(),
            commit_log_index,
            commit_log_term,
            state: PullMergeState::RejectedMerge,
            reason,
            terminal_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionOutcome {
    ProjectedCommitted { replayed: bool },
    ProjectedRejected { replayed: bool },
    ProjectedAborted { replayed: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeAttemptOutcome {
    Committed(CommittedMergeReceipt),
    Rejected(RejectedMergeReceipt),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedPullRecord {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pull_number: i64,
    pub state: String,
    pub head_oid: String,
    pub base_oid: String,
    pub merge_commit_oid: Option<String>,
    pub merged_storage_generation: Option<i64>,
    pub version: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MergeFaultInjection {
    #[default]
    None,
    DisconnectBeforePendingInsert,
    DisconnectAfterPendingBeforeCas,
    CoordinatorTimeoutAfterCasBeforeProjection,
    DisconnectDuringProjectionCommit,
}

pub(super) fn sha256_hex_valid(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn oid_valid_for_format(oid: &str, fmt: GitObjectFormat) -> bool {
    let expected_len = fmt.oid_hex_len();
    oid.len() == expected_len
        && oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && oid.bytes().any(|b| b != b'0')
}

pub(super) fn unique_sorted_checks(required_checks: &[String]) -> Result<Vec<String>, RemoteMergeError> {
    let mut out = Vec::with_capacity(required_checks.len());
    let mut seen = HashSet::with_capacity(required_checks.len());
    for ctx in required_checks {
        if ctx.is_empty() || ctx.len() > 128 || ctx.trim().is_empty() {
            return Err(RemoteMergeError::InvalidInput(format!("invalid required check context `{ctx}`")));
        }
        if seen.insert(ctx.clone()) {
            out.push(ctx.clone());
        }
    }
    out.sort();
    Ok(out)
}
