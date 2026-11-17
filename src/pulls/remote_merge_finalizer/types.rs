//! Typed domain contracts, canonical digest bindings, and errors for remote-authz PR merges (`Refs #156`).

use std::collections::{BTreeSet, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::state_machine::ScopeLifecycle;
use crate::ref_store::core::types::GitObjectFormat;
use crate::ref_store::projector::{GrantExpectedRealm, SignedDecisionGrant};

const MERGE_BINDING_DOMAIN: &[u8] = b"rootyard/pulls/remote-merge-binding/v1";
const REQUIRED_CHECKS_DOMAIN: &[u8] = b"rootyard/pulls/required-checks/v1";

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
    pub operation_id: Uuid,
    pub decision_id: Uuid,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pull_number: i64,
    pub base_ref: String,
    pub previous_base_oid: String,
    pub merged_oid: String,
    pub commit_log_index: u64,
    pub commit_log_term: u64,
    pub gate_revision: i64,
    pub terminal_digest: String,
    pub replayed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedMergeReceipt {
    pub operation_id: Uuid,
    pub repository_id: Uuid,
    pub pull_number: i64,
    pub commit_log_index: Option<u64>,
    pub commit_log_term: Option<u64>,
    pub state: PullMergeState,
    pub reason: String,
    pub terminal_digest: Option<String>,
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

pub fn compute_required_checks_digest(required_checks: &[String], min_sequence: i64) -> String {
    let mut unique: Vec<&str> = required_checks.iter().map(String::as_str).collect();
    unique.sort_unstable();
    unique.dedup();
    let mut h = Sha256::new();
    h.update(REQUIRED_CHECKS_DOMAIN);
    h.update([0]);
    h.update(min_sequence.to_be_bytes());
    h.update((unique.len() as u64).to_be_bytes());
    for ctx in unique {
        h.update((ctx.len() as u64).to_be_bytes());
        h.update(ctx.as_bytes());
    }
    hex::encode(h.finalize())
}

#[derive(Clone, Debug)]
pub struct MergeBindingInputs<'a> {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pull_number: i64,
    pub actor_id: Uuid,
    pub operation_id: Uuid,
    pub decision_id: Uuid,
    pub base_ref: &'a str,
    pub expected_head_oid: &'a str,
    pub expected_base_oid: &'a str,
    pub candidate_target_oid: &'a str,
    pub strategy: MergeStrategy,
    pub expected_version: i64,
    pub expected_storage_generation: i64,
    pub required_checks: &'a [String],
    pub min_check_sequence: i64,
    pub authz_epoch: i64,
}

pub fn compute_merge_binding_digest(inputs: &MergeBindingInputs<'_>) -> String {
    let checks_digest = compute_required_checks_digest(inputs.required_checks, inputs.min_check_sequence);
    let mut h = Sha256::new();
    h.update(MERGE_BINDING_DOMAIN);
    h.update([0]);
    for id in [inputs.tenant_id, inputs.repository_id, inputs.actor_id, inputs.operation_id, inputs.decision_id] {
        h.update(id.as_bytes());
    }
    for n in [
        inputs.pull_number,
        inputs.expected_version,
        inputs.expected_storage_generation,
        inputs.min_check_sequence,
        inputs.authz_epoch,
    ] {
        h.update(n.to_be_bytes());
    }
    for s in [
        inputs.base_ref,
        inputs.expected_head_oid,
        inputs.expected_base_oid,
        inputs.candidate_target_oid,
        inputs.strategy.as_str(),
        &checks_digest,
    ] {
        h.update((s.len() as u64).to_be_bytes());
        h.update(s.as_bytes());
    }
    hex::encode(h.finalize())
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
