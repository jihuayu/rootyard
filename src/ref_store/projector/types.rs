//! Core domain types for deterministic Ref-CAS event replay, PostgreSQL
//! projection, reliable business job bridging, and truncation closures (#117).

use crate::ref_store::core::state_machine::StateMachineEvent;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use uuid::Uuid;

pub const MAX_REPLAY_BATCH: usize = 256;
pub const DEFAULT_REPLAY_BATCH: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    InvalidInput(String),
    Decode(String),
    SequenceGap {
        expected_min_event_seq: u64,
        got_event_seq: u64,
    },
    StreamRegression(String),
    Equivocation {
        op_event_id: String,
        expected_digest: String,
        actual_digest: String,
    },
    TruncatedBeforeCursor {
        cutoff_log_index: u64,
        cutoff_event_seq: u64,
        cursor_log_index: u64,
        cursor_event_seq: u64,
        closure_digest: String,
    },
    ResyncRequired(String),
    AuthorityViolation(&'static str),
    Database(String),
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "invalid ref-cas projection input: {msg}"),
            Self::Decode(msg) => write!(f, "ref-cas projection decode failure: {msg}"),
            Self::SequenceGap { expected_min_event_seq, got_event_seq } => write!(
                f,
                "out-of-order ref-cas event gap: expected event_seq {expected_min_event_seq}, got {got_event_seq}"
            ),
            Self::StreamRegression(msg) => write!(f, "ref-cas projection stream regression: {msg}"),
            Self::Equivocation { op_event_id, expected_digest, actual_digest } => write!(
                f,
                "ref-cas event equivocation on {op_event_id}: expected digest {expected_digest}, got {actual_digest}"
            ),
            Self::TruncatedBeforeCursor {
                cutoff_log_index,
                cutoff_event_seq,
                cursor_log_index,
                cursor_event_seq,
                closure_digest,
            } => write!(
                f,
                "ref-cas stream truncated past durable cursor: cutoff=({cutoff_log_index},{cutoff_event_seq}) \
                 cursor=({cursor_log_index},{cursor_event_seq}) closure={closure_digest}"
            ),
            Self::ResyncRequired(msg) => write!(f, "ref-cas projection resync required: {msg}"),
            Self::AuthorityViolation(msg) => write!(f, "ref-cas projection authority violation: {msg}"),
            Self::Database(msg) => write!(f, "ref-cas projection database error: {msg}"),
        }
    }
}

impl std::error::Error for ProjectionError {}

/// Immutable consensus-stream realm identifying which Ref-CAS log stream produced an event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRealm {
    pub history_incarnation: Uuid,
    pub group_id: i64,
    pub group_epoch: i64,
}

impl ProjectionRealm {
    pub fn new(history_incarnation: Uuid, group_id: i64, group_epoch: i64) -> Result<Self, ProjectionError> {
        let realm = Self { history_incarnation, group_id, group_epoch };
        realm.validate()?;
        Ok(realm)
    }

    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self.history_incarnation.is_nil() {
            return Err(ProjectionError::InvalidInput("history_incarnation must be non-nil".into()));
        }
        if self.group_id < 0 {
            return Err(ProjectionError::InvalidInput("group_id must be non-negative".into()));
        }
        if self.group_epoch < 1 {
            return Err(ProjectionError::InvalidInput("group_epoch must be >= 1".into()));
        }
        Ok(())
    }
}

/// Sealed archive / retention boundary proving everything at or before `event_seq` /
/// `log_index` was retained with `closure_digest` prior to Raft log compaction.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TruncationCutoff {
    pub log_index: u64,
    pub event_seq: u64,
    pub log_term: u64,
    pub closure_digest: String,
    pub archive_uri: Option<String>,
}

impl TruncationCutoff {
    pub fn validate(&self) -> Result<(), ProjectionError> {
        if self.log_index == 0 || self.event_seq == 0 {
            return Err(ProjectionError::InvalidInput("truncation cutoff indices must be >= 1".into()));
        }
        if !is_sha256_hex(&self.closure_digest) {
            return Err(ProjectionError::InvalidInput(
                "truncation closure_digest must be 64 lowercase hex chars".into(),
            ));
        }
        if let Some(uri) = &self.archive_uri
            && (uri.is_empty() || uri.len() > 1024)
        {
            return Err(ProjectionError::InvalidInput("truncation archive_uri length out of bounds".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionStreamState {
    Active,
    ResyncRequired,
}

impl ProjectionStreamState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ResyncRequired => "resync_required",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, ProjectionError> {
        match raw {
            "active" => Ok(Self::Active),
            "resync_required" => Ok(Self::ResyncRequired),
            other => Err(ProjectionError::Decode(format!("unknown projection stream state `{other}`"))),
        }
    }
}

/// Durable cursor persisted atomically with projection effects, webhooks, and reliable jobs.
/// Replay always resumes from these explicit consensus coordinates — never from `MAX(id)`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCursor {
    pub realm: ProjectionRealm,
    pub applied_event_seq: u64,
    pub applied_log_index: u64,
    pub applied_log_term: u64,
    pub last_event_id: Option<String>,
    pub truncation_cutoff: Option<TruncationCutoff>,
    pub stream_state: ProjectionStreamState,
}

impl ProjectionCursor {
    pub fn genesis(realm: ProjectionRealm) -> Result<Self, ProjectionError> {
        realm.validate()?;
        Ok(Self {
            realm,
            applied_event_seq: 0,
            applied_log_index: 0,
            applied_log_term: 0,
            last_event_id: None,
            truncation_cutoff: None,
            stream_state: ProjectionStreamState::Active,
        })
    }
}

/// One immutable terminal event read from a Ref-CAS state machine / consensus log.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefCasEventEnvelope {
    pub realm: ProjectionRealm,
    pub event_seq: u64,
    pub log_index: u64,
    pub log_term: u64,
    pub repository_id: Uuid,
    pub tenant_id: Option<Uuid>,
    /// Historical actor/token snapshot recorded purely for audit visibility. Never inspected as
    /// live authorization and never allowed to authorize any new ref write.
    pub actor_id: Option<Uuid>,
    pub token_id: Option<Uuid>,
    pub revision: i64,
    pub operation_id: Uuid,
    pub outcome: String,
    pub payload: Value,
}

impl RefCasEventEnvelope {
    pub fn from_state_machine_event(
        realm: ProjectionRealm,
        tenant_id: Option<Uuid>,
        actor_id: Option<Uuid>,
        token_id: Option<Uuid>,
        event: &StateMachineEvent,
    ) -> Result<Self, ProjectionError> {
        let env = Self {
            realm,
            event_seq: event.event_seq,
            log_index: event.log_index,
            log_term: event.log_term,
            repository_id: event.repository_id,
            tenant_id,
            actor_id,
            token_id,
            revision: event.revision,
            operation_id: event.operation_id,
            outcome: event.outcome.clone(),
            payload: event.payload.clone(),
        };
        env.validate()?;
        Ok(env)
    }

    pub fn validate(&self) -> Result<(), ProjectionError> {
        self.realm.validate()?;
        if self.event_seq == 0 {
            return Err(ProjectionError::InvalidInput("event_seq must be >= 1".into()));
        }
        if self.log_index == 0 {
            return Err(ProjectionError::InvalidInput("log_index must be >= 1".into()));
        }
        if self.repository_id.is_nil() {
            return Err(ProjectionError::InvalidInput("repository_id must be non-nil".into()));
        }
        if let Some(tenant_id) = self.tenant_id
            && tenant_id.is_nil()
        {
            return Err(ProjectionError::InvalidInput("tenant_id must be non-nil when present".into()));
        }
        if self.operation_id.is_nil() {
            return Err(ProjectionError::InvalidInput("operation_id must be non-nil".into()));
        }
        if self.revision < 0 {
            return Err(ProjectionError::InvalidInput("revision must be >= 0".into()));
        }
        if self.outcome.is_empty() || self.outcome.len() > 64 {
            return Err(ProjectionError::InvalidInput("outcome length out of bounds".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionJobKind {
    CiSync,
    RepoIndexRefresh,
    ArtifactReconcile,
    BackupCheckpoint,
}

impl ProjectionJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CiSync => "ci_sync",
            Self::RepoIndexRefresh => "repo_index_refresh",
            Self::ArtifactReconcile => "artifact_reconcile",
            Self::BackupCheckpoint => "backup_checkpoint",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, ProjectionError> {
        match raw {
            "ci_sync" => Ok(Self::CiSync),
            "repo_index_refresh" => Ok(Self::RepoIndexRefresh),
            "artifact_reconcile" => Ok(Self::ArtifactReconcile),
            "backup_checkpoint" => Ok(Self::BackupCheckpoint),
            other => Err(ProjectionError::Decode(format!("unknown projection job kind `{other}`"))),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionJobState {
    Queued,
    Running,
    Succeeded,
    Failed,
    UnknownHold,
}

impl ProjectionJobState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::UnknownHold => "unknown_hold",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, ProjectionError> {
        match raw {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "unknown_hold" => Ok(Self::UnknownHold),
            other => Err(ProjectionError::Decode(format!("unknown projection job state `{other}`"))),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionJobSpec {
    pub job_key: String,
    pub repository_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub op_event_id: String,
    pub realm: ProjectionRealm,
    pub log_index: u64,
    pub event_seq: u64,
    pub kind: ProjectionJobKind,
    pub scope_key: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionJobRecord {
    pub job_key: String,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub op_event_id: String,
    pub realm: ProjectionRealm,
    pub log_index: u64,
    pub event_seq: u64,
    pub kind: ProjectionJobKind,
    pub scope_key: String,
    pub state: ProjectionJobState,
    pub attempt: i64,
    pub claim_generation: i64,
    pub lease_owner: Option<Uuid>,
    pub last_error: Option<String>,
    pub payload: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcomeSummary {
    Committed,
    Rejected,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedOperationRecord {
    pub op_event_id: String,
    pub realm: ProjectionRealm,
    pub log_index: u64,
    pub log_term: u64,
    pub event_seq: u64,
    pub repository_id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub operation_id: Uuid,
    pub revision: i64,
    pub outcome: String,
    pub head_ref: Option<String>,
    pub actor_id: Option<Uuid>,
    pub token_id: Option<Uuid>,
    pub terminal_digest: String,
    pub applied_ref_count: usize,
    pub can_authorize_write: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedRefDelta {
    pub event_id: String,
    pub webhook_event_id: String,
    pub ref_sequence: i64,
    pub ref_name: String,
    pub old_oid: Option<String>,
    pub new_oid: Option<String>,
    pub deleted: bool,
    pub emit_push_webhook: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedRefState {
    pub repository_id: Uuid,
    pub ref_name: String,
    pub oid: Option<String>,
    pub deleted: bool,
    pub revision: i64,
    pub realm: ProjectionRealm,
    pub log_index: u64,
    pub log_term: u64,
    pub event_seq: u64,
    pub op_event_id: String,
    pub can_authorize_write: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedOperationProjection {
    pub operation: ProjectedOperationRecord,
    pub deltas: Vec<ProjectedRefDelta>,
    pub jobs: Vec<ProjectionJobSpec>,
    pub summary: TerminalOutcomeSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SingleEventOutcome {
    Applied {
        op_event_id: String,
        projected_refs: usize,
        enqueued_webhooks: usize,
        enqueued_jobs: usize,
        cursor: ProjectionCursor,
    },
    DuplicateSkipped {
        op_event_id: String,
        cursor: ProjectionCursor,
    },
    ResyncRequired {
        cursor: ProjectionCursor,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayBatchOutcome {
    pub applied_events: usize,
    pub duplicate_skipped: usize,
    pub projected_refs: usize,
    pub enqueued_webhooks: usize,
    pub enqueued_jobs: usize,
    pub batches: usize,
    pub cursor: ProjectionCursor,
}

/// Runtime source slice returned by a Ref-CAS log / state machine stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RefCasEventPage {
    pub realm: ProjectionRealm,
    pub events: Vec<RefCasEventEnvelope>,
    pub earliest_available_event_seq: u64,
    pub earliest_available_log_index: u64,
    pub truncation_cutoff: Option<TruncationCutoff>,
    pub has_more: bool,
}

pub(crate) fn is_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
