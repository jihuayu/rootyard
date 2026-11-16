//! Asynchronous PostgreSQL Ref-CAS projection dependency verifier and
//! atomic contiguous-frontier advancement guards over Migration 149 tables (#175).

use std::fmt;
use std::time::Duration;

use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;
use tokio_postgres::GenericClient;
use uuid::Uuid;

use super::pg::{load_cursor, pg_err, project_event_in_tx, to_pg_i64};
use super::types::{
    ProjectionCursor, ProjectionError, ProjectionRealm, ProjectionStreamState, RefCasEventEnvelope, SingleEventOutcome,
    TruncationCutoff, is_sha256_hex,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionDependencyTarget {
    pub realm: ProjectionRealm,
    pub min_log_index: u64,
    pub min_event_seq: u64,
    pub required_op_event_id: Option<String>,
    pub required_repository_id: Option<Uuid>,
    pub min_repo_revision: Option<i64>,
}

impl ProjectionDependencyTarget {
    pub fn validate(&self) -> Result<(), ProjectionDependencyError> {
        self.realm.validate().map_err(|e| ProjectionDependencyError::InvalidInput(e.to_string()))?;
        if self.min_log_index == 0 || self.min_event_seq == 0 {
            return Err(ProjectionDependencyError::InvalidInput("min_log_index and min_event_seq must be >= 1".into()));
        }
        if let Some(op_id) = &self.required_op_event_id
            && !is_sha256_hex(op_id)
        {
            return Err(ProjectionDependencyError::InvalidInput(
                "required_op_event_id must be 64 lowercase hex characters".into(),
            ));
        }
        if let Some(rev) = self.min_repo_revision
            && rev < 0
        {
            return Err(ProjectionDependencyError::InvalidInput("min_repo_revision must be >= 0".into()));
        }
        if self.min_repo_revision.is_some() && self.required_repository_id.is_none() {
            return Err(ProjectionDependencyError::InvalidInput(
                "min_repo_revision requires required_repository_id".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionDependencyError {
    InvalidInput(String),
    StreamNotInitialized { group_id: i64, history_incarnation: Uuid },
    RealmEpochMismatch { expected_min_epoch: i64, actual_epoch: i64 },
    BehindFrontier { expected_log_index: u64, expected_event_seq: u64, actual_log_index: u64, actual_event_seq: u64 },
    SequenceGapOrResync { expected_event_seq: u64, cursor: ProjectionCursor },
    MissingRequiredOperation { op_event_id: String, cursor: ProjectionCursor },
    RevisionBehind { repository_id: Uuid, required_revision: i64, projected_revision: Option<i64> },
    AuthorityViolation(&'static str),
    Timeout { group_id: i64, history_incarnation: Uuid, min_log_index: u64, min_event_seq: u64, last_reason: String },
    Database(String),
}

impl fmt::Display for ProjectionDependencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "invalid projection dependency target: {msg}"),
            Self::StreamNotInitialized { group_id, history_incarnation } => {
                write!(f, "projection cursor absent for group={group_id} history={history_incarnation}")
            }
            Self::RealmEpochMismatch { expected_min_epoch, actual_epoch } => {
                write!(f, "projection group_epoch={actual_epoch} behind required {expected_min_epoch}")
            }
            Self::BehindFrontier { expected_log_index, expected_event_seq, actual_log_index, actual_event_seq } => {
                write!(
                    f,
                    "projection frontier ({actual_log_index},{actual_event_seq}) behind \
                     ({expected_log_index},{expected_event_seq})"
                )
            }
            Self::SequenceGapOrResync { expected_event_seq, cursor } => write!(
                f,
                "projection gap or resync_required at applied_event_seq={} while awaiting >={expected_event_seq}",
                cursor.applied_event_seq
            ),
            Self::MissingRequiredOperation { op_event_id, cursor } => write!(
                f,
                "required op_event_id={op_event_id} missing below applied_event_seq={}",
                cursor.applied_event_seq
            ),
            Self::RevisionBehind { repository_id, required_revision, projected_revision } => write!(
                f,
                "projected revision {projected_revision:?} for repo {repository_id} behind {required_revision}"
            ),
            Self::AuthorityViolation(msg) => write!(f, "projection authority violation: {msg}"),
            Self::Timeout { group_id, history_incarnation, min_log_index, min_event_seq, last_reason } => write!(
                f,
                "timed out waiting for projection ({group_id},{history_incarnation}) >= \
                 ({min_log_index},{min_event_seq}): {last_reason}"
            ),
            Self::Database(msg) => write!(f, "projection dependency database error: {msg}"),
        }
    }
}

impl std::error::Error for ProjectionDependencyError {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedProjectionWait {
    pub cursor: ProjectionCursor,
    pub verified_op_event_id: Option<String>,
    pub max_projected_repo_revision: Option<i64>,
}

/// Checks whether PostgreSQL's contiguous durable cursor and projected records satisfy `target`.
/// Never derives progress from `MAX(id)` or `MAX(event_seq)` across potentially gapped tables.
pub async fn verify_projection_dependency<C: GenericClient + Sync>(
    client: &C,
    target: &ProjectionDependencyTarget,
) -> Result<VerifiedProjectionWait, ProjectionDependencyError> {
    target.validate()?;
    let cursor = load_cursor(client, target.realm.group_id, target.realm.history_incarnation)
        .await
        .map_err(|e| ProjectionDependencyError::Database(e.to_string()))?
        .ok_or(ProjectionDependencyError::StreamNotInitialized {
            group_id: target.realm.group_id,
            history_incarnation: target.realm.history_incarnation,
        })?;

    if cursor.stream_state != ProjectionStreamState::Active {
        return Err(ProjectionDependencyError::SequenceGapOrResync {
            expected_event_seq: target.min_event_seq,
            cursor,
        });
    }
    if cursor.realm.group_epoch < target.realm.group_epoch {
        return Err(ProjectionDependencyError::RealmEpochMismatch {
            expected_min_epoch: target.realm.group_epoch,
            actual_epoch: cursor.realm.group_epoch,
        });
    }
    if cursor.applied_log_index < target.min_log_index || cursor.applied_event_seq < target.min_event_seq {
        return Err(ProjectionDependencyError::BehindFrontier {
            expected_log_index: target.min_log_index,
            expected_event_seq: target.min_event_seq,
            actual_log_index: cursor.applied_log_index,
            actual_event_seq: cursor.applied_event_seq,
        });
    }

    let cursor_seq_i64 = to_pg_i64(cursor.applied_event_seq, "applied_event_seq")
        .map_err(|e| ProjectionDependencyError::InvalidInput(e.to_string()))?;

    let mut verified_op_event_id = None;
    if let Some(op_event_id) = &target.required_op_event_id {
        let row = client
            .query_opt(
                "SELECT can_authorize_write, event_seq FROM ref_cas_projected_operations \
                 WHERE op_event_id = $1 AND history_incarnation = $2 AND group_id = $3 AND event_seq <= $4",
                &[op_event_id, &target.realm.history_incarnation, &target.realm.group_id, &cursor_seq_i64],
            )
            .await
            .map_err(|e| ProjectionDependencyError::Database(e.to_string()))?;
        let Some(row) = row else {
            return Err(ProjectionDependencyError::MissingRequiredOperation {
                op_event_id: op_event_id.clone(),
                cursor,
            });
        };
        let writable: bool = row.get("can_authorize_write");
        if writable {
            return Err(ProjectionDependencyError::AuthorityViolation("projected operation illegally marked writable"));
        }
        verified_op_event_id = Some(op_event_id.clone());
    }

    let mut max_projected_repo_revision = None;
    if let Some(repo_id) = target.required_repository_id {
        let row = client
            .query_one(
                "SELECT MAX(revision) AS max_rev, COALESCE(BOOL_OR(can_authorize_write), FALSE) AS any_writable \
                 FROM ref_cas_projected_operations \
                 WHERE repository_id = $1 AND history_incarnation = $2 AND group_id = $3 AND event_seq <= $4",
                &[&repo_id, &target.realm.history_incarnation, &target.realm.group_id, &cursor_seq_i64],
            )
            .await
            .map_err(|e| ProjectionDependencyError::Database(e.to_string()))?;
        let any_writable: bool = row.get("any_writable");
        if any_writable {
            return Err(ProjectionDependencyError::AuthorityViolation("projected operation illegally marked writable"));
        }
        let max_rev: Option<i64> = row.get("max_rev");
        if let Some(min_rev) = target.min_repo_revision
            && max_rev.is_none_or(|rev| rev < min_rev)
        {
            return Err(ProjectionDependencyError::RevisionBehind {
                repository_id: repo_id,
                required_revision: min_rev,
                projected_revision: max_rev,
            });
        }
        max_projected_repo_revision = max_rev;
    }

    Ok(VerifiedProjectionWait { cursor, verified_op_event_id, max_projected_repo_revision })
}

/// Projects one event inside a single PostgreSQL transaction, optionally aborting before `COMMIT`
/// to verify zero partial side effects or cursor advancement on transaction interruption.
pub async fn apply_projection_step_atomically(
    pool: &Pool,
    envelope: &RefCasEventEnvelope,
    cutoff_hint: Option<&TruncationCutoff>,
    inject_pre_commit_abort: bool,
) -> Result<SingleEventOutcome, ProjectionError> {
    let mut client = pool.get().await.map_err(|e| ProjectionError::Database(e.to_string()))?;
    let tx = client.transaction().await.map_err(pg_err)?;
    let outcome = project_event_in_tx(&tx, envelope, cutoff_hint).await?;
    if inject_pre_commit_abort {
        tx.rollback().await.map_err(pg_err)?;
        return Err(ProjectionError::Database("injected pre-commit transaction rollback".into()));
    }
    tx.commit().await.map_err(pg_err)?;
    Ok(outcome)
}

/// Applies events sequentially, stopping immediately on the first sequence gap, equivocation,
/// or resync error so contiguous cursors and effects never advance past unseen events.
pub async fn apply_projection_stream_stop_on_gap(
    pool: &Pool,
    envelopes: &[RefCasEventEnvelope],
    cutoff_hint: Option<&TruncationCutoff>,
) -> Result<(Vec<SingleEventOutcome>, Option<(usize, ProjectionError)>), ProjectionError> {
    let mut outcomes = Vec::new();
    for (idx, envelope) in envelopes.iter().enumerate() {
        match apply_projection_step_atomically(pool, envelope, cutoff_hint, false).await {
            Ok(outcome) => outcomes.push(outcome),
            Err(
                err @ (ProjectionError::SequenceGap { .. }
                | ProjectionError::ResyncRequired(_)
                | ProjectionError::Equivocation { .. }),
            ) => {
                return Ok((outcomes, Some((idx, err))));
            }
            Err(err) => return Err(err),
        }
    }
    Ok((outcomes, None))
}

/// Waits within `wait_timeout` for PostgreSQL projection cursors and records to reach `target`.
/// Fails immediately on stream `resync_required` / gaps or `Timeout` when the deadline expires.
pub async fn await_projected_event(
    pool: &Pool,
    target: &ProjectionDependencyTarget,
    wait_timeout: Duration,
    poll_interval: Duration,
) -> Result<VerifiedProjectionWait, ProjectionDependencyError> {
    target.validate()?;
    let deadline = Instant::now() + wait_timeout;
    let poll = poll_interval.max(Duration::from_millis(5));
    loop {
        let client = pool.get().await.map_err(|e| ProjectionDependencyError::Database(e.to_string()))?;
        match verify_projection_dependency(&**client, target).await {
            Ok(verified) => return Ok(verified),
            Err(
                err @ (ProjectionDependencyError::SequenceGapOrResync { .. }
                | ProjectionDependencyError::AuthorityViolation(_)
                | ProjectionDependencyError::InvalidInput(_)),
            ) => return Err(err),
            Err(transient) => {
                drop(client);
                let now = Instant::now();
                if now >= deadline {
                    return Err(ProjectionDependencyError::Timeout {
                        group_id: target.realm.group_id,
                        history_incarnation: target.realm.history_incarnation,
                        min_log_index: target.min_log_index,
                        min_event_seq: target.min_event_seq,
                        last_reason: transient.to_string(),
                    });
                }
                tokio::time::sleep(poll.min(deadline.saturating_duration_since(now))).await;
            }
        }
    }
}
