//! Pure deterministic planning, contiguous ordering verification, truncation
//! closure reconciliation, and historical non-authorization enforcement (#117).

use super::identity::{
    compute_terminal_digest, derive_job_key, derive_operation_event_id, derive_ref_event_id, derive_webhook_event_id,
};
use super::types::{
    PlannedOperationProjection, ProjectedOperationRecord, ProjectedRefDelta, ProjectionCursor, ProjectionError,
    ProjectionJobKind, ProjectionJobSpec, ProjectionStreamState, RefCasEventEnvelope, RefCasEventPage,
    TerminalOutcomeSummary, TruncationCutoff,
};
use crate::ref_store::core::terminal::{CommitTerminal, RefCommitResult};
use serde_json::json;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CursorTransition {
    HistoricalOrDuplicate,
    AdvanceNext,
}

/// Validates that a historical projected operation record can never authorize a new ref write.
pub fn assert_projection_cannot_authorize_write(record: &ProjectedOperationRecord) -> Result<(), ProjectionError> {
    if record.can_authorize_write {
        return Err(ProjectionError::AuthorityViolation(
            "historical projected Ref-CAS operation record cannot grant write authority",
        ));
    }
    Ok(())
}

/// Refuses any attempt to mint a new writable lease/decision/admission from a projected receipt.
pub fn refuse_write_from_historical_receipt(record: &ProjectedOperationRecord) -> ProjectionError {
    let _ = record;
    ProjectionError::AuthorityViolation("historical Ref-CAS projection receipt cannot authorize new ref writes")
}

/// Builds a deterministic, replay-invariant projection plan from one Ref-CAS terminal event.
pub fn plan_operation_projection(
    envelope: &RefCasEventEnvelope,
) -> Result<PlannedOperationProjection, ProjectionError> {
    envelope.validate()?;
    let op_event_id =
        derive_operation_event_id(&envelope.realm, envelope.log_index, envelope.operation_id, envelope.repository_id)?;
    let terminal_digest =
        compute_terminal_digest(envelope.repository_id, envelope.revision, &envelope.outcome, &envelope.payload);

    let (summary, head_ref, deltas, jobs) = match envelope.outcome.as_str() {
        "committed" => plan_committed_event(envelope, &op_event_id)?,
        "rejected" => plan_rejected_event(envelope)?,
        other => plan_other_event(envelope, &op_event_id, other)?,
    };

    let operation = ProjectedOperationRecord {
        op_event_id,
        realm: envelope.realm,
        log_index: envelope.log_index,
        log_term: envelope.log_term,
        event_seq: envelope.event_seq,
        repository_id: envelope.repository_id,
        tenant_id: envelope.tenant_id,
        operation_id: envelope.operation_id,
        revision: envelope.revision,
        outcome: envelope.outcome.clone(),
        head_ref,
        actor_id: envelope.actor_id,
        token_id: envelope.token_id,
        terminal_digest,
        applied_ref_count: deltas.len(),
        can_authorize_write: false,
    };
    assert_projection_cannot_authorize_write(&operation)?;

    Ok(PlannedOperationProjection { operation, deltas, jobs, summary })
}

fn plan_committed_event(
    envelope: &RefCasEventEnvelope,
    op_event_id: &str,
) -> Result<(TerminalOutcomeSummary, Option<String>, Vec<ProjectedRefDelta>, Vec<ProjectionJobSpec>), ProjectionError> {
    let terminal: CommitTerminal = serde_json::from_value(envelope.payload.clone())
        .map_err(|e| ProjectionError::Decode(format!("invalid committed CommitTerminal payload: {e}")))?;
    if !terminal.is_committed() {
        return Err(ProjectionError::Decode("committed event payload carried non-committed terminal kind".into()));
    }
    if terminal.repository_id != envelope.repository_id || terminal.revision != envelope.revision {
        return Err(ProjectionError::Decode("committed terminal repository_id/revision mismatches envelope".into()));
    }

    let mut deltas = Vec::new();
    let mut seq = 0i64;
    let mut has_user_branch_or_tag = false;
    let mut has_internal_ref = false;

    for item in &terminal.refs {
        if let RefCommitResult::Applied { name, old_oid, new_oid } = item {
            seq += 1;
            let event_id = derive_ref_event_id(op_event_id, seq, name)?;
            let webhook_event_id = derive_webhook_event_id(&event_id);
            let reserved_ci = crate::ci_pins::reserved(name);
            if reserved_ci {
                has_internal_ref = true;
            } else if name.starts_with("refs/heads/") || name.starts_with("refs/tags/") {
                has_user_branch_or_tag = true;
            }
            deltas.push(ProjectedRefDelta {
                event_id,
                webhook_event_id,
                ref_sequence: seq,
                ref_name: name.clone(),
                old_oid: old_oid.clone(),
                new_oid: new_oid.clone(),
                deleted: new_oid.is_none(),
                emit_push_webhook: !reserved_ci,
            });
        }
    }

    let mut jobs = Vec::new();
    if !deltas.is_empty() {
        jobs.push(build_job_spec(
            envelope,
            op_event_id,
            ProjectionJobKind::RepoIndexRefresh,
            &format!("repo:{}", envelope.revision),
            json!({
                "revision": envelope.revision,
                "applied_refs": deltas.len(),
                "head_ref": terminal.head_ref,
            }),
        )?);
    }
    if has_user_branch_or_tag {
        jobs.push(build_job_spec(
            envelope,
            op_event_id,
            ProjectionJobKind::CiSync,
            &format!("ci:{}", envelope.revision),
            json!({
                "revision": envelope.revision,
                "operation_id": envelope.operation_id,
            }),
        )?);
    }
    if has_internal_ref {
        jobs.push(build_job_spec(
            envelope,
            op_event_id,
            ProjectionJobKind::ArtifactReconcile,
            &format!("internal:{}", envelope.revision),
            json!({
                "revision": envelope.revision,
                "reason": "internal_ref_delta",
            }),
        )?);
    }

    Ok((TerminalOutcomeSummary::Committed, terminal.head_ref, deltas, jobs))
}

fn plan_rejected_event(
    envelope: &RefCasEventEnvelope,
) -> Result<(TerminalOutcomeSummary, Option<String>, Vec<ProjectedRefDelta>, Vec<ProjectionJobSpec>), ProjectionError> {
    let terminal: CommitTerminal = serde_json::from_value(envelope.payload.clone())
        .map_err(|e| ProjectionError::Decode(format!("invalid rejected CommitTerminal payload: {e}")))?;
    if terminal.is_committed() {
        return Err(ProjectionError::Decode("rejected event payload carried committed terminal kind".into()));
    }
    if terminal.repository_id != envelope.repository_id {
        return Err(ProjectionError::Decode("rejected terminal repository_id mismatches envelope".into()));
    }
    Ok((TerminalOutcomeSummary::Rejected, terminal.head_ref, Vec::new(), Vec::new()))
}

fn plan_other_event(
    envelope: &RefCasEventEnvelope,
    op_event_id: &str,
    outcome: &str,
) -> Result<(TerminalOutcomeSummary, Option<String>, Vec<ProjectedRefDelta>, Vec<ProjectionJobSpec>), ProjectionError> {
    let mut jobs = Vec::new();
    if outcome.contains("hold") || outcome.contains("root") || outcome.contains("pin") {
        jobs.push(build_job_spec(
            envelope,
            op_event_id,
            ProjectionJobKind::ArtifactReconcile,
            &format!("lifecycle:{outcome}:{}", envelope.operation_id),
            json!({
                "outcome": outcome,
                "revision": envelope.revision,
                "operation_id": envelope.operation_id,
            }),
        )?);
    }
    Ok((TerminalOutcomeSummary::Other, None, Vec::new(), jobs))
}

fn build_job_spec(
    envelope: &RefCasEventEnvelope,
    op_event_id: &str,
    kind: ProjectionJobKind,
    scope_key: &str,
    payload: serde_json::Value,
) -> Result<ProjectionJobSpec, ProjectionError> {
    let job_key = derive_job_key(op_event_id, kind, scope_key)?;
    Ok(ProjectionJobSpec {
        job_key,
        repository_id: envelope.repository_id,
        tenant_id: envelope.tenant_id,
        op_event_id: op_event_id.to_owned(),
        realm: envelope.realm,
        log_index: envelope.log_index,
        event_seq: envelope.event_seq,
        kind,
        scope_key: scope_key.to_owned(),
        payload,
    })
}

/// Verifies whether `envelope` may be replayed idempotently or advances the contiguous
/// frontier of `cursor`, refusing any epoch regression or skipped sequence gap.
pub fn validate_cursor_step(
    cursor: &ProjectionCursor,
    envelope: &RefCasEventEnvelope,
) -> Result<CursorTransition, ProjectionError> {
    envelope.validate()?;
    if cursor.realm.history_incarnation != envelope.realm.history_incarnation
        || cursor.realm.group_id != envelope.realm.group_id
    {
        return Err(ProjectionError::StreamRegression(
            "event stream history_incarnation or group_id does not match cursor".into(),
        ));
    }
    if envelope.realm.group_epoch < cursor.realm.group_epoch {
        return Err(ProjectionError::StreamRegression(format!(
            "group_epoch regressed from {} to {}",
            cursor.realm.group_epoch, envelope.realm.group_epoch
        )));
    }
    if cursor.stream_state == ProjectionStreamState::ResyncRequired {
        return Err(ProjectionError::ResyncRequired(format!(
            "stream ({},{}) requires archive/snapshot closure resync before advancing from event_seq {}",
            cursor.realm.history_incarnation, cursor.realm.group_id, cursor.applied_event_seq
        )));
    }
    if envelope.event_seq <= cursor.applied_event_seq {
        return Ok(CursorTransition::HistoricalOrDuplicate);
    }
    let expected = cursor.applied_event_seq.saturating_add(1);
    if envelope.event_seq > expected {
        return Err(ProjectionError::SequenceGap {
            expected_min_event_seq: expected,
            got_event_seq: envelope.event_seq,
        });
    }
    if envelope.log_index < cursor.applied_log_index {
        return Err(ProjectionError::StreamRegression(format!(
            "log_index regressed from {} to {} at advancing event_seq {}",
            cursor.applied_log_index, envelope.log_index, envelope.event_seq
        )));
    }
    if let Some(cutoff) = &cursor.truncation_cutoff
        && cursor.applied_event_seq < cutoff.event_seq
        && envelope.event_seq > cutoff.event_seq
    {
        return Err(ProjectionError::TruncatedBeforeCursor {
            cutoff_log_index: cutoff.log_index,
            cutoff_event_seq: cutoff.event_seq,
            cursor_log_index: cursor.applied_log_index,
            cursor_event_seq: cursor.applied_event_seq,
            closure_digest: cutoff.closure_digest.clone(),
        });
    }
    Ok(CursorTransition::AdvanceNext)
}

/// Monotonically records an archive/retention truncation closure marker onto `cursor`.
pub fn reconcile_cutoff_on_cursor(
    cursor: &mut ProjectionCursor,
    cutoff: &TruncationCutoff,
) -> Result<(), ProjectionError> {
    cutoff.validate()?;
    if let Some(existing) = &cursor.truncation_cutoff {
        if cutoff.event_seq < existing.event_seq || cutoff.log_index < existing.log_index {
            return Err(ProjectionError::StreamRegression("truncation cutoff must advance monotonically".into()));
        }
        if cutoff.event_seq == existing.event_seq
            && cutoff.log_index == existing.log_index
            && cutoff.closure_digest != existing.closure_digest
        {
            return Err(ProjectionError::Equivocation {
                op_event_id: format!("cutoff:{}:{}", cutoff.log_index, cutoff.event_seq),
                expected_digest: existing.closure_digest.clone(),
                actual_digest: cutoff.closure_digest.clone(),
            });
        }
    }
    cursor.truncation_cutoff = Some(cutoff.clone());
    Ok(())
}

/// Checks whether a source page's earliest retained log window still connects seamlessly to
/// the durable cursor. If truncation removed events ahead of the cursor, marks `ResyncRequired`.
pub fn check_stream_continuity(cursor: &mut ProjectionCursor, page: &RefCasEventPage) -> Result<(), ProjectionError> {
    page.realm.validate()?;
    if page.realm.history_incarnation != cursor.realm.history_incarnation
        || page.realm.group_id != cursor.realm.group_id
    {
        return Err(ProjectionError::StreamRegression("source page realm does not match cursor stream".into()));
    }
    if page.realm.group_epoch < cursor.realm.group_epoch {
        return Err(ProjectionError::StreamRegression("source page group_epoch regressed".into()));
    }
    if let Some(cutoff) = &page.truncation_cutoff {
        reconcile_cutoff_on_cursor(cursor, cutoff)?;
    }
    if page.earliest_available_event_seq > cursor.applied_event_seq.saturating_add(1) {
        cursor.stream_state = ProjectionStreamState::ResyncRequired;
        let closure_digest = cursor
            .truncation_cutoff
            .as_ref()
            .map(|c| c.closure_digest.clone())
            .unwrap_or_else(|| "unsealed-truncation".into());
        return Err(ProjectionError::TruncatedBeforeCursor {
            cutoff_log_index: page.earliest_available_log_index,
            cutoff_event_seq: page.earliest_available_event_seq.saturating_sub(1),
            cursor_log_index: cursor.applied_log_index,
            cursor_event_seq: cursor.applied_event_seq,
            closure_digest,
        });
    }
    Ok(())
}

/// Completes a `ResyncRequired` closure transition after verified snapshot/archive catchup.
pub fn complete_cursor_resync(
    cursor: &mut ProjectionCursor,
    cutoff: TruncationCutoff,
    verified_last_event_id: Option<String>,
) -> Result<(), ProjectionError> {
    reconcile_cutoff_on_cursor(cursor, &cutoff)?;
    if cursor.applied_event_seq > cutoff.event_seq {
        return Err(ProjectionError::StreamRegression(
            "cannot resync cursor backwards behind already applied event_seq".into(),
        ));
    }
    cursor.applied_event_seq = cutoff.event_seq;
    cursor.applied_log_index = cutoff.log_index;
    cursor.applied_log_term = cutoff.log_term;
    if verified_last_event_id.is_some() {
        cursor.last_event_id = verified_last_event_id;
    }
    cursor.stream_state = ProjectionStreamState::Active;
    Ok(())
}
