//! GET-only typed projection of the current public operation terminal.
//!
//! The status query is the ordinary one-statement public snapshot plus the
//! current attempt's immutable terminal body. The request-aware push lookup
//! deliberately does not use this SQL and keeps its existing payload-free
//! proof. A returned terminal is decoded from `PackCommitTerminal`, re-encoded
//! to compare the entire JSON shape (so unknown, missing or coerced fields fail
//! closed), validated against the wrapper repository, current event revision,
//! object format and state, and only then serialized. Pending is `None`;
//! cancelled is the exact two-field tombstone body.
use super::{is_canonical_hex_64, ledger};
use crate::ref_store::{
    GitObjectFormat, GitOid, OperationState, RefCommitResult, RefName, TerminalKind, TerminalResult,
    core::pack_commit::{
        MAX_BATCH_NEW_PACKS, MAX_PLAN_REFS, PackCommitError, PackCommitRejectCode, PackCommitTerminal, PackMode,
    },
    core::publication_decision::codes::DenialCode,
};
use serde_json::Value;
use uuid::Uuid;

/// The ordinary public snapshot with exactly one GET-only addition: the current
/// attempt's terminal body. It stays in the same single statement and snapshot;
/// no second read happens after authorization.
pub(super) const SELECT_STATUS_SNAPSHOT: &str = r#"
SELECT jsonb_build_object(
    'wrapper', (
        SELECT to_jsonb(w) FROM (
            SELECT repository_id, public_id, admission_owner_id, issuer_id, wire_digest,
                   request_mode, backend_identity, object_format, history_incarnation,
                   authority_epoch, group_epoch, restore_incarnation, current_slot,
                   state, event_id, retired_event_id, cancelled_private_id
              FROM ref_store_public_operations
             WHERE repository_id=$1 AND public_id=$2
        ) w
    ),
    'attempts', COALESCE((
        SELECT jsonb_agg(to_jsonb(x) ORDER BY x.slot) FROM (
            SELECT a.slot, a.private_id, a.plan_digest, a.proof_digest, a.base_revision,
                   rootyard_ref_store_attempt_has_binding(w, a) AS serving_bound,
                   o.issuer_id AS operation_issuer_id,
                   o.lane AS operation_lane,
                   o.sequence AS operation_sequence,
                   o.request_digest AS operation_request_digest,
                   o.state AS operation_state,
                   o.terminal_result IS NOT NULL AS terminal_present,
                   COALESCE(o.terminal_result =
                       '{"state":"cancelled","reason":"cancel_requested"}'::jsonb, false)
                       AS terminal_cancelled_exact,
                   e.event_id,
                   e.revision AS event_revision,
                   COALESCE(e.event_id IS NOT NULL AND e.outcome = o.state, false)
                       AS event_outcome_matches,
                   COALESCE(e.event_id IS NOT NULL
                            AND e.payload IS NOT DISTINCT FROM o.terminal_result
                            AND e.payload->>'kind' = o.state
                            AND e.payload->'repository_id' = to_jsonb(w.repository_id)
                            AND e.payload->'revision' = to_jsonb(e.revision), false)
                       AS event_body_matches,
                   COALESCE(c.operation_id IS NOT NULL, false) AS tombstone_present,
                   (c.operation_id IS NULL AND k.operation_id IS NULL) AS tombstone_absent,
                   COALESCE(c.operation_id IS NOT NULL AND c.operation_id = k.operation_id, false)
                       AS tombstone_matches_lane,
                   COALESCE(c.operation_id IS NOT NULL
                            AND c.operation_id = a.private_id
                            AND c.issuer_id = o.issuer_id
                            AND c.lane = o.lane
                            AND c.sequence = o.sequence
                            AND c.request_digest = o.request_digest, false)
                       AS tombstone_exact_operation,
                   COALESCE(e.event_id IS NOT NULL
                            AND e.payload#>>'{rejection,code}' = 'revision_mismatch'
                            AND e.payload->'registrations' = '[]'::jsonb, false)
                       AS revision_mismatch_rejection
              FROM ref_store_private_attempts a
              JOIN ref_store_public_operations w
                ON w.repository_id=a.repository_id AND w.public_id=a.public_id
              LEFT JOIN ref_store_operations o
                ON o.repository_id=a.repository_id AND o.operation_id=a.private_id
              LEFT JOIN ref_store_core_events e
                ON e.repository_id=a.repository_id AND e.operation_id=a.private_id
              LEFT JOIN ref_store_cancellations c
                ON c.repository_id=a.repository_id AND c.operation_id=a.private_id
              LEFT JOIN ref_store_cancellations k
                ON k.repository_id=o.repository_id AND k.issuer_id=o.issuer_id
               AND k.lane=o.lane AND k.sequence=o.sequence
             WHERE a.repository_id=$1 AND a.public_id=$2
        ) x
    ), '[]'::jsonb),
    'private_occupied', EXISTS(
        SELECT 1 FROM ref_store_private_attempts p
         WHERE p.repository_id=$1 AND p.private_id=$2
    ),
    'legacy_operation', EXISTS(
        SELECT 1 FROM ref_store_operations o
         WHERE o.repository_id=$1 AND o.operation_id=$2
    ),
    'legacy_cancellation', EXISTS(
        SELECT 1 FROM ref_store_cancellations c
         WHERE c.repository_id=$1 AND c.operation_id=$2
    ),
    'status_terminal', (
        SELECT o.terminal_result
          FROM ref_store_public_operations w
          JOIN ref_store_private_attempts a
            ON a.repository_id=w.repository_id AND a.public_id=w.public_id AND a.slot=w.current_slot
          LEFT JOIN ref_store_operations o
            ON o.repository_id=a.repository_id AND o.operation_id=a.private_id
         WHERE w.repository_id=$1 AND w.public_id=$2
    ),
    'realm_matches', COALESCE((
        SELECT (
            r.archived_at IS NULL AND r.deleted_at IS NULL
            AND (r.owner_id, r.object_format, r.state, r.storage_backend, r.transition_state)
                = (w.admission_owner_id, w.object_format, 'ready', 'pg_refstore', 'stable')
            AND (g.tenant_id, g.object_format, g.history_incarnation, g.authority_epoch, g.group_epoch)
                = (w.admission_owner_id, w.object_format, w.history_incarnation, w.authority_epoch, w.group_epoch)
            AND (s.owner_id, s.object_format, s.history_incarnation, s.authority_epoch, s.group_epoch)
                = (g.tenant_id, g.object_format, g.history_incarnation, g.authority_epoch, g.group_epoch)
            AND (p.tenant_id, p.object_format, p.history_incarnation, p.authority_epoch, p.group_epoch)
                = (g.tenant_id, g.object_format, g.history_incarnation, g.authority_epoch, g.group_epoch)
            AND s.state = 'ready' AND s.name = r.name AND p.decision_required
            AND s.backend_identity = w.backend_identity AND c.incarnation = w.restore_incarnation
        )
          FROM ref_store_public_operations w
          JOIN repositories r ON r.id = w.repository_id
          JOIN ref_store_core_gates g ON g.repository_id = w.repository_id
          JOIN ref_store_serving_repositories s ON s.repository_id = w.repository_id
          JOIN ref_store_core_protocol_repos p ON p.repository_id = w.repository_id
          JOIN public.cluster_authority c ON c.singleton
         WHERE w.repository_id = $1 AND w.public_id = $2
    ), false)
) AS snapshot
"#;

/// Project the current terminal from the already-authorized snapshot.
///
/// `event_revision` is the current attempt's migration-139 revision. The body
/// is first bounded with the same compact `TerminalResult` 64 KiB rule as the
/// producer, never with PostgreSQL text length (JSONB pretty text may contain
/// spaces). A typed round-trip must reproduce the exact value, so extra, missing
/// or silently coerced fields are refused before any payload leaves.
pub(super) fn project_terminal(
    state: OperationState,
    repository_id: Uuid,
    object_format: GitObjectFormat,
    event_revision: Option<i64>,
    terminal: Option<&Value>,
) -> Result<Option<Value>, PackCommitError> {
    match state {
        OperationState::Pending => {
            if terminal.is_some() {
                return Err(ledger("pending public operation carries a terminal"));
            }
            Ok(None)
        }
        OperationState::Cancelled => {
            let value = terminal.ok_or_else(|| ledger("cancelled public operation has no terminal"))?;
            let expected = cancelled_terminal();
            if value != &expected {
                return Err(ledger("cancelled public operation does not carry the exact tombstone body"));
            }
            Ok(Some(expected))
        }
        OperationState::Committed | OperationState::Rejected => {
            let value = terminal.ok_or_else(|| ledger("terminal public operation has no terminal"))?;
            let result = TerminalResult::json(value.clone())
                .map_err(|_| ledger("public terminal is not a bounded JSON object"))?;
            let typed: PackCommitTerminal = serde_json::from_value(result.value().clone())
                .map_err(|_| ledger("public terminal is not a canonical pack terminal"))?;
            let canonical = serde_json::to_value(&typed).map_err(|_| ledger("public terminal is not serializable"))?;
            if &canonical != result.value() {
                return Err(ledger("public terminal has non-canonical or undeclared fields"));
            }
            validate_typed(state, repository_id, object_format, event_revision, &typed)?;
            Ok(Some(canonical))
        }
    }
}

fn cancelled_terminal() -> Value {
    serde_json::json!({"state": "cancelled", "reason": "cancel_requested"})
}

fn validate_typed(
    state: OperationState,
    repository_id: Uuid,
    object_format: GitObjectFormat,
    event_revision: Option<i64>,
    typed: &PackCommitTerminal,
) -> Result<(), PackCommitError> {
    if typed.repository_id != repository_id || typed.repository_id.is_nil() {
        return Err(ledger("public terminal repository differs from its wrapper"));
    }
    if typed.revision < 0 || event_revision != Some(typed.revision) {
        return Err(ledger("public terminal revision differs from its current event"));
    }
    PackMode::parse(&typed.mode).map_err(|_| ledger("public terminal mode is not recognized"))?;

    match state {
        OperationState::Committed => {
            if typed.kind != TerminalKind::Committed || typed.rejection.is_some() {
                return Err(ledger("committed public terminal kind or rejection differs"));
            }
            if typed.head_ref.is_none() {
                return Err(ledger("committed public terminal has no HEAD"));
            }
            if !typed.refs.iter().all(|result| matches!(result, RefCommitResult::Applied { .. })) {
                return Err(ledger("committed public terminal contains a non-applied ref"));
            }
        }
        OperationState::Rejected => {
            if typed.kind != TerminalKind::Rejected || typed.rejection.is_none() {
                return Err(ledger("rejected public terminal kind or rejection differs"));
            }
            if !typed.registrations.is_empty() {
                return Err(ledger("rejected public terminal carries registrations"));
            }
            if !typed.refs.iter().all(|result| matches!(result, RefCommitResult::NotApplied { .. })) {
                return Err(ledger("rejected public terminal contains an applied ref"));
            }
        }
        OperationState::Pending | OperationState::Cancelled => {
            return Err(ledger("non-terminal public state reached terminal projection"));
        }
    }

    if let Some(head_ref) = &typed.head_ref {
        RefName::branch(head_ref.clone()).map_err(|_| ledger("public terminal HEAD is not a valid branch"))?;
    }
    if typed.refs.len() > MAX_PLAN_REFS {
        return Err(ledger("public terminal has too many refs"));
    }
    for result in &typed.refs {
        validate_ref_result(object_format, result)?;
    }
    if typed.registrations.len() > MAX_BATCH_NEW_PACKS {
        return Err(ledger("public terminal has too many registrations"));
    }
    for registration in &typed.registrations {
        if registration.pack_id.is_nil()
            || registration.registration_id.is_nil()
            || !is_canonical_hex_64(&registration.artifact_set_digest)
        {
            return Err(ledger("public terminal registration identity or digest is not canonical"));
        }
    }
    if let Some(rejection) = &typed.rejection {
        validate_rejection(rejection)?;
    }
    Ok(())
}

fn validate_ref_result(object_format: GitObjectFormat, result: &RefCommitResult) -> Result<(), PackCommitError> {
    match result {
        RefCommitResult::Applied { name, old_oid, new_oid } => {
            validate_ref_name(name)?;
            if old_oid.is_none() && new_oid.is_none() {
                return Err(ledger("applied public ref has neither an old nor a new object"));
            }
            for oid in [old_oid.as_deref(), new_oid.as_deref()].into_iter().flatten() {
                GitOid::parse(object_format, oid)
                    .map_err(|_| ledger("applied public ref object id is not canonical"))?;
            }
        }
        RefCommitResult::NotApplied { name, .. } => validate_ref_name(name)?,
    }
    Ok(())
}

fn validate_ref_name(name: &str) -> Result<(), PackCommitError> {
    RefName::new(name.to_owned()).map_err(|_| ledger("public terminal ref name is not canonical")).map(|_| ())
}

fn validate_rejection(
    rejection: &crate::ref_store::core::pack_commit::receipt::PackTerminalRejection,
) -> Result<(), PackCommitError> {
    let code = PackCommitRejectCode::parse(&rejection.code)
        .map_err(|_| ledger("public terminal rejection code is not recognized"))?;
    let detail = rejection.detail.as_str();
    let accepted = match code {
        PackCommitRejectCode::RevisionMismatch => detail == "admitted base was superseded",
        PackCommitRejectCode::NoRefApplied => {
            detail == "no ref accepted" || DenialCode::ALL.iter().any(|code| code.as_str() == detail)
        }
        PackCommitRejectCode::DecisionRejected => DenialCode::ALL.iter().any(|code| code.as_str() == detail),
        _ => false,
    };
    if !accepted {
        return Err(ledger("public terminal rejection detail is not from an accepted producer path"));
    }
    Ok(())
}
