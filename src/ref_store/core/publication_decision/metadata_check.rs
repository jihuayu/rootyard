//! Final metadata-only consume check (split from `metadata.rs` to keep every Rust file < 600 lines).
//!
//! It re-reads the live gate/protocol realm, the exact request, the captured PG ref map and the live
//! policy, recomputes the metadata selection digest and consumes the decision in the same transaction.
//! No `PackClosureProof` is involved or claimed.
use super::contract::{ConsumptionRecord, DecisionError, DecisionState, DenialCode};
use super::metadata::{
    MetadataSelectedDecision, capture_metadata_refs, metadata_authority, metadata_dependencies, metadata_rows,
    metadata_selection_digest,
};
use super::policy;
use super::sql_locks;
use crate::db::Identity;
use crate::ref_store::core::command::CommitRefsRequest;
use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Final metadata re-check in the commit transaction. No closure proof is accepted or claimed: the
/// captured ref map and the exact request/selection digests are the binding.
pub(crate) async fn authorized_metadata_final_check(
    tx: &Transaction<'_>,
    selected: &MetadataSelectedDecision,
    request: &CommitRefsRequest,
    actor: &Identity,
    receipt_id: Uuid,
    deadline: Instant,
) -> Result<ConsumptionRecord, DecisionError> {
    if receipt_id.is_nil() {
        return Err(DecisionError::Ledger("consume requires a non-nil terminal receipt id"));
    }
    selected.ensure_actor(actor).map_err(DecisionError::Denied)?;
    crate::ref_store::pg::bound(tx, deadline).await?;
    sql_locks::lock_source_tables(tx, selected.action()).await?;
    sql_locks::lock_repository_row(tx, request.repository_id()).await?;
    sql_locks::lock_usage(tx, request.repository_id(), request.tenant_id()).await?;
    let authority = metadata_authority(tx, request.repository_id(), actor).await?;
    if authority.owner_id != request.tenant_id()
        || authority.object_format != request.object_format().as_str()
        || authority.tenant_id != request.tenant_id()
        || authority.history_incarnation != request.history_incarnation()
        || authority.authority_epoch != request.authority_epoch()
        || authority.group_epoch != request.group_epoch()
        || authority.revision != request.expected_revision()
    {
        return Ok(ConsumptionRecord::Rejected {
            decision_id: selected.decision_id(),
            code: DenialCode::GateDigestMismatch,
        });
    }
    let row = sql_locks::decision_by_id(tx, selected.decision_id(), true)
        .await?
        .ok_or(DecisionError::DecisionNotFound(selected.decision_id()))?;
    match row.state {
        DecisionState::Open => {}
        DecisionState::Consumed => {
            return Err(DecisionError::Consumed {
                decision_id: row.decision_id,
                receipt_id: row.consume_receipt_id.unwrap_or_else(Uuid::nil),
            });
        }
        DecisionState::Cancelled => {
            return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::Cancelled });
        }
        DecisionState::Rejected => {
            return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::LedgerIntegrity });
        }
    }
    let now = sql_locks::db_clock(tx).await?;
    if row.actor_id != actor.id
        || row.token_id != actor.token_id
        || row.token_digest != hex::encode(&actor.token_digest)
    {
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::TokenInvalid });
    }
    if now > row.not_after_millis {
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::Expired });
    }
    if selected.accepted_is_empty() {
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::RejectedBatch });
    }
    let captured = capture_metadata_refs(tx, request.repository_id(), request.object_format()).await?;
    if &captured != selected.captured() {
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::SelectionChanged });
    }
    let head_oids = request
        .refs()
        .iter()
        .filter_map(|update| update.target().oid().map(|oid| oid.as_hex()))
        .collect::<Vec<String>>();
    let policy = policy::read_policy_repo(tx, request.repository_id(), authority.tenant_id, &head_oids).await?;
    let dependencies = metadata_dependencies(request, actor, &authority, &policy);
    if row.authz_digest != authority.authz_digest
        || row.policy_digest != super::digest::policy_digest(&policy)
        || row.dependencies_digest != super::digest::dependencies_digest(&dependencies)
        || row.base_gate_digest != authority.gate_digest
    {
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::DependencyChanged });
    }
    let (rows, _accepted) = metadata_rows(request, &captured, &policy, &authority.head_ref);
    let fresh = metadata_selection_digest(request, &captured, &rows);
    if &fresh != selected.selection_digest() || row.selection_digest != fresh {
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::SelectionChanged });
    }
    let admitted_at = sql_locks::db_clock(tx).await?;
    if admitted_at.saturating_add(super::contract::CLOCK_UNCERTAINTY_MILLIS) > row.not_after_millis
        || authority
            .token_expires_millis
            .is_some_and(|expiry| admitted_at.saturating_add(super::contract::CLOCK_UNCERTAINTY_MILLIS) > expiry)
    {
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::Expired });
    }
    let updated = tx
        .query_opt(
            "UPDATE ref_store_publication_decisions
             SET state='CONSUMED',consume_receipt_id=$2,consumed_at=clock_timestamp()
             WHERE decision_id=$1 AND state='OPEN' RETURNING decision_id",
            &[&row.decision_id, &receipt_id],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    if updated.is_none() {
        return Err(DecisionError::DecisionConflict { decision_id: row.decision_id, state: row.state });
    }
    Ok(ConsumptionRecord::Consumed {
        decision_id: row.decision_id,
        receipt_id,
        selection_digest: fresh,
        dependencies_digest: row.dependencies_digest,
    })
}
