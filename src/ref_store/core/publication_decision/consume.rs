//! `authorized_final_check`: the in-commit re-authorization and the one-way consume.
//!
//! This function is called by the integration commit **inside the same short transaction** that writes
//! refs, packs, the gate revision, the migration-138 terminal and the event. It therefore never
//! commits, never rolls back and never performs native/blob IO.
//!
//! Frozen order: source-table `SHARE NOWAIT` locks -> repository row -> tenant usage -> repository
//! usage -> gate -> protocol -> decision row -> fresh database clock. The sealed final proof is
//! optional **only** for an all-rejected projection (no ref write, no revision change); otherwise it
//! must bind the exact original parent, gate revision/digest, old membership, verified pack counters,
//! full resulting ref map/head and the sealed selection digest. There is no post-proof filtering and
//! no shrinking: any difference is a durable rejection.
use super::auth_deps;
use super::contract::{
    CLOCK_UNCERTAINTY_MILLIS, ConsumptionRecord, DecisionError, DecisionState, DenialCode, SelectedDecision,
};
use super::digest::DecisionDigests;
use super::facts_bridge;
use super::select::{self, SelectionInput};
use super::sql_locks::{self, DecisionRow};
use super::subset::SelectedPackPlan;
use crate::db::Identity;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::VerifiedPublicationFacts;
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::pack_commit::proof::PackClosureProof;
use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Re-authorize and consume (or durably reject) the decision inside the caller's commit transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn authorized_final_check(
    tx: &Transaction<'_>,
    selected: &SelectedDecision,
    plan: &PackCommitPlan,
    actor: &Identity,
    proof: Option<&PackClosureProof>,
    facts: &VerifiedPublicationFacts,
    receipt_id: Uuid,
    deadline: Instant,
) -> Result<ConsumptionRecord, DecisionError> {
    if receipt_id.is_nil() {
        return Err(DecisionError::Ledger("consume requires a non-nil terminal receipt id"));
    }
    crate::ref_store::pg::bound(tx, deadline).await?;
    selected.capability().matches_plan(plan).map_err(DecisionError::Denied)?;
    selected.capability().ensure_actor(actor).map_err(DecisionError::Denied)?;
    facts_bridge::ensure_binds(plan, facts)?;
    facts_bridge::verify_final_proof(selected, plan, facts, proof)?;

    // 1. Coarse source locks for the exact semantic action, then the ordered repo/usage rows.
    let action = selected.action().clone();
    sql_locks::lock_source_tables(tx, &action).await?;
    sql_locks::lock_repository_row(tx, plan.repository_id()).await?;
    sql_locks::lock_usage(tx, plan.repository_id(), plan.tenant_id()).await?;

    // 2. Live gate -> protocol realm (exact match) and the decision control row.
    let protocol = sql_locks::protocol_state(tx, plan.repository_id()).await?;
    if protocol.tenant_id != plan.tenant_id()
        || protocol.object_format != plan.object_format().as_str()
        || protocol.history_incarnation != plan.history_incarnation()
        || protocol.authority_epoch != plan.authority_epoch()
        || protocol.group_epoch != plan.group_epoch()
        || protocol.revision != plan.expected().revision()
    {
        return Err(DecisionError::Denied(DenialCode::GateDigestMismatch));
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
            return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: closed_denial(&row) });
        }
    }
    // 3. The database clock is read after every row wait.
    let now = sql_locks::db_clock(tx).await?;

    if row.actor_id != actor.id
        || row.token_id != actor.token_id
        || row.token_digest != hex::encode(&actor.token_digest)
        || row.action != action
    {
        close(tx, &row, DecisionState::Rejected, DenialCode::TokenInvalid, None, None).await?;
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::TokenInvalid });
    }
    if now.saturating_add(CLOCK_UNCERTAINTY_MILLIS) > row.not_after_millis {
        close(tx, &row, DecisionState::Rejected, DenialCode::Expired, None, None).await?;
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::Expired });
    }

    // All-rejected is durable and needs no proof, no ref revision and no extra root/hold change.
    if selected.accepted_is_empty() {
        close(tx, &row, DecisionState::Rejected, DenialCode::AllRejected, None, None).await?;
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::AllRejected });
    }

    // 4. Re-read every live authority/policy fact and re-run the SAME pure policy pass.
    let mut authority = match auth_deps::load_live_authority(tx, plan, actor, &action).await {
        Ok(authority) => authority,
        Err(DecisionError::Denied(code)) => {
            close(tx, &row, DecisionState::Rejected, code, None, None).await?;
            return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code });
        }
        Err(other) => return Err(other),
    };
    let pointer_oids = match select::collect_lfs_oids(plan.refs(), facts) {
        Ok(oids) => oids,
        Err(error) => {
            close(tx, &row, DecisionState::Rejected, DenialCode::FactsUnverifiable, None, None).await?;
            return Err(error);
        }
    };
    authority.policy.lfs_objects = auth_deps::read_lfs_objects(tx, plan, &pointer_oids).await?;
    let outcome = match select::policy_verdicts(&SelectionInput {
        action: &action,
        format: plan.object_format(),
        refs: plan.refs(),
        actor_id: actor.id,
        policy: &authority.policy,
        facts,
    }) {
        Ok(outcome) => outcome,
        Err(error) => {
            close(tx, &row, DecisionState::Rejected, DenialCode::FactsUnverifiable, None, None).await?;
            return Err(error);
        }
    };
    // Recompute the sealed projection from the original plan and the same facts. A selection that
    // differs is a refusal; the accepted subset is never shrunk or reselected in this transaction.
    let fresh: SelectedPackPlan = match SelectedPackPlan::seal(plan.clone(), facts, &outcome.policy) {
        Ok(projection) => projection,
        Err(_) => {
            close(tx, &row, DecisionState::Rejected, DenialCode::SelectionChanged, None, None).await?;
            return Ok(ConsumptionRecord::Rejected {
                decision_id: row.decision_id,
                code: DenialCode::SelectionChanged,
            });
        }
    };
    if fresh.selection_digest() != selected.selection_digest() {
        close(tx, &row, DecisionState::Rejected, DenialCode::SelectionChanged, None, None).await?;
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::SelectionChanged });
    }

    let captured = facts_bridge::captured_oid_digest(facts)?;
    let digests = DecisionDigests::compute(
        plan,
        *fresh.selection_digest(),
        &authority.policy,
        authority.authz_digest(),
        &authority.dependencies,
        facts_bridge::facts_digest(facts),
        captured,
    );
    if let Some(code) = compare_digests(&row, &digests) {
        close(tx, &row, DecisionState::Rejected, code, None, None).await?;
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code });
    }

    let admitted_at = sql_locks::db_clock(tx).await?;
    if admitted_at.saturating_add(CLOCK_UNCERTAINTY_MILLIS) > row.not_after_millis
        || authority
            .earliest_expiry_millis()
            .is_some_and(|expiry| admitted_at.saturating_add(CLOCK_UNCERTAINTY_MILLIS) > expiry)
    {
        close(tx, &row, DecisionState::Rejected, DenialCode::Expired, None, None).await?;
        return Ok(ConsumptionRecord::Rejected { decision_id: row.decision_id, code: DenialCode::Expired });
    }
    close(
        tx,
        &row,
        DecisionState::Consumed,
        DenialCode::LedgerIntegrity,
        Some(receipt_id),
        Some(&digests.facts_digest),
    )
    .await?;
    Ok(ConsumptionRecord::Consumed {
        decision_id: row.decision_id,
        receipt_id,
        selection_digest: digests.selection_digest,
        dependencies_digest: digests.dependencies_digest,
    })
}

fn compare_digests(row: &DecisionRow, digests: &DecisionDigests) -> Option<DenialCode> {
    if digests.authz_digest != row.authz_digest {
        return Some(DenialCode::AuthorizationChanged);
    }
    if digests.dependencies_digest != row.dependencies_digest {
        return Some(DenialCode::DependencyChanged);
    }
    if digests.policy_digest != row.policy_digest {
        return Some(DenialCode::PolicyChanged);
    }
    if digests.facts_digest != row.facts_digest || digests.captured_oid_digest != row.captured_oid_digest {
        return Some(DenialCode::ProofMismatch);
    }
    if digests.command_digest != row.command_digest
        || digests.refs_digest != row.refs_digest
        || digests.selection_digest != row.selection_digest
        || digests.selected_refs_digest != row.selected_refs_digest
    {
        return Some(DenialCode::SelectionChanged);
    }
    if digests.packs_digest != row.packs_digest || digests.hold_receipts_digest != row.hold_receipts_digest {
        return Some(DenialCode::ProofMismatch);
    }
    if digests.base_gate_digest != row.base_gate_digest {
        return Some(DenialCode::GateDigestMismatch);
    }
    None
}

fn closed_denial(row: &DecisionRow) -> DenialCode {
    match row.closed_code.as_deref() {
        Some("cancelled") => DenialCode::Cancelled,
        Some("expired") => DenialCode::Expired,
        Some("all_rejected") => DenialCode::AllRejected,
        Some("rejected_batch") => DenialCode::RejectedBatch,
        Some("authorization_changed") => DenialCode::AuthorizationChanged,
        Some("policy_changed") => DenialCode::PolicyChanged,
        Some("dependency_changed") => DenialCode::DependencyChanged,
        Some("selection_changed") => DenialCode::SelectionChanged,
        Some("proof_mismatch") => DenialCode::ProofMismatch,
        Some("facts_unverifiable") => DenialCode::FactsUnverifiable,
        _ => DenialCode::LedgerIntegrity,
    }
}

async fn close(
    tx: &Transaction<'_>,
    row: &DecisionRow,
    state: DecisionState,
    code: DenialCode,
    receipt_id: Option<Uuid>,
    proof_facts_digest: Option<&RequestDigest>,
) -> Result<(), DecisionError> {
    let state_text = state.as_str();
    let code_text: Option<&str> = if state == DecisionState::Consumed { None } else { Some(code.as_str()) };
    let proof_facts = proof_facts_digest.map(|digest| digest.as_hex());
    let updated = tx
        .query_opt(
            "UPDATE ref_store_publication_decisions
             SET state=$2,
                 closed_code=$3,
                 consume_receipt_id=$4,
                 proof_facts_digest=COALESCE($5,proof_facts_digest),
                 consumed_at=CASE WHEN $2='CONSUMED' THEN clock_timestamp() ELSE consumed_at END,
                 rejected_at=CASE WHEN $2='REJECTED' THEN clock_timestamp() ELSE rejected_at END
             WHERE decision_id=$1 AND state='OPEN'
             RETURNING decision_id",
            &[&row.decision_id, &state_text, &code_text, &receipt_id, &proof_facts],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    if updated.is_none() {
        return Err(DecisionError::DecisionConflict { decision_id: row.decision_id, state: row.state });
    }
    Ok(())
}
