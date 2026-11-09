//! One short transaction consumes the decision and records every publication effect.
use super::super::context::{PackCommitBaseline, refs_digest};
use super::super::contract::{MAX_CAPTURE_REFS, PackMode};
use super::super::error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
use super::super::receipt::{
    PackCommitReceipt, PackCommitTerminal, PackTerminalRegistration, ensure_pack_terminal_budget,
};
use super::super::{pg, pg_commit, registration, sql, usage};
use super::{
    AuthorizedCommitError, PgAuthorizedCommit, VerifiedAuthorizedPublication, effective_deadline, pooled_client,
};
use crate::ref_store::contract::{OperationRecord, OperationState, RequestDigest, TerminalOutcome};
use crate::ref_store::core::decision_commit::{self, RealmExpectation};
use crate::ref_store::core::publication_decision::{self as decisions, ConsumptionRecord};
use crate::ref_store::core::subset::RefRejectReason;
use crate::ref_store::core::terminal::{CommitRejectCode, RefCommitResult};
use crate::ref_store::pg::PgRefStore;
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedCommitReceipt {
    pub record: OperationRecord,
    pub replayed: bool,
    pub terminal: PackCommitTerminal,
    pub selection_digest: RequestDigest,
}

impl AuthorizedCommitReceipt {
    pub fn is_committed(&self) -> bool {
        self.record.state() == OperationState::Committed && self.terminal.is_committed()
    }
}

impl PgAuthorizedCommit {
    pub async fn commit(
        &self,
        pool: &deadpool_postgres::Pool,
        verified: &VerifiedAuthorizedPublication,
        deadline: Instant,
    ) -> Result<AuthorizedCommitReceipt, AuthorizedCommitError> {
        let deadline = effective_deadline(deadline)?;
        let plan = verified.selection().prepared().plan();
        ensure_pack_terminal_budget(plan)?;
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        let outcome = match timeout_at(deadline, commit_in_tx(&tx, verified, deadline)).await {
            Ok(value) => value,
            Err(_) => Err(AuthorizedCommitError::Timeout),
        };
        match outcome {
            Ok(receipt) => {
                commit_bounded(tx, deadline, plan.repository_id(), Some(plan.identity().operation_id()))
                    .await
                    .map_err(PackCommitError::from)?;
                Ok(receipt)
            }
            Err(error) => {
                let _cleanup = super::rollback(tx, deadline).await;
                Err(error)
            }
        }
    }
}

async fn commit_in_tx(
    tx: &Transaction<'_>,
    verified: &VerifiedAuthorizedPublication,
    deadline: Instant,
) -> Result<AuthorizedCommitReceipt, AuthorizedCommitError> {
    let selection = verified.selection();
    let prepared = selection.prepared();
    let plan = prepared.plan();
    pg::set_ack_durability(tx, deadline).await?;
    let begun = PgRefStore.begin(tx, plan.identity(), deadline).await?;
    match begun.record.state() {
        OperationState::Committed | OperationState::Rejected => {
            return Ok(receipt(pg::replay_terminal(begun)?, *selection.selection_digest()));
        }
        OperationState::Cancelled => {
            return Err(super::reject(PackCommitRejectCode::Cancelled, "cancellation tombstone won"));
        }
        OperationState::Pending if begun.created => {
            return Err(super::reject(
                PackCommitRejectCode::PendingMissing,
                "publication needs an existing pending operation",
            ));
        }
        OperationState::Pending => {}
    }
    // SHARE NOWAIT is taken before any authorization reads and retained through COMMIT.
    decisions::sql_locks::lock_source_tables(tx, selection.selected().action()).await.map_err(super::decision_error)?;
    pg::ensure_repository(tx, plan, true).await?;
    decisions::sql_locks::lock_usage(tx, plan.repository_id(), plan.tenant_id())
        .await
        .map_err(super::decision_error)?;
    let locked = usage::lock(tx, plan.repository_id(), plan.tenant_id()).await?;
    let (gate, mode) = sql::gate_locked(tx, plan.repository_id())
        .await?
        .ok_or_else(|| pg::reject(PackCommitRejectCode::GateNotFound, "core gate missing"))?;
    pg::ensure_gate_matches(plan, &gate, mode)?;
    decision_commit::lock_and_enforce(tx, &RealmExpectation::from_gate(&gate)).await?;
    let refs = sql::capture_refs(tx, plan.repository_id(), gate.object_format(), MAX_CAPTURE_REFS).await?;
    if refs_digest(&refs) != *prepared.refs_digest() {
        return Err(super::reject(PackCommitRejectCode::OldOidMismatch, "captured ref set changed"));
    }
    let old_packs = registration::old_memberships(tx, &gate, deadline).await?;
    let baseline = PackCommitBaseline::new(gate.version(), mode, refs, old_packs)?;
    if baseline.membership_digest() != prepared.baseline().membership_digest() {
        return Err(super::reject(PackCommitRejectCode::OldMembershipMismatch, "captured membership changed"));
    }
    let new_packs = sql::registered_for_parent(tx, plan).await?;
    let projection = selection.selected().selected_plan();
    let context = if projection.is_all_rejected() {
        None
    } else {
        let context = super::super::PackClosureContext::capture_selected(projection, &baseline, new_packs)?;
        let proof = verified
            .proof()
            .ok_or_else(|| super::reject(PackCommitRejectCode::ClosureMismatch, "missing selected closure"))?;
        if !proof.binds(plan, &context) {
            return Err(super::reject(PackCommitRejectCode::ClosureMismatch, "selected closure binding changed"));
        }
        Some(context)
    };
    let consumed = decisions::authorized_final_check(
        tx,
        selection.selected(),
        plan,
        selection.actor(),
        verified.proof(),
        selection.facts(),
        plan.identity().operation_id(),
        deadline,
    )
    .await
    .map_err(super::decision_error)?;
    let rejection = match consumed {
        ConsumptionRecord::Consumed { .. } if !projection.is_all_rejected() => None,
        ConsumptionRecord::Consumed { .. } => {
            Some(PackCommitRejection::new(PackCommitRejectCode::NoRefApplied, "no ref accepted"))
        }
        ConsumptionRecord::Rejected { code, .. } => Some(PackCommitRejection::new(
            if projection.is_all_rejected() {
                PackCommitRejectCode::NoRefApplied
            } else {
                PackCommitRejectCode::DecisionRejected
            },
            code.as_str(),
        )),
    };
    let mut outcomes = outcomes(projection);
    if rejection.is_some() && !projection.is_all_rejected() {
        outcomes = plan
            .refs()
            .iter()
            .map(|update| RefCommitResult::NotApplied {
                name: update.name().as_str().to_owned(),
                reason: CommitRejectCode::PolicyDenied,
            })
            .collect();
    }
    let terminal = if let Some(reason) = rejection {
        PackCommitTerminal::rejected(
            plan.repository_id(),
            gate.revision(),
            Some(gate.head_ref().as_str().to_owned()),
            mode,
            outcomes,
            reason,
        )
    } else {
        let context = context
            .as_ref()
            .ok_or_else(|| super::reject(PackCommitRejectCode::ClosureMismatch, "missing selected context"))?;
        let revision =
            gate.revision().checked_add(1).ok_or(AuthorizedCommitError::Unverifiable("revision exhausted"))?;
        PackCommitTerminal::committed(
            plan.repository_id(),
            revision,
            context.resulting_head().as_str().to_owned(),
            PackMode::PackVerified,
            outcomes,
            context
                .new_packs()
                .iter()
                .map(|pack| PackTerminalRegistration {
                    pack_id: pack.pack_id(),
                    registration_id: pack.registration_id(),
                    artifact_set_digest: pack.artifact_set_digest().as_hex(),
                })
                .collect(),
        )
    };
    let result = terminal.to_terminal_result()?;
    let body_bytes = serde_json::to_vec(&terminal)
        .map_err(|_| AuthorizedCommitError::Unverifiable("terminal encoding failed"))?
        .len();
    let history = verified.proof().map(|proof| proof.context_digest().as_hex()).unwrap_or_default();
    let quota = usage::plan(
        &locked,
        usage::Charge::membership(
            if terminal.is_committed() { plan.packs().len() as i64 } else { 0 },
            history.len(),
            body_bytes,
        )?,
    )?;
    let committed = if terminal.is_committed() {
        let prepared = pg_commit::PreparedCommit {
            new_revision: terminal.revision,
            new_head: terminal.head_ref.clone().ok_or(AuthorizedCommitError::Unverifiable("terminal HEAD missing"))?,
            terminal,
            result,
            terminal_body_bytes: body_bytes,
        };
        pg_commit::write_verified_commit(
            tx,
            plan,
            projection.accepted(),
            &history,
            context.as_ref().ok_or(AuthorizedCommitError::Unverifiable("selected context missing"))?,
            &gate,
            &prepared,
            deadline,
        )
        .await?
    } else {
        let record =
            PgRefStore.record_terminal(tx, plan.identity(), TerminalOutcome::Rejected, &result, deadline).await?;
        crate::ref_store::core::sql::insert_event(
            tx,
            plan.repository_id(),
            gate.revision(),
            plan.identity().operation_id(),
            "rejected",
            &result,
        )
        .await?;
        PackCommitReceipt { record: record.record, replayed: record.replayed, terminal }
    };
    usage::apply(tx, &quota).await?;
    Ok(receipt(committed, *selection.selection_digest()))
}

fn receipt(value: PackCommitReceipt, selection_digest: RequestDigest) -> AuthorizedCommitReceipt {
    AuthorizedCommitReceipt {
        record: value.record,
        replayed: value.replayed,
        terminal: value.terminal,
        selection_digest,
    }
}

fn outcomes(projection: &crate::ref_store::core::subset::SelectedPackPlan) -> Vec<RefCommitResult> {
    projection
        .original()
        .refs()
        .iter()
        .zip(projection.selection().verdicts())
        .map(|(update, verdict)| {
            if verdict.is_accepted() {
                RefCommitResult::Applied {
                    name: update.name().as_str().to_owned(),
                    old_oid: update.precondition().oid().map(|oid| oid.as_hex()),
                    new_oid: update.target().oid().map(|oid| oid.as_hex()),
                }
            } else {
                let reason = match verdict.reason() {
                    Some(RefRejectReason::Cas) => CommitRejectCode::OldOidMismatch,
                    Some(RefRejectReason::MissingTarget) => CommitRejectCode::MissingTarget,
                    Some(RefRejectReason::BadObjectType) => CommitRejectCode::BadObjectType,
                    Some(RefRejectReason::PrefixConflict) => CommitRejectCode::PrefixConflict,
                    Some(RefRejectReason::HeadDependency) => CommitRejectCode::HeadDependencyMissing,
                    _ => CommitRejectCode::PolicyDenied,
                };
                RefCommitResult::NotApplied { name: update.name().as_str().to_owned(), reason }
            }
        })
        .collect()
}
