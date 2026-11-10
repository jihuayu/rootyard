//! A served operation whose admitted base was superseded gets a durable no-write
//! result. This is never an error-to-abort conversion: the caller supplies the
//! sealed pending token, and this transaction proves the same realm advanced.
use super::super::error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
use super::super::plan::PackCommitPlan;
use super::super::receipt::{PackCommitTerminal, ensure_pack_terminal_budget};
use super::super::request::PackPendingToken;
use super::super::{pg, producer, sql, usage};
use super::{AuthorizedCommitError, PgAuthorizedCommit, effective_deadline, pooled_client};
use crate::db::Identity;
use crate::ref_store::contract::{OperationState, RequestDigest, TerminalOutcome};
use crate::ref_store::core::decision_commit::{self, RealmExpectation};
use crate::ref_store::core::publication_decision as decisions;
use crate::ref_store::core::terminal::{CommitRejectCode, RefCommitResult};
use crate::ref_store::pg::PgRefStore;
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;

impl PgAuthorizedCommit {
    /// Close only a previously admitted served plan whose exact base revision
    /// has advanced. The method cannot create a pending row or publish refs.
    /// An ambiguous commit remains unknown, including this refusal's COMMIT.
    pub(crate) async fn reject_superseded_serving(
        &self,
        pool: &deadpool_postgres::Pool,
        token: &PackPendingToken,
        plan: &PackCommitPlan,
        actor: &Identity,
        producer_digest: RequestDigest,
        deadline: Instant,
    ) -> Result<Option<PackCommitTerminal>, AuthorizedCommitError> {
        if !token.binds(plan) || plan.identity().issuer_id() != actor.id {
            return Err(AuthorizedCommitError::Denied("issuer_mismatch"));
        }
        let deadline = effective_deadline(deadline)?;
        ensure_pack_terminal_budget(plan)?;
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        let result = match timeout_at(deadline, reject_in_tx(&tx, plan, actor, producer_digest, deadline)).await {
            Ok(value) => value,
            Err(_) => Err(AuthorizedCommitError::Timeout),
        };
        match result {
            Ok(Some(terminal)) => {
                commit_bounded(tx, deadline, plan.repository_id(), Some(plan.identity().operation_id()))
                    .await
                    .map_err(PackCommitError::from)?;
                Ok(Some(terminal))
            }
            Ok(None) => {
                super::rollback(tx, deadline).await?;
                Ok(None)
            }
            Err(error) => {
                let _cleanup = super::rollback(tx, deadline).await;
                Err(error)
            }
        }
    }
}

async fn reject_in_tx(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    actor: &Identity,
    producer_digest: RequestDigest,
    deadline: Instant,
) -> Result<Option<PackCommitTerminal>, AuthorizedCommitError> {
    pg::set_ack_durability(tx, deadline).await?;
    let begun = PgRefStore.begin(tx, plan.identity(), deadline).await?;
    if begun.created {
        return Err(super::reject(PackCommitRejectCode::PendingMissing, "refusal requires admitted operation"));
    }
    let binding = producer::read_serving_operation(tx, plan.repository_id(), plan.identity().operation_id(), deadline)
        .await?
        .ok_or(AuthorizedCommitError::Ledger("refusal has no served request binding"))?;
    if binding.parent_digest() != plan.parent_digest() || binding.producer_digest() != &producer_digest {
        return Err(AuthorizedCommitError::Ledger("refusal served request binding differs"));
    }
    match begun.record.state() {
        OperationState::Committed | OperationState::Rejected => return Ok(Some(pg::replay_terminal(begun)?.terminal)),
        OperationState::Cancelled => return Ok(None),
        OperationState::Pending => {}
    }
    decisions::lock_source_tables(tx, &decisions::PublicationAction::Push).await.map_err(super::decision_error)?;
    pg::ensure_repository(tx, plan, true).await?;
    decisions::lock_usage(tx, plan.repository_id(), plan.tenant_id()).await.map_err(super::decision_error)?;
    let locked = usage::lock(tx, plan.repository_id(), plan.tenant_id()).await?;
    let (gate, mode) = sql::gate_locked(tx, plan.repository_id())
        .await?
        .ok_or_else(|| super::reject(PackCommitRejectCode::GateNotFound, "core gate missing"))?;
    let expected_realm = RealmExpectation::new(
        plan.repository_id(),
        plan.tenant_id(),
        plan.object_format(),
        plan.history_incarnation(),
        plan.authority_epoch(),
        plan.group_epoch(),
    )?;
    if RealmExpectation::from_gate(&gate) != expected_realm {
        return Err(super::reject(PackCommitRejectCode::HistoryIncarnationMismatch, "refusal realm differs"));
    }
    decision_commit::lock_and_enforce(tx, &expected_realm).await?;
    // A changed error string, a stale HTTP lookup or an unknown COMMIT is not
    // proof. Only the locked authoritative gate moving forward is sufficient.
    if gate.revision() <= plan.expected().revision() {
        return Ok(None);
    }
    decisions::reject_superseded_push(tx, plan, actor).await.map_err(super::decision_error)?;
    let terminal = PackCommitTerminal::rejected(
        plan.repository_id(),
        gate.revision(),
        Some(gate.head_ref().as_str().to_owned()),
        mode,
        plan.refs()
            .iter()
            .map(|update| RefCommitResult::NotApplied {
                name: update.name().as_str().to_owned(),
                reason: CommitRejectCode::OldOidMismatch,
            })
            .collect(),
        PackCommitRejection::new(PackCommitRejectCode::RevisionMismatch, "admitted base was superseded"),
    );
    let result = terminal.to_terminal_result()?;
    let body_bytes = serde_json::to_vec(&terminal)
        .map_err(|_| AuthorizedCommitError::Unverifiable("terminal encoding failed"))?
        .len();
    let quota = usage::plan(&locked, usage::Charge::membership(0, 0, body_bytes)?)?;
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
    usage::apply(tx, &quota).await?;
    Ok(Some(terminal))
}
