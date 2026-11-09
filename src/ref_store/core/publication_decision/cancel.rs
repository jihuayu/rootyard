//! Cancellation of a publication decision, including cancel-before-install.
//!
//! There is exactly one entry point, the crate-private [`coordinator_cancel`], which runs inside the
//! caller-owned transaction and performs the real authorization: the actor must be the live
//! owner/admin of the repository (effective RBAC role, live non-read-only `api` token). There is
//! deliberately no authority-skipping variant, so a native hook, a request body or an unauthenticated
//! caller can never cancel an operation.
//!
//! Order is the migration-138 prefix first (operation advisory key -> lane -> 138 tombstone), then the
//! decision control row. That is the same prefix a commit takes, so a cancel can never invert against a
//! commit and exactly one terminal outcome is durable in either race order.
use super::contract::{
    CancelOutcome, DecisionError, DecisionState, DenialCode, MAX_CANCEL_REASON_BYTES, PublicationAction,
};
use super::sql_locks;
use super::usage;
use crate::db::Identity;
use crate::members::models::Role;
use crate::ref_store::contract::{OperationIdentity, OperationState};
use crate::ref_store::pg::PgRefStore;
use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// The only cancellation entry: inside a caller-owned transaction. The live authority checks below are
/// mandatory; nothing is skipped.
pub(crate) async fn coordinator_cancel(
    tx: &Transaction<'_>,
    actor: &Identity,
    identity: &OperationIdentity,
    reason: &str,
    deadline: Instant,
) -> Result<CancelOutcome, DecisionError> {
    validate_reason(reason)?;
    cancel_in_tx(tx, actor, identity, reason, deadline).await
}

fn validate_reason(reason: &str) -> Result<(), DecisionError> {
    if reason.is_empty() || reason.len() > MAX_CANCEL_REASON_BYTES {
        return Err(DecisionError::Ledger("cancellation reason length is out of bounds"));
    }
    if reason.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(DecisionError::Ledger("cancellation reason contains control characters"));
    }
    Ok(())
}

async fn cancel_in_tx(
    tx: &Transaction<'_>,
    actor: &Identity,
    identity: &OperationIdentity,
    reason: &str,
    deadline: Instant,
) -> Result<CancelOutcome, DecisionError> {
    crate::ref_store::pg::bound(tx, deadline).await?;

    // 1. Migration-138 prefix FIRST (operation advisory key -> lane -> tombstone), so a cancel can
    //    never invert against a commit that takes the same prefix.
    let receipt = PgRefStore.cancel(tx, identity, deadline).await?;
    // 2. Frozen source table locks, then repository -> tenant usage -> repository usage -> gate ->
    //    protocol, before any live authority read.
    sql_locks::lock_source_tables(tx, &PublicationAction::Push).await?;
    sql_locks::lock_repository_row(tx, identity.repository_id()).await?;
    let tenant_id: Uuid = tx
        .query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&identity.repository_id()])
        .await
        .map_err(sql_locks::sql_error)?
        .get(0);
    sql_locks::lock_usage(tx, identity.repository_id(), tenant_id).await?;
    let _ = sql_locks::protocol_state(tx, identity.repository_id()).await?;
    authorize(tx, actor, identity.repository_id()).await?;
    let operation_id = identity.operation_id();
    let decision = sql_locks::decision_by_operation(tx, identity.repository_id(), operation_id, true).await?;

    if let Some(record) = &receipt.record {
        match record.state() {
            OperationState::Committed => {
                let decision = decision
                    .as_ref()
                    .ok_or(DecisionError::Ledger("committed operation has no durable publication decision"))?;
                if decision.state != DecisionState::Consumed {
                    return Err(DecisionError::Ledger("committed operation decision is not consumed"));
                }
                return Ok(CancelOutcome::AlreadyConsumed {
                    operation_id,
                    decision_id: decision.decision_id,
                    receipt_id: decision.consume_receipt_id.unwrap_or_else(Uuid::nil),
                });
            }
            OperationState::Rejected => {
                return Ok(CancelOutcome::AlreadyRejected {
                    operation_id,
                    decision_id: decision.as_ref().map(|row| row.decision_id),
                });
            }
            OperationState::Cancelled | OperationState::Pending => {}
        }
    }

    match &decision {
        Some(row) => match row.state {
            DecisionState::Open => {
                let updated = tx
                    .query_opt(
                        "UPDATE ref_store_publication_decisions
                         SET state='CANCELLED',cancelled_at=clock_timestamp(),closed_code='cancelled'
                         WHERE decision_id=$1 AND state='OPEN'
                         RETURNING decision_id",
                        &[&row.decision_id],
                    )
                    .await
                    .map_err(sql_locks::sql_error)?;
                if updated.is_none() {
                    return Err(DecisionError::DecisionConflict { decision_id: row.decision_id, state: row.state });
                }
                bind_cancellation(tx, identity, Some(row.decision_id), actor, reason).await?;
                Ok(CancelOutcome::Cancelled {
                    operation_id,
                    decision_id: Some(row.decision_id),
                    tombstone_created: receipt.tombstone_created,
                })
            }
            DecisionState::Consumed => Ok(CancelOutcome::AlreadyConsumed {
                operation_id,
                decision_id: row.decision_id,
                receipt_id: row.consume_receipt_id.unwrap_or_else(Uuid::nil),
            }),
            DecisionState::Cancelled => {
                bind_cancellation(tx, identity, Some(row.decision_id), actor, reason).await?;
                Ok(CancelOutcome::AlreadyCancelled { operation_id, decision_id: Some(row.decision_id) })
            }
            DecisionState::Rejected => {
                Ok(CancelOutcome::AlreadyRejected { operation_id, decision_id: Some(row.decision_id) })
            }
        },
        None => {
            // Cancel-before-install: the durable tombstone is the winner; a later install finds it and
            // never mints a decision or writes a ref.
            bind_cancellation(tx, identity, None, actor, reason).await?;
            Ok(CancelOutcome::Cancelled {
                operation_id,
                decision_id: None,
                tombstone_created: receipt.tombstone_created,
            })
        }
    }
}

/// Live owner/admin authority over the repository, from the real RBAC and token rows.
async fn authorize(tx: &Transaction<'_>, actor: &Identity, repository_id: Uuid) -> Result<(), DecisionError> {
    let token = tx
        .query_opt(
            "SELECT t.read_only FROM tokens t
             WHERE t.id=$1 AND t.user_id=$2 AND t.digest=$3 AND NOT t.revoked
               AND (t.expires_at IS NULL OR t.expires_at > clock_timestamp()) AND t.kind='api'",
            &[&actor.token_id, &actor.id, &actor.token_digest],
        )
        .await
        .map_err(sql_locks::sql_error)?
        .ok_or(DecisionError::Denied(DenialCode::TokenInvalid))?;
    if token.get::<_, bool>(0) {
        return Err(DecisionError::Denied(DenialCode::TokenReadOnly));
    }
    let repository = tx
        .query_opt("SELECT owner_id FROM repositories WHERE id=$1", &[&repository_id])
        .await
        .map_err(sql_locks::sql_error)?
        .ok_or(DecisionError::Denied(DenialCode::RepositoryNotFound))?;
    let owner_id: Uuid = repository.get(0);
    let role = crate::members::rbac::resolve_effective_role(tx, repository_id, owner_id, actor.id)
        .await
        .map_err(|_| DecisionError::Unverifiable("live RBAC resolution failed"))?
        .map(|(effective, _, _)| effective)
        .ok_or(DecisionError::Denied(DenialCode::RoleDenied))?;
    if role < Role::Admin {
        return Err(DecisionError::Denied(DenialCode::RoleDenied));
    }
    Ok(())
}

/// Persist (or verify) the decision-level cancellation tombstone and bind its decision id once.
async fn bind_cancellation(
    tx: &Transaction<'_>,
    identity: &OperationIdentity,
    decision_id: Option<Uuid>,
    actor: &Identity,
    reason: &str,
) -> Result<(), DecisionError> {
    let request_digest = identity.digest().as_hex();
    let inserted = tx
        .query_opt(
            "INSERT INTO ref_store_decision_cancellations(
                 repository_id,operation_id,decision_id,request_digest,actor_id,reason)
             VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(repository_id,operation_id) DO NOTHING
             RETURNING repository_id",
            &[&identity.repository_id(), &identity.operation_id(), &decision_id, &request_digest, &actor.id, &reason],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    if inserted.is_some() && decision_id.is_none() {
        // Installed decisions prepaid their cancellation row at admission.
        // A decision-less tombstone is charged once; exact replay charges zero.
        let tenant_id: Uuid = tx
            .query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&identity.repository_id()])
            .await
            .map_err(sql_locks::sql_error)?
            .get(0);
        usage::charge(tx, identity.repository_id(), tenant_id, usage::cancellation_delta(reason.len())).await?;
    }
    let row = tx
        .query_one(
            "SELECT request_digest,actor_id,decision_id FROM ref_store_decision_cancellations
             WHERE repository_id=$1 AND operation_id=$2 FOR UPDATE",
            &[&identity.repository_id(), &identity.operation_id()],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    let stored_digest: String = row.get(0);
    if stored_digest != request_digest {
        return Err(DecisionError::Ledger("cancellation tombstone binds another operation digest"));
    }
    let stored_actor: Uuid = row.get(1);
    if stored_actor != actor.id {
        return Err(DecisionError::Ledger("cancellation tombstone binds another actor"));
    }
    let stored_decision: Option<Uuid> = row.get(2);
    match (stored_decision, decision_id) {
        (None, Some(decision_id)) => {
            tx.execute(
                "UPDATE ref_store_decision_cancellations SET decision_id=$3
                 WHERE repository_id=$1 AND operation_id=$2 AND decision_id IS NULL",
                &[&identity.repository_id(), &identity.operation_id(), &decision_id],
            )
            .await
            .map_err(sql_locks::sql_error)?;
            Ok(())
        }
        (Some(left), Some(right)) if left != right => {
            Err(DecisionError::Ledger("cancellation tombstone binds another decision"))
        }
        _ => Ok(()),
    }
}
