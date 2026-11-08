//! SQL helpers shared by the isolated core adapter.
//!
//! These functions are always called inside the owned short transaction that
//! `super::pg` starts. They contain no commit/rollback logic of their own and
//! never open a connection, so the transaction ownership and rollback policy
//! live in exactly one place.
use super::super::contract::{BeginReceipt, OperationState, RefStoreError, TerminalOutcome, TerminalResult};
use super::super::pg::{self, PgRefStore};
use super::command::CommitRefsRequest;
use super::contract::CoreGate;
use super::terminal::{CommitRefsReceipt, CommitRejectCode, CommitRejection, CommitTerminal, RefCommitResult};
use super::types::{GitObjectFormat, HeadUpdate, RefName, RefPrecondition};
use std::collections::BTreeMap;
use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(super) fn replay_terminal(begun: BeginReceipt) -> Result<CommitRefsReceipt, RefStoreError> {
    match begun.record.state() {
        OperationState::Committed | OperationState::Rejected => {
            let stored = begun
                .record
                .terminal_result()
                .ok_or_else(|| RefStoreError::Database("terminal operation has no result".into()))?;
            let terminal = CommitTerminal::from_terminal_result(stored)?;
            Ok(CommitRefsReceipt { replayed: true, record: begun.record, terminal })
        }
        OperationState::Cancelled => Err(RefStoreError::Cancelled {
            operation_id: begun.record.identity().operation_id(),
        }),
        OperationState::Pending => Err(RefStoreError::OperationPending {
            operation_id: begun.record.identity().operation_id(),
        }),
    }
}

pub(super) async fn gate_row(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    for_update: bool,
) -> Result<Option<CoreGate>, RefStoreError> {
    let query = format!(
        "SELECT tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,head_ref,revision
         FROM ref_store_core_gates WHERE repository_id=$1{}",
        if for_update { " FOR UPDATE" } else { "" }
    );
    tx.query_opt(&query, &[&repository_id])
        .await
        .map_err(pg::db_error)?
        .map(|row| gate_from_row(repository_id, &row))
        .transpose()
}

pub(super) fn gate_from_row(repository_id: Uuid, row: &tokio_postgres::Row) -> Result<CoreGate, RefStoreError> {
    let object_format: String = row.get(1);
    let head_ref: String = row.get(5);
    CoreGate::new(
        repository_id,
        row.get(0),
        GitObjectFormat::parse(&object_format)?,
        row.get(2),
        row.get(3),
        row.get(4),
        RefName::new(head_ref)?,
        row.get(6),
    )
}

pub(super) fn lookup_names(request: &CommitRefsRequest, current_head: &RefName) -> Vec<String> {
    let mut names = request.refs().iter().map(|update| update.name().as_str().to_owned()).collect::<Vec<_>>();
    names.push(current_head.as_str().to_owned());
    if let HeadUpdate::Retarget(target) = request.head() {
        names.push(target.as_str().to_owned());
    }
    names.sort();
    names.dedup();
    names
}

pub(super) async fn lock_relevant_refs(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    names: Vec<String>,
) -> Result<BTreeMap<String, String>, RefStoreError> {
    let rows = tx
        .query(
            "SELECT ref_name,oid FROM ref_store_core_refs
             WHERE repository_id=$1 AND (
                 ref_name = ANY($2::text[])
                 OR EXISTS (
                     SELECT 1 FROM unnest($2::text[]) AS requested(name)
                     WHERE left(ref_store_core_refs.ref_name, length(requested.name)+1) = requested.name || '/'
                        OR left(requested.name, length(ref_store_core_refs.ref_name)+1) = ref_store_core_refs.ref_name || '/'
                 )
             )
             ORDER BY ref_name FOR UPDATE",
            &[&repository_id, &names],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(rows.into_iter().map(|row| (row.get(0), row.get(1))).collect())
}

type Reject = (CommitRejectCode, String, Option<String>, Option<String>);

pub(super) fn check_cas(request: &CommitRefsRequest, existing: &BTreeMap<String, String>) -> Result<(), Reject> {
    for update in request.refs() {
        let name = update.name().as_str();
        let actual = existing.get(name).cloned();
        match update.precondition() {
            RefPrecondition::Absent => {
                if let Some(actual) = actual {
                    return Err((
                        CommitRejectCode::OldOidMismatch,
                        name.to_owned(),
                        Some("absent".into()),
                        Some(actual),
                    ));
                }
            }
            RefPrecondition::Present(expected) => {
                let expected = expected.as_hex();
                if actual.as_deref() != Some(expected.as_str()) {
                    return Err((CommitRejectCode::OldOidMismatch, name.to_owned(), Some(expected), actual));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn check_existing_prefixes(
    request: &CommitRefsRequest,
    existing: &BTreeMap<String, String>,
) -> Result<(), (String, String)> {
    for update in request.refs() {
        let name = update.name().as_str();
        for current in existing.keys() {
            if current.as_str() == name {
                continue;
            }
            if super::types::is_strict_prefix(name, current) || super::types::is_strict_prefix(current, name) {
                return Err((name.to_owned(), current.clone()));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn reject(
    tx: &Transaction<'_>,
    request: &CommitRefsRequest,
    gate: Option<&CoreGate>,
    code: CommitRejectCode,
    ref_name: Option<String>,
    expected: Option<String>,
    actual: Option<String>,
    deadline: Instant,
) -> Result<CommitRefsReceipt, RefStoreError> {
    let revision = gate.map(CoreGate::revision).unwrap_or(0);
    let head_ref = gate.map(|gate| gate.head_ref().as_str().to_owned());
    let refs = request
        .refs()
        .iter()
        .map(|update| RefCommitResult::NotApplied { name: update.name().as_str().to_owned(), reason: code })
        .collect::<Vec<_>>();
    let rejection = CommitRejection { code, ref_name, expected, actual };
    // The pre-begin terminal budget covered this exact rejected shape too.
    let terminal = CommitTerminal::rejected(request.repository_id(), revision, head_ref, refs, rejection);
    let result = terminal.to_terminal_result()?;
    let receipt =
        PgRefStore.record_terminal(tx, request.identity(), TerminalOutcome::Rejected, &result, deadline).await?;
    let operation_id = receipt.record.identity().operation_id();
    insert_event(tx, request.repository_id(), revision, operation_id, "rejected", &result).await?;
    Ok(CommitRefsReceipt { replayed: receipt.replayed, record: receipt.record, terminal })
}

pub(super) async fn insert_event(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    revision: i64,
    operation_id: Uuid,
    outcome: &str,
    result: &TerminalResult,
) -> Result<(), RefStoreError> {
    tx.execute(
        "INSERT INTO ref_store_core_events(event_id,repository_id,revision,operation_id,outcome,payload)
         VALUES($1,$2,$3,$4,$5,$6)",
        &[&Uuid::new_v4(), &repository_id, &revision, &operation_id, &outcome, &result.value()],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}
