//! Retained decision usage: monotone per-repository and per-tenant ceilings.
//!
//! Every new decision row, per-ref verdict row, dependency observation, cancellation tombstone and the
//! PG-only credential identity is charged in the **same transaction** that writes it. Exact replay is
//! charged `0`. Nothing is refunded by a cancel, rejection, expiry, error, unknown completion or
//! repository delete; reaching a bound is backpressure (`QuotaExceeded`), never pruning.
//!
//! Lock order is the frozen global `tenant usage -> repository usage`; integration calls
//! [`super::sql_locks::lock_usage`] before the gate, and [`charge`] only reads/updates rows this
//! transaction already holds. There is no second lock order and no double charge.
use super::contract::{
    DecisionError, QuotaResource, QuotaScope, REPO_MAX_DECISIONS, REPO_MAX_LOGICAL_BYTES, REPO_MAX_REF_VERDICTS,
    TENANT_MAX_DECISIONS, TENANT_MAX_LOGICAL_BYTES, TENANT_MAX_REF_VERDICTS,
};
use super::sql_locks;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Fixed framing overhead of one decision row (uuid ids, counters and row header).
const DECISION_FRAME_BYTES: i64 = 512;
/// One persisted 64-hex digest.
const DIGEST_BYTES: i64 = 64;
/// One persisted UUID (binary form, charged as its canonical 36-byte text plus framing).
const UUID_BYTES: i64 = 36;
/// Fixed overhead of one per-ref verdict row.
const VERDICT_FRAME_BYTES: i64 = 96;
/// Fixed overhead of one dependency observation row.
const DEPENDENCY_FRAME_BYTES: i64 = 128;
/// Fixed overhead of one cancellation tombstone row.
const CANCELLATION_FRAME_BYTES: i64 = 1024;
/// Admission prepays one maximum cancellation, including both tombstone ledgers.
const INSTALLED_CANCELLATION_RESERVE: i64 = 2048;
/// Fixed framing overhead of the terminal/event metadata payload (keys, quoting, headers).
const TERMINAL_FRAME_BYTES: i64 = 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct UsageDelta {
    pub decisions: i64,
    pub ref_verdicts: i64,
    pub logical_bytes: i64,
}

/// Charge for all new data of one freshly minted decision (never for a replay).
///
/// The logical bytes include the PG-only credential digest, every persisted digest field, both ref
/// names/OIDs of every verdict row and every dependency observation, so the 32 MiB bound covers the
/// real retained payload rather than an optimistic constant.
pub(super) fn delta_for(
    verdict_rows: &[(String, String)],
    dependencies: usize,
    token_digest_len: usize,
) -> Result<UsageDelta, DecisionError> {
    let mut logical_bytes = (DECISION_FRAME_BYTES + 512 + INSTALLED_CANCELLATION_RESERVE)
        .checked_add((token_digest_len as i64).max(DIGEST_BYTES))
        .and_then(|total| total.checked_add(12 * DIGEST_BYTES))
        .and_then(|total| total.checked_add(8 * UUID_BYTES))
        .ok_or(DecisionError::Ledger("decision logical byte total overflows i64"))?;
    for (name, canonical) in verdict_rows {
        logical_bytes = logical_bytes
            .checked_add(VERDICT_FRAME_BYTES)
            .and_then(|total| total.checked_add(name.len() as i64))
            .and_then(|total| total.checked_add(canonical.len() as i64))
            .and_then(|total| total.checked_add(2 * DIGEST_BYTES))
            .ok_or(DecisionError::Ledger("decision logical byte total overflows i64"))?;
    }
    logical_bytes = logical_bytes
        .checked_add((dependencies as i64).saturating_mul(DEPENDENCY_FRAME_BYTES + DIGEST_BYTES + 192))
        .ok_or(DecisionError::Ledger("decision logical byte total overflows i64"))?;
    Ok(UsageDelta { decisions: 1, ref_verdicts: verdict_rows.len() as i64, logical_bytes })
}

/// Charge for one durable cancellation tombstone (charged only when the row is really inserted).
pub(super) fn cancellation_delta(reason_len: usize) -> UsageDelta {
    UsageDelta {
        decisions: 0,
        ref_verdicts: 0,
        logical_bytes: CANCELLATION_FRAME_BYTES + (reason_len as i64).min(256) + DIGEST_BYTES + 2 * UUID_BYTES,
    }
}

fn exceeded(scope: QuotaScope, resource: QuotaResource, bound: i64, actual: i64) -> DecisionError {
    DecisionError::QuotaExceeded { scope, resource, bound, actual }
}

fn checked(value: i64, delta: i64) -> Result<i64, DecisionError> {
    value.checked_add(delta).ok_or(DecisionError::Ledger("decision usage counter overflows i64"))
}

struct Counters {
    decisions: i64,
    ref_verdicts: i64,
    logical_bytes: i64,
}

fn tenant_bounds(counters: &Counters) -> Result<(), DecisionError> {
    if counters.decisions > TENANT_MAX_DECISIONS {
        return Err(exceeded(QuotaScope::Tenant, QuotaResource::Decisions, TENANT_MAX_DECISIONS, counters.decisions));
    }
    if counters.ref_verdicts > TENANT_MAX_REF_VERDICTS {
        return Err(exceeded(
            QuotaScope::Tenant,
            QuotaResource::RefVerdicts,
            TENANT_MAX_REF_VERDICTS,
            counters.ref_verdicts,
        ));
    }
    if counters.logical_bytes > TENANT_MAX_LOGICAL_BYTES {
        return Err(exceeded(
            QuotaScope::Tenant,
            QuotaResource::LogicalBytes,
            TENANT_MAX_LOGICAL_BYTES,
            counters.logical_bytes,
        ));
    }
    Ok(())
}

fn repo_bounds(counters: &Counters) -> Result<(), DecisionError> {
    if counters.decisions > REPO_MAX_DECISIONS {
        return Err(exceeded(QuotaScope::Repository, QuotaResource::Decisions, REPO_MAX_DECISIONS, counters.decisions));
    }
    if counters.ref_verdicts > REPO_MAX_REF_VERDICTS {
        return Err(exceeded(
            QuotaScope::Repository,
            QuotaResource::RefVerdicts,
            REPO_MAX_REF_VERDICTS,
            counters.ref_verdicts,
        ));
    }
    if counters.logical_bytes > REPO_MAX_LOGICAL_BYTES {
        return Err(exceeded(
            QuotaScope::Repository,
            QuotaResource::LogicalBytes,
            REPO_MAX_LOGICAL_BYTES,
            counters.logical_bytes,
        ));
    }
    Ok(())
}

/// Charge both counters. The transaction must already hold them in the frozen `tenant -> repo` order
/// (via [`super::sql_locks::lock_usage`]); a missing row is a ledger error, never an implicit new lock.
pub(super) async fn charge(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    tenant_id: Uuid,
    delta: UsageDelta,
) -> Result<(), DecisionError> {
    let tenant_row = tx
        .query_opt(
            "SELECT decisions,ref_verdicts,logical_bytes FROM ref_store_decision_tenant_usage
             WHERE tenant_id=$1 FOR UPDATE",
            &[&tenant_id],
        )
        .await
        .map_err(sql_locks::sql_error)?
        .ok_or(DecisionError::Ledger("tenant usage row was not locked before charging"))?;
    let tenant = Counters {
        decisions: checked(tenant_row.get::<_, i64>(0), delta.decisions)?,
        ref_verdicts: checked(tenant_row.get::<_, i64>(1), delta.ref_verdicts)?,
        logical_bytes: checked(tenant_row.get::<_, i64>(2), delta.logical_bytes)?,
    };
    tenant_bounds(&tenant)?;

    let repo_row = tx
        .query_opt(
            "SELECT decisions,ref_verdicts,logical_bytes FROM ref_store_decision_repo_usage
             WHERE repository_id=$1 FOR UPDATE",
            &[&repository_id],
        )
        .await
        .map_err(sql_locks::sql_error)?
        .ok_or(DecisionError::Ledger("repository usage row was not locked before charging"))?;
    let repo = Counters {
        decisions: checked(repo_row.get::<_, i64>(0), delta.decisions)?,
        ref_verdicts: checked(repo_row.get::<_, i64>(1), delta.ref_verdicts)?,
        logical_bytes: checked(repo_row.get::<_, i64>(2), delta.logical_bytes)?,
    };
    repo_bounds(&repo)?;

    tx.execute(
        "UPDATE ref_store_decision_tenant_usage
         SET decisions=$2,ref_verdicts=$3,logical_bytes=$4,updated_at=clock_timestamp()
         WHERE tenant_id=$1",
        &[&tenant_id, &tenant.decisions, &tenant.ref_verdicts, &tenant.logical_bytes],
    )
    .await
    .map_err(sql_locks::sql_error)?;
    tx.execute(
        "UPDATE ref_store_decision_repo_usage
         SET decisions=$2,ref_verdicts=$3,logical_bytes=$4,updated_at=clock_timestamp()
         WHERE repository_id=$1",
        &[&repository_id, &repo.decisions, &repo.ref_verdicts, &repo.logical_bytes],
    )
    .await
    .map_err(sql_locks::sql_error)?;
    Ok(())
}

/// Reserve the bounded terminal/event metadata payload before decision admission.
///
/// Admission reserves the fixed 64 KiB body ceiling twice (registry and
/// event), conservative possible ref-row bytes and framing. The final metadata
/// transaction needs no additional quota. Exact install replay reserves zero;
/// unused reservation is retained, so full counters cannot trap an installed
/// operation without a terminal. All decisions also prepay one cancellation
/// tombstone in `delta_for`.
pub(in crate::ref_store::core) async fn reserve_metadata_terminal(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    tenant_id: Uuid,
    terminal_body_bytes: usize,
    ref_bytes: usize,
) -> Result<(), DecisionError> {
    let terminal_body_bytes = i64::try_from(terminal_body_bytes)
        .map_err(|_| DecisionError::Ledger("metadata terminal byte length exceeds i64"))?;
    let ref_bytes =
        i64::try_from(ref_bytes).map_err(|_| DecisionError::Ledger("metadata ref byte length exceeds i64"))?;
    let logical_bytes = terminal_body_bytes
        .checked_mul(2)
        .and_then(|total| total.checked_add(ref_bytes))
        .and_then(|total| total.checked_add(TERMINAL_FRAME_BYTES))
        .ok_or(DecisionError::Ledger("metadata terminal logical byte total overflows i64"))?;
    let delta = UsageDelta { decisions: 0, ref_verdicts: 0, logical_bytes };
    charge(tx, repository_id, tenant_id, delta).await
}
