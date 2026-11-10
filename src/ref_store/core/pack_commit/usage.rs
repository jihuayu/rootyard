//! Retained-admission accounting for pack registrations and memberships.
//!
//! Lock order is fixed: migration-138 operation prefix → separate registration
//! request keys → **tenant usage → repository usage** → core gate → sorted
//! registrations/holds. Counter rows are therefore *locked* before the gate is
//! touched, the exact delta is computed and checked before the first persistent
//! pack/ref write, and `apply` writes the admitted values in the same
//! transaction. There is no global counter lock and no refund path.
use super::contract::{
    RECEIPT_OVERHEAD_BYTES, REPO_MAX_ARTIFACTS, REPO_MAX_LOGICAL_BYTES, REPO_MAX_MEMBERSHIPS, REPO_MAX_RECEIPTS,
    REPO_MAX_REGISTRATIONS, TENANT_MAX_ARTIFACTS, TENANT_MAX_LOGICAL_BYTES, TENANT_MAX_MEMBERSHIPS,
    TENANT_MAX_RECEIPTS, TENANT_MAX_REGISTRATIONS,
};
use super::error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::pg;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// One exact logical charge. `logical_bytes` counts retained DB row/body bytes
/// only (publication ACK body, history body, terminal body and fixed row
/// overhead); Blob payload bytes are A3 declared bytes and are never relabelled.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Charge {
    pub registrations: i64,
    pub artifacts: i64,
    pub memberships: i64,
    pub logical_bytes: i64,
    pub receipts: i64,
}

impl Charge {
    /// One registration = 1 publication row, 2 artifact rows, 1 ACK body
    /// (charged twice: ACK body + identical permanent history body) and 2
    /// retained receipts.
    pub(super) fn registration(ack_body_bytes: usize, history_body_bytes: usize) -> Result<Self, RefStoreError> {
        Ok(Self {
            registrations: 1,
            artifacts: super::contract::ARTIFACTS_PER_PACK as i64,
            memberships: 0,
            logical_bytes: retained_logical_bytes(&[ack_body_bytes, history_body_bytes], 4)?,
            receipts: 2,
        })
    }

    /// One verified commit writes, per new pack, one `pack_memberships` row and
    /// one `pack_history` row, plus the operation terminal row and the event
    /// payload copy. Rows = `2 * packs + 2`; logical bodies = one history body
    /// per pack plus two terminal-body copies. Receipts count history rows plus
    /// the operation terminal. All arithmetic is checked (no wrapping casts).
    pub(super) fn membership(
        packs: i64,
        history_body_bytes: usize,
        terminal_body_bytes: usize,
    ) -> Result<Self, RefStoreError> {
        if packs < 0 {
            return Err(RefStoreError::InvalidIdentity("membership pack count must not be negative".into()));
        }
        let pack_count = usize::try_from(packs)
            .map_err(|_| RefStoreError::InvalidIdentity("membership pack count exceeds usize".into()))?;
        let rows = packs
            .checked_mul(2)
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| RefStoreError::InvalidIdentity("retained row count overflow".into()))?;
        let receipts =
            packs.checked_add(1).ok_or_else(|| RefStoreError::InvalidIdentity("receipt count overflow".into()))?;
        let mut bodies = Vec::with_capacity(pack_count.saturating_add(2));
        for _ in 0..pack_count {
            bodies.push(history_body_bytes);
        }
        bodies.push(terminal_body_bytes);
        bodies.push(terminal_body_bytes);
        Ok(Self {
            registrations: 0,
            artifacts: 0,
            memberships: packs,
            logical_bytes: retained_logical_bytes(&bodies, rows)?,
            receipts,
        })
    }
}

/// Bounded logical size of retained DB records: body lengths plus fixed per-row
/// overhead. Rejects overflow and an upper bound above the tenant ceiling.
pub(super) fn retained_logical_bytes(bodies: &[usize], rows: i64) -> Result<i64, RefStoreError> {
    if rows < 0 {
        return Err(RefStoreError::InvalidIdentity("retained row count must not be negative".into()));
    }
    let mut total = rows
        .checked_mul(RECEIPT_OVERHEAD_BYTES)
        .ok_or_else(|| RefStoreError::InvalidIdentity("retained row overhead overflowed".into()))?;
    for body in bodies {
        let body = i64::try_from(*body)
            .map_err(|_| RefStoreError::InvalidIdentity("retained body length exceeds i64".into()))?;
        total = total
            .checked_add(body)
            .ok_or_else(|| RefStoreError::InvalidIdentity("retained body bytes overflowed".into()))?;
    }
    if total <= 0 || total > TENANT_MAX_LOGICAL_BYTES {
        return Err(RefStoreError::InvalidIdentity("retained logical bytes exceed the fixed bound".into()));
    }
    Ok(total)
}

/// Locked counter rows (still at their pre-charge values).
#[derive(Debug)]
pub(super) struct QuotaLock {
    repository_id: Uuid,
    tenant_id: Uuid,
    tenant: [i64; 5],
    repo: [i64; 5],
}

/// Admitted next values for both rows.
#[derive(Debug)]
pub(super) struct QuotaPlan {
    repository_id: Uuid,
    tenant_id: Uuid,
    tenant_next: [i64; 5],
    repo_next: [i64; 5],
}

fn quota_refusal(detail: &'static str) -> PackCommitError {
    PackCommitError::Rejected(PackCommitRejection::new(PackCommitRejectCode::QuotaExceeded, detail))
}

fn ensure(bound: i64, current: i64, extra: i64, detail: &'static str) -> Result<i64, PackCommitError> {
    let next = current.checked_add(extra).ok_or_else(|| quota_refusal(detail))?;
    if next > bound {
        return Err(quota_refusal(detail));
    }
    Ok(next)
}

/// Creates-if-missing and locks the tenant row, then the repository row. Called
/// before the core gate is locked. No counter is changed here.
pub(super) async fn lock(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    tenant_id: Uuid,
) -> Result<QuotaLock, PackCommitError> {
    tx.execute(
        "INSERT INTO ref_store_core_pack_tenant_usage(tenant_id) VALUES($1) ON CONFLICT (tenant_id) DO NOTHING",
        &[&tenant_id],
    )
    .await
    .map_err(pg::db_error)?;
    let tenant = tx
        .query_one(
            "SELECT registration_count,artifact_count,membership_count,logical_bytes,receipt_count
             FROM ref_store_core_pack_tenant_usage WHERE tenant_id=$1 FOR UPDATE",
            &[&tenant_id],
        )
        .await
        .map_err(pg::db_error)?;
    tx.execute(
        "INSERT INTO ref_store_core_pack_repo_usage(repository_id,tenant_id) VALUES($1,$2)
         ON CONFLICT (repository_id) DO NOTHING",
        &[&repository_id, &tenant_id],
    )
    .await
    .map_err(pg::db_error)?;
    let repo = tx
        .query_one(
            "SELECT tenant_id,registration_count,artifact_count,membership_count,logical_bytes,receipt_count
             FROM ref_store_core_pack_repo_usage WHERE repository_id=$1 FOR UPDATE",
            &[&repository_id],
        )
        .await
        .map_err(pg::db_error)?;
    if repo.get::<_, Uuid>(0) != tenant_id {
        return Err(PackCommitError::Rejected(PackCommitRejection::new(
            PackCommitRejectCode::TenantMismatch,
            "repository usage belongs to another tenant",
        )));
    }
    Ok(QuotaLock {
        repository_id,
        tenant_id,
        tenant: [tenant.get(0), tenant.get(1), tenant.get(2), tenant.get(3), tenant.get(4)],
        repo: [repo.get(1), repo.get(2), repo.get(3), repo.get(4), repo.get(5)],
    })
}

/// Pure delta check against the locked values. Must run before the first
/// persistent pack/ref write.
pub(super) fn plan(locked: &QuotaLock, charge: Charge) -> Result<QuotaPlan, PackCommitError> {
    if charge.registrations < 0 || charge.artifacts < 0 || charge.memberships < 0 || charge.logical_bytes < 0 {
        return Err(PackCommitError::Invalid("usage charge must not be negative"));
    }
    let t = locked.tenant;
    let r = locked.repo;
    Ok(QuotaPlan {
        repository_id: locked.repository_id,
        tenant_id: locked.tenant_id,
        tenant_next: [
            ensure(TENANT_MAX_REGISTRATIONS, t[0], charge.registrations, "tenant registrations")?,
            ensure(TENANT_MAX_ARTIFACTS, t[1], charge.artifacts, "tenant artifacts")?,
            ensure(TENANT_MAX_MEMBERSHIPS, t[2], charge.memberships, "tenant memberships")?,
            ensure(TENANT_MAX_LOGICAL_BYTES, t[3], charge.logical_bytes, "tenant logical bytes")?,
            ensure(TENANT_MAX_RECEIPTS, t[4], charge.receipts, "tenant receipts")?,
        ],
        repo_next: [
            ensure(REPO_MAX_REGISTRATIONS, r[0], charge.registrations, "repo registrations")?,
            ensure(REPO_MAX_ARTIFACTS, r[1], charge.artifacts, "repo artifacts")?,
            ensure(REPO_MAX_MEMBERSHIPS, r[2], charge.memberships, "repo memberships")?,
            ensure(REPO_MAX_LOGICAL_BYTES, r[3], charge.logical_bytes, "repo logical bytes")?,
            ensure(REPO_MAX_RECEIPTS, r[4], charge.receipts, "repo receipts")?,
        ],
    })
}

/// Writes the admitted values in the same transaction as `lock` and `plan`.
pub(super) async fn apply(tx: &Transaction<'_>, plan: &QuotaPlan) -> Result<(), RefStoreError> {
    let t = plan.tenant_next;
    tx.execute(
        "UPDATE ref_store_core_pack_tenant_usage SET registration_count=$2,artifact_count=$3,
             membership_count=$4,logical_bytes=$5,receipt_count=$6 WHERE tenant_id=$1",
        &[&plan.tenant_id, &t[0], &t[1], &t[2], &t[3], &t[4]],
    )
    .await
    .map_err(pg::db_error)?;
    let r = plan.repo_next;
    tx.execute(
        "UPDATE ref_store_core_pack_repo_usage SET registration_count=$2,artifact_count=$3,
             membership_count=$4,logical_bytes=$5,receipt_count=$6 WHERE repository_id=$1",
        &[&plan.repository_id, &r[0], &r[1], &r[2], &r[3], &r[4]],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_bytes_count_rows_and_bodies_only() {
        assert_eq!(retained_logical_bytes(&[10, 20], 2).unwrap(), 2 * RECEIPT_OVERHEAD_BYTES + 30);
        assert!(retained_logical_bytes(&[0], 0).is_err());
        assert!(retained_logical_bytes(&[TENANT_MAX_LOGICAL_BYTES as usize], 1).is_err());
        let registration = Charge::registration(64, 64).unwrap();
        assert_eq!((registration.receipts, registration.artifacts), (2, 2));
        assert_eq!(Charge::membership(2, 64, 64).unwrap().receipts, 3);
    }

    #[test]
    fn deltas_are_checked_against_fixed_bounds() {
        assert!(ensure(REPO_MAX_RECEIPTS, REPO_MAX_RECEIPTS, 1, "repo receipts").is_err());
        assert!(ensure(10, i64::MAX, 1, "repo receipts").is_err());
        assert_eq!(ensure(10, 1, 2, "repo receipts").unwrap(), 3);
    }
}
