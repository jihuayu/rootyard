//! Permanent, no-cascade admission counters for retained pack snapshot state.
//!
//! Unlike the migration-140 A2 counters (which cascade away with the repository
//! and tenant), these two rows have **no** business foreign key at all: they
//! bound what stays retained forever — snapshot headers, captured ref rows, pack
//! bindings, pins, permanent history rows, receipts and logical bytes.
//!
//! Rules encoded in migration 143 and enforced here:
//!
//! * counters only grow — there is no refund on release, expiry, retry or
//!   repository deletion, and no TTL/reset path;
//! * `DELETE`/`TRUNCATE` of a counter row is refused unconditionally by trigger,
//!   so retained budget can never be re-granted by deleting the row;
//! * the fixed ceilings are repeated as database `CHECK`s so the SQL layer can
//!   never accept more than the contract allows.
//!
//! Lock order inside this module: tenant-scope row, then repository-scope row.
//! A caller that also locks an A2 usage row interleaves strictly as
//! `pack tenant -> A2 tenant -> pack repository -> A2 repository`, which is the
//! single global order every A5/A2 write path follows.
//!
//! Quota refusals reuse the shared [`RefStoreError::MetadataQuotaExceeded`]
//! vocabulary with a documented mapping: pack bindings are retained ref-set
//! identity (`SnapshotRefs`), one pin exists per snapshot (`Snapshots`), and a
//! permanent history row is one retained receipt (`Receipts`).
use super::contract::{
    REPO_MAX_PACK_BINDINGS, REPO_MAX_PACK_HISTORY, REPO_MAX_PACK_LOGICAL_BYTES, REPO_MAX_PACK_PINS,
    REPO_MAX_PACK_RECEIPTS, REPO_MAX_PACK_REFS, REPO_MAX_PACK_SNAPSHOTS, TENANT_MAX_PACK_BINDINGS,
    TENANT_MAX_PACK_HISTORY, TENANT_MAX_PACK_LOGICAL_BYTES, TENANT_MAX_PACK_PINS, TENANT_MAX_PACK_RECEIPTS,
    TENANT_MAX_PACK_REFS, TENANT_MAX_PACK_SNAPSHOTS,
};
use crate::ref_store::contract::{MetadataQuotaResource, MetadataQuotaScope, RefStoreError};
use crate::ref_store::pg;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

/// Permanent retained counters, read under `FOR UPDATE`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PackUsageCounts {
    pub snapshots: i64,
    pub refs: i64,
    pub bindings: i64,
    pub pins: i64,
    pub history: i64,
    pub receipts: i64,
    pub logical_bytes: i64,
}

/// One admission delta against the permanent counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PackUsageDelta {
    pub snapshots: i64,
    pub refs: i64,
    pub bindings: i64,
    pub pins: i64,
    pub history: i64,
    pub receipts: i64,
    pub logical_bytes: i64,
}

impl PackUsageDelta {
    /// A renew/release appends exactly one permanent history row plus its
    /// canonical body; the A2 receipt it duplicates is charged separately (and
    /// conservatively, at the fixed maximum body size).
    pub(crate) fn history_mutation(logical_bytes: i64) -> Self {
        Self { snapshots: 0, refs: 0, bindings: 0, pins: 0, history: 1, receipts: 1, logical_bytes }
    }
}

impl PackUsageCounts {
    fn checked_add(self, delta: PackUsageDelta) -> Self {
        Self {
            snapshots: self.snapshots.saturating_add(delta.snapshots),
            refs: self.refs.saturating_add(delta.refs),
            bindings: self.bindings.saturating_add(delta.bindings),
            pins: self.pins.saturating_add(delta.pins),
            history: self.history.saturating_add(delta.history),
            receipts: self.receipts.saturating_add(delta.receipts),
            logical_bytes: self.logical_bytes.saturating_add(delta.logical_bytes),
        }
    }
}

fn counts_from_row(row: &Row, base: usize) -> PackUsageCounts {
    PackUsageCounts {
        snapshots: row.get(base),
        refs: row.get(base + 1),
        bindings: row.get(base + 2),
        pins: row.get(base + 3),
        history: row.get(base + 4),
        receipts: row.get(base + 5),
        logical_bytes: row.get(base + 6),
    }
}

/// Lock (or create) and read the permanent *tenant* counter row.
pub(crate) async fn lock_tenant(tx: &Transaction<'_>, tenant_id: Uuid) -> Result<PackUsageCounts, RefStoreError> {
    tx.execute(
        "INSERT INTO ref_store_core_pack_snapshot_tenant_usage(tenant_id) VALUES($1)
         ON CONFLICT(tenant_id) DO NOTHING",
        &[&tenant_id],
    )
    .await
    .map_err(pg::db_error)?;
    let row = tx
        .query_one(
            "SELECT snapshot_count,snapshot_ref_count,binding_count,pin_count,history_count,receipt_count,
                    logical_bytes
             FROM ref_store_core_pack_snapshot_tenant_usage WHERE tenant_id=$1 FOR UPDATE",
            &[&tenant_id],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(counts_from_row(&row, 0))
}

/// Lock (or create) and read the permanent *repository* counter row. Always
/// taken after the tenant-scope row(s) of the same transaction.
pub(crate) async fn lock_repository(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
) -> Result<PackUsageCounts, RefStoreError> {
    tx.execute(
        "INSERT INTO ref_store_core_pack_snapshot_repo_usage(repository_id,tenant_id) VALUES($2,$1)
         ON CONFLICT(repository_id) DO NOTHING",
        &[&tenant_id, &repository_id],
    )
    .await
    .map_err(pg::db_error)?;
    let row = tx
        .query_one(
            "SELECT tenant_id,snapshot_count,snapshot_ref_count,binding_count,pin_count,history_count,
                    receipt_count,logical_bytes
             FROM ref_store_core_pack_snapshot_repo_usage WHERE repository_id=$1 FOR UPDATE",
            &[&repository_id],
        )
        .await
        .map_err(pg::db_error)?;
    // These rows outlive the business repository, so a recreated repository UUID
    // must never inherit (or re-point) another tenant's permanent counters: the
    // stored tenant is compared with the caller's tenant after the row is locked.
    // A mismatch is a typed identity conflict, never a silent rebind and never a
    // fresh zero row that would re-grant retained quota.
    let stored_tenant: Uuid = row.get(0);
    if stored_tenant != tenant_id {
        return Err(RefStoreError::IdentityConflict);
    }
    Ok(counts_from_row(&row, 1))
}

/// Admission check against the locked permanent counters. Backpressure is
/// explicit; nothing is evicted, refunded or reset to make room.
pub(crate) fn check_admission(
    tenant: PackUsageCounts,
    repository: PackUsageCounts,
    delta: PackUsageDelta,
) -> Result<(), RefStoreError> {
    let tenant = tenant.checked_add(delta);
    let repository = repository.checked_add(delta);
    let refuse = |scope: MetadataQuotaScope, resource: MetadataQuotaResource| {
        Err(RefStoreError::MetadataQuotaExceeded { scope, resource })
    };
    if repository.snapshots > REPO_MAX_PACK_SNAPSHOTS || repository.pins > REPO_MAX_PACK_PINS {
        return refuse(MetadataQuotaScope::Repository, MetadataQuotaResource::Snapshots);
    }
    if repository.refs > REPO_MAX_PACK_REFS || repository.bindings > REPO_MAX_PACK_BINDINGS {
        return refuse(MetadataQuotaScope::Repository, MetadataQuotaResource::SnapshotRefs);
    }
    if repository.history > REPO_MAX_PACK_HISTORY || repository.receipts > REPO_MAX_PACK_RECEIPTS {
        return refuse(MetadataQuotaScope::Repository, MetadataQuotaResource::Receipts);
    }
    if repository.logical_bytes > REPO_MAX_PACK_LOGICAL_BYTES {
        return refuse(MetadataQuotaScope::Repository, MetadataQuotaResource::LogicalBytes);
    }
    if tenant.snapshots > TENANT_MAX_PACK_SNAPSHOTS || tenant.pins > TENANT_MAX_PACK_PINS {
        return refuse(MetadataQuotaScope::Tenant, MetadataQuotaResource::Snapshots);
    }
    if tenant.refs > TENANT_MAX_PACK_REFS || tenant.bindings > TENANT_MAX_PACK_BINDINGS {
        return refuse(MetadataQuotaScope::Tenant, MetadataQuotaResource::SnapshotRefs);
    }
    if tenant.history > TENANT_MAX_PACK_HISTORY || tenant.receipts > TENANT_MAX_PACK_RECEIPTS {
        return refuse(MetadataQuotaScope::Tenant, MetadataQuotaResource::Receipts);
    }
    if tenant.logical_bytes > TENANT_MAX_PACK_LOGICAL_BYTES {
        return refuse(MetadataQuotaScope::Tenant, MetadataQuotaResource::LogicalBytes);
    }
    Ok(())
}

/// Charge the locked permanent counters in the same transaction as the rows they
/// cover. The database additionally refuses any decrease, delete or truncate.
pub(crate) async fn apply(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
    delta: PackUsageDelta,
) -> Result<(), RefStoreError> {
    tx.execute(
        "UPDATE ref_store_core_pack_snapshot_tenant_usage
         SET snapshot_count=snapshot_count+$2,snapshot_ref_count=snapshot_ref_count+$3,
             binding_count=binding_count+$4,pin_count=pin_count+$5,history_count=history_count+$6,
             receipt_count=receipt_count+$7,logical_bytes=logical_bytes+$8
         WHERE tenant_id=$1",
        &[
            &tenant_id,
            &delta.snapshots,
            &delta.refs,
            &delta.bindings,
            &delta.pins,
            &delta.history,
            &delta.receipts,
            &delta.logical_bytes,
        ],
    )
    .await
    .map_err(pg::db_error)?;
    tx.execute(
        "UPDATE ref_store_core_pack_snapshot_repo_usage
         SET snapshot_count=snapshot_count+$2,snapshot_ref_count=snapshot_ref_count+$3,
             binding_count=binding_count+$4,pin_count=pin_count+$5,history_count=history_count+$6,
             receipt_count=receipt_count+$7,logical_bytes=logical_bytes+$8
         WHERE repository_id=$1",
        &[
            &repository_id,
            &delta.snapshots,
            &delta.refs,
            &delta.bindings,
            &delta.pins,
            &delta.history,
            &delta.receipts,
            &delta.logical_bytes,
        ],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}
