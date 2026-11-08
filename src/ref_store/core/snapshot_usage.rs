//! Retained admission-usage SQL for the metadata snapshot adapter (A2).
//!
//! Usage is charged for *all retained* metadata — snapshot headers, snapshot ref
//! rows, logical metadata bytes, pin rows and successful mutation receipts —
//! at both repository and tenant scope, including expired and released
//! history. Nothing is refunded by expiry/release and no identity is deleted to
//! free room, so a full budget stays full until a later reviewed archival
//! protocol exists.
//!
//! Lock order inside this module: tenant usage row, then repository usage row.
//! The adapter calls it before the repository/gate rows and never after the
//! gate, so no path can build the reverse order.
use super::super::contract::RefStoreError;
use super::super::pg;
use super::snapshot_contract::{
    REPO_MAX_LOGICAL_BYTES, REPO_MAX_RECEIPTS, REPO_MAX_SNAPSHOT_REFS, REPO_MAX_SNAPSHOTS, TENANT_MAX_LOGICAL_BYTES,
    TENANT_MAX_RECEIPTS, TENANT_MAX_SNAPSHOT_REFS, TENANT_MAX_SNAPSHOTS,
};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

/// Retained admission counters, read under `FOR UPDATE`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct UsageCounts {
    pub snapshots: i64,
    pub snapshot_refs: i64,
    pub logical_bytes: i64,
    pub receipts: i64,
}

/// One create/renew/release admission delta.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct UsageDelta {
    pub snapshots: i64,
    pub snapshot_refs: i64,
    pub logical_bytes: i64,
    pub receipts: i64,
}

impl UsageDelta {
    pub(super) fn receipt(bytes: i64) -> Self {
        Self { snapshots: 0, snapshot_refs: 0, logical_bytes: bytes, receipts: 1 }
    }
}

impl UsageCounts {
    fn checked_add(self, delta: UsageDelta) -> Self {
        Self {
            snapshots: self.snapshots.saturating_add(delta.snapshots),
            snapshot_refs: self.snapshot_refs.saturating_add(delta.snapshot_refs),
            logical_bytes: self.logical_bytes.saturating_add(delta.logical_bytes),
            receipts: self.receipts.saturating_add(delta.receipts),
        }
    }
}

fn usage_from_row(row: &Row) -> UsageCounts {
    UsageCounts { snapshots: row.get(0), snapshot_refs: row.get(1), logical_bytes: row.get(2), receipts: row.get(3) }
}

/// Map a foreign-key violation on the usage rows to `RepositoryNotFound`
/// instead of a generic database error. Nothing is charged: the statement (and
/// the whole owned transaction) rolls back.
fn map_usage_error(error: tokio_postgres::Error) -> RefStoreError {
    match error.code() {
        Some(code) if *code == tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION => {
            RefStoreError::RepositoryNotFound
        }
        _ => pg::db_error(error),
    }
}

/// Lock (or create) the retained tenant usage row and then the repository usage
/// row, and return both counters. This is the quota prefix of the fixed lock
/// order: it is always taken before the repository/gate rows and never after.
/// Lock (or create) and read the retained *tenant* usage row.
///
/// Split out from the repository row so a caller that also owns a permanent
/// pack-snapshot counter row can follow one global order: every tenant-scope
/// row first, then every repository-scope row. The pair helper below keeps the
/// A2-only call sites unchanged.
pub(super) async fn lock_tenant_usage(tx: &Transaction<'_>, tenant_id: Uuid) -> Result<UsageCounts, RefStoreError> {
    tx.execute(
        "INSERT INTO ref_store_core_tenant_usage(tenant_id) VALUES($1) ON CONFLICT(tenant_id) DO NOTHING",
        &[&tenant_id],
    )
    .await
    .map_err(map_usage_error)?;
    let tenant = tx
        .query_one(
            "SELECT snapshot_count,snapshot_ref_count,logical_bytes,receipt_count
             FROM ref_store_core_tenant_usage WHERE tenant_id=$1 FOR UPDATE",
            &[&tenant_id],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(usage_from_row(&tenant))
}

/// Lock (or create) and read the retained *repository* usage row. It is always
/// taken after the tenant-scope row(s) of the same transaction.
pub(super) async fn lock_repository_usage(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
) -> Result<UsageCounts, RefStoreError> {
    tx.execute(
        "INSERT INTO ref_store_core_repo_usage(repository_id,tenant_id) VALUES($2,$1) ON CONFLICT(repository_id) DO NOTHING",
        &[&tenant_id, &repository_id],
    )
    .await
    .map_err(map_usage_error)?;
    let repository = tx
        .query_one(
            "SELECT snapshot_count,snapshot_ref_count,logical_bytes,receipt_count
             FROM ref_store_core_repo_usage WHERE repository_id=$1 FOR UPDATE",
            &[&repository_id],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(usage_from_row(&repository))
}

/// Lock the tenant row and then the repository row and return both counters.
/// Used by the A2-only paths that hold no permanent pack-snapshot counter.
pub(super) async fn lock_usage(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
) -> Result<(UsageCounts, UsageCounts), RefStoreError> {
    let tenant = lock_tenant_usage(tx, tenant_id).await?;
    let repository = lock_repository_usage(tx, tenant_id, repository_id).await?;
    Ok((tenant, repository))
}

/// Retained admission check against locked counters. Backpressure is explicit;
/// nothing is evicted or refunded to make room.
pub(super) fn check_admission(
    tenant: UsageCounts,
    repository: UsageCounts,
    delta: UsageDelta,
) -> Result<(), RefStoreError> {
    let tenant = tenant.checked_add(delta);
    let repository = repository.checked_add(delta);
    let refuse = |scope, resource| Err(RefStoreError::MetadataQuotaExceeded { scope, resource });
    use super::super::contract::{MetadataQuotaResource as Resource, MetadataQuotaScope as Scope};
    if repository.snapshots > REPO_MAX_SNAPSHOTS {
        return refuse(Scope::Repository, Resource::Snapshots);
    }
    if repository.snapshot_refs > REPO_MAX_SNAPSHOT_REFS {
        return refuse(Scope::Repository, Resource::SnapshotRefs);
    }
    if repository.logical_bytes > REPO_MAX_LOGICAL_BYTES {
        return refuse(Scope::Repository, Resource::LogicalBytes);
    }
    if repository.receipts > REPO_MAX_RECEIPTS {
        return refuse(Scope::Repository, Resource::Receipts);
    }
    if tenant.snapshots > TENANT_MAX_SNAPSHOTS {
        return refuse(Scope::Tenant, Resource::Snapshots);
    }
    if tenant.snapshot_refs > TENANT_MAX_SNAPSHOT_REFS {
        return refuse(Scope::Tenant, Resource::SnapshotRefs);
    }
    if tenant.logical_bytes > TENANT_MAX_LOGICAL_BYTES {
        return refuse(Scope::Tenant, Resource::LogicalBytes);
    }
    if tenant.receipts > TENANT_MAX_RECEIPTS {
        return refuse(Scope::Tenant, Resource::Receipts);
    }
    Ok(())
}

/// Charge the locked usage rows. Counters only grow: expiry and release never
/// refund, and old identities are never deleted to free quota. The migration
/// additionally rejects any direct counter decrease and any direct usage-row
/// delete while the parent repository/tenant exists.
pub(super) async fn apply_usage(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
    delta: UsageDelta,
) -> Result<(), RefStoreError> {
    tx.execute(
        "UPDATE ref_store_core_tenant_usage
         SET snapshot_count=snapshot_count+$2,snapshot_ref_count=snapshot_ref_count+$3,
             logical_bytes=logical_bytes+$4,receipt_count=receipt_count+$5
         WHERE tenant_id=$1",
        &[&tenant_id, &delta.snapshots, &delta.snapshot_refs, &delta.logical_bytes, &delta.receipts],
    )
    .await
    .map_err(pg::db_error)?;
    tx.execute(
        "UPDATE ref_store_core_repo_usage
         SET snapshot_count=snapshot_count+$2,snapshot_ref_count=snapshot_ref_count+$3,
             logical_bytes=logical_bytes+$4,receipt_count=receipt_count+$5
         WHERE repository_id=$1",
        &[&repository_id, &delta.snapshots, &delta.snapshot_refs, &delta.logical_bytes, &delta.receipts],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::{MetadataQuotaResource, MetadataQuotaScope};

    fn counts(snapshots: i64, snapshot_refs: i64, logical_bytes: i64, receipts: i64) -> UsageCounts {
        UsageCounts { snapshots, snapshot_refs, logical_bytes, receipts }
    }

    fn delta(snapshots: i64, snapshot_refs: i64, logical_bytes: i64, receipts: i64) -> UsageDelta {
        UsageDelta { snapshots, snapshot_refs, logical_bytes, receipts }
    }

    #[test]
    fn repository_snapshot_bound_is_exact() {
        let full = UsageCounts { snapshots: REPO_MAX_SNAPSHOTS - 1, ..Default::default() };
        assert!(check_admission(Default::default(), full, delta(1, 0, 1, 1)).is_ok());
        let refused = check_admission(Default::default(), counts(REPO_MAX_SNAPSHOTS, 0, 0, 0), delta(1, 0, 1, 1));
        assert!(matches!(
            refused,
            Err(RefStoreError::MetadataQuotaExceeded {
                scope: MetadataQuotaScope::Repository,
                resource: MetadataQuotaResource::Snapshots
            })
        ));
    }

    #[test]
    fn tenant_and_receipt_bounds_are_exact_and_never_active_only() {
        assert!(
            check_admission(counts(TENANT_MAX_SNAPSHOTS - 1, 0, 0, 0), Default::default(), delta(1, 0, 1, 1)).is_ok()
        );
        assert!(matches!(
            check_admission(counts(TENANT_MAX_SNAPSHOTS, 0, 0, 0), Default::default(), delta(1, 0, 1, 1)),
            Err(RefStoreError::MetadataQuotaExceeded {
                scope: MetadataQuotaScope::Tenant,
                resource: MetadataQuotaResource::Snapshots
            })
        ));
        assert!(matches!(
            check_admission(Default::default(), counts(0, 0, 0, REPO_MAX_RECEIPTS), UsageDelta::receipt(1)),
            Err(RefStoreError::MetadataQuotaExceeded {
                scope: MetadataQuotaScope::Repository,
                resource: MetadataQuotaResource::Receipts
            })
        ));
        assert!(matches!(
            check_admission(counts(0, 0, 0, TENANT_MAX_RECEIPTS), Default::default(), UsageDelta::receipt(1)),
            Err(RefStoreError::MetadataQuotaExceeded {
                scope: MetadataQuotaScope::Tenant,
                resource: MetadataQuotaResource::Receipts
            })
        ));
    }

    #[test]
    fn logical_byte_bounds_are_exact_at_both_scopes() {
        let repo_full = UsageCounts { logical_bytes: REPO_MAX_LOGICAL_BYTES - 1, ..Default::default() };
        assert!(check_admission(Default::default(), repo_full, delta(0, 0, 1, 0)).is_ok());
        assert!(matches!(
            check_admission(Default::default(), counts(0, 0, REPO_MAX_LOGICAL_BYTES, 0), delta(0, 0, 1, 0)),
            Err(RefStoreError::MetadataQuotaExceeded {
                scope: MetadataQuotaScope::Repository,
                resource: MetadataQuotaResource::LogicalBytes
            })
        ));
        assert!(matches!(
            check_admission(counts(0, 0, TENANT_MAX_LOGICAL_BYTES, 0), Default::default(), delta(0, 0, 1, 0)),
            Err(RefStoreError::MetadataQuotaExceeded {
                scope: MetadataQuotaScope::Tenant,
                resource: MetadataQuotaResource::LogicalBytes
            })
        ));
        let full_refs = UsageCounts { snapshot_refs: REPO_MAX_SNAPSHOT_REFS, ..Default::default() };
        assert!(matches!(
            check_admission(Default::default(), full_refs, delta(0, 1, 0, 0)),
            Err(RefStoreError::MetadataQuotaExceeded {
                scope: MetadataQuotaScope::Repository,
                resource: MetadataQuotaResource::SnapshotRefs
            })
        ));
    }
}
