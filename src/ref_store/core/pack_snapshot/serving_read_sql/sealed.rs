//! #174 cluster-authority lock shared by the serving capture and T2.
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::core::pack_commit::PackCommitError;
use crate::ref_store::pg;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Lock and read the global restore incarnation (migration 085) `FOR SHARE`.
///
/// The capture and its T2 recheck both call this **first** in their short
/// transaction, before any repository/gate/usage lock, so the read lock only
/// ever conflicts with `src/backup/authority::fence`'s `UPDATE` of the singleton
/// and never participates in an A5 lock cycle. Exactly one valid non-nil row is
/// required: a missing, duplicated or nil incarnation is a typed database
/// refusal, never a silently empty anchor.
pub(crate) async fn lock_cluster_incarnation(tx: &Transaction<'_>) -> Result<Uuid, RefStoreError> {
    let rows = tx
        .query("SELECT incarnation FROM public.cluster_authority WHERE singleton=true FOR SHARE", &[])
        .await
        .map_err(pg::db_error)?;
    let [row] = rows.as_slice() else {
        return Err(RefStoreError::Database(format!(
            "cluster authority has {} singleton incarnation rows, expected exactly one",
            rows.len()
        )));
    };
    let incarnation: Uuid =
        row.try_get(0).map_err(|_| RefStoreError::Database("cluster authority row has no uuid incarnation".into()))?;
    if incarnation.is_nil() {
        return Err(RefStoreError::Database("cluster authority incarnation is nil".into()));
    }
    Ok(incarnation)
}

pub(crate) fn pack_error(what: &'static str) -> impl Fn(PackCommitError) -> RefStoreError {
    move |_| RefStoreError::Database(format!("stored serving read pack {what} is invalid"))
}
