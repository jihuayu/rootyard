//! Transfer record persistence and epoch-fenced lease helpers (#85).
use super::transfer_model::{CopiedRemoteObject, TransferPhase, TransferStatusView};
use crate::Error;
use deadpool_postgres::{Pool, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RollbackDecision {
    DriveForward,
    AlreadyRolledBack,
    RolledBack,
}

#[derive(Clone)]
pub(super) struct TransferRecord {
    pub(super) id: Uuid,
    pub(super) repository_id: Uuid,
    pub(super) from_owner_id: Uuid,
    pub(super) to_owner_id: Uuid,
    pub(super) from_owner: String,
    pub(super) to_owner: String,
    pub(super) from_name: String,
    pub(super) to_name: String,
    pub(super) initiated_by: Uuid,
    pub(super) revoke_collaborators: bool,
    pub(super) keep_alias: bool,
    pub(super) expected_version: i64,
    pub(super) phase: TransferPhase,
    pub(super) copied_objects: Vec<CopiedRemoteObject>,
    pub(super) last_error: Option<String>,
    pub(super) lease_owner: Option<String>,
    pub(super) lease_epoch: i64,
}

pub(super) fn parse_phase(s: &str) -> TransferPhase {
    TransferPhase::parse(s).unwrap_or(TransferPhase::Failed)
}

pub(super) fn record_to_view(r: &TransferRecord, version: i64) -> TransferStatusView {
    TransferStatusView {
        transfer_id: r.id,
        repository_id: r.repository_id,
        from_owner_id: r.from_owner_id,
        to_owner_id: r.to_owner_id,
        from_owner: r.from_owner.clone(),
        to_owner: r.to_owner.clone(),
        old_name: r.from_name.clone(),
        new_name: r.to_name.clone(),
        state: r.phase,
        revoke_collaborators: r.revoke_collaborators,
        copied_object_count: r.copied_objects.len(),
        version,
        last_error: r.last_error.clone(),
    }
}

pub(super) async fn load_record_with_lock(
    tx: &Transaction<'_>,
    transfer_id: Uuid,
    for_update: bool,
) -> Result<TransferRecord, Error> {
    let lock_clause = if for_update { " FOR UPDATE OF t" } else { "" };
    let sql = format!(
        "SELECT t.id, t.repository_id, t.from_owner_id, t.to_owner_id, \
                fn.slug, tn.slug, t.from_name, t.to_name, t.initiated_by, \
                t.revoke_collaborators, t.keep_alias, t.expected_version, \
                t.state, t.copied_objects, t.last_error, t.lease_owner, t.lease_epoch \
         FROM repository_transfers t \
         JOIN namespaces fn ON fn.id = t.from_owner_id \
         JOIN namespaces tn ON tn.id = t.to_owner_id \
         WHERE t.id = $1{lock_clause}"
    );
    let row = tx.query_opt(&sql, &[&transfer_id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let copied: Vec<CopiedRemoteObject> = serde_json::from_value(row.get(13)).unwrap_or_default();
    Ok(TransferRecord {
        id: row.get(0),
        repository_id: row.get(1),
        from_owner_id: row.get(2),
        to_owner_id: row.get(3),
        from_owner: row.get(4),
        to_owner: row.get(5),
        from_name: row.get(6),
        to_name: row.get(7),
        initiated_by: row.get(8),
        revoke_collaborators: row.get(9),
        keep_alias: row.get(10),
        expected_version: row.get(11),
        phase: parse_phase(row.get(12)),
        copied_objects: copied,
        last_error: row.get(14),
        lease_owner: row.get(15),
        lease_epoch: row.get(16),
    })
}

pub(super) async fn load_record(tx: &Transaction<'_>, transfer_id: Uuid) -> Result<TransferRecord, Error> {
    load_record_with_lock(tx, transfer_id, false).await
}

pub async fn load_transfer_status(tx: &Transaction<'_>, repo_id: Uuid) -> Result<Option<TransferStatusView>, Error> {
    let Some(row) = tx
        .query_opt(
            "SELECT t.id, r.version FROM repository_transfers t \
             JOIN repositories r ON r.id = t.repository_id \
             WHERE t.repository_id = $1 ORDER BY t.created_at DESC LIMIT 1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
    else {
        return Ok(None);
    };
    let transfer_id: Uuid = row.get(0);
    let version: i64 = row.get(1);
    let rec = load_record(tx, transfer_id).await?;
    Ok(Some(record_to_view(&rec, version)))
}

pub(super) fn expected_lease(rec: &TransferRecord) -> anyhow::Result<(&str, i64)> {
    let owner = rec.lease_owner.as_deref().ok_or_else(|| anyhow::anyhow!("transfer lease owner missing"))?;
    anyhow::ensure!(rec.lease_epoch > 0, "transfer lease epoch invalid");
    Ok((owner, rec.lease_epoch))
}

pub(super) async fn renew_transfer_lease(
    pool: &Pool,
    transfer_id: Uuid,
    lease_owner: &str,
    lease_epoch: i64,
) -> anyhow::Result<()> {
    let client = pool.get().await?;
    let changed = client
        .execute(
            "UPDATE repository_transfers \
             SET lease_until = clock_timestamp() + interval '60 seconds', updated_at = clock_timestamp() \
             WHERE id = $1 AND lease_owner = $2 AND lease_epoch = $3 \
               AND state NOT IN ('completed', 'rolled_back', 'failed')",
            &[&transfer_id, &lease_owner, &lease_epoch],
        )
        .await?;
    anyhow::ensure!(changed == 1, "transfer lease lost");
    Ok(())
}
