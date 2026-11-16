//! Phase execution helpers (`draining`, `rekeying_db`, `revoking_legacy`, `rolling_back`)
//! for crash-recoverable repository ownership transfer.
use super::{
    purge_exec::remove_local_repo_dir,
    transfer_model::{CopiedRemoteObject, TransferPhase, TransferStatusView},
    transfer_remote::cleanup_rollback_remote_objects,
};
use crate::{AppState, Error, storage::read_leases};
use deadpool_postgres::Transaction;
use serde_json::json;
use std::{path::PathBuf, time::Duration};
use tokio::time::{Instant, sleep};
use uuid::Uuid;

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
}

pub(super) fn parse_phase(s: &str) -> TransferPhase {
    match s {
        "preparing" => TransferPhase::Preparing,
        "draining" => TransferPhase::Draining,
        "copying_remote" => TransferPhase::CopyingRemote,
        "rekeying_db" => TransferPhase::RekeyingDb,
        "revoking_legacy" => TransferPhase::RevokingLegacy,
        "completed" => TransferPhase::Completed,
        "rolling_back" => TransferPhase::RollingBack,
        "rolled_back" => TransferPhase::RolledBack,
        _ => TransferPhase::Failed,
    }
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

pub(super) async fn load_record(tx: &Transaction<'_>, transfer_id: Uuid) -> Result<TransferRecord, Error> {
    let row = tx
        .query_opt(
            "SELECT t.id, t.repository_id, t.from_owner_id, t.to_owner_id, \
                    fn.slug, tn.slug, t.from_name, t.to_name, t.initiated_by, \
                    t.revoke_collaborators, t.keep_alias, t.expected_version, \
                    t.state, t.copied_objects, t.last_error \
             FROM repository_transfers t \
             JOIN namespaces fn ON fn.id = t.from_owner_id \
             JOIN namespaces tn ON tn.id = t.to_owner_id \
             WHERE t.id = $1",
            &[&transfer_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
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
    })
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

pub(super) async fn phase_drain(state: &AppState, rec: &TransferRecord, deadline: Instant) -> anyhow::Result<()> {
    let _maint = state.storage.maintenance_exclusive(rec.repository_id).await;
    let _read = read_leases::exclusive(&state.pool, rec.repository_id, deadline).await?;

    {
        let mut client = state.pool.get().await?;
        let tx = client.transaction().await?;
        tx.execute(
            "UPDATE ci_checkout_jobs SET revoked = true WHERE repository_id = $1 AND NOT revoked",
            &[&rec.repository_id],
        )
        .await?;
        tx.execute("DELETE FROM ci_integration_checkout_jobs WHERE repository_id = $1", &[&rec.repository_id]).await?;
        tx.execute("DELETE FROM ci_checkout_delegations WHERE repository_id = $1", &[&rec.repository_id]).await?;
        tx.execute("DELETE FROM ci_integration_source_grants WHERE repository_id = $1", &[&rec.repository_id]).await?;
        tx.execute(
            "UPDATE ci_service_principals SET active = false WHERE repository_id = $1 AND active",
            &[&rec.repository_id],
        )
        .await?;
        tx.commit().await?;
    }

    for _ in 0..10 {
        let client = state.pool.get().await?;
        let active_ops: i64 = client
            .query_one(
                "SELECT (SELECT count(*) FROM storage_write_admissions WHERE repository_id = $1 AND state = 'active') \
                      + (SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id = $1 AND state IN ('queued','running')) \
                      + (SELECT count(*) FROM artifact_holds WHERE repository_id = $1 AND state = 'active') \
                      + (SELECT count(*) FROM ci_runs WHERE repository_id = $1 AND state IN ('queued','leased')) \
                      + (SELECT count(*) FROM pando_publication_fences f JOIN pando_pack_manifests m ON m.id = f.manifest_id \
                         WHERE m.repository_id = $1 AND f.lease_until > clock_timestamp())",
                &[&rec.repository_id],
            )
            .await?
            .get(0);
        if active_ops == 0 {
            client
                .execute(
                    "UPDATE repository_transfers SET state = 'copying_remote', updated_at = clock_timestamp() \
                     WHERE id = $1 AND state = 'draining'",
                    &[&rec.id],
                )
                .await?;
            return Ok(());
        }
        anyhow::ensure!(Instant::now() < deadline, "timed out draining active repository operations");
        sleep(Duration::from_millis(150)).await;
    }
    anyhow::bail!("active repository operations did not drain before transfer deadline")
}

pub(super) async fn phase_rekey_db(state: &AppState, rec: &TransferRecord, deadline: Instant) -> anyhow::Result<()> {
    let _maint = state.storage.maintenance_exclusive(rec.repository_id).await;
    let _read = read_leases::exclusive(&state.pool, rec.repository_id, deadline).await?;

    let mut client = state.pool.get().await?;
    let tx = client.transaction().await?;
    let locked = load_record(&tx, rec.id).await?;
    if locked.phase == TransferPhase::RevokingLegacy || locked.phase == TransferPhase::Completed {
        tx.commit().await?;
        return Ok(());
    }

    let r = tx
        .query_one(
            "SELECT owner_id, version, deleted_at IS NOT NULL, archived_at IS NOT NULL, transition_state \
             FROM repositories WHERE id = $1 FOR UPDATE",
            &[&rec.repository_id],
        )
        .await?;
    let current_owner: Uuid = r.get(0);
    let current_version: i64 = r.get(1);
    anyhow::ensure!(current_owner == rec.from_owner_id, "repository owner changed unexpectedly before rekeying_db");
    anyhow::ensure!(
        current_version == rec.expected_version,
        "repository version changed concurrently before rekeying_db"
    );
    anyhow::ensure!(
        !r.get::<_, bool>(2) && !r.get::<_, bool>(3) && r.get::<_, &str>(4) == "stable",
        "repository state incompatible with rekey"
    );

    tx.execute("DELETE FROM repository_team_members WHERE repository_id = $1", &[&rec.repository_id]).await?;
    tx.execute("DELETE FROM repository_teams WHERE repository_id = $1", &[&rec.repository_id]).await?;
    tx.execute(
        "DELETE FROM repository_collaborators WHERE repository_id = $1 AND user_id = $2",
        &[&rec.repository_id, &rec.to_owner_id],
    )
    .await?;
    if rec.revoke_collaborators {
        tx.execute("DELETE FROM repository_collaborators WHERE repository_id = $1", &[&rec.repository_id]).await?;
        tx.execute("DELETE FROM token_repository_scopes WHERE repository_id = $1", &[&rec.repository_id]).await?;
    } else {
        tx.execute(
            "DELETE FROM token_repository_scopes s USING tokens t \
             WHERE s.token_id = t.id AND s.repository_id = $1 AND t.user_id <> $2",
            &[&rec.repository_id, &rec.initiated_by],
        )
        .await?;
    }

    tx.execute(
        "DELETE FROM repository_aliases WHERE alias_owner_id = $1 AND alias_name = $2 AND repository_id = $3",
        &[&rec.to_owner_id, &rec.to_name, &rec.repository_id],
    )
    .await?;
    tx.execute(
        "UPDATE repositories SET owner_id = $2, name = $3, version = version + 1 WHERE id = $1",
        &[&rec.repository_id, &rec.to_owner_id, &rec.to_name],
    )
    .await?;

    tx.execute(
        "UPDATE pando_pack_manifests SET manifest = jsonb_set(manifest, '{tenant_id}', to_jsonb($2::text)) \
         WHERE repository_id = $1 AND tenant_id = $2",
        &[&rec.repository_id, &rec.to_owner_id],
    )
    .await?;

    for item in &locked.copied_objects {
        if item.kind == "workspace_manifest"
            && let (Some(old_digest), Some(new_digest)) =
                (item.from_key.rsplit('/').next(), item.to_key.rsplit('/').next())
        {
            tx.execute(
                "UPDATE workspace_checkpoints SET manifest_digest = $3 WHERE repository_id = $1 AND manifest_digest = $2",
                &[&rec.repository_id, &old_digest, &new_digest],
            )
            .await?;
        }
    }
    tx.execute(
        "UPDATE workspace_remote_staging_objects s SET tenant_id = $2 FROM workspace_checkpoints c \
         WHERE s.checkpoint_id = c.id AND c.repository_id = $1 AND s.tenant_id <> $2",
        &[&rec.repository_id, &rec.to_owner_id],
    )
    .await?;
    tx.execute(
        "UPDATE workspaces SET owner_slug = $2, repository_name = $3 WHERE repository_id = $1",
        &[&rec.repository_id, &rec.to_owner, &rec.to_name],
    )
    .await?;
    tx.execute(
        "UPDATE workspace_namespace_mounts SET owner_slug = $2, repository_name = $3 WHERE repository_id = $1",
        &[&rec.repository_id, &rec.to_owner, &rec.to_name],
    )
    .await?;
    tx.execute(
        "UPDATE workspace_changeset_steps SET owner_slug = $2, repository_name = $3 WHERE repository_id = $1",
        &[&rec.repository_id, &rec.to_owner, &rec.to_name],
    )
    .await?;

    if rec.keep_alias {
        let alias_id = Uuid::new_v4();
        tx.execute(
            "INSERT INTO repository_aliases (id, alias_owner_id, alias_name, repository_id, created_by, reason) \
             VALUES ($1, $2, $3, $4, $5, 'transfer') ON CONFLICT (alias_owner_id, alias_name) DO NOTHING",
            &[&alias_id, &rec.from_owner_id, &rec.from_name, &rec.repository_id, &rec.initiated_by],
        )
        .await?;
    }

    let actor_username: String =
        tx.query_one("SELECT username FROM users WHERE id = $1", &[&rec.initiated_by]).await?.get(0);
    let details = json!({"transfer_id": rec.id, "from_owner": rec.from_owner, "to_owner": rec.to_owner, "from_name": rec.from_name, "to_name": rec.to_name});
    crate::members::audit::record_audit_event_for_actor(
        &tx,
        rec.to_owner_id,
        rec.repository_id,
        rec.initiated_by,
        &actor_username,
        "repository.transferred",
        "repository",
        &rec.to_name,
        details.clone(),
    )
    .await?;
    for ns in [rec.from_owner_id, rec.to_owner_id] {
        if tx.query_opt("SELECT 1 FROM organizations WHERE id = $1", &[&ns]).await?.is_some() {
            crate::organizations::handlers::audit(
                &tx,
                ns,
                rec.initiated_by,
                "repository.transferred",
                &format!("{}/{}", rec.to_owner, rec.to_name),
                details.clone(),
            )
            .await?;
        }
    }

    tx.execute(
        "UPDATE repository_transfers SET state = 'revoking_legacy', updated_at = clock_timestamp() WHERE id = $1",
        &[&rec.id],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(super) async fn phase_revoke_legacy(state: &AppState, rec: &TransferRecord) -> anyhow::Result<()> {
    let mut client = state.pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute("DELETE FROM repository_team_members WHERE repository_id = $1", &[&rec.repository_id]).await?;
    tx.execute("DELETE FROM repository_teams WHERE repository_id = $1", &[&rec.repository_id]).await?;
    tx.execute(
        "UPDATE ci_checkout_jobs SET revoked = true WHERE repository_id = $1 AND NOT revoked",
        &[&rec.repository_id],
    )
    .await?;
    tx.execute(
        "UPDATE ci_service_principals SET active = false WHERE repository_id = $1 AND active",
        &[&rec.repository_id],
    )
    .await?;
    if rec.revoke_collaborators {
        tx.execute("DELETE FROM repository_collaborators WHERE repository_id = $1", &[&rec.repository_id]).await?;
        tx.execute("DELETE FROM token_repository_scopes WHERE repository_id = $1", &[&rec.repository_id]).await?;
    }
    let owner_id: Uuid =
        tx.query_one("SELECT owner_id FROM repositories WHERE id = $1", &[&rec.repository_id]).await?.get(0);
    anyhow::ensure!(owner_id == rec.to_owner_id, "single-owner invariant violated in revoking_legacy");
    tx.execute(
        "UPDATE repository_transfers SET state = 'completed', completed_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = $1",
        &[&rec.id],
    )
    .await?;
    tx.commit().await?;

    let ci_dir: PathBuf = state.storage.root.join("ci-pins").join(rec.repository_id.to_string());
    if ci_dir.exists() {
        let _ = remove_local_repo_dir(&state.storage.root, &ci_dir).await;
    }
    Ok(())
}

pub(super) async fn phase_rollback(
    state: &AppState,
    rec: &TransferRecord,
    reason: &str,
    deadline: Instant,
) -> anyhow::Result<()> {
    {
        let client = state.pool.get().await?;
        client
            .execute(
                "UPDATE repository_transfers SET state = 'rolling_back', last_error = $2, updated_at = clock_timestamp() \
                 WHERE id = $1 AND state NOT IN ('revoking_legacy','completed','rolled_back')",
                &[&rec.id, &reason],
            )
            .await?;
    }
    cleanup_rollback_remote_objects(state, rec.repository_id, rec.to_owner_id, &rec.copied_objects, deadline).await?;
    let client = state.pool.get().await?;
    client
        .execute(
            "UPDATE repository_transfers SET state = 'rolled_back', completed_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = $1",
            &[&rec.id],
        )
        .await?;
    Ok(())
}
