//! Phase execution helpers (`draining`, `rekeying_db`, `revoking_legacy`, `rolling_back`)
//! for crash-recoverable repository ownership transfer.
use super::{
    purge_exec::remove_local_repo_dir,
    transfer_lease::{RollbackDecision, TransferRecord, expected_lease, load_record_with_lock, renew_transfer_lease},
    transfer_model::{CopiedRemoteObject, TransferPhase},
    transfer_remote::cleanup_rollback_remote_objects,
};
use crate::{AppState, Error, storage::read_leases};
use serde_json::json;
use std::{path::PathBuf, time::Duration};
use tokio::time::{Instant, sleep};
use uuid::Uuid;

pub(super) async fn phase_drain(state: &AppState, rec: &TransferRecord, deadline: Instant) -> anyhow::Result<()> {
    let (lease_owner, lease_epoch) = expected_lease(rec)?;
    renew_transfer_lease(&state.pool, rec.id, lease_owner, lease_epoch).await?;
    let _maint = state.storage.maintenance_exclusive(rec.repository_id).await;
    let _read = read_leases::exclusive(&state.pool, rec.repository_id, deadline).await?;

    {
        let mut client = state.pool.get().await?;
        let tx = client.transaction().await?;
        let renewed = tx
            .execute(
                "UPDATE repository_transfers \
                 SET lease_until = clock_timestamp() + interval '60 seconds', updated_at = clock_timestamp() \
                 WHERE id = $1 AND state = 'draining' AND lease_owner = $2 AND lease_epoch = $3",
                &[&rec.id, &lease_owner, &lease_epoch],
            )
            .await?;
        anyhow::ensure!(renewed == 1, "transfer lease lost during drain");
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

    let mut ticks = 0u64;
    loop {
        if ticks > 0 && ticks.is_multiple_of(20) {
            renew_transfer_lease(&state.pool, rec.id, lease_owner, lease_epoch).await?;
        }
        let client = state.pool.get().await?;
        let active_ops: i64 = client
            .query_one(
                "SELECT (SELECT count(*) FROM storage_write_admissions WHERE repository_id = $1 AND state = 'active' AND lease_until > clock_timestamp()) \
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
            let changed = client
                .execute(
                    "UPDATE repository_transfers \
                     SET state = 'copying_remote', lease_until = clock_timestamp() + interval '60 seconds', \
                         updated_at = clock_timestamp() \
                     WHERE id = $1 AND state = 'draining' AND lease_owner = $2 AND lease_epoch = $3",
                    &[&rec.id, &lease_owner, &lease_epoch],
                )
                .await?;
            anyhow::ensure!(changed == 1, "transfer lease lost transitioning draining -> copying_remote");
            return Ok(());
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "active repository operations did not drain before transfer deadline"
        );
        ticks += 1;
        sleep(Duration::from_millis(100)).await;
    }
}

pub(super) async fn phase_rekey_db(state: &AppState, rec: &TransferRecord, deadline: Instant) -> anyhow::Result<()> {
    let _maint = state.storage.maintenance_exclusive(rec.repository_id).await;
    phase_rekey_db_with_pool(&state.pool, rec, deadline).await
}

pub(super) async fn phase_rekey_db_with_pool(
    pool: &deadpool_postgres::Pool,
    rec: &TransferRecord,
    deadline: Instant,
) -> anyhow::Result<()> {
    let (lease_owner, lease_epoch) = expected_lease(rec)?;
    renew_transfer_lease(pool, rec.id, lease_owner, lease_epoch).await?;
    let _read = read_leases::exclusive(pool, rec.repository_id, deadline).await?;

    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let locked = load_record_with_lock(&tx, rec.id, true).await?;
    anyhow::ensure!(
        locked.lease_owner.as_deref() == Some(lease_owner) && locked.lease_epoch == lease_epoch,
        "transfer lease lost before rekeying_db"
    );
    if locked.phase == TransferPhase::RevokingLegacy || locked.phase == TransferPhase::Completed {
        tx.commit().await?;
        return Ok(());
    }
    anyhow::ensure!(locked.phase == TransferPhase::RekeyingDb, "unexpected transfer phase in rekeying_db");

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

    let has_linked_pando = super::transfer_pando::verify_pando_rekey_ready_tx(
        &tx,
        rec.repository_id,
        rec.from_owner_id,
        rec.to_owner_id,
        &locked.copied_objects,
    )
    .await?;

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
    if has_linked_pando {
        super::transfer_pando::clear_transfer_pando_fences_tx(&tx, rec.repository_id, rec.to_owner_id).await?;
    }

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
             VALUES ($1, $2, $3, $4, $5, 'transfer')",
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

    let changed = tx
        .execute(
            "UPDATE repository_transfers \
             SET state = 'revoking_legacy', lease_until = clock_timestamp() + interval '60 seconds', \
                 updated_at = clock_timestamp() \
             WHERE id = $1 AND state = 'rekeying_db' AND lease_owner = $2 AND lease_epoch = $3",
            &[&rec.id, &lease_owner, &lease_epoch],
        )
        .await?;
    anyhow::ensure!(changed == 1, "transfer lease lost transitioning rekeying_db -> revoking_legacy");
    tx.commit().await?;
    Ok(())
}

pub(super) async fn phase_revoke_legacy(state: &AppState, rec: &TransferRecord) -> anyhow::Result<()> {
    let (lease_owner, lease_epoch) = expected_lease(rec)?;
    let mut client = state.pool.get().await?;
    let tx = client.transaction().await?;
    let locked = load_record_with_lock(&tx, rec.id, true).await?;
    anyhow::ensure!(
        locked.lease_owner.as_deref() == Some(lease_owner) && locked.lease_epoch == lease_epoch,
        "transfer lease lost before revoking_legacy"
    );
    if locked.phase == TransferPhase::Completed {
        tx.commit().await?;
        return Ok(());
    }
    anyhow::ensure!(locked.phase == TransferPhase::RevokingLegacy, "unexpected transfer phase in revoking_legacy");
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
    let changed = tx
        .execute(
            "UPDATE repository_transfers \
             SET state = 'completed', completed_at = clock_timestamp(), updated_at = clock_timestamp() \
             WHERE id = $1 AND state = 'revoking_legacy' AND lease_owner = $2 AND lease_epoch = $3",
            &[&rec.id, &lease_owner, &lease_epoch],
        )
        .await?;
    anyhow::ensure!(changed == 1, "transfer lease lost transitioning revoking_legacy -> completed");
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
) -> anyhow::Result<RollbackDecision> {
    let (lease_owner, lease_epoch) = expected_lease(rec)?;
    let copied_to_clean: Vec<CopiedRemoteObject> = {
        let mut client = state.pool.get().await?;
        let tx = client.transaction().await?;
        let row = tx
            .query_opt(
                "SELECT t.state, t.lease_owner, t.lease_epoch, t.copied_objects, r.owner_id \
                 FROM repository_transfers t JOIN repositories r ON r.id = t.repository_id \
                 WHERE t.id = $1 FOR UPDATE OF t, r",
                &[&rec.id],
            )
            .await?
            .ok_or_else(Error::not_found)?;
        let db_state: String = row.get(0);
        let db_owner: Option<String> = row.get(1);
        let db_epoch: i64 = row.get(2);
        let db_copied: Vec<CopiedRemoteObject> = serde_json::from_value(row.get(3)).unwrap_or_default();
        let repo_owner_id: Uuid = row.get(4);
        anyhow::ensure!(
            db_owner.as_deref() == Some(lease_owner) && db_epoch == lease_epoch,
            "transfer lease lost before rollback"
        );
        if matches!(db_state.as_str(), "revoking_legacy" | "completed") || repo_owner_id == rec.to_owner_id {
            if db_state == "rekeying_db" {
                let changed = tx
                    .execute(
                        "UPDATE repository_transfers \
                         SET state = 'revoking_legacy', lease_until = clock_timestamp() + interval '60 seconds', \
                             updated_at = clock_timestamp() \
                         WHERE id = $1 AND lease_owner = $2 AND lease_epoch = $3",
                        &[&rec.id, &lease_owner, &lease_epoch],
                    )
                    .await?;
                anyhow::ensure!(changed == 1, "transfer lease lost advancing committed rekey");
            }
            tx.commit().await?;
            return Ok(RollbackDecision::DriveForward);
        }
        if db_state == "rolled_back" {
            tx.commit().await?;
            return Ok(RollbackDecision::AlreadyRolledBack);
        }
        anyhow::ensure!(db_state != "failed", "transfer already in failed state");
        let changed = tx
            .execute(
                "UPDATE repository_transfers \
                 SET state = 'rolling_back', last_error = $2, \
                     lease_until = clock_timestamp() + interval '60 seconds', \
                     updated_at = clock_timestamp() \
                 WHERE id = $1 AND lease_owner = $3 AND lease_epoch = $4 \
                   AND state NOT IN ('revoking_legacy','completed','rolled_back','failed')",
                &[&rec.id, &reason, &lease_owner, &lease_epoch],
            )
            .await?;
        anyhow::ensure!(changed == 1, "transfer lease lost entering rolling_back");
        tx.commit().await?;
        db_copied
    };
    cleanup_rollback_remote_objects(
        state,
        rec.id,
        lease_owner,
        lease_epoch,
        rec.repository_id,
        rec.to_owner_id,
        &copied_to_clean,
        deadline,
    )
    .await?;
    let client = state.pool.get().await?;
    let changed = client
        .execute(
            "UPDATE repository_transfers \
             SET state = 'rolled_back', completed_at = clock_timestamp(), updated_at = clock_timestamp() \
             WHERE id = $1 AND state = 'rolling_back' AND lease_owner = $2 AND lease_epoch = $3",
            &[&rec.id, &lease_owner, &lease_epoch],
        )
        .await?;
    anyhow::ensure!(changed == 1, "transfer lease lost finalizing rolled_back");
    Ok(RollbackDecision::RolledBack)
}
