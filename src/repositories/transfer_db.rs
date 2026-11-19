//! Crash-recoverable ownership transfer entrypoint and startup recovery loop.
use super::{
    lifecycle::{check_cas_version, request_sha256},
    lifecycle_ops::{decide_idempotent_cas, json_no_store, require_idempotency_key_valid},
    transfer_exec::{NamespaceKind, check_target_namespace_authority, http_status_for_transfer_phase},
    transfer_lease::{load_record, record_to_view, renew_transfer_lease},
    transfer_model::{TransferInput, TransferPhase, TransferStatusView, validate_transfer_input},
    transfer_phases::{phase_drain, phase_rekey_db, phase_revoke_legacy, phase_rollback},
    transfer_remote::copy_repository_remote_objects,
};
use crate::{AppState, Error, auth, db::Identity, members::models::Role, token_scopes::RepoAction};
use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::{Value, json};
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::time::Instant;
use uuid::Uuid;

pub use super::transfer_lease::load_transfer_status;

static PROCESS_LEASE_ID: OnceLock<String> = OnceLock::new();

fn process_lease_id() -> &'static str {
    PROCESS_LEASE_ID.get_or_init(|| Uuid::new_v4().to_string())
}

async fn current_repo_version(pool: &deadpool_postgres::Pool, repo_id: Uuid) -> Result<i64, Error> {
    let client = pool.get().await.map_err(Error::internal)?;
    Ok(client
        .query_one("SELECT version FROM repositories WHERE id = $1", &[&repo_id])
        .await
        .map_err(Error::internal)?
        .get(0))
}

async fn prepare_transfer(
    state: &AppState,
    actor: &Identity,
    owner: &str,
    name: &str,
    idem_key: Option<&str>,
    req_hash: &str,
    input: &TransferInput,
) -> Result<Result<(Uuid, String, i64), (StatusCode, Value)>, Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;

    let access =
        auth::authorize_repo_lifecycle(&tx, actor, owner, name, Role::Admin, RepoAction::RepoAdmin, false).await?;
    let row = tx
        .query_one(
            "SELECT r.id, r.owner_id, n.slug, r.name, r.version, r.storage_backend, r.transition_state, \
                    r.archived_at IS NOT NULL, r.deleted_at IS NOT NULL, \
                    (r.gc_owner IS NOT NULL AND r.gc_lease_until IS NOT NULL AND r.gc_lease_until > clock_timestamp()), \
                    EXISTS (SELECT 1 FROM repository_transfers t WHERE t.repository_id = r.id AND t.state NOT IN ('completed','rolled_back','failed')), \
                    EXISTS (SELECT 1 FROM pando_retention_roots pr WHERE pr.state = 'active' AND (pr.repository_id = r.id OR EXISTS (SELECT 1 FROM pando_retention_root_manifests rm WHERE rm.root_id = pr.id AND rm.repository_id = r.id))), \
                    EXISTS (SELECT 1 FROM ref_cas_projected_operations rc WHERE rc.repository_id = r.id) \
             FROM repositories r JOIN namespaces n ON n.id = r.owner_id WHERE r.id = $1 FOR UPDATE OF r",
            &[&access.repo_id],
        )
        .await
        .map_err(Error::internal)?;

    let repo_id: Uuid = row.get(0);
    let from_owner_id: Uuid = row.get(1);
    let from_owner_slug: String = row.get(2);
    let from_name: String = row.get(3);
    let actual_version: i64 = row.get(4);
    let storage_backend: String = row.get(5);
    let transition_state: String = row.get(6);
    let archived: bool = row.get(7);
    let deleted: bool = row.get(8);
    let gc_fenced: bool = row.get(9);
    let active_transfer: bool = row.get(10);
    let active_pando_root: bool = row.get(11);
    let has_refcas_projection: bool = row.get(12);

    if let Some(key) = idem_key {
        let existing = tx
            .query_opt(
                "SELECT request_sha256, response_status, response_body FROM repository_lifecycle_idempotency \
                 WHERE repository_id = $1 AND actor_id = $2 AND action = 'transfer' AND idempotency_key = $3",
                &[&repo_id, &actor.id, &key],
            )
            .await
            .map_err(Error::internal)?;
        let stored_row = existing.as_ref().and_then(|r| {
            let hash: &str = r.get(0);
            let status: i32 = r.get(1);
            let body: Value = r.get(2);
            i16::try_from(status).ok().map(|s| (hash, s, body))
        });
        let expected_v = input.expected_version.unwrap_or(0);
        let stored_ref = stored_row.as_ref().map(|(h, s, b)| (*h, *s, b));
        if let Some(replay) = decide_idempotent_cas(stored_ref, req_hash, actual_version, expected_v)? {
            auth::finish_tx(tx, actor, false).await?;
            return Ok(Err(replay));
        }
    }

    let (target_name, revoke_collaborators) = validate_transfer_input(&from_owner_slug, &from_name, input)?;
    let expected_version = input.expected_version.ok_or(Error(StatusCode::CONFLICT, "expected_version required"))?;
    check_cas_version(actual_version, expected_version)?;
    if deleted {
        return Err(Error::not_found());
    }
    if archived {
        return Err(Error(StatusCode::FORBIDDEN, "repository is archived and read-only"));
    }
    if storage_backend == "pg_refstore"
        || has_refcas_projection
        || transition_state != "stable"
        || gc_fenced
        || active_transfer
        || active_pando_root
    {
        return Err(Error(StatusCode::CONFLICT, "repository state blocks ownership transfer"));
    }

    let ns_row = tx
        .query_opt("SELECT id, kind, user_id FROM namespaces WHERE slug = $1 FOR SHARE", &[&input.new_owner])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let to_owner_id: Uuid = ns_row.get(0);
    let to_kind = if ns_row.get::<_, &str>(1) == "user" { NamespaceKind::User } else { NamespaceKind::Organization };
    let to_user_id: Option<Uuid> = ns_row.get(2);
    if to_owner_id == from_owner_id {
        return Err(Error(StatusCode::CONFLICT, "target owner matches current repository owner"));
    }

    let can_create_in_org = if to_kind == NamespaceKind::Organization {
        crate::organizations::authorize_namespace_create(&tx, actor, &input.new_owner).await.is_ok()
    } else {
        false
    };
    check_target_namespace_authority(actor.id, to_kind, to_user_id, can_create_in_org)?;

    let collision = tx
        .query_opt(
            "SELECT 1 FROM repositories WHERE owner_id = $1 AND name = $2 \
             UNION ALL \
             SELECT 1 FROM repository_aliases WHERE alias_owner_id = $1 AND alias_name = $2 AND repository_id <> $3 \
             LIMIT 1",
            &[&to_owner_id, &target_name, &repo_id],
        )
        .await
        .map_err(Error::internal)?
        .is_some();
    if collision {
        return Err(Error(StatusCode::CONFLICT, "target repository path or alias already exists"));
    }

    let transfer_id = Uuid::new_v4();
    let lease_owner = process_lease_id().to_owned();
    let lease_epoch: i64 = 1;
    tx.execute(
        "INSERT INTO repository_transfers \
         (id, repository_id, from_owner_id, to_owner_id, from_name, to_name, initiated_by, \
          revoke_collaborators, keep_alias, expected_version, state, lease_owner, lease_until, lease_epoch) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, $9, 'draining', $10, \
                 clock_timestamp() + interval '60 seconds', $11)",
        &[
            &transfer_id,
            &repo_id,
            &from_owner_id,
            &to_owner_id,
            &from_name,
            &target_name,
            &actor.id,
            &revoke_collaborators,
            &expected_version,
            &lease_owner,
            &lease_epoch,
        ],
    )
    .await
    .map_err(|err| {
        if err.as_db_error().is_some_and(|db| *db.code() == tokio_postgres::error::SqlState::UNIQUE_VIOLATION) {
            Error(StatusCode::CONFLICT, "target repository path, alias, or active transfer already exists")
        } else {
            Error::internal(err)
        }
    })?;

    crate::members::audit::record_audit_event(
        &tx,
        from_owner_id,
        repo_id,
        actor,
        "repository.transfer_started",
        "repository",
        &from_name,
        json!({"transfer_id": transfer_id, "to_owner": input.new_owner, "to_name": target_name}),
    )
    .await?;

    auth::finish_tx(tx, actor, true).await?;
    Ok(Ok((transfer_id, lease_owner, lease_epoch)))
}

async fn drive_transfer(
    state: &AppState,
    transfer_id: Uuid,
    initial_lease: Option<(String, i64)>,
) -> anyhow::Result<TransferStatusView> {
    let deadline = Instant::now() + Duration::from_secs(60);
    let (lease_owner, lease_epoch) = if let Some(lease) = initial_lease {
        lease
    } else {
        let candidate = process_lease_id().to_owned();
        let mut client = state.pool.get().await?;
        let tx = client.transaction().await?;
        let claimed = tx
            .query_opt(
                "UPDATE repository_transfers \
                 SET lease_owner = $2, lease_epoch = lease_epoch + 1, \
                     lease_until = clock_timestamp() + interval '60 seconds', updated_at = clock_timestamp() \
                 WHERE id = $1 AND state NOT IN ('completed', 'rolled_back', 'failed') \
                   AND (lease_owner IS NULL OR lease_until IS NULL OR lease_until <= clock_timestamp()) \
                 RETURNING lease_epoch",
                &[&transfer_id, &candidate],
            )
            .await?;
        if let Some(row) = claimed {
            let epoch: i64 = row.get(0);
            tx.commit().await?;
            (candidate, epoch)
        } else {
            let r = load_record(&tx, transfer_id).await?;
            tx.commit().await?;
            let version = current_repo_version(&state.pool, r.repository_id).await?;
            return Ok(record_to_view(&r, version));
        }
    };

    loop {
        let rec = {
            let mut client = state.pool.get().await?;
            let tx = client.transaction().await?;
            let r = load_record(&tx, transfer_id).await?;
            tx.commit().await?;
            r
        };
        if rec.phase.is_terminal() {
            let version = current_repo_version(&state.pool, rec.repository_id).await?;
            return Ok(record_to_view(&rec, version));
        }
        anyhow::ensure!(
            rec.lease_owner.as_deref() == Some(lease_owner.as_str()) && rec.lease_epoch == lease_epoch,
            "transfer lease lost"
        );
        renew_transfer_lease(&state.pool, transfer_id, &lease_owner, lease_epoch).await?;

        match rec.phase {
            TransferPhase::Preparing | TransferPhase::Draining => {
                if let Err(err) = phase_drain(state, &rec, deadline).await {
                    let _ = phase_rollback(state, &rec, &format!("{err:#}"), deadline).await?;
                }
            }
            TransferPhase::CopyingRemote => {
                match copy_repository_remote_objects(
                    state,
                    rec.id,
                    &lease_owner,
                    lease_epoch,
                    rec.repository_id,
                    rec.from_owner_id,
                    rec.to_owner_id,
                    deadline,
                )
                .await
                {
                    Ok(_) => {
                        let client = state.pool.get().await?;
                        let changed = client
                            .execute(
                                "UPDATE repository_transfers \
                                 SET state = 'rekeying_db', lease_until = clock_timestamp() + interval '60 seconds', \
                                     updated_at = clock_timestamp() \
                                 WHERE id = $1 AND state = 'copying_remote' \
                                   AND lease_owner = $2 AND lease_epoch = $3",
                                &[&rec.id, &lease_owner, &lease_epoch],
                            )
                            .await?;
                        anyhow::ensure!(
                            changed == 1,
                            "transfer lease lost transitioning copying_remote -> rekeying_db"
                        );
                    }
                    Err(err) => {
                        let fresh = {
                            let mut c = state.pool.get().await?;
                            let tx = c.transaction().await?;
                            let r = load_record(&tx, transfer_id).await?;
                            tx.commit().await?;
                            r
                        };
                        let _ = phase_rollback(state, &fresh, &format!("{err:#}"), deadline).await?;
                    }
                }
            }
            TransferPhase::RekeyingDb => {
                let current_owner: Uuid = state
                    .pool
                    .get()
                    .await?
                    .query_one("SELECT owner_id FROM repositories WHERE id = $1", &[&rec.repository_id])
                    .await?
                    .get(0);
                if current_owner == rec.to_owner_id {
                    let changed = state
                        .pool
                        .get()
                        .await?
                        .execute(
                            "UPDATE repository_transfers \
                             SET state = 'revoking_legacy', lease_until = clock_timestamp() + interval '60 seconds', \
                                 updated_at = clock_timestamp() \
                             WHERE id = $1 AND state = 'rekeying_db' AND lease_owner = $2 AND lease_epoch = $3",
                            &[&rec.id, &lease_owner, &lease_epoch],
                        )
                        .await?;
                    anyhow::ensure!(changed == 1, "transfer lease lost advancing committed rekeying_db");
                } else if let Err(err) = phase_rekey_db(state, &rec, deadline).await {
                    let _ = phase_rollback(state, &rec, &format!("{err:#}"), deadline).await?;
                }
            }
            TransferPhase::RevokingLegacy => phase_revoke_legacy(state, &rec).await?,
            TransferPhase::RollingBack => {
                let _ = phase_rollback(state, &rec, rec.last_error.as_deref().unwrap_or("recovery rollback"), deadline)
                    .await?;
            }
            TransferPhase::Completed | TransferPhase::RolledBack | TransferPhase::Failed => {
                let version = current_repo_version(&state.pool, rec.repository_id).await?;
                return Ok(record_to_view(&rec, version));
            }
        }
    }
}

pub async fn start_or_drive_transfer(
    state: &Arc<AppState>,
    owner: &str,
    name: &str,
    headers: HeaderMap,
    input: TransferInput,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let idem_key = require_idempotency_key_valid(&headers)?;
    let req_hash = request_sha256(&input)?;

    let (transfer_id, lease_owner, lease_epoch) =
        match prepare_transfer(state, &actor, owner, name, idem_key.as_deref(), &req_hash, &input).await? {
            Ok(claimed) => claimed,
            Err((status, body)) => return json_no_store(status, &body),
        };

    let view = drive_transfer(state, transfer_id, Some((lease_owner, lease_epoch))).await.map_err(Error::internal)?;
    let status = http_status_for_transfer_phase(view.state);
    if status.is_success()
        && let Some(key) = idem_key
    {
        let client = state.pool.get().await.map_err(Error::internal)?;
        let body_val = serde_json::to_value(&view).map_err(Error::internal)?;
        let _ = client
            .execute(
                "INSERT INTO repository_lifecycle_idempotency \
                 (repository_id, actor_id, action, idempotency_key, request_sha256, response_status, response_body) \
                 VALUES ($1, $2, 'transfer', $3, $4, $5, $6) ON CONFLICT DO NOTHING",
                &[&view.repository_id, &actor.id, &key, &req_hash, &(i32::from(status.as_u16())), &body_val],
            )
            .await;
    }
    json_no_store(status, &view)
}

pub async fn recover_transfers(state: &AppState) -> anyhow::Result<usize> {
    let lease_owner = process_lease_id().to_owned();
    let client = state.pool.get().await?;
    let rows = client
        .query(
            "UPDATE repository_transfers \
             SET lease_owner = $1, lease_epoch = lease_epoch + 1, \
                 lease_until = clock_timestamp() + interval '60 seconds', updated_at = clock_timestamp() \
             WHERE id IN ( \
                 SELECT id FROM repository_transfers \
                 WHERE state NOT IN ('completed', 'rolled_back', 'failed') \
                   AND (lease_owner IS NULL OR lease_until IS NULL OR lease_until <= clock_timestamp()) \
                 ORDER BY created_at ASC LIMIT 32 FOR UPDATE SKIP LOCKED \
             ) RETURNING id, lease_epoch",
            &[&lease_owner],
        )
        .await?;
    let mut processed = 0usize;
    for row in rows {
        let id: Uuid = row.get(0);
        let epoch: i64 = row.get(1);
        drive_transfer(state, id, Some((lease_owner.clone(), epoch))).await?;
        processed += 1;
    }
    Ok(processed)
}
