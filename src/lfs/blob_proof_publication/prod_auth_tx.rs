//! Single-transaction post-auth authorization checks for durable LFS publication (`Refs #145`).

use deadpool_postgres::Transaction;
use uuid::Uuid;

use crate::token_scopes::RepoAction;

pub(super) use super::authz_tx::resolve_authoritative_repo_access_in_tx;
use super::pg_store::{PgLfsBlobStore, pg_err};
use super::types::{CommittedLfsBlobRecord, LfsBlobError, LfsProofRejectCode, StoredBlobLocatorRef};

#[derive(Clone)]
pub struct ProdCommitAuthCheck {
    pub actor: crate::db::Identity,
    pub owner_slug: String,
    pub repo_name: String,
    pub expected_generation: Option<i64>,
}

#[derive(Clone, Copy, Debug)]
pub struct PushCommitAuthCheck {
    pub actor_id: Uuid,
    pub token_id: Option<Uuid>,
    pub expected_generation: Option<i64>,
}

/// Stable PostgreSQL session-advisory-lock key pair for one upload attempt.
pub fn upload_attempt_advisory_keys(attempt_id: Uuid) -> (i32, i32) {
    let hi64 = ((attempt_id.as_u128() >> 64) as u64) ^ 0x5334_4c46_535f_5550u64;
    ((hi64 >> 32) as i32, (hi64 & 0xffff_ffff) as i32)
}

pub(super) fn map_app_auth_err(err: crate::Error) -> LfsBlobError {
    match err.0 {
        axum::http::StatusCode::UNAUTHORIZED => LfsBlobError::new(LfsProofRejectCode::Unauthenticated, err.1),
        axum::http::StatusCode::FORBIDDEN | axum::http::StatusCode::NOT_FOUND => {
            LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, err.1)
        }
        axum::http::StatusCode::CONFLICT => LfsBlobError::new(LfsProofRejectCode::AttestationEquivocation, err.1),
        _ => LfsBlobError::new(LfsProofRejectCode::PgDatabase, err.1),
    }
}

/// Verifies live token liveness, repository identity/generation, and relational write RBAC inside `tx`.
pub(super) async fn verify_commit_write_authority_in_tx(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    expected_tenant_id: Uuid,
    uploader_actor_id: Uuid,
    commit_auth: Option<&ProdCommitAuthCheck>,
) -> Result<(), LfsBlobError> {
    if let Some(ca) = commit_auth {
        if let Some(exp_gen) = ca.expected_generation {
            crate::auth::authorize_publication_window(tx, &ca.actor, repository_id, exp_gen)
                .await
                .map_err(map_app_auth_err)?;
        }
        let reauth = crate::auth::authorize_repo_with_role(
            tx,
            &ca.actor,
            &ca.owner_slug,
            &ca.repo_name,
            crate::auth::Role::Write,
            RepoAction::ContentsWrite,
        )
        .await
        .map_err(map_app_auth_err)?;
        if reauth.repo_id != repository_id || reauth.owner_id != expected_tenant_id {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::AttestationEquivocation,
                "repository identity changed during upload",
            ));
        }
        crate::auth::verify_token(tx, &ca.actor, true).await.map_err(map_app_auth_err)?;
    }
    let user_row = tx
        .query_opt("SELECT username FROM users WHERE id = $1 FOR SHARE", &[&uploader_actor_id])
        .await
        .map_err(pg_err)?
        .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "uploader actor missing"))?;
    let _ = resolve_authoritative_repo_access_in_tx(
        tx,
        repository_id,
        Some(expected_tenant_id),
        uploader_actor_id,
        user_row.get(0),
        true,
        false,
    )
    .await?;
    Ok(())
}

/// Verifies live push attestation authority, generation, and token write scope inside `tx`.
pub(super) async fn verify_push_attestation_authority_in_tx(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    expected_tenant_id: Uuid,
    actor_id: Uuid,
    push_auth: Option<PushCommitAuthCheck>,
) -> Result<(), LfsBlobError> {
    let username: String = tx
        .query_opt("SELECT username FROM users WHERE id = $1 FOR SHARE", &[&actor_id])
        .await
        .map_err(pg_err)?
        .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "attestation actor missing"))?
        .get(0);
    resolve_authoritative_repo_access_in_tx(
        tx,
        repository_id,
        Some(expected_tenant_id),
        actor_id,
        &username,
        true,
        false,
    )
    .await?;
    if let Some(pa) = push_auth {
        if let Some(exp_gen) = pa.expected_generation {
            let cur_gen: i64 = tx
                .query_one("SELECT storage_generation FROM repositories WHERE id = $1 FOR SHARE", &[&repository_id])
                .await
                .map_err(pg_err)?
                .get(0);
            if cur_gen != exp_gen {
                return Err(LfsBlobError::new(
                    LfsProofRejectCode::AttestationEquivocation,
                    "repository generation changed before push attestation",
                ));
            }
        }
        if let Some(tok_id) = pa.token_id {
            crate::auth::verify_repo_write_access(
                &**tx,
                pa.actor_id,
                tok_id,
                repository_id,
                false,
                RepoAction::ContentsWrite,
            )
            .await
            .map_err(map_app_auth_err)?;
        }
    }
    Ok(())
}

/// Authorizes a write actor against live relational RBAC before any realm or `pending` mutation.
pub(super) async fn preflight_write_authority(
    pg: &PgLfsBlobStore,
    repository_id: Uuid,
    expected_tenant_id: Uuid,
    actor_id: Uuid,
    actor_username: &str,
) -> Result<(), LfsBlobError> {
    let mut client = pg.pool().get().await.map_err(pg_err)?;
    let tx = client.transaction().await.map_err(pg_err)?;
    resolve_authoritative_repo_access_in_tx(
        &tx,
        repository_id,
        Some(expected_tenant_id),
        actor_id,
        actor_username,
        true,
        false,
    )
    .await?;
    tx.commit().await.map_err(pg_err)?;
    Ok(())
}

/// Locks the live attempt row, verifies its metadata/lease/operation state, and only then
/// transitions it to `committed` — strictly before any `lfs_blob_objects` / `lfs_objects` write.
pub(super) async fn enforce_live_attempt_and_commit_in_tx(
    tx: &Transaction<'_>,
    attempt_id: Uuid,
    operation_id: Option<Uuid>,
    record: &CommittedLfsBlobRecord,
) -> Result<Option<Uuid>, LfsBlobError> {
    let att_row = tx
        .query_opt(
            "SELECT state, (lease_until > clock_timestamp()) AS lease_live,
                    tenant_id, repository_id, actor_id, oid_sha256, size_bytes, operation_id
             FROM lfs_blob_upload_attempts
             WHERE attempt_id = $1
             FOR UPDATE",
            &[&attempt_id],
        )
        .await
        .map_err(pg_err)?
        .ok_or_else(|| {
            LfsBlobError::new(LfsProofRejectCode::AttestationEquivocation, "upload attempt missing at commit")
        })?;
    let att_state: String = att_row.get(0);
    let lease_live: bool = att_row.get(1);
    let att_tenant: Uuid = att_row.get(2);
    let att_repo: Uuid = att_row.get(3);
    let att_actor: Uuid = att_row.get(4);
    let att_oid: String = att_row.get(5);
    let att_size: i64 = att_row.get(6);
    let att_op: Option<Uuid> = att_row.get(7);
    if att_tenant != record.tenant_id
        || att_repo != record.repository_id
        || att_actor != record.uploader_actor_id
        || att_oid != record.oid_sha256
        || att_size != record.size_bytes
    {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::AttestationEquivocation,
            "upload attempt metadata mismatch at commit",
        ));
    }
    let effective_op_id = match (att_op, operation_id) {
        (Some(a), Some(b)) if a != b => {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::AttestationEquivocation,
                "upload attempt operation_id mismatch at commit",
            ));
        }
        (a, b) => b.or(a),
    };
    if att_state != "pending" || !lease_live {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::AttestationEquivocation,
            "upload attempt lease expired or already revoked/aborted before commit",
        ));
    }
    if let Some(op_id) = effective_op_id {
        let op_row = tx
            .query_opt(
                "SELECT state, tenant_id, actor_id, oid_sha256, size_bytes
                 FROM lfs_blob_upload_operations
                 WHERE repository_id = $1 AND operation_id = $2
                 FOR UPDATE",
                &[&record.repository_id, &op_id],
            )
            .await
            .map_err(pg_err)?
            .ok_or_else(|| {
                LfsBlobError::new(LfsProofRejectCode::AttestationEquivocation, "upload operation missing at commit")
            })?;
        let op_state: String = op_row.get(0);
        let op_tenant: Uuid = op_row.get(1);
        let op_actor: Uuid = op_row.get(2);
        let op_oid: String = op_row.get(3);
        let op_size: i64 = op_row.get(4);
        if op_tenant != record.tenant_id
            || op_actor != record.uploader_actor_id
            || op_oid != record.oid_sha256
            || op_size != record.size_bytes
        {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::AttestationEquivocation,
                "upload operation metadata mismatch at commit",
            ));
        }
        if !matches!(op_state.as_str(), "pending" | "committed") {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::AttestationEquivocation,
                "upload operation is no longer pending (aborted or cancelled) at commit",
            ));
        }
    }
    let updated_att = tx
        .execute(
            "UPDATE lfs_blob_upload_attempts
             SET state = 'committed',
                 operation_id = COALESCE(operation_id, $3),
                 updated_at = clock_timestamp()
             WHERE attempt_id = $1
               AND repository_id = $2
               AND state = 'pending'
               AND lease_until > clock_timestamp()",
            &[&attempt_id, &record.repository_id, &effective_op_id],
        )
        .await
        .map_err(pg_err)?;
    if updated_att != 1 {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::AttestationEquivocation,
            "upload attempt lost lease or pending state before commit",
        ));
    }
    Ok(effective_op_id)
}

/// Finalizes a committed operation under the authoritative `pending|committed` predicate.
pub(super) async fn finalize_committed_operation_in_tx(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    op_id: Uuid,
    locator: &StoredBlobLocatorRef,
    hold_id: Uuid,
) -> Result<(), LfsBlobError> {
    let final_loc_json = serde_json::to_value(locator)
        .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
    let updated_op = tx
        .execute(
            "UPDATE lfs_blob_upload_operations
             SET state = 'committed', locator_json = $3, hold_id = $4, updated_at = clock_timestamp()
             WHERE repository_id = $1
               AND operation_id = $2
               AND state IN ('pending', 'committed')",
            &[&repository_id, &op_id, &final_loc_json, &hold_id],
        )
        .await
        .map_err(pg_err)?;
    if updated_op != 1 {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::AttestationEquivocation,
            "upload operation lost pending/committed state during commit",
        ));
    }
    Ok(())
}

/// Re-checks the live attempt lease immediately before staging handoff or remote upload.
pub(super) async fn verify_staged_attempt_lease(
    pg: &PgLfsBlobStore,
    attempt_id: Uuid,
    expected_size: i64,
    bind_unknown_size: bool,
) -> Result<(), LfsBlobError> {
    let client = pg.pool().get().await.map_err(pg_err)?;
    if bind_unknown_size {
        let n = client
            .execute(
                "UPDATE lfs_blob_upload_attempts
                 SET size_bytes = $2, updated_at = clock_timestamp()
                 WHERE attempt_id = $1 AND state = 'pending' AND lease_until > clock_timestamp()",
                &[&attempt_id, &expected_size],
            )
            .await
            .map_err(pg_err)?;
        if n != 1 {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::AttestationEquivocation,
                "upload attempt lease expired or revoked while streaming",
            ));
        }
        return Ok(());
    }
    let ok = client
        .query_opt(
            "SELECT (state = 'pending' AND lease_until > clock_timestamp() AND size_bytes = $2)
             FROM lfs_blob_upload_attempts WHERE attempt_id = $1",
            &[&attempt_id, &expected_size],
        )
        .await
        .map_err(pg_err)?
        .is_some_and(|r| r.get::<_, bool>(0));
    if !ok {
        return Err(LfsBlobError::new(
            LfsProofRejectCode::AttestationEquivocation,
            "upload attempt lease expired or already revoked before staging handoff",
        ));
    }
    Ok(())
}

/// Aborts an attempt and orphans its still-pending operation when no other live attempt references it.
pub(super) async fn abort_attempt_and_orphan_op(
    pg: &PgLfsBlobStore,
    repository_id: Uuid,
    attempt_id: Uuid,
    operation_id: Uuid,
    reason: &str,
) {
    let _ = pg.mark_upload_attempt_aborted(attempt_id, reason).await;
    if let Ok(client) = pg.pool().get().await {
        let _ = client
            .execute(
                "UPDATE lfs_blob_upload_operations o
                 SET state = 'aborted_cancelled', updated_at = clock_timestamp()
                 WHERE o.repository_id = $1
                   AND o.operation_id = $2
                   AND o.state = 'pending'
                   AND NOT EXISTS (
                       SELECT 1 FROM lfs_blob_upload_attempts a
                       WHERE a.repository_id = o.repository_id
                         AND a.state = 'pending'
                         AND a.lease_until > clock_timestamp()
                         AND (
                             a.operation_id = o.operation_id
                             OR (a.operation_id IS NULL AND a.actor_id = o.actor_id
                                 AND a.oid_sha256 = o.oid_sha256 AND a.size_bytes = o.size_bytes)
                         )
                   )",
                &[&repository_id, &operation_id],
            )
            .await;
    }
}
