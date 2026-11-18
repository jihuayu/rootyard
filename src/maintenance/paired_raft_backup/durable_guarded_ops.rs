//! Guarded PostgreSQL + live 3-voter mTLS Raft mutations (`repo_access`, holds,
//! Ref-CAS writes, deleter leases) and `schema 151` spec extraction (#153).

use std::collections::BTreeMap;

use deadpool_postgres::Pool;
use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::ref_store::GitObjectFormat;
use crate::ref_store::core::state_machine::{AcquireHoldBatchCommand, ApplyResponse, RefCasCommand};

use super::durable_freeze_gate::read_pg_database_freeze_marker;
use super::freeze_drain::RepoBackupRegistrationSpec;
use super::mtls_raft::MtlsLiveRaftBackend;
use super::pg_cutpoint::pg_err;
use super::quorum_wal::DurableRaftBackend;
use super::types::{DeleterLeaseTicket, ExpectedPackPairSpec, PairedBackupError};

/// Query BOTH durable PostgreSQL (`pg_db_role_setting` + `pando_storage_authorities` +
/// `ref_store_decision_scopes('repo_access', repo_id)`) AND live 3-voter mTLS Raft
/// (`EnsureReadIndex` `refcas/paired_freeze`) to enforce fail-closed write admission.
pub async fn require_unfrozen_pg_and_raft(
    pg_client: &(impl GenericClient + Sync),
    raft: &MtlsLiveRaftBackend,
    repository_id: Uuid,
) -> Result<i64, PairedBackupError> {
    if read_pg_database_freeze_marker(pg_client).await?.is_some() {
        return Err(PairedBackupError::FreezeNotHeld(
            "PostgreSQL durable paired_backup_freeze marker active; concurrent writes rejected",
        ));
    }
    let fenced: bool = pg_client
        .query_one("SELECT remote_delete_fenced FROM public.pando_storage_authorities WHERE singleton = true", &[])
        .await
        .map_err(pg_err)?
        .get(0);
    if fenced {
        return Err(PairedBackupError::FreezeNotHeld("PostgreSQL storage authority delete fence active"));
    }
    if let Some(rec) = raft.read_freeze_record()?
        && rec.frozen
    {
        return Err(PairedBackupError::FreezeNotHeld(
            "3-voter mTLS Raft durable freeze record active; concurrent writes rejected",
        ));
    }
    let scope_row = pg_client
        .query_opt(
            "SELECT version, state FROM public.ref_store_decision_scopes \
             WHERE scope_kind = 'repo_access' AND scope_id = $1",
            &[&repository_id],
        )
        .await
        .map_err(pg_err)?;
    let Some(sr) = scope_row else {
        return Ok(1);
    };
    let (ver, st): (i64, String) = (sr.get(0), sr.get(1));
    if st != "OPEN" {
        return Err(PairedBackupError::ScopeNotClosed("repo_access decision scope is not OPEN".into()));
    }
    Ok(ver)
}

/// Guarded `repo_access` collaborator upsert enforcing the durable PG + 3-voter mTLS Raft freeze gate
/// inside a transaction locking `ref_store_decision_scopes('repo_access', repository_id) FOR UPDATE`.
pub async fn upsert_repo_access_collaborator_guarded(
    pool: &Pool,
    raft: &MtlsLiveRaftBackend,
    repository_id: Uuid,
    user_id: Uuid,
    role: &str,
) -> Result<i64, PairedBackupError> {
    let mut client = pool.get().await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    let tx = client.transaction().await.map_err(pg_err)?;
    let _ = tx
        .query_opt(
            "SELECT version FROM public.ref_store_decision_scopes \
             WHERE scope_kind = 'repo_access' AND scope_id = $1 FOR UPDATE",
            &[&repository_id],
        )
        .await
        .map_err(pg_err)?;
    let _ = require_unfrozen_pg_and_raft(&tx, raft, repository_id).await?;
    tx.execute(
        "INSERT INTO public.repository_collaborators(repository_id, user_id, role) \
         VALUES($1, $2, $3) \
         ON CONFLICT (repository_id, user_id) DO UPDATE SET role = EXCLUDED.role",
        &[&repository_id, &user_id, &role],
    )
    .await
    .map_err(pg_err)?;
    let next_ver: i64 = tx
        .query_one(
            "INSERT INTO public.ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
             VALUES('repo_access', $1, 1, 'OPEN', NULL) \
             ON CONFLICT (scope_kind, scope_id) DO UPDATE \
             SET version = public.ref_store_decision_scopes.version + 1 \
             RETURNING version",
            &[&repository_id],
        )
        .await
        .map_err(pg_err)?
        .get(0);
    tx.commit().await.map_err(pg_err)?;
    Ok(next_ver)
}

/// Guarded artifact-hold acquisition enforcing durable PG + 3-voter mTLS Raft freeze admission.
pub async fn propose_raft_hold_guarded(
    pool: &Pool,
    raft: &mut MtlsLiveRaftBackend,
    cmd: AcquireHoldBatchCommand,
) -> Result<ApplyResponse, PairedBackupError> {
    let client = pool.get().await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    let _ = require_unfrozen_pg_and_raft(&**client, raft, cmd.repository_id).await?;
    let (_, resp) = raft.commit_and_apply(RefCasCommand::AcquireHoldBatch(cmd))?;
    Ok(resp)
}

/// Guarded Ref-CAS quorum mutation enforcing BOTH durable PG + 3-voter mTLS Raft unfreeze state
/// AND `authz_epoch >= current_repo_access_floor`.
pub async fn propose_raft_ref_write_guarded(
    pool: &Pool,
    raft: &mut MtlsLiveRaftBackend,
    repository_id: Uuid,
    authz_epoch: i64,
    cmd: RefCasCommand,
) -> Result<ApplyResponse, PairedBackupError> {
    let client = pool.get().await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    let floor = require_unfrozen_pg_and_raft(&**client, raft, repository_id).await?;
    if authz_epoch < floor {
        return Err(PairedBackupError::StaleGrantRefused("Ref-CAS write authz_epoch below durable repo_access floor"));
    }
    let (_, resp) = raft.commit_and_apply(cmd)?;
    Ok(resp)
}

/// Guarded deleter execution check enforcing durable PG + 3-voter mTLS Raft freeze & epoch fences.
pub async fn execute_deleter_guarded(
    pool: &Pool,
    raft: &MtlsLiveRaftBackend,
    ticket: &DeleterLeaseTicket,
) -> Result<(), PairedBackupError> {
    let client = pool.get().await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    if read_pg_database_freeze_marker(&**client).await?.is_some() {
        return Err(PairedBackupError::DeleterNotFenced("PostgreSQL paired backup freeze active"));
    }
    if let Some(rec) = raft.read_freeze_record()?
        && (rec.frozen || ticket.deleter_epoch < rec.fenced_deleter_epoch)
    {
        return Err(PairedBackupError::DeleterNotFenced(
            "Raft freeze active or deleter_epoch superseded by backup barrier",
        ));
    }
    let row = client
        .query_one(
            "SELECT authority_id, generation, restore_generation, remote_delete_fenced \
             FROM public.pando_storage_authorities WHERE singleton = true",
            &[],
        )
        .await
        .map_err(pg_err)?;
    let (auth_id, gen_i64, restore_gen, fenced): (Uuid, i64, i64, bool) =
        (row.get(0), row.get(1), row.get(2), row.get(3));
    if fenced
        || ticket.storage_authority_id != auth_id
        || ticket.storage_generation < gen_i64
        || (restore_gen > 0 && ticket.deleter_epoch < restore_gen as u64)
    {
        return Err(PairedBackupError::DeleterNotFenced("deleter fenced or superseded in PostgreSQL"));
    }
    Ok(())
}

/// Load authoritative `RepoBackupRegistrationSpec`s directly from a `schema 151` PostgreSQL database.
pub async fn load_pg_repo_backup_specs(
    client: &(impl GenericClient + Sync),
) -> Result<Vec<RepoBackupRegistrationSpec>, PairedBackupError> {
    let auth_row = client
        .query_one("SELECT authority_id, generation FROM public.pando_storage_authorities WHERE singleton = true", &[])
        .await
        .map_err(pg_err)?;
    let (authority_id, authority_generation): (Uuid, i64) = (auth_row.get(0), auth_row.get(1));

    let repo_rows = client
        .query(
            "SELECT g.repository_id, g.tenant_id, g.object_format, g.history_incarnation, \
                    g.authority_epoch, g.group_epoch, s.backend_identity \
             FROM public.ref_store_core_gates g \
             JOIN public.ref_store_serving_repositories s ON s.repository_id = g.repository_id \
             WHERE s.state = 'ready' \
             ORDER BY g.repository_id",
            &[],
        )
        .await
        .map_err(pg_err)?;

    let mut specs = Vec::with_capacity(repo_rows.len());
    for rr in repo_rows {
        let repository_id: Uuid = rr.get(0);
        let fmt = match rr.get::<_, String>(2).as_str() {
            "sha1" => GitObjectFormat::Sha1,
            "sha256" => GitObjectFormat::Sha256,
            other => return Err(PairedBackupError::Postgres(format!("unsupported format {other}"))),
        };
        let art_rows = client
            .query(
                "SELECT pack_id, role, sha256, content_length \
                 FROM public.ref_store_core_pack_artifacts \
                 WHERE repository_id = $1 ORDER BY pack_id, role",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?;
        let mut by_pack: BTreeMap<Uuid, (Option<(String, u64)>, Option<(String, u64)>)> = BTreeMap::new();
        for ar in art_rows {
            let pid: Uuid = ar.get(0);
            let role: String = ar.get(1);
            let sha: String = ar.get(2);
            let len = u64::try_from(ar.get::<_, i64>(3)).unwrap_or(0);
            let entry = by_pack.entry(pid).or_default();
            if role == "pack" {
                entry.0 = Some((sha, len));
            } else if role == "idx" {
                entry.1 = Some((sha, len));
            }
        }
        let mut expected_packs = Vec::with_capacity(by_pack.len());
        for (pack_id, (p_opt, i_opt)) in by_pack {
            let ((pack_sha256, pack_bytes), (idx_sha256, idx_bytes)) = (
                p_opt.ok_or_else(|| PairedBackupError::BlobClosureIncomplete("PG missing .pack".into()))?,
                i_opt.ok_or_else(|| PairedBackupError::BlobClosureIncomplete("PG missing .idx".into()))?,
            );
            expected_packs.push(ExpectedPackPairSpec { pack_id, pack_sha256, pack_bytes, idx_sha256, idx_bytes });
        }
        specs.push(RepoBackupRegistrationSpec {
            repository_id,
            tenant_id: rr.get(1),
            owner_id: rr.get(1),
            object_format: fmt,
            history_incarnation: rr.get(3),
            authority_epoch: rr.get(4),
            group_epoch: rr.get(5),
            authority_id,
            authority_generation,
            backend_identity: rr.get(6),
            expected_packs,
        });
    }
    Ok(specs)
}
