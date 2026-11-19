//! Guarded PostgreSQL + live 3-voter mTLS Raft mutations (`repo_access`, holds,
//! Ref-CAS writes, deleter leases) and `schema 151` spec extraction (#153).

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use deadpool_postgres::Pool;
use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AcquireHoldBatchCommand, ApplyResponse, CommitRefsCommand, InitializeGateCommand, RefCasCommand, RepositoryLane,
    SmPackMode, WireCommitRefsRequest, WireGateInit,
};
use crate::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, RefName,
    RefPrecondition, RefTarget, RefUpdate,
};

use super::durable_freeze_gate::{
    DurableFreezeHandle, read_pg_database_freeze_marker, read_pg_database_read_only,
    verify_no_active_pg_writers_except_fence,
};
use super::freeze_drain::RepoBackupRegistrationSpec;
use super::mtls_raft::MtlsLiveRaftBackend;
use super::peer_groups::PeerGroupBackupInput;
use super::pg_cutpoint::pg_err;
use super::quorum_wal::DurableRaftBackend;
use super::types::{DeleterLeaseTicket, ExpectedPackPairSpec, PairedBackupError};

#[derive(Default)]
struct RawPackSlot {
    pack: Option<(String, u64)>,
    idx: Option<(String, u64)>,
}

/// Query BOTH durable PostgreSQL (`default_transaction_read_only` + `pg_db_role_setting` +
/// `pando_storage_authorities` + `ref_store_decision_scopes('repo_access', repo_id)`) AND live
/// 3-voter mTLS Raft (`EnsureReadIndex` `refcas/paired_freeze`) for fail-closed write admission.
pub async fn require_unfrozen_pg_and_raft(
    pg_client: &(impl GenericClient + Sync),
    raft: &MtlsLiveRaftBackend,
    repository_id: Uuid,
) -> Result<i64, PairedBackupError> {
    if read_pg_database_freeze_marker(pg_client).await?.is_some() || read_pg_database_read_only(pg_client).await? {
        return Err(PairedBackupError::FreezeNotHeld(
            "PostgreSQL durable paired_backup_freeze / read_only fence active; concurrent writes rejected",
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
    if read_pg_database_freeze_marker(&**client).await?.is_some() || read_pg_database_read_only(&**client).await? {
        return Err(PairedBackupError::FreezeNotHeld(
            "PostgreSQL durable paired_backup_freeze / read_only fence active; concurrent repo_access write rejected",
        ));
    }
    let tx = tokio_postgres::Client::transaction(&mut client).await.map_err(pg_err)?;
    let _ = tx
        .query_opt(
            "SELECT version FROM public.ref_store_decision_scopes \
             WHERE scope_kind = 'repo_access' AND scope_id = $1 FOR UPDATE",
            &[&repository_id],
        )
        .await
        .map_err(pg_err)?;
    let _ = require_unfrozen_pg_and_raft(&tx, raft, repository_id).await?;
    let affected = tx
        .execute(
            "INSERT INTO public.repository_collaborators(repository_id, tenant_id, user_id, role) \
             SELECT id, owner_id, $2, $3 FROM public.repositories WHERE id = $1 \
             ON CONFLICT (repository_id, user_id) DO UPDATE \
             SET role = EXCLUDED.role, \
                 version = public.repository_collaborators.version + 1, \
                 updated_at = clock_timestamp()",
            &[&repository_id, &user_id, &role],
        )
        .await
        .map_err(pg_err)?;
    if affected != 1 {
        return Err(PairedBackupError::Postgres(
            "target repository missing for repository_collaborators upsert".into(),
        ));
    }
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
                "SELECT a.pack_id, a.role, a.sha256, a.content_length \
                 FROM public.ref_store_core_pack_artifacts a \
                 JOIN public.ref_store_core_pack_memberships m \
                   ON m.repository_id = a.repository_id AND m.pack_id = a.pack_id \
                  AND m.registration_id = a.registration_id \
                 WHERE a.repository_id = $1 ORDER BY a.pack_id, a.role",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?;
        let mut by_pack: BTreeMap<Uuid, RawPackSlot> = BTreeMap::new();
        for ar in art_rows {
            let pid: Uuid = ar.get(0);
            let role: String = ar.get(1);
            let sha: String = ar.get(2);
            let len = u64::try_from(ar.get::<_, i64>(3)).unwrap_or(0);
            let entry = by_pack.entry(pid).or_default();
            if role == "pack" {
                entry.pack = Some((sha, len));
            } else if role == "idx" {
                entry.idx = Some((sha, len));
            }
        }
        let mut expected_packs = Vec::with_capacity(by_pack.len());
        for (pack_id, slot) in by_pack {
            let ((pack_sha256, pack_bytes), (idx_sha256, idx_bytes)) = (
                slot.pack.ok_or_else(|| PairedBackupError::BlobClosureIncomplete("PG missing .pack".into()))?,
                slot.idx.ok_or_else(|| PairedBackupError::BlobClosureIncomplete("PG missing .idx".into()))?,
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

fn state_machine_err(error: impl std::fmt::Display) -> PairedBackupError {
    PairedBackupError::StateMachine(error.to_string())
}

/// Replicate the PG-authoritative gate and refs of one ready serving repository into the live
/// 3-voter mTLS Raft state machine under the guarded freeze/authz admission checks, so a restore
/// target can be cut and attested without any test-only gate seeding.
pub async fn replicate_pg_repo_to_raft_guarded(
    pool: &Pool,
    raft: &mut MtlsLiveRaftBackend,
    repository_id: Uuid,
) -> Result<(), PairedBackupError> {
    let client = pool.get().await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    let floor = require_unfrozen_pg_and_raft(&**client, raft, repository_id).await?;
    let specs = load_pg_repo_backup_specs(&**client).await?;
    let spec = specs
        .into_iter()
        .find(|s| s.repository_id == repository_id)
        .ok_or(PairedBackupError::InvalidArgument("repository is not a ready serving repository closure"))?;
    let head_ref: String = client
        .query_one("SELECT head_ref FROM public.ref_store_core_gates WHERE repository_id = $1", &[&repository_id])
        .await
        .map_err(pg_err)?
        .get(0);
    let rows = client
        .query(
            "SELECT ref_name, oid FROM public.ref_store_core_refs WHERE repository_id = $1 ORDER BY ref_name",
            &[&repository_id],
        )
        .await
        .map_err(pg_err)?;
    let init = CoreGateInit::new(
        spec.repository_id,
        spec.tenant_id,
        spec.object_format,
        spec.history_incarnation,
        spec.authority_epoch,
        spec.group_epoch,
        RefName::branch(&head_ref).map_err(state_machine_err)?,
    )
    .map_err(state_machine_err)?;
    let (_, init_resp) = raft.commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
        gate: WireGateInit::from(&init),
        pack_mode: SmPackMode::MetadataOnly,
        lane: RepositoryLane::ServingRefStore,
        authz_floor: floor.max(1),
    }))?;
    if !matches!(
        init_resp,
        ApplyResponse::GateInitialized { .. } | ApplyResponse::AlreadyApplied { .. } | ApplyResponse::Noop
    ) {
        return Err(PairedBackupError::StateMachine("Raft InitializeGate replication was rejected".into()));
    }
    if rows.is_empty() {
        return Ok(());
    }
    let mut updates = Vec::with_capacity(rows.len());
    for row in rows {
        let (name, oid_hex): (String, String) = (row.get(0), row.get(1));
        updates.push(RefUpdate::new(
            RefName::new(&name).map_err(state_machine_err)?,
            RefPrecondition::Absent,
            RefTarget::Oid(GitOid::parse(spec.object_format, &oid_hex).map_err(state_machine_err)?),
        ));
    }
    let lane = IssuerLane::new("paired-pg-raft-sync").map_err(state_machine_err)?;
    let request = CommitRefsRequest::new(
        spec.repository_id,
        spec.tenant_id,
        Uuid::new_v4(),
        lane,
        1,
        Uuid::new_v4(),
        spec.object_format,
        spec.history_incarnation,
        spec.authority_epoch,
        spec.group_epoch,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        updates,
    )
    .map_err(state_machine_err)?;
    let (_, commit_resp) = raft.commit_and_apply(RefCasCommand::CommitRefs(CommitRefsCommand {
        request: WireCommitRefsRequest::from(&request),
        decision_id: None,
        required_holds: Vec::new(),
        policy_rejects: BTreeMap::new(),
        logical_tick: 1,
    }))?;
    if !matches!(commit_resp, ApplyResponse::RefsCommitted(_)) {
        return Err(PairedBackupError::StateMachine("Raft CommitRefs PG replication was rejected".into()));
    }
    Ok(())
}

impl DurableFreezeHandle {
    /// Drop the held SHARE table fence: the only test-only fail-closed injection point.
    pub async fn drop_write_fence_for_test(&self) -> Result<(), PairedBackupError> {
        let held = self.write_fence.lock().await.take();
        if let Some(fence) = held {
            fence.release().await?;
        }
        Ok(())
    }

    pub fn set_fault_drop_fence_stage_for_test(&self, stage: u8) {
        self.fault_drop_fence_stage.store(stage, Ordering::SeqCst);
    }

    pub(super) async fn maybe_inject_fence_fault(&self, stage: u8) -> Result<(), PairedBackupError> {
        if self.fault_drop_fence_stage.load(Ordering::SeqCst) == stage {
            self.drop_write_fence_for_test().await?;
        }
        Ok(())
    }

    /// Continuous fail-closed proof that the PG SHARE fence and every Raft freeze barrier survive
    /// archive capture and receipt publication, re-verified at each publication boundary.
    pub async fn verify_fence_intact_for_publication(
        &self,
        pg_client: &(impl GenericClient + Sync),
        raft: &MtlsLiveRaftBackend,
        peer_groups: &[PeerGroupBackupInput<'_>],
    ) -> Result<(), PairedBackupError> {
        let fence_pid = self
            .write_fence_pid()
            .await
            .ok_or(PairedBackupError::FreezeNotHeld("PostgreSQL SHARE table write fence missing"))?;
        self.verify_write_fence_held().await?;
        verify_no_active_pg_writers_except_fence(pg_client, Some(fence_pid)).await?;
        let fenced: bool = pg_client
            .query_one("SELECT remote_delete_fenced FROM public.pando_storage_authorities WHERE singleton = true", &[])
            .await
            .map_err(pg_err)?
            .get(0);
        if !fenced {
            return Err(PairedBackupError::DeleterNotFenced(
                "PostgreSQL storage authority delete fence lost during archive publication",
            ));
        }
        self.verify_still_frozen_on(pg_client, raft).await?;
        for pg in peer_groups {
            if pg.raft.committed_quorum_index()? < pg.freeze_barrier.barrier_log_id.index {
                return Err(PairedBackupError::FreezeNotHeld("peer Raft quorum_commit_index behind barrier"));
            }
            pg.raft.verify_freeze_barrier_active(self.active_barrier.barrier_id)?;
        }
        Ok(())
    }
}
