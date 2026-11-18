//! Durable PostgreSQL 17 + live 3-voter mTLS Raft `freeze`/`thaw` barrier lifecycle
//! covering `repo_access`, `repo_lifecycle`, and `authority` across restarts (#153).

use std::collections::BTreeMap;
use std::path::Path;

use tokio_postgres::{Client, GenericClient};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{AppliedLogId, ScopeLifecycle};

pub use super::durable_guarded_ops::{
    execute_deleter_guarded, load_pg_repo_backup_specs, propose_raft_hold_guarded, propose_raft_ref_write_guarded,
    require_unfrozen_pg_and_raft, upsert_repo_access_collaborator_guarded,
};
use super::freeze_drain::{RepoBackupRegistrationSpec, TriPartyBackupCoordinator};
use super::mtls_raft::{DurableRaftFreezeRecord, MtlsLiveRaftBackend};
use super::pg_cutpoint::pg_err;
use super::quorum_wal::DurableRaftBackend;
use super::raft_barrier::{DurableFreezeBarrierProof, SealedArchiveReceipt};
use super::types::{CloseScopeBarrierReceipt, FreezePartyStatus, PairedBackupError};

/// Database-wide durable freeze setting stored in PostgreSQL `pg_db_role_setting`
/// (outside the `public` schema catalog so `schema 151` / `format 30` stays unmodified).
pub const PG_FREEZE_SETTING: &str = "rootyard.paired_backup_freeze";

pub struct DurableFreezeRequest<'a> {
    pub fenced_deleter_epoch: u64,
    pub app_fence_seq: u64,
    pub scope_authz_floor: i64,
    pub repos: &'a [RepoBackupRegistrationSpec],
    pub peer_repos_by_group: BTreeMap<i64, Vec<(Uuid, Uuid, Uuid)>>,
}

pub struct DurableFreezeHandle {
    pub active_barrier: DurableFreezeBarrierProof,
    pub peer_barriers: BTreeMap<i64, DurableFreezeBarrierProof>,
    pub freeze_record: DurableRaftFreezeRecord,
}

impl DurableFreezeHandle {
    pub async fn verify_still_frozen_on(
        &self,
        pg_client: &(impl GenericClient + Sync),
        raft: &MtlsLiveRaftBackend,
    ) -> Result<(), PairedBackupError> {
        let marker = read_pg_database_freeze_marker(pg_client).await?.ok_or(PairedBackupError::FreezeNotHeld(
            "PostgreSQL durable paired_backup_freeze marker missing during backup capture",
        ))?;
        if !marker.starts_with(&format!("{}:", self.active_barrier.barrier_id)) {
            return Err(PairedBackupError::FreezeNotHeld("PostgreSQL freeze marker barrier_id mismatch"));
        }
        let rec = raft
            .read_freeze_record()?
            .ok_or(PairedBackupError::FreezeNotHeld("3-voter mTLS Raft freeze record missing"))?;
        if !rec.frozen || rec.barrier_id != self.active_barrier.barrier_id {
            return Err(PairedBackupError::FreezeNotHeld("3-voter mTLS Raft freeze barrier released early"));
        }
        Ok(())
    }
}

/// Durably freeze PostgreSQL (`pg_db_role_setting` + `pando_storage_authorities` +
/// `ref_store_decision_scopes` `repo_access` / `repo_lifecycle` / `authority` floors)
/// AND live 3-voter mTLS Raft clusters (active + peers), registering durable backup pin+holds+roots.
pub async fn enter_durable_pg_raft_freeze(
    pg_client: &mut Client,
    raft: &mut MtlsLiveRaftBackend,
    peer_rafts: &mut BTreeMap<i64, MtlsLiveRaftBackend>,
    req: &DurableFreezeRequest<'_>,
) -> Result<DurableFreezeHandle, PairedBackupError> {
    if req.repos.is_empty() || req.scope_authz_floor <= 0 {
        return Err(PairedBackupError::InvalidArgument(
            "enter_durable_pg_raft_freeze requires non-empty repos and positive scope_authz_floor",
        ));
    }
    verify_pg_quiescent_before_freeze(pg_client).await?;

    let barrier_id = Uuid::new_v4();
    let mut repo_access_floors = BTreeMap::new();
    {
        let tx = pg_client.transaction().await.map_err(pg_err)?;
        for spec in req.repos {
            for (kind, sid) in [
                ("repo_access", spec.repository_id),
                ("repo_lifecycle", spec.repository_id),
                ("authority", spec.authority_id),
            ] {
                let row = tx
                    .query_one(
                        "INSERT INTO public.ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
                         VALUES($1, $2, $3, 'OPEN', NULL) \
                         ON CONFLICT (scope_kind, scope_id) DO UPDATE \
                         SET version = GREATEST(public.ref_store_decision_scopes.version + 1, EXCLUDED.version) \
                         RETURNING version, state",
                        &[&kind, &sid, &req.scope_authz_floor],
                    )
                    .await
                    .map_err(pg_err)?;
                let (ver, state): (i64, String) = (row.get(0), row.get(1));
                if state != "OPEN" && kind == "repo_access" {
                    return Err(PairedBackupError::ScopeNotClosed("repo_access scope unexpectedly CLOSING".into()));
                }
                if kind == "repo_access" {
                    repo_access_floors.insert(spec.repository_id, ver);
                }
            }
        }
        let reason = format!("paired-backup-freeze:{barrier_id}:{}", req.fenced_deleter_epoch);
        let updated = tx
            .execute(
                "UPDATE public.pando_storage_authorities \
                 SET remote_delete_fenced = true, remote_delete_fence_reason = $1 \
                 WHERE singleton = true",
                &[&reason],
            )
            .await
            .map_err(pg_err)?;
        if updated != 1 {
            return Err(PairedBackupError::DeleterNotFenced("singleton pando_storage_authorities missing"));
        }
        tx.commit().await.map_err(pg_err)?;
    }

    let coord =
        TriPartyBackupCoordinator::new(req.fenced_deleter_epoch.saturating_sub(1), req.app_fence_seq.saturating_sub(1));
    let mut apply_receipts = Vec::new();
    let mut backup_holds = Vec::with_capacity(req.repos.len());
    for spec in req.repos {
        backup_holds.push(coord.register_backup_closure_hold(raft, spec, &mut apply_receipts)?);
    }

    let (durable_snap, durable_digest) = raft.durable_state()?;
    let active_log_id = durable_snap
        .body
        .last_applied
        .ok_or(PairedBackupError::FreezeNotHeld("active mTLS Raft cluster has no applied log entries"))?;
    let targets: Vec<_> = req.repos.iter().map(|s| (s.repository_id, s.tenant_id, s.authority_id)).collect();
    let close_receipts = verify_raft_scopes_quiescent_and_seal(raft, &targets, req.scope_authz_floor, active_log_id)?;

    let status = FreezePartyStatus {
        app_paused: true,
        worker_paused: true,
        deleter_fenced: true,
        consensus_replication_active: true,
        leader_election_active: true,
        fenced_deleter_epoch: req.fenced_deleter_epoch,
        app_fence_seq: req.app_fence_seq,
        worker_drain_settled: 0,
        unknown_ops_resolved: 0,
    };
    let freeze_record = DurableRaftFreezeRecord {
        frozen: true,
        barrier_id,
        fenced_deleter_epoch: req.fenced_deleter_epoch,
        app_fence_seq: req.app_fence_seq,
        repo_access_floors,
        seal_receipt_digest: None,
        record_seal: String::new(),
    }
    .seal()?;
    raft.write_freeze_record(&freeze_record)?;
    set_pg_database_freeze_marker(pg_client, Some(&format!("{barrier_id}:{}", req.fenced_deleter_epoch))).await?;

    let active_barrier = DurableFreezeBarrierProof {
        barrier_id,
        group_id: raft.group_id(),
        group_membership_digest: raft.group_membership_digest(),
        status,
        barrier_log_id: active_log_id,
        barrier_state_digest: durable_digest.clone(),
        apply_receipts,
        close_receipts,
        backup_holds,
        proof_digest: String::new(),
    }
    .seal()?;
    active_barrier.verify_against_raft_group(
        raft.group_id(),
        &raft.group_membership_digest(),
        &durable_snap,
        &durable_digest,
        true,
    )?;

    let mut peer_barriers = BTreeMap::new();
    for (&gid, peer_raft) in peer_rafts.iter_mut() {
        let ptargets = req.peer_repos_by_group.get(&gid).cloned().unwrap_or_default();
        if ptargets.is_empty() {
            return Err(PairedBackupError::InvalidArgument("peer Raft group missing repository targets"));
        }
        let mut peer_coord = TriPartyBackupCoordinator::new(
            req.fenced_deleter_epoch.saturating_sub(1),
            req.app_fence_seq.saturating_sub(1),
        );
        let pb = peer_coord.freeze_peer_group_and_close(peer_raft, &ptargets, req.scope_authz_floor)?;
        peer_raft.write_freeze_record(&freeze_record)?;
        peer_barriers.insert(gid, pb);
    }

    Ok(DurableFreezeHandle { active_barrier, peer_barriers, freeze_record })
}

/// Thaw durable PostgreSQL + 3-voter mTLS Raft admission ONLY after verifying `SealedArchiveReceipt`,
/// on-disk `format 30` archive (`verify_format30_paired_archive`), and durable 3-voter Raft state.
pub async fn thaw_durable_pg_raft_freeze(
    pg_client: &mut Client,
    raft: &MtlsLiveRaftBackend,
    peer_rafts: &BTreeMap<i64, MtlsLiveRaftBackend>,
    handle: &DurableFreezeHandle,
    archive_dir: &Path,
    seal_receipt: &SealedArchiveReceipt,
) -> Result<i64, PairedBackupError> {
    handle.active_barrier.verify_thaw_receipt_binds(raft, seal_receipt)?;
    let manifest = super::format30_paired::verify_format30_paired_archive(archive_dir, None)?;
    let (_, complete_sha) = super::backup::stream_sha256_file(&archive_dir.join(super::types::COMPLETE_MARKER))?;
    if manifest.backup_id != seal_receipt.backup_id
        || manifest.paired_cut_digest != seal_receipt.paired_cut_digest
        || complete_sha != seal_receipt.complete_marker_sha256
    {
        return Err(PairedBackupError::IncompleteCut(
            "format 30 paired archive or COMPLETE marker mismatches SealedArchiveReceipt",
        ));
    }
    if raft.committed_quorum_index()? < handle.active_barrier.barrier_log_id.index {
        return Err(PairedBackupError::FreezeNotHeld("active 3-voter Raft quorum_commit_index behind barrier"));
    }

    let mut post_thaw_floors = BTreeMap::new();
    let mut max_post_floor = 1i64;
    {
        let tx = pg_client.transaction().await.map_err(pg_err)?;
        for (&repo_id, &frozen_floor) in &handle.freeze_record.repo_access_floors {
            let target_floor = frozen_floor.saturating_add(1);
            let ver: i64 = tx
                .query_one(
                    "UPDATE public.ref_store_decision_scopes \
                     SET version = GREATEST(version + 1, $2) \
                     WHERE scope_kind = 'repo_access' AND scope_id = $1 \
                     RETURNING version",
                    &[&repo_id, &target_floor],
                )
                .await
                .map_err(pg_err)?
                .get(0);
            post_thaw_floors.insert(repo_id, ver);
            max_post_floor = max_post_floor.max(ver);
        }
        tx.execute(
            "UPDATE public.pando_storage_authorities \
             SET remote_delete_fenced = false, remote_delete_fence_reason = NULL \
             WHERE singleton = true",
            &[],
        )
        .await
        .map_err(pg_err)?;
        tx.commit().await.map_err(pg_err)?;
    }

    let thawed_rec = DurableRaftFreezeRecord {
        frozen: false,
        barrier_id: handle.active_barrier.barrier_id,
        fenced_deleter_epoch: handle.freeze_record.fenced_deleter_epoch,
        app_fence_seq: handle.freeze_record.app_fence_seq,
        repo_access_floors: post_thaw_floors,
        seal_receipt_digest: Some(seal_receipt.receipt_seal.clone()),
        record_seal: String::new(),
    }
    .seal()?;
    raft.write_freeze_record(&thawed_rec)?;
    for peer_raft in peer_rafts.values() {
        peer_raft.write_freeze_record(&thawed_rec)?;
    }
    set_pg_database_freeze_marker(pg_client, None).await?;
    Ok(max_post_floor)
}

async fn verify_pg_quiescent_before_freeze(client: &(impl GenericClient + Sync)) -> Result<(), PairedBackupError> {
    let row = client
        .query_one(
            "SELECT \
               (SELECT count(*)::bigint FROM public.repositories WHERE transition_state <> 'stable'), \
               (SELECT count(*)::bigint FROM public.git_operations WHERE outcome = 'unknown') \
               + (SELECT count(*)::bigint FROM public.ref_store_operations WHERE state NOT IN ('committed','rejected','cancelled')) \
               + (SELECT count(*)::bigint FROM public.ref_store_publication_decisions WHERE state = 'OPEN')",
            &[],
        )
        .await
        .map_err(pg_err)?;
    let (transitioning, inflight): (i64, i64) = (row.get(0), row.get(1));
    if transitioning != 0 {
        return Err(PairedBackupError::FreezeNotHeld("repository storage transition in progress"));
    }
    if inflight != 0 {
        return Err(PairedBackupError::UnknownInFlightOperations(inflight as usize));
    }
    Ok(())
}

fn verify_raft_scopes_quiescent_and_seal(
    raft: &MtlsLiveRaftBackend,
    targets: &[(Uuid, Uuid, Uuid)],
    authz_floor: i64,
    log_id: AppliedLogId,
) -> Result<Vec<CloseScopeBarrierReceipt>, PairedBackupError> {
    let sm = raft.durable_state_machine();
    let mut receipts = Vec::new();
    for &(repo_id, tenant_id, auth_id) in targets {
        for (kind, sid) in [("repo_access", repo_id), ("repo_lifecycle", repo_id), ("authority", auth_id)] {
            let drain =
                sm.inspect_scope_drain(kind, sid).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
            if !drain.open_decision_ids.is_empty() || !drain.pending_operation_ids.is_empty() {
                return Err(PairedBackupError::UnknownInFlightOperations(
                    drain.open_decision_ids.len() + drain.pending_operation_ids.len(),
                ));
            }
            receipts.push(
                CloseScopeBarrierReceipt {
                    scope_kind: kind.to_owned(),
                    scope_id: sid,
                    repository_id: Some(repo_id),
                    tenant_id: Some(tenant_id),
                    lifecycle: ScopeLifecycle::Closed,
                    authz_floor,
                    raft_log_index: log_id.index,
                    raft_log_term: log_id.term,
                    pending_operation_ids: Vec::new(),
                    open_decision_ids: Vec::new(),
                    receipt_digest: String::new(),
                }
                .seal()?,
            );
        }
    }
    Ok(receipts)
}

pub async fn read_pg_database_freeze_marker(
    client: &(impl GenericClient + Sync),
) -> Result<Option<String>, PairedBackupError> {
    let prefix = format!("{PG_FREEZE_SETTING}=");
    let row = client
        .query_opt(
            "SELECT setting FROM pg_db_role_setting s, unnest(s.setconfig) AS setting \
             WHERE s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database()) \
               AND s.setrole = 0 AND setting LIKE $1 LIMIT 1",
            &[&format!("{prefix}%")],
        )
        .await
        .map_err(pg_err)?;
    Ok(row.and_then(|r| r.get::<_, String>(0).strip_prefix(&prefix).map(str::to_owned)))
}

async fn set_pg_database_freeze_marker(
    client: &(impl GenericClient + Sync),
    marker: Option<&str>,
) -> Result<(), PairedBackupError> {
    let db_name: String = client.query_one("SELECT current_database()", &[]).await.map_err(pg_err)?.get(0);
    let quoted_db = db_name.replace('"', "\"\"");
    let sql = match marker {
        Some(val) => {
            if val.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != ':') {
                return Err(PairedBackupError::InvalidArgument("invalid characters in PG freeze marker"));
            }
            format!("ALTER DATABASE \"{quoted_db}\" SET {PG_FREEZE_SETTING} = '{val}'")
        }
        None => format!("ALTER DATABASE \"{quoted_db}\" RESET {PG_FREEZE_SETTING}"),
    };
    client.batch_execute(&sql).await.map_err(pg_err)?;
    Ok(())
}
