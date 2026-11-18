//! Clean-room `schema 151` / `format 30` restore + new-incarnation installation & boot
//! onto fresh PostgreSQL 17, isolated `BlobStore`, and fresh 3-voter mTLS Raft clusters (#153).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use tokio_postgres::Client;
use uuid::Uuid;

use crate::blob_store::opendal::BlobStore;
use crate::config::Config;
use crate::ref_store::core::state_machine::{
    CommitRefsCommand, InitializeGateCommand, RefCasCommand, RepositoryLane, SmPackMode, WireCommitRefsRequest,
    WireGateInit,
};
use crate::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitOid, HeadUpdate, IssuerLane, RefName, RefPrecondition, RefTarget,
    RefUpdate,
};

use super::admission_guard::IncarnationAdmissionGuard;
use super::format30_paired::{FORMAT30_SUBDIR, Format30PairedManifest, verify_format30_paired_archive};
use super::freeze_drain::{RepoBackupRegistrationSpec, TriPartyBackupCoordinator};
use super::git_verify::verify_bare_repo_from_blobs;
use super::mtls_raft::{DurableRaftFreezeRecord, MtlsLiveRaftBackend};
use super::peer_groups::PeerRaftCutpointProof;
use super::pg_cutpoint::{pg_err, sync_restored_pg_projection_cursors};
use super::pg_restore_admission::verify_pg_restored_cursors;
use super::quorum_wal::DurableRaftBackend;
use super::types::{
    BlobArtifactEntry, ExpectedPackPairSpec, NewIncarnationAuthority, PairedBackupError, RestoreOutcome,
};

/// Restore the complete `schema 151` / `format 30` archive (`pg_restore` + `BlobStore` rebuild) into
/// a brand-new PG 17 database + target `BlobStore`, and **install + boot** the new incarnation
/// (`new_cluster_incarnation` + restored `authz_floor` + `deleter_epoch` floor + revoked pre-restore
/// tokens/decisions) onto both the restored `schema 151` PG DB and fresh 3-voter mTLS Raft clusters.
pub async fn restore_and_boot_format30_new_incarnation(
    archive_dir: &Path,
    work_dir: &Path,
    dst_config: &Config,
    target_store: &BlobStore,
    booted_active_raft: &mut MtlsLiveRaftBackend,
    booted_peer_rafts: &mut BTreeMap<i64, MtlsLiveRaftBackend>,
) -> Result<(RestoreOutcome, IncarnationAdmissionGuard), PairedBackupError> {
    let backend_hex = target_store.backend_identity().as_hex().to_owned();
    let manifest = verify_format30_paired_archive(archive_dir, Some(&backend_hex))?;
    let fmt30_dir = archive_dir.join(FORMAT30_SUBDIR);

    // Refuse to restore into a dirty/previous incarnation: every configured target voter must be a
    // brand-new empty `raft-node` replica that never hosted this backup's cluster or authority.
    let forbidden_incarnations = BTreeSet::from([
        manifest.pg_cutpoint.source_cluster_incarnation,
        manifest.pg_cutpoint.source_storage_authority_id,
    ]);
    booted_active_raft.verify_pristine_new_incarnation_target(
        &manifest.raft_cutpoint.group_membership_digest,
        &forbidden_incarnations,
    )?;
    for (&gid, peer) in booted_peer_rafts.iter() {
        let proof =
            manifest.raft_cutpoint.peer_groups.iter().find(|p| p.group_id == gid).ok_or_else(|| {
                PairedBackupError::CutpointSkew(format!("booted peer Raft group {gid} has no cutpoint"))
            })?;
        peer.verify_pristine_new_incarnation_target(&proof.group_membership_digest, &forbidden_incarnations)?;
    }

    crate::backup::restore(
        dst_config, &fmt30_dir, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false,
    )
    .await
    .map_err(|e| PairedBackupError::Postgres(format!("format 30 backup::restore failed: {e:#}")))?;

    let parsed: tokio_postgres::Config = dst_config.database_url.parse().map_err(pg_err)?;
    let mut dst_client =
        crate::db::connect_config(parsed).await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;

    let inc = install_new_incarnation_on_restored_schema151(&mut dst_client, &manifest).await?;
    let git_verified_refs = boot_active_and_peer_mtls_raft_incarnation(
        &fmt30_dir,
        work_dir,
        &manifest,
        &inc,
        booted_active_raft,
        booted_peer_rafts,
    )?;

    let (active_snap, _) = booted_active_raft.durable_state()?;
    let mut peer_snaps = BTreeMap::new();
    for (&gid, pr) in booted_peer_rafts.iter() {
        peer_snaps.insert(gid, pr.durable_state()?.0);
    }
    sync_restored_pg_projection_cursors(&mut dst_client, manifest.raft_cutpoint.group_id, &active_snap, &peer_snaps)
        .await?;
    verify_pg_restored_cursors(&dst_client, manifest.raft_cutpoint.group_id, &active_snap, &peer_snaps).await?;

    let guard = IncarnationAdmissionGuard { live: inc.clone() };
    let outcome = RestoreOutcome {
        backup_id: manifest.backup_id,
        restored_repos: manifest.pg_cutpoint.repositories.len(),
        restored_blobs: manifest.blob_closure.total_artifacts,
        reused_blobs: 0,
        git_verified_refs,
        incarnation: inc,
    };
    Ok((outcome, guard))
}

async fn install_new_incarnation_on_restored_schema151(
    client: &mut Client,
    manifest: &Format30PairedManifest,
) -> Result<NewIncarnationAuthority, PairedBackupError> {
    let gate_auth_e = manifest.pg_cutpoint.repositories.iter().map(|r| r.authority_epoch).max().unwrap_or(1).max(1);
    let active_grp_e = manifest
        .raft_cutpoint
        .group_epochs
        .get(&manifest.raft_cutpoint.group_id)
        .copied()
        .or_else(|| manifest.pg_cutpoint.repositories.first().map(|r| r.group_epoch))
        .unwrap_or(1)
        .max(1);
    let max_floor = manifest
        .raft_cutpoint
        .close_receipts
        .iter()
        .map(|r| r.authz_floor)
        .max()
        .unwrap_or(1)
        .max(manifest.pg_cutpoint.max_decision_scope_version);
    let new_authz_floor = max_floor.saturating_add(10);
    let new_deleter_epoch = manifest.freeze.fenced_deleter_epoch.saturating_add(1);
    let deleter_floor_i64 = i64::try_from(new_deleter_epoch).unwrap_or(i64::MAX);

    let new_cluster_inc = Uuid::new_v4();
    let new_storage_auth = Uuid::new_v4();
    let new_storage_gen = manifest.pg_cutpoint.source_storage_generation.saturating_add(2);
    let primary_hist =
        manifest.pg_cutpoint.repositories.first().map(|r| r.history_incarnation).unwrap_or_else(Uuid::new_v4);

    let tx = client.transaction().await.map_err(pg_err)?;
    tx.execute(
        "UPDATE public.cluster_authority SET incarnation = $1, rotated_at = clock_timestamp() WHERE singleton = true",
        &[&new_cluster_inc],
    )
    .await
    .map_err(pg_err)?;
    let srow = tx
        .query_one(
            "UPDATE public.pando_storage_authorities \
             SET authority_id = $1, generation = GREATEST(generation + 1, $2), \
                 restore_generation = GREATEST(restore_generation + 1, $3), \
                 authority_epoch = $4, \
                 remote_delete_fenced = false, remote_delete_fence_reason = NULL, rotated_at = clock_timestamp() \
             WHERE singleton = true \
             RETURNING generation, authority_epoch",
            &[&new_storage_auth, &new_storage_gen, &deleter_floor_i64, &gate_auth_e],
        )
        .await
        .map_err(pg_err)?;
    let (actual_storage_gen, actual_auth_e): (i64, i64) = (srow.get(0), srow.get(1));

    tx.execute("UPDATE public.tokens SET revoked = true WHERE NOT revoked", &[]).await.map_err(pg_err)?;
    tx.execute(
        "UPDATE public.ref_store_publication_decisions \
         SET state = 'CANCELLED', closed_code = 'restored_new_incarnation', \
             cancelled_at = clock_timestamp(), cancel_change_id = $1 \
         WHERE state = 'OPEN'",
        &[&Uuid::new_v4()],
    )
    .await
    .map_err(pg_err)?;

    tx.execute(
        "INSERT INTO public.ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
         VALUES('authority', $1, $2, 'CLOSING', $3) \
         ON CONFLICT (scope_kind, scope_id) DO UPDATE \
         SET state = 'CLOSING', \
             version = GREATEST(public.ref_store_decision_scopes.version, EXCLUDED.version), \
             change_id = COALESCE(public.ref_store_decision_scopes.change_id, EXCLUDED.change_id)",
        &[&manifest.pg_cutpoint.source_storage_authority_id, &new_authz_floor, &Uuid::new_v4()],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "INSERT INTO public.ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
         VALUES('authority', $1, $2, 'OPEN', NULL) \
         ON CONFLICT (scope_kind, scope_id) DO UPDATE \
         SET version = GREATEST(public.ref_store_decision_scopes.version, EXCLUDED.version)",
        &[&new_storage_auth, &new_authz_floor],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "UPDATE public.ref_store_decision_scopes SET version = GREATEST(version, $1) WHERE state = 'OPEN'",
        &[&new_authz_floor],
    )
    .await
    .map_err(pg_err)?;
    for repo in &manifest.pg_cutpoint.repositories {
        for kind in ["repo_access", "repo_lifecycle"] {
            tx.execute(
                "INSERT INTO public.ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
                 VALUES($1, $2, $3, 'OPEN', NULL) \
                 ON CONFLICT (scope_kind, scope_id) DO UPDATE \
                 SET version = GREATEST(public.ref_store_decision_scopes.version, EXCLUDED.version)",
                &[&kind, &repo.repository_id, &new_authz_floor],
            )
            .await
            .map_err(pg_err)?;
        }
    }
    tx.commit().await.map_err(pg_err)?;

    let fenced_inc = BTreeSet::from([
        manifest.pg_cutpoint.source_cluster_incarnation,
        manifest.pg_cutpoint.source_storage_authority_id,
    ]);
    let fenced_decisions: BTreeSet<Uuid> =
        manifest.raft_cutpoint.snapshot.body.decisions.iter().map(|d| d.decision_id).collect();
    Ok(NewIncarnationAuthority {
        new_cluster_incarnation: new_cluster_inc,
        new_storage_authority_id: new_storage_auth,
        new_storage_generation: actual_storage_gen,
        new_history_incarnation: primary_hist,
        new_authority_epoch: actual_auth_e,
        new_group_epoch: active_grp_e,
        new_authz_floor,
        new_deleter_epoch,
        fenced_prior_incarnations: fenced_inc,
        fenced_pre_backup_decision_ids: fenced_decisions,
    })
}

#[derive(Default)]
struct EntrySlot<'a> {
    pack: Option<&'a BlobArtifactEntry>,
    idx: Option<&'a BlobArtifactEntry>,
}

fn boot_active_and_peer_mtls_raft_incarnation(
    fmt30_dir: &Path,
    work_dir: &Path,
    manifest: &Format30PairedManifest,
    inc: &NewIncarnationAuthority,
    active_raft: &mut MtlsLiveRaftBackend,
    peer_rafts: &mut BTreeMap<i64, MtlsLiveRaftBackend>,
) -> Result<usize, PairedBackupError> {
    let mut git_verified_refs = 0usize;
    let coord = TriPartyBackupCoordinator::new(inc.new_deleter_epoch.saturating_sub(1), 0);
    let mut repo_access_floors = BTreeMap::new();

    for repo in &manifest.pg_cutpoint.repositories {
        repo_access_floors.insert(repo.repository_id, inc.new_authz_floor);
        let mut by_pack: BTreeMap<Uuid, EntrySlot<'_>> = BTreeMap::new();
        for e in manifest.blob_closure.entries.iter().filter(|e| e.repository_id == repo.repository_id) {
            let slot = by_pack.entry(e.pack_id).or_default();
            if e.role == "pack" {
                slot.pack = Some(e);
            } else {
                slot.idx = Some(e);
            }
        }
        let mut pairs = Vec::with_capacity(by_pack.len());
        let mut expected_packs = Vec::with_capacity(by_pack.len());
        for (&pack_id, slot) in &by_pack {
            let (pe, ie) = (
                slot.pack.ok_or_else(|| PairedBackupError::BlobClosureIncomplete("missing .pack".into()))?,
                slot.idx.ok_or_else(|| PairedBackupError::BlobClosureIncomplete("missing .idx".into()))?,
            );
            pairs.push((fmt30_dir.join(&pe.archive_rel_path), fmt30_dir.join(&ie.archive_rel_path)));
            expected_packs.push(ExpectedPackPairSpec {
                pack_id,
                pack_sha256: pe.sha256.clone(),
                pack_bytes: pe.length,
                idx_sha256: ie.sha256.clone(),
                idx_bytes: ie.length,
            });
        }
        let rw = work_dir.join(repo.repository_id.to_string());
        git_verified_refs += verify_bare_repo_from_blobs(&rw, repo.object_format, &repo.refs, &pairs, &rw.join("cl"))?;
        replay_repo_onto_booted_raft(active_raft, repo, inc.new_authz_floor)?;

        let spec = RepoBackupRegistrationSpec {
            repository_id: repo.repository_id,
            tenant_id: repo.tenant_id,
            owner_id: repo.tenant_id,
            object_format: repo.object_format,
            history_incarnation: repo.history_incarnation,
            authority_epoch: repo.authority_epoch,
            group_epoch: repo.group_epoch,
            authority_id: inc.new_storage_authority_id,
            authority_generation: inc.new_storage_generation,
            backend_identity: manifest.blob_closure.backend_identity.clone(),
            expected_packs,
        };
        let mut reg_recs = Vec::new();
        coord.register_backup_closure_hold(active_raft, &spec, &mut reg_recs)?;
    }

    let boot_thaw = DurableRaftFreezeRecord {
        frozen: false,
        barrier_id: Uuid::new_v4(),
        fenced_deleter_epoch: inc.new_deleter_epoch,
        app_fence_seq: 1,
        repo_access_floors,
        seal_receipt_digest: Some(manifest.paired_cut_digest.clone()),
        record_seal: String::new(),
    }
    .seal()?;
    active_raft.write_incarnation_record(inc)?;
    active_raft.write_freeze_record(&boot_thaw)?;

    for peer in &manifest.raft_cutpoint.peer_groups {
        let pr = peer_rafts
            .get_mut(&peer.group_id)
            .ok_or(PairedBackupError::IncompleteCut("missing booted 3-voter mTLS Raft cluster for peer group"))?;
        boot_single_peer_mtls_raft(pr, peer, inc, &boot_thaw)?;
    }
    Ok(git_verified_refs)
}

fn replay_repo_onto_booted_raft(
    raft: &mut MtlsLiveRaftBackend,
    repo: &super::types::PgRepositoryRowProof,
    authz_floor: i64,
) -> Result<(), PairedBackupError> {
    let head_branch = repo
        .refs
        .keys()
        .find(|r| r.as_str() == "refs/heads/main")
        .or_else(|| repo.refs.keys().find(|r| r.starts_with("refs/heads/")))
        .cloned()
        .unwrap_or_else(|| "refs/heads/main".into());
    let init = CoreGateInit::new(
        repo.repository_id,
        repo.tenant_id,
        repo.object_format,
        repo.history_incarnation,
        repo.authority_epoch,
        repo.group_epoch,
        RefName::branch(&head_branch).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?,
    )
    .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    raft.commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
        gate: WireGateInit::from(&init),
        pack_mode: SmPackMode::MetadataOnly,
        lane: RepositoryLane::ServingRefStore,
        authz_floor,
    }))?;
    if repo.refs.is_empty() {
        return Ok(());
    }
    let mut updates = Vec::with_capacity(repo.refs.len());
    for (k, v) in &repo.refs {
        let rn = RefName::new(k).map_err(|e| PairedBackupError::GitVerificationFailed(e.to_string()))?;
        let oid = GitOid::parse(repo.object_format, v)
            .map_err(|e| PairedBackupError::GitVerificationFailed(e.to_string()))?;
        updates.push(RefUpdate::new(rn, RefPrecondition::Absent, RefTarget::Oid(oid)));
    }
    let issuer = Uuid::new_v4();
    let lane = IssuerLane::new("fmt30-restore").map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    let req = CommitRefsRequest::new(
        repo.repository_id,
        repo.tenant_id,
        issuer,
        lane.clone(),
        1,
        Uuid::new_v4(),
        repo.object_format,
        repo.history_incarnation,
        repo.authority_epoch,
        repo.group_epoch,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        updates,
    )
    .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    raft.commit_and_apply(RefCasCommand::CommitRefs(CommitRefsCommand {
        request: WireCommitRefsRequest::from(&req),
        decision_id: None,
        required_holds: Vec::new(),
        policy_rejects: BTreeMap::new(),
        logical_tick: authz_floor as u64,
    }))?;
    if let Some((rk, rv)) = repo.refs.iter().next() {
        let rn = RefName::new(rk).map_err(|e| PairedBackupError::GitVerificationFailed(e.to_string()))?;
        let oid = GitOid::parse(repo.object_format, rv)
            .map_err(|e| PairedBackupError::GitVerificationFailed(e.to_string()))?;
        for (seq_off, rev) in (2..repo.gate_revision).enumerate() {
            let step = CommitRefsRequest::new(
                repo.repository_id,
                repo.tenant_id,
                issuer,
                lane.clone(),
                (seq_off + 2) as i64,
                Uuid::new_v4(),
                repo.object_format,
                repo.history_incarnation,
                repo.authority_epoch,
                repo.group_epoch,
                rev,
                HeadUpdate::Keep,
                CommitMode::Atomic,
                vec![RefUpdate::new(rn.clone(), RefPrecondition::Present(oid), RefTarget::Oid(oid))],
            )
            .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
            raft.commit_and_apply(RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&step),
                decision_id: None,
                required_holds: Vec::new(),
                policy_rejects: BTreeMap::new(),
                logical_tick: authz_floor as u64,
            }))?;
        }
    }
    Ok(())
}

fn boot_single_peer_mtls_raft(
    pr: &mut MtlsLiveRaftBackend,
    peer: &PeerRaftCutpointProof,
    inc: &NewIncarnationAuthority,
    boot_thaw: &DurableRaftFreezeRecord,
) -> Result<(), PairedBackupError> {
    for gate in &peer.snapshot.body.gates {
        let init = CoreGateInit::new(
            gate.repository_id,
            gate.tenant_id,
            gate.object_format,
            gate.history_incarnation,
            gate.authority_epoch,
            peer.group_epoch,
            RefName::branch(&gate.head_ref).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?,
        )
        .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        pr.commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&init),
            pack_mode: gate.pack_mode,
            lane: gate.lane,
            authz_floor: inc.new_authz_floor,
        }))?;
        if let Some(rr) = peer.snapshot.body.refs.iter().find(|r| r.repository_id == gate.repository_id)
            && !rr.refs.is_empty()
        {
            let mut updates = Vec::with_capacity(rr.refs.len());
            for (k, v) in &rr.refs {
                let rn = RefName::new(k).map_err(|e| PairedBackupError::GitVerificationFailed(e.to_string()))?;
                let oid = GitOid::parse(gate.object_format, v)
                    .map_err(|e| PairedBackupError::GitVerificationFailed(e.to_string()))?;
                updates.push(RefUpdate::new(rn, RefPrecondition::Absent, RefTarget::Oid(oid)));
            }
            let req = CommitRefsRequest::new(
                gate.repository_id,
                gate.tenant_id,
                Uuid::new_v4(),
                IssuerLane::new("fmt30-peer").map_err(|e| PairedBackupError::StateMachine(e.to_string()))?,
                1,
                Uuid::new_v4(),
                gate.object_format,
                gate.history_incarnation,
                gate.authority_epoch,
                peer.group_epoch,
                1,
                HeadUpdate::Keep,
                CommitMode::Atomic,
                updates,
            )
            .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
            pr.commit_and_apply(RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req),
                decision_id: None,
                required_holds: Vec::new(),
                policy_rejects: BTreeMap::new(),
                logical_tick: inc.new_authz_floor as u64,
            }))?;
        }
    }
    pr.write_incarnation_record(inc)?;
    pr.write_freeze_record(boot_thaw)?;
    Ok(())
}
