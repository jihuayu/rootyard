//! Archive verification, clean-room multi-group new-incarnation restore, stock-Git clone/fsck,
//! and fail-closed stale credential/grant/decision/deleter admission (#153).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use tokio_postgres::Client;
use uuid::Uuid;

use crate::blob_store::capacity_contract::git_ops::{UploadScope, upload_pack_pair};
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::core::state_machine::{
    CommitRefsCommand, InitializeGateCommand, RefCasCommand, RefCasStateMachine, RepositoryLane, SmPackMode,
    WireCommitRefsRequest, WireGateInit,
};
use crate::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, HeadUpdate, IssuerLane, RefName, RefPrecondition, RefTarget, RefUpdate,
};

pub use super::admission_guard::IncarnationAdmissionGuard;
use super::backup::{reconcile_pg_raft_repositories, stream_sha256_file};
use super::closure_bind::verify_blob_closure_against_durable_raft;
use super::freeze_drain::{RepoBackupRegistrationSpec, TriPartyBackupCoordinator};
use super::git_verify::verify_bare_repo_from_blobs;
use super::peer_groups::{
    ExpectedGroupCursorCut, restore_peer_groups_state, verify_all_group_cursors, verify_archived_peer_groups,
};
use super::pg_restore_admission::{install_restored_pg_incarnation, verify_pg_restored_cursors};
use super::quorum_wal::{DurableRaftBackend, WalSyncedRaftBackend};
use super::types::{
    COMPLETE_MARKER, ExpectedPackPairSpec, MANIFEST_FILE, MAX_MANIFEST_BYTES, NewIncarnationAuthority,
    PAIRED_BACKUP_FORMAT_V1, PairedBackupError, PairedBackupManifest, RestoreOutcome,
};

#[derive(Clone, Debug, Default)]
pub struct RestoreTargetScope {
    pub expected_tenant_id: Option<Uuid>,
    pub expected_repository_id: Option<Uuid>,
    pub expected_backend_identity: Option<String>,
}

/// Strictly verify `COMPLETE` seal, manifest integrity, active + peer durable Raft snapshots,
/// PG <-> Raft `group_epoch` + index cursors, complete durable hold/root/pin Blob closure, and Blob SHA-256s.
pub fn verify_backup_archive(
    source: &Path,
    expected_backend_identity: Option<&str>,
) -> Result<PairedBackupManifest, PairedBackupError> {
    let manifest_path = source.join(MANIFEST_FILE);
    let complete_path = source.join(COMPLETE_MARKER);
    let c_meta = fs::symlink_metadata(&complete_path)
        .map_err(|_| PairedBackupError::IncompleteCut("missing COMPLETE completion marker"))?;
    let m_meta =
        fs::symlink_metadata(&manifest_path).map_err(|_| PairedBackupError::IncompleteCut("missing manifest.json"))?;
    if !c_meta.file_type().is_file() || !m_meta.file_type().is_file() || m_meta.len() > MAX_MANIFEST_BYTES {
        return Err(PairedBackupError::IncompleteCut("manifest.json or COMPLETE marker invalid"));
    }
    let mut marker_hex = String::new();
    File::open(&complete_path)?.take(65).read_to_string(&mut marker_hex)?;
    let actual_manifest_hex = stream_sha256_file(&manifest_path)?.1;
    if marker_hex.trim() != actual_manifest_hex {
        return Err(PairedBackupError::IncompleteCut("COMPLETE checksum mismatches manifest.json"));
    }

    let manifest_raw = fs::read(&manifest_path)?;
    let manifest: PairedBackupManifest = serde_json::from_slice(&manifest_raw).map_err(|e| {
        PairedBackupError::IncompleteCut(if e.is_data() {
            "malformed or unknown manifest field"
        } else {
            "manifest parse failed"
        })
    })?;
    if manifest.format_version != PAIRED_BACKUP_FORMAT_V1 {
        return Err(PairedBackupError::IncompleteCut("unsupported paired backup format_version"));
    }
    let sealed_check = manifest.clone().seal()?;
    if sealed_check.paired_cut_digest != manifest.paired_cut_digest {
        return Err(PairedBackupError::CorruptBlobOrDigest("paired_cut_digest mismatch".into()));
    }

    manifest.freeze.require_frozen()?;
    manifest.pg_cutpoint.verify()?;
    manifest.blob_closure.verify()?;
    super::format30_paired::enforce_blob_closure_verifier_budget(&manifest.blob_closure.entries)?;
    if let Some(expected_be) = expected_backend_identity
        && manifest.blob_closure.backend_identity != expected_be
    {
        return Err(PairedBackupError::BackendIdentityMismatch {
            expected: expected_be.to_owned(),
            actual: manifest.blob_closure.backend_identity,
        });
    }

    let raft = &manifest.raft_cutpoint;
    raft.snapshot.verify_integrity().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    if raft.snapshot.checksum != raft.snapshot_checksum || raft.snapshot.body.last_applied != Some(raft.applied_log_id)
    {
        return Err(PairedBackupError::CutpointSkew("Raft snapshot last_applied or checksum mismatch".into()));
    }
    let rebuilt_active =
        RefCasStateMachine::restore(&raft.snapshot).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    if rebuilt_active.state_digest().map_err(|e| PairedBackupError::StateMachine(e.to_string()))? != raft.state_digest {
        return Err(PairedBackupError::CutpointSkew("active Raft state_digest mismatches snapshot".into()));
    }
    if raft.close_receipts.is_empty() || raft.backup_holds.is_empty() {
        return Err(PairedBackupError::IncompleteCut("manifest missing close barrier receipts or backup holds"));
    }

    let active_cut = ExpectedGroupCursorCut::from_verified_snapshot(raft.group_id, &raft.snapshot)?;
    super::raft_barrier::verify_cutpoint_attestations(
        (raft.group_id, active_cut.group_epoch),
        &raft.voter_ids,
        &raft.group_membership_digest,
        (raft.applied_log_id, raft.min_consensus_index),
        (&raft.state_digest, &raft.snapshot_checksum),
        &raft.cutpoint_attestations,
    )?;
    let peer_cuts =
        verify_archived_peer_groups(raft.group_id, active_cut.group_epoch, &raft.group_epochs, &raft.peer_groups)?;
    verify_all_group_cursors(&manifest.pg_cutpoint, &active_cut, &peer_cuts)?;
    reconcile_pg_raft_repositories(&manifest.pg_cutpoint, &raft.snapshot, raft.applied_log_id, &raft.close_receipts)?;
    verify_blob_closure_against_durable_raft(
        &raft.snapshot,
        &raft.backup_holds,
        &manifest.blob_closure.entries,
        &manifest.pg_cutpoint.repositories,
    )?;

    for entry in &manifest.blob_closure.entries {
        if entry.backend_identity != manifest.blob_closure.backend_identity {
            return Err(PairedBackupError::BackendIdentityMismatch {
                expected: manifest.blob_closure.backend_identity.clone(),
                actual: entry.backend_identity.clone(),
            });
        }
        let disk_file = source.join(&entry.archive_rel_path);
        let (len, hex) = stream_sha256_file(&disk_file).map_err(|_| {
            PairedBackupError::CorruptBlobOrDigest(format!("missing archive blob {}", entry.archive_rel_path))
        })?;
        if len != entry.length || hex != entry.sha256 {
            return Err(PairedBackupError::CorruptBlobOrDigest(format!(
                "truncated or corrupted archive blob {}",
                entry.archive_rel_path
            )));
        }
    }
    Ok(manifest)
}

/// Clean-room restore creating a strictly fresh incarnation (`history_incarnation`,
/// `cluster_incarnation`, bumped epochs & `authz_floor`), uploading verified blobs into `target_store`,
/// checking real `git clone` + `git fsck --full --strict`, and committing via 3-voter fsynced WAL.
pub async fn restore_new_incarnation(
    source: &Path,
    work_dir: &Path,
    target_store: &BlobStore,
    scope: &RestoreTargetScope,
    deadline: Instant,
) -> Result<(RestoreOutcome, RefCasStateMachine, IncarnationAdmissionGuard), PairedBackupError> {
    let (out, sm, guard, _peers) =
        restore_new_incarnation_full(source, work_dir, target_store, scope, deadline).await?;
    Ok((out, sm, guard))
}

async fn restore_new_incarnation_full(
    source: &Path,
    work_dir: &Path,
    target_store: &BlobStore,
    scope: &RestoreTargetScope,
    deadline: Instant,
) -> Result<
    (
        RestoreOutcome,
        RefCasStateMachine,
        IncarnationAdmissionGuard,
        BTreeMap<i64, crate::ref_store::core::state_machine::RefCasSnapshot>,
    ),
    PairedBackupError,
> {
    let manifest = verify_backup_archive(source, scope.expected_backend_identity.as_deref())?;
    let target_backend = target_store.backend_identity().as_hex();
    if manifest.blob_closure.backend_identity != target_backend {
        return Err(PairedBackupError::BackendIdentityMismatch {
            expected: target_backend.to_owned(),
            actual: manifest.blob_closure.backend_identity,
        });
    }
    for repo in &manifest.pg_cutpoint.repositories {
        if let Some(tid) = scope.expected_tenant_id
            && repo.tenant_id != tid
        {
            return Err(PairedBackupError::TenantOrRepoMismatch(format!(
                "expected tenant {tid}, backup holds {}",
                repo.tenant_id
            )));
        }
        if let Some(rid) = scope.expected_repository_id
            && repo.repository_id != rid
        {
            return Err(PairedBackupError::TenantOrRepoMismatch(format!(
                "expected repository {rid}, backup holds {}",
                repo.repository_id
            )));
        }
    }

    let max_auth_e = manifest.pg_cutpoint.repositories.iter().map(|r| r.authority_epoch).max().unwrap_or(1);
    let max_grp_e = manifest
        .pg_cutpoint
        .repositories
        .iter()
        .map(|r| r.group_epoch)
        .chain(manifest.raft_cutpoint.group_epochs.values().copied())
        .max()
        .unwrap_or(1);
    let max_floor = manifest
        .raft_cutpoint
        .close_receipts
        .iter()
        .chain(manifest.raft_cutpoint.peer_groups.iter().flat_map(|p| p.freeze_barrier.close_receipts.iter()))
        .map(|r| r.authz_floor)
        .max()
        .unwrap_or(1)
        .max(manifest.pg_cutpoint.max_decision_scope_version);
    let mut fenced_inc = BTreeSet::from([
        manifest.pg_cutpoint.source_cluster_incarnation,
        manifest.pg_cutpoint.source_storage_authority_id,
    ]);
    for r in &manifest.pg_cutpoint.repositories {
        fenced_inc.insert(r.history_incarnation);
    }
    for p in &manifest.raft_cutpoint.peer_groups {
        fenced_inc.insert(p.history_incarnation);
    }
    let fenced_decisions: BTreeSet<Uuid> =
        manifest.raft_cutpoint.snapshot.body.decisions.iter().map(|d| d.decision_id).collect();

    let inc = NewIncarnationAuthority {
        new_cluster_incarnation: Uuid::new_v4(),
        new_storage_authority_id: Uuid::new_v4(),
        new_storage_generation: manifest.pg_cutpoint.source_storage_generation.saturating_add(1),
        new_history_incarnation: Uuid::new_v4(),
        new_authority_epoch: max_auth_e.saturating_add(1),
        new_group_epoch: max_grp_e.saturating_add(1),
        new_authz_floor: max_floor.saturating_add(10),
        new_deleter_epoch: manifest.freeze.fenced_deleter_epoch.saturating_add(1),
        fenced_prior_incarnations: fenced_inc,
        fenced_pre_backup_decision_ids: fenced_decisions,
    };

    let (mut restored_blobs, mut git_verified_refs) = (0usize, 0usize);
    type PackPairSlot<'a> = (
        Option<(&'a super::types::BlobArtifactEntry, PathBuf)>,
        Option<(&'a super::types::BlobArtifactEntry, PathBuf)>,
    );
    let mut by_repo_packs: BTreeMap<Uuid, BTreeMap<Uuid, PackPairSlot<'_>>> = BTreeMap::new();

    for entry in &manifest.blob_closure.entries {
        let local_blob = source.join(&entry.archive_rel_path);
        let slot = by_repo_packs.entry(entry.repository_id).or_default().entry(entry.pack_id).or_default();
        if entry.role == "pack" {
            slot.0 = Some((entry, local_blob));
        } else if entry.role == "idx" {
            slot.1 = Some((entry, local_blob));
        } else {
            return Err(PairedBackupError::BlobClosureIncomplete(format!("unexpected role {}", entry.role)));
        }
    }

    let wal_path = work_dir.join("restored-raft.wal");
    if wal_path.exists() {
        fs::remove_file(&wal_path)?;
    }
    let mut wal_raft = WalSyncedRaftBackend::open_group(&wal_path, manifest.raft_cutpoint.group_id, 1)?;
    let mut specs = Vec::with_capacity(manifest.pg_cutpoint.repositories.len());

    for repo in &manifest.pg_cutpoint.repositories {
        let pack_map = by_repo_packs.get(&repo.repository_id).ok_or_else(|| {
            PairedBackupError::BlobClosureIncomplete(format!("missing packs for repo {}", repo.repository_id))
        })?;
        let mut pairs = Vec::with_capacity(pack_map.len());
        let mut expected_packs = Vec::with_capacity(pack_map.len());
        for (&pack_id, (p, i)) in pack_map {
            let (pe, pp) =
                p.as_ref().ok_or_else(|| PairedBackupError::BlobClosureIncomplete("missing .pack in repo".into()))?;
            let (ie, ip) =
                i.as_ref().ok_or_else(|| PairedBackupError::BlobClosureIncomplete("missing .idx in repo".into()))?;
            let uploaded = upload_pack_pair(
                target_store,
                UploadScope {
                    tenant_id: repo.tenant_id,
                    authority_id: inc.new_storage_authority_id,
                    generation: inc.new_storage_generation,
                },
                pp,
                ip,
                deadline,
            )
            .await
            .map_err(|e| PairedBackupError::Blob(e.to_string()))?;
            if uploaded.pack_receipt.backend_identity() != target_store.backend_identity()
                || uploaded.idx_receipt.backend_identity() != target_store.backend_identity()
            {
                return Err(PairedBackupError::BackendIdentityMismatch {
                    expected: target_backend.to_owned(),
                    actual: uploaded.pack_receipt.backend_identity().as_hex().to_owned(),
                });
            }
            if uploaded.pack_sha256 != pe.sha256
                || uploaded.pack_length != pe.length
                || uploaded.idx_sha256 != ie.sha256
                || uploaded.idx_length != ie.length
            {
                return Err(PairedBackupError::CorruptBlobOrDigest(
                    "target Blob store upload readback mismatch".into(),
                ));
            }
            restored_blobs += 2;
            pairs.push((pp.clone(), ip.clone()));
            expected_packs.push(ExpectedPackPairSpec {
                pack_id,
                pack_sha256: pe.sha256.clone(),
                pack_bytes: pe.length,
                idx_sha256: ie.sha256.clone(),
                idx_bytes: ie.length,
            });
        }

        let repo_work = work_dir.join(repo.repository_id.to_string());
        let clone_dir = repo_work.join("clone-check");
        git_verified_refs +=
            verify_bare_repo_from_blobs(&repo_work, repo.object_format, &repo.refs, &pairs, &clone_dir)?;

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
            inc.new_history_incarnation,
            inc.new_authority_epoch,
            inc.new_group_epoch,
            RefName::branch(&head_branch).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?,
        )
        .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let (_, init_resp) = wal_raft.commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&init),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::ServingRefStore,
            authz_floor: inc.new_authz_floor,
        }))?;
        super::format30_pg_raft_sync::ensure_raft_gate_initialized(&init_resp, "format30 restore")?;

        let mut updates = Vec::with_capacity(repo.refs.len());
        for (k, v) in &repo.refs {
            let rn = RefName::new(k).map_err(|e| PairedBackupError::GitVerificationFailed(e.to_string()))?;
            let oid = crate::ref_store::GitOid::parse(repo.object_format, v)
                .map_err(|e| PairedBackupError::GitVerificationFailed(e.to_string()))?;
            updates.push(RefUpdate::new(rn, RefPrecondition::Absent, RefTarget::Oid(oid)));
        }
        let lane = IssuerLane::new("paired-restore").map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        // `CommitRefs` admits at most `MAX_REFS_PER_COMMIT` refs per command, so a restored
        // repository holding more archived refs replays as ordered commits that each advance the
        // freshly initialized gate revision by exactly one.
        for (chunk_idx, chunk) in updates.chunks(crate::ref_store::core::pack_commit::MAX_PLAN_REFS).enumerate() {
            let index = chunk_idx as i64 + 1;
            let req = CommitRefsRequest::new(
                repo.repository_id,
                repo.tenant_id,
                Uuid::new_v4(),
                lane.clone(),
                index,
                Uuid::new_v4(),
                repo.object_format,
                inc.new_history_incarnation,
                inc.new_authority_epoch,
                inc.new_group_epoch,
                index,
                HeadUpdate::Keep,
                CommitMode::Atomic,
                chunk.to_vec(),
            )
            .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
            let (_, commit_resp) = wal_raft.commit_and_apply(RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req),
                decision_id: None,
                required_holds: Vec::new(),
                policy_rejects: BTreeMap::new(),
                logical_tick: (inc.new_authz_floor as u64).saturating_add(chunk_idx as u64),
            }))?;
            super::format30_pg_raft_sync::ensure_raft_commit_refs_committed(&commit_resp, "format30 restore")?;
        }

        specs.push(RepoBackupRegistrationSpec {
            repository_id: repo.repository_id,
            tenant_id: repo.tenant_id,
            owner_id: repo.tenant_id,
            object_format: repo.object_format,
            history_incarnation: inc.new_history_incarnation,
            authority_epoch: inc.new_authority_epoch,
            group_epoch: inc.new_group_epoch,
            authority_id: inc.new_storage_authority_id,
            authority_generation: inc.new_storage_generation,
            backend_identity: target_backend.to_owned(),
            expected_packs,
        });
    }

    let coord = TriPartyBackupCoordinator::new(inc.new_deleter_epoch.saturating_sub(1), 0);
    let mut restore_receipts = Vec::new();
    for spec in &specs {
        coord.register_backup_closure_hold(&mut wal_raft, spec, &mut restore_receipts)?;
    }
    let (durable_snap, _) = wal_raft.durable_state()?;
    durable_snap.verify_integrity().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;

    let restored_peers = restore_peer_groups_state(work_dir, &manifest.raft_cutpoint.peer_groups, &inc)?;
    let guard = IncarnationAdmissionGuard { live: inc.clone() };
    let outcome = RestoreOutcome {
        backup_id: manifest.backup_id,
        restored_repos: manifest.pg_cutpoint.repositories.len(),
        restored_blobs,
        reused_blobs: 0,
        git_verified_refs,
        incarnation: inc,
    };
    Ok((outcome, wal_raft.into_state_machine(), guard, restored_peers))
}

/// Clean-room restore also persisting new-incarnation state, `authz_floor` + `deleter_epoch`
/// floors, and verified active + peer `group_epoch` cursors into PostgreSQL 17.
pub async fn restore_new_incarnation_with_pg(
    source: &Path,
    work_dir: &Path,
    target_store: &BlobStore,
    pg_client: &mut Client,
    scope: &RestoreTargetScope,
    deadline: Instant,
) -> Result<(RestoreOutcome, RefCasStateMachine, IncarnationAdmissionGuard), PairedBackupError> {
    let manifest = verify_backup_archive(source, scope.expected_backend_identity.as_deref())?;
    let (outcome, sm, guard, restored_peers) =
        restore_new_incarnation_full(source, work_dir, target_store, scope, deadline).await?;
    let restored_snap = sm.snapshot().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    install_restored_pg_incarnation(
        pg_client,
        &manifest,
        &outcome.incarnation,
        manifest.raft_cutpoint.group_id,
        &restored_snap,
        &restored_peers,
    )
    .await?;
    verify_pg_restored_cursors(pg_client, manifest.raft_cutpoint.group_id, &restored_snap, &restored_peers).await?;
    Ok((outcome, sm, guard))
}
