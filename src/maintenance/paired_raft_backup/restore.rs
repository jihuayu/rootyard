//! Archive verification, clean-room new-incarnation restore, stock-Git clone/fsck,
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
    AppliedLogId, CommitRefsCommand, InitializeGateCommand, RefCasCommand, RefCasStateMachine, RepositoryLane,
    SmPackMode, WireCommitRefsRequest, WireGateInit,
};
use crate::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, HeadUpdate, IssuerLane, RefName, RefPrecondition, RefTarget, RefUpdate,
};

use super::backup::stream_sha256_file;
use super::freeze_drain::{RepoBackupRegistrationSpec, TriPartyBackupCoordinator};
use super::git_verify::verify_bare_repo_from_blobs;
use super::pg_cutpoint::install_restored_pg_incarnation;
use super::types::{
    COMPLETE_MARKER, DecisionExecutionTicket, DeleterLeaseTicket, MANIFEST_FILE, MAX_MANIFEST_BYTES,
    NewIncarnationAuthority, PAIRED_BACKUP_FORMAT_V1, PairedBackupError, PairedBackupManifest, RestoreOutcome,
    WriterGrantTicket,
};

#[derive(Clone, Debug, Default)]
pub struct RestoreTargetScope {
    pub expected_tenant_id: Option<Uuid>,
    pub expected_repository_id: Option<Uuid>,
    pub expected_backend_identity: Option<String>,
}

/// Fail-closed guard loaded into a restored cluster to refuse pre-backup credentials.
#[derive(Clone, Debug)]
pub struct IncarnationAdmissionGuard {
    pub live: NewIncarnationAuthority,
}

impl IncarnationAdmissionGuard {
    pub fn verify_writer_grant(&self, ticket: &WriterGrantTicket) -> Result<(), PairedBackupError> {
        if ticket.cluster_incarnation != self.live.new_cluster_incarnation
            || self.live.fenced_prior_incarnations.contains(&ticket.cluster_incarnation)
        {
            return Err(PairedBackupError::StaleIncarnation {
                field: "cluster_incarnation",
                expected: self.live.new_cluster_incarnation.to_string(),
                got: ticket.cluster_incarnation.to_string(),
            });
        }
        if ticket.history_incarnation != self.live.new_history_incarnation
            || self.live.fenced_prior_incarnations.contains(&ticket.history_incarnation)
        {
            return Err(PairedBackupError::StaleIncarnation {
                field: "history_incarnation",
                expected: self.live.new_history_incarnation.to_string(),
                got: ticket.history_incarnation.to_string(),
            });
        }
        if ticket.authority_epoch < self.live.new_authority_epoch || ticket.group_epoch < self.live.new_group_epoch {
            return Err(PairedBackupError::StaleGrantRefused(
                "authority_epoch or group_epoch from pre-backup incarnation",
            ));
        }
        if ticket.authz_epoch < self.live.new_authz_floor {
            return Err(PairedBackupError::StaleGrantRefused("authz_epoch below restored authz_floor"));
        }
        Ok(())
    }

    pub fn verify_decision_execution(&self, ticket: &DecisionExecutionTicket) -> Result<(), PairedBackupError> {
        if self.live.fenced_pre_backup_decision_ids.contains(&ticket.decision_id) {
            return Err(PairedBackupError::StaleDecisionRefused(ticket.decision_id));
        }
        if ticket.history_incarnation != self.live.new_history_incarnation
            || ticket.authority_epoch < self.live.new_authority_epoch
            || ticket.group_epoch < self.live.new_group_epoch
            || ticket.authz_epoch < self.live.new_authz_floor
        {
            return Err(PairedBackupError::StaleDecisionRefused(ticket.decision_id));
        }
        Ok(())
    }

    pub fn verify_deleter_lease(&self, ticket: &DeleterLeaseTicket) -> Result<(), PairedBackupError> {
        if ticket.cluster_incarnation != self.live.new_cluster_incarnation
            || ticket.storage_authority_id != self.live.new_storage_authority_id
        {
            return Err(PairedBackupError::StaleDeleterRefused("deleter belongs to pre-backup cluster/authority"));
        }
        if ticket.storage_generation < self.live.new_storage_generation
            || ticket.deleter_epoch < self.live.new_deleter_epoch
        {
            return Err(PairedBackupError::StaleDeleterRefused("deleter generation/epoch superseded by restore"));
        }
        Ok(())
    }
}

/// Strictly verify `COMPLETE` seal, manifest integrity, PG <-> Raft cutpoint reconciliation,
/// scope close receipts, backup holds, and every archived Blob member SHA-256 + byte length.
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
    if raft.close_receipts.is_empty() || raft.backup_holds.is_empty() {
        return Err(PairedBackupError::IncompleteCut("manifest missing close barrier receipts or backup holds"));
    }
    for r in &raft.close_receipts {
        r.verify()?;
        if r.raft_log_index > raft.applied_log_id.index || r.raft_log_term != raft.applied_log_id.term {
            return Err(PairedBackupError::CutpointSkew(
                "close receipt Raft index/term disagrees with snapshot".into(),
            ));
        }
    }

    let expected_seq = raft.snapshot.body.next_event_seq.saturating_sub(1) as i64;
    let cursor = manifest
        .pg_cutpoint
        .projection_cursors
        .iter()
        .find(|c| c.group_id == raft.group_id)
        .ok_or_else(|| PairedBackupError::CutpointSkew("missing PG cursor for backed-up Raft group".into()))?;
    if cursor.applied_log_index != raft.applied_log_id.index as i64
        || cursor.applied_log_term != raft.applied_log_id.term as i64
        || cursor.applied_event_seq != expected_seq
    {
        return Err(PairedBackupError::CutpointSkew("PG projection cursor skewed from Raft snapshot index".into()));
    }

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
/// `cluster_incarnation`, bumped epochs & authz_floor), uploading verified blobs into `target_store`,
/// checking real `git clone` + `git fsck --full --strict`, and returning fresh `RefCasStateMachine`.
pub async fn restore_new_incarnation(
    source: &Path,
    work_dir: &Path,
    target_store: &BlobStore,
    scope: &RestoreTargetScope,
    deadline: Instant,
) -> Result<(RestoreOutcome, RefCasStateMachine, IncarnationAdmissionGuard), PairedBackupError> {
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
    let max_grp_e = manifest.pg_cutpoint.repositories.iter().map(|r| r.group_epoch).max().unwrap_or(1);
    let max_floor = manifest.raft_cutpoint.close_receipts.iter().map(|r| r.authz_floor).max().unwrap_or(1);
    let mut fenced_inc = BTreeSet::from([
        manifest.pg_cutpoint.source_cluster_incarnation,
        manifest.pg_cutpoint.source_storage_authority_id,
    ]);
    for r in &manifest.pg_cutpoint.repositories {
        fenced_inc.insert(r.history_incarnation);
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

    let mut new_sm = RefCasStateMachine::new();
    let mut log_idx = 0u64;
    let mut specs = Vec::with_capacity(manifest.pg_cutpoint.repositories.len());

    for repo in &manifest.pg_cutpoint.repositories {
        let pack_map = by_repo_packs.get(&repo.repository_id).ok_or_else(|| {
            PairedBackupError::BlobClosureIncomplete(format!("missing packs for repo {}", repo.repository_id))
        })?;
        let mut pairs = Vec::with_capacity(pack_map.len());
        let mut pack_digests = Vec::new();
        let mut hold_specs = Vec::new();
        for (p, i) in pack_map.values() {
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
            pack_digests.push(pe.sha256.clone());
            let decl = i64::try_from(pe.length.max(1)).unwrap_or(i64::MAX);
            hold_specs.push((pe.sha256.clone(), decl, 512));
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
        log_idx += 1;
        new_sm
            .apply(
                AppliedLogId { term: 1, index: log_idx },
                RefCasCommand::InitializeGate(InitializeGateCommand {
                    gate: WireGateInit::from(&init),
                    pack_mode: SmPackMode::MetadataOnly,
                    lane: RepositoryLane::ServingRefStore,
                    authz_floor: inc.new_authz_floor,
                }),
            )
            .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;

        let mut updates = Vec::with_capacity(repo.refs.len());
        for (k, v) in &repo.refs {
            let rn = RefName::new(k).map_err(|e| PairedBackupError::GitVerificationFailed(e.to_string()))?;
            let oid = crate::ref_store::GitOid::parse(repo.object_format, v)
                .map_err(|e| PairedBackupError::GitVerificationFailed(e.to_string()))?;
            updates.push(RefUpdate::new(rn, RefPrecondition::Absent, RefTarget::Oid(oid)));
        }
        let req = CommitRefsRequest::new(
            repo.repository_id,
            repo.tenant_id,
            Uuid::new_v4(),
            IssuerLane::new("paired-restore").map_err(|e| PairedBackupError::StateMachine(e.to_string()))?,
            1,
            Uuid::new_v4(),
            repo.object_format,
            inc.new_history_incarnation,
            inc.new_authority_epoch,
            inc.new_group_epoch,
            1,
            HeadUpdate::Keep,
            CommitMode::Atomic,
            updates,
        )
        .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        log_idx += 1;
        new_sm
            .apply(
                AppliedLogId { term: 1, index: log_idx },
                RefCasCommand::CommitRefs(CommitRefsCommand {
                    request: WireCommitRefsRequest::from(&req),
                    decision_id: None,
                    required_holds: Vec::new(),
                    policy_rejects: BTreeMap::new(),
                    logical_tick: inc.new_authz_floor as u64,
                }),
            )
            .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;

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
            pack_digests,
            hold_specs,
        });
    }

    let coord = TriPartyBackupCoordinator::new(inc.new_deleter_epoch.saturating_sub(1), 0);
    for spec in &specs {
        coord.register_backup_closure_hold(&mut new_sm, 1, &mut log_idx, spec)?;
    }

    let guard = IncarnationAdmissionGuard { live: inc.clone() };
    let outcome = RestoreOutcome {
        backup_id: manifest.backup_id,
        restored_repos: manifest.pg_cutpoint.repositories.len(),
        restored_blobs,
        reused_blobs: 0,
        git_verified_refs,
        incarnation: inc.clone(),
    };
    Ok((outcome, new_sm, guard))
}

/// Clean-room restore also persisting new-incarnation state into PostgreSQL 17.
pub async fn restore_new_incarnation_with_pg(
    source: &Path,
    work_dir: &Path,
    target_store: &BlobStore,
    pg_client: &mut Client,
    scope: &RestoreTargetScope,
    deadline: Instant,
) -> Result<(RestoreOutcome, RefCasStateMachine, IncarnationAdmissionGuard), PairedBackupError> {
    let manifest = verify_backup_archive(source, scope.expected_backend_identity.as_deref())?;
    let (outcome, sm, guard) = restore_new_incarnation(source, work_dir, target_store, scope, deadline).await?;
    install_restored_pg_incarnation(pg_client, &manifest, &outcome.incarnation).await?;
    Ok((outcome, sm, guard))
}
