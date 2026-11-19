//! Active + peer new-incarnation mTLS Raft replay under rotated epochs, frozen boot records,
//! and server-signed cutpoint verification for the clean-room `format 30` restore (#153).
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::ref_store::core::state_machine::{
    CommitRefsCommand, InitializeGateCommand, RefCasCommand, RepositoryLane, SmPackMode, WireCommitRefsRequest,
    WireGateInit,
};
use crate::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, RefName,
    RefPrecondition, RefTarget, RefUpdate,
};
use uuid::Uuid;

use super::format30_paired::Format30PairedManifest;
use super::freeze_drain::{RepoBackupRegistrationSpec, TriPartyBackupCoordinator};
use super::git_verify::verify_bare_repo_from_blobs;
use super::mtls_raft::{DurableRaftFreezeRecord, MtlsLiveRaftBackend};
use super::peer_groups::PeerRaftCutpointProof;
use super::quorum_wal::DurableRaftBackend;
use super::raft_barrier::verify_cutpoint_attestations;
use super::types::{ExpectedPackPairSpec, NewIncarnationAuthority, PairedBackupError, PgRepositoryRowProof};

pub(super) fn boot_record(
    manifest: &Format30PairedManifest,
    inc: &NewIncarnationAuthority,
    frozen: bool,
    barrier_id: Uuid,
    seal_receipt_digest: Option<String>,
) -> Result<DurableRaftFreezeRecord, PairedBackupError> {
    let repo_access_floors =
        manifest.pg_cutpoint.repositories.iter().map(|r| (r.repository_id, inc.new_authz_floor)).collect();
    DurableRaftFreezeRecord {
        frozen,
        barrier_id,
        fenced_deleter_epoch: inc.new_deleter_epoch,
        app_fence_seq: 1,
        repo_access_floors,
        seal_receipt_digest,
        record_seal: String::new(),
    }
    .seal()
}

/// Replay every restored repository onto the target active Raft group, register its durable
/// backup closure holds, boot each peer group under a rotated realm, and verify every group's
/// server-signed cutpoint while PostgreSQL and all Raft groups are still frozen.
pub(super) fn boot_active_and_peer_mtls_raft_incarnation(
    (fmt30_dir, work_dir): (&Path, &Path),
    manifest: &Format30PairedManifest,
    inc: &NewIncarnationAuthority,
    boot_freeze: &DurableRaftFreezeRecord,
    rebound_packs: &BTreeMap<Uuid, Vec<ExpectedPackPairSpec>>,
    active_raft: &mut MtlsLiveRaftBackend,
    peer_rafts: &mut BTreeMap<i64, MtlsLiveRaftBackend>,
) -> Result<usize, PairedBackupError> {
    active_raft.write_freeze_record(boot_freeze)?;
    peer_rafts.values().try_for_each(|pr| pr.write_freeze_record(boot_freeze).map(|_| ()))?;
    let coord = TriPartyBackupCoordinator::new(inc.new_deleter_epoch.saturating_sub(1), 0);
    let mut git_verified_refs = 0usize;
    for repo in &manifest.pg_cutpoint.repositories {
        let (pairs, archive_packs) = repo_pack_pairs(fmt30_dir, manifest, repo.repository_id)?;
        let expected_packs = rebound_packs.get(&repo.repository_id).cloned().unwrap_or(archive_packs);
        let rw = work_dir.join(repo.repository_id.to_string());
        git_verified_refs += verify_bare_repo_from_blobs(&rw, repo.object_format, &repo.refs, &pairs, &rw.join("cl"))?;
        replay_repo_onto_booted_raft(active_raft, repo, inc)?;
        let spec = RepoBackupRegistrationSpec {
            repository_id: repo.repository_id,
            tenant_id: repo.tenant_id,
            owner_id: repo.tenant_id,
            object_format: repo.object_format,
            history_incarnation: inc.new_history_incarnation,
            authority_epoch: inc.new_authority_epoch,
            group_epoch: inc.new_group_epoch,
            authority_id: inc.new_storage_authority_id,
            authority_generation: inc.new_storage_generation,
            backend_identity: manifest.blob_closure.backend_identity.clone(),
            expected_packs,
        };
        let mut reg_recs = Vec::new();
        coord.register_backup_closure_hold(active_raft, &spec, &mut reg_recs)?;
    }
    active_raft.write_incarnation_record(inc)?;
    verify_booted_group(active_raft, inc.new_group_epoch)?;
    for peer in &manifest.raft_cutpoint.peer_groups {
        let pr = peer_rafts
            .get_mut(&peer.group_id)
            .ok_or(PairedBackupError::IncompleteCut("missing booted 3-voter mTLS Raft cluster for peer group"))?;
        boot_single_peer_mtls_raft(pr, peer, inc)?;
        verify_booted_group(pr, inc.new_group_epoch)?;
    }
    Ok(git_verified_refs)
}
fn repo_pack_pairs(
    fmt30_dir: &Path,
    manifest: &Format30PairedManifest,
    repository_id: Uuid,
) -> Result<(Vec<(PathBuf, PathBuf)>, Vec<ExpectedPackPairSpec>), PairedBackupError> {
    let entries = &manifest.blob_closure.entries;
    let mut pairs = Vec::new();
    let mut specs = Vec::new();
    for pack in entries.iter().filter(|e| e.repository_id == repository_id && e.role == "pack") {
        let idx = entries
            .iter()
            .find(|e| e.repository_id == repository_id && e.pack_id == pack.pack_id && e.role == "idx")
            .ok_or_else(|| PairedBackupError::BlobClosureIncomplete("restored repo missing .idx".into()))?;
        pairs.push((fmt30_dir.join(&pack.archive_rel_path), fmt30_dir.join(&idx.archive_rel_path)));
        specs.push(ExpectedPackPairSpec {
            pack_id: pack.pack_id,
            pack_sha256: pack.sha256.clone(),
            pack_bytes: pack.length,
            idx_sha256: idx.sha256.clone(),
            idx_bytes: idx.length,
        });
    }
    Ok((pairs, specs))
}

struct ReplayGate<'a> {
    repository_id: Uuid,
    tenant_id: Uuid,
    object_format: GitObjectFormat,
    head_ref: &'a str,
    pack_mode: SmPackMode,
    lane: RepositoryLane,
    refs: &'a BTreeMap<String, String>,
}

fn repo_head_ref(refs: &BTreeMap<String, String>) -> &str {
    refs.keys()
        .find(|k| k.as_str() == "refs/heads/main")
        .or_else(|| refs.keys().find(|k| k.starts_with("refs/heads/")))
        .map_or("refs/heads/main", String::as_str)
}

fn replay_repo_onto_booted_raft(
    raft: &mut MtlsLiveRaftBackend,
    repo: &PgRepositoryRowProof,
    inc: &NewIncarnationAuthority,
) -> Result<(), PairedBackupError> {
    replay_gate(
        raft,
        ReplayGate {
            repository_id: repo.repository_id,
            tenant_id: repo.tenant_id,
            object_format: repo.object_format,
            head_ref: repo_head_ref(&repo.refs),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::ServingRefStore,
            refs: &repo.refs,
        },
        inc.new_history_incarnation,
        inc.new_authority_epoch,
        inc.new_group_epoch,
        inc.new_authz_floor,
    )
}

fn replay_gate(
    raft: &mut MtlsLiveRaftBackend,
    gate: ReplayGate<'_>,
    history: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    authz_floor: i64,
) -> Result<(), PairedBackupError> {
    let init = CoreGateInit::new(
        gate.repository_id,
        gate.tenant_id,
        gate.object_format,
        history,
        authority_epoch,
        group_epoch,
        RefName::branch(gate.head_ref).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?,
    )
    .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    raft.commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
        gate: WireGateInit::from(&init),
        pack_mode: gate.pack_mode,
        lane: gate.lane,
        authz_floor,
    }))?;
    if gate.refs.is_empty() {
        return Ok(());
    }
    let mut updates = Vec::with_capacity(gate.refs.len());
    for (name, oid) in gate.refs {
        updates.push(RefUpdate::new(
            RefName::new(name).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?,
            RefPrecondition::Absent,
            RefTarget::Oid(
                GitOid::parse(gate.object_format, oid).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?,
            ),
        ));
    }
    let lane =
        IssuerLane::new("paired-format30-restore").map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    let req = CommitRefsRequest::new(
        gate.repository_id,
        gate.tenant_id,
        Uuid::new_v4(),
        lane,
        1,
        Uuid::new_v4(),
        gate.object_format,
        history,
        authority_epoch,
        group_epoch,
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
    Ok(())
}

fn boot_single_peer_mtls_raft(
    raft: &mut MtlsLiveRaftBackend,
    peer: &PeerRaftCutpointProof,
    inc: &NewIncarnationAuthority,
) -> Result<(), PairedBackupError> {
    for gate in &peer.snapshot.body.gates {
        let refs = peer
            .snapshot
            .body
            .refs
            .iter()
            .find(|r| r.repository_id == gate.repository_id)
            .map(|r| &r.refs)
            .unwrap_or(&EMPTY_REFS);
        replay_gate(
            raft,
            ReplayGate {
                repository_id: gate.repository_id,
                tenant_id: gate.tenant_id,
                object_format: gate.object_format,
                head_ref: &gate.head_ref,
                pack_mode: gate.pack_mode,
                lane: gate.lane,
                refs,
            },
            inc.new_history_incarnation,
            inc.new_authority_epoch,
            inc.new_group_epoch,
            inc.new_authz_floor,
        )?;
    }
    raft.write_incarnation_record(inc)?;
    Ok(())
}
static EMPTY_REFS: BTreeMap<String, String> = BTreeMap::new();
fn verify_booted_group(raft: &MtlsLiveRaftBackend, group_epoch: i64) -> Result<(), PairedBackupError> {
    let (snapshot, state_digest) = raft.durable_state()?;
    let applied =
        snapshot.body.last_applied.ok_or(PairedBackupError::IncompleteCut("booted Raft group has no applied entry"))?;
    let attestations = raft.attest_group_cutpoint(group_epoch, &snapshot, &state_digest)?;
    verify_cutpoint_attestations(
        raft.group_id(),
        group_epoch,
        &raft.voter_ids(),
        &raft.group_membership_digest(),
        applied,
        &state_digest,
        &snapshot.checksum,
        &attestations,
    )
}
