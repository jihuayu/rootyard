//! Durable peer-group Raft cutpoint proofs, cursor epoch/index verification,
//! and clean-room multi-group Raft state restoration (#153).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, CommitRefsCommand, InitializeGateCommand, RefCasCommand, RefCasSnapshot, RefCasStateMachine,
    WireCommitRefsRequest, WireGateInit,
};
use crate::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitOid, HeadUpdate, IssuerLane, RefName, RefPrecondition, RefTarget,
    RefUpdate,
};

use super::closure_bind::extract_raft_group_realm;
use super::quorum_wal::{DurableRaftBackend, WalSyncedRaftBackend};
use super::raft_barrier::DurableFreezeBarrierProof;
use super::types::{NewIncarnationAuthority, PairedBackupError, PgCutpointProof};

pub struct PeerGroupBackupInput<'a> {
    pub group_id: i64,
    pub freeze_barrier: &'a DurableFreezeBarrierProof,
    pub raft: &'a dyn DurableRaftBackend,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerRaftCutpointProof {
    pub group_id: i64,
    pub history_incarnation: Uuid,
    pub group_epoch: i64,
    pub applied_log_id: AppliedLogId,
    pub applied_event_seq: u64,
    pub logical_clock_floor: u64,
    pub state_digest: String,
    pub group_membership_digest: String,
    pub snapshot_checksum: String,
    pub snapshot: RefCasSnapshot,
    pub freeze_barrier: DurableFreezeBarrierProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedGroupCursorCut {
    pub group_id: i64,
    pub history_incarnation: Uuid,
    pub group_epoch: i64,
    pub applied_index: u64,
    pub applied_term: u64,
    pub applied_event_seq: u64,
}

impl ExpectedGroupCursorCut {
    pub fn from_verified_snapshot(group_id: i64, snap: &RefCasSnapshot) -> Result<Self, PairedBackupError> {
        let (history_incarnation, group_epoch) = extract_raft_group_realm(snap)?;
        let applied = snap
            .body
            .last_applied
            .ok_or(PairedBackupError::IncompleteCut("durable Raft snapshot missing last_applied"))?;
        Ok(Self {
            group_id,
            history_incarnation,
            group_epoch,
            applied_index: applied.index,
            applied_term: applied.term,
            applied_event_seq: snap.body.next_event_seq,
        })
    }
}

/// Extract verified cursor cuts and `PeerRaftCutpointProof`s from live durable peer Raft backends.
pub fn extract_peer_expected_cuts(
    active_group_id: i64,
    peers: &[PeerGroupBackupInput<'_>],
) -> Result<(Vec<ExpectedGroupCursorCut>, Vec<PeerRaftCutpointProof>), PairedBackupError> {
    let mut seen_groups = BTreeSet::from([active_group_id]);
    let mut cuts = Vec::with_capacity(peers.len());
    let mut proofs = Vec::with_capacity(peers.len());

    for peer in peers {
        if peer.group_id < 0 || !seen_groups.insert(peer.group_id) {
            return Err(PairedBackupError::CutpointSkew(format!(
                "duplicate or invalid peer Raft group_id {}",
                peer.group_id
            )));
        }
        if peer.raft.group_id() != peer.group_id {
            return Err(PairedBackupError::CutpointSkew("PeerGroupBackupInput group_id mismatches backend".into()));
        }
        let (snap, state_digest) = peer.raft.durable_state()?;
        let committed_idx = peer.raft.committed_quorum_index()?;
        let mem_digest = peer.raft.group_membership_digest();
        peer.freeze_barrier.verify_against_raft_group(peer.group_id, &mem_digest, &snap, &state_digest, false)?;
        if committed_idx < peer.freeze_barrier.barrier_log_id.index {
            return Err(PairedBackupError::FreezeNotHeld("peer Raft quorum_commit_index behind freeze barrier"));
        }
        let cut = ExpectedGroupCursorCut::from_verified_snapshot(peer.group_id, &snap)?;
        let applied_log_id = AppliedLogId { term: cut.applied_term, index: cut.applied_index };
        proofs.push(PeerRaftCutpointProof {
            group_id: peer.group_id,
            history_incarnation: cut.history_incarnation,
            group_epoch: cut.group_epoch,
            applied_log_id,
            applied_event_seq: cut.applied_event_seq,
            logical_clock_floor: snap.body.logical_clock_floor,
            state_digest,
            group_membership_digest: mem_digest,
            snapshot_checksum: snap.checksum.clone(),
            snapshot: snap,
            freeze_barrier: peer.freeze_barrier.clone(),
        });
        cuts.push(cut);
    }
    Ok((cuts, proofs))
}

/// Independently verify every archived `PeerRaftCutpointProof` snapshot, checksum, `state_digest`,
/// `QuorumCommitReceipt`s, `LocalWalApplyReceipt`s, `CloseScopeBarrierReceipt`s, and `group_epochs`.
pub fn verify_archived_peer_groups(
    active_group_id: i64,
    active_epoch: i64,
    group_epochs: &BTreeMap<i64, i64>,
    peers: &[PeerRaftCutpointProof],
) -> Result<Vec<ExpectedGroupCursorCut>, PairedBackupError> {
    if group_epochs.len() != 1 + peers.len() || group_epochs.get(&active_group_id) != Some(&active_epoch) {
        return Err(PairedBackupError::CutpointSkew(
            "manifest group_epochs disagrees with active or peer durable Raft cutpoints".into(),
        ));
    }
    let mut seen_groups = BTreeSet::from([active_group_id]);
    let mut cuts = Vec::with_capacity(peers.len());
    for peer in peers {
        if peer.group_id < 0 || !seen_groups.insert(peer.group_id) {
            return Err(PairedBackupError::CutpointSkew("duplicate or invalid peer group_id in manifest".into()));
        }
        peer.snapshot.verify_integrity().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        if peer.snapshot.checksum != peer.snapshot_checksum
            || peer.snapshot.body.last_applied != Some(peer.applied_log_id)
            || peer.snapshot.body.logical_clock_floor != peer.logical_clock_floor
        {
            return Err(PairedBackupError::CutpointSkew("peer Raft snapshot checksum or log_id mismatch".into()));
        }
        let rebuilt =
            RefCasStateMachine::restore(&peer.snapshot).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let actual_digest = rebuilt.state_digest().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        if actual_digest != peer.state_digest {
            return Err(PairedBackupError::CutpointSkew("peer Raft state_digest mismatches snapshot".into()));
        }
        peer.freeze_barrier.verify_against_raft_group(
            peer.group_id,
            &peer.group_membership_digest,
            &peer.snapshot,
            &peer.state_digest,
            false,
        )?;
        let cut = ExpectedGroupCursorCut::from_verified_snapshot(peer.group_id, &peer.snapshot)?;
        if peer.history_incarnation != cut.history_incarnation
            || peer.group_epoch != cut.group_epoch
            || peer.applied_event_seq != cut.applied_event_seq
            || group_epochs.get(&peer.group_id) != Some(&cut.group_epoch)
        {
            return Err(PairedBackupError::CutpointSkew(format!(
                "peer group {} metadata or group_epochs disagrees with verified durable Raft snapshot",
                peer.group_id
            )));
        }
        cuts.push(cut);
    }
    Ok(cuts)
}

/// Verify PG <-> Raft cursor `(history_incarnation, group_epoch, index, term, event_seq)` equality
/// across the active group AND every verified peer Raft group.
pub fn verify_all_group_cursors(
    pg: &PgCutpointProof,
    active_cut: &ExpectedGroupCursorCut,
    peer_cuts: &[ExpectedGroupCursorCut],
) -> Result<(), PairedBackupError> {
    let total_expected = 1 + peer_cuts.len();
    if pg.projection_cursors.len() != total_expected {
        return Err(PairedBackupError::CutpointSkew(format!(
            "PG projection_cursors count ({}) != verified Raft group count ({total_expected})",
            pg.projection_cursors.len()
        )));
    }
    let mut seen_pg_groups = BTreeSet::new();
    for cur in &pg.projection_cursors {
        if !seen_pg_groups.insert(cur.group_id) || cur.stream_state != "active" || cur.group_epoch <= 0 {
            return Err(PairedBackupError::CutpointSkew("duplicate or inactive PG projection cursor".into()));
        }
    }
    for cut in std::iter::once(active_cut).chain(peer_cuts.iter()) {
        let cur = pg.projection_cursors.iter().find(|c| c.group_id == cut.group_id).ok_or_else(|| {
            PairedBackupError::CutpointSkew(format!("PG cursor missing for Raft group {}", cut.group_id))
        })?;
        if cur.history_incarnation != cut.history_incarnation
            || cur.group_epoch != cut.group_epoch
            || cur.applied_log_index != cut.applied_index as i64
            || cur.applied_log_term != cut.applied_term as i64
            || cur.applied_event_seq != cut.applied_event_seq as i64
        {
            return Err(PairedBackupError::CutpointSkew(format!(
                "PG cursor group {} (inc={}, grp_epoch={}, term={}, idx={}, seq={}) skewed from durable Raft cut (inc={}, grp_epoch={}, term={}, idx={}, seq={})",
                cut.group_id,
                cur.history_incarnation,
                cur.group_epoch,
                cur.applied_log_term,
                cur.applied_log_index,
                cur.applied_event_seq,
                cut.history_incarnation,
                cut.group_epoch,
                cut.applied_term,
                cut.applied_index,
                cut.applied_event_seq,
            )));
        }
    }
    for repo in &pg.repositories {
        if repo.history_incarnation != active_cut.history_incarnation || repo.group_epoch != active_cut.group_epoch {
            return Err(PairedBackupError::CutpointSkew(format!(
                "PG repository {} realm skewed from active durable Raft group",
                repo.repository_id
            )));
        }
    }
    Ok(())
}

/// Restore every peer Raft group's durable state under the fresh incarnation via 3-voter WAL.
pub fn restore_peer_groups_state(
    work_dir: &Path,
    peers: &[PeerRaftCutpointProof],
    inc: &NewIncarnationAuthority,
) -> Result<BTreeMap<i64, RefCasSnapshot>, PairedBackupError> {
    let mut out = BTreeMap::new();
    for peer in peers {
        let wal_path = work_dir.join(format!("restored-peer-{}.wal", peer.group_id));
        if wal_path.exists() {
            fs::remove_file(&wal_path)?;
        }
        let mut wal_raft = WalSyncedRaftBackend::open_group(&wal_path, peer.group_id, 1)?;
        for gate in &peer.snapshot.body.gates {
            let init = CoreGateInit::new(
                gate.repository_id,
                gate.tenant_id,
                gate.object_format,
                inc.new_history_incarnation,
                inc.new_authority_epoch,
                inc.new_group_epoch,
                RefName::branch(&gate.head_ref).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?,
            )
            .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
            wal_raft.commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
                gate: WireGateInit::from(&init),
                pack_mode: gate.pack_mode,
                lane: gate.lane,
                authz_floor: inc.new_authz_floor,
            }))?;

            if let Some(repo_refs) = peer.snapshot.body.refs.iter().find(|r| r.repository_id == gate.repository_id)
                && !repo_refs.refs.is_empty()
            {
                let mut updates = Vec::with_capacity(repo_refs.refs.len());
                for (k, v) in &repo_refs.refs {
                    let rn = RefName::new(k).map_err(|e| PairedBackupError::GitVerificationFailed(e.to_string()))?;
                    let oid = GitOid::parse(gate.object_format, v)
                        .map_err(|e| PairedBackupError::GitVerificationFailed(e.to_string()))?;
                    updates.push(RefUpdate::new(rn, RefPrecondition::Absent, RefTarget::Oid(oid)));
                }
                let req = CommitRefsRequest::new(
                    gate.repository_id,
                    gate.tenant_id,
                    Uuid::new_v4(),
                    IssuerLane::new("paired-peer-restore")
                        .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?,
                    1,
                    Uuid::new_v4(),
                    gate.object_format,
                    inc.new_history_incarnation,
                    inc.new_authority_epoch,
                    inc.new_group_epoch,
                    1,
                    HeadUpdate::Keep,
                    CommitMode::Atomic,
                    updates,
                )
                .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
                wal_raft.commit_and_apply(RefCasCommand::CommitRefs(CommitRefsCommand {
                    request: WireCommitRefsRequest::from(&req),
                    decision_id: None,
                    required_holds: Vec::new(),
                    policy_rejects: BTreeMap::new(),
                    logical_tick: inc.new_authz_floor as u64,
                }))?;
            }
        }
        let (snap, _) = wal_raft.durable_state()?;
        snap.verify_integrity().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        out.insert(peer.group_id, snap);
    }
    Ok(out)
}
