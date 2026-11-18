//! Quorum commit receipts, local WAL apply receipts, freeze barrier proofs,
//! and verified archive sealing receipts constraining freeze/thaw (#153).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{AppliedLogId, RefCasSnapshot, ScopeLifecycle, SmHoldState, SmRootState};

use super::quorum_wal::DurableRaftBackend;
use super::types::{
    BackupRetentionHoldRecord, CloseScopeBarrierReceipt, FreezePartyStatus, PairedBackupError, sha256_json_tagged,
    validate_hex64,
};

pub const MIN_QUORUM_VOTERS: usize = 3;

/// Compute canonical 64-hex `group_membership_digest` over sorted unique voter UUIDs (`>= 3`).
pub fn compute_group_membership_digest(voter_ids: &[Uuid]) -> Result<String, PairedBackupError> {
    if voter_ids.len() < MIN_QUORUM_VOTERS {
        return Err(PairedBackupError::FreezeNotHeld("Raft group requires >= 3 distinct voters for quorum proof"));
    }
    let mut sorted = voter_ids.to_vec();
    sorted.sort();
    let mut uniq = BTreeSet::new();
    for v in &sorted {
        if v.is_nil() || !uniq.insert(*v) {
            return Err(PairedBackupError::FreezeNotHeld("Raft group voter_ids contain nil or duplicate voter"));
        }
    }
    sha256_json_tagged(b"rootyard-raft-voters-v1", &sorted)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VoterWalAck {
    pub voter_id: Uuid,
    pub log_id: AppliedLogId,
    pub command_sha256: String,
    pub wal_record_digest: String,
    pub ack_digest: String,
}

impl VoterWalAck {
    pub fn seal(mut self) -> Result<Self, PairedBackupError> {
        self.ack_digest.clear();
        self.ack_digest = sha256_json_tagged(b"rootyard-voter-wal-ack-v1", &self)?;
        Ok(self)
    }

    pub fn verify(&self, expected_log_id: AppliedLogId, expected_cmd_sha256: &str) -> Result<(), PairedBackupError> {
        if self.voter_id.is_nil()
            || self.log_id != expected_log_id
            || self.command_sha256 != expected_cmd_sha256
            || !validate_hex64(&self.command_sha256)
            || !validate_hex64(&self.wal_record_digest)
        {
            return Err(PairedBackupError::FreezeNotHeld("invalid VoterWalAck fields or log/command mismatch"));
        }
        let mut clean = self.clone();
        clean.ack_digest.clear();
        if sha256_json_tagged(b"rootyard-voter-wal-ack-v1", &clean)? != self.ack_digest {
            return Err(PairedBackupError::FreezeNotHeld("VoterWalAck digest tampered"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuorumCommitReceipt {
    pub group_id: i64,
    pub group_epoch: i64,
    pub group_membership_digest: String,
    pub voter_ids: Vec<Uuid>,
    pub log_id: AppliedLogId,
    pub command_sha256: String,
    pub voter_acks: Vec<VoterWalAck>,
    pub quorum_digest: String,
}

impl QuorumCommitReceipt {
    pub fn seal(mut self) -> Result<Self, PairedBackupError> {
        self.quorum_digest.clear();
        self.quorum_digest = sha256_json_tagged(b"rootyard-quorum-commit-receipt-v1", &self)?;
        Ok(self)
    }

    pub fn verify(&self) -> Result<(), PairedBackupError> {
        if self.group_id < 0 || self.group_epoch <= 0 || !validate_hex64(&self.command_sha256) {
            return Err(PairedBackupError::FreezeNotHeld("QuorumCommitReceipt has invalid group/epoch/command digest"));
        }
        if compute_group_membership_digest(&self.voter_ids)? != self.group_membership_digest {
            return Err(PairedBackupError::FreezeNotHeld("QuorumCommitReceipt group_membership_digest mismatch"));
        }
        let allowed: BTreeSet<Uuid> = self.voter_ids.iter().copied().collect();
        let mut seen_voters = BTreeSet::new();
        for ack in &self.voter_acks {
            if !allowed.contains(&ack.voter_id) || !seen_voters.insert(ack.voter_id) {
                return Err(PairedBackupError::FreezeNotHeld(
                    "QuorumCommitReceipt contains unauthorized or duplicate voter ack",
                ));
            }
            ack.verify(self.log_id, &self.command_sha256)?;
        }
        if self.voter_acks.len() <= self.voter_ids.len() / 2 {
            return Err(PairedBackupError::FreezeNotHeld(
                "consensus majority quorum not reached; refusing uncommitted WAL entry",
            ));
        }
        let mut clean = self.clone();
        clean.quorum_digest.clear();
        if sha256_json_tagged(b"rootyard-quorum-commit-receipt-v1", &clean)? != self.quorum_digest {
            return Err(PairedBackupError::FreezeNotHeld("QuorumCommitReceipt digest tampered"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalWalApplyReceipt {
    pub local_node_id: Uuid,
    pub group_id: i64,
    pub log_id: AppliedLogId,
    pub command_sha256: String,
    pub local_wal_record_digest: String,
    pub committed_index_on_disk: u64,
    pub state_digest_after_apply: String,
    pub apply_digest: String,
}

impl LocalWalApplyReceipt {
    pub fn seal(mut self) -> Result<Self, PairedBackupError> {
        self.apply_digest.clear();
        self.apply_digest = sha256_json_tagged(b"rootyard-local-wal-apply-v1", &self)?;
        Ok(self)
    }

    pub fn verify(&self, quorum: &QuorumCommitReceipt) -> Result<(), PairedBackupError> {
        if self.local_node_id.is_nil()
            || !quorum.voter_ids.contains(&self.local_node_id)
            || self.group_id != quorum.group_id
            || self.log_id != quorum.log_id
            || self.command_sha256 != quorum.command_sha256
            || self.committed_index_on_disk < self.log_id.index
            || !validate_hex64(&self.local_wal_record_digest)
            || !validate_hex64(&self.state_digest_after_apply)
        {
            return Err(PairedBackupError::FreezeNotHeld(
                "LocalWalApplyReceipt lags or mismatches verified QuorumCommitReceipt",
            ));
        }
        let mut clean = self.clone();
        clean.apply_digest.clear();
        if sha256_json_tagged(b"rootyard-local-wal-apply-v1", &clean)? != self.apply_digest {
            return Err(PairedBackupError::FreezeNotHeld("LocalWalApplyReceipt digest tampered"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableRaftApplyReceipt {
    pub log_id: AppliedLogId,
    pub quorum_receipt: QuorumCommitReceipt,
    pub local_apply_receipt: LocalWalApplyReceipt,
    pub receipt_digest: String,
}

impl DurableRaftApplyReceipt {
    pub fn seal(mut self) -> Result<Self, PairedBackupError> {
        self.receipt_digest.clear();
        self.receipt_digest = sha256_json_tagged(b"rootyard-durable-raft-apply-v2", &self)?;
        Ok(self)
    }

    pub fn verify(
        &self,
        expected_group_id: Option<i64>,
        expected_membership_digest: Option<&str>,
    ) -> Result<(), PairedBackupError> {
        self.quorum_receipt.verify()?;
        self.local_apply_receipt.verify(&self.quorum_receipt)?;
        if self.log_id != self.quorum_receipt.log_id {
            return Err(PairedBackupError::FreezeNotHeld("DurableRaftApplyReceipt log_id mismatch"));
        }
        if let Some(gid) = expected_group_id
            && self.quorum_receipt.group_id != gid
        {
            return Err(PairedBackupError::FreezeNotHeld("DurableRaftApplyReceipt group_id mismatch"));
        }
        if let Some(mem) = expected_membership_digest
            && self.quorum_receipt.group_membership_digest != mem
        {
            return Err(PairedBackupError::FreezeNotHeld("DurableRaftApplyReceipt membership digest mismatch"));
        }
        let mut clean = self.clone();
        clean.receipt_digest.clear();
        if sha256_json_tagged(b"rootyard-durable-raft-apply-v2", &clean)? != self.receipt_digest {
            return Err(PairedBackupError::FreezeNotHeld("DurableRaftApplyReceipt digest tampered"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableFreezeBarrierProof {
    pub barrier_id: Uuid,
    pub group_id: i64,
    pub group_membership_digest: String,
    pub status: FreezePartyStatus,
    pub barrier_log_id: AppliedLogId,
    pub barrier_state_digest: String,
    pub apply_receipts: Vec<DurableRaftApplyReceipt>,
    pub close_receipts: Vec<CloseScopeBarrierReceipt>,
    pub backup_holds: Vec<BackupRetentionHoldRecord>,
    pub proof_digest: String,
}

impl DurableFreezeBarrierProof {
    pub fn seal(mut self) -> Result<Self, PairedBackupError> {
        self.proof_digest.clear();
        self.proof_digest = sha256_json_tagged(b"rootyard-durable-freeze-barrier-v2", &self)?;
        Ok(self)
    }

    pub fn verify(&self) -> Result<(), PairedBackupError> {
        self.verify_inner(true)
    }

    pub(super) fn verify_inner(&self, require_holds: bool) -> Result<(), PairedBackupError> {
        self.status.require_frozen()?;
        if self.barrier_id.is_nil()
            || self.group_id < 0
            || !validate_hex64(&self.group_membership_digest)
            || !validate_hex64(&self.barrier_state_digest)
            || self.apply_receipts.is_empty()
            || self.close_receipts.is_empty()
            || (require_holds && self.backup_holds.is_empty())
        {
            return Err(PairedBackupError::FreezeNotHeld("incomplete durable freeze barrier proof"));
        }
        for r in &self.apply_receipts {
            r.verify(Some(self.group_id), Some(&self.group_membership_digest))?;
        }
        for cr in &self.close_receipts {
            cr.verify()?;
        }
        let last_rec = self
            .apply_receipts
            .last()
            .ok_or(PairedBackupError::FreezeNotHeld("missing final apply receipt in barrier"))?;
        if last_rec.log_id != self.barrier_log_id
            || last_rec.local_apply_receipt.state_digest_after_apply != self.barrier_state_digest
        {
            return Err(PairedBackupError::FreezeNotHeld(
                "barrier_log_id or barrier_state_digest mismatches final local/quorum apply",
            ));
        }
        let mut clean = self.clone();
        clean.proof_digest.clear();
        if sha256_json_tagged(b"rootyard-durable-freeze-barrier-v2", &clean)? != self.proof_digest {
            return Err(PairedBackupError::FreezeNotHeld("durable freeze barrier digest tampered"));
        }
        Ok(())
    }

    pub fn verify_against_raft_group(
        &self,
        expected_group_id: i64,
        expected_membership_digest: &str,
        durable_snap: &RefCasSnapshot,
        state_digest: &str,
        require_holds: bool,
    ) -> Result<(), PairedBackupError> {
        self.verify_inner(require_holds)?;
        if self.group_id != expected_group_id || self.group_membership_digest != expected_membership_digest {
            return Err(PairedBackupError::FreezeNotHeld(
                "freeze barrier group_id or group_membership_digest mismatches Raft group",
            ));
        }
        durable_snap.verify_integrity().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        if durable_snap.body.last_applied != Some(self.barrier_log_id) || state_digest != self.barrier_state_digest {
            return Err(PairedBackupError::FreezeNotHeld(
                "durable Raft snapshot log_id or state_digest diverges from freeze barrier",
            ));
        }
        for hold in &self.backup_holds {
            let root = durable_snap
                .body
                .roots
                .iter()
                .find(|r| r.root_id == hold.root_id && r.state == SmRootState::Active)
                .ok_or(PairedBackupError::FreezeNotHeld("backup retention root missing from durable Raft state"))?;
            if root.bound_hold_ids != hold.hold_ids {
                return Err(PairedBackupError::FreezeNotHeld("root bound_hold_ids mismatch durable freeze barrier"));
            }
            for hid in &hold.hold_ids {
                let he = durable_snap
                    .body
                    .holds
                    .iter()
                    .find(|h| h.hold_id == *hid)
                    .ok_or(PairedBackupError::FreezeNotHeld("backup hold missing from durable Raft state"))?;
                if he.state == SmHoldState::Retired {
                    return Err(PairedBackupError::FreezeNotHeld("backup hold retired before archive completion"));
                }
            }
        }
        Ok(())
    }

    pub(super) fn verify_thaw_receipt_binds(
        &self,
        raft: &dyn DurableRaftBackend,
        seal_receipt: &SealedArchiveReceipt,
    ) -> Result<(), PairedBackupError> {
        self.verify_inner(!self.backup_holds.is_empty())?;
        seal_receipt.verify()?;
        if seal_receipt.barrier_id != self.barrier_id
            || seal_receipt.fenced_deleter_epoch != self.status.fenced_deleter_epoch
            || seal_receipt.app_fence_seq != self.status.app_fence_seq
            || seal_receipt.barrier_log_id != self.barrier_log_id
            || seal_receipt.barrier_state_digest != self.barrier_state_digest
            || raft.group_id() != self.group_id
            || raft.group_membership_digest() != self.group_membership_digest
        {
            return Err(PairedBackupError::FreezeNotHeld(
                "sealed archive receipt or Raft group does not match active durable freeze barrier",
            ));
        }
        Ok(())
    }

    pub(super) fn verify_thaw_durable_wal(
        &self,
        raft: &dyn DurableRaftBackend,
        seal_receipt: &SealedArchiveReceipt,
    ) -> Result<(), PairedBackupError> {
        let committed_idx = raft.committed_quorum_index()?;
        let (durable_snap, _) = raft.durable_state()?;
        durable_snap.verify_integrity().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let Some(last_durable) = durable_snap.body.last_applied else {
            return Err(PairedBackupError::FreezeNotHeld("durable Raft WAL has no applied entries at thaw"));
        };
        if committed_idx < self.barrier_log_id.index
            || (last_durable.term, last_durable.index) < (self.barrier_log_id.term, self.barrier_log_id.index)
        {
            return Err(PairedBackupError::FreezeNotHeld(
                "quorum_commit_index or local WAL apply lags behind freeze barrier at thaw",
            ));
        }
        for rid in &seal_receipt.root_ids {
            if !durable_snap.body.roots.iter().any(|r| r.root_id == *rid && r.state == SmRootState::Active) {
                return Err(PairedBackupError::FreezeNotHeld(
                    "backup retention root missing or inactive in durable WAL",
                ));
            }
        }
        for hid in &seal_receipt.hold_ids {
            if !durable_snap.body.holds.iter().any(|h| h.hold_id == *hid && h.state != SmHoldState::Retired) {
                return Err(PairedBackupError::FreezeNotHeld("backup hold missing or retired in durable WAL"));
            }
        }
        for cr in &self.close_receipts {
            let found = durable_snap.body.scope_floors.iter().any(|s| {
                s.key.scope_kind == cr.scope_kind
                    && s.key.scope_id == cr.scope_id
                    && s.lifecycle == ScopeLifecycle::Closed
                    && s.authz_floor >= cr.authz_floor
            });
            if !found {
                return Err(PairedBackupError::ScopeNotClosed(
                    "closed auth scope missing from durable WAL at thaw".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SealedArchiveReceipt {
    pub backup_id: Uuid,
    pub barrier_id: Uuid,
    pub fenced_deleter_epoch: u64,
    pub app_fence_seq: u64,
    pub barrier_log_id: AppliedLogId,
    pub barrier_state_digest: String,
    pub paired_cut_digest: String,
    pub complete_marker_sha256: String,
    pub root_ids: Vec<Uuid>,
    pub hold_ids: Vec<Uuid>,
    pub receipt_seal: String,
}

impl SealedArchiveReceipt {
    pub(super) fn mint(mut self) -> Result<Self, PairedBackupError> {
        self.receipt_seal.clear();
        self.receipt_seal = sha256_json_tagged(b"rootyard-sealed-archive-receipt-v1", &self)?;
        self.verify()?;
        Ok(self)
    }

    pub fn verify(&self) -> Result<(), PairedBackupError> {
        if self.backup_id.is_nil()
            || self.barrier_id.is_nil()
            || !validate_hex64(&self.barrier_state_digest)
            || !validate_hex64(&self.paired_cut_digest)
            || !validate_hex64(&self.complete_marker_sha256)
            || self.root_ids.is_empty()
            || self.hold_ids.is_empty()
        {
            return Err(PairedBackupError::IncompleteCut("invalid or unsealed archive completion receipt"));
        }
        let mut clean = self.clone();
        clean.receipt_seal.clear();
        if sha256_json_tagged(b"rootyard-sealed-archive-receipt-v1", &clean)? != self.receipt_seal {
            return Err(PairedBackupError::IncompleteCut("sealed archive receipt digest mismatch"));
        }
        Ok(())
    }
}
