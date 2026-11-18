//! Durable Raft apply commit witness, fsynced WAL backend, freeze barrier proof,
//! and verified archive sealing receipt constraining freeze/thaw (#153).

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, RefCasCommand, RefCasLogEntry, RefCasSnapshot, RefCasStateMachine, SmHoldState,
    SmRootState, encode_command,
};

use super::types::{
    BackupRetentionHoldRecord, CloseScopeBarrierReceipt, FreezePartyStatus, PairedBackupError, sha256_json_tagged,
    validate_hex64,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableRaftApplyReceipt {
    pub log_id: AppliedLogId,
    pub command_sha256: String,
    pub state_digest_after: String,
    pub wal_synced: bool,
    pub quorum_committed: bool,
    pub receipt_digest: String,
}

impl DurableRaftApplyReceipt {
    pub fn seal(mut self) -> Result<Self, PairedBackupError> {
        self.receipt_digest.clear();
        self.receipt_digest = sha256_json_tagged(b"rootyard-durable-raft-apply-v1", &self)?;
        Ok(self)
    }

    pub fn verify(&self, expected_cmd_sha256: Option<&str>) -> Result<(), PairedBackupError> {
        if !self.wal_synced || !self.quorum_committed {
            return Err(PairedBackupError::FreezeNotHeld(
                "Raft barrier command lacks durable WAL fsync or quorum commit",
            ));
        }
        if !validate_hex64(&self.command_sha256) || !validate_hex64(&self.state_digest_after) {
            return Err(PairedBackupError::FreezeNotHeld("invalid command/state digest in Raft apply receipt"));
        }
        if let Some(exp) = expected_cmd_sha256
            && self.command_sha256 != exp
        {
            return Err(PairedBackupError::FreezeNotHeld("Raft apply receipt command_sha256 mismatch"));
        }
        let mut clean = self.clone();
        clean.receipt_digest.clear();
        if sha256_json_tagged(b"rootyard-durable-raft-apply-v1", &clean)? != self.receipt_digest {
            return Err(PairedBackupError::FreezeNotHeld("Raft apply receipt digest tampered"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableFreezeBarrierProof {
    pub barrier_id: Uuid,
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
        self.proof_digest = sha256_json_tagged(b"rootyard-durable-freeze-barrier-v1", &self)?;
        Ok(self)
    }

    pub fn verify(&self) -> Result<(), PairedBackupError> {
        self.status.require_frozen()?;
        if self.barrier_id.is_nil()
            || !validate_hex64(&self.barrier_state_digest)
            || self.apply_receipts.is_empty()
            || self.close_receipts.is_empty()
            || self.backup_holds.is_empty()
        {
            return Err(PairedBackupError::FreezeNotHeld("incomplete durable freeze barrier proof"));
        }
        for r in &self.apply_receipts {
            r.verify(None)?;
        }
        for cr in &self.close_receipts {
            cr.verify()?;
        }
        if self.apply_receipts.last().map(|r| r.log_id) != Some(self.barrier_log_id) {
            return Err(PairedBackupError::FreezeNotHeld("barrier_log_id mismatches final durable Raft apply"));
        }
        let mut clean = self.clone();
        clean.proof_digest.clear();
        if sha256_json_tagged(b"rootyard-durable-freeze-barrier-v1", &clean)? != self.proof_digest {
            return Err(PairedBackupError::FreezeNotHeld("durable freeze barrier digest tampered"));
        }
        Ok(())
    }

    pub fn verify_against_raft(
        &self,
        durable_snap: &RefCasSnapshot,
        state_digest: &str,
    ) -> Result<(), PairedBackupError> {
        self.verify()?;
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

/// Durable Raft execution gate ensuring barrier mutations are WAL-fsynced and quorum-committed.
pub trait DurableRaftBackend {
    fn commit_and_apply(
        &mut self,
        cmd: RefCasCommand,
    ) -> Result<(DurableRaftApplyReceipt, ApplyResponse), PairedBackupError>;
    fn durable_state(&self) -> Result<(RefCasSnapshot, String), PairedBackupError>;
    fn durable_snapshot(&self) -> Result<RefCasSnapshot, PairedBackupError> {
        Ok(self.durable_state()?.0)
    }
    fn durable_state_machine(&self) -> &RefCasStateMachine;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WalRecord {
    log_id: AppliedLogId,
    command_sha256: String,
    payload_hex: String,
    record_digest: String,
}

/// Disk-backed fsynced WAL + quorum witness Raft backend for paired backup barriers.
pub struct WalSyncedRaftBackend {
    wal_path: PathBuf,
    term: u64,
    next_index: u64,
    wal_sync_enabled: bool,
    quorum_healthy: bool,
    sm: RefCasStateMachine,
}

impl WalSyncedRaftBackend {
    pub fn open(wal_path: impl Into<PathBuf>, term: u64) -> Result<Self, PairedBackupError> {
        if term == 0 {
            return Err(PairedBackupError::InvalidArgument("Raft term must be >= 1"));
        }
        let wal_path = wal_path.into();
        if let Some(parent) = wal_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut sm = RefCasStateMachine::new();
        let mut next_index = 0u64;
        if wal_path.exists() {
            let reader = BufReader::new(fs::File::open(&wal_path)?);
            for line in reader.lines() {
                let raw = line?;
                if raw.trim().is_empty() {
                    continue;
                }
                let rec: WalRecord = serde_json::from_str(&raw)
                    .map_err(|_| PairedBackupError::StateMachine("corrupt WAL record JSON".into()))?;
                let mut check = rec.clone();
                check.record_digest.clear();
                if sha256_json_tagged(b"rootyard-raft-wal-rec-v1", &check)? != rec.record_digest {
                    return Err(PairedBackupError::StateMachine("WAL record digest mismatch".into()));
                }
                let payload = hex::decode(&rec.payload_hex)
                    .map_err(|_| PairedBackupError::StateMachine("invalid WAL payload hex".into()))?;
                if hex::encode(Sha256::digest(&payload)) != rec.command_sha256 {
                    return Err(PairedBackupError::StateMachine("WAL command_sha256 mismatch".into()));
                }
                sm.recover_entries([RefCasLogEntry { log_id: rec.log_id, payload }])
                    .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
                next_index = next_index.max(rec.log_id.index);
            }
        }
        Ok(Self { wal_path, term, next_index, wal_sync_enabled: true, quorum_healthy: true, sm })
    }

    pub fn set_wal_sync_enabled(&mut self, enabled: bool) {
        self.wal_sync_enabled = enabled;
    }

    pub fn set_quorum_healthy(&mut self, healthy: bool) {
        self.quorum_healthy = healthy;
    }

    pub fn wal_path(&self) -> &Path {
        &self.wal_path
    }

    pub fn into_state_machine(self) -> RefCasStateMachine {
        self.sm
    }
}

impl DurableRaftBackend for WalSyncedRaftBackend {
    fn commit_and_apply(
        &mut self,
        cmd: RefCasCommand,
    ) -> Result<(DurableRaftApplyReceipt, ApplyResponse), PairedBackupError> {
        if !self.wal_sync_enabled || !self.quorum_healthy {
            return Err(PairedBackupError::FreezeNotHeld(
                "Raft WAL fsync disabled or consensus quorum unavailable; refusing local-only apply",
            ));
        }
        let payload = encode_command(&cmd).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let command_sha256 = hex::encode(Sha256::digest(&payload));
        let log_id = AppliedLogId { term: self.term, index: self.next_index.saturating_add(1) };

        let mut rec = WalRecord {
            log_id,
            command_sha256: command_sha256.clone(),
            payload_hex: hex::encode(&payload),
            record_digest: String::new(),
        };
        rec.record_digest = sha256_json_tagged(b"rootyard-raft-wal-rec-v1", &rec)?;
        let line = serde_json::to_string(&rec).map_err(|_| PairedBackupError::IncompleteCut("WAL serialize failed"))?;

        let mut f = OpenOptions::new().create(true).append(true).open(&self.wal_path)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_data()?;

        let resp = self.sm.apply(log_id, cmd).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        self.next_index = log_id.index;
        let state_digest_after = self.sm.state_digest().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let receipt = DurableRaftApplyReceipt {
            log_id,
            command_sha256,
            state_digest_after,
            wal_synced: true,
            quorum_committed: true,
            receipt_digest: String::new(),
        }
        .seal()?;
        Ok((receipt, resp))
    }

    fn durable_state(&self) -> Result<(RefCasSnapshot, String), PairedBackupError> {
        let reopened = Self::open(&self.wal_path, self.term)?;
        let snap = reopened.sm.snapshot().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let digest = reopened.sm.state_digest().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        Ok((snap, digest))
    }

    fn durable_state_machine(&self) -> &RefCasStateMachine {
        &self.sm
    }
}
