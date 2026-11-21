//! Multi-voter fsynced Raft WAL backend separating majority `QuorumCommitReceipt`
//! persistence (`quorum_commit_index`) from local WAL apply (`LocalWalApplyReceipt`) (#153).

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, RefCasCommand, RefCasLogEntry, RefCasSnapshot, RefCasStateMachine, encode_command,
};

use super::peer_attestation::PeerDurableAttestation;
use super::raft_barrier::{
    DurableRaftApplyReceipt, LocalWalApplyReceipt, QuorumCommitReceipt, VoterWalAck, compute_group_membership_digest,
};
use super::types::{PairedBackupError, sha256_json_tagged, validate_hex64};
use super::wal_voters::{WalVoterBinding, WalVoterRing};

/// Durable Raft execution gate separating quorum commit witnesses from local WAL apply.
pub trait DurableRaftBackend {
    fn group_id(&self) -> i64;
    fn group_membership_digest(&self) -> String;
    fn voter_ids(&self) -> Vec<Uuid>;
    fn commit_and_apply(
        &mut self,
        cmd: RefCasCommand,
    ) -> Result<(DurableRaftApplyReceipt, ApplyResponse), PairedBackupError>;
    fn durable_state(&self) -> Result<(RefCasSnapshot, String), PairedBackupError>;
    fn committed_quorum_index(&self) -> Result<u64, PairedBackupError>;
    fn attest_group_cutpoint(
        &self,
        group_epoch: i64,
        snapshot: &RefCasSnapshot,
        state_digest: &str,
    ) -> Result<Vec<PeerDurableAttestation>, PairedBackupError>;
    fn durable_snapshot(&self) -> Result<RefCasSnapshot, PairedBackupError> {
        Ok(self.durable_state()?.0)
    }
    fn verify_freeze_barrier_active(&self, _expected_barrier_id: Uuid) -> Result<(), PairedBackupError> {
        Ok(())
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QuorumCommitMarker {
    group_id: i64,
    committed_index: u64,
    quorum_digest: String,
    marker_seal: String,
}

/// Multi-voter fsynced Raft WAL backend maintaining per-voter WAL files + durable quorum commit index.
/// Reopening NEVER applies uncommitted local WAL tail entries (`log_id.index > committed_index`).
pub struct WalSyncedRaftBackend {
    wal_path: PathBuf,
    group_id: i64,
    term: u64,
    voter_ids: Vec<Uuid>,
    voter_bindings: Vec<WalVoterBinding>,
    voter_keys: Vec<ring::signature::Ed25519KeyPair>,
    voter_online: Vec<bool>,
    group_membership_digest: String,
    committed_index: u64,
    local_wal_sync_enabled: bool,
    local_apply_enabled: bool,
    sm: RefCasStateMachine,
}

impl WalSyncedRaftBackend {
    pub fn open(wal_path: impl Into<PathBuf>, term: u64) -> Result<Self, PairedBackupError> {
        Self::open_group(wal_path, 1, term)
    }

    pub fn open_group(wal_path: impl Into<PathBuf>, group_id: i64, term: u64) -> Result<Self, PairedBackupError> {
        if term == 0 || group_id < 0 {
            return Err(PairedBackupError::InvalidArgument("Raft term >= 1 and non-negative group_id required"));
        }
        let wal_path = wal_path.into();
        if let Some(parent) = wal_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let voters = super::wal_voters::open_or_create_voters(&wal_path, group_id)?;
        let voter_ids = voters.voter_ids;
        let voter_bindings = voters.bindings;
        let voter_keys = voters.keys;
        let group_membership_digest = compute_group_membership_digest(&voter_ids)?;

        let commit_path = Self::sidecar(&wal_path, "commit");
        let committed_index = if commit_path.exists() {
            let cm: QuorumCommitMarker = serde_json::from_slice(&fs::read(&commit_path)?)
                .map_err(|_| PairedBackupError::StateMachine("corrupt quorum commit marker".into()))?;
            let mut clean = cm.clone();
            clean.marker_seal.clear();
            if cm.group_id != group_id
                || !validate_hex64(&cm.quorum_digest)
                || sha256_json_tagged(b"rootyard-wal-commit-marker-v1", &clean)? != cm.marker_seal
            {
                return Err(PairedBackupError::StateMachine("quorum commit marker seal mismatch".into()));
            }
            cm.committed_index
        } else {
            0
        };

        let records = Self::read_wal_records(&wal_path)?;
        let mut sm = RefCasStateMachine::new();
        let mut max_committed_seen = 0u64;
        for rec in &records {
            if rec.log_id.index <= committed_index {
                let payload = hex::decode(&rec.payload_hex)
                    .map_err(|_| PairedBackupError::StateMachine("invalid WAL payload hex".into()))?;
                sm.recover_entries([RefCasLogEntry { log_id: rec.log_id, payload }])
                    .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
                max_committed_seen = max_committed_seen.max(rec.log_id.index);
            }
        }
        if max_committed_seen < committed_index {
            return Err(PairedBackupError::FreezeNotHeld("local voter WAL lags behind durable quorum_commit_index"));
        }
        for peer_slot in 1..voter_ids.len() {
            let _ = Self::read_wal_records(&Self::voter_wal_path(&wal_path, peer_slot))?;
        }
        let voter_online = vec![true; voter_ids.len()];
        Ok(Self {
            wal_path,
            group_id,
            term,
            voter_ids,
            voter_bindings,
            voter_keys,
            voter_online,
            group_membership_digest,
            committed_index,
            local_wal_sync_enabled: true,
            local_apply_enabled: true,
            sm,
        })
    }

    pub fn set_wal_sync_enabled(&mut self, enabled: bool) {
        self.local_wal_sync_enabled = enabled;
    }

    pub fn set_local_apply_enabled(&mut self, enabled: bool) {
        self.local_apply_enabled = enabled;
    }

    pub fn set_quorum_healthy(&mut self, healthy: bool) {
        for online in self.voter_online.iter_mut().skip(1) {
            *online = healthy;
        }
    }

    pub fn set_voter_online(&mut self, slot: usize, online: bool) {
        if let Some(flag) = self.voter_online.get_mut(slot) {
            *flag = online;
        }
    }

    pub fn uncommitted_local_wal_entries(&self) -> Result<usize, PairedBackupError> {
        let recs = Self::read_wal_records(&self.wal_path)?;
        Ok(recs.iter().filter(|r| r.log_id.index > self.committed_index).count())
    }

    fn sign_voter_ack(
        &self,
        slot: usize,
        group_epoch: i64,
        log_id: AppliedLogId,
        command_sha256: &str,
        wal_record_digest: &str,
    ) -> Result<VoterWalAck, PairedBackupError> {
        super::wal_voters::sign_commit_ack(
            &WalVoterRing {
                voter_ids: &self.voter_ids,
                bindings: &self.voter_bindings,
                keys: &self.voter_keys,
                wal_base: &self.wal_path,
            },
            self.group_id,
            slot,
            group_epoch,
            log_id,
            command_sha256,
            wal_record_digest,
        )
    }

    /// Replicate & fsync to remote quorum peers (`1..N`) WITHOUT local voter `0` WAL/apply,
    /// returning a genuine `2/3` `QuorumCommitReceipt` while local WAL/apply lags behind.
    pub fn commit_quorum_only(&mut self, cmd: &RefCasCommand) -> Result<QuorumCommitReceipt, PairedBackupError> {
        let (log_id, rec, group_epoch) = self.prepare_wal_record(cmd)?;
        let mut acks = Vec::new();
        for slot in 1..self.voter_ids.len() {
            if self.voter_online[slot] {
                Self::append_wal_record(&Self::voter_wal_path(&self.wal_path, slot), &rec)?;
                acks.push(self.sign_voter_ack(slot, group_epoch, log_id, &rec.command_sha256, &rec.record_digest)?);
            }
        }
        let qr = QuorumCommitReceipt {
            group_id: self.group_id,
            group_epoch,
            group_membership_digest: self.group_membership_digest.clone(),
            voter_ids: self.voter_ids.clone(),
            log_id,
            command_sha256: rec.command_sha256,
            voter_acks: acks,
            quorum_digest: String::new(),
        }
        .seal()?;
        qr.verify()?;
        Self::persist_commit_marker(
            &Self::sidecar(&self.wal_path, "commit"),
            self.group_id,
            log_id.index,
            &qr.quorum_digest,
        )?;
        self.committed_index = log_id.index;
        Ok(qr)
    }

    pub fn wal_path(&self) -> &Path {
        &self.wal_path
    }

    pub fn into_state_machine(self) -> RefCasStateMachine {
        self.sm
    }

    fn sidecar(base: &Path, suffix: &str) -> PathBuf {
        let mut os = base.as_os_str().to_owned();
        os.push(format!(".{suffix}"));
        PathBuf::from(os)
    }

    fn voter_wal_path(base: &Path, slot: usize) -> PathBuf {
        if slot == 0 { base.to_path_buf() } else { Self::sidecar(base, &format!("voter{slot}.wal")) }
    }

    fn resolve_group_epoch(&self, cmd: &RefCasCommand) -> i64 {
        if let RefCasCommand::InitializeGate(init) = cmd {
            return init.gate.group_epoch.max(1);
        }
        self.sm.snapshot().ok().and_then(|s| s.body.gates.first().map(|g| g.group_epoch)).unwrap_or(1).max(1)
    }

    fn prepare_wal_record(&self, cmd: &RefCasCommand) -> Result<(AppliedLogId, WalRecord, i64), PairedBackupError> {
        let payload = encode_command(cmd).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let command_sha256 = hex::encode(Sha256::digest(&payload));
        let log_id = AppliedLogId { term: self.term, index: self.committed_index.saturating_add(1) };
        let mut rec =
            WalRecord { log_id, command_sha256, payload_hex: hex::encode(&payload), record_digest: String::new() };
        rec.record_digest = sha256_json_tagged(b"rootyard-raft-wal-rec-v1", &rec)?;
        Ok((log_id, rec, self.resolve_group_epoch(cmd)))
    }

    fn truncate_uncommitted_tail(&self, path: &Path) -> Result<(), PairedBackupError> {
        if !path.exists() {
            return Ok(());
        }
        let committed: Vec<WalRecord> =
            Self::read_wal_records(path)?.into_iter().filter(|r| r.log_id.index <= self.committed_index).collect();
        let mut out = Vec::new();
        for r in committed {
            let line = serde_json::to_string(&r).map_err(|_| PairedBackupError::IncompleteCut("WAL rewrite"))?;
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
        Self::write_atomic(path, &out)
    }

    fn append_wal_record(path: &Path, rec: &WalRecord) -> Result<(), PairedBackupError> {
        let line = serde_json::to_string(rec).map_err(|_| PairedBackupError::IncompleteCut("WAL serialize failed"))?;
        let mut f = OpenOptions::new().create(true).append(true).open(path)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_data()?;
        Ok(())
    }

    fn read_wal_records(path: &Path) -> Result<Vec<WalRecord>, PairedBackupError> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for line in BufReader::new(fs::File::open(path)?).lines() {
            let raw = line?;
            if raw.trim().is_empty() {
                continue;
            }
            let rec: WalRecord =
                serde_json::from_str(&raw).map_err(|_| PairedBackupError::StateMachine("corrupt WAL JSON".into()))?;
            let mut check = rec.clone();
            check.record_digest.clear();
            if sha256_json_tagged(b"rootyard-raft-wal-rec-v1", &check)? != rec.record_digest {
                return Err(PairedBackupError::StateMachine("WAL record digest mismatch".into()));
            }
            let payload =
                hex::decode(&rec.payload_hex).map_err(|_| PairedBackupError::StateMachine("bad WAL hex".into()))?;
            if hex::encode(Sha256::digest(&payload)) != rec.command_sha256 {
                return Err(PairedBackupError::StateMachine("WAL command_sha256 mismatch".into()));
            }
            out.push(rec);
        }
        Ok(out)
    }

    fn persist_commit_marker(
        path: &Path,
        group_id: i64,
        committed_index: u64,
        quorum_digest: &str,
    ) -> Result<(), PairedBackupError> {
        let mut cm = QuorumCommitMarker {
            group_id,
            committed_index,
            quorum_digest: quorum_digest.to_owned(),
            marker_seal: String::new(),
        };
        cm.marker_seal = sha256_json_tagged(b"rootyard-wal-commit-marker-v1", &cm)?;
        let bytes = serde_json::to_vec(&cm).map_err(|_| PairedBackupError::IncompleteCut("commit marker serialize"))?;
        Self::write_atomic(path, &bytes)
    }

    fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), PairedBackupError> {
        let tmp = Self::sidecar(path, "tmp");
        let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        Ok(())
    }
}

impl DurableRaftBackend for WalSyncedRaftBackend {
    fn group_id(&self) -> i64 {
        self.group_id
    }

    fn group_membership_digest(&self) -> String {
        self.group_membership_digest.clone()
    }

    fn voter_ids(&self) -> Vec<Uuid> {
        self.voter_ids.clone()
    }

    fn attest_group_cutpoint(
        &self,
        group_epoch: i64,
        snapshot: &RefCasSnapshot,
        state_digest: &str,
    ) -> Result<Vec<PeerDurableAttestation>, PairedBackupError> {
        let attestations = super::wal_voters::sign_cutpoint_attestations(
            &WalVoterRing {
                voter_ids: &self.voter_ids,
                bindings: &self.voter_bindings,
                keys: &self.voter_keys,
                wal_base: &self.wal_path,
            },
            self.group_id,
            group_epoch,
            &self.voter_online,
            snapshot,
            state_digest,
        )?;
        if attestations.len() <= self.voter_ids.len() / 2 {
            return Err(PairedBackupError::FreezeNotHeld(
                "fewer than a majority of voters are online for cutpoint attestations",
            ));
        }
        Ok(attestations)
    }

    fn commit_and_apply(
        &mut self,
        cmd: RefCasCommand,
    ) -> Result<(DurableRaftApplyReceipt, ApplyResponse), PairedBackupError> {
        for slot in 0..self.voter_ids.len() {
            if self.voter_online[slot] && (slot > 0 || self.local_wal_sync_enabled) {
                self.truncate_uncommitted_tail(&Self::voter_wal_path(&self.wal_path, slot))?;
            }
        }
        let (log_id, rec, group_epoch) = self.prepare_wal_record(&cmd)?;
        let mut acks = Vec::new();
        let mut local_acked = false;

        for slot in 0..self.voter_ids.len() {
            let can_write = self.voter_online[slot] && (slot > 0 || self.local_wal_sync_enabled);
            if can_write {
                Self::append_wal_record(&Self::voter_wal_path(&self.wal_path, slot), &rec)?;
                if slot == 0 {
                    local_acked = true;
                }
                acks.push(self.sign_voter_ack(slot, group_epoch, log_id, &rec.command_sha256, &rec.record_digest)?);
            }
        }
        let quorum_receipt = QuorumCommitReceipt {
            group_id: self.group_id,
            group_epoch,
            group_membership_digest: self.group_membership_digest.clone(),
            voter_ids: self.voter_ids.clone(),
            log_id,
            command_sha256: rec.command_sha256.clone(),
            voter_acks: acks,
            quorum_digest: String::new(),
        }
        .seal()?;
        quorum_receipt.verify()?;

        Self::persist_commit_marker(
            &Self::sidecar(&self.wal_path, "commit"),
            self.group_id,
            log_id.index,
            &quorum_receipt.quorum_digest,
        )?;
        self.committed_index = log_id.index;

        if !local_acked || !self.local_apply_enabled {
            return Err(PairedBackupError::FreezeNotHeld(
                "consensus quorum committed on peers, but local node WAL fsync or state-machine apply lagged",
            ));
        }
        let resp = self.sm.apply(log_id, cmd).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let state_digest_after = self.sm.state_digest().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let local_apply_receipt = LocalWalApplyReceipt {
            local_node_id: self.voter_ids[0],
            group_id: self.group_id,
            log_id,
            command_sha256: rec.command_sha256,
            local_wal_record_digest: rec.record_digest,
            committed_index_on_disk: self.committed_index,
            state_digest_after_apply: state_digest_after,
            apply_digest: String::new(),
        }
        .seal()?;
        local_apply_receipt.verify(&quorum_receipt)?;

        let combined =
            DurableRaftApplyReceipt { log_id, quorum_receipt, local_apply_receipt, receipt_digest: String::new() }
                .seal()?;
        Ok((combined, resp))
    }

    fn durable_state(&self) -> Result<(RefCasSnapshot, String), PairedBackupError> {
        let reopened = Self::open_group(&self.wal_path, self.group_id, self.term)?;
        let snap = reopened.sm.snapshot().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let digest = reopened.sm.state_digest().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        Ok((snap, digest))
    }

    fn committed_quorum_index(&self) -> Result<u64, PairedBackupError> {
        let reopened = Self::open_group(&self.wal_path, self.group_id, self.term)?;
        Ok(reopened.committed_index)
    }

    fn durable_state_machine(&self) -> &RefCasStateMachine {
        &self.sm
    }
}
