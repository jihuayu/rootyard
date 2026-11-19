//! Production 3-voter mTLS live Raft backend with X.509-authenticated peers, linearizable barriers, split apply (#153).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, RefCasCommand, RefCasSnapshot, RefCasStateMachine, encode_command,
};

pub use super::mtls_wire::{DurableRaftFreezeRecord, MtlsRaftClusterConfig};
use super::mtls_wire::{build_mtls_client_config, mtls_rpc_call};
use super::peer_attestation::{PeerDurableAttestation, derive_voter_uuid_bound};
use super::quorum_wal::DurableRaftBackend;
use super::raft_barrier::{
    DurableRaftApplyReceipt, LocalWalApplyReceipt, MIN_QUORUM_VOTERS, QuorumCommitReceipt, VoterWalAck,
    compute_group_membership_digest,
};
use super::types::{NewIncarnationAuthority, PairedBackupError, sha256_json_tagged};

const FREEZE_KV_KEY: &str = "refcas/paired_freeze";
const FREEZE_RECORD_MISSING: &str = "3-voter mTLS Raft freeze record missing";
pub(super) const INCARNATION_KV_KEY: &str = "refcas/cluster_incarnation";
pub(super) const GROUP_EPOCH_KV_KEY: &str = "refcas/group_epoch";
pub(super) const HEAD_RAFT_INDEX_KV_KEY: &str = "refcas/head_raft_index";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedRaftCmd {
    term: u64,
    cmd: RefCasCommand,
}

#[derive(Clone, Debug)]
pub(super) struct AuthenticatedVoterInfo {
    voter_uuid: Uuid,
    last_log_index: u64,
    current_term: u64,
}

#[derive(Clone, Debug)]
pub(super) struct MtlsVoterBinding {
    pub(super) voter_uuid: Uuid,
    pub(super) cert_sha256: String,
    pub(super) ed25519_pubkey_hex: String,
}

/// Production `DurableRaftBackend` backed by a live `>= 3`-voter mTLS `raft-node` cluster.
pub struct MtlsLiveRaftBackend {
    pub(super) cfg: MtlsRaftClusterConfig,
    pub(super) tls_cfg: Arc<ClientConfig>,
    pub(super) voter_uuids: Vec<Uuid>,
    pub(super) voter_bindings: BTreeMap<u64, MtlsVoterBinding>,
    pub(super) group_membership_digest: String,
    cached_sm: RefCasStateMachine,
}

impl MtlsLiveRaftBackend {
    pub fn connect(cfg: MtlsRaftClusterConfig) -> Result<Self, PairedBackupError> {
        if cfg.group_id < 0 || cfg.voter_endpoints.len() < MIN_QUORUM_VOTERS {
            return Err(PairedBackupError::InvalidArgument("live mTLS Raft needs group_id >= 0 and >= 3 voters"));
        }
        if !cfg.voter_endpoints.contains_key(&cfg.local_node_id) {
            return Err(PairedBackupError::InvalidArgument("local_node_id must belong to voter_endpoints"));
        }
        if cfg.attestor_endpoints.keys().ne(cfg.voter_endpoints.keys()) {
            return Err(PairedBackupError::InvalidArgument("attestor_endpoints must cover the Raft voter node_ids"));
        }
        let tls_cfg = build_mtls_client_config(&cfg)?;
        let mut voter_bindings = BTreeMap::new();
        let mut cert_hashes = BTreeSet::new();
        for (&node_id, addr) in &cfg.voter_endpoints {
            let (resp, cert_sha) = mtls_rpc_call(&tls_cfg, addr, node_id, &json!("Metrics"), cfg.rpc_timeout)?;
            let Some(m) = resp.get("Metrics") else {
                return Err(PairedBackupError::FreezeNotHeld("live mTLS peer rejected Metrics probe"));
            };
            if m["node_id"].as_u64() != Some(node_id) || m["running_ok"].as_bool() != Some(true) {
                return Err(PairedBackupError::FreezeNotHeld("live mTLS peer identity or running_ok invalid"));
            }
            if !cert_hashes.insert(cert_sha.clone()) {
                return Err(PairedBackupError::FreezeNotHeld("duplicate leaf X.509 certificate across Raft voters"));
            }
            let (reported_cert, pubkey_hex) = super::peer_attestation::probe_attestor_identity(
                &tls_cfg,
                &cfg.attestor_endpoints[&node_id],
                node_id,
                &cert_sha,
                cfg.rpc_timeout,
            )?;
            let voter_uuid = derive_voter_uuid_bound(cfg.group_id, node_id, &reported_cert, &pubkey_hex);
            voter_bindings.insert(
                node_id,
                MtlsVoterBinding { voter_uuid, cert_sha256: reported_cert, ed25519_pubkey_hex: pubkey_hex },
            );
        }
        let mut voter_uuids: Vec<Uuid> = voter_bindings.values().map(|b| b.voter_uuid).collect();
        voter_uuids.sort();
        let group_membership_digest = compute_group_membership_digest(&voter_uuids)?;
        let mut backend = Self {
            cfg,
            tls_cfg,
            voter_uuids,
            voter_bindings,
            group_membership_digest,
            cached_sm: RefCasStateMachine::new(),
        };
        backend.sync_cached_state_machine()?;
        Ok(backend)
    }
    pub fn update_endpoints(
        &mut self,
        endpoints: BTreeMap<u64, String>,
        attestor_endpoints: BTreeMap<u64, String>,
    ) -> Result<(), PairedBackupError> {
        if endpoints.keys().collect::<Vec<_>>() != self.cfg.voter_endpoints.keys().collect::<Vec<_>>()
            || attestor_endpoints.keys().collect::<Vec<_>>() != endpoints.keys().collect::<Vec<_>>()
        {
            return Err(PairedBackupError::InvalidArgument("updated endpoints changed voter node_id set"));
        }
        self.cfg.voter_endpoints = endpoints;
        self.cfg.attestor_endpoints = attestor_endpoints;
        Ok(())
    }
    pub fn write_freeze_record(&self, rec: &DurableRaftFreezeRecord) -> Result<u64, PairedBackupError> {
        rec.verify()?;
        let raw = serde_json::to_string(rec).map_err(|_| PairedBackupError::IncompleteCut("freeze serialize"))?;
        let (idx, _) = self.quorum_kv_put(FREEZE_KV_KEY, &raw).map_err(|err| {
            if rec.frozen {
                err
            } else {
                PairedBackupError::BootThawRefused(format!("Raft quorum refused thaw commit: {err}"))
            }
        })?;
        self.trigger_leader_snapshot().map_err(|err| {
            let msg = format!("Raft freeze/thaw committed at index {idx}, post-commit snapshot failed: {err}");
            PairedBackupError::StateMachine(msg)
        })?;
        Ok(idx)
    }

    pub fn read_freeze_record(&self) -> Result<Option<DurableRaftFreezeRecord>, PairedBackupError> {
        let Some(raw) = self.linearizable_kv_get(FREEZE_KV_KEY)? else {
            return Ok(None);
        };
        let rec: DurableRaftFreezeRecord = serde_json::from_str(&raw)
            .map_err(|_| PairedBackupError::FreezeNotHeld("corrupt durable Raft freeze record"))?;
        rec.verify()?;
        Ok(Some(rec))
    }
    pub fn write_incarnation_record(&self, inc: &NewIncarnationAuthority) -> Result<u64, PairedBackupError> {
        let raw = serde_json::to_string(inc).map_err(|_| PairedBackupError::IncompleteCut("incarnation serialize"))?;
        let _ = self.quorum_kv_put(GROUP_EPOCH_KV_KEY, &inc.new_group_epoch.to_string())?;
        let (idx, _) = self.quorum_kv_put(INCARNATION_KV_KEY, &raw)?;
        self.trigger_leader_snapshot()?;
        Ok(idx)
    }
    pub fn read_incarnation_record(&self) -> Result<Option<NewIncarnationAuthority>, PairedBackupError> {
        let Some(raw) = self.linearizable_kv_get(INCARNATION_KV_KEY)? else {
            return Ok(None);
        };
        let inc = serde_json::from_str(&raw)
            .map_err(|_| PairedBackupError::StateMachine("corrupt Raft incarnation record".into()))?;
        Ok(Some(inc))
    }

    pub(super) fn probe_live_voters(&self) -> Result<(BTreeMap<u64, AuthenticatedVoterInfo>, u64), PairedBackupError> {
        let expected_ids: BTreeSet<u64> = self.cfg.voter_endpoints.keys().copied().collect();
        let mut infos = BTreeMap::new();
        let mut leader_opt = None;
        for (&node_id, addr) in &self.cfg.voter_endpoints {
            let Ok((resp, cert_sha)) =
                mtls_rpc_call(&self.tls_cfg, addr, node_id, &json!("Metrics"), self.cfg.rpc_timeout)
            else {
                continue;
            };
            let Some(m) = resp.get("Metrics") else { continue };
            if m["running_ok"].as_bool() != Some(true) || m["node_id"].as_u64() != Some(node_id) {
                continue;
            }
            let binding = self
                .voter_bindings
                .get(&node_id)
                .ok_or(PairedBackupError::FreezeNotHeld("unknown voter node_id in Metrics"))?;
            if binding.cert_sha256 != cert_sha {
                return Err(PairedBackupError::FreezeNotHeld("live peer X.509 certificate changed unexpectedly"));
            }
            let expected_uuid = binding.voter_uuid;
            let mv: BTreeSet<u64> = m["membership_voters"]
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_u64).collect())
                .unwrap_or_default();
            if mv.len() < MIN_QUORUM_VOTERS || mv != expected_ids {
                continue;
            }
            if let Some(cl) = m["current_leader"].as_u64() {
                leader_opt = Some(cl);
            }
            infos.insert(
                node_id,
                AuthenticatedVoterInfo {
                    voter_uuid: expected_uuid,
                    last_log_index: m["last_log_index"].as_u64().unwrap_or(0),
                    current_term: m["current_term"].as_u64().unwrap_or(1).max(1),
                },
            );
        }
        if infos.len() <= self.voter_uuids.len() / 2 {
            return Err(PairedBackupError::FreezeNotHeld("authenticated mTLS Raft majority quorum unavailable"));
        }
        let leader_id = leader_opt
            .filter(|id| self.cfg.voter_endpoints.contains_key(id))
            .or_else(|| infos.keys().next().copied())
            .ok_or(PairedBackupError::FreezeNotHeld("no Raft leader elected"))?;
        Ok((infos, leader_id))
    }

    fn quorum_kv_put(&self, key: &str, value: &str) -> Result<(u64, u64), PairedBackupError> {
        let payload = serde_json::to_vec(&json!({ "Put": { "key": key, "value": value } }))
            .map_err(|_| PairedBackupError::IncompleteCut("Put payload encode"))?;
        let deadline = Instant::now() + Duration::from_secs(12);
        let mut target: Option<u64> = None;
        while Instant::now() < deadline {
            let Ok((infos, lid)) = self.probe_live_voters() else {
                std::thread::sleep(Duration::from_millis(60));
                continue;
            };
            let candidate = target.take().filter(|id| self.cfg.voter_endpoints.contains_key(id)).unwrap_or(lid);
            let addr = &self.cfg.voter_endpoints[&candidate];
            if let Ok((resp, _)) = mtls_rpc_call(
                &self.tls_cfg,
                addr,
                candidate,
                &json!({ "ClientWrite": { "payload": payload } }),
                self.cfg.rpc_timeout,
            ) {
                if let Some(idx) = resp.pointer("/ClientWrite/log_index").and_then(Value::as_u64) {
                    let term = infos.get(&candidate).map_or(1, |i| i.current_term.max(1));
                    return Ok((idx, term));
                }
                if let Some(fwd) = resp.pointer("/Error/forward_to_leader_id").and_then(Value::as_u64)
                    && fwd != candidate
                {
                    target = Some(fwd);
                }
            }
            std::thread::sleep(Duration::from_millis(60));
        }
        Err(PairedBackupError::FreezeNotHeld("mTLS Raft ClientWrite timed out awaiting majority quorum"))
    }

    pub(super) fn replica_kv_u64(&self, node_id: u64, key: &str) -> Result<u64, PairedBackupError> {
        let addr = &self.cfg.voter_endpoints[&node_id];
        let (kv, _) = mtls_rpc_call(
            &self.tls_cfg,
            addr,
            node_id,
            &json!({ "InspectReplicaKv": { "key": key } }),
            self.cfg.rpc_timeout,
        )?;
        Ok(kv.pointer("/KvValue/value").and_then(Value::as_str).unwrap_or("0").parse().unwrap_or(0))
    }

    pub(super) fn trigger_leader_snapshot(&self) -> Result<(), PairedBackupError> {
        let (_, lid) = self.probe_live_voters()?;
        let addr = &self.cfg.voter_endpoints[&lid];
        let (resp, _) = mtls_rpc_call(&self.tls_cfg, addr, lid, &json!("TriggerSnapshot"), self.cfg.rpc_timeout)?;
        if resp != json!("Ok") {
            return Err(PairedBackupError::StateMachine(format!("leader TriggerSnapshot rejected: {resp}")));
        }
        Ok(())
    }

    fn replay_linearizable_sm(&self) -> Result<(RefCasStateMachine, u64), PairedBackupError> {
        let head_seq: u64 = self
            .linearizable_kv_get("refcas/head_seq")?
            .as_deref()
            .unwrap_or("0")
            .parse()
            .map_err(|_| PairedBackupError::StateMachine("invalid refcas/head_seq".into()))?;
        let _ = super::peer_attestation::verify_local_replica_caught_up(self, head_seq)?;
        Ok((self.replay_up_to(head_seq)?, head_seq))
    }

    fn replay_up_to(&self, limit_seq: u64) -> Result<RefCasStateMachine, PairedBackupError> {
        let mut sm = RefCasStateMachine::new();
        for seq in 1..=limit_seq {
            let raw = self
                .linearizable_kv_get(&format!("refcas/cmd/{seq:08}"))?
                .ok_or(PairedBackupError::IncompleteCut("missing committed refcas/cmd entry"))?;
            let entry: PersistedRaftCmd =
                serde_json::from_str(&raw).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
            sm.apply(AppliedLogId { term: entry.term.max(1), index: seq }, entry.cmd)
                .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        }
        Ok(sm)
    }

    fn collect_voter_acks(
        &self,
        group_epoch: i64,
        log_id: AppliedLogId,
        seq: u64,
        (commit_raft_idx, idx_put_raft_idx): (u64, u64),
        command_sha256: &str,
    ) -> Result<Vec<VoterWalAck>, PairedBackupError> {
        for attempt in 0..15 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(80));
            }
            let (infos, _) = self.probe_live_voters()?;
            let mut acks = Vec::new();
            for (&node_id, info) in &infos {
                let Ok(peer_seq) = self.replica_kv_u64(node_id, "refcas/head_seq") else { continue };
                let Ok(peer_raft_idx) = self.replica_kv_u64(node_id, HEAD_RAFT_INDEX_KV_KEY) else { continue };
                let replicated = attempt > 0 || info.last_log_index >= idx_put_raft_idx;
                if peer_seq >= seq && peer_raft_idx >= commit_raft_idx && replicated {
                    let Ok(attestation) = super::peer_attestation_rpc::request_commit_attestation(
                        self,
                        node_id,
                        group_epoch,
                        seq,
                        commit_raft_idx,
                        command_sha256,
                    ) else {
                        continue;
                    };
                    acks.push(
                        VoterWalAck {
                            voter_id: info.voter_uuid,
                            log_id,
                            command_sha256: command_sha256.to_owned(),
                            wal_record_digest: attestation.claims.secondary_digest.clone(),
                            peer_attestation: attestation,
                            ack_digest: String::new(),
                        }
                        .seal()?,
                    );
                }
            }
            let local_replicated =
                self.replica_kv_u64(self.cfg.local_node_id, HEAD_RAFT_INDEX_KV_KEY).unwrap_or(0) >= commit_raft_idx;
            if acks.len() > self.voter_uuids.len() / 2 && local_replicated {
                return Ok(acks);
            }
        }
        Ok(Vec::new())
    }

    fn resolve_group_epoch(&self, cmd: &RefCasCommand, before_sm: &RefCasStateMachine) -> i64 {
        if let RefCasCommand::InitializeGate(init) = cmd {
            return init.gate.group_epoch.max(1);
        }
        let current = before_sm.snapshot().ok().and_then(|s| s.body.gates.first().map(|g| g.group_epoch));
        current.unwrap_or(1).max(1)
    }

    pub fn sync_cached_state_machine(&mut self) -> Result<(), PairedBackupError> {
        let (sm, _) = self.replay_linearizable_sm()?;
        self.cached_sm = sm;
        Ok(())
    }

    pub fn verify_pristine_new_incarnation_target(
        &self,
        source_membership_digest: &str,
        forbidden_incarnations: &BTreeSet<Uuid>,
    ) -> Result<(), PairedBackupError> {
        super::mtls_consensus::verify_pristine_target(self, source_membership_digest, forbidden_incarnations)
    }
}

impl DurableRaftBackend for MtlsLiveRaftBackend {
    fn group_id(&self) -> i64 {
        self.cfg.group_id
    }

    fn group_membership_digest(&self) -> String {
        self.group_membership_digest.clone()
    }

    fn voter_ids(&self) -> Vec<Uuid> {
        self.voter_uuids.clone()
    }

    fn commit_and_apply(
        &mut self,
        cmd: RefCasCommand,
    ) -> Result<(DurableRaftApplyReceipt, ApplyResponse), PairedBackupError> {
        let (before_sm, head_before) = self.replay_linearizable_sm()?;
        let floor_term = before_sm.snapshot().ok().and_then(|s| s.body.last_applied.map(|a| a.term)).unwrap_or(1);
        let (infos, lid) = self.probe_live_voters()?;
        let observed_term = infos.get(&lid).map_or(1, |i| i.current_term).max(floor_term).max(1);
        let seq = head_before.saturating_add(1);
        let group_epoch = self.resolve_group_epoch(&cmd, &before_sm);
        let wire_bytes = encode_command(&cmd).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let command_sha256 = hex::encode(Sha256::digest(&wire_bytes));
        let persisted = PersistedRaftCmd { term: observed_term, cmd: cmd.clone() };
        let cmd_json = serde_json::to_string(&persisted).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;

        let (_, cmd_term) = self.quorum_kv_put(&format!("refcas/cmd/{seq:08}"), &cmd_json)?;
        let final_term = observed_term.max(cmd_term);
        if final_term > observed_term {
            let updated = PersistedRaftCmd { term: final_term, cmd: cmd.clone() };
            let raw = serde_json::to_string(&updated).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
            let _ = self.quorum_kv_put(&format!("refcas/cmd/{seq:08}"), &raw)?;
        }
        if matches!(&cmd, RefCasCommand::InitializeGate(_)) || seq == 1 {
            let _ = self.quorum_kv_put(GROUP_EPOCH_KV_KEY, &group_epoch.to_string())?;
        }
        let (commit_raft_idx, _) = self.quorum_kv_put("refcas/head_seq", &seq.to_string())?;
        let (idx_put_raft_idx, _) = self.quorum_kv_put(HEAD_RAFT_INDEX_KV_KEY, &commit_raft_idx.to_string())?;
        let log_id = AppliedLogId { term: final_term, index: seq };
        let _ = self.trigger_leader_snapshot();

        let acks =
            self.collect_voter_acks(group_epoch, log_id, seq, (commit_raft_idx, idx_put_raft_idx), &command_sha256)?;
        let quorum_receipt = QuorumCommitReceipt {
            group_id: self.cfg.group_id,
            group_epoch,
            group_membership_digest: self.group_membership_digest.clone(),
            voter_ids: self.voter_uuids.clone(),
            log_id,
            command_sha256: command_sha256.clone(),
            voter_acks: acks,
            quorum_digest: String::new(),
        }
        .seal()?;
        quorum_receipt.verify()?;

        let local_cert_sha = super::peer_attestation::verify_local_replica_caught_up(self, seq)?;
        let mut step_sm = self.replay_up_to(head_before)?;
        let resp = step_sm.apply(log_id, cmd).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let state_digest_after = step_sm.state_digest().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        self.cached_sm = step_sm;

        let local_wal_digest = sha256_json_tagged(
            b"rootyard-mtls-local-wal-v1",
            &(self.cfg.local_node_id, &local_cert_sha, commit_raft_idx, seq, &command_sha256),
        )?;
        let local_apply_receipt = LocalWalApplyReceipt {
            local_node_id: self.voter_bindings[&self.cfg.local_node_id].voter_uuid,
            group_id: self.cfg.group_id,
            log_id,
            command_sha256,
            local_wal_record_digest: local_wal_digest,
            committed_index_on_disk: commit_raft_idx,
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
        let (sm, _) = self.replay_linearizable_sm()?;
        let snap = sm.snapshot().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        let digest = sm.state_digest().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
        Ok((snap, digest))
    }

    fn committed_quorum_index(&self) -> Result<u64, PairedBackupError> {
        self.linearizable_consensus_index()
    }
    fn verify_freeze_barrier_active(&self, expected_barrier_id: Uuid) -> Result<(), PairedBackupError> {
        let rec = self.read_freeze_record()?.ok_or(PairedBackupError::FreezeNotHeld(FREEZE_RECORD_MISSING))?;
        if !rec.frozen || rec.barrier_id != expected_barrier_id {
            return Err(PairedBackupError::FreezeNotHeld("3-voter mTLS Raft freeze barrier released early"));
        }
        Ok(())
    }

    fn durable_state_machine(&self) -> &RefCasStateMachine {
        &self.cached_sm
    }
    fn attest_group_cutpoint(
        &self,
        group_epoch: i64,
        snapshot: &RefCasSnapshot,
        state_digest: &str,
    ) -> Result<Vec<PeerDurableAttestation>, PairedBackupError> {
        super::peer_attestation_rpc::attest_group_cutpoint(self, group_epoch, snapshot, state_digest)
    }
}
