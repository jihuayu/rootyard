//! Server-side attestation request handlers (querying the voter's own `raft-node`)
//! and client-side helpers used by `MtlsLiveRaftBackend` (#153).

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, RefCasCommand, RefCasSnapshot, RefCasStateMachine, encode_command,
};

use super::mtls_raft::{GROUP_EPOCH_KV_KEY, INCARNATION_KV_KEY, MtlsLiveRaftBackend};
use super::mtls_wire::mtls_rpc_call;
use super::peer_attestation::{PeerAttestorState, PeerDurableAttestation, PeerDurableAttestationClaims};
use super::quorum_wal::DurableRaftBackend;
use super::types::{NewIncarnationAuthority, PairedBackupError, sha256_json_tagged, validate_hex64};
use super::wal_file_digest::{extract_committed_applied_index, fsync_and_hash_voter_durable_wal};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PersistedRaftCmd {
    term: u64,
    cmd: RefCasCommand,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestCommitRequest {
    group_id: i64,
    group_epoch: i64,
    seq: u64,
    min_raft_index: u64,
    command_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestCutpointRequest {
    group_id: i64,
    group_epoch: i64,
    expected_seq: u64,
    min_committed_index: u64,
    expected_state_digest: String,
    expected_snapshot_checksum: String,
}

impl PeerAttestorState {
    fn call_raft(&self, request: &Value) -> Result<Value, PairedBackupError> {
        let (response, cert_sha) =
            mtls_rpc_call(&self.tls_cfg, &self.raft_node_addr, self.node_id, request, self.rpc_timeout)?;
        if cert_sha != self.cert_sha256 {
            return Err(PairedBackupError::FreezeNotHeld(
                "local raft-node X.509 certificate does not match this voter's attestor identity",
            ));
        }
        Ok(response)
    }

    fn metrics(&self) -> Result<Value, PairedBackupError> {
        self.call_raft(&json!("Metrics"))?
            .get("Metrics")
            .cloned()
            .ok_or(PairedBackupError::FreezeNotHeld("local raft-node rejected Metrics probe"))
    }

    fn read_replica_kv(&self, key: &str) -> Result<Option<String>, PairedBackupError> {
        let response = self.call_raft(&json!({ "InspectReplicaKv": { "key": key } }))?;
        Ok(response.pointer("/KvValue/value").and_then(Value::as_str).map(str::to_owned))
    }

    fn read_replica_u64(&self, key: &str) -> Result<u64, PairedBackupError> {
        Ok(self.read_replica_kv(key)?.as_deref().unwrap_or("0").parse().unwrap_or(0))
    }

    fn read_replica_i64(&self, key: &str) -> Result<Option<i64>, PairedBackupError> {
        self.read_replica_kv(key)?
            .map(|raw| {
                raw.parse::<i64>().map_err(|_| PairedBackupError::StateMachine("corrupt local group_epoch".into()))
            })
            .transpose()
    }

    fn verify_running_identity(&self, metrics: &Value) -> Result<u64, PairedBackupError> {
        (metrics["running_ok"].as_bool() == Some(true) && metrics["node_id"].as_u64() == Some(self.node_id))
            .then(|| metrics["last_log_index"].as_u64().unwrap_or(0))
            .ok_or(PairedBackupError::FreezeNotHeld("local raft-node not running or node_id mismatch"))
    }

    fn verify_local_group_epoch(&self, requested_epoch: i64, up_to_seq: u64) -> Result<i64, PairedBackupError> {
        if requested_epoch < 1 {
            return Err(PairedBackupError::InvalidArgument("group_epoch must be >= 1"));
        }
        let inc_epoch = match self.read_replica_kv(INCARNATION_KV_KEY)? {
            Some(raw) => Some(
                serde_json::from_str::<NewIncarnationAuthority>(&raw)
                    .map_err(|_| PairedBackupError::StateMachine("corrupt Raft incarnation record".into()))?
                    .new_group_epoch,
            ),
            None => None,
        };
        let kv_epoch = self.read_replica_i64(GROUP_EPOCH_KV_KEY)?;
        let gate_epoch = if up_to_seq >= 1 {
            self.read_replica_kv("refcas/cmd/00000001")?.and_then(|raw| {
                match serde_json::from_str::<PersistedRaftCmd>(&raw) {
                    Ok(PersistedRaftCmd { cmd: RefCasCommand::InitializeGate(init), .. }) => {
                        Some(init.gate.group_epoch)
                    }
                    _ => None,
                }
            })
        } else {
            None
        };
        let mut local_epoch = None;
        for source in [inc_epoch, kv_epoch, gate_epoch].into_iter().flatten() {
            if source < 1 {
                return Err(PairedBackupError::StateMachine("local replica group_epoch must be >= 1".into()));
            }
            if local_epoch.is_some_and(|previous| previous != source) {
                return Err(PairedBackupError::CutpointSkew("local replica group_epoch sources diverge".into()));
            }
            local_epoch = Some(source);
        }
        let local_epoch = local_epoch
            .ok_or(PairedBackupError::FreezeNotHeld("local raft-node replica has no durable group_epoch"))?;
        if requested_epoch != local_epoch {
            return Err(PairedBackupError::StaleIncarnation {
                field: "group_epoch",
                expected: local_epoch.to_string(),
                got: requested_epoch.to_string(),
            });
        }
        Ok(local_epoch)
    }
}

/// Server-side handler for `AttestCommit`: verifies the persisted command on the voter's
/// own replica, fsyncs `sm.sqlite3` + `log.sqlite3`, then signs the durable claims.
pub(super) fn attest_commit(
    state: &PeerAttestorState,
    body: &Value,
) -> Result<PeerDurableAttestation, PairedBackupError> {
    let req: AttestCommitRequest = serde_json::from_value(body.clone())
        .map_err(|_| PairedBackupError::InvalidArgument("malformed AttestCommit request"))?;
    if req.group_id != state.group_id || !validate_hex64(&req.command_sha256) {
        return Err(PairedBackupError::FreezeNotHeld("AttestCommit group_id or command digest mismatch"));
    }
    let metrics = state.metrics()?;
    let last_log_index = state.verify_running_identity(&metrics)?;
    let committed_applied_index = extract_committed_applied_index(&metrics).unwrap_or(0);
    if last_log_index < req.min_raft_index
        || committed_applied_index < req.min_raft_index
        || committed_applied_index == 0
    {
        return Err(PairedBackupError::FreezeNotHeld("voter Raft committed/applied index behind attested commit"));
    }
    if state.read_replica_u64("refcas/head_seq")? < req.seq {
        return Err(PairedBackupError::FreezeNotHeld("local raft-node applied seq behind attested commit"));
    }
    let raw = state
        .read_replica_kv(&format!("refcas/cmd/{:08}", req.seq))?
        .ok_or(PairedBackupError::IncompleteCut("local raft-node is missing the committed command for attested seq"))?;
    let persisted: PersistedRaftCmd = serde_json::from_str(&raw)
        .map_err(|_| PairedBackupError::StateMachine("corrupt persisted raft command".into()))?;
    if persisted.term < 1 {
        return Err(PairedBackupError::FreezeNotHeld("persisted raft command has no durable term"));
    }
    let wire = encode_command(&persisted.cmd).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    if hex::encode(Sha256::digest(&wire)) != req.command_sha256 {
        return Err(PairedBackupError::FreezeNotHeld(
            "persisted command digest does not match the attested command_sha256",
        ));
    }
    let local_group_epoch = state.verify_local_group_epoch(req.group_epoch, req.seq)?;
    let sqlite_wal_sha256 = fsync_and_hash_voter_durable_wal(&state.data_dir)?;
    let wal_digest = sha256_json_tagged(
        b"rootyard-mtls-peer-wal-v3",
        &(
            state.node_id,
            state.cert_sha256.as_str(),
            persisted.term,
            committed_applied_index,
            req.seq,
            local_group_epoch,
            req.command_sha256.as_str(),
            sqlite_wal_sha256.as_str(),
        ),
    )?;
    PeerDurableAttestation::sign(
        PeerDurableAttestationClaims {
            kind: "commit".to_owned(),
            group_id: req.group_id,
            group_epoch: local_group_epoch,
            node_id: state.node_id,
            voter_id: state.voter_id,
            peer_cert_sha256: state.cert_sha256.clone(),
            ed25519_pubkey_hex: state.pubkey_hex.clone(),
            raft_term: persisted.term,
            raft_committed_index: committed_applied_index,
            refcas_seq: req.seq,
            subject_digest: req.command_sha256,
            secondary_digest: wal_digest,
            durable_sqlite_sha256: sqlite_wal_sha256,
        },
        &state.keypair,
    )
}

/// Server-side handler for `AttestCutpoint`: replays the voter's own local replica to
/// verify `state_digest` + `snapshot.checksum`, fsyncs state, then signs the claims.
pub(super) fn attest_cutpoint(
    state: &PeerAttestorState,
    body: &Value,
) -> Result<PeerDurableAttestation, PairedBackupError> {
    let req: AttestCutpointRequest = serde_json::from_value(body.clone())
        .map_err(|_| PairedBackupError::InvalidArgument("malformed AttestCutpoint request"))?;
    if req.group_id != state.group_id
        || !validate_hex64(&req.expected_state_digest)
        || !validate_hex64(&req.expected_snapshot_checksum)
    {
        return Err(PairedBackupError::FreezeNotHeld("AttestCutpoint group_id or digest mismatch"));
    }
    let metrics = state.metrics()?;
    let last_log_index = state.verify_running_identity(&metrics)?;
    let committed_applied_index = extract_committed_applied_index(&metrics).unwrap_or(0);
    if req.expected_seq == 0
        || req.min_committed_index < req.expected_seq
        || committed_applied_index == 0
        || last_log_index < committed_applied_index
        || committed_applied_index < req.expected_seq
        || committed_applied_index < req.min_committed_index
    {
        return Err(PairedBackupError::FreezeNotHeld(
            "voter Raft committed_index has not reached the attested cutpoint",
        ));
    }
    if state.read_replica_u64("refcas/head_seq")? != req.expected_seq {
        return Err(PairedBackupError::FreezeNotHeld(
            "local raft-node applied seq diverges from the attested cutpoint",
        ));
    }
    let local_group_epoch = state.verify_local_group_epoch(req.group_epoch, req.expected_seq)?;
    let mut sm = RefCasStateMachine::new();
    for seq in 1..=req.expected_seq {
        let raw = state.read_replica_kv(&format!("refcas/cmd/{seq:08}"))?.ok_or(PairedBackupError::IncompleteCut(
            "local raft-node is missing a committed command during cutpoint replay",
        ))?;
        let persisted: PersistedRaftCmd = serde_json::from_str(&raw)
            .map_err(|_| PairedBackupError::StateMachine("corrupt persisted raft command".into()))?;
        sm.apply(AppliedLogId { term: persisted.term.max(1), index: seq }, persisted.cmd)
            .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    }
    let snapshot = sm.snapshot().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    if !snapshot.body.gates.iter().all(|gate| gate.group_epoch == local_group_epoch) {
        return Err(PairedBackupError::CutpointSkew("local replica gates diverge from group_epoch".into()));
    }
    if snapshot.checksum != req.expected_snapshot_checksum {
        return Err(PairedBackupError::FreezeNotHeld(
            "local replica snapshot checksum diverges from the attested cutpoint",
        ));
    }
    let state_digest = sm.state_digest().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    if state_digest != req.expected_state_digest {
        return Err(PairedBackupError::FreezeNotHeld("local replica state_digest diverges from the attested cutpoint"));
    }
    let sqlite_wal_sha256 = fsync_and_hash_voter_durable_wal(&state.data_dir)?;
    PeerDurableAttestation::sign(
        PeerDurableAttestationClaims {
            kind: "cutpoint".to_owned(),
            group_id: req.group_id,
            group_epoch: local_group_epoch,
            node_id: state.node_id,
            voter_id: state.voter_id,
            peer_cert_sha256: state.cert_sha256.clone(),
            ed25519_pubkey_hex: state.pubkey_hex.clone(),
            raft_term: metrics["current_term"].as_u64().unwrap_or(1).max(1),
            raft_committed_index: committed_applied_index,
            refcas_seq: req.expected_seq,
            subject_digest: req.expected_state_digest,
            secondary_digest: req.expected_snapshot_checksum,
            durable_sqlite_sha256: sqlite_wal_sha256,
        },
        &state.keypair,
    )
}

fn decode_attestation(response: &Value, refused: &'static str) -> Result<PeerDurableAttestation, PairedBackupError> {
    let raw = response.get("Attestation").ok_or(PairedBackupError::FreezeNotHeld(refused))?;
    let attestation: PeerDurableAttestation = serde_json::from_value(raw.clone())
        .map_err(|_| PairedBackupError::FreezeNotHeld("malformed peer durable attestation response"))?;
    attestation.verify()?;
    Ok(attestation)
}

/// Ask one live voter's `PeerAttestationDaemon` for a server-signed `"commit"` attestation.
pub(super) fn request_commit_attestation(
    raft: &MtlsLiveRaftBackend,
    node_id: u64,
    group_epoch: i64,
    seq: u64,
    min_raft_index: u64,
    command_sha256: &str,
) -> Result<PeerDurableAttestation, PairedBackupError> {
    let endpoint = raft
        .cfg
        .attestor_endpoints
        .get(&node_id)
        .ok_or(PairedBackupError::FreezeNotHeld("no peer attestor endpoint configured for voter"))?;
    let binding = raft
        .voter_bindings
        .get(&node_id)
        .ok_or(PairedBackupError::FreezeNotHeld("unknown voter node_id for commit attestation"))?;
    let (response, _cert_sha) = mtls_rpc_call(
        &raft.tls_cfg,
        endpoint,
        node_id,
        &json!({ "AttestCommit": {
            "group_id": raft.cfg.group_id,
            "group_epoch": group_epoch,
            "seq": seq,
            "min_raft_index": min_raft_index,
            "command_sha256": command_sha256,
        }}),
        raft.cfg.rpc_timeout,
    )?;
    let attestation = decode_attestation(&response, "peer attestor refused AttestCommit")?;
    if attestation.claims.voter_id != binding.voter_uuid
        || attestation.claims.ed25519_pubkey_hex != binding.ed25519_pubkey_hex
        || attestation.claims.peer_cert_sha256 != binding.cert_sha256
    {
        return Err(PairedBackupError::FreezeNotHeld(
            "commit attestation key/certificate mismatches pinned voter binding",
        ));
    }
    Ok(attestation)
}

/// Collect a majority of server-signed `"cutpoint"` attestations from live voters.
pub(super) fn attest_group_cutpoint(
    raft: &MtlsLiveRaftBackend,
    group_epoch: i64,
    snapshot: &RefCasSnapshot,
    state_digest: &str,
) -> Result<Vec<PeerDurableAttestation>, PairedBackupError> {
    let applied = snapshot.body.last_applied.ok_or(PairedBackupError::IncompleteCut(
        "durable Raft snapshot has no applied entry for a cutpoint attestation",
    ))?;
    let min_committed_index =
        DurableRaftBackend::committed_quorum_index(raft).unwrap_or(applied.index).max(applied.index);
    raft.trigger_leader_snapshot()?;
    let mut attestations = Vec::new();
    let mut seen = BTreeSet::new();
    for (&node_id, endpoint) in &raft.cfg.attestor_endpoints {
        let Some(binding) = raft.voter_bindings.get(&node_id) else {
            continue;
        };
        let mut attested = None;
        for attempt in 0..10 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(80));
            }
            let Ok((response, _cert_sha)) = mtls_rpc_call(
                &raft.tls_cfg,
                endpoint,
                node_id,
                &json!({ "AttestCutpoint": {
                    "group_id": raft.cfg.group_id,
                    "group_epoch": group_epoch,
                    "expected_seq": applied.index,
                    "min_committed_index": min_committed_index,
                    "expected_state_digest": state_digest,
                    "expected_snapshot_checksum": snapshot.checksum.as_str(),
                }}),
                raft.cfg.rpc_timeout,
            ) else {
                continue;
            };
            if let Ok(attestation) = decode_attestation(&response, "peer attestor refused AttestCutpoint") {
                attested = Some(attestation);
                break;
            }
        }
        let Some(attestation) = attested else {
            continue;
        };
        let claims = &attestation.claims;
        if claims.kind != "cutpoint"
            || claims.voter_id != binding.voter_uuid
            || claims.ed25519_pubkey_hex != binding.ed25519_pubkey_hex
            || claims.peer_cert_sha256 != binding.cert_sha256
            || claims.group_id != raft.cfg.group_id
            || claims.group_epoch != group_epoch
            || claims.refcas_seq != applied.index
            || claims.raft_committed_index < min_committed_index
            || claims.raft_committed_index < applied.index
            || claims.subject_digest != state_digest
            || claims.secondary_digest != snapshot.checksum
            || !validate_hex64(&claims.durable_sqlite_sha256)
            || claims.durable_sqlite_sha256.bytes().all(|b| b == b'0')
            || !seen.insert(claims.voter_id)
        {
            continue;
        }
        attestations.push(attestation);
    }
    if attestations.len() <= raft.voter_uuids.len() / 2 {
        return Err(PairedBackupError::FreezeNotHeld(
            "fewer than a majority of live voters produced server-signed cutpoint attestations",
        ));
    }
    Ok(attestations)
}

fn stale(field: &'static str, expected: String, got: String) -> PairedBackupError {
    PairedBackupError::StaleIncarnation { field, expected, got }
}

/// Fail-closed brand-new incarnation probe over 100% of the configured target voters.
pub(super) fn verify_pristine_target(
    raft: &MtlsLiveRaftBackend,
    source_membership_digest: &str,
    forbidden_incarnations: &BTreeSet<Uuid>,
) -> Result<(), PairedBackupError> {
    if raft.group_membership_digest == source_membership_digest {
        return Err(stale(
            "group_membership_digest",
            "brand-new target Raft cluster".into(),
            source_membership_digest.to_owned(),
        ));
    }
    if raft.cfg.voter_endpoints.len() < 3 {
        return Err(PairedBackupError::InvalidArgument("pristine target check requires >= 3 configured target voters"));
    }
    for (&node_id, endpoint) in &raft.cfg.voter_endpoints {
        let (metrics_response, _cert_sha) =
            mtls_rpc_call(&raft.tls_cfg, endpoint, node_id, &json!("Metrics"), raft.cfg.rpc_timeout).map_err(|_| {
                stale("target_voter_unreachable", format!("reachable target voter {node_id}"), "unreachable".into())
            })?;
        let metrics = metrics_response.get("Metrics").ok_or_else(|| {
            stale("target_voter_metrics", format!("Metrics from target voter {node_id}"), "missing".into())
        })?;
        if metrics["running_ok"].as_bool() != Some(true) || metrics["node_id"].as_u64() != Some(node_id) {
            return Err(stale(
                "target_voter_running_ok",
                format!("running voter {node_id}"),
                "not running or node_id mismatch".into(),
            ));
        }
        let summary = metrics
            .get("sm_summary")
            .ok_or_else(|| stale("target_sm_summary", "empty state machine".to_owned(), "missing".into()))?;
        if summary["kv_count"].as_u64() != Some(0)
            || !summary["active_snapshot_id"].is_null()
            || !summary["active_snapshot_file"].is_null()
        {
            return Err(stale(
                "target_sm_summary",
                "empty state machine (kv_count=0, no active snapshot)".to_owned(),
                summary.to_string(),
            ));
        }
        for key in ["refcas/head_seq", "refcas/cluster_incarnation", "refcas/paired_freeze", GROUP_EPOCH_KV_KEY] {
            let (kv_response, _cert_sha) = mtls_rpc_call(
                &raft.tls_cfg,
                endpoint,
                node_id,
                &json!({ "InspectReplicaKv": { "key": key } }),
                raft.cfg.rpc_timeout,
            )?;
            if let Some(value) = kv_response.pointer("/KvValue/value").filter(|value| !value.is_null()) {
                let text = value.as_str().unwrap_or_default();
                let field = if text.parse::<Uuid>().ok().is_some_and(|id| forbidden_incarnations.contains(&id)) {
                    "forbidden_incarnation"
                } else {
                    "dirty_target_raft"
                };
                return Err(stale(field, format!("empty {key} on target voter {node_id}"), text.to_owned()));
            }
        }
    }
    Ok(())
}
