//! Server-side attestation request handlers (querying the voter's own `raft-node`)
//! and client-side helpers used by `MtlsLiveRaftBackend` (#153).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, RefCasCommand, RefCasSnapshot, RefCasStateMachine, encode_command,
};

use super::mtls_raft::MtlsLiveRaftBackend;
use super::mtls_wire::mtls_rpc_call;
use super::peer_attestation::{
    PeerAttestorState, PeerDurableAttestation, PeerDurableAttestationClaims, sync_file_if_exists,
};
use super::types::{PairedBackupError, sha256_json_tagged, validate_hex64};

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
        let response = self.call_raft(&json!("Metrics"))?;
        response
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

    fn verify_running_identity(&self, metrics: &Value) -> Result<u64, PairedBackupError> {
        if metrics["running_ok"].as_bool() != Some(true) || metrics["node_id"].as_u64() != Some(self.node_id) {
            return Err(PairedBackupError::FreezeNotHeld("local raft-node not running or node_id mismatch"));
        }
        Ok(metrics["last_log_index"].as_u64().unwrap_or(0))
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
    if last_log_index < req.min_raft_index {
        return Err(PairedBackupError::FreezeNotHeld("local raft-node log index behind attested commit"));
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
    sync_file_if_exists(&state.data_dir.join("sm.sqlite3"))?;
    sync_file_if_exists(&state.data_dir.join("log.sqlite3"))?;
    let wal_digest = sha256_json_tagged(
        b"rootyard-mtls-peer-wal-v2",
        &(
            state.node_id,
            state.cert_sha256.as_str(),
            persisted.term,
            last_log_index,
            req.seq,
            req.command_sha256.as_str(),
        ),
    )?;
    PeerDurableAttestation::sign(
        PeerDurableAttestationClaims {
            kind: "commit".to_owned(),
            group_id: req.group_id,
            group_epoch: req.group_epoch,
            node_id: state.node_id,
            voter_id: state.voter_id,
            peer_cert_sha256: state.cert_sha256.clone(),
            ed25519_pubkey_hex: state.pubkey_hex.clone(),
            raft_term: persisted.term,
            raft_committed_index: last_log_index,
            refcas_seq: req.seq,
            subject_digest: req.command_sha256,
            secondary_digest: wal_digest,
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
    if state.read_replica_u64("refcas/head_seq")? != req.expected_seq {
        return Err(PairedBackupError::FreezeNotHeld(
            "local raft-node applied seq diverges from the attested cutpoint",
        ));
    }
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
    if snapshot.checksum != req.expected_snapshot_checksum {
        return Err(PairedBackupError::FreezeNotHeld(
            "local replica snapshot checksum diverges from the attested cutpoint",
        ));
    }
    let state_digest = sm.state_digest().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    if state_digest != req.expected_state_digest {
        return Err(PairedBackupError::FreezeNotHeld("local replica state_digest diverges from the attested cutpoint"));
    }
    sync_file_if_exists(&state.data_dir.join("sm.sqlite3"))?;
    sync_file_if_exists(&state.data_dir.join("log.sqlite3"))?;
    PeerDurableAttestation::sign(
        PeerDurableAttestationClaims {
            kind: "cutpoint".to_owned(),
            group_id: req.group_id,
            group_epoch: req.group_epoch,
            node_id: state.node_id,
            voter_id: state.voter_id,
            peer_cert_sha256: state.cert_sha256.clone(),
            ed25519_pubkey_hex: state.pubkey_hex.clone(),
            raft_term: metrics["current_term"].as_u64().unwrap_or(1).max(1),
            raft_committed_index: last_log_index,
            refcas_seq: req.expected_seq,
            subject_digest: req.expected_state_digest,
            secondary_digest: req.expected_snapshot_checksum,
        },
        &state.keypair,
    )
}

/// Wait until the local `raft-node` replica has applied `required_seq`, returning its leaf digest.
pub(super) fn verify_local_replica_caught_up(
    raft: &MtlsLiveRaftBackend,
    required_seq: u64,
) -> Result<String, PairedBackupError> {
    let local_addr = &raft.cfg.voter_endpoints[&raft.cfg.local_node_id];
    let deadline = std::time::Instant::now() + Duration::from_millis(900);
    while std::time::Instant::now() < deadline {
        if let Ok((response, cert_sha)) = mtls_rpc_call(
            &raft.tls_cfg,
            local_addr,
            raft.cfg.local_node_id,
            &json!({ "InspectReplicaKv": { "key": "refcas/head_seq" } }),
            raft.cfg.rpc_timeout,
        ) {
            let seq: u64 =
                response.pointer("/KvValue/value").and_then(Value::as_str).unwrap_or("0").parse().unwrap_or(0);
            if seq >= required_seq {
                return Ok(cert_sha);
            }
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    Err(PairedBackupError::FreezeNotHeld(
        "consensus quorum committed on remote mTLS peers, but local Raft replica WAL/apply lagged",
    ))
}

/// Probe one voter's `PeerAttestationDaemon` and prove its `Identity` is bound to the
/// same X.509 leaf certificate the `raft-node` presented.
pub(super) fn probe_attestor_identity(
    tls_cfg: &Arc<ClientConfig>,
    endpoint: &str,
    node_id: u64,
    observed_cert_sha: &str,
    timeout: Duration,
) -> Result<(String, String), PairedBackupError> {
    let (response, handshake_cert_sha) =
        mtls_rpc_call(tls_cfg, endpoint, node_id, &json!({ "Identity": {} }), timeout)?;
    if handshake_cert_sha != observed_cert_sha {
        return Err(PairedBackupError::FreezeNotHeld(
            "peer attestor certificate differs from the voter's raft-node certificate",
        ));
    }
    let identity = response
        .get("Identity")
        .ok_or(PairedBackupError::FreezeNotHeld("peer attestation daemon rejected Identity probe"))?;
    let reported_cert = identity["peer_cert_sha256"]
        .as_str()
        .ok_or(PairedBackupError::FreezeNotHeld("peer attestation daemon returned no certificate digest"))?;
    let pubkey_hex = identity["ed25519_pubkey_hex"]
        .as_str()
        .ok_or(PairedBackupError::FreezeNotHeld("peer attestation daemon returned no Ed25519 public key"))?;
    if reported_cert != observed_cert_sha
        || identity["node_id"].as_u64() != Some(node_id)
        || !validate_hex64(pubkey_hex)
    {
        return Err(PairedBackupError::FreezeNotHeld(
            "peer attestation identity is not bound to the live voter certificate/key",
        ));
    }
    Ok((reported_cert.to_owned(), pubkey_hex.to_owned()))
}

fn decode_attestation(response: &Value, operation: &'static str) -> Result<PeerDurableAttestation, PairedBackupError> {
    let raw = response.get("Attestation").ok_or(PairedBackupError::FreezeNotHeld(match operation {
        "commit" => "peer attestor refused AttestCommit",
        _ => "peer attestor refused AttestCutpoint",
    }))?;
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
    let attestation = decode_attestation(&response, "commit")?;
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
    raft.trigger_leader_snapshot()?;
    let mut attestations = Vec::new();
    let mut seen = BTreeSet::new();
    for (&node_id, endpoint) in &raft.cfg.attestor_endpoints {
        let Some(binding) = raft.voter_bindings.get(&node_id) else {
            continue;
        };
        let Ok((response, _cert_sha)) = mtls_rpc_call(
            &raft.tls_cfg,
            endpoint,
            node_id,
            &json!({ "AttestCutpoint": {
                "group_id": raft.cfg.group_id,
                "group_epoch": group_epoch,
                "expected_seq": applied.index,
                "expected_state_digest": state_digest,
                "expected_snapshot_checksum": snapshot.checksum.as_str(),
            }}),
            raft.cfg.rpc_timeout,
        ) else {
            continue;
        };
        let Ok(attestation) = decode_attestation(&response, "cutpoint") else {
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
            || claims.subject_digest != state_digest
            || claims.secondary_digest != snapshot.checksum
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

/// Fail-closed brand-new incarnation probe over 100% of the configured target voters.
pub(super) fn verify_pristine_target(
    raft: &MtlsLiveRaftBackend,
    source_membership_digest: &str,
    forbidden_incarnations: &BTreeSet<Uuid>,
) -> Result<(), PairedBackupError> {
    if raft.group_membership_digest == source_membership_digest {
        return Err(PairedBackupError::StaleIncarnation {
            field: "group_membership_digest",
            expected: "brand-new target Raft cluster".into(),
            got: source_membership_digest.to_owned(),
        });
    }
    if raft.cfg.voter_endpoints.len() < 3 {
        return Err(PairedBackupError::InvalidArgument("pristine target check requires >= 3 configured target voters"));
    }
    for (&node_id, endpoint) in &raft.cfg.voter_endpoints {
        let (metrics_response, _cert_sha) =
            mtls_rpc_call(&raft.tls_cfg, endpoint, node_id, &json!("Metrics"), raft.cfg.rpc_timeout).map_err(|_| {
                PairedBackupError::StaleIncarnation {
                    field: "target_voter_unreachable",
                    expected: format!("reachable target voter {node_id}"),
                    got: "unreachable".to_owned(),
                }
            })?;
        let metrics = metrics_response.get("Metrics").ok_or(PairedBackupError::StaleIncarnation {
            field: "target_voter_metrics",
            expected: format!("Metrics from target voter {node_id}"),
            got: "missing".to_owned(),
        })?;
        if metrics["running_ok"].as_bool() != Some(true) || metrics["node_id"].as_u64() != Some(node_id) {
            return Err(PairedBackupError::StaleIncarnation {
                field: "target_voter_running_ok",
                expected: format!("running voter {node_id}"),
                got: "not running or node_id mismatch".to_owned(),
            });
        }
        let summary = metrics.get("sm_summary").ok_or(PairedBackupError::StaleIncarnation {
            field: "target_sm_summary",
            expected: "empty state machine".to_owned(),
            got: "missing".to_owned(),
        })?;
        if summary["kv_count"].as_u64() != Some(0)
            || !summary["active_snapshot_id"].is_null()
            || !summary["active_snapshot_file"].is_null()
        {
            return Err(PairedBackupError::StaleIncarnation {
                field: "target_sm_summary",
                expected: "empty state machine (kv_count=0, no active snapshot)".to_owned(),
                got: summary.to_string(),
            });
        }
        for key in ["refcas/head_seq", "refcas/cluster_incarnation", "refcas/paired_freeze"] {
            let (kv_response, _cert_sha) = mtls_rpc_call(
                &raft.tls_cfg,
                endpoint,
                node_id,
                &json!({ "InspectReplicaKv": { "key": key } }),
                raft.cfg.rpc_timeout,
            )?;
            let value = kv_response.pointer("/KvValue/value").filter(|v| !v.is_null());
            if let Some(value) = value {
                let text = value.as_str().unwrap_or_default();
                let forbidden = text.parse::<Uuid>().ok().is_some_and(|id| forbidden_incarnations.contains(&id));
                return Err(PairedBackupError::StaleIncarnation {
                    field: if forbidden { "forbidden_incarnation" } else { "dirty_target_raft" },
                    expected: format!("empty {key} on target voter {node_id}"),
                    got: text.to_owned(),
                });
            }
        }
    }
    Ok(())
}
