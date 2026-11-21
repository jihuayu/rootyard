//! Linearizable `EnsureReadIndex` consensus floors and linearizable KV reads for the
//! live 3-voter mTLS Raft backend (#153).

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use uuid::Uuid;

use super::mtls_raft::{GROUP_EPOCH_KV_KEY, HEAD_RAFT_INDEX_KV_KEY, MtlsLiveRaftBackend};
use super::mtls_wire::mtls_rpc_call;
use super::peer_attestation::verify_local_replica_caught_up;
use super::types::PairedBackupError;

impl MtlsLiveRaftBackend {
    /// Run the leader's `EnsureReadIndex` quorum barrier, following structured leader redirects.
    fn ensure_read_index(&self) -> Result<u64, PairedBackupError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut target: Option<u64> = None;
        while Instant::now() < deadline {
            let candidate = match target.take() {
                Some(id) if self.cfg.voter_endpoints.contains_key(&id) => id,
                _ => self.probe_live_voters()?.1,
            };
            let addr = &self.cfg.voter_endpoints[&candidate];
            if let Ok((resp, _)) =
                mtls_rpc_call(&self.tls_cfg, addr, candidate, &json!("EnsureReadIndex"), self.cfg.rpc_timeout)
            {
                if let Some(idx) = resp.pointer("/ReadIndex/read_log_id/index").and_then(Value::as_u64) {
                    return Ok(idx);
                }
                if let Some(fwd) = resp.pointer("/Error/forward_to_leader_id").and_then(Value::as_u64)
                    && fwd != candidate
                {
                    target = Some(fwd);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(PairedBackupError::FreezeNotHeld("mTLS EnsureReadIndex consensus floor read failed"))
    }

    pub(super) fn linearizable_kv_get(&self, key: &str) -> Result<Option<String>, PairedBackupError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut target: Option<u64> = None;
        while Instant::now() < deadline {
            let candidate = match target.take() {
                Some(id) if self.cfg.voter_endpoints.contains_key(&id) => id,
                _ => self.probe_live_voters()?.1,
            };
            let addr = &self.cfg.voter_endpoints[&candidate];
            let payload = json!({ "KvGet": { "key": key } });
            if let Ok((resp, _)) = mtls_rpc_call(&self.tls_cfg, addr, candidate, &payload, self.cfg.rpc_timeout) {
                if resp.get("KvValue").is_some() {
                    return Ok(resp.pointer("/KvValue/value").and_then(Value::as_str).map(str::to_owned));
                }
                if let Some(fwd) = resp.pointer("/Error/forward_to_leader_id").and_then(Value::as_u64)
                    && fwd != candidate
                {
                    target = Some(fwd);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(PairedBackupError::FreezeNotHeld("mTLS linearizable ReadIndex KvGet failed"))
    }

    fn linearizable_u64(&self, key: &str) -> Result<u64, PairedBackupError> {
        self.linearizable_kv_get(key)?
            .as_deref()
            .unwrap_or("0")
            .parse()
            .map_err(|_| PairedBackupError::StateMachine("corrupt linearizable Raft counter".into()))
    }

    /// Real Raft consensus log index (`EnsureReadIndex`) proven `>=` the persisted
    /// `refcas/head_raft_index` floor of the last RefCAS apply, never the RefCAS `seq`.
    pub fn linearizable_consensus_index(&self) -> Result<u64, PairedBackupError> {
        let read_idx = self.ensure_read_index()?;
        let seq = self.linearizable_u64("refcas/head_seq")?;
        let head_raft_idx = self.linearizable_u64(HEAD_RAFT_INDEX_KV_KEY)?;
        let _ = verify_local_replica_caught_up(self, seq)?;
        if seq == 0 && head_raft_idx == 0 {
            return Ok(read_idx);
        }
        if head_raft_idx < seq || read_idx < head_raft_idx {
            return Err(PairedBackupError::FreezeNotHeld(
                "linearizable Raft read index lags the persisted head_seq consensus index",
            ));
        }
        Ok(read_idx)
    }
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
        for key in [
            "refcas/head_seq",
            HEAD_RAFT_INDEX_KV_KEY,
            "refcas/cluster_incarnation",
            "refcas/paired_freeze",
            GROUP_EPOCH_KV_KEY,
        ] {
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
