//! Production mTLS `raft-node` committed writer for `pm/*` Ref-CAS slots (#122).
//!
//! The writer resolves the active Raft leader, reads `pm/head` through a linearizable `KvGet`,
//! writes every slot on the exact leader that owns `expected_term`, and only then replays that
//! leader's committed state. A changed term, a forwarded `Error`, or a corrupt `pm/*` value fails
//! closed instead of retrying or defaulting.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use serde_json::{Value, json};

use crate::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, RefCasCommand, RefCasStateMachine, StateMachineError,
};

use super::{
    SafeGcError,
    voter_service::{MtlsReplicaEndpoint, parse_pm_head_slot, raft_mtls_rpc, replay_raft_replica},
};

/// Result the committed `pm/*` command produced when the leader replayed it.
pub type RaftCommitApplyOutcome = Option<std::result::Result<ApplyResponse, StateMachineError>>;

/// Committed `pm/*` writer bound to one pinned `raft-node` replica per consensus member.
#[derive(Clone)]
pub struct SafeGcRaftCommitWriter {
    replicas: BTreeMap<u64, MtlsReplicaEndpoint>,
    write_timeout: Duration,
}

impl SafeGcRaftCommitWriter {
    /// Build a writer over the pinned replicas; an empty set or zero timeout is invalid.
    pub fn new(replicas: BTreeMap<u64, MtlsReplicaEndpoint>, write_timeout: Duration) -> Result<Self, SafeGcError> {
        if replicas.is_empty() || write_timeout.is_zero() {
            return Err(SafeGcError::InvalidInput(
                "safe-gc raft commit writer needs at least one replica and a non-zero timeout".into(),
            ));
        }
        Ok(Self { replicas, write_timeout })
    }

    /// Poll until one pinned replica reports a healthy leader with a completed read index.
    pub async fn wait_active_leader(&self) -> Result<(u64, u64), SafeGcError> {
        let deadline = Instant::now() + self.write_timeout;
        loop {
            for endpoint in self.replicas.values() {
                let Ok(metrics) = raft_mtls_rpc(endpoint, json!("Metrics")).await else { continue };
                let running = metrics.pointer("/Metrics/running_ok").and_then(Value::as_bool) == Some(true);
                let term = metrics.pointer("/Metrics/current_term").and_then(Value::as_u64).unwrap_or(0);
                let Some(leader_id) = metrics.pointer("/Metrics/current_leader").and_then(Value::as_u64) else {
                    continue;
                };
                if !running || term == 0 || !self.replicas.contains_key(&leader_id) {
                    continue;
                }
                let Some(leader) = self.replicas.get(&leader_id) else { continue };
                let Ok(read_index) = raft_mtls_rpc(leader, json!("EnsureReadIndex")).await else { continue };
                if read_index.get("ReadIndex").is_none() {
                    continue;
                }
                let Ok(confirmed) = raft_mtls_rpc(leader, json!("Metrics")).await else { continue };
                if confirmed.pointer("/Metrics/running_ok").and_then(Value::as_bool) == Some(true)
                    && confirmed.pointer("/Metrics/current_leader").and_then(Value::as_u64) == Some(leader_id)
                    && confirmed.pointer("/Metrics/current_term").and_then(Value::as_u64) == Some(term)
                {
                    return Ok((leader_id, term));
                }
            }
            if Instant::now() >= deadline {
                return Err(SafeGcError::InvalidInput("raft-node never reported an active leader".into()));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Read `pm/head` through a linearizable `KvGet` served by the confirmed leader.
    pub async fn read_linearizable_head_slot(&self) -> Result<(u64, u64, u64), SafeGcError> {
        let deadline = Instant::now() + self.write_timeout;
        let (mut leader_id, mut term) = self.wait_active_leader().await?;
        loop {
            let Some(endpoint) = self.replicas.get(&leader_id) else {
                (leader_id, term) = self.retry_leader(deadline, "raft-node leader left the pinned set").await?;
                continue;
            };
            let Ok(response) = raft_mtls_rpc(endpoint, json!({ "KvGet": { "key": "pm/head" } })).await else {
                (leader_id, term) = self.retry_leader(deadline, "raft-node pm/head unreadable on the leader").await?;
                continue;
            };
            let Some(kv) = response.get("KvValue") else {
                (leader_id, term) = self.retry_leader(deadline, "raft-node pm/head unreadable on the leader").await?;
                continue;
            };
            let head_slot = match kv.get("value") {
                Some(Value::Null) => 0,
                Some(Value::String(raw)) => parse_pm_head_slot(Some(raw.as_str()))?,
                _ => return Err(SafeGcError::Serialization("raft-node pm/head has an unsupported JSON type".into())),
            };
            if self.exact_leader_active(leader_id, term).await {
                return Ok((leader_id, term, head_slot));
            }
            (leader_id, term) = self.retry_leader(deadline, "raft-node pm/head served by a stale leader").await?;
        }
    }

    /// Commit one Ref-CAS command into the next `pm/*` slot and replay the leader's committed state.
    pub async fn commit_command(
        &self,
        command: &RefCasCommand,
    ) -> Result<(AppliedLogId, RefCasStateMachine, RaftCommitApplyOutcome), SafeGcError> {
        let (leader_id, term, head) = self.read_linearizable_head_slot().await?;
        let slot = head.checked_add(1).ok_or_else(|| SafeGcError::InvalidInput("pm/head slot overflow".into()))?;
        let payload = serde_json::to_string(command).map_err(|err| SafeGcError::Serialization(err.to_string()))?;
        let entry_key = format!("pm/{slot:08}");
        let index = self.write_kv_on_exact_leader(leader_id, term, &entry_key, &payload).await?;
        let idx_key = format!("{entry_key}/idx");
        let _ = self.write_kv_on_exact_leader(leader_id, term, &idx_key, &index.to_string()).await?;
        let term_key = format!("{entry_key}/term");
        let _ = self.write_kv_on_exact_leader(leader_id, term, &term_key, &term.to_string()).await?;
        let head_value = slot.to_string();
        let _ = self.write_kv_on_exact_leader(leader_id, term, "pm/head", &head_value).await?;
        self.await_replicated_head(slot).await?;
        let Some(endpoint) = self.replicas.get(&leader_id) else {
            return Err(SafeGcError::InvalidInput("raft-node leader left the pinned set".into()));
        };
        let replay = replay_raft_replica(endpoint).await?;
        Ok((AppliedLogId { term, index }, replay.sm, replay.last))
    }

    async fn retry_leader(&self, deadline: Instant, reason: &'static str) -> Result<(u64, u64), SafeGcError> {
        if Instant::now() >= deadline {
            return Err(SafeGcError::InvalidInput(reason.into()));
        }
        self.wait_active_leader().await
    }

    async fn exact_leader_active(&self, leader_id: u64, expected_term: u64) -> bool {
        let Some(endpoint) = self.replicas.get(&leader_id) else { return false };
        let Ok(metrics) = raft_mtls_rpc(endpoint, json!("Metrics")).await else { return false };
        metrics.pointer("/Metrics/running_ok").and_then(Value::as_bool) == Some(true)
            && metrics.pointer("/Metrics/current_leader").and_then(Value::as_u64) == Some(leader_id)
            && metrics.pointer("/Metrics/current_term").and_then(Value::as_u64) == Some(expected_term)
            && expected_term > 0
    }

    async fn write_kv_on_exact_leader(
        &self,
        leader_id: u64,
        expected_term: u64,
        key: &str,
        value: &str,
    ) -> Result<u64, SafeGcError> {
        if !self.exact_leader_active(leader_id, expected_term).await {
            return Err(SafeGcError::InvalidInput("raft-node leader changed before the pm write".into()));
        }
        let Some(endpoint) = self.replicas.get(&leader_id) else {
            return Err(SafeGcError::InvalidInput("raft-node leader left the pinned set".into()));
        };
        let payload = serde_json::to_vec(&json!({ "Put": { "key": key, "value": value } }))
            .map_err(|err| SafeGcError::Serialization(err.to_string()))?;
        let response = raft_mtls_rpc(endpoint, json!({ "ClientWrite": { "payload": payload } })).await?;
        let log_index = response.pointer("/ClientWrite/log_index").and_then(Value::as_u64).unwrap_or(0);
        if response.get("Error").is_some() || log_index == 0 {
            return Err(SafeGcError::InvalidInput("raft-node ClientWrite did not commit on the exact leader".into()));
        }
        if !self.exact_leader_active(leader_id, expected_term).await {
            return Err(SafeGcError::InvalidInput("raft-node leader term changed mid-slot".into()));
        }
        Ok(log_index)
    }

    async fn await_replicated_head(&self, slot: u64) -> Result<(), SafeGcError> {
        let wanted = slot.to_string();
        let quorum = (self.replicas.len() / 2) + 1;
        let deadline = Instant::now() + self.write_timeout;
        loop {
            let mut observed = 0_usize;
            for endpoint in self.replicas.values() {
                let probe = json!({ "InspectReplicaKv": { "key": "pm/head" } });
                if let Ok(response) = raft_mtls_rpc(endpoint, probe).await
                    && response.pointer("/KvValue/value").and_then(Value::as_str) == Some(wanted.as_str())
                {
                    observed += 1;
                }
            }
            if observed == self.replicas.len() && observed >= quorum {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(SafeGcError::InvalidInput(
                    "raft-node replicas never observed the committed pm/head".into(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}
