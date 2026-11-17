//! Test-only bounded quorum observation for the real Root Raft case.
//!
//! One observed call samples the existing three owned `RootRaftNode` metric snapshots
//! synchronously before the original future is polled and again immediately after it returns an
//! error. It performs no extra RPC, SQLite, probe, await or retry. A single fixed stderr JSON frame
//! is emitted only on error and is bounded to 8192 bytes. No identity, address, log object, PKI
//! material or payload is serialized.

use std::future::Future;
use std::io::Write;
use std::time::Instant;

use openraft::ServerState;
use openraft::error::Fatal;
use rootyard::ref_store::raft_backend::{RaftBackendError, RootRaftNode};
use serde::Serialize;

use super::{CASE_REAL, Phase, PhaseGuard, PhaseLabel};

#[path = "../../src/ref_store/raft_backend/backend/cause.rs"]
mod cause;

pub(crate) use cause::Operation;

const SCHEMA: &str = "rootyard.quorum_diagnostics.v1";
const FRAME_PREFIX: &str = "ROOTYARD_QUORUM_DIAGNOSTICS v1 ";
const MAX_FRAME_BYTES: usize = 8_192;
const MAX_ELAPSED_MS: u64 = 900_000;
const MAX_TERM: u64 = 1_000_000_000;
const MAX_LOG_INDEX: u64 = 1_000_000_000_000;
const MAX_MILLIS_SINCE_QUORUM_ACK: u64 = 900_000;

#[derive(Serialize)]
struct Frame {
    schema: &'static str,
    case: &'static str,
    phase: &'static str,
    operation: &'static str,
    cause: &'static str,
    elapsed_ms: u64,
    elapsed_overflow: bool,
    snapshots: Vec<Snapshot>,
}

#[derive(Serialize)]
struct Snapshot {
    at: &'static str,
    nodes: Vec<NodeSample>,
}

#[derive(Serialize)]
struct NodeSample {
    slot: u8,
    running_state: &'static str,
    server_state: &'static str,
    leader_slot: &'static str,
    term: Option<u64>,
    last_log_index: Option<u64>,
    last_applied_index: Option<u64>,
    voter_count: Option<u64>,
    millis_since_quorum_ack: Option<u64>,
    numeric_overflow: bool,
}

/// Polls `future` exactly once around two synchronous fixed-node metric snapshots.
pub(crate) async fn observe_call<T, F>(
    phase: &PhaseGuard<Phase>,
    cluster: &crate::TestCluster,
    operation: Operation,
    future: F,
) -> Result<T, RaftBackendError>
where
    F: Future<Output = Result<T, RaftBackendError>>,
{
    let started = Instant::now();
    let before = sample(cluster, "before");
    let result = future.await;
    if let Err(error) = &result {
        let after = sample(cluster, "after");
        if let (Some(before), Some(after)) = (before, after) {
            emit(phase, operation, error, started, before, after);
        }
    }
    result
}

fn sample(cluster: &crate::TestCluster, at: &'static str) -> Option<Snapshot> {
    let mut nodes = Vec::with_capacity(3);
    for node in &cluster.nodes {
        let slot = match node.id {
            1 => 1,
            2 => 2,
            3 => 3,
            _ => return None,
        };
        nodes.push(node_sample(slot, &node.node));
    }
    nodes.sort_by_key(|node| node.slot);
    if nodes.len() != 3 || nodes[0].slot != 1 || nodes[1].slot != 2 || nodes[2].slot != 3 {
        return None;
    }
    Some(Snapshot { at, nodes })
}

fn node_sample(slot: u8, node: &RootRaftNode) -> NodeSample {
    let metrics = node.metrics();
    let mut numeric_overflow = false;
    let term = Some(bounded(metrics.current_term, MAX_TERM, &mut numeric_overflow));
    let last_log_index = metrics.last_log_index.map(|value| bounded(value, MAX_LOG_INDEX, &mut numeric_overflow));
    let last_applied_index =
        metrics.last_applied.map(|log_id| bounded(log_id.index, MAX_LOG_INDEX, &mut numeric_overflow));
    let voter_count = u64::try_from(metrics.membership_config.membership().voter_ids().count()).ok();
    let millis_since_quorum_ack =
        metrics.millis_since_quorum_ack.map(|value| bounded(value, MAX_MILLIS_SINCE_QUORUM_ACK, &mut numeric_overflow));
    NodeSample {
        slot,
        running_state: running_state(&metrics.running_state),
        server_state: server_state(metrics.state),
        leader_slot: leader_slot(metrics.current_leader),
        term,
        last_log_index,
        last_applied_index,
        voter_count,
        millis_since_quorum_ack,
        numeric_overflow,
    }
}

fn bounded(value: u64, maximum: u64, overflow: &mut bool) -> u64 {
    if value > maximum {
        *overflow = true;
        maximum
    } else {
        value
    }
}

fn running_state(value: &Result<(), Fatal<u64>>) -> &'static str {
    match value {
        Ok(()) => "ok",
        Err(Fatal::StorageError(_)) => "storage_fatal",
        Err(Fatal::Panicked) => "panicked",
        Err(Fatal::Stopped) => "stopped",
    }
}

fn server_state(value: ServerState) -> &'static str {
    match value {
        ServerState::Learner => "learner",
        ServerState::Follower => "follower",
        ServerState::Candidate => "candidate",
        ServerState::Leader => "leader",
        ServerState::Shutdown => "shutdown",
    }
}

fn leader_slot(value: Option<u64>) -> &'static str {
    match value {
        Some(1) => "slot1",
        Some(2) => "slot2",
        Some(3) => "slot3",
        Some(_) => "other",
        None => "none",
    }
}

fn classify(error: &RaftBackendError, expected: Operation) -> (Operation, &'static str) {
    match error {
        RaftBackendError::QuorumUnavailable(code) => match cause::Site::decode(code) {
            Some(site) => (site.operation(), site.cause().code()),
            None => (expected, "unclassified"),
        },
        RaftBackendError::FollowerRedirect(_) => {
            let cause = match expected {
                Operation::ClientWrite => "write_forward",
                _ => "read_forward",
            };
            (expected, cause)
        }
        _ => (expected, "unclassified"),
    }
}

fn emit(
    phase: &PhaseGuard<Phase>,
    expected: Operation,
    error: &RaftBackendError,
    started: Instant,
    before: Snapshot,
    after: Snapshot,
) {
    let (operation, cause) = classify(error, expected);
    let elapsed = started.elapsed().as_millis();
    let (elapsed_ms, elapsed_overflow) =
        if elapsed > u128::from(MAX_ELAPSED_MS) { (MAX_ELAPSED_MS, true) } else { (elapsed as u64, false) };
    let frame = Frame {
        schema: SCHEMA,
        case: CASE_REAL,
        phase: phase.current().code(),
        operation: operation.code(),
        cause,
        elapsed_ms,
        elapsed_overflow,
        snapshots: vec![before, after],
    };
    let Ok(payload) = serde_json::to_string(&frame) else {
        return;
    };
    let line = format!("\n{FRAME_PREFIX}{payload}\n");
    if line.len() > MAX_FRAME_BYTES {
        return;
    }
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}
