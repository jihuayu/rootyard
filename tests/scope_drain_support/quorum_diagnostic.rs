//! Test-only bounded quorum observation for the real Root Raft case.
//!
//! One observed call samples the existing three owned `RootRaftNode` metric snapshots
//! synchronously before the original future is polled and again immediately after it returns an
//! error. It performs no extra RPC, SQLite, probe, await or retry. Its fixed stderr JSON frame is
//! emitted only on error and is bounded to 8192 bytes. No identity, address, log object, PKI
//! material or payload is serialized.
//!
//! The listener retains only fixed-slot counters and scalars for non-empty AppendEntries decoded at
//! the existing test mTLS boundary. A second fixed companion frame is emitted only from the
//! existing case-level failure receipt and never from a successful run.

use std::collections::BTreeMap;
use std::future::Future;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::time::Instant;

use openraft::error::Fatal;
use openraft::raft::AppendEntriesResponse;
use openraft::{LogId, ServerState};
use rootyard::ref_store::raft_backend::{RaftBackendError, RootRaftNode};
use rootyard_refcas_log::cluster::RpcResponse;
use serde::Serialize;

use super::{PhaseGuard, PhaseLabel};

#[path = "../../src/ref_store/raft_backend/backend/cause.rs"]
mod cause;

pub(crate) use cause::Operation;

const SCHEMA: &str = "rootyard.quorum_diagnostics.v2";
const FRAME_PREFIX: &str = "ROOTYARD_QUORUM_DIAGNOSTICS v2 ";
const MAX_FRAME_BYTES: usize = 8_192;
const MAX_ELAPSED_MS: u64 = 900_000;
const MAX_TERM: u64 = 1_000_000_000;
const MAX_LOG_INDEX: u64 = 1_000_000_000_000;
const MAX_MILLIS_SINCE_QUORUM_ACK: u64 = 900_000;
const FIXTURE_SLOTS: [u8; 3] = [1, 2, 3];
const APPEND_WITNESS_SCHEMA: &str = "rootyard.append_witness.v1";
const APPEND_WITNESS_PREFIX: &str = "ROOTYARD_APPEND_WITNESS v1 ";
const MAX_APPEND_WITNESS_BYTES: usize = 8_192;
const MAX_APPEND_ENTRIES: u64 = 1_000_000;
const MAX_APPEND_COUNT: u64 = 1_000_000;
const APPEND_SLOTS: usize = 3;
const NONE_INDEX: u64 = u64::MAX;
const HANDLER_NONE: u8 = 0;
const HANDLER_SUCCESS: u8 = 1;
const HANDLER_PARTIAL_SUCCESS: u8 = 2;
const HANDLER_CONFLICT: u8 = 3;
const HANDLER_HIGHER_VOTE: u8 = 4;
const HANDLER_RAFT_ERROR: u8 = 5;
const HANDLER_OTHER: u8 = 6;

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
    replication_matching: Option<Vec<MatchingSample>>,
}

#[derive(Serialize)]
struct MatchingSample {
    slot: u8,
    matched_index: Option<u64>,
    matched_term: Option<u64>,
    matched_leader_slot: Option<&'static str>,
}

/// Polls `future` exactly once around two synchronous fixed-node metric snapshots.
pub(crate) async fn observe_call<P, T, F>(
    phase: &PhaseGuard<P>,
    cluster: &crate::TestCluster,
    operation: Operation,
    future: F,
) -> Result<T, RaftBackendError>
where
    P: PhaseLabel,
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
    let observed_leader_slot = leader_slot(metrics.current_leader);
    let matching = replication_matching(metrics.replication.as_ref(), &mut numeric_overflow);
    NodeSample {
        slot,
        running_state: running_state(&metrics.running_state),
        server_state: server_state(metrics.state),
        leader_slot: observed_leader_slot,
        term,
        last_log_index,
        last_applied_index,
        voter_count,
        millis_since_quorum_ack,
        numeric_overflow,
        replication_matching: matching,
    }
}

/// Projects `RaftMetrics::replication` matching coordinates from the already-read metrics value.
///
/// The map is present only on a leader and contains the local leader plus both remote targets. An
/// exact fixed three-slot key set is required; any other shape is reported as unavailable without
/// exposing the observed identifiers. A present target with no matching log id keeps all three
/// coordinate fields null, which is distinct from an absent target. The matched leader slot is the
/// actual proposer retained in the matching `LogId` (the pinned configuration keeps
/// `leader_id.node_id`), not this publication's current leader. A coordinate for an older log is
/// therefore not relabelled after a leadership change. This is published per-target progress, not a
/// remote acknowledgment and not a commit claim.
fn replication_matching(
    replication: Option<&BTreeMap<u64, Option<LogId<u64>>>>,
    overflow: &mut bool,
) -> Option<Vec<MatchingSample>> {
    let replication = replication?;
    if replication.len() != FIXTURE_SLOTS.len()
        || !FIXTURE_SLOTS.iter().all(|slot| replication.contains_key(&u64::from(*slot)))
    {
        return None;
    }
    let mut entries = Vec::with_capacity(FIXTURE_SLOTS.len());
    for slot in FIXTURE_SLOTS {
        let matching_log_id = replication.get(&u64::from(slot)).copied().flatten();
        let (matched_index, matched_term) = match matching_log_id {
            Some(log_id) => (
                Some(bounded(log_id.index, MAX_LOG_INDEX, overflow)),
                Some(bounded(log_id.leader_id.term, MAX_TERM, overflow)),
            ),
            None => (None, None),
        };
        entries.push(MatchingSample {
            slot,
            matched_index,
            matched_term,
            matched_leader_slot: matching_leader_slot(matching_log_id),
        });
    }
    Some(entries)
}

/// Maps the actual matching log proposer into the same closed slot vocabulary as `leader_slot`.
///
/// Raw node identifiers are never serialized. Unknown identifiers become `"other"`.
const fn matching_leader_slot(matching: Option<LogId<u64>>) -> Option<&'static str> {
    match matching {
        Some(log_id) => Some(leader_slot(Some(log_id.leader_id.node_id))),
        None => None,
    }
}

/// Compile-time regression for proposer attribution with the actual configured `LogId` type.
///
/// A runtime `#[test]` cannot be added here without changing the fixed three-case integration-test
/// inventory. This constant item is compiled by the integration test target and calls the same
/// helper used by the projection. It constructs a log proposed by slot 2 while the observed current
/// leader is slot 1, proving the projection does not coerce the historical proposer.
#[cfg(test)]
const _: () = {
    const fn bytes_equal(left: &str, right: &str) -> bool {
        let left = left.as_bytes();
        let right = right.as_bytes();
        if left.len() != right.len() {
            return false;
        }
        let mut index = 0;
        while index < left.len() {
            if left[index] != right[index] {
                return false;
            }
            index += 1;
        }
        true
    }

    const fn option_str_is(value: Option<&str>, expected: &str) -> bool {
        match value {
            Some(actual) => bytes_equal(actual, expected),
            None => false,
        }
    }

    let matched = LogId { leader_id: openraft::CommittedLeaderId { term: 6, node_id: 2 }, index: 11 };
    let observed_current_leader: Option<u64> = Some(1);
    assert!(option_str_is(matching_leader_slot(Some(matched)), "slot2"));
    assert!(!option_str_is(matching_leader_slot(Some(matched)), "slot1"));
    assert!(matching_leader_slot(None).is_none());
    assert!(bytes_equal(leader_slot(observed_current_leader), "slot1"));
};

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

const fn leader_slot(value: Option<u64>) -> &'static str {
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

fn emit<P: PhaseLabel>(
    phase: &PhaseGuard<P>,
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
        case: phase.case(),
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

/// Bounded retained state for non-empty AppendEntries observed at one fixture listener.
struct AppendCell {
    decoded: AtomicU64,
    handled: AtomicU64,
    write_ok: AtomicU64,
    write_error: AtomicU64,
    term: AtomicU64,
    prev_index: AtomicU64,
    first_index: AtomicU64,
    last_index: AtomicU64,
    entry_count: AtomicU64,
    handler: AtomicU8,
    /// Sticky across observed events: a later in-range event does not clear it.
    overflow: AtomicBool,
}

impl AppendCell {
    const fn new() -> Self {
        Self {
            decoded: AtomicU64::new(0),
            handled: AtomicU64::new(0),
            write_ok: AtomicU64::new(0),
            write_error: AtomicU64::new(0),
            term: AtomicU64::new(0),
            prev_index: AtomicU64::new(NONE_INDEX),
            first_index: AtomicU64::new(0),
            last_index: AtomicU64::new(0),
            entry_count: AtomicU64::new(0),
            handler: AtomicU8::new(HANDLER_NONE),
            overflow: AtomicBool::new(false),
        }
    }
}

static APPEND_CELLS: [AppendCell; APPEND_SLOTS * APPEND_SLOTS] = [
    AppendCell::new(),
    AppendCell::new(),
    AppendCell::new(),
    AppendCell::new(),
    AppendCell::new(),
    AppendCell::new(),
    AppendCell::new(),
    AppendCell::new(),
    AppendCell::new(),
];

#[derive(Serialize)]
struct AppendWitnessFrame {
    schema: &'static str,
    case: &'static str,
    observations: Vec<AppendObservation>,
}

#[derive(Serialize)]
struct AppendObservation {
    target_slot: u8,
    sender_slot: u8,
    decoded: u64,
    handled: u64,
    handler: &'static str,
    write_ok: u64,
    write_error: u64,
    term: u64,
    prev_index: Option<u64>,
    first_index: u64,
    last_index: u64,
    entry_count: u64,
    /// Sticky historical saturation flag. A later in-range event can replace every gauge above
    /// while this remains true, so it does not imply that a current gauge equals its cap.
    overflow: bool,
}

/// Clears only the retained fixed-slot listener state at the start of the real case.
pub(crate) fn reset_append_witness() {
    for cell in &APPEND_CELLS {
        cell.decoded.store(0, Ordering::Relaxed);
        cell.handled.store(0, Ordering::Relaxed);
        cell.write_ok.store(0, Ordering::Relaxed);
        cell.write_error.store(0, Ordering::Relaxed);
        cell.term.store(0, Ordering::Relaxed);
        cell.prev_index.store(NONE_INDEX, Ordering::Relaxed);
        cell.first_index.store(0, Ordering::Relaxed);
        cell.last_index.store(0, Ordering::Relaxed);
        cell.entry_count.store(0, Ordering::Relaxed);
        cell.handler.store(HANDLER_NONE, Ordering::Relaxed);
        cell.overflow.store(false, Ordering::Relaxed);
    }
}

/// Records a non-empty AppendEntries after decoding and before the real handler is awaited.
#[allow(clippy::too_many_arguments)]
pub(crate) fn note_append_decoded(
    target_slot: u8,
    sender: u64,
    term: u64,
    prev_index: Option<u64>,
    first_index: u64,
    last_index: u64,
    entry_count: u64,
) {
    let Some(index) = append_cell_index(target_slot, sender) else {
        return;
    };
    let cell = &APPEND_CELLS[index];
    let mut overflow = false;
    let term = bounded(term, MAX_TERM, &mut overflow);
    let prev_index = prev_index.map(|value| bounded(value, MAX_LOG_INDEX, &mut overflow)).unwrap_or(NONE_INDEX);
    let first_index = bounded(first_index, MAX_LOG_INDEX, &mut overflow);
    let last_index = bounded(last_index, MAX_LOG_INDEX, &mut overflow);
    let entry_count = bounded(entry_count, MAX_APPEND_ENTRIES, &mut overflow);
    cell.term.store(term, Ordering::Relaxed);
    cell.prev_index.store(prev_index, Ordering::Relaxed);
    cell.first_index.store(first_index, Ordering::Relaxed);
    cell.last_index.store(last_index, Ordering::Relaxed);
    cell.entry_count.store(entry_count, Ordering::Relaxed);
    bump(&cell.decoded, &cell.overflow);
    if overflow {
        cell.overflow.store(true, Ordering::Relaxed);
    }
}

/// Records the real handler result class without retaining the response or any error text.
pub(crate) fn note_append_handled(target_slot: u8, sender: u64, response: &RpcResponse) {
    let Some(index) = append_cell_index(target_slot, sender) else {
        return;
    };
    let handler = match response {
        RpcResponse::AppendEntries(result) => match result.as_ref() {
            Ok(AppendEntriesResponse::Success) => HANDLER_SUCCESS,
            Ok(AppendEntriesResponse::PartialSuccess(_)) => HANDLER_PARTIAL_SUCCESS,
            Ok(AppendEntriesResponse::Conflict) => HANDLER_CONFLICT,
            Ok(AppendEntriesResponse::HigherVote(_)) => HANDLER_HIGHER_VOTE,
            Err(_) => HANDLER_RAFT_ERROR,
        },
        RpcResponse::Error { .. } => HANDLER_RAFT_ERROR,
        _ => HANDLER_OTHER,
    };
    let cell = &APPEND_CELLS[index];
    cell.handler.store(handler, Ordering::Relaxed);
    bump(&cell.handled, &cell.overflow);
}

/// Records whether the existing framed response write completed for the observed request.
pub(crate) fn note_append_written(target_slot: u8, sender: u64, completed: bool) {
    let Some(index) = append_cell_index(target_slot, sender) else {
        return;
    };
    let cell = &APPEND_CELLS[index];
    if completed {
        bump(&cell.write_ok, &cell.overflow);
    } else {
        bump(&cell.write_error, &cell.overflow);
    }
}

fn append_cell_index(target_slot: u8, sender: u64) -> Option<usize> {
    if target_slot == 0 || usize::from(target_slot) > APPEND_SLOTS {
        return None;
    }
    let sender_slot = u8::try_from(sender).ok().filter(|slot| usize::from(*slot) <= APPEND_SLOTS)?;
    Some((usize::from(target_slot) - 1) * APPEND_SLOTS + (usize::from(sender_slot) - 1))
}

fn bump(counter: &AtomicU64, overflow: &AtomicBool) {
    let previous = counter.fetch_add(1, Ordering::Relaxed);
    if previous >= MAX_APPEND_COUNT {
        counter.store(MAX_APPEND_COUNT, Ordering::Relaxed);
        overflow.store(true, Ordering::Relaxed);
    }
}

const fn handler_name(code: u8) -> &'static str {
    match code {
        HANDLER_SUCCESS => "success",
        HANDLER_PARTIAL_SUCCESS => "partial_success",
        HANDLER_CONFLICT => "conflict",
        HANDLER_HIGHER_VOTE => "higher_vote",
        HANDLER_RAFT_ERROR => "raft_error",
        HANDLER_OTHER => "other",
        HANDLER_NONE => "none",
        _ => "other",
    }
}

/// Emits the fixed companion frame only when called from the real case failure receipt.
pub(crate) fn emit_append_witness(case: &'static str) {
    let mut observations = Vec::new();
    for target_slot in 1..=3_u8 {
        for sender_slot in 1..=3_u64 {
            let Some(index) = append_cell_index(target_slot, sender_slot) else {
                continue;
            };
            let cell = &APPEND_CELLS[index];
            let decoded = cell.decoded.load(Ordering::Relaxed);
            if decoded == 0 {
                continue;
            }
            let prev_index = match cell.prev_index.load(Ordering::Relaxed) {
                NONE_INDEX => None,
                value => Some(value),
            };
            observations.push(AppendObservation {
                target_slot,
                sender_slot: u8::try_from(sender_slot).expect("fixture slot"),
                decoded,
                handled: cell.handled.load(Ordering::Relaxed),
                handler: handler_name(cell.handler.load(Ordering::Relaxed)),
                write_ok: cell.write_ok.load(Ordering::Relaxed),
                write_error: cell.write_error.load(Ordering::Relaxed),
                term: cell.term.load(Ordering::Relaxed),
                prev_index,
                first_index: cell.first_index.load(Ordering::Relaxed),
                last_index: cell.last_index.load(Ordering::Relaxed),
                entry_count: cell.entry_count.load(Ordering::Relaxed),
                overflow: cell.overflow.load(Ordering::Relaxed),
            });
        }
    }
    let frame = AppendWitnessFrame { schema: APPEND_WITNESS_SCHEMA, case, observations };
    let Ok(payload) = serde_json::to_string(&frame) else {
        return;
    };
    let line = format!("\n{APPEND_WITNESS_PREFIX}{payload}\n");
    if line.len() > MAX_APPEND_WITNESS_BYTES {
        return;
    }
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}
