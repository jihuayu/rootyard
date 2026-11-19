//! Dedicated slow-body witness for the original #42 distinct-ref criterion.
//!
//! This module is compiled only through its `cfg(test)` parent. It reuses the
//! parent's real fixture, teardown and PostgreSQL helpers, and adds only a
//! router-local request-body observer plus the strict two-ACK/private-wrapper
//! assertions. No production router, state, route or configuration reaches it.

use std::{
    collections::HashMap,
    io::{self, Write},
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, ensure};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::Request,
    middleware::{self, Next},
    response::Response,
};
use futures_util::{FutureExt, StreamExt};
use serde_json::Value;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::oneshot,
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use uuid::Uuid;

use super::super::session_http_acceptance::fixtures::{
    actor::{self, Actor},
    db::{Db, deadline, prepare},
    git::{self, Git},
};
use super::{
    Captures, INDEPENDENT_A, INDEPENDENT_B, SEED_CONTENT, SEED_FILE, SEED_REF, WitnessResources, clone_url,
    create_repository, durable_ref, gate_revision, open_store, pinned_operation, provision_decision_realm,
    report_status, require_owned_disposable_blob_fixture, require_per_run_blob_prefix,
};
use crate::{
    blob_git_gateway::{
        BlobGitConfig, BlobGitState, NATIVE_ACCEPTANCE_SERIAL, operation,
        protocol::{self, MAX_COMMAND_BYTES},
        router,
    },
    ref_store::{
        CommitMode, GitObjectFormat, OperationState, PgRefStore, RefCommitResult, RequestDigest, TerminalKind,
        core::pack_commit::PackCommitTerminal,
        pg::public_attempt::{PublicAttemptLookup, PublicAttemptRequest},
        serving::{ServingRepository, lookup},
    },
};

/// Two incompressible, deterministic fixture files keep both incoming packs
/// nontrivially larger than the minimum progress interval the witness requires.
const SLOW_PACK_BYTES: usize = 2 * 1024 * 1024;
/// The test-only receive-body wrapper delays each already-observed data frame
/// before handing it to the handler. This is body pacing, not response pacing
/// and not a synthetic client frame.
const SLOW_FRAME_PACE: Duration = Duration::from_millis(8);
/// Bound each unchanged slice of an incoming data frame so minimal advancing
/// observations do not depend on hyper's delivery chunk size.
const MAX_OBSERVED_CHUNK_BYTES: usize = 16 * 1024;
/// Above either fixture pack and below the gateway request ceiling. This is a
/// command-local bound only; stock Git's global/default HTTP configuration is
/// never read or written by this test.
const FIXTURE_HTTP_POST_BUFFER_BYTES: usize = 4 * 1024 * 1024;
/// A progress segment must reach this much actual pack stream on both sides.
const MIN_OVERLAP_PACK_BYTES: u64 = 64 * 1024;
/// Bounded receipt: never retain an unbounded number of observed frames.
const MAX_BODY_SAMPLES: usize = 8_192;
/// Bounded receipt: enough bytes to parse the real pkt-line command section.
const MAX_BODY_PREFIX: usize = MAX_COMMAND_BYTES + 4;

#[derive(Clone, Copy, Debug)]
struct BodySample {
    at: Instant,
    pack_bytes: u64,
}

#[derive(Clone, Debug, Default)]
struct BodyTrace {
    total_bytes: u64,
    command_end: Option<usize>,
    prefix: Vec<u8>,
    samples: Vec<BodySample>,
    samples_truncated: bool,
    content_encoded: bool,
    completed: Option<Instant>,
}

/// Test-only witness for exactly two pinned receive-pack operations. It is
/// attached only by this harness' router, and it records bytes as the production
/// receive handler consumes its actual request body stream.
struct BodyWitness {
    first: Uuid,
    second: Uuid,
    receipt_root: PathBuf,
    state: Mutex<BodyWitnessState>,
}

#[derive(Default)]
struct BodyWitnessState {
    traces: HashMap<Uuid, BodyTrace>,
    requests: HashMap<Uuid, usize>,
}

impl BodyWitness {
    fn new(first: Uuid, second: Uuid, receipt_root: PathBuf) -> Arc<Self> {
        Arc::new(Self { first, second, receipt_root, state: Mutex::new(BodyWitnessState::default()) })
    }

    fn body_path(&self, operation: Uuid) -> PathBuf {
        self.receipt_root.join(format!("{operation}.receive-pack-request"))
    }

    fn accepts(&self, operation: Uuid) -> bool {
        operation == self.first || operation == self.second
    }

    fn begin_request(&self, operation: Uuid, content_encoded: bool) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        *state.requests.entry(operation).or_insert(0) += 1;
        if content_encoded {
            state.traces.entry(operation).or_default().content_encoded = true;
        }
    }

    fn observe(&self, operation: Uuid, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let at = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let trace = state.traces.entry(operation).or_default();
        let total = trace.total_bytes.saturating_add(bytes.len() as u64);
        trace.total_bytes = total;
        if trace.prefix.len() < MAX_BODY_PREFIX {
            let take = (MAX_BODY_PREFIX - trace.prefix.len()).min(bytes.len());
            trace.prefix.extend_from_slice(&bytes[..take]);
        }
        if trace.command_end.is_none() {
            trace.command_end = command_section_end(&trace.prefix);
        }
        let pack_bytes = trace.command_end.map_or(0, |end| total.saturating_sub(end as u64));
        if trace.samples.len() == MAX_BODY_SAMPLES {
            trace.samples_truncated = true;
        } else {
            trace.samples.push(BodySample { at, pack_bytes });
        }
    }

    fn complete(&self, operation: Uuid) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let trace = state.traces.entry(operation).or_default();
        if trace.completed.is_none() {
            trace.completed = Some(Instant::now());
        }
    }

    fn trace(&self, operation: Uuid) -> Option<BodyTrace> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).traces.get(&operation).cloned()
    }

    fn request_counts(&self) -> Vec<usize> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).requests.values().copied().collect()
    }
}

fn observe_receive_bodies(router: Router, witness: Arc<BodyWitness>) -> Router {
    router.layer(middleware::from_fn_with_state(witness, observe_receive_body))
}

/// Replace only the two pinned request bodies with an observing stream. The
/// wrapper may split a large data frame into concatenation-identical bounded
/// slices, applies a small finite pace, records each actual delivery immediately
/// before yielding its unchanged bytes, and marks completion only after the real
/// response has been produced. Non-pinned requests take no wrapper.
async fn observe_receive_body(State(witness): State<Arc<BodyWitness>>, request: Request<Body>, next: Next) -> Response {
    let Some(operation) = pinned_operation(&request) else {
        return next.run(request).await;
    };
    if !witness.accepts(operation) {
        return next.run(request).await;
    }
    let content_encoded = request
        .headers()
        .get_all("content-encoding")
        .iter()
        .any(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"));
    witness.begin_request(operation, content_encoded);
    let (parts, body) = request.into_parts();
    let body_witness = witness.clone();
    let receipt_path = witness.body_path(operation);
    let mut receipt = tokio::fs::File::create(&receipt_path).await.ok();
    let observed = async_stream::stream! {
        let mut body = body.into_data_stream();
        while let Some(frame) = body.next().await {
            match frame {
                Ok(bytes) if bytes.is_empty() => yield Ok(bytes),
                Ok(bytes) => {
                    let mut offset = 0usize;
                    while offset < bytes.len() {
                        let end = (offset + MAX_OBSERVED_CHUNK_BYTES).min(bytes.len());
                        let chunk = bytes.slice(offset..end);
                        if let Some(file) = receipt.as_mut() {
                            let _ = file.write_all(&chunk).await;
                        }
                        tokio::time::sleep(SLOW_FRAME_PACE).await;
                        // Timestamp immediately before the unchanged bytes are
                        // yielded, after pacing. Only actual received body data
                        // creates a progress sample.
                        body_witness.observe(operation, &chunk);
                        yield Ok(chunk);
                        offset = end;
                    }
                }
                Err(error) => yield Err(error),
            }
        }
        if let Some(mut file) = receipt {
            let _ = file.flush().await;
        }
    };
    let request = Request::from_parts(parts, Body::from_stream(observed));
    let response = next.run(request).await;
    witness.complete(operation);
    response
}

/// End offset of the command pkt-line section in a bounded body prefix. `None`
/// means the flush has not arrived yet; malformed framing is refused later by
/// the production `protocol::parse_push`.
fn command_section_end(prefix: &[u8]) -> Option<usize> {
    let mut position = 0usize;
    loop {
        let header = prefix.get(position..position.checked_add(4)?)?;
        let length = usize::from_str_radix(std::str::from_utf8(header).ok()?, 16).ok()?;
        position = position.checked_add(4)?;
        if length == 0 {
            return Some(position);
        }
        if length < 4 {
            return None;
        }
        position = position.checked_add(length - 4)?;
        if position > prefix.len() {
            return None;
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ProgressWindow {
    start: Instant,
    end: Instant,
    pack_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct BodyOverlap {
    start: Instant,
    end: Instant,
    first_pack_bytes: u64,
    second_pack_bytes: u64,
}

fn progress_windows(trace: &BodyTrace) -> Vec<ProgressWindow> {
    trace
        .samples
        .windows(2)
        .filter_map(|pair| {
            let (start, end) = (pair[0], pair[1]);
            (start.pack_bytes > 0
                && start.at < end.at
                && end.pack_bytes > start.pack_bytes
                && end.pack_bytes >= MIN_OVERLAP_PACK_BYTES)
                .then_some(ProgressWindow { start: start.at, end: end.at, pack_bytes: end.pack_bytes })
        })
        .collect()
}

/// Exact predicate: some consecutive-progress window of the first body and some
/// consecutive-progress window of the second body strictly overlap, both windows
/// already carry actual pack bytes at their start and end, and the overlap ends
/// before *both* response-completion times. Request scheduling, native child
/// lifetime or response delivery cannot satisfy it because only received
/// request-body frames create these samples.
fn body_overlap_witness(first: &BodyTrace, second: &BodyTrace) -> Result<BodyOverlap> {
    ensure!(!first.samples_truncated && !second.samples_truncated, "a receive body exceeded its sample receipt bound");
    let first_done = first.completed.ok_or_else(|| anyhow!("the first receive body never reached completion"))?;
    let second_done = second.completed.ok_or_else(|| anyhow!("the second receive body never reached completion"))?;
    let first_windows = progress_windows(first);
    let second_windows = progress_windows(second);
    ensure!(!first_windows.is_empty(), "the first receive body produced no bounded pack-progress interval");
    ensure!(!second_windows.is_empty(), "the second receive body produced no bounded pack-progress interval");

    // Consecutive progress windows in each trace are chronologically sorted by
    // both start and end. One two-pointer scan finds any strict overlap without
    // changing the predicate or its completion bound.
    let (mut first_index, mut second_index) = (0usize, 0usize);
    while first_index < first_windows.len() && second_index < second_windows.len() {
        let first_window = &first_windows[first_index];
        let second_window = &second_windows[second_index];
        let start = if first_window.start > second_window.start { first_window.start } else { second_window.start };
        let end = if first_window.end < second_window.end { first_window.end } else { second_window.end };
        if start < end && end < first_done && end < second_done {
            return Ok(BodyOverlap {
                start,
                end,
                first_pack_bytes: first_window.pack_bytes,
                second_pack_bytes: second_window.pack_bytes,
            });
        }
        match first_window.end.cmp(&second_window.end) {
            std::cmp::Ordering::Less => first_index += 1,
            std::cmp::Ordering::Greater => second_index += 1,
            std::cmp::Ordering::Equal => {
                first_index += 1;
                second_index += 1;
            }
        }
    }
    Err(anyhow!(
        "the two actual receive-pack body progress intervals did not overlap before both completions \
         (first_windows={}, second_windows={}, first_pack_bytes={}, second_pack_bytes={})",
        first_windows.len(),
        second_windows.len(),
        first.samples.last().map_or(0, |sample| sample.pack_bytes),
        second.samples.last().map_or(0, |sample| sample.pack_bytes),
    ))
}

#[cfg(test)]
fn mocked_trace(base: Instant, points: &[(u64, u64)], completed_ms: u64) -> BodyTrace {
    BodyTrace {
        samples: points
            .iter()
            .map(|(at_ms, pack_bytes)| BodySample { at: base + Duration::from_millis(*at_ms), pack_bytes: *pack_bytes })
            .collect(),
        completed: Some(base + Duration::from_millis(completed_ms)),
        ..BodyTrace::default()
    }
}

#[test]
fn body_overlap_requires_advancing_pack_bytes_before_both_completions() {
    let base = Instant::now();
    let first = mocked_trace(base, &[(10, 0), (20, 70 * 1024), (40, 140 * 1024)], 100);
    let second = mocked_trace(base, &[(15, 0), (25, 70 * 1024), (35, 140 * 1024)], 110);
    let overlap = body_overlap_witness(&first, &second).expect("interleaved pack progress must overlap");
    assert!(overlap.start < overlap.end);
    assert!(overlap.end < base + Duration::from_millis(100));

    let sequential = mocked_trace(base, &[(120, 0), (130, 70 * 1024), (140, 140 * 1024)], 150);
    assert!(
        body_overlap_witness(&first, &sequential).is_err(),
        "pack progress after the first response completed must not satisfy the predicate"
    );
}

/// Parse the bounded real request prefix and require exactly one report-status
/// command for the expected fixture ref and OID. This proves the observed bytes
/// are that operation's standard receive-pack body, not a response or a
/// synthetic client stream.
fn ensure_body_command(trace: &BodyTrace, expected_ref: &str, expected_oid: &str) -> Result<protocol::PushRequest> {
    let request = protocol::parse_push(&trace.prefix, GitObjectFormat::Sha1)
        .map_err(|_| anyhow!("the pinned receive-pack command prefix was refused"))?;
    ensure!(request.commands.len() == 1, "the pinned receive-pack body did not carry exactly one command");
    let command = &request.commands[0];
    ensure!(command.name.as_str() == expected_ref, "the pinned receive-pack body named another ref");
    ensure!(!command.is_delete(), "the pinned receive-pack body requested a delete");
    ensure!(command.new.as_str() == expected_oid, "the pinned receive-pack body named another target OID");
    ensure!(request.wants_report(), "the pinned receive-pack body did not request report-status");
    ensure!(!request.wants_atomic(), "the single-ref slow-body criterion must not be a multi-ref atomic batch");
    let command_end = trace.command_end.ok_or_else(|| anyhow!("the pinned receive-pack body has no command flush"))?;
    ensure!(
        trace.total_bytes > command_end as u64,
        "the pinned receive-pack body carried no pack bytes after its flush"
    );
    Ok(request)
}

fn ensure_committed_terminal(terminal: Value, expected_ref: &str, expected_new: &str) -> Result<PackCommitTerminal> {
    let terminal: PackCommitTerminal = serde_json::from_value(terminal)
        .map_err(|_| anyhow!("the committed terminal does not match the pack terminal schema"))?;
    ensure!(terminal.kind == TerminalKind::Committed, "the terminal is not committed");
    ensure!(terminal.refs.len() == 1, "the committed terminal does not cover exactly one ref");
    match &terminal.refs[0] {
        RefCommitResult::Applied { name, old_oid, new_oid } => {
            ensure!(name.as_str() == expected_ref, "the committed terminal names another ref");
            ensure!(old_oid.is_none(), "the newly created ref unexpectedly carried an old OID");
            ensure!(new_oid.as_deref() == Some(expected_new), "the committed terminal applied another target OID");
        }
        RefCommitResult::NotApplied { .. } => {
            return Err(anyhow!("the committed terminal contains a not-applied ref"));
        }
    }
    Ok(terminal)
}

/// Strict intended-product oracle: one public Git operation UUID is resolved
/// through migration 152's restore-scoped wrapper, then to the selected private
/// operation and its exact terminal/event. A legacy operation row is never a
/// success branch here, even if it happens to carry the same public UUID.
async fn verify_private_committed_ack(
    db: &Db,
    serving: &ServingRepository,
    owner: &Actor,
    public_id: Uuid,
    request: &protocol::PushRequest,
    wire_digest: RequestDigest,
    mode: CommitMode,
    backend_identity: &str,
    expected_ref: &str,
    expected_oid: &str,
) -> Result<i64> {
    let repository_id = serving.gate.repository_id();
    ensure!(serving.repository.id == repository_id, "authoritative serving view names another repository");
    let public_request = PublicAttemptRequest {
        repository_id,
        admission_owner_id: serving.gate.tenant_id(),
        issuer_id: owner.identity.id,
        public_id,
        wire_digest,
        request_mode: mode,
        backend_identity: backend_identity.to_owned(),
        object_format: serving.gate.object_format(),
        history_incarnation: serving.gate.history_incarnation(),
        authority_epoch: serving.gate.authority_epoch(),
        group_epoch: serving.gate.group_epoch(),
        restore_incarnation: serving.cluster_incarnation,
    };
    let bound = deadline();
    let mut client = timeout_at(bound, db.pool.get())
        .await
        .map_err(|_| anyhow!("private wrapper pool checkout timed out"))?
        .map_err(|_| anyhow!("private wrapper pool checkout failed"))?;
    let tx = timeout_at(bound, client.transaction())
        .await
        .map_err(|_| anyhow!("private wrapper transaction timed out"))?
        .map_err(|_| anyhow!("private wrapper transaction failed"))?;
    let result = verify_private_committed_ack_in_tx(
        &tx,
        &public_request,
        request,
        wire_digest,
        expected_ref,
        expected_oid,
        bound,
    )
    .await;
    let rollback = tx.rollback().await;
    match (result, rollback) {
        (Ok(revision), Ok(())) => Ok(revision),
        (Err(error), _) => Err(error),
        (Ok(_), Err(_)) => Err(anyhow!("private wrapper transaction rollback failed")),
    }
}

async fn verify_private_committed_ack_in_tx(
    tx: &tokio_postgres::Transaction<'_>,
    public_request: &PublicAttemptRequest,
    request: &protocol::PushRequest,
    wire_digest: RequestDigest,
    expected_ref: &str,
    expected_oid: &str,
    bound: Instant,
) -> Result<i64> {
    let proposed = Uuid::new_v4();
    ensure!(!proposed.is_nil() && proposed != public_request.public_id, "private wrapper lock proposal was invalid");
    PgRefStore
        .lock_public_attempt(tx, public_request, proposed, bound)
        .await
        .map_err(|_| anyhow!("private wrapper lock was refused"))?;
    let evidence = match PgRefStore
        .lookup_public_attempt(tx, public_request, bound)
        .await
        .map_err(|_| anyhow!("private wrapper lookup was refused"))?
    {
        PublicAttemptLookup::Committed(evidence) => evidence,
        PublicAttemptLookup::Unknown => {
            return Err(anyhow!("private wrapper is missing for the claimed committed operation"));
        }
        PublicAttemptLookup::PrivateIdentifier => {
            return Err(anyhow!("public operation UUID was already a private identifier"));
        }
        PublicAttemptLookup::LegacyPath => {
            return Err(anyhow!("a legacy operation row cannot satisfy private product qualification"));
        }
        PublicAttemptLookup::Pending(_) => {
            return Err(anyhow!("private wrapper is pending, not a committed two-ACK result"));
        }
        PublicAttemptLookup::Rejected(_) => {
            return Err(anyhow!("private wrapper rejected the expected ACK"));
        }
        PublicAttemptLookup::Cancelled(_) => {
            return Err(anyhow!("private wrapper cancelled the expected ACK"));
        }
    };
    ensure!(evidence.public_id == public_request.public_id, "private wrapper names another public operation");
    ensure!(evidence.current.state == OperationState::Committed, "private wrapper current attempt is not committed");
    ensure!(
        !evidence.current.private_id.is_nil() && evidence.current.private_id != public_request.public_id,
        "private wrapper selected an invalid private operation"
    );
    let phase_slot_ok = match (evidence.current.slot, evidence.retired.as_ref()) {
        (0, None) => true,
        (1, Some(retired)) => retired.slot == 0 && retired.state == OperationState::Rejected,
        _ => false,
    };
    ensure!(phase_slot_ok, "private wrapper phase/slot does not match the selected committed attempt");
    ensure!(
        evidence.current.event_id.is_some() && evidence.current.event_revision.is_some(),
        "private wrapper committed attempt has no exact core event"
    );

    let claimed = operation::lookup_public_private_in_tx(tx, public_request, &evidence, request, wire_digest, bound)
        .await
        .map_err(|_| anyhow!("verified private operation binding was refused"))?;
    let claimed_terminal = match claimed {
        operation::Claim::Replay(terminal) => terminal,
        operation::Claim::Fresh | operation::Claim::Pending | operation::Claim::Cancelled(_) => {
            return Err(anyhow!("verified private operation is not a committed ACK replay"));
        }
    };
    ensure!(
        claimed_terminal.kind == TerminalKind::Committed
            && claimed_terminal.repository_id == public_request.repository_id,
        "verified private ACK terminal is not committed in this repository"
    );

    // Read the exact selected private operation and core event in the same
    // wrapper transaction snapshot. The public operation UUID is never used as
    // the private row key.
    let private_id = evidence.current.private_id;
    let row = tx
        .query_opt(
            "SELECT state, terminal_result FROM ref_store_operations
              WHERE repository_id=$1 AND operation_id=$2",
            &[&public_request.repository_id, &private_id],
        )
        .await
        .map_err(|_| anyhow!("selected private operation read failed"))?
        .ok_or_else(|| anyhow!("private wrapper selected a missing private operation"))?;
    let state: String = row.get(0);
    let terminal_value: Option<Value> = row.get(1);
    ensure!(state == "committed", "selected private operation is not committed");
    let terminal = ensure_committed_terminal(
        terminal_value.ok_or_else(|| anyhow!("selected private operation has no terminal"))?,
        expected_ref,
        expected_oid,
    )?;
    ensure!(
        terminal.repository_id == public_request.repository_id,
        "selected private terminal names another repository"
    );
    ensure!(terminal == claimed_terminal, "selected private terminal differs from the verified replay terminal");

    let event = tx
        .query_opt(
            "SELECT revision, outcome FROM ref_store_core_events
              WHERE repository_id=$1 AND operation_id=$2",
            &[&public_request.repository_id, &private_id],
        )
        .await
        .map_err(|_| anyhow!("selected private core event read failed"))?
        .ok_or_else(|| anyhow!("selected private operation has no core event"))?;
    let event_revision: i64 = event.get(0);
    let event_outcome: String = event.get(1);
    ensure!(event_outcome == "committed", "selected private core event is not committed");
    ensure!(
        Some(event_revision) == evidence.current.event_revision,
        "selected private core event revision differs from wrapper evidence"
    );
    ensure!(terminal.revision == event_revision, "selected private terminal revision differs from its core event");
    Ok(event_revision)
}

fn deterministic_pack_bytes(mut state: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SLOW_PACK_BYTES);
    for _ in 0..SLOW_PACK_BYTES {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.push((state >> 24) as u8);
    }
    bytes
}

/// The exact two fixture pushes only: command-local `http.postBuffer` above
/// each 2 MiB incompressible pack, plus the existing operation pin. The stock
/// Git global/system configuration remains disabled by the shared fixture.
fn spawn_fixture_push_ref(
    git: &'static Git,
    directory: std::path::PathBuf,
    url: String,
    operation: Uuid,
    ref_name: &'static str,
) -> JoinHandle<Result<git::Output>> {
    tokio::spawn(async move {
        let header = format!("http.extraHeader=X-Rootyard-Operation: {operation}");
        let post_buffer = format!("http.postBuffer={FIXTURE_HTTP_POST_BUFFER_BYTES}");
        let target = format!("HEAD:{ref_name}");
        git.run(&directory, &["-c", post_buffer.as_str(), "-c", header.as_str(), "push", url.as_str(), target.as_str()])
            .await
    })
}

/// Fixed-diagnostic clone for the two fixture worktrees. Failure never echoes
/// the credentialed URL or stock output.
async fn clone_fixture(git: &Git, root: &Path, url: &str, destination: &str) -> Result<PathBuf> {
    let output =
        git.clone(root, url, destination).await.map_err(|_| anyhow!("stock fixture clone invocation failed"))?;
    ensure!(output.success, "stock fixture clone failed");
    Ok(root.join(destination))
}

async fn commit_bytes(git: &Git, directory: &Path, file: &str, bytes: &[u8], message: &str) -> Result<String> {
    std::fs::write(directory.join(file), bytes).with_context(|| format!("write fixture file {file}"))?;
    git.ok(directory, &["add", file]).await?;
    git.ok(directory, &["commit", "--quiet", "-m", message]).await?;
    git.text(directory, &["rev-parse", "HEAD"]).await
}

/// Strict original distinct-ref slow-body criterion. The two stock Git children
/// run concurrently against one tenant-created repository and standard Smart
/// HTTP route; each pushes one unrelated new branch from a nontrivial pack.
///
/// Durable qualification is private-wrapper-only: the public Git operation UUID
/// must resolve through migration 152 to a committed private operation with its
/// exact terminal and core event. A legacy-only row is a red refusal, never an
/// alternate success path.
///
/// This test intentionally makes no local-pass claim. The current branch's
/// legacy admission path may refuse the second independent ref as `stale info`;
/// that remains a red original-AC regression, not a reason to accept one ACK.
#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn slow_body_distinct_refs_overlap_and_both_commit() -> Result<()> {
    require_owned_disposable_blob_fixture()
        .map_err(|_| anyhow!("owned disposable Blob fixture opt-in was not proven"))?;
    let _serial = NATIVE_ACCEPTANCE_SERIAL.lock().await;
    prepare().map_err(|_| anyhow!("shared fixture environment preparation failed"))?;
    require_per_run_blob_prefix().map_err(|_| anyhow!("per-run Blob fixture prefix was not proven"))?;
    let db = Db::setup().await.map_err(|_| anyhow!("fixture PostgreSQL schema setup failed"))?;
    let mut resources = WitnessResources::default();
    let outcome = AssertUnwindSafe(async {
        let db = &db;
        let store = open_store().map_err(|_| anyhow!("fixture Blob store setup failed"))?;
        let git: &'static Git =
            Box::leak(Box::new(Git::new().map_err(|_| anyhow!("fixture Git binary setup failed"))?));

        let first_operation = Uuid::new_v4();
        let second_operation = Uuid::new_v4();
        ensure!(first_operation != second_operation, "the slow-body race pins shared an operation id");
        let receipt = tempfile::tempdir().map_err(|_| anyhow!("temporary receive-body receipt root was refused"))?;
        let witness = BodyWitness::new(first_operation, second_operation, receipt.path().to_path_buf());
        let captures = Captures::default();
        let scratch = resources
            .scratch
            .insert(tempfile::tempdir().map_err(|_| anyhow!("temporary gateway scratch root was refused"))?);
        let state = Arc::new(
            BlobGitState::new(BlobGitConfig {
                pool: db.pool.clone(),
                store: store.clone(),
                git_binary: git.binary().to_path_buf(),
                scratch_root: scratch.path().to_path_buf(),
                max_concurrent_requests: 4,
                max_request_bytes: 16 * 1024 * 1024,
                max_response_bytes: 64 * 1024 * 1024,
                max_inflight_bytes: 64 * 1024 * 1024,
                operation_deadline: Duration::from_secs(120),
                native_limits: Default::default(),
            })
            .map_err(|_| anyhow!("gateway configuration was refused"))?,
        );
        let listener =
            TcpListener::bind("127.0.0.1:0").await.map_err(|_| anyhow!("gateway listener bind was refused"))?;
        let address = listener.local_addr().map_err(|_| anyhow!("gateway listener address was refused"))?;
        let app =
            observe_receive_bodies(capture_receive_responses(router(state.clone()), captures.clone()), witness.clone());
        let (shutdown, signal) = oneshot::channel();
        resources.shutdown = Some(shutdown);
        resources.server = Some(tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = signal.await;
                })
                .await
        }));

        let owner = actor::owner(&db.pool).await.map_err(|_| anyhow!("fixture actor creation was refused"))?;
        let name = format!("slow-body-{}", &Uuid::new_v4().simple().to_string()[..12]);
        let created = create_repository(address, &owner, &name)
            .await
            .map_err(|_| anyhow!("fixture repository creation was refused"))?;
        let repository_id = Uuid::parse_str(
            created["id"].as_str().ok_or_else(|| anyhow!("fixture repository creation returned no id"))?,
        )
        .map_err(|_| anyhow!("fixture repository creation returned an invalid id"))?;
        provision_decision_realm(db, &owner, &name, &store)
            .await
            .map_err(|_| anyhow!("decision realm provisioning was refused"))?;

        let work =
            resources.work.insert(tempfile::tempdir().map_err(|_| anyhow!("temporary Git work root was refused"))?);
        let direct_url = clone_url(address, &owner, &name);
        let seeded = git
            .clone(work.path(), &direct_url, "seed")
            .await
            .map_err(|_| anyhow!("seed stock clone invocation was refused"))?;
        ensure!(seeded.success, "real Smart HTTP clone of the empty repository failed");
        let seed_dir = work.path().join("seed");
        let seed = git
            .commit(&seed_dir, SEED_FILE, SEED_CONTENT, "seed commit")
            .await
            .map_err(|_| anyhow!("seed commit was refused"))?;
        let seed_target = format!("HEAD:{SEED_REF}");
        let pushed = git
            .run(&seed_dir, &["push", "origin", seed_target.as_str()])
            .await
            .map_err(|_| anyhow!("seed push invocation was refused"))?;
        ensure!(pushed.success, "seed push was refused");

        let first_dir = clone_fixture(git, work.path(), &direct_url, "slow-a").await?;
        let second_dir = clone_fixture(git, work.path(), &direct_url, "slow-b").await?;
        let first_old = git
            .text(&first_dir, &["rev-parse", "refs/remotes/origin/main"])
            .await
            .map_err(|_| anyhow!("first fixture old-OID readback failed"))?;
        let second_old = git
            .text(&second_dir, &["rev-parse", "refs/remotes/origin/main"])
            .await
            .map_err(|_| anyhow!("second fixture old-OID readback failed"))?;
        ensure!(first_old == seed && second_old == seed, "the two slow-body clones did not share the seed tip");

        let first_new =
            commit_bytes(git, &first_dir, "slow-a.bin", &deterministic_pack_bytes(0x51a7_0001), "slow body a")
                .await
                .map_err(|_| anyhow!("first fixture commit was refused"))?;
        let second_new =
            commit_bytes(git, &second_dir, "slow-b.bin", &deterministic_pack_bytes(0x51a7_0002), "slow body b")
                .await
                .map_err(|_| anyhow!("second fixture commit was refused"))?;
        ensure!(first_new != second_new, "the two slow-body commits are identical");
        let revision_before =
            gate_revision(db, repository_id).await.map_err(|_| anyhow!("fixture gate revision read failed"))?;

        ensure!(
            FIXTURE_HTTP_POST_BUFFER_BYTES > SLOW_PACK_BYTES && FIXTURE_HTTP_POST_BUFFER_BYTES < 16 * 1024 * 1024,
            "the command-local fixture post buffer is outside its exact fixture pack bound"
        );
        *resources.first_push =
            Some(spawn_fixture_push_ref(git, first_dir, direct_url.clone(), first_operation, INDEPENDENT_A));
        *resources.second_push =
            Some(spawn_fixture_push_ref(git, second_dir, direct_url.clone(), second_operation, INDEPENDENT_B));

        // Both stock children were spawned before either join; the second body
        // is not started only after the first finishes. The fixture's own Git
        // and gateway deadlines bound a stuck child, and teardown aborts/joins
        // any handle left by an earlier failure.
        let first_join = {
            let first_handle = resources
                .first_push
                .as_mut()
                .ok_or_else(|| anyhow!("the first slow-body push task was not created"))?;
            first_handle.await
        };
        *resources.first_push = None;
        let first_output = first_join
            .map_err(|_| anyhow!("the first slow-body stock push task failed"))?
            .map_err(|_| anyhow!("the first slow-body stock push failed"))?;
        let second_join = {
            let second_handle = resources
                .second_push
                .as_mut()
                .ok_or_else(|| anyhow!("the second slow-body push task was not created"))?;
            second_handle.await
        };
        *resources.second_push = None;
        let second_output = second_join
            .map_err(|_| anyhow!("the second slow-body stock push task failed"))?
            .map_err(|_| anyhow!("the second slow-body stock push failed"))?;

        // The body criterion is independent of the ACK outcome and is checked
        // first: exactly one request body per pinned operation, exact command
        // refs/OIDs, nontrivial actual pack progress on both sides, and a
        // paired progress interval ending before either response completed.
        let requests = witness.request_counts();
        ensure!(requests.len() == 2, "the pinned receive-pack POSTs were not exactly the two operations");
        ensure!(
            requests.iter().all(|count| *count == 1),
            "a pinned receive-pack operation issued more than one POST, including a flush-only preflight"
        );
        let first_trace =
            witness.trace(first_operation).ok_or_else(|| anyhow!("the first receive body was not observed"))?;
        let second_trace =
            witness.trace(second_operation).ok_or_else(|| anyhow!("the second receive body was not observed"))?;
        ensure!(!first_trace.samples_truncated, "the first receive body exceeded its sample receipt bound");
        ensure!(!second_trace.samples_truncated, "the second receive body exceeded its sample receipt bound");
        ensure!(
            !first_trace.content_encoded,
            "the first receive body was encoded, not the exact decoded request bytes"
        );
        ensure!(
            !second_trace.content_encoded,
            "the second receive body was encoded, not the exact decoded request bytes"
        );
        let first_request = ensure_body_command(&first_trace, INDEPENDENT_A, &first_new)?;
        let second_request = ensure_body_command(&second_trace, INDEPENDENT_B, &second_new)?;
        let first_digest = operation::request_digest(
            repository_id,
            first_operation,
            GitObjectFormat::Sha1,
            &first_request,
            CommitMode::AcceptedSubset,
            &witness.body_path(first_operation),
            deadline(),
        )
        .await
        .map_err(|_| anyhow!("the first pinned request digest could not be recomputed"))?;
        let second_digest = operation::request_digest(
            repository_id,
            second_operation,
            GitObjectFormat::Sha1,
            &second_request,
            CommitMode::AcceptedSubset,
            &witness.body_path(second_operation),
            deadline(),
        )
        .await
        .map_err(|_| anyhow!("the second pinned request digest could not be recomputed"))?;
        let overlap = body_overlap_witness(&first_trace, &second_trace)?;
        ensure!(
            overlap.start < overlap.end
                && overlap.first_pack_bytes >= MIN_OVERLAP_PACK_BYTES
                && overlap.second_pack_bytes >= MIN_OVERLAP_PACK_BYTES,
            "the observed body-progress overlap was not substantial on both sides"
        );

        // The service's own bytes, keyed by pinned operation. Both must be HTTP
        // 200 and exactly one `ok` for the command ref. No verdict is synthesized
        // or repaired from the stock client's exit status.
        let first_capture =
            captures.take(first_operation).ok_or_else(|| anyhow!("the first slow-body push has no raw reply"))?;
        let second_capture =
            captures.take(second_operation).ok_or_else(|| anyhow!("the second slow-body push has no raw reply"))?;
        ensure!(captures.is_empty(), "the service answered unexpected extra receive-pack operations");
        ensure!(
            first_capture.status == 200,
            "the service answered the first slow-body push with {}",
            first_capture.status
        );
        ensure!(
            second_capture.status == 200,
            "the service answered the second slow-body push with {}",
            second_capture.status
        );
        ensure!(!first_capture.truncated, "the first slow-body raw reply is truncated");
        ensure!(!second_capture.truncated, "the second slow-body raw reply is truncated");
        let (first_unpack, first_verdicts) = report_status(&first_capture.body)
            .map_err(|_| anyhow!("raw report-status parser refused the first pinned reply"))?;
        let (second_unpack, second_verdicts) = report_status(&second_capture.body)
            .map_err(|_| anyhow!("raw report-status parser refused the second pinned reply"))?;
        ensure!(first_unpack == "ok", "the first slow-body report-status did not unpack");
        ensure!(second_unpack == "ok", "the second slow-body report-status did not unpack");
        ensure!(
            first_verdicts == vec![(INDEPENDENT_A.to_owned(), None)],
            "the first slow-body report-status is not exactly one ok on the expected ref"
        );
        ensure!(
            second_verdicts == vec![(INDEPENDENT_B.to_owned(), None)],
            "the second slow-body report-status is not exactly one ok on the expected ref"
        );
        ensure!(first_output.success, "the first slow-body stock push was refused");
        ensure!(second_output.success, "the second slow-body stock push was refused");

        // Durable refs/OIDs, then the intended product route: a real
        // restore-scoped public wrapper lookup selects the exact committed
        // private operation, terminal and core event. The public Git operation
        // UUID is not used as the private row key, and a legacy-only row is a
        // fixed refusal rather than a qualification success.
        let first_oid = durable_ref(db, repository_id, INDEPENDENT_A)
            .await
            .map_err(|_| anyhow!("durable indep-a read failed"))?
            .ok_or_else(|| anyhow!("durable indep-a is missing"))?;
        let second_oid = durable_ref(db, repository_id, INDEPENDENT_B)
            .await
            .map_err(|_| anyhow!("durable indep-b read failed"))?
            .ok_or_else(|| anyhow!("durable indep-b is missing"))?;
        ensure!(first_oid == first_new, "durable indep-a OID differs from the pushed commit");
        ensure!(second_oid == second_new, "durable indep-b OID differs from the pushed commit");

        let served =
            lookup(&db.pool, &owner.identity, &owner.username, &name, false, store.backend_identity(), deadline())
                .await
                .map_err(|_| anyhow!("authoritative serving lookup was refused"))?;
        ensure!(served.gate.repository_id() == repository_id, "the authoritative lookup named another repository");
        ensure!(
            served.gate.revision() == revision_before + 2,
            "the authoritative lookup gate revision is not exactly two independent revisions"
        );
        let backend_identity = store.backend_identity().as_hex();
        let first_event_revision = verify_private_committed_ack(
            db,
            &served,
            &owner,
            first_operation,
            &first_request,
            first_digest,
            CommitMode::AcceptedSubset,
            &backend_identity,
            INDEPENDENT_A,
            &first_new,
        )
        .await?;
        let second_event_revision = verify_private_committed_ack(
            db,
            &served,
            &owner,
            second_operation,
            &second_request,
            second_digest,
            CommitMode::AcceptedSubset,
            &backend_identity,
            INDEPENDENT_B,
            &second_new,
        )
        .await?;
        let revision_after =
            gate_revision(db, repository_id).await.map_err(|_| anyhow!("post-ACK gate revision read failed"))?;
        ensure!(revision_after == revision_before + 2, "the gate did not advance by exactly two independent revisions");
        let mut event_revisions = vec![first_event_revision, second_event_revision];
        event_revisions.sort_unstable();
        ensure!(
            event_revisions == vec![revision_before + 1, revision_before + 2],
            "the two private core events do not carry exact consecutive revisions"
        );

        // A fresh stock client readback including `fsck --strict` proves both
        // durable refs and their pack bytes are readable without compute-view
        // reuse. It does not substitute for the private wrapper oracle above.
        let readback = git
            .clone(work.path(), &direct_url, "slow-readback")
            .await
            .map_err(|_| anyhow!("fresh stock readback clone invocation failed"))?;
        ensure!(readback.success, "the fresh stock readback clone failed");
        let readback_dir = work.path().join("slow-readback");
        let fsck = git
            .run(&readback_dir, &["fsck", "--strict"])
            .await
            .map_err(|_| anyhow!("stock readback fsck invocation failed"))?;
        ensure!(fsck.success, "stock readback fsck failed");
        let first_read = git
            .text(&readback_dir, &["rev-parse", "refs/remotes/origin/indep-a"])
            .await
            .map_err(|_| anyhow!("stock readback of indep-a failed"))?;
        let second_read = git
            .text(&readback_dir, &["rev-parse", "refs/remotes/origin/indep-b"])
            .await
            .map_err(|_| anyhow!("stock readback of indep-b failed"))?;
        ensure!(first_read == first_oid, "stock readback of indep-a differs from the durable OID");
        ensure!(second_read == second_oid, "stock readback of indep-b differs from the durable OID");

        Ok::<(), anyhow::Error>(())
    })
    .catch_unwind()
    .await;

    let mut fence = Vec::new();
    let cleanup = AssertUnwindSafe(resources.teardown(&db, &mut fence))
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(anyhow!("slow-body witness cleanup panicked")));
    if cleanup.is_err() {
        let sealed = AssertUnwindSafe(resources.seal_failed_cleanup(&db)).catch_unwind().await;
        if sealed.is_err() {
            let _ = writeln!(io::stderr().lock(), "slow-body witness cleanup fallback panicked");
        }
        if !matches!(&outcome, Ok(Ok(()))) {
            let _ = writeln!(io::stderr().lock(), "slow-body witness cleanup failed");
        }
    }
    drop(fence);

    match outcome {
        Ok(result) => result.and(cleanup),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}
