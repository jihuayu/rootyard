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
    path::Path,
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
use futures_util::StreamExt;
use serde_json::Value;
use tokio::{net::TcpListener, sync::oneshot, time::Instant};
use uuid::Uuid;

use super::super::session_http_acceptance::fixtures::{
    actor,
    db::{Db, deadline, prepare},
    git::Git,
};
use super::{
    Captures, INDEPENDENT_A, INDEPENDENT_B, SEED_CONTENT, SEED_FILE, SEED_REF, WitnessResources, clone_one, clone_url,
    core_event, create_repository, durable_ref, gate_revision, open_store, operation_row, pinned_operation,
    provision_decision_realm, redacted, report_status, require_owned_disposable_blob_fixture,
    require_per_run_blob_prefix, spawn_push_ref,
};
use crate::{
    blob_git_gateway::{
        BlobGitConfig, BlobGitState, NATIVE_ACCEPTANCE_SERIAL,
        protocol::{self, MAX_COMMAND_BYTES},
        router,
    },
    ref_store::{
        GitObjectFormat, RefCommitResult, TerminalKind, core::pack_commit::PackCommitTerminal, serving::lookup,
    },
};

/// Two incompressible, deterministic fixture files keep both incoming packs
/// nontrivially larger than the minimum progress interval the witness requires.
const SLOW_PACK_BYTES: usize = 2 * 1024 * 1024;
/// The test-only receive-body wrapper delays each already-observed data frame
/// before handing it to the handler. This is body pacing, not response pacing
/// and not a synthetic client frame.
const SLOW_FRAME_PACE: Duration = Duration::from_millis(8);
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
    completed: Option<Instant>,
}

/// Test-only witness for exactly two pinned receive-pack operations. It is
/// attached only by this harness' router, and it records bytes as the production
/// receive handler consumes its actual request body stream.
struct BodyWitness {
    first: Uuid,
    second: Uuid,
    state: Mutex<BodyWitnessState>,
}

#[derive(Default)]
struct BodyWitnessState {
    traces: HashMap<Uuid, BodyTrace>,
    requests: HashMap<Uuid, usize>,
}

impl BodyWitness {
    fn new(first: Uuid, second: Uuid) -> Arc<Self> {
        Arc::new(Self { first, second, state: Mutex::new(BodyWitnessState::default()) })
    }

    fn accepts(&self, operation: Uuid) -> bool {
        operation == self.first || operation == self.second
    }

    fn begin_request(&self, operation: Uuid) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        *state.requests.entry(operation).or_insert(0) += 1;
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
/// wrapper records an actual data frame before yielding that same frame
/// unchanged, adds a small finite pace, and marks completion only after the
/// real response has been produced. Non-pinned requests take no wrapper.
async fn observe_receive_body(State(witness): State<Arc<BodyWitness>>, request: Request<Body>, next: Next) -> Response {
    let Some(operation) = pinned_operation(&request) else {
        return next.run(request).await;
    };
    if !witness.accepts(operation) {
        return next.run(request).await;
    }
    witness.begin_request(operation);
    let (parts, body) = request.into_parts();
    let body_witness = witness.clone();
    let observed = async_stream::stream! {
        let mut body = body.into_data_stream();
        while let Some(frame) = body.next().await {
            if let Ok(bytes) = &frame
                && !bytes.is_empty()
            {
                body_witness.observe(operation, bytes);
                tokio::time::sleep(SLOW_FRAME_PACE).await;
            }
            yield frame;
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

    for first_window in &first_windows {
        for second_window in &second_windows {
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
fn ensure_body_command(trace: &BodyTrace, expected_ref: &str, expected_oid: &str) -> Result<()> {
    let request = protocol::parse_push(&trace.prefix, GitObjectFormat::Sha1)
        .map_err(|error| anyhow!("the pinned receive-pack command prefix was refused: {error}"))?;
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
    Ok(())
}

fn ensure_committed_terminal(terminal: Value, expected_ref: &str, expected_new: &str) -> Result<()> {
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
    Ok(())
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
/// This test intentionally makes no local-pass claim. The current branch's
/// legacy admission path may refuse the second independent ref as `stale info`;
/// that remains a red original-AC regression, not a reason to accept one ACK.
#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn slow_body_distinct_refs_overlap_and_both_commit() -> Result<()> {
    require_owned_disposable_blob_fixture()?;
    let _serial = NATIVE_ACCEPTANCE_SERIAL.lock().await;
    prepare()?;
    require_per_run_blob_prefix()?;
    let db = Db::setup().await?;
    let mut resources = WitnessResources::default();
    let outcome = AssertUnwindSafe(async {
        let db = &db;
        let store = open_store()?;
        let git: &'static Git = Box::leak(Box::new(Git::new()?));

        let first_operation = Uuid::new_v4();
        let second_operation = Uuid::new_v4();
        ensure!(first_operation != second_operation, "the slow-body race pins shared an operation id");
        let witness = BodyWitness::new(first_operation, second_operation);
        let captures = Captures::default();
        let scratch = resources.scratch.insert(tempfile::tempdir().context("temporary gateway scratch root")?);
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
            .map_err(|error| anyhow!("gateway configuration was refused: {error}"))?,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
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

        let owner = actor::owner(&db.pool).await?;
        let name = format!("slow-body-{}", &Uuid::new_v4().simple().to_string()[..12]);
        let created = create_repository(address, &owner, &name).await?;
        let repository_id = Uuid::parse_str(created["id"].as_str().ok_or_else(|| anyhow!("create API has no id"))?)?;
        provision_decision_realm(db, &owner, &name, &store).await?;

        let work = resources.work.insert(tempfile::tempdir().context("temporary Git work root")?);
        let direct_url = clone_url(address, &owner, &name);
        let seeded = git.clone(work.path(), &direct_url, "seed").await?;
        ensure!(seeded.success, "real Smart HTTP clone of the empty repository failed: {}", redacted(&seeded));
        let seed_dir = work.path().join("seed");
        let seed = git.commit(&seed_dir, SEED_FILE, SEED_CONTENT, "seed commit").await?;
        let seed_target = format!("HEAD:{SEED_REF}");
        let pushed = git.run(&seed_dir, &["push", "origin", seed_target.as_str()]).await?;
        ensure!(pushed.success, "seed push was refused: {}", redacted(&pushed));

        let first_dir = clone_one(git, work.path(), &direct_url, "slow-a").await?;
        let second_dir = clone_one(git, work.path(), &direct_url, "slow-b").await?;
        let first_old = git.text(&first_dir, &["rev-parse", "refs/remotes/origin/main"]).await?;
        let second_old = git.text(&second_dir, &["rev-parse", "refs/remotes/origin/main"]).await?;
        ensure!(first_old == seed && second_old == seed, "the two slow-body clones did not share the seed tip");

        let first_new =
            commit_bytes(git, &first_dir, "slow-a.bin", &deterministic_pack_bytes(0x51a7_0001), "slow body a").await?;
        let second_new =
            commit_bytes(git, &second_dir, "slow-b.bin", &deterministic_pack_bytes(0x51a7_0002), "slow body b").await?;
        ensure!(first_new != second_new, "the two slow-body commits are identical");
        let revision_before = gate_revision(db, repository_id).await?;

        *resources.first_push =
            Some(spawn_push_ref(git, first_dir, direct_url.clone(), first_operation, INDEPENDENT_A));
        *resources.second_push =
            Some(spawn_push_ref(git, second_dir, direct_url.clone(), second_operation, INDEPENDENT_B));

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
        let first_output = first_join.context("the first slow-body stock push task failed")??;
        let second_join = {
            let second_handle = resources
                .second_push
                .as_mut()
                .ok_or_else(|| anyhow!("the second slow-body push task was not created"))?;
            second_handle.await
        };
        *resources.second_push = None;
        let second_output = second_join.context("the second slow-body stock push task failed")??;

        // The body criterion is independent of the ACK outcome and is checked
        // first: exactly one request body per pinned operation, exact command
        // refs/OIDs, nontrivial actual pack progress on both sides, and a
        // paired progress interval ending before either response completed.
        let requests = witness.request_counts();
        ensure!(
            requests.len() == 2 && requests.iter().all(|count| *count == 1),
            "the two pinned receive-pack operations did not each arrive exactly once"
        );
        let first_trace =
            witness.trace(first_operation).ok_or_else(|| anyhow!("the first receive body was not observed"))?;
        let second_trace =
            witness.trace(second_operation).ok_or_else(|| anyhow!("the second receive body was not observed"))?;
        ensure!(!first_trace.samples_truncated, "the first receive body exceeded its sample receipt bound");
        ensure!(!second_trace.samples_truncated, "the second receive body exceeded its sample receipt bound");
        ensure_body_command(&first_trace, INDEPENDENT_A, &first_new)?;
        ensure_body_command(&second_trace, INDEPENDENT_B, &second_new)?;
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
        let (first_unpack, first_verdicts) = report_status(&first_capture.body)?;
        let (second_unpack, second_verdicts) = report_status(&second_capture.body)?;
        ensure!(first_unpack == "ok", "the first slow-body report-status did not unpack: {first_unpack}");
        ensure!(second_unpack == "ok", "the second slow-body report-status did not unpack: {second_unpack}");
        ensure!(
            first_verdicts == vec![(INDEPENDENT_A.to_owned(), None)],
            "the first slow-body report-status is not exactly one ok on {INDEPENDENT_A}: {first_verdicts:?}"
        );
        ensure!(
            second_verdicts == vec![(INDEPENDENT_B.to_owned(), None)],
            "the second slow-body report-status is not exactly one ok on {INDEPENDENT_B}: {second_verdicts:?}"
        );
        ensure!(first_output.success, "the first slow-body stock push was refused: {}", redacted(&first_output));
        ensure!(second_output.success, "the second slow-body stock push was refused: {}", redacted(&second_output));

        // Durable refs/OIDs, both exact committed terminals, exactly two gate
        // revisions and one committed core event per pinned operation.
        let first_oid = durable_ref(db, repository_id, INDEPENDENT_A)
            .await?
            .ok_or_else(|| anyhow!("durable {INDEPENDENT_A} is missing"))?;
        let second_oid = durable_ref(db, repository_id, INDEPENDENT_B)
            .await?
            .ok_or_else(|| anyhow!("durable {INDEPENDENT_B} is missing"))?;
        ensure!(first_oid == first_new, "durable {INDEPENDENT_A} is {first_oid}, not {first_new}");
        ensure!(second_oid == second_new, "durable {INDEPENDENT_B} is {second_oid}, not {second_new}");
        let (first_state, first_terminal) = operation_row(db, repository_id, first_operation)
            .await?
            .ok_or_else(|| anyhow!("the first slow-body operation has no durable row"))?;
        let (second_state, second_terminal) = operation_row(db, repository_id, second_operation)
            .await?
            .ok_or_else(|| anyhow!("the second slow-body operation has no durable row"))?;
        ensure!(first_state == "committed", "the first slow-body operation is {first_state}, not committed");
        ensure!(second_state == "committed", "the second slow-body operation is {second_state}, not committed");
        ensure_committed_terminal(
            first_terminal.ok_or_else(|| anyhow!("the first slow-body operation has no terminal"))?,
            INDEPENDENT_A,
            &first_new,
        )?;
        ensure_committed_terminal(
            second_terminal.ok_or_else(|| anyhow!("the second slow-body operation has no terminal"))?,
            INDEPENDENT_B,
            &second_new,
        )?;
        let revision_after = gate_revision(db, repository_id).await?;
        ensure!(
            revision_after == revision_before + 2,
            "the gate moved {revision_before}->{revision_after}, not exactly two independent revisions"
        );
        let (first_event_revision, first_event_outcome) = core_event(db, repository_id, first_operation)
            .await?
            .ok_or_else(|| anyhow!("the first slow-body operation has no core event"))?;
        let (second_event_revision, second_event_outcome) = core_event(db, repository_id, second_operation)
            .await?
            .ok_or_else(|| anyhow!("the second slow-body operation has no core event"))?;
        ensure!(first_event_outcome == "committed", "the first slow-body core event is not committed");
        ensure!(second_event_outcome == "committed", "the second slow-body core event is not committed");
        let mut event_revisions = vec![first_event_revision, second_event_revision];
        event_revisions.sort_unstable();
        ensure!(
            event_revisions == vec![revision_before + 1, revision_before + 2],
            "the two slow-body core events do not carry exact consecutive revisions: {event_revisions:?}"
        );

        // Fresh authoritative serving lookup, then a fresh stock client readback
        // including `fsck --strict`, proves both durable refs and their pack bytes
        // are readable without any compute-view reuse.
        let served =
            lookup(&db.pool, &owner.identity, &owner.username, &name, false, store.backend_identity(), deadline())
                .await?;
        ensure!(served.gate.repository_id() == repository_id, "the authoritative lookup named another repository");
        ensure!(
            served.gate.revision() == revision_before + 2,
            "the authoritative lookup gate revision is {}, not {}",
            served.gate.revision(),
            revision_before + 2
        );
        let readback = git.clone(work.path(), &direct_url, "slow-readback").await?;
        ensure!(readback.success, "the fresh stock readback clone failed: {}", redacted(&readback));
        let readback_dir = work.path().join("slow-readback");
        git.ok(&readback_dir, &["fsck", "--strict"]).await?;
        let first_read = git.text(&readback_dir, &["rev-parse", "refs/remotes/origin/indep-a"]).await?;
        let second_read = git.text(&readback_dir, &["rev-parse", "refs/remotes/origin/indep-b"]).await?;
        ensure!(first_read == first_oid, "stock readback of {INDEPENDENT_A} is {first_read}, not {first_oid}");
        ensure!(second_read == second_oid, "stock readback of {INDEPENDENT_B} is {second_read}, not {second_oid}");

        Ok::<(), anyhow::Error>(())
    })
    .catch_unwind()
    .await;

    let mut fence = Vec::new();
    let cleanup = AssertUnwindSafe(resources.teardown(&db, &mut fence))
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(anyhow!("slow-body witness cleanup panicked")));
    if let Err(error) = &cleanup {
        let sealed = AssertUnwindSafe(resources.seal_failed_cleanup(&db)).catch_unwind().await;
        if sealed.is_err() {
            let _ = writeln!(io::stderr().lock(), "slow-body witness cleanup fallback panicked");
        }
        if !matches!(&outcome, Ok(Ok(()))) {
            let _ = writeln!(io::stderr().lock(), "slow-body witness cleanup failed ({error})");
        }
    }
    drop(fence);

    match outcome {
        Ok(result) => result.and(cleanup),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}
