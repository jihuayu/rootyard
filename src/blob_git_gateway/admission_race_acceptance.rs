//! Deterministic acceptance for the stale-baseline races.
//!
//! This is a `cfg(test)`-only internal HTTP harness. It drives the production
//! router over a real loopback listener, real PostgreSQL, the operator's real
//! S3-compatible Blob profile and real stock Git clients. The only test-only
//! artifacts are two in-memory rendezvous attached to one gateway instance:
//!
//! * the pre-admission pause holds one selected operation after its publish
//!   baseline was captured and before its admission transaction begins, so the
//!   retry must recapture and persist the per-ref CAS `OldOidMismatch`;
//! * the post-admission pause holds one selected operation after its admission
//!   transaction returned a definite `COMMIT` and before its first A3 hold or
//!   protected upload, so the already-admitted older plan must be closed as
//!   `RevisionMismatch`/`admitted base was superseded` without a second write.
//!
//! There is no request header, environment variable, route or runtime
//! configuration that can reach either rendezvous, and the production
//! `BlobGitState` has no such field at all. A second test-only middleware
//! records the exact `report-status` body the service wrote for each pinned
//! operation; it does not synthesize or rewrite a ref verdict.
//!
//! Pre-admission interleaving:
//!
//! 1. seed `refs/heads/main`, then clone A and B from that same tip;
//! 2. start B and let its native receive-pack, pair staging and baseline
//!    capture complete; the test-only pause holds it before admission;
//! 3. run A from the same seed baseline to a durable commit;
//! 4. release B; its first admission transaction observes the winner's newer
//!    gate revision, is rolled back, recaptures the baseline and rebuilds the
//!    plan under the original operation id/deadline;
//! 5. B's refreshed native facts must select `OldOidMismatch`, and only that
//!    durable terminal may produce the raw `ng refs/heads/main stale info`.
//!
//! Post-admission interleaving:
//!
//! 1. seed and clone the same way, so both real pushes carry one old OID and
//!    target the SAME `refs/heads/main`;
//! 2. start B, wait for its admission `COMMIT`, then hold it before the first
//!    protected upload; its pending row and serving-operation binding are
//!    already durable, and it has no terminal, event or ref change;
//! 3. run A from the same revision to a durable commit; B remains pending;
//! 4. release B; its A3 gate proof observes the winner's newer revision, so the
//!    exact admitted plan is closed as `RevisionMismatch`/`admitted base was
//!    superseded` with the fixed per-ref `OldOidMismatch`;
//! 5. the winner stays the only writer and membership gain, B's stored identity
//!    and serving-operation binding are unchanged, and the same rejected
//!    terminal is observable from the authenticated operation read with exactly
//!    one correlated `rejected` event.
//!
//! The external `tests/blob_git_gateway.rs` race case and its exact one-ok /
//! one-ng assertions remain untouched; it stays the unsynchronized stress case.
//!
//! Blob lifecycle: both cases intentionally retain every object they write. They
//! require `ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB=1`, which attests that the
//! caller owns the whole configured bucket/namespace and will dispose of the
//! complete test fixture after the run. The existing fixture pins a fresh
//! relative `blob-gateway-suite/<uuid>` prefix for this run; per-key deletion is
//! not attempted because remote PUT quiescence after a provider timeout cannot
//! be proven here. No product deletion path is used, no object is claimed to
//! have been removed, and whole-fixture disposal is the caller's responsibility.
//!
//! Run explicitly by Root (hard-fails when the ownership opt-in, PostgreSQL,
//! Blob or Git is absent):
//!
//! ```text
//! ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB=1 \
//! ROOTYARD_TEST_DATABASE_URL=... ROOTYARD_BLOB_*... ROOTYARD_TEST_GIT=/usr/bin/git \
//! cargo test --lib admission_race_acceptance -- --ignored --test-threads=1
//! ```

// Reuse the fixture entry point already loaded by the session HTTP harness.
// Registering the same actor/database/Git files here again would duplicate the
// modules in the cfg(test) library graph.
use super::session_http_acceptance::fixtures::{
    actor::{self, Actor},
    db::{Db, RUN_BLOB_PREFIX, deadline},
    git::{self, Git},
};

use std::{
    collections::HashMap,
    fs::OpenOptions,
    future::Future,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Method, Request},
    middleware::{self, Next},
    response::Response,
};
use futures_util::future::FutureExt;
use serde_json::Value;
use tokio::{net::TcpListener, task::JoinHandle};
use uuid::Uuid;

use crate::{
    blob_git_gateway::{BlobGitConfig, BlobGitState, router, state::AdmissionPause},
    blob_store::{BlobProvider, config::BlobProfile, opendal::BlobStore},
    ref_store::{
        CommitRejectCode, RefCommitResult, TerminalKind,
        core::{
            decision_commit::{PgDecisionProtocol, RealmExpectation},
            pack_commit::{PackCommitRejectCode, PackCommitTerminal},
            publication_decision::codes::DenialCode,
        },
        serving::lookup,
    },
};

const SEED_FILE: &str = "seed.txt";
const SEED_CONTENT: &str = "seed\n";
const SEED_REF: &str = "refs/heads/main";
const MAX_CAPTURED_RESPONSE: usize = 64 * 1024 * 1024;
const OWNED_BLOB_OPT_IN: &str = "ROOTYARD_TEST_OWNED_DISPOSABLE_BLOB";
const FAILURE_PHASE_MARKER: &str = "ROOTYARD_TEST_174_CASE18_FAILURE_PHASE_MARKER";
/// Bound for one real stock push task inside these deterministic cases. The
/// gateway's own operation deadline is 120s; this leaves transport and native
/// Git some headroom while still aborting a detached task on a hang.
const PUSH_BOUND: Duration = Duration::from_secs(180);
/// A failed normal join is followed by one bounded stop attempt. Settling the
/// Task here is containment, not proof that the stock Git child was reaped.
const CLEANUP_STOP_BOUND: Duration = Duration::from_secs(30);
/// One authenticated operation read is a small bounded JSON response. The whole
/// send-to-body loop uses this deadline, never the request's larger operation
/// deadline, and never an unbounded `json()`/`bytes()` helper.
const OPERATION_VIEW_BOUND: Duration = Duration::from_secs(10);
const MAX_OPERATION_VIEW_BYTES: usize = 64 * 1024;
/// Exact persisted detail of the post-admission immutable-plan refusal built by
/// `authorized/refusal.rs` (`RevisionMismatch` + this detail). No production
/// constant names this literal, so it stays local to the assertion instead of
/// widening that module; `PackCommitRejectCode::RevisionMismatch.as_str()` is
/// used for the code half.
const POST_ADMISSION_REFUSAL_DETAIL: &str = "admitted base was superseded";

/// A parsed `report-status`: the `unpack` status and `(ref, ng reason)` rows.
type GitReport = (String, Vec<(String, Option<String>)>);

/// Abort the real `axum::serve` task when the case ends, including on failure.
struct ServerGuard {
    task: JoinHandle<Result<(), std::io::Error>>,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Graceful, bounded server owner for the admitted-refusal fixture. Unlike a
/// bare abort, `drain` stops accepting, releases no request by itself, and
/// waits for the real serve task (including its connection tasks) to finish.
struct RaceServer {
    task: JoinHandle<Result<(), std::io::Error>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl RaceServer {
    fn start(listener: TcpListener, app: Router) -> Self {
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stopped.await;
                })
                .await
        });
        Self { task, shutdown: Some(shutdown) }
    }

    async fn drain(&mut self, bound: Duration) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        match tokio::time::timeout(bound, &mut self.task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(_))) => Err(anyhow!("race server exited with an error")),
            Ok(Err(_)) => Err(anyhow!("race server task did not join cleanly")),
            Err(_) => {
                self.task.abort();
                Err(anyhow!("race server drain exceeded its bound"))
            }
        }
    }
}

impl Drop for RaceServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

/// Armed pause guard for the admitted-refusal fixture. Error paths call
/// `abandon` before draining the client/server; the Drop fallback makes an
/// unwind release the rendezvous too, so a paused handler returns the fixed
/// pre-upload refusal instead of writing or waiting forever.
struct PauseReleaseGuard {
    pause: Arc<AdmissionPause>,
    armed: bool,
}

impl PauseReleaseGuard {
    fn new(pause: Arc<AdmissionPause>) -> Self {
        Self { pause, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn abandon(&mut self) {
        if self.armed {
            self.pause.abandon();
            self.armed = false;
        }
    }
}

impl Drop for PauseReleaseGuard {
    fn drop(&mut self) {
        if self.armed {
            self.pause.abandon();
        }
    }
}

/// One real stock push task that is aborted if the case returns early or
/// unwinds before it is joined. This keeps a paused request from outliving its
/// fixture without a detached wait.
struct PushTask(JoinHandle<Result<git::Output>>);

impl Drop for PushTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What one poll cycle of an owned push task proved.
enum JoinFailure {
    /// The task produced a result that is not a normal `Git::run` `Output`.
    /// The handle's result is consumed and must be removed.
    SettledUnproven,
    /// The timeout fired before the handle produced a result. The handle is
    /// still owned and has not been consumed.
    NotSettled,
}

impl PushTask {
    /// Consume at most one `JoinHandle` result. Only `Ok(Ok(Output))` proves
    /// `Command::output` completed and the child was waited/reaped. A timeout
    /// leaves the handle unconsumed for the caller's slot.
    async fn join_once(&mut self, bound: Duration) -> Result<git::Output, JoinFailure> {
        match tokio::time::timeout(bound, &mut self.0).await {
            Ok(Ok(Ok(output))) => Ok(output),
            Ok(Ok(Err(_))) | Ok(Err(_)) => Err(JoinFailure::SettledUnproven),
            Err(_) => Err(JoinFailure::NotSettled),
        }
    }

    /// Containment only: abort the task and wait a smaller bound for the task
    /// itself to settle. Returning true does not prove the Git child was
    /// waited/reaped, so callers keep their cleanup-unproven state.
    async fn stop_unproven(&mut self, bound: Duration) -> bool {
        self.0.abort();
        tokio::time::timeout(bound, &mut self.0).await.is_ok()
    }
}

impl Future for PushTask {
    type Output = Result<Result<git::Output>, tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

#[derive(Clone, Default)]
struct Captures(Arc<Mutex<HashMap<Uuid, CapturedResponse>>>);

struct CapturedResponse {
    status: u16,
    body: Vec<u8>,
    truncated: bool,
}

impl Captures {
    fn insert(&self, operation: Uuid, captured: CapturedResponse) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).insert(operation, captured);
    }

    fn take(&self, operation: Uuid) -> Option<CapturedResponse> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).remove(&operation)
    }

    fn is_empty(&self) -> bool {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).is_empty()
    }
}

fn capture_receive_responses(router: Router, captures: Captures) -> Router {
    router.layer(middleware::from_fn_with_state(captures, capture_receive_response))
}

/// Observe only the real response body of a pinned receive-pack POST. The body
/// is put back verbatim so the stock client still reads the service's own
/// report-status; nothing is fabricated or rewritten.
async fn capture_receive_response(State(captures): State<Captures>, request: Request<Body>, next: Next) -> Response {
    let operation = pinned_operation(&request);
    let response = next.run(request).await;
    let Some(operation) = operation else { return response };
    let status = response.status().as_u16();
    let (parts, body) = response.into_parts();
    let (body, truncated) = match to_bytes(body, MAX_CAPTURED_RESPONSE).await {
        Ok(bytes) => (bytes.to_vec(), false),
        Err(_) => (Vec::new(), true),
    };
    captures.insert(operation, CapturedResponse { status, body: body.clone(), truncated });
    Response::from_parts(parts, Body::from(body))
}

fn pinned_operation(request: &Request<Body>) -> Option<Uuid> {
    if request.method() != Method::POST
        || !request.uri().path().starts_with("/git/")
        || !request.uri().path().ends_with("/git-receive-pack")
    {
        return None;
    }
    request
        .headers()
        .get("x-rootyard-operation")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
}

/// The provider acceptance reserves remote objects under the fixture's per-run
/// prefix. It must never run against a shared bucket with an unowned lifecycle.
fn require_owned_disposable_blob_fixture() -> Result<()> {
    ensure!(
        matches!(std::env::var(OWNED_BLOB_OPT_IN).as_deref(), Ok("1")),
        "this provider acceptance requires {OWNED_BLOB_OPT_IN}=1: the caller must own the whole configured Blob bucket/namespace and dispose of the complete fixture after the run"
    );
    Ok(())
}

/// The existing `Db` fixture pins one random relative prefix per process. Fail
/// before opening the store if the job-level shared prefix was not replaced by
/// that fixture-owned namespace.
fn require_per_run_blob_prefix() -> Result<()> {
    let root =
        std::env::var("ROOTYARD_BLOB_ROOT").map_err(|_| anyhow!("the fixture did not pin ROOTYARD_BLOB_ROOT"))?;
    let suffix = root.strip_prefix(RUN_BLOB_PREFIX).unwrap_or_default();
    ensure!(
        suffix.len() == 32 && suffix.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
        "the fixture did not pin its per-run Blob prefix"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn pre_admission_revision_mismatch_rebases_to_old_oid_mismatch() -> Result<()> {
    let mut phase = "fixture_setup";
    let result = async {
        require_owned_disposable_blob_fixture()?;
        let _serial = super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
        let db = Db::setup().await?;
        let outcome = async {
            require_per_run_blob_prefix()?;
            case(&db, &mut phase).await
        }
        .await;
        if outcome.is_ok() {
            phase = "fixture_cleanup";
        }
        db.finish(outcome).await
    }
    .await;

    // The fixture preserves a case error over a cleanup error. Record its
    // phase only after that decision, never while the race is in flight.
    if result.is_err()
        && let Some(path) = std::env::var_os(FAILURE_PHASE_MARKER)
    {
        let _ = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut file| file.write_all(phase.as_bytes()));
    }
    result
}

async fn case(db: &Db, phase: &mut &'static str) -> Result<()> {
    let store = open_store()?;
    let git: &'static Git = Box::leak(Box::new(Git::new()?));
    let owner = actor::owner(&db.pool).await?;
    let name = format!("race-admission-{}", &Uuid::new_v4().simple().to_string()[..12]);

    let winner_operation = Uuid::new_v4();
    let loser_operation = Uuid::new_v4();
    ensure!(winner_operation != loser_operation, "the race pins shared an operation id");

    // The rendezvous is keyed by the operation UUID and can fire only once.
    let pause = Arc::new(AdmissionPause::new(loser_operation));
    let captures = Captures::default();
    let scratch = tempfile::tempdir().context("temporary gateway scratch root")?;
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
        .map_err(|error| anyhow!("gateway configuration was refused: {error}"))?
        .with_admission_pause(pause.clone()),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = capture_receive_responses(router(state.clone()), captures.clone());
    let _server = ServerGuard { task: tokio::spawn(async move { axum::serve(listener, app).await }) };

    *phase = "repository_seed";
    let created = create_repository(address, &owner, &name).await?;
    let repository_id = Uuid::parse_str(created["id"].as_str().ok_or_else(|| anyhow!("create API has no id"))?)?;
    provision_decision_realm(db, &owner, &name, &store).await?;

    // Seed one real main tip, then clone twice so both stock clients advertise
    // exactly the same old OID.
    let SameTipRace { work: _work, direct_url, seed, first_dir, second_dir, first_new, revision_before } =
        seed_same_tip_race(db, git, address, &owner, &name, repository_id).await?;

    // Start the loser and wait until its native receive-pack, pair staging and
    // publish baseline capture have completed. It is then held before its
    // admission transaction while the winner commits.
    *phase = "pre_admission_barrier";
    let mut loser_push = spawn_push(git, second_dir, direct_url.clone(), loser_operation);
    tokio::select! {
        reached = tokio::time::timeout(PUSH_BOUND, pause.wait_reached()) => {
            reached.map_err(|_| anyhow!("the losing stock push did not reach its post-capture rendezvous"))?;
        }
        exited = &mut loser_push => {
            let output = exited.context("the losing stock push task failed")??;
            return Err(anyhow!(
                "the losing stock push exited before its post-capture rendezvous: {}",
                redacted(&output)
            ));
        }
    }
    ensure!(
        operation_row(db, repository_id, loser_operation).await?.is_none(),
        "the loser was admitted before its post-capture rendezvous"
    );
    ensure!(gate_revision(db, repository_id).await? == revision_before, "the gate moved before the winner started");

    *phase = "winner_publish";
    let winner_output = wait_push(spawn_push(git, first_dir, direct_url, winner_operation), "winning").await?;
    ensure!(winner_output.success, "the winning stock push failed: {}", redacted(&winner_output));

    *phase = "loser_rebase_await";
    pause.release();
    let loser_output = wait_push(loser_push, "losing").await?;
    *phase = "loser_rebase_exit_status";
    ensure!(!loser_output.success, "the paused loser unexpectedly succeeded");
    *phase = "loser_rebase_forbidden_text";
    let loser_text = output_text(&loser_output);
    for forbidden in ["409", "503", "non-fast-forward", "fetch first", "unexpected disconnect", "remote end hung up"] {
        let found = match forbidden {
            "409" | "503" => has_stock_http_error(&loser_text, forbidden),
            _ => loser_text.contains(forbidden),
        };
        ensure!(!found, "loser saw `{forbidden}`, not a report-status: {}", redacted(&loser_output));
    }
    *phase = "loser_rebase_stale_info";
    ensure!(
        loser_text.contains("[rejected]") && loser_text.contains("stale info"),
        "the loser did not print the stock stale-info rejection: {}",
        redacted(&loser_output)
    );

    // Exact raw service report-statuses, keyed by pinned operation. Both must
    // be HTTP 200 and parse as real Git pkt-lines; the loser must carry exactly
    // one `ng refs/heads/main stale info` and the winner exactly one `ok`.
    *phase = "http_report_assertions";
    let winner_capture = captures.take(winner_operation).ok_or_else(|| anyhow!("the winner has no raw reply"))?;
    let loser_capture = captures.take(loser_operation).ok_or_else(|| anyhow!("the loser has no raw reply"))?;
    ensure!(captures.is_empty(), "the service answered unexpected extra receive-pack operations");
    ensure!(winner_capture.status == 200, "the service answered the winner with {}", winner_capture.status);
    ensure!(loser_capture.status == 200, "the service answered the loser with {}", loser_capture.status);
    ensure!(!winner_capture.truncated, "the winner's raw service reply is truncated");
    ensure!(!loser_capture.truncated, "the loser's raw service reply is truncated");
    let (winner_unpack, winner_verdicts) = report_status(&winner_capture.body)?;
    ensure!(winner_unpack == "ok", "the winner's report-status did not unpack: {winner_unpack}");
    ensure!(
        winner_verdicts == vec![(SEED_REF.to_owned(), None)],
        "the winner's report-status is not exactly one ok on main: {winner_verdicts:?}"
    );
    let (loser_unpack, loser_verdicts) = report_status(&loser_capture.body)?;
    ensure!(loser_unpack == "ok", "the loser's report-status did not unpack: {loser_unpack}");
    ensure!(
        loser_verdicts == vec![(SEED_REF.to_owned(), Some("stale info".to_owned()))],
        "the loser's report-status is not exactly one ng stale info on main: {loser_verdicts:?}"
    );

    // Durable state: exactly the winner committed; the loser has one durable
    // rejected terminal whose per-ref reason is OldOidMismatch. The gate moved
    // once and main is the winner.
    *phase = "durable_state_assertions";
    let (winner_state, winner_terminal) = operation_row(db, repository_id, winner_operation)
        .await?
        .ok_or_else(|| anyhow!("the winning operation has no durable row"))?;
    ensure!(winner_state == "committed", "the winning operation is {winner_state}, not committed");
    let winner_terminal = winner_terminal.ok_or_else(|| anyhow!("the committed operation has no terminal"))?;
    let applied = winner_terminal["refs"]
        .as_array()
        .and_then(|refs| refs.iter().find(|result| result["name"].as_str() == Some(SEED_REF)))
        .ok_or_else(|| anyhow!("the committed terminal does not name the applied main ref: {winner_terminal}"))?;
    ensure!(
        applied["old_oid"].as_str() == Some(seed.as_str()),
        "the winner did not use the shared seed old OID: {winner_terminal}"
    );
    ensure!(
        applied["new_oid"].as_str() == Some(first_new.as_str()),
        "the committed terminal did not apply the winner: {winner_terminal}"
    );
    let (loser_state, loser_terminal) = operation_row(db, repository_id, loser_operation)
        .await?
        .ok_or_else(|| anyhow!("the losing operation has no durable row"))?;
    ensure!(loser_state == "rejected", "the losing operation is {loser_state}, not rejected");
    let terminal = loser_terminal.ok_or_else(|| anyhow!("the rejected operation has no terminal"))?;
    let terminal: PackCommitTerminal = serde_json::from_value(terminal)
        .map_err(|_| anyhow!("the rejected terminal does not match the pack terminal schema"))?;
    ensure!(terminal.kind == TerminalKind::Rejected, "the rejected terminal has another kind: {terminal:?}");
    ensure!(terminal.refs.len() == 1, "the rejected terminal does not cover exactly one ref: {terminal:?}");
    match &terminal.refs[0] {
        RefCommitResult::NotApplied { name, reason } => {
            ensure!(name.as_str() == SEED_REF, "the rejected terminal names another ref: {terminal:?}");
            ensure!(
                *reason == CommitRejectCode::OldOidMismatch,
                "the rejected terminal reason is {reason:?}, not OldOidMismatch: {terminal:?}"
            );
        }
        RefCommitResult::Applied { .. } => {
            return Err(anyhow!("the rejected terminal contains an applied ref: {terminal:?}"));
        }
    }
    ensure!(terminal.repository_id == repository_id, "the rejected terminal names another repository: {terminal:?}");
    let rejection = terminal
        .rejection
        .as_ref()
        .ok_or_else(|| anyhow!("the rejected terminal has no operation-level rejection: {terminal:?}"))?;
    let rejection_code = PackCommitRejectCode::parse(&rejection.code)
        .map_err(|_| anyhow!("the rejected terminal carries an unknown rejection code: {terminal:?}"))?;
    ensure!(
        rejection_code == PackCommitRejectCode::NoRefApplied,
        "the loser terminal rejection is {rejection_code:?}, not the per-ref CAS refusal: {terminal:?}"
    );
    ensure!(
        rejection.detail == DenialCode::AllRejected.as_str(),
        "the loser terminal rejection detail is {:?}, not the per-ref CAS reason: {terminal:?}",
        rejection.detail
    );
    // `operation_verdict.py` classifies this exact persisted pair as
    // `per_ref_cas_rejected`. The post-admission immutable-plan refusal is
    // `RevisionMismatch` + "admitted base was superseded"
    // (`admitted_base_superseded`). Compare typed persisted wire fields, never
    // a std `Debug` rendering of the operation.
    ensure!(
        (rejection.code.as_str(), rejection.detail.as_str())
            != (PackCommitRejectCode::RevisionMismatch.as_str(), POST_ADMISSION_REFUSAL_DETAIL),
        "the loser terminal is the post-admission immutable-plan refusal, not the pre-admission per-ref CAS refusal: {terminal:?}"
    );
    let revision_after = gate_revision(db, repository_id).await?;
    ensure!(
        revision_after == revision_before + 1,
        "the gate moved {revision_before}->{revision_after}, not exactly one winner revision"
    );
    let durable_main = durable_main(db, repository_id).await?;
    ensure!(durable_main == first_new, "durable main is {durable_main}, not the winning commit {first_new}");

    Ok(())
}

/// One real seed push and two real clones from that tip. Both clones advertise
/// the same old OID and each makes a distinct commit, which is the shared
/// starting point of both deterministic races.
struct SameTipRace {
    work: tempfile::TempDir,
    direct_url: String,
    seed: String,
    first_dir: PathBuf,
    second_dir: PathBuf,
    first_new: String,
    revision_before: i64,
}

async fn seed_same_tip_race(
    db: &Db,
    git: &Git,
    address: SocketAddr,
    owner: &Actor,
    name: &str,
    repository_id: Uuid,
) -> Result<SameTipRace> {
    let work = tempfile::tempdir().context("temporary Git work root")?;
    let direct_url = clone_url(address, owner, name);
    let seeded = git.clone(work.path(), &direct_url, "seed").await?;
    ensure!(seeded.success, "real Smart HTTP clone of the empty repository failed");
    let seed_dir = work.path().join("seed");
    let seed = git.commit(&seed_dir, SEED_FILE, SEED_CONTENT, "seed commit").await?;
    let seed_target = format!("HEAD:{SEED_REF}");
    let pushed = git.run(&seed_dir, &["push", "origin", seed_target.as_str()]).await?;
    ensure!(pushed.success, "seed push was refused");

    let first_dir = clone_one(git, work.path(), &direct_url, "race-a").await?;
    let second_dir = clone_one(git, work.path(), &direct_url, "race-b").await?;
    let first_old = git.text(&first_dir, &["rev-parse", "refs/remotes/origin/main"]).await?;
    let second_old = git.text(&second_dir, &["rev-parse", "refs/remotes/origin/main"]).await?;
    ensure!(first_old == seed && second_old == seed, "the two clones did not share the seed tip");
    let first_new = git.commit(&first_dir, "a.txt", "from a\n", "commit from a").await?;
    let second_new = git.commit(&second_dir, "b.txt", "from b\n", "commit from b").await?;
    ensure!(first_new != second_new, "the two racers made the same commit");
    let revision_before = gate_revision(db, repository_id).await?;
    Ok(SameTipRace { work, direct_url, seed, first_dir, second_dir, first_new, revision_before })
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn admitted_same_ref_attempt_is_refused_after_winner_commits() -> Result<()> {
    let mut phase = "fixture_setup";
    let result = async {
        require_owned_disposable_blob_fixture()?;
        let _serial = super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
        let db = Db::setup().await?;
        let outcome = async {
            require_per_run_blob_prefix()?;
            admitted_refusal_case(&db, &mut phase).await
        }
        .await;
        if phase == "cleanup_drain" {
            // A join/drain was not proved within its bound, so the schema and
            // its fixture-owned directories are retained rather than dropped
            // underneath a possibly live handler.
            return Err(anyhow!("admitted refusal fixture retained after unresolved cleanup"));
        }
        if outcome.is_ok() {
            phase = "fixture_cleanup";
        }
        db.finish(outcome).await
    }
    .await;

    if result.is_err()
        && let Some(path) = std::env::var_os(FAILURE_PHASE_MARKER)
    {
        let _ = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut file| file.write_all(phase.as_bytes()));
    }
    // The test failure exposes only the finite phase. Detailed assertion,
    // database/Git/HTTP errors and any identity material stay inside the
    // fixture and are never formatted into the outer error.
    let final_phase = phase;
    result.map_err(|_| anyhow!("admitted refusal fixture failed during fixed phase `{final_phase}`"))
}

/// Post-admission immutable-refusal case: two distinct commits from the same
/// old OID to the SAME ref are both admitted at the same gate revision. The
/// loser is held after its admission `COMMIT`; the winner then commits. The
/// loser's admitted plan can only be closed, never retargeted or relabelled.
async fn admitted_refusal_case(db: &Db, phase: &mut &'static str) -> Result<()> {
    let store = open_store()?;
    let git: &'static Git = Box::leak(Box::new(Git::new()?));
    let owner = actor::owner(&db.pool).await?;
    let name = format!("race-admitted-{}", &Uuid::new_v4().simple().to_string()[..12]);

    let winner_operation = Uuid::new_v4();
    let loser_operation = Uuid::new_v4();
    ensure!(winner_operation != loser_operation, "the race pins shared an operation id");

    // A distinct post-admission rendezvous: the existing pre-admission hook is
    // deliberately not attached here. The guard abandons and releases the
    // rendezvous on every early return or unwind.
    let pause = Arc::new(AdmissionPause::new(loser_operation));
    let mut pause_guard = PauseReleaseGuard::new(pause.clone());
    let captures = Captures::default();
    let scratch = tempfile::tempdir().context("temporary gateway scratch root")?;
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
        .map_err(|error| anyhow!("gateway configuration was refused: {error}"))?
        .with_publication_pause(pause.clone()),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = capture_receive_responses(router(state.clone()), captures.clone());
    let mut race_work: Option<tempfile::TempDir> = None;
    let mut server = RaceServer::start(listener, app);
    let mut loser_push: Option<PushTask> = None;
    let mut winner_push: Option<PushTask> = None;
    let mut join_unproven = false;

    let outcome = std::panic::AssertUnwindSafe(async {
        *phase = "repository_seed";
        let created = create_repository(address, &owner, &name).await?;
        let repository_id = Uuid::parse_str(created["id"].as_str().ok_or_else(|| anyhow!("create API has no id"))?)?;
        provision_decision_realm(db, &owner, &name, &store).await?;
        let SameTipRace { work, direct_url, seed, first_dir, second_dir, first_new, revision_before } =
            seed_same_tip_race(db, git, address, &owner, &name, repository_id).await?;
        race_work = Some(work);

        // Start the loser and wait for its admitted pending row and serving binding.
        // The pause is after the caller-owned admission `COMMIT` and before the
        // first A3 hold/protected upload.
        *phase = "post_admission_barrier";
        loser_push = Some(spawn_push(git, second_dir, direct_url.clone(), loser_operation));
        let early_exit = {
            let loser_task =
                loser_push.as_mut().ok_or_else(|| anyhow!("the losing stock push task was not retained"))?;
            tokio::select! {
                reached = tokio::time::timeout(PUSH_BOUND, pause.wait_reached()) => {
                    reached.map_err(|_| anyhow!("the losing stock push did not reach its post-admission rendezvous"))?;
                    None
                }
                exited = loser_task => Some(exited),
            }
        };
        if let Some(ready) = early_exit {
            // The select arm already consumed the JoinHandle result. Record
            // that exact result and remove the handle before the early
            // return so cleanup can never poll it a second time.
            match consume_ready_push(&mut loser_push, ready, &mut join_unproven) {
                Ok(output) => {
                    return Err(anyhow!(
                        "the losing stock push exited before its post-admission rendezvous: {}",
                        redacted(&output)
                    ));
                }
                Err(error) => return Err(error),
            }
        }

        *phase = "pre_release_assertions";
        let loser_before = operation_witness(db, repository_id, loser_operation)
            .await?
            .ok_or_else(|| anyhow!("the admitted operation has no durable row"))?;
        ensure!(loser_before.state == "pending", "the admitted older attempt is {}, not pending", loser_before.state);
        ensure!(loser_before.terminal.is_none(), "the admitted older attempt already has a terminal");
        let binding_before = loser_before
            .binding
            .clone()
            .ok_or_else(|| anyhow!("the admitted operation has no serving-operation binding"))?;
        ensure!(
            binding_before.issuer_id == loser_before.identity.issuer_id,
            "the serving binding issuer differs from its stored operation"
        );
        ensure!(
            binding_before.parent_digest == loser_before.identity.request_digest,
            "the serving binding parent digest differs from its stored operation identity"
        );
        ensure!(
            operation_events(db, repository_id, loser_operation).await?.is_empty(),
            "the admitted older attempt emitted an event before release"
        );
        ensure!(durable_main(db, repository_id).await? == seed, "durable main changed before the winner started");
        ensure!(gate_revision(db, repository_id).await? == revision_before, "the gate moved before the winner started");
        ensure!(ref_count(db, repository_id).await? == 1, "the acknowledged ref set is not exactly main");
        let memberships_before = membership_stats(db, repository_id, revision_before).await?;
        ensure!(memberships_before.above_revision == 0, "a membership was recorded beyond the current revision");

        // The winner uses a different commit, the same old OID and the SAME ref.
        *phase = "winner_publish";
        winner_push = Some(spawn_push(git, first_dir, direct_url, winner_operation));
        let winner_output = take_push_output(&mut winner_push, "winning", &mut join_unproven).await?;
        ensure!(winner_output.success, "the winning stock push failed: {}", redacted(&winner_output));

        // The winner is the only writer so far, and the older admitted attempt is
        // still pending with no terminal/event before release.
        *phase = "post_winner_assertions";
        let revision_after = gate_revision(db, repository_id).await?;
        ensure!(
            revision_after == revision_before + 1,
            "the gate moved {revision_before}->{revision_after}, not exactly one winner revision"
        );
        ensure!(durable_main(db, repository_id).await? == first_new, "durable main is not the winning commit");
        let loser_mid = operation_witness(db, repository_id, loser_operation)
            .await?
            .ok_or_else(|| anyhow!("the admitted operation row disappeared before release"))?;
        ensure!(loser_mid.state == "pending", "the admitted older attempt settled before release");
        ensure!(loser_mid.terminal.is_none(), "the admitted older attempt has a terminal before release");
        ensure!(
            loser_mid.identity == loser_before.identity,
            "the admitted attempt's stored identity changed before release"
        );
        ensure!(
            loser_mid.binding == loser_before.binding,
            "the admitted attempt's serving binding changed before release"
        );
        ensure!(
            operation_events(db, repository_id, loser_operation).await?.is_empty(),
            "the admitted older attempt emitted an event before release"
        );
        let memberships_after_winner = membership_stats(db, repository_id, revision_after).await?;
        ensure!(
            memberships_after_winner.total == memberships_before.total + 1,
            "the winner did not add exactly one pack membership"
        );
        ensure!(
            memberships_after_winner.at_revision == 1,
            "the winner added {} pack memberships at its revision, not one",
            memberships_after_winner.at_revision
        );
        ensure!(
            memberships_after_winner.above_revision == 0,
            "a pack membership was recorded beyond the winner revision"
        );

        // Release the older admitted plan. Its A3 gate proof now sees the winner's
        // revision; it must be closed with the fixed superseded refusal.
        *phase = "superseded_refusal_await";
        pause.release();
        pause_guard.disarm();
        let loser_output = take_push_output(&mut loser_push, "losing", &mut join_unproven).await?;
        ensure!(!loser_output.success, "the admitted older attempt unexpectedly succeeded");
        let loser_text = output_text(&loser_output);
        for forbidden in
            ["409", "503", "non-fast-forward", "fetch first", "unexpected disconnect", "remote end hung up"]
        {
            let found = match forbidden {
                "409" | "503" => has_stock_http_error(&loser_text, forbidden),
                _ => loser_text.contains(forbidden),
            };
            ensure!(!found, "the admitted older attempt saw `{forbidden}`, not a report-status");
        }
        ensure!(
            loser_text.contains("[rejected]") && loser_text.contains("stale info"),
            "the admitted older attempt did not print the stock stale-info rejection"
        );

        *phase = "report_assertions";
        let winner_capture = captures.take(winner_operation).ok_or_else(|| anyhow!("the winner has no raw reply"))?;
        let loser_capture = captures.take(loser_operation).ok_or_else(|| anyhow!("the loser has no raw reply"))?;
        ensure!(captures.is_empty(), "the service answered unexpected extra receive-pack operations");
        ensure!(winner_capture.status == 200, "the service answered the winner with {}", winner_capture.status);
        ensure!(loser_capture.status == 200, "the service answered the loser with {}", loser_capture.status);
        ensure!(!winner_capture.truncated, "the winner's raw service reply is truncated");
        ensure!(!loser_capture.truncated, "the loser's raw service reply is truncated");
        let (winner_unpack, winner_verdicts) = report_status(&winner_capture.body)?;
        ensure!(winner_unpack == "ok", "the winner's report-status did not unpack: {winner_unpack}");
        ensure!(
            winner_verdicts == vec![(SEED_REF.to_owned(), None)],
            "the winner's report-status is not exactly one ok on main: {winner_verdicts:?}"
        );
        let (loser_unpack, loser_verdicts) = report_status(&loser_capture.body)?;
        ensure!(loser_unpack == "ok", "the loser's report-status did not unpack: {loser_unpack}");
        ensure!(
            loser_verdicts == vec![(SEED_REF.to_owned(), Some("stale info".to_owned()))],
            "the loser's report-status is not exactly one ng stale info on main: {loser_verdicts:?}"
        );

        // Scoped durable terminal: the current legacy shape still names the correct
        // repository, the exact superseded operation refusal and the fixed per-ref
        // `OldOidMismatch`. The older attempt's identity and binding are immutable.
        *phase = "durable_refusal_assertions";
        let loser_after = operation_witness(db, repository_id, loser_operation)
            .await?
            .ok_or_else(|| anyhow!("the rejected operation has no durable row"))?;
        ensure!(loser_after.state == "rejected", "the admitted older attempt is {}, not rejected", loser_after.state);
        ensure!(
            loser_after.identity == loser_before.identity,
            "the admitted attempt's stored identity was mutated or relabelled"
        );
        ensure!(
            loser_after.binding == loser_before.binding,
            "the admitted attempt's serving binding was mutated or relabelled"
        );
        let terminal_value =
            loser_after.terminal.clone().ok_or_else(|| anyhow!("the rejected admitted attempt has no terminal"))?;
        let terminal: PackCommitTerminal = serde_json::from_value(terminal_value.clone())
            .map_err(|_| anyhow!("the rejected terminal does not match the pack terminal schema"))?;
        ensure!(terminal.kind == TerminalKind::Rejected, "the rejected terminal has another kind: {terminal:?}");
        ensure!(
            terminal.repository_id == repository_id,
            "the rejected terminal names another repository: {terminal:?}"
        );
        ensure!(
            terminal.revision == revision_after,
            "the rejected terminal recorded revision {}, not the winner's {revision_after}: {terminal:?}",
            terminal.revision
        );
        ensure!(
            terminal.head_ref.as_deref() == Some(SEED_REF),
            "the rejected terminal names another head: {terminal:?}"
        );
        ensure!(
            terminal.registrations.is_empty(),
            "the refused admitted attempt registered pack membership: {terminal:?}"
        );
        ensure!(terminal.refs.len() == 1, "the rejected terminal does not cover exactly one ref: {terminal:?}");
        match &terminal.refs[0] {
            RefCommitResult::NotApplied { name, reason } => {
                ensure!(name.as_str() == SEED_REF, "the rejected terminal names another ref: {terminal:?}");
                ensure!(
                    *reason == CommitRejectCode::OldOidMismatch,
                    "the rejected terminal reason is {reason:?}, not the fixed per-ref OldOidMismatch: {terminal:?}"
                );
            }
            RefCommitResult::Applied { .. } => {
                return Err(anyhow!("the rejected terminal contains an applied ref: {terminal:?}"));
            }
        }
        let rejection = terminal
            .rejection
            .as_ref()
            .ok_or_else(|| anyhow!("the rejected terminal has no operation-level rejection: {terminal:?}"))?;
        let rejection_code = PackCommitRejectCode::parse(&rejection.code)
            .map_err(|_| anyhow!("the rejected terminal carries an unknown rejection code: {terminal:?}"))?;
        ensure!(
            rejection_code == PackCommitRejectCode::RevisionMismatch,
            "the admitted older attempt was closed as {rejection_code:?}, not RevisionMismatch: {terminal:?}"
        );
        ensure!(
            rejection.detail == POST_ADMISSION_REFUSAL_DETAIL,
            "the admitted older attempt detail is {:?}, not the exact superseded reason: {terminal:?}",
            rejection.detail
        );
        ensure!(
            (rejection.code.as_str(), rejection.detail.as_str())
                == (PackCommitRejectCode::RevisionMismatch.as_str(), POST_ADMISSION_REFUSAL_DETAIL),
            "the admitted older attempt is not the fixed admitted_base_superseded terminal: {terminal:?}"
        );

        // Exactly one correlated rejected event, and the authenticated operation
        // read returns the same terminal without appending another event.
        let events = operation_events(db, repository_id, loser_operation).await?;
        ensure!(
            events.len() == 1,
            "the rejected admitted attempt has {} RefStore events, not exactly one",
            events.len()
        );
        ensure!(events[0].0 == "rejected", "the single RefStore event is not `rejected`");
        ensure!(events[0].1 == terminal_value, "the rejected RefStore event payload differs from the durable terminal");

        *phase = "authenticated_operation_read";
        let view = operation_view(address, &owner, &name, loser_operation).await?;
        ensure!(view["state"].as_str() == Some("rejected"), "the authenticated operation read is not rejected");
        ensure!(view["terminal"] == terminal_value, "the authenticated operation read returned a different terminal");
        ensure!(
            operation_events(db, repository_id, loser_operation).await?.len() == 1,
            "the authenticated operation read appended another RefStore event"
        );

        // The winner remains the only writer and membership gain; the loser added
        // no ref, no terminal beyond the refusal above and no membership.
        ensure!(
            gate_revision(db, repository_id).await? == revision_after,
            "the refused admitted attempt advanced the gate"
        );
        ensure!(
            durable_main(db, repository_id).await? == first_new,
            "durable main is not the winner after the refusal"
        );
        ensure!(
            ref_count(db, repository_id).await? == 1,
            "the refused admitted attempt changed the acknowledged ref set"
        );
        ensure!(
            membership_stats(db, repository_id, revision_after).await? == memberships_after_winner,
            "the refused admitted attempt changed pack membership"
        );
        let winner_after = operation_witness(db, repository_id, winner_operation)
            .await?
            .ok_or_else(|| anyhow!("the winning operation row disappeared"))?;
        ensure!(winner_after.state == "committed", "the winning operation is {}, not committed", winner_after.state);
        let winner_terminal: PackCommitTerminal = serde_json::from_value(
            winner_after.terminal.ok_or_else(|| anyhow!("the committed operation has no terminal"))?,
        )
        .map_err(|_| anyhow!("the committed terminal does not match the pack terminal schema"))?;
        ensure!(winner_terminal.kind == TerminalKind::Committed, "the winning terminal is not committed");
        ensure!(winner_terminal.repository_id == repository_id, "the winning terminal names another repository");
        ensure!(winner_terminal.revision == revision_after, "the winning terminal recorded another revision");
        ensure!(winner_terminal.refs.len() == 1, "the winning terminal does not cover exactly one ref");
        match &winner_terminal.refs[0] {
            RefCommitResult::Applied { name, old_oid, new_oid } => {
                ensure!(name.as_str() == SEED_REF, "the winning terminal names another ref");
                ensure!(
                    old_oid.as_deref() == Some(seed.as_str()),
                    "the winning terminal did not use the shared old OID"
                );
                ensure!(
                    new_oid.as_deref() == Some(first_new.as_str()),
                    "the winning terminal did not apply the winner"
                );
            }
            RefCommitResult::NotApplied { .. } => {
                return Err(anyhow!("the winning terminal contains a refused ref"));
            }
        }

        Ok(())
    })
    .catch_unwind()
    .await;
    // The payload is discarded. The outer failure is only the fixed phase.
    let panicked = outcome.is_err();
    let outcome = outcome.unwrap_or_else(|_| Err(anyhow!("admitted refusal fixture assertion panicked")));

    // Release the still-paused request before joining either owner. The hook
    // turns an abandoned rendezvous into the fixed pre-upload refusal, so an
    // early failure cannot let the pending loser write. A normal join after
    // `Git::output` is the only proof that the stock child was waited/reaped;
    // an ordinary-wait timeout is never promoted to a clean cleanup.
    pause_guard.abandon();
    let loser_clean = confirm_or_stop(&mut loser_push, join_unproven, PUSH_BOUND).await;
    let winner_clean = confirm_or_stop(&mut winner_push, join_unproven, PUSH_BOUND).await;
    let server_clean = server.drain(PUSH_BOUND).await.is_ok();
    let cleanup_proven = !join_unproven && loser_clean && winner_clean && server_clean;

    if cleanup_proven {
        // The client work tree and gateway scratch are deleted only after both
        // real Git tasks and the server disposal are proved.
        drop(race_work.take());
        if panicked {
            *phase = "panic_assertion";
            return Err(anyhow!("admitted refusal fixture assertion panicked"));
        }
        outcome
    } else {
        // Keep every unresolved owned handle from being dropped/aborted as if
        // that were proof. The schema, work tree and scratch stay retained.
        for slot in [&mut loser_push, &mut winner_push] {
            if let Some(task) = slot.take() {
                std::mem::forget(task);
            }
        }
        *phase = "cleanup_drain";
        std::mem::forget(race_work.take());
        std::mem::forget(scratch);
        Err(anyhow!("admitted refusal fixture join/drain was not proved"))
    }
}

fn open_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == BlobProvider::S3, "ROOTYARD_BLOB_SERVICE must be s3 for this suite");
    ensure!(!profile.root().is_empty(), "the suite pinned no remote Blob prefix");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

fn clone_url(address: std::net::SocketAddr, owner: &Actor, name: &str) -> String {
    format!("http://{}:{}@{address}/git/{}/{name}.git", owner.username, owner.token, owner.username)
}

async fn clone_one(git: &Git, root: &Path, url: &str, destination: &str) -> Result<std::path::PathBuf> {
    let output = git.clone(root, url, destination).await?;
    ensure!(output.success, "stock Git clone failed: {}", redacted(&output));
    Ok(root.join(destination))
}

async fn create_repository(address: std::net::SocketAddr, owner: &Actor, name: &str) -> Result<Value> {
    let client = reqwest::Client::builder().no_proxy().build()?;
    let response = client
        .post(format!("http://{address}/api/repos"))
        .bearer_auth(&owner.token)
        .json(&serde_json::json!({"name": name, "object_format": "sha1"}))
        .send()
        .await?;
    let status = response.status();
    let body: Value = response.json().await?;
    ensure!(status.is_success(), "create API returned {status}: {}", body["error"].as_str().unwrap_or("<no body>"));
    ensure!(
        body["owner"].as_str() == Some(owner.username.as_str()) && body["name"].as_str() == Some(name),
        "create API returned another repository identity"
    );
    Ok(body)
}

async fn provision_decision_realm(db: &Db, owner: &Actor, name: &str, store: &BlobStore) -> Result<()> {
    let serving =
        lookup(&db.pool, &owner.identity, &owner.username, name, true, store.backend_identity(), deadline()).await?;
    let gate = serving.gate;
    let expectation = RealmExpectation::new(
        gate.repository_id(),
        gate.tenant_id(),
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let mut client = db.pool.get().await?;
    PgDecisionProtocol
        .provision(&mut client, &expectation, deadline())
        .await
        .map_err(|error| anyhow!("decision realm provisioning refused: {error}"))?;
    Ok(())
}

/// One real stock push, carrying the operation id exactly as the external race
/// case does (`http.extraHeader`). The guard aborts the task on early return.
fn spawn_push(git: &'static Git, directory: std::path::PathBuf, url: String, operation: Uuid) -> PushTask {
    PushTask(tokio::spawn(async move {
        let header = format!("http.extraHeader=X-Rootyard-Operation: {operation}");
        let target = format!("HEAD:{SEED_REF}");
        git.run(&directory, &["-c", header.as_str(), "push", url.as_str(), target.as_str()]).await
    }))
}

async fn wait_push(task: PushTask, label: &str) -> Result<git::Output> {
    let joined = tokio::time::timeout(PUSH_BOUND, task)
        .await
        .map_err(|_| anyhow!("the {label} stock push exceeded its bound"))?;
    joined.with_context(|| format!("the {label} stock push task failed"))?
}

/// Record a `JoinHandle` result that a `select!` arm already consumed. The
/// handle is always removed, so no later cleanup can poll it again. Only a
/// normal `Git::run` `Output` is proved; any runner error or `JoinError` is
/// recorded as cleanup-unproven and the fixed error is returned.
fn consume_ready_push(
    slot: &mut Option<PushTask>,
    ready: Result<Result<git::Output>, tokio::task::JoinError>,
    join_unproven: &mut bool,
) -> Result<git::Output> {
    drop(slot.take());
    match ready {
        Ok(Ok(output)) => Ok(output),
        Ok(Ok(Err(_))) | Ok(Err(_)) => {
            *join_unproven = true;
            Err(anyhow!("stock push task ended without a Git output proof"))
        }
    }
}

/// Wait for one real push output without discarding its owned handle on a
/// timeout. The caller keeps the slot so cleanup can either prove a normal join
/// or perform bounded containment and retain an unresolved handle.
async fn take_push_output(slot: &mut Option<PushTask>, label: &str, join_unproven: &mut bool) -> Result<git::Output> {
    let joined = match slot.as_mut() {
        Some(task) => task.join_once(PUSH_BOUND).await,
        None => return Err(anyhow!("the {label} stock push task was not retained")),
    };
    match joined {
        Ok(output) => {
            drop(slot.take());
            Ok(output)
        }
        Err(JoinFailure::SettledUnproven) => {
            drop(slot.take());
            *join_unproven = true;
            Err(anyhow!("stock push task ended without a Git output proof"))
        }
        Err(JoinFailure::NotSettled) => {
            *join_unproven = true;
            Err(anyhow!("stock push task join exceeded its bound"))
        }
    }
}

/// Prove a normal join when no earlier ordinary wait timed out. Once any
/// ordinary wait is unproven, only containment is attempted and the result is
/// never promoted to a clean cleanup. Any consumed result is removed here, so
/// a slot that survives this call still owns an unconsumed handle.
async fn confirm_or_stop(slot: &mut Option<PushTask>, join_unproven: bool, bound: Duration) -> bool {
    if slot.is_none() {
        return true;
    }
    if !join_unproven {
        let joined = match slot.as_mut() {
            Some(task) => task.join_once(bound).await,
            None => return true,
        };
        match joined {
            Ok(_) => {
                drop(slot.take());
                return true;
            }
            Err(JoinFailure::SettledUnproven) => {
                drop(slot.take());
                return false;
            }
            Err(JoinFailure::NotSettled) => {}
        }
    }
    let settled = match slot.as_mut() {
        Some(task) => task.stop_unproven(CLEANUP_STOP_BOUND).await,
        None => true,
    };
    if settled {
        drop(slot.take());
    }
    false
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DurableIdentity {
    issuer_id: Uuid,
    lane: String,
    sequence: i64,
    request_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ServingBinding {
    issuer_id: Uuid,
    producer_digest: String,
    parent_digest: String,
}

struct DurableWitness {
    state: String,
    terminal: Option<Value>,
    identity: DurableIdentity,
    binding: Option<ServingBinding>,
}

/// One repository+operation-scoped read of the migration-138 row and its
/// migration-147 serving binding. This is read-only; the fixture never writes
/// either row by SQL.
async fn operation_witness(db: &Db, repository_id: Uuid, operation: Uuid) -> Result<Option<DurableWitness>> {
    let row = db
        .pool
        .get()
        .await?
        .query_opt(
            "SELECT o.state,o.terminal_result,o.issuer_id,o.lane,o.sequence,o.request_digest,
                    s.issuer_id,s.producer_request_digest,s.plan_parent_digest
               FROM ref_store_operations o
               LEFT JOIN ref_store_serving_operations s
                 ON s.repository_id=o.repository_id AND s.operation_id=o.operation_id
              WHERE o.repository_id=$1 AND o.operation_id=$2",
            &[&repository_id, &operation],
        )
        .await?;
    Ok(row.map(|row| {
        let binding_issuer: Option<Uuid> = row.get(6);
        let producer_digest: Option<String> = row.get(7);
        let parent_digest: Option<String> = row.get(8);
        DurableWitness {
            state: row.get(0),
            terminal: row.get(1),
            identity: DurableIdentity {
                issuer_id: row.get(2),
                lane: row.get(3),
                sequence: row.get(4),
                request_digest: row.get(5),
            },
            binding: match (binding_issuer, producer_digest, parent_digest) {
                (Some(issuer_id), Some(producer_digest), Some(parent_digest)) => {
                    Some(ServingBinding { issuer_id, producer_digest, parent_digest })
                }
                _ => None,
            },
        }
    }))
}

/// Bounded repository+operation-scoped event read. The expected count is one,
/// so the small cap only keeps an unexpected duplicate from being unbounded.
async fn operation_events(db: &Db, repository_id: Uuid, operation: Uuid) -> Result<Vec<(String, Value)>> {
    let rows = db
        .pool
        .get()
        .await?
        .query(
            "SELECT outcome,payload FROM ref_store_core_events
              WHERE repository_id=$1 AND operation_id=$2
              ORDER BY revision,event_id LIMIT 8",
            &[&repository_id, &operation],
        )
        .await?;
    Ok(rows.into_iter().map(|row| (row.get(0), row.get(1))).collect())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MembershipStats {
    total: i64,
    at_revision: i64,
    above_revision: i64,
}

async fn membership_stats(db: &Db, repository_id: Uuid, revision: i64) -> Result<MembershipStats> {
    let row = db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT count(*),
                    count(*) FILTER (WHERE joined_revision=$2),
                    count(*) FILTER (WHERE joined_revision>$2)
               FROM ref_store_core_pack_memberships WHERE repository_id=$1",
            &[&repository_id, &revision],
        )
        .await?;
    Ok(MembershipStats { total: row.get(0), at_revision: row.get(1), above_revision: row.get(2) })
}

async fn ref_count(db: &Db, repository_id: Uuid) -> Result<i64> {
    Ok(db
        .pool
        .get()
        .await?
        .query_one("SELECT count(*) FROM ref_store_core_refs WHERE repository_id=$1", &[&repository_id])
        .await?
        .get(0))
}

/// Authenticated historical operation read via the existing production route.
/// The caller compares the returned terminal with the scoped durable row.
async fn operation_view(address: SocketAddr, owner: &Actor, name: &str, operation: Uuid) -> Result<Value> {
    let result = tokio::time::timeout(OPERATION_VIEW_BOUND, async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| anyhow!("operation view client unavailable"))?;
        let mut response = client
            .get(format!("http://{address}/api/repos/{}/{name}/operations/{operation}", owner.username))
            .bearer_auth(&owner.token)
            .send()
            .await
            .map_err(|_| anyhow!("operation view transport failed"))?;
        if !response.status().is_success() {
            return Err(anyhow!("operation view returned a non-success status"));
        }
        if matches!(response.content_length(), Some(length) if length > MAX_OPERATION_VIEW_BYTES as u64) {
            return Err(anyhow!("operation view body exceeded its fixed cap"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| anyhow!("operation view body read failed"))? {
            let next =
                body.len().checked_add(chunk.len()).ok_or_else(|| anyhow!("operation view body length overflow"))?;
            if next > MAX_OPERATION_VIEW_BYTES {
                return Err(anyhow!("operation view body exceeded its fixed cap"));
            }
            body.extend_from_slice(&chunk);
        }
        let body: Value =
            serde_json::from_slice(&body).map_err(|_| anyhow!("operation view body was not valid JSON"))?;
        let expected = operation.to_string();
        ensure!(body["operation_id"].as_str() == Some(expected.as_str()), "operation view identity mismatch");
        Ok(body)
    })
    .await;
    match result {
        Ok(value) => value,
        Err(_) => Err(anyhow!("operation view exceeded its fixed deadline")),
    }
}

async fn gate_revision(db: &Db, repository_id: Uuid) -> Result<i64> {
    Ok(db
        .pool
        .get()
        .await?
        .query_one("SELECT revision FROM ref_store_core_gates WHERE repository_id=$1", &[&repository_id])
        .await?
        .get(0))
}

async fn durable_main(db: &Db, repository_id: Uuid) -> Result<String> {
    Ok(db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT oid FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name=$2",
            &[&repository_id, &SEED_REF],
        )
        .await?
        .get(0))
}

async fn operation_row(db: &Db, repository_id: Uuid, operation: Uuid) -> Result<Option<(String, Option<Value>)>> {
    let row = db
        .pool
        .get()
        .await?
        .query_opt(
            "SELECT state, terminal_result FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2",
            &[&repository_id, &operation],
        )
        .await?;
    Ok(row.map(|row| (row.get(0), row.get(1))))
}

/// Parse only a real Git `report-status`: `unpack <status>` plus
/// `ok|ng <ref> [reason]` pkt-lines followed by exactly one flush. Anything
/// else is refused, so an HTTP body or a fabricated string cannot pass.
fn report_status(response: &[u8]) -> Result<GitReport> {
    ensure!(!response.is_empty(), "service response is empty");
    let mut position = 0usize;
    let mut unpack = None;
    let mut results = Vec::new();
    loop {
        ensure!(position + 4 <= response.len(), "report-status has no flush pkt-line");
        let length = usize::from_str_radix(&String::from_utf8_lossy(&response[position..position + 4]), 16)
            .map_err(|_| anyhow!("report-status pkt-line length is invalid"))?;
        position += 4;
        if length == 0 {
            ensure!(position == response.len(), "report-status has bytes after its flush");
            break;
        }
        ensure!(length >= 4 && position + length - 4 <= response.len(), "report-status pkt-line is malformed");
        let raw = std::str::from_utf8(&response[position..position + length - 4])
            .map_err(|_| anyhow!("report-status line is not UTF-8"))?;
        ensure!(
            raw.ends_with('\n') && !raw[..raw.len() - 1].contains('\n') && !raw.contains('\r'),
            "report-status pkt-line must end in exactly one LF and contain no CR: {raw:?}"
        );
        let line = raw[..raw.len() - 1].to_owned();
        position += length - 4;
        if let Some(value) = line.strip_prefix("unpack ") {
            ensure!(unpack.is_none(), "report-status repeats unpack");
            unpack = Some(value.to_owned());
        } else if let Some(rest) = line.strip_prefix("ok ") {
            results.push((rest.to_owned(), None));
        } else if let Some(rest) = line.strip_prefix("ng ") {
            let (name, reason) = rest.split_once(' ').ok_or_else(|| anyhow!("ng line has no reason: {line}"))?;
            results.push((name.to_owned(), Some(reason.to_owned())));
        } else {
            return Err(anyhow!("unexpected report-status line: {line}"));
        }
    }
    Ok((unpack.ok_or_else(|| anyhow!("report-status has no unpack line"))?, results))
}

// Git's destination lines include the fixture's ephemeral port and random hex repo name.
fn has_stock_http_error(text: &str, status: &str) -> bool {
    let rpc_error = format!("RPC failed; HTTP {status} curl ");
    let url_error = format!("The requested URL returned error: {status}");
    text.lines().any(|line| {
        line.strip_prefix("error: ").unwrap_or(line).starts_with(rpc_error.as_str())
            || line.ends_with(url_error.as_str())
    })
}

fn synthetic_push_output() -> git::Output {
    git::Output { success: false, stdout: Vec::new(), stderr: Vec::new() }
}

/// Pure Tokio regression: a timeout leaves the owned handle unconsumed, a
/// select-consumed result is removed before cleanup, and cleanup never polls a
/// consumed JoinHandle. No real Git, server or PostgreSQL is involved.
#[tokio::test]
async fn push_join_results_are_consumed_once_before_cleanup() {
    let (release, wait) = tokio::sync::oneshot::channel::<()>();
    let mut task = PushTask(tokio::spawn(async move {
        let _ = wait.await;
        Ok::<_, anyhow::Error>(synthetic_push_output())
    }));
    assert!(matches!(task.join_once(Duration::from_millis(1)).await, Err(JoinFailure::NotSettled)));
    let _ = release.send(());
    assert!(task.join_once(Duration::from_secs(1)).await.is_ok());
    drop(task);

    let mut join_unproven = false;
    let mut slot = Some(PushTask(tokio::spawn(async {
        let value: Result<git::Output> = Err(anyhow!("synthetic git runner error"));
        value
    })));
    let ready = match slot.as_mut() {
        Some(task) => (&mut task.0).await,
        None => unreachable!("synthetic push task disappeared"),
    };
    assert!(consume_ready_push(&mut slot, ready, &mut join_unproven).is_err());
    assert!(join_unproven);
    assert!(slot.is_none());
    let _ = confirm_or_stop(&mut slot, join_unproven, Duration::from_millis(10)).await;
}

#[test]
fn stock_http_errors_distinguish_status_from_destination_digits() {
    let destination = "To http://127.0.0.1:54090/git/owner/race-admission-a503b0000000.git\n\
         ! [rejected] HEAD -> main (stale info)\n\
        error: failed to push some refs to 'http://127.0.0.1:54090/git/owner/race-admission-a503b0000000.git'";
    for status in ["409", "503"] {
        assert!(destination.contains(status));
        assert!(!has_stock_http_error(destination, status));
        assert!(has_stock_http_error(&format!("error: RPC failed; HTTP {status} curl 22"), status));
        assert!(has_stock_http_error(
            &format!("fatal: unable to access 'http://example.invalid/': The requested URL returned error: {status}"),
            status
        ));
    }
}

fn output_text(output: &git::Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))
}

/// Redacted diagnostic: never include a URL, credentials or an operation id.
fn redacted(output: &git::Output) -> String {
    output_text(output)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
            let line = line.split_once("://").map_or(line.clone(), |(head, _)| format!("{head}://<redacted>"));
            if line.len() > 300 {
                let mut end = 300;
                while !line.is_char_boundary(end) {
                    end -= 1;
                }
                return format!("{}<truncated>", &line[..end]);
            }
            line
        })
        .collect::<Vec<_>>()
        .join(" | ")
}
