//! Deterministic acceptance for the pre-admission stale-baseline race.
//!
//! This is a `cfg(test)`-only internal HTTP harness. It drives the production
//! router over a real loopback listener, real PostgreSQL, the operator's real
//! S3-compatible Blob profile and real stock Git clients. The only test-only
//! artifact is an in-memory rendezvous attached to one gateway instance: it
//! pauses the selected losing operation after its publish baseline was captured
//! and before its admission transaction begins. There is no request header,
//! environment variable, route or runtime configuration that can reach it, and
//! the production `BlobGitState` has no such field at all. A second test-only
//! middleware records the exact `report-status` body the service wrote for each
//! pinned operation; it does not synthesize or rewrite a ref verdict.
//!
//! Interleaving:
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
//! The external `tests/blob_git_gateway.rs` race case and its exact one-ok /
//! one-ng assertions remain untouched; it stays the unsynchronized stress case.
//!
//! Run explicitly by Root (hard-fails when PostgreSQL, Blob or Git is absent):
//!
//! ```text
//! ROOTYARD_TEST_DATABASE_URL=... ROOTYARD_BLOB_*... ROOTYARD_TEST_GIT=/usr/bin/git \
//! cargo test --lib admission_race_acceptance -- --ignored --test-threads=1
//! ```

// Reuse the fixture entry point already loaded by the session HTTP harness.
// Registering the same actor/database/Git files here again would duplicate the
// modules in the cfg(test) library graph.
use super::session_http_acceptance::fixtures::{
    actor::{self, Actor},
    db::{Db, deadline},
    git::{self, Git},
};

use std::{
    collections::HashMap,
    path::Path,
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
use serde_json::Value;
use tokio::{net::TcpListener, task::JoinHandle};
use uuid::Uuid;

use crate::{
    blob_git_gateway::{BlobGitConfig, BlobGitState, router, state::AdmissionPause},
    blob_store::{BlobProvider, config::BlobProfile, opendal::BlobStore},
    ref_store::{
        core::decision_commit::{PgDecisionProtocol, RealmExpectation},
        serving::lookup,
    },
};

const SEED_FILE: &str = "seed.txt";
const SEED_CONTENT: &str = "seed\n";
const SEED_REF: &str = "refs/heads/main";
const MAX_CAPTURED_RESPONSE: usize = 64 * 1024 * 1024;

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

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn pre_admission_revision_mismatch_rebases_to_old_oid_mismatch() -> Result<()> {
    let _serial = super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    let db = Db::setup().await?;
    let outcome = case(&db).await;
    db.finish(outcome).await
}

async fn case(db: &Db) -> Result<()> {
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

    let created = create_repository(address, &owner, &name).await?;
    let repository_id = Uuid::parse_str(created["id"].as_str().ok_or_else(|| anyhow!("create API has no id"))?)?;
    provision_decision_realm(db, &owner, &name, &store).await?;

    // Seed one real main tip, then clone twice so both stock clients advertise
    // exactly the same old OID.
    let work = tempfile::tempdir().context("temporary Git work root")?;
    let direct_url = clone_url(address, &owner, &name);
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

    // Start the loser and wait until its native receive-pack, pair staging and
    // publish baseline capture have completed. It is then held before its
    // admission transaction while the winner commits.
    let mut loser_push = spawn_push(git, second_dir, direct_url.clone(), loser_operation);
    tokio::select! {
        _ = pause.wait_reached() => {}
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

    let winner_output = spawn_push(git, first_dir, direct_url, winner_operation).await?;
    let winner_output = winner_output.context("the winning stock push task failed")?;
    ensure!(winner_output.success, "the winning stock push failed: {}", redacted(&winner_output));

    pause.release();
    let loser_output = loser_push.await.context("the losing stock push task failed")??;
    ensure!(!loser_output.success, "the paused loser unexpectedly succeeded");
    let loser_text = output_text(&loser_output);
    for forbidden in ["409", "503", "non-fast-forward", "fetch first", "unexpected disconnect", "remote end hung up"] {
        ensure!(
            !loser_text.contains(forbidden),
            "loser saw `{forbidden}`, not a report-status: {}",
            redacted(&loser_output)
        );
    }
    ensure!(
        loser_text.contains("[rejected]") && loser_text.contains("stale info"),
        "the loser did not print the stock stale-info rejection: {}",
        redacted(&loser_output)
    );

    // Exact raw service report-statuses, keyed by pinned operation. Both must
    // be HTTP 200 and parse as real Git pkt-lines; the loser must carry exactly
    // one `ng refs/heads/main stale info` and the winner exactly one `ok`.
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
    let refs = terminal["refs"].as_array().ok_or_else(|| anyhow!("the rejected terminal has no refs"))?;
    ensure!(refs.len() == 1, "the rejected terminal does not cover exactly one ref: {terminal}");
    ensure!(refs[0]["name"].as_str() == Some(SEED_REF), "the rejected terminal names another ref: {terminal}");
    let code = refs[0]["reason"]["code"].as_str().or_else(|| refs[0]["reason"].as_str()).unwrap_or_default();
    ensure!(
        code.contains("OldOidMismatch") || code.contains("old_oid_mismatch"),
        "the rejected terminal carries {code:?}: {terminal}"
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
/// case does (`http.extraHeader`).
fn spawn_push(
    git: &'static Git,
    directory: std::path::PathBuf,
    url: String,
    operation: Uuid,
) -> JoinHandle<Result<git::Output>> {
    tokio::spawn(async move {
        let header = format!("http.extraHeader=X-Rootyard-Operation: {operation}");
        let target = format!("HEAD:{SEED_REF}");
        git.run(&directory, &["-c", header.as_str(), "push", url.as_str(), target.as_str()]).await
    })
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
