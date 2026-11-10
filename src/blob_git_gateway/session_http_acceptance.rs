//! Real HTTP acceptance for the push-bound repository session (#174).
//!
//! Compiled only inside the library's `cfg(test)` build, so it opens the very
//! same production token codec (`SessionTokenCodec`, `SessionTokens`) that the
//! standalone keyring loader uses. It adds no production API and edits no
//! keyring: the only test-only artifact is one deterministic HMAC key held in
//! `Zeroizing` memory, attached exactly like a configured key set.
//!
//! Run explicitly by Root (one case, `#[ignore]`, hard-fails when a real
//! service or variable is absent):
//!
//! ```text
//! ROOTYARD_TEST_DATABASE_URL=... ROOTYARD_BLOB_SERVICE=s3 ROOTYARD_BLOB_ENDPOINT=... \
//! ROOTYARD_BLOB_BUCKET=... ROOTYARD_BLOB_REGION=... ROOTYARD_BLOB_ACCESS_KEY_ID=... \
//! ROOTYARD_BLOB_SECRET_ACCESS_KEY=... ROOTYARD_TEST_GIT=/usr/bin/git \
//! cargo test --lib session_http_acceptance -- --ignored --test-threads=1
//! ```
//!
//! The outer runner first migrates a fresh owned physical database with the
//! current CLI, so `public.cluster_authority` already holds the production
//! fence. This case never writes that row: it creates its own random schema
//! with the real `db::migrate` and reads the fence only through the real
//! lookups.
//!
//! Flow: real `POST /api/repos`, real `lookup` + `PgDecisionProtocol::provision`
//! of the migration-144 realm, a native Git clone/commit/push over the real
//! `/git/{owner}/{name}.git` Smart HTTP route, then `/refs` -> `/tree?oid=HEAD`
//! -> `/commits`, each presenting the previous successful read's session token.
//! Every answer must carry a nonempty token and a positive revision that never
//! regresses. A final `/refs` without any session header proves the token-free
//! request still succeeds. The negative/refusal matrix is NOT covered here.
//!
//! Messages are generic on purpose: Git URLs carry credentials, so neither a
//! URL, Git stderr, a token, the key, the database URL nor Blob secrets are
//! ever printed.

#[path = "../../tests/blob_gateway_support/mod.rs"]
mod support;

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderName, Method, Request},
    middleware::{self, Next},
    response::Response,
};
use support::{
    actor::{self, Actor},
    db::{Db, deadline},
    git::{Git, assert_no_compute_views, clone_url},
};
use tokio::net::TcpListener;
use uuid::Uuid;
use zeroize::Zeroizing;

use anyhow::{Context, Result, anyhow, ensure};
use serde_json::{Value, json};
use super::{
    BlobGitConfig, BlobGitState,
    repo_session::{SessionTokenCodec, SessionTokens},
};
use crate::{
    blob_store::{BlobBackendIdentity, BlobProvider, config::BlobProfile, opendal::BlobStore},
    ref_store::{
        core::decision_commit::{PgDecisionProtocol, RealmExpectation},
        serving::lookup,
    },
};

/// Request header carrying the session token.
const SESSION_HEADER: &str = "x-rootyard-session";
/// Response header naming the exact gate revision served.
const REVISION_HEADER: &str = "x-rootyard-session-revision";
/// Test-only key id inside the signed frame; it is not secret.
const TEST_KEY_ID: u8 = 7;
/// Fixed test-only key bytes: a deterministic 32-byte sequence, not read from
/// the environment, so the outcome is stable and nothing secret is printed.
const TEST_KEY_BYTES: [u8; 32] = [0x5a; 32];
/// Lifetime signed into every frame for this run.
const BOUNDED_LIFETIME: u32 = 120;
/// The fixture commit pushed through the real receive pipeline.
const COMMIT_FILE: &str = "readme.txt";
const COMMIT_CONTENT: &str = "session-bound fixture file\n";
const PUSHED_REF: &str = "refs/heads/main";

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn push_token_bounds_repeated_http_reads() -> Result<()> {
    let db = Db::setup().await?;
    let outcome = case(&db).await;
    db.finish(outcome).await
}

async fn case(db: &Db) -> Result<()> {
    let store = open_store()?;
    let git = Git::new()?;
    let scratch = tempfile::tempdir().context("temporary gateway scratch root")?;
    let owner = actor::owner(&db.pool).await?;
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
        .with_sessions(open_test_tokens(store.backend_identity())?),
    );
    let push = Arc::new(Mutex::new(PushSession::default()));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = observe_push_session(super::router(state.clone()), push.clone());
    let server = ServerGuard::start(listener, app);

    let owner_name = owner.username.clone();
    let name = format!("session-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let created = create_repository(address, &owner, &name).await?;
    ensure!(
        created["owner"].as_str() == Some(owner_name.as_str()) && created["name"].as_str() == Some(name.as_str()),
        "create API returned another repository identity"
    );
    provision_decision_realm(db, &state, &owner, &name).await?;

    // Real native Git over the real Smart HTTP routes.
    let work = tempfile::tempdir().context("temporary Git work tree")?;
    let checkout = work.path().join("clone");
    let url = clone_url(address, &owner_name, &name, &owner_name, &owner.token);
    let cloned = git.clone(work.path(), &url, "clone").await?;
    ensure!(cloned.success, "real Smart HTTP clone of the empty repository failed");
    let oid = git.commit(&checkout, COMMIT_FILE, COMMIT_CONTENT, "session fixture commit").await?;
    let pushed = git.run(&checkout, &["push", "origin", &format!("HEAD:{PUSHED_REF}")]).await?;
    ensure!(pushed.success, "real Smart HTTP push was refused");
    assert_no_compute_views(scratch.path()).await?;

    let pushed_bound = {
        let push = push.lock().unwrap_or_else(PoisonError::into_inner);
        RawSession { token: push.token.clone(), revision: push.revision.clone() }
    }
    .admit()?;

    let base = format!("http://{address}/api/repos/{owner_name}/{name}");
    let client = reqwest::Client::new();

    // 1. refs, presenting the push-issued bound.
    let answer = json_read(&client, &format!("{base}/refs"), &owner.token, Some(&pushed_bound.token)).await?;
    ensure!(
        contains(&answer.body, PUSHED_REF) && contains(&answer.body, &oid),
        "refs body did not contain the pushed ref and OID"
    );
    let refs_bound = answer.session.admit_at_least(&pushed_bound)?;

    // 2. tree at HEAD, presenting the refs bound.
    let answer = json_read(&client, &format!("{base}/tree?oid=HEAD"), &owner.token, Some(&refs_bound.token)).await?;
    ensure!(
        contains(&answer.body, &json_string(COMMIT_FILE)) && contains(&answer.body, &oid),
        "tree body did not contain the pushed commit and file"
    );
    let tree_bound = answer.session.admit_at_least(&refs_bound)?;

    // 3. commits, presenting the tree bound.
    let answer = json_read(&client, &format!("{base}/commits"), &owner.token, Some(&tree_bound.token)).await?;
    ensure!(contains(&answer.body, &oid), "commits body did not contain the pushed commit");
    let commits_bound = answer.session.admit_at_least(&tree_bound)?;

    // 4. Token-free compatibility: no session header is presented at all.
    let answer = json_read(&client, &format!("{base}/refs"), &owner.token, None).await?;
    ensure!(
        contains(&answer.body, PUSHED_REF) && contains(&answer.body, &oid),
        "token-free refs body did not contain the pushed ref and OID"
    );
    // A configured gateway may answer with its own token; if it does, it is
    // still a complete, non-regressing bound against the last presented one.
    drop(answer.session.admit_at_least(&commits_bound)?);

    drop(server);
    Ok(())
}

fn open_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == BlobProvider::S3, "ROOTYARD_BLOB_SERVICE must be s3 for this suite");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

/// The real production token types, opened with one deterministic test-only
/// key bound to the actually opened Blob backend identity.
fn open_test_tokens(backend: &BlobBackendIdentity) -> Result<SessionTokens> {
    // The key lives only in this `Zeroizing` owner and is wiped with it.
    let key = Zeroizing::new(TEST_KEY_BYTES);
    let codec = SessionTokenCodec::new([(TEST_KEY_ID, key)], TEST_KEY_ID, backend, BOUNDED_LIFETIME)
        .map_err(|error| anyhow!("test session codec was refused: {error}"))?;
    Ok(SessionTokens::new(codec))
}

/// The session headers exactly as one response carried them, before admission.
struct RawSession {
    token: Option<String>,
    revision: Option<String>,
}

impl RawSession {
    fn from_headers(headers: &HeaderMap) -> Self {
        Self { token: header_text(headers, SESSION_HEADER), revision: header_text(headers, REVISION_HEADER) }
    }

    /// The first bound: nonempty token, positive revision.
    fn admit(self) -> Result<Bound> {
        let token = nonempty(self.token.as_deref(), "push response carried no session token")?.to_owned();
        let revision = parse_revision(self.revision.as_deref())?;
        Ok(Bound { token, revision })
    }

    /// Admit this response's headers against the bound the read presented:
    /// nonempty token, positive revision, never behind it. The result is the
    /// token the next read presents. The token is never printed.
    fn admit_at_least(self, previous: &Bound) -> Result<Bound> {
        let token = nonempty(self.token.as_deref(), "a read response carried no session token")?.to_owned();
        let revision = parse_revision(self.revision.as_deref())?;
        ensure!(revision >= previous.revision, "a read response revision regressed below its presented bound");
        Ok(Bound { token, revision })
    }
}

/// One admitted session lower bound, presented to the next read.
struct Bound {
    token: String,
    revision: i64,
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    let name = HeaderName::from_static(name);
    headers.get(&name).map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

fn parse_revision(value: Option<&str>) -> Result<i64> {
    let revision = nonempty(value, "a response carried no session revision")?
        .parse::<i64>()
        .map_err(|_| anyhow!("a response carried an unparseable session revision"))?;
    ensure!(revision > 0, "a response carried a non-positive session revision");
    Ok(revision)
}

fn nonempty<'a>(value: Option<&'a str>, message: &'static str) -> Result<&'a str> {
    let value = value.ok_or_else(|| anyhow!(message))?;
    ensure!(!value.is_empty(), "{message}");
    Ok(value)
}

fn contains(body: &str, needle: &str) -> bool {
    body.contains(needle)
}

fn json_string(value: &str) -> String {
    Value::String(value.to_owned()).to_string()
}

struct JsonAnswer {
    body: String,
    session: RawSession,
}

/// One real JSON read over TCP with the owner bearer token, presenting
/// `session` when given, and returning the complete body with the session
/// headers this response carried.
async fn json_read(client: &reqwest::Client, url: &str, bearer: &str, session: Option<&str>) -> Result<JsonAnswer> {
    let mut request = client.get(url).bearer_auth(bearer);
    if let Some(session) = session {
        request = request.header(SESSION_HEADER, session);
    }
    let response = request.send().await.context("real gateway TCP request failed")?;
    let status = response.status();
    let session = RawSession::from_headers(response.headers());
    let bytes = response.bytes().await.context("real gateway response body failed")?;
    ensure!(status.is_success(), "gateway read returned {status}");
    ensure!(!bytes.is_empty(), "gateway read returned an empty body");
    Ok(JsonAnswer { body: String::from_utf8_lossy(&bytes).into_owned(), session })
}

/// The push response's session headers, captured in memory only.
#[derive(Default)]
struct PushSession {
    token: Option<String>,
    revision: Option<String>,
}

impl Drop for PushSession {
    fn drop(&mut self) {
        // Best effort: clear the buffered bearer-equivalent value, never print it.
        if let Some(token) = self.token.as_mut() {
            token.clear();
        }
    }
}

/// Test-only middleware: capture only the push response's session headers into
/// memory. Nothing is logged and no other request is recorded.
fn observe_push_session(router: Router, push: Arc<Mutex<PushSession>>) -> Router {
    router.layer(middleware::from_fn_with_state(push, capture_push_session))
}

async fn capture_push_session(
    State(push): State<Arc<Mutex<PushSession>>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let is_push = request.method() == Method::POST
        && request.uri().path().starts_with("/git/")
        && request.uri().path().ends_with("/git-receive-pack");
    let response = next.run(request).await;
    if is_push {
        let captured = RawSession::from_headers(response.headers());
        let mut slot = push.lock().unwrap_or_else(PoisonError::into_inner);
        *slot = PushSession::default();
        slot.token = captured.token;
        slot.revision = captured.revision;
    }
    response
}

/// Abort-on-drop guard for the real `axum::serve` task.
struct ServerGuard {
    task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

impl ServerGuard {
    fn start(listener: TcpListener, app: Router) -> Self {
        Self { task: tokio::spawn(async move { axum::serve(listener, app).await }) }
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn create_repository(address: SocketAddr, owner: &Actor, name: &str) -> Result<Value> {
    let response = reqwest::Client::new()
        .post(format!("http://{address}/api/repos"))
        .bearer_auth(&owner.token)
        .json(&json!({"name": name, "object_format": "sha1"}))
        .send()
        .await?;
    let status = response.status();
    let body: Value = response.json().await?;
    ensure!(
        status.is_success(),
        "create API returned {status}: {}",
        body["error"].as_str().unwrap_or("<no error body>")
    );
    Ok(body)
}

/// Provision the migration-144 decision realm for the created repository,
/// exactly as `tests/blob_git_gateway.rs` does.
async fn provision_decision_realm(db: &Db, state: &BlobGitState, owner: &Actor, name: &str) -> Result<()> {
    let serving =
        lookup(&db.pool, &owner.identity, &owner.username, name, true, state.store().backend_identity(), deadline())
            .await
            .map_err(|error| anyhow!("serving lookup refused the created repository: {}", error.1))?;
    let gate = serving.gate;
    let expectation = RealmExpectation::new(
        gate.repository_id(),
        gate.tenant_id(),
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )
    .map_err(|error| anyhow!("decision realm expectation refused: {error}"))?;
    let mut client = db.pool.get().await?;
    PgDecisionProtocol
        .provision(&mut client, &expectation, deadline())
        .await
        .map_err(|error| anyhow!("decision realm provisioning refused: {error}"))?;
    Ok(())
}
