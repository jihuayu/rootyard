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
//! request still succeeds.
//!
//! Refusals over the same real routes, never through handler calls:
//!
//! * a malformed `x-rootyard-session` from the owner is an explicit `400`;
//! * a live foreign actor (`support::actor::stranger`) sending malformed and no
//!   session header to the owner's repository gets the same refusal and body,
//!   so actor/repository authorization runs before any version-token error;
//! * a correctly MACed lower bound `live_revision + 1` minted through the
//!   crate-private test-only `SessionRealm::new` + `SessionTokens::issue_for_test`
//!   for a fresh authorized `serving::lookup` realm is the generic `503`
//!   `BEHIND_MESSAGE`.
//!
//! Every refusal body is checked against the pushed OID/ref so it discloses
//! neither repository content nor another repository's details.
//!
//! Task 2 browser read integration (read-only; no browser-initiated writes):
//!
//! * a real `POST /web/login` API-token exchange with the exact same-origin
//!   `Origin`; its `Set-Cookie` values are retained privately in a cookie jar;
//! * `GET /web/blob` and the new `GET /web/blob/repos/{owner}/{name}` page load
//!   with that cookie, and their HTML must carry no API token, cookie value or
//!   session value;
//! * the `/web/blob/api/...` read aliases, with only the browser cookie plus the
//!   actual session token/revision captured from the real Git push, return the
//!   pushed ref + OID (`/refs`), the pushed commit and `COMMIT_FILE`
//!   (`/tree?oid=HEAD`), the pushed OID (`/commits`) and the pushed ref + OID
//!   again (last `/refs`), each with a complete non-regressing pair that the
//!   next read chains;
//! * the same browser cookie sent to the unchanged ordinary `/api/.../refs`
//!   route is still denied, so cookie authentication was not enabled globally.
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
    http::{HeaderMap, Method, Request, header},
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

use super::{
    BlobGitConfig, BlobGitState,
    repo_session::{BEHIND_MESSAGE, SessionRealm, SessionTokenCodec, SessionTokens},
};
use crate::{
    blob_store::{BlobBackendIdentity, BlobProvider, config::BlobProfile, opendal::BlobStore},
    ref_store::{
        core::decision_commit::{PgDecisionProtocol, RealmExpectation},
        serving::lookup,
    },
};
use anyhow::{Context, Result, anyhow, ensure};
use serde_json::{Value, json};

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
/// A syntactically invalid session header value: never a framed token.
const MALFORMED_SESSION: &str = "not-a-session-token";

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob and Git"]
async fn push_token_bounds_repeated_http_reads() -> Result<()> {
    let db = Db::setup().await?;
    let outcome = case(&db).await;
    db.finish(outcome).await
}

async fn case(db: &Db) -> Result<()> {
    let store = open_store()?;
    let tokens = open_test_tokens(store.backend_identity())?;
    let git = Git::new()?;
    let scratch = tempfile::tempdir().context("temporary gateway scratch root")?;
    let owner = actor::owner(&db.pool).await?;
    // A live real actor with no role on the owner's repository.
    let stranger = actor::stranger(&db.pool).await?;
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
        .with_sessions(tokens.clone()),
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

    let secrets = [oid.as_str(), PUSHED_REF];

    // 5. The authorized owner's malformed session header is an explicit 400.
    let malformed = raw_get(&client, &format!("{base}/refs"), &owner.token, Some(MALFORMED_SESSION)).await?;
    ensure!(malformed.status == 400, "malformed session header was not refused with 400");
    ensure!(!malformed.body.is_empty(), "malformed session refusal carried no body");
    ensure_no_disclosure(&malformed.body, &secrets, "malformed session refusal")?;

    // 6. The live foreign actor is refused identically with a malformed and no
    // session header: actor/repository authorization precedes token errors.
    let foreign = format!("http://{address}/api/repos/{owner_name}/{name}/refs");
    let mut denied = Vec::new();
    for session in [Some(MALFORMED_SESSION), None] {
        let answer = raw_get(&client, &foreign, &stranger.token, session).await?;
        ensure!(!status_succeeds(answer.status), "foreign actor was not denied on the owner's repository");
        ensure!(is_denial(answer.status), "foreign actor denial was not an authorization refusal");
        ensure!(!answer.body.is_empty(), "foreign actor denial carried no body");
        ensure!(!looks_like_refs(&answer.body), "foreign actor denial looked like a successful refs answer");
        ensure_no_disclosure(&answer.body, &secrets, "foreign actor denial")?;
        ensure_no_disclosure(
            &answer.body,
            &[stranger.username.as_str(), owner.username.as_str()],
            "foreign actor denial",
        )?;
        denied.push(answer);
    }
    ensure!(denied[0].status == denied[1].status, "foreign actor denial status depended on the session header");
    ensure!(denied[0].body == denied[1].body, "foreign actor denial body depended on the session header");

    // 7. A correctly MACed lower bound one past the live revision, minted for
    // the exact realm a fresh authorized lookup states, is the generic 503.
    let live =
        lookup(&db.pool, &owner.identity, &owner.username, &name, true, state.store().backend_identity(), deadline())
            .await
            .map_err(|error| anyhow!("authorized serving lookup refused: {}", error.1))?;
    let gate = &live.gate;
    let realm = SessionRealm::new(
        gate.tenant_id(),
        gate.repository_id(),
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
        live.cluster_incarnation,
    )
    .map_err(|_| anyhow!("live session realm refused"))?;
    let future_revision = gate.revision().checked_add(1).context("live gate revision overflow")?;
    let future =
        tokens.issue_for_test(&realm, future_revision).map_err(|_| anyhow!("future-bound session issue refused"))?;
    let ahead = raw_get(&client, &format!("{base}/refs"), &owner.token, Some(future.token())).await?;
    ensure!(ahead.status == 503, "future session bound was not refused with 503");
    ensure!(contains(&ahead.body, BEHIND_MESSAGE), "future session refusal did not carry BEHIND_MESSAGE");
    ensure!(!looks_like_refs(&ahead.body), "future session refusal looked like a successful refs answer");
    ensure_no_disclosure(&ahead.body, &secrets, "future session refusal")?;

    // 8. Browser read integration (read-only). A real API-token exchange mints
    // the HttpOnly browser session; its cookies stay in this jar, never printed.
    let login = browser_login(address, &owner).await?;
    let cookie = browser_cookie_header(&login)?;
    let origin = format!("http://{address}");
    for path in ["/web/blob".to_owned(), format!("/web/blob/repos/{owner_name}/{name}")] {
        browser_page(&client, &origin, &path, &cookie, &login).await?;
    }

    // The index alias lists the authorized repository through the browser cookie
    // (the list handler issues no session, so only its JSON is asserted).
    let answer = browser_get(&client, &format!("{origin}/web/blob/api/repos"), &cookie, None).await?;
    ensure!(status_succeeds(answer.status), "the Web repository list alias was refused");
    ensure!(
        contains(&answer.body, &name) && !looks_like_refs(&answer.body),
        "the Web repository list did not contain the repository"
    );

    // Each detail read presents the bound of the previous answer, starting from
    // the real push's; every answer must carry the endpoint's pushed content and
    // a complete pair that never regresses below the presented one.
    let mut presented = pushed_bound;
    let mut browser_revisions = Vec::new();
    for (path, expected) in [
        ("refs", [Some(PUSHED_REF), Some(oid.as_str())]),
        ("tree?oid=HEAD", [Some(&*json_string(COMMIT_FILE)), Some(oid.as_str())]),
        ("commits", [None, Some(oid.as_str())]),
        ("refs", [Some(PUSHED_REF), Some(oid.as_str())]),
    ] {
        let url = web_scope(&origin, &owner_name, &name, path);
        let answer = browser_get(&client, &url, &cookie, Some(&presented.token)).await?;
        ensure!(status_succeeds(answer.status), "a Web Blob read alias was refused");
        for needle in expected.into_iter().flatten() {
            ensure!(contains(&answer.body, needle), "a Web Blob read alias did not return its expected content");
        }
        if path == "tree?oid=HEAD" {
            ensure!(
                !contains(&answer.body, PUSHED_REF),
                "the tree alias returned a ref name instead of the commit and file"
            );
        }
        ensure_no_disclosure(&answer.body, &[cookie.as_str()], "Web Blob read alias")?;
        let raw = RawSession { token: answer.session.token, revision: answer.session.revision };
        presented = raw.admit_at_least(&presented)?;
        browser_revisions.push(presented.revision);
    }
    ensure!(
        browser_revisions.windows(2).all(|pair| pair[1] >= pair[0]),
        "successive Web reads regressed their session revision"
    );

    // Outside this session, that same browser cookie on the unchanged ordinary
    // `/api/.../refs` route is still denied: no global cookie authentication.
    let ordinary = client.get(format!("{base}/refs")).header(header::COOKIE, cookie.clone()).send().await?;
    let status = ordinary.status().as_u16();
    let body = String::from_utf8_lossy(&ordinary.bytes().await?).into_owned();
    ensure!(!status_succeeds(status), "the browser cookie authenticated the ordinary /api route");
    ensure!(is_denial(status), "the ordinary /api route did not deny the browser cookie");
    ensure!(!looks_like_refs(&body), "the ordinary /api denial looked like a successful refs answer");
    ensure_no_disclosure(&body, &secrets, "ordinary /api cookie denial")?;

    drop(server);
    Ok(())
}

/// One browser sign-in exchange: only the two named cookies, in a private jar.
///
/// The values are never formatted, logged or echoed; a failed sign-in yields a
/// generic error.
struct BrowserLogin {
    session: String,
    csrf: String,
}

impl Drop for BrowserLogin {
    fn drop(&mut self) {
        self.session.clear();
        self.csrf.clear();
    }
}

/// The private `Cookie` request header value built from the jar.
fn browser_cookie_header(login: &BrowserLogin) -> Result<String> {
    ensure!(!login.session.is_empty() && !login.csrf.is_empty(), "browser session cookies are incomplete");
    Ok(format!("rootyard_session={}; rootyard_csrf={}", login.session, login.csrf))
}

/// Sign in over the real `POST /web/login` with the owner's real API token and
/// the exact same-origin `Origin`, keeping only `rootyard_session` and
/// `rootyard_csrf` from the `303` response. Redirects are disabled so that the
/// one exchange, its status and its `Set-Cookie` values are inspected directly.
async fn browser_login(address: SocketAddr, owner: &Actor) -> Result<BrowserLogin> {
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("browser sign-in client could not be built")?;
    let response = client
        .post(format!("{origin}/web/login"))
        .header(header::ORIGIN, origin.as_str())
        // `serde_json::to_string` of strings is exactly the form-urlencoded
        // percent encoding; the body is built without the client's `form`
        // feature and is never printed.
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(login_form(&owner.username, &owner.token))
        .send()
        .await
        .context("browser sign-in request failed")?;
    ensure!(response.status().as_u16() == 303, "browser sign-in did not answer with 303");
    let mut login = BrowserLogin { session: String::new(), csrf: String::new() };
    for value in response.headers().get_all(header::SET_COOKIE) {
        // `to_str` fails rather than echo a non-text cookie value.
        let Ok(raw) = value.to_str() else { continue };
        let (pair, _) = raw.split_once(';').unwrap_or((raw, ""));
        let Some((name, value)) = pair.trim().split_once('=') else { continue };
        match name {
            "rootyard_session" => login.session = value.to_owned(),
            "rootyard_csrf" => login.csrf = value.to_owned(),
            _ => {}
        }
    }
    ensure!(!login.session.is_empty(), "browser sign-in did not set the session cookie");
    ensure!(!login.csrf.is_empty(), "browser sign-in did not set the CSRF cookie");
    ensure!(
        login.session != owner.token && !login.session.contains(&owner.token),
        "browser session embedded the API token"
    );
    Ok(login)
}

/// The url-encoded sign-in form of one username and API token.
fn login_form(username: &str, token: &str) -> String {
    let field = |value: &str| serde_json::to_string(value).unwrap_or_default();
    format!("username={}&token={}&return_to={}", field(username), field(token), field("/web/blob"))
}

/// One signed-in page load: `200`, HTML, and none of the credentials in it.
async fn browser_page(
    client: &reqwest::Client,
    origin: &str,
    path: &str,
    cookie: &str,
    login: &BrowserLogin,
) -> Result<()> {
    let response = client
        .get(format!("{origin}{path}"))
        .header(header::COOKIE, cookie)
        .header(header::ACCEPT, "text/html")
        .header("sec-fetch-mode", "navigate")
        .send()
        .await
        .context("browser page request failed")?;
    ensure!(status_succeeds(response.status().as_u16()), "a signed-in browser page was not served");
    let body = String::from_utf8_lossy(&response.bytes().await?).into_owned();
    ensure!(body.contains("</html>"), "a signed-in browser page was not HTML");
    for secret in [&login.session, &login.csrf] {
        ensure!(!secret.is_empty() && !body.contains(secret), "a browser page carried a credential");
    }
    Ok(())
}

/// One same-origin browser read with only the cookie and an optional session
/// header. Redirects are disabled so a refused navigation cannot hide behind a
/// login page.
async fn browser_get(
    client: &reqwest::Client,
    url: &str,
    cookie: &str,
    session: Option<&str>,
) -> Result<RawAnswer> {
    let mut request = client.get(url).header(header::COOKIE, cookie);
    if let Some(session) = session {
        request = request.header(SESSION_HEADER, session);
    }
    let response = request.send().await.context("Web Blob browser read failed")?;
    let status = response.status().as_u16();
    let session = RawSession::from_headers(response.headers());
    let bytes = response.bytes().await.context("Web Blob browser read body failed")?;
    Ok(RawAnswer { status, body: String::from_utf8_lossy(&bytes).into_owned(), session })
}

/// One read alias URL of the browser subtree for a repository.
fn web_scope(origin: &str, owner: &str, name: &str, tail: &str) -> String {
    format!("{origin}/web/blob/api/repos/{owner}/{name}/{tail}")
}

fn is_denial(status: u16) -> bool {
    matches!(status, 401 | 403 | 404)
}

fn status_succeeds(status: u16) -> bool {
    (200..300).contains(&status)
}

/// A body of a successful refs answer names refs; a refusal body must not.
fn looks_like_refs(body: &str) -> bool {
    body.contains("refs/") || body.contains("\"refs\"")
}

fn ensure_no_disclosure(body: &str, needles: &[&str], what: &str) -> Result<()> {
    for needle in needles {
        ensure!(!needle.is_empty() && !contains(body, needle), "{what} disclosed a repository or actor detail");
    }
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
        .map_err(|_| anyhow!("test session codec was refused"))?;
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
    headers.get(name).map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
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

/// One real GET's raw answer: status code, complete body and the session
/// headers it carried, whether or not it succeeded.
struct RawAnswer {
    status: u16,
    body: String,
    session: RawSession,
}

/// One real GET over TCP with the bearer token of `bearer`, presenting
/// `session` as the session header when given (even a malformed value).
async fn raw_get(client: &reqwest::Client, url: &str, bearer: &str, session: Option<&str>) -> Result<RawAnswer> {
    // The bearer and the session header are sent as header values only, never
    // in the URL, and are never printed here.
    let mut request = client.get(url).bearer_auth(bearer);
    if let Some(session) = session {
        request = request.header(SESSION_HEADER, session);
    }
    let response = request.send().await.context("real gateway TCP request failed")?;
    let status = response.status().as_u16();
    let session = RawSession::from_headers(response.headers());
    let bytes = response.bytes().await.context("real gateway response body failed")?;
    Ok(RawAnswer { status, body: String::from_utf8_lossy(&bytes).into_owned(), session })
}

/// One successful real JSON read with the bearer token, presenting `session`
/// when given, returning the complete body with the session headers.
async fn json_read(client: &reqwest::Client, url: &str, bearer: &str, session: Option<&str>) -> Result<JsonAnswer> {
    let RawAnswer { status, body, session } = raw_get(client, url, bearer, session).await?;
    ensure!(status_succeeds(status), "gateway read returned {status}");
    ensure!(!body.is_empty(), "gateway read returned an empty body");
    Ok(JsonAnswer { body, session })
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
