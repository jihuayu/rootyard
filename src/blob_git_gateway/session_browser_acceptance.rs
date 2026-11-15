//! Real browser acceptance for the push-bound Blob browser (#174).
//!
//! A sibling of [`super::session_http_acceptance`] and a separate checkpoint:
//! that case drives the production `Router` with an HTTP client; this one runs
//! the compiled standalone service as a child process and executes the actual
//! page script, DOM and network requests in headless Chromium.
//!
//! Run explicitly when PostgreSQL, S3-compatible Blob storage, native Git, a
//! compiled `rootyard` CLI, Playwright Python and Chromium are installed:
//!
//! ```text
//! ROOTYARD_TEST_DATABASE_URL=... ROOTYARD_BLOB_SERVICE=s3 ROOTYARD_BLOB_ENDPOINT=... \
//! ROOTYARD_BLOB_BUCKET=... ROOTYARD_BLOB_REGION=... ROOTYARD_BLOB_ACCESS_KEY_ID=... \
//! ROOTYARD_BLOB_SECRET_ACCESS_KEY=... ROOTYARD_TEST_GIT=/usr/bin/git \
//! ROOTYARD_TEST_CLI_BIN=/evidence/rootyard \
//! cargo test --lib session_browser_acceptance -- --ignored --test-threads=1
//! ```
//!
//! `ROOTYARD_TEST_CLI_BIN` is required. `ROOTYARD_TEST_CHROMIUM` defaults to
//! `/usr/bin/chromium` and fails explicitly when that file is absent;
//! `ROOTYARD_TEST_PLAYWRIGHT_PYTHON` defaults to
//! `/opt/session174-playwright/bin/python3`.
//!
//! The child is the production CLI started the way an operator starts it:
//! `DATABASE_URL` is the isolated schema URL configured in `ROOTYARD_TEST_DATABASE_URL`,
//! `ROOTYARD_BIND` a free loopback port, the configured native Git, a private
//! scratch root and a private production-format session keyring (test-only key
//! id `7`, fixed bytes, lifetime 300). Its environment is rebuilt from the
//! configured Blob/PostgreSQL settings only and `ROOTYARD_DATA_DIR` is removed.
//! stdout and stderr share one private mode-`0600` log file that is never read
//! back or printed.
use std::{path::Path, time::Duration};

use anyhow::{Context, Result, anyhow, ensure};
use serde_json::{Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

mod attest;
mod capture;
mod runner;
mod server;

use crate::{
    blob_store::{BlobBackendIdentity, opendal::BlobStore},
    ref_store::{
        core::decision_commit::{PgDecisionProtocol, RealmExpectation},
        serving::lookup,
    },
};
use capture::{Capture, Fixture, serve_adapter};
use server::{RunRoot, Server, require_executable, required_binary, write_private};

use super::session_http_acceptance::fixtures as support;
use support::{
    actor::{self, Actor},
    db::{Db, deadline},
    git::{Git, clone_url},
};

/// The Playwright script, byte-for-byte, materialized once per run.
const BROWSER_SCRIPT: &str = include_str!("session_browser_acceptance/browser.py");
/// Test-only key id inside the signed frame; it is not secret.
const TEST_KEY_ID: u8 = 7;
/// Fixed test-only key material; never read from the environment.
const TEST_KEY_BYTES: [u8; 32] = [0x5a; 32];
/// Lifetime signed into every frame for this run.
const BOUNDED_LIFETIME: u32 = 300;
/// Bound on each fixture HTTP call and on the whole Chromium run.
const HTTP_SECONDS: u64 = 300;
const BROWSER_SECONDS: u64 = 600;
/// The default Chromium of the browser image; `ROOTYARD_TEST_CHROMIUM`
/// overrides it.
const DEFAULT_CHROMIUM: &str = "/usr/bin/chromium";
/// The Playwright interpreter of the browser image.
const DEFAULT_PLAYWRIGHT: &str = "/opt/session174-playwright/bin/python3";
/// The pushed files and the branch the two real pushes update.
const COMMIT_FILE: &str = "readme.txt";
const SECOND_FILE: &str = "unsafe-name with spaces.txt";
const LAST_TREE_FILE: &str = "z-pad-258.txt";
const LAST_REF: &str = "refs/heads/z-page-54";
const FIRST_COMMIT_SUBJECT: &str = "session browser fixture commit";
const PUSHED_REF: &str = "refs/heads/main";

#[test]
fn fault_page_goto_uses_origin_scope() {
    assert!(BROWSER_SCRIPT.contains("self.goto(fault_page, self.origin + self.scope, "));
    assert!(!BROWSER_SCRIPT.contains("self.web + self.scope"));
}

#[tokio::test]
#[ignore = "requires real PostgreSQL, S3-compatible Blob, native Git, a compiled production CLI, Playwright Python and Chromium"]
async fn standalone_cli_browser_session_is_bound_in_chromium() -> Result<()> {
    let _serial = super::NATIVE_ACCEPTANCE_SERIAL.lock().await;
    let db = Db::setup().await?;
    let outcome = case(&db).await;
    db.finish(outcome).await
}

async fn case(db: &Db) -> Result<()> {
    // Every real dependency is required up front; none is skipped.
    let cli = required_binary("ROOTYARD_TEST_CLI_BIN")?;
    let chromium = chromium_binary()?;
    browser_python()?;
    let store = open_store()?;
    let git = Git::new()?;
    let run = RunRoot::create()?;
    let scratch = run.private_dir("scratch")?;
    write_keyring(&run)?;

    let mut child = Server::spawn(&cli, &git, &scratch, &run)?;
    let outcome = match server::wait_ready(&mut child, &run).await {
        Ok(address) => browse(db, &store, &git, &run, address, &chromium).await,
        Err(error) => Err(error),
    };
    // SIGTERM and the bounded drain run after the case stops touching the
    // schema; the cleanup then drops the owned schema.
    outcome.and(child.stop().await)
}

/// The production keyring layout with test material: schema 2, explicit id
/// `7`, deterministic bytes, private manifest and key files.
fn write_keyring(run: &RunRoot) -> Result<()> {
    let directory = run.private_dir("session-keyring")?;
    let manifest = json!({
        "schema": 2,
        "current": "browser-test",
        "lifetime_seconds": BOUNDED_LIFETIME,
        "keys": [{ "key_id": "browser-test", "id": TEST_KEY_ID }],
    });
    write_private(&directory.join("keyring.json"), &serde_json::to_vec(&manifest)?)?;
    write_private(&directory.join("browser-test.key"), Zeroizing::new(TEST_KEY_BYTES).as_slice())
}

/// The operator's real S3-compatible profile (`ROOTYARD_BLOB_*`).
fn open_store() -> Result<BlobStore> {
    use crate::blob_store::{BlobProvider, config::BlobProfile};
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == BlobProvider::S3, "ROOTYARD_BLOB_SERVICE must be s3 for this suite");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

async fn browse(
    db: &Db,
    store: &BlobStore,
    git: &Git,
    run: &RunRoot,
    address: std::net::SocketAddr,
    chromium: &Path,
) -> Result<()> {
    let mut owner = actor::owner(&db.pool).await?;
    let client = http_client()?;
    for idx in 1..=101 {
        let pad = format!("a-pad-{idx:03}");
        create_repository(&client, address, &owner, &pad).await?;
        provision_decision_realm(db, store.backend_identity(), &owner, &pad).await?;
    }
    let name = format!("browser-{}", &Uuid::new_v4().simple().to_string()[..12]);
    create_repository(&client, address, &owner, &name).await?;
    provision_decision_realm(db, store.backend_identity(), &owner, &name).await?;
    let (oid, live) = push_fixture(db, store.backend_identity(), git, run, address, &owner, &name).await?;

    // The script and its inputs: mode-0600 files inside private directories.
    let script = run.path("browser.py");
    write_private(&script, BROWSER_SCRIPT.as_bytes())?;
    let inputs = run.private_dir("browser-input")?;
    let config_path = inputs.join("config.json");
    let capture = Capture::default();
    let fixture = Fixture {
        owner: owner.username.clone(),
        name: name.clone(),
        oid: oid.clone(),
        file: COMMIT_FILE.to_owned(),
        second_file: SECOND_FILE.to_owned(),
        upstream: format!("http://{address}"),
    };
    let front = serve_adapter(capture.clone(), fixture).await?;
    let config = json!({
        "origin": format!("http://{front}"),
        "username": owner.username,
        "token": owner.token,
        "repo": name,
        "oid": oid,
        "file": COMMIT_FILE,
        "second_file": SECOND_FILE,
        "last_tree_file": LAST_TREE_FILE,
        "last_ref": LAST_REF,
        "first_commit_subject": FIRST_COMMIT_SUBJECT,
        "expected_revision": live,
        "chromium": chromium,
        "python": browser_python()?,
        "profile": run.private_dir("chromium-profile")?,
    });
    let config = Zeroizing::new(serde_json::to_vec(&config)?);
    write_private(&config_path, config.as_slice())?;
    let token = Zeroizing::new(std::mem::take(&mut owner.token));
    drop(owner);
    let summary = runner::run(&script, &config_path, &run.private_file("browser.log")?).await?;
    let recorded = capture.snapshot();
    let chain = attest::summary(&summary, live)?;
    attest::verify(&recorded, &chain, &chain.denials, &summary["list"], &summary["fault"], live)?;
    no_credentials(&summary, token.as_str(), &oid, COMMIT_FILE, &name)
}

/// The summary, URL-bearing fields included, never carries the API token, a
/// session token or the pushed OID. It is the one line the client prints.
fn no_credentials(summary: &Value, token: &str, oid: &str, file: &str, name: &str) -> Result<()> {
    let printed = summary.to_string();
    let credentials = [token, oid, name, file].into_iter().filter(|value| value.len() >= 8);
    for value in credentials {
        ensure!(!printed.contains(value), "the browser summary carried a credential, URL or fixture value");
    }
    Ok(())
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_SECONDS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("HTTP fixture client could not be built")
}

async fn create_repository(
    client: &reqwest::Client,
    address: std::net::SocketAddr,
    owner: &Actor,
    name: &str,
) -> Result<()> {
    let response = client
        .post(format!("http://{address}/api/repos"))
        .bearer_auth(&owner.token)
        .json(&json!({"name": name, "object_format": "sha1"}))
        .send()
        .await
        .context("create API request failed")?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    ensure!(status.is_success(), "create API returned {status}: {}", body["error"].as_str().unwrap_or("<none>"));
    ensure!(
        body["owner"].as_str() == Some(owner.username.as_str()) && body["name"].as_str() == Some(name),
        "create API returned another repository identity"
    );
    Ok(())
}

/// The typed migration-144 realm fixture: the production `lookup` states the
/// realm of the created repository and `PgDecisionProtocol::provision` applies
/// exactly that expectation. No realm or terminal row is written by SQL.
async fn provision_decision_realm(db: &Db, backend: &BlobBackendIdentity, owner: &Actor, name: &str) -> Result<()> {
    let live = lookup(&db.pool, &owner.identity, &owner.username, name, true, backend, deadline())
        .await
        .map_err(|error| anyhow!("serving lookup refused the created repository: {}", error.1))?;
    let expectation = RealmExpectation::from_gate(&live.gate);
    let mut client = db.pool.get().await?;
    PgDecisionProtocol
        .provision(&mut client, &expectation, deadline())
        .await
        .map_err(|error| anyhow!("decision realm provisioning refused: {error}"))?;
    Ok(())
}

/// A real clone and bounded real pushes through the child's Smart HTTP routes,
/// returning the pushed OID and the live gate revision after them.
async fn push_fixture(
    db: &Db,
    backend: &BlobBackendIdentity,
    git: &Git,
    run: &RunRoot,
    address: std::net::SocketAddr,
    owner: &Actor,
    name: &str,
) -> Result<(String, i64)> {
    let work = run.private_dir("git-work")?;
    let checkout = work.join("clone");
    let url = Zeroizing::new(clone_url(address, &owner.username, name, &owner.username, &owner.token));
    let cloned = git.clone(&work, url.as_str(), "clone").await?;
    ensure!(cloned.success, "real Smart HTTP clone through the CLI child failed");
    let branch = format!("HEAD:{PUSHED_REF}");
    git.commit(&checkout, COMMIT_FILE, "session browser fixture file\n", FIRST_COMMIT_SUBJECT).await?;
    git.ok(&checkout, &["branch", "-M", "main"]).await?;
    let first = git.run(&checkout, &["push", "--quiet", "origin", &branch]).await?;
    ensure!(first.success, "the first real push through the CLI child was refused");
    let first_revision = live_revision(db, backend, owner, name).await?;
    for idx in 1..=258 {
        git.ok(&checkout, &["commit", "--quiet", "--allow-empty", "-m", &format!("history pad {idx:03}")]).await?;
    }
    for idx in 1..=258 {
        std::fs::write(checkout.join(format!("z-pad-{idx:03}.txt")), "pad\n")?;
    }
    std::fs::write(checkout.join(SECOND_FILE), "second fixture file\n")?;
    git.ok(&checkout, &["add", "."]).await?;
    git.ok(&checkout, &["commit", "--quiet", "-m", "session browser advance"]).await?;
    let oid = git.text(&checkout, &["rev-parse", "HEAD"]).await?;
    for idx in 1..=54 {
        git.ok(&checkout, &["branch", &format!("z-page-{idx:02}")]).await?;
    }
    let second = git.run(&checkout, &["push", "--quiet", "origin", &branch]).await?;
    ensure!(second.success, "the second real push through the CLI child was refused");
    let page_refs: Vec<String> = (1..=54).map(|idx| format!("refs/heads/z-page-{idx:02}")).collect();
    // Each push stays well below the 64 KiB worst-case PackCommitTerminal budget (<= 52 refs).
    for chunk in page_refs.chunks(27) {
        let mut args = vec!["push", "--quiet", "origin"];
        args.extend(chunk.iter().map(String::as_str));
        let batch = git.run(&checkout, &args).await?;
        ensure!(batch.success, "paginated branch push through the CLI child was refused");
    }
    ensure!(git.text(&checkout, &["rev-parse", "HEAD"]).await? == oid, "the pushed commit is not the local HEAD");
    let live = live_revision(db, backend, owner, name).await?;
    ensure!(first_revision > 0 && live > first_revision && live > 1, "the live gate revision did not advance");
    Ok((oid, live))
}

async fn live_revision(db: &Db, backend: &BlobBackendIdentity, owner: &Actor, name: &str) -> Result<i64> {
    let live = lookup(&db.pool, &owner.identity, &owner.username, name, true, backend, deadline())
        .await
        .map_err(|error| anyhow!("serving lookup refused the repository revision check: {}", error.1))?;
    Ok(live.gate.revision())
}

fn chromium_binary() -> Result<std::path::PathBuf> {
    let path = std::env::var_os("ROOTYARD_TEST_CHROMIUM")
        .map_or_else(|| std::path::PathBuf::from(DEFAULT_CHROMIUM), std::path::PathBuf::from);
    ensure!(path.is_absolute(), "ROOTYARD_TEST_CHROMIUM must be an absolute path");
    require_executable(&path, "ROOTYARD_TEST_CHROMIUM (default /usr/bin/chromium)")
}

fn browser_python() -> Result<std::path::PathBuf> {
    let path = std::env::var_os("ROOTYARD_TEST_PLAYWRIGHT_PYTHON")
        .map_or_else(|| std::path::PathBuf::from(DEFAULT_PLAYWRIGHT), std::path::PathBuf::from);
    require_executable(&path, "the Playwright Python interpreter")
}
