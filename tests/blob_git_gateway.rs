//! Real end-to-end acceptance for the Blob-only Git gateway.
//!
//! Run explicitly by Root (every case is `#[ignore]` and hard-fails on a
//! missing service, binary, Git or Blob profile):
//!
//! ```text
//! # the operator's real profile provides ROOTYARD_TEST_DATABASE_URL and the
//! # ROOTYARD_BLOB_* S3 profile; the suite itself pins one fresh schema selector
//! # and one fresh relative Blob prefix for the whole run.
//! ROOTYARD_TEST_GIT=/absolute/git \
//! ROOTYARD_SERVING_BINARY=/absolute/rootyard \
//! cargo test --locked --no-default-features --test blob_git_gateway -- --ignored --test-threads=1
//! ```
//!
//! The first case uses the in-process gateway router (real create API, real
//! Smart HTTP clone/push through the real receive pipeline, PostgreSQL + Blob
//! re-clone, stale-CAS push). The issue-126 protocol cases run the already built
//! `serve-blob` binary exactly as the `standalone` entrypoint configures it,
//! with real stock Git clients behind a bounded loopback proxy:
//!
//! 1. two stock clients that advertised the same `refs/heads/main` old OID push
//!    concurrently; exactly one wins and the other reads the parsed
//!    `ng refs/heads/main stale info` report;
//! 2. a stock push whose committed receive-pack ACK is lost on the wire: the
//!    client sees a transport failure, its operation is terminal `committed`,
//!    the durable ref names its commit and the fresh clone reads it back;
//! 3. one real `git push --atomic` of two refs: stock Git's own local atomic
//!    preflight passes with the normally advertised old OIDs, then the proxy
//!    rewrites only the old OID of the `refs/heads/side` command after the client
//!    formed its POST and forwards that single mutated request; the service
//!    refuses both refs with parsed report-status lines and neither durable ref
//!    nor the gate revision moves.
//!
//! TODO(Root, honest): schema/source-binding negative cases (a second schema
//! naming the same repository UUID, or a foreign physical Blob backend) are not
//! fabricated here; they require the real A3/A4 fixtures already qualified by
//! `ref_store_packs`/`ref_store_materialized_reads` and Root's runner.
mod blob_gateway_support;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use blob_gateway_support::{
    actor::{self, Actor},
    blob,
    db::{Db, deadline},
    git::{Git, Output as GitOutput, assert_no_compute_views, clone_url},
    proxy::{self, Proxy},
    service::Service,
};
use rootyard::blob_git_gateway::{BlobGitConfig, BlobGitState, router};
use rootyard::blob_store::BlobBackendIdentity;
use rootyard::ref_store::{
    IssuerLane, OperationIdentity, PgRefStore, PgRefStoreCore, RequestDigest, VersionCheck,
    core::decision_commit::{PgDecisionProtocol, RealmExpectation},
    serving::lookup,
};
use serde_json::{Value, json};

use tokio::{net::TcpListener, sync::OnceCell};
use uuid::Uuid;

fn open_store() -> Result<rootyard::blob_store::opendal::BlobStore> {
    blob::open_store()
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git, a built serve-blob binary and stock clients"]
async fn concurrent_same_tip_pushes_get_parsed_ng_stale_info() -> Result<()> {
    let node = node().await?;
    let git: &'static Git = Box::leak(Box::new(Git::new()?));
    let owner = actor::owner(&node.db.pool).await?;
    let case = Case::new(node, owner, "race-stale").await?;
    let result = race_case(&case, git).await;
    let value = case.finish(result).await?;
    println!("race-stale: {}", serde_json::to_string(&value)?);
    Ok(())
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git"]
async fn smart_http_push_then_reclone_without_compute_views_has_exact_oid() -> Result<()> {
    let db = Db::setup().await?;
    let outcome = case(&db).await;
    db.finish(outcome).await
}

async fn case(db: &Db) -> Result<()> {
    let store = open_store()?;
    let git = Git::new()?;
    let scratch = tempfile::tempdir()?;
    let owner = actor::owner(&db.pool).await?;
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
        .map_err(|error| anyhow!("gateway configuration was refused: {error}"))?,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    let name = "blob-repo";
    let created = create_repository(address, &owner, name).await?;
    ensure!(
        created["owner"].as_str() == Some(owner.username.as_str()) && created["name"].as_str() == Some(name),
        "create API returned another repository identity"
    );
    provision_decision_realm(db, &state, &owner, name).await?;

    let work = tempfile::tempdir()?;
    let url = clone_url(address, &owner.username, name, &owner.username, &owner.token);
    let first_clone = work.path().join("clone1");
    let output = git.clone(work.path(), &url, "clone1").await?;
    ensure!(
        output.success,
        "real Smart HTTP clone of the empty repository failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );

    let first = git.commit(&first_clone, "a.txt", "first fixture file\n", "first fixture commit").await?;
    let pushed = git.ok(&first_clone, &["push", "origin", "HEAD:refs/heads/main"]).await;
    pushed.with_context(|| "real Smart HTTP push of the first commit was refused")?;
    assert_no_compute_views(scratch.path()).await?;

    // Second clone comes only from PostgreSQL metadata + Blob bytes.
    let second_clone = work.path().join("clone2");
    let output = git.clone(work.path(), &url, "clone2").await?;
    ensure!(
        output.success,
        "second clone failed after deleting every compute view: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    git.ok(&second_clone, &["fsck", "--strict"]).await?;
    let observed = git.text(&second_clone, &["rev-parse", "refs/remotes/origin/main"]).await?;
    ensure!(observed == first, "second clone observed {observed}, expected the pushed {first}");
    let checked_out = git.text(&second_clone, &["rev-parse", "HEAD"]).await?;
    ensure!(checked_out == first, "second clone did not check out the pushed commit (HEAD {checked_out})");

    let second = git.commit(&second_clone, "b.txt", "second fixture file\n", "second fixture commit").await?;
    git.ok(&second_clone, &["push", "origin", "HEAD:refs/heads/main"]).await?;
    assert_no_compute_views(scratch.path()).await?;

    // Real authoritative old-tip CAS: clone1 still believes main is `first`.
    let stale = git.commit(&first_clone, "c.txt", "stale fixture file\n", "stale fixture commit").await?;
    let refused = git.run(&first_clone, &["push", "origin", "HEAD:refs/heads/main"]).await?;
    ensure!(!refused.success, "a stale-CAS push unexpectedly succeeded ({stale})");
    let refusal = format!("{}{}", String::from_utf8_lossy(&refused.stdout), String::from_utf8_lossy(&refused.stderr));
    ensure!(
        refusal.contains("stale") || refusal.contains("rejected") || refusal.contains("non-fast-forward"),
        "stale-CAS refusal was not a parseable Git report: {refusal}"
    );
    assert_no_compute_views(scratch.path()).await?;

    // Wrong token / unknown user must not clone another actor's repository.
    let denied = git
        .clone(work.path(), &clone_url(address, &owner.username, name, &stranger.username, &stranger.token), "denied")
        .await?;
    ensure!(!denied.success, "a foreign token cloned the repository");

    // Third clone proves the failed stale push and the failed auth changed
    // nothing durable.
    let third_clone = work.path().join("clone3");
    let output = git.clone(work.path(), &url, "clone3").await?;
    ensure!(output.success, "third clone failed: {}", String::from_utf8_lossy(&output.stderr).trim());
    git.ok(&third_clone, &["fsck", "--strict"]).await?;
    let observed = git.text(&third_clone, &["rev-parse", "refs/remotes/origin/main"]).await?;
    ensure!(observed == second, "third clone observed {observed}, expected {second}");
    assert_no_compute_views(scratch.path()).await?;

    // Read-only observations of the durable core; never an ACK substitute.
    let repository_id: Uuid = db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT r.id FROM repositories r JOIN namespaces ns ON ns.id=r.owner_id WHERE ns.slug=$1 AND r.name=$2",
            &[&owner.username, &name],
        )
        .await?
        .get(0);
    let stored: String = db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT oid FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name='refs/heads/main'",
            &[&repository_id],
        )
        .await?
        .get(0);
    ensure!(stored == second, "durable refs/heads/main is {stored}, expected {second}");
    let memberships: i64 = db
        .pool
        .get()
        .await?
        .query_one("SELECT count(*) FROM ref_store_core_pack_memberships WHERE repository_id=$1", &[&repository_id])
        .await?
        .get(0);
    ensure!(memberships >= 1, "no durable pack membership was registered");
    let committed: i64 = db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT count(*) FROM ref_store_operations WHERE repository_id=$1 AND state='committed'",
            &[&repository_id],
        )
        .await?
        .get(0);
    ensure!(committed >= 2, "successful pushes did not leave committed operation rows");

    server.abort();
    Ok(())
}

async fn create_repository(address: std::net::SocketAddr, owner: &Actor, name: &str) -> Result<serde_json::Value> {
    let response = reqwest::Client::new()
        .post(format!("http://{address}/api/repos"))
        .bearer_auth(&owner.token)
        .json(&json!({"name": name, "object_format": "sha1"}))
        .send()
        .await?;
    let status = response.status();
    let body: serde_json::Value = response.json().await?;
    ensure!(
        status.is_success(),
        "create API returned {status}: {}",
        body["error"].as_str().unwrap_or("<no error body>")
    );
    Ok(body)
}

/// Provision the migration-144 decision realm for the created repository. The
/// shared serving worker is expected to do this at create time; the fixture
/// calls the idempotent provision API explicitly so the push path is testable
/// even before that wiring lands.
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
    )?;
    let mut client = db.pool.get().await?;
    PgDecisionProtocol
        .provision(&mut client, &expectation, deadline())
        .await
        .map_err(|error| anyhow!("decision realm provisioning refused: {error}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers for the issue-126 protocol cases.
//
// Every case owns its repository, actors, Git work trees, proxy and temp
// directory. The only shared state is one already built `serve-blob` process
// and one disposable PostgreSQL schema, because a per-case process start-up
// costs more than the whole suite. Nothing here builds or patches the binary.
// ---------------------------------------------------------------------------

struct Node {
    db: Db,
    service: Service,
}

async fn node() -> Result<&'static Node> {
    static NODE: OnceCell<Result<Node>> = OnceCell::const_new();
    let node = NODE
        .get_or_init(|| async {
            let binary = std::env::var("ROOTYARD_SERVING_BINARY")
                .map_err(|_| anyhow!("ROOTYARD_SERVING_BINARY must name the already built rootyard binary"))?;
            let binary = std::path::PathBuf::from(binary);
            ensure!(binary.is_absolute(), "ROOTYARD_SERVING_BINARY must be absolute");
            let db = Db::setup().await?;
            match Service::launch(&binary).await {
                Ok(service) => Ok(Node { db, service }),
                Err(error) => {
                    // The schema is run-owned and the failure is reported with
                    // its cause; the clean-up itself must not mask that cause.
                    let note = match db.teardown().await {
                        Ok(()) => format!("clean-up: schema {} dropped", db.schema()),
                        Err(cleanup) => format!("clean-up: schema {} could not be dropped: {cleanup:#}", db.schema()),
                    };
                    Err(error.context(note))
                }
            }
        })
        .await;
    node.as_ref().map_err(|error| anyhow!("{error:#}"))
}

struct Case {
    db: &'static Db,
    service: &'static Service,
    owner: Actor,
    name: &'static str,
    repository: Uuid,
    work: tempfile::TempDir,
    proxy: Proxy,
}

impl Case {
    async fn new(node: &'static Node, owner: Actor, name: &'static str) -> Result<Self> {
        let repository = node.service.create_repository(&owner, name).await?;
        node.service.provision_decision_realm(&node.db, &owner, name).await?;
        let proxy = Proxy::start(node.service.address, proxy::Limits::default()).await?;
        Ok(Self { db: &node.db, service: &node.service, owner, name, repository, work: tempfile::tempdir()?, proxy })
    }

    fn path(&self, suffix: &str) -> String {
        format!("/api/repos/{}/{}{suffix}", self.owner.username, self.name)
    }

    async fn gate_revision(&self) -> Result<i64> {
        Ok(self
            .db
            .pool
            .get()
            .await?
            .query_one("SELECT revision FROM ref_store_core_gates WHERE repository_id=$1", &[&self.repository])
            .await?
            .get(0))
    }

    async fn durable_refs(&self) -> Result<std::collections::BTreeMap<String, String>> {
        let rows = self
            .db
            .pool
            .get()
            .await?
            .query(
                "SELECT ref_name, oid FROM ref_store_core_refs WHERE repository_id=$1 ORDER BY ref_name",
                &[&self.repository],
            )
            .await?;
        Ok(rows.into_iter().map(|row| (row.get(0), row.get(1))).collect())
    }

    /// `(state, terminal value)`; read-only observation of the durable registry.
    async fn operation_row(&self, operation: Uuid) -> Result<Option<(String, Option<Value>)>> {
        let row = self
            .db
            .pool
            .get()
            .await?
            .query_opt(
                "SELECT state, terminal_result FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2",
                &[&self.repository, &operation],
            )
            .await?;
        Ok(row.map(|row| (row.get(0), row.get(1))))
    }

    /// Fresh stock clone through the proxy, over the protocol the case needs;
    /// returns its path and the OID it read for `refs/remotes/origin/main`.
    async fn clone_protocol(
        &self,
        git: &Git,
        destination: &str,
        protocol: &str,
    ) -> Result<(std::path::PathBuf, String)> {
        let url = self.proxy.url(&self.owner, self.name);
        let output = git
            .run(self.work.path(), &["-c", &format!("protocol.version={protocol}"), "clone", &url, destination])
            .await?;
        ensure!(
            output.success,
            "stock Git {protocol} clone failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let path = self.work.path().join(destination);
        let main = git.text(&path, &["rev-parse", "refs/remotes/origin/main"]).await?;
        git.ok(&path, &["fsck", "--strict"]).await?;
        Ok((path, main))
    }

    async fn clone(&self, git: &Git, destination: &str) -> Result<(std::path::PathBuf, String)> {
        let url = self.proxy.url(&self.owner, self.name);
        let output = git.clone(self.work.path(), &url, destination).await?;
        ensure!(output.success, "stock Git clone failed: {}", String::from_utf8_lossy(&output.stderr).trim());
        let path = self.work.path().join(destination);
        let main = git.text(&path, &["rev-parse", "refs/remotes/origin/main"]).await?;
        git.ok(&path, &["fsck", "--strict"]).await?;
        Ok((path, main))
    }

    /// Initial clone of the still-empty repository; there is no
    /// `refs/remotes/origin/main` yet, so no remote branch is resolved.
    async fn clone_seed(&self, git: &Git, destination: &str, protocol: Option<&str>) -> Result<std::path::PathBuf> {
        let url = self.proxy.url(&self.owner, self.name);
        let output = match protocol {
            None => git.clone(self.work.path(), &url, destination).await?,
            Some(version) => {
                git.run(self.work.path(), &["-c", &format!("protocol.version={version}"), "clone", &url, destination])
                    .await?
            }
        };
        ensure!(
            output.success,
            "stock Git {} clone failed: {}",
            protocol.map_or("default", |version| version),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(self.work.path().join(destination))
    }

    async fn finish(self, result: Result<Value>) -> Result<Value> {
        let failure = self.proxy.failure();
        let _ = self.proxy.stop().await;
        match result {
            Ok(value) => {
                ensure!(failure.is_none(), "proxy failed during the case: {}", failure.unwrap_or_default());
                Ok(value)
            }
            Err(error) => match failure {
                Some(failure) => Err(error.context(format!("proxy failure: {failure}"))),
                None => Err(error),
            },
        }
    }
}

fn git_text(output: &GitOutput) -> String {
    format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))
}

/// A failed client's outcome plus a redacted diagnostic for assertion
/// messages: no remote URL, URL userinfo, token, credential-bearing profile
/// value, request header or operation id reaches the message, and each line is
/// bounded. Only sanitized stderr is reported; stdout can carry a pushed URL or
/// operation id (e.g. a remote line) and is never emitted. Raw output stays
/// available to the case for in-memory acceptance matching only.
fn redacted_git_output(label: &str, output: &GitOutput) -> String {
    fn redact_line(line: &str) -> String {
        // Fold newlines so one diagnostic line cannot smuggle further output.
        let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
        // `scheme://...` is masked up to its end (any path may name a repo).
        let mut text = String::new();
        let mut rest = line.as_str();
        while let Some(start) = rest.find("://") {
            text.push_str(&rest[..start]);
            text.push_str("://<redacted>");
            let tail = &rest[start + 3..];
            let end = tail.find(char::is_whitespace).unwrap_or(tail.len());
            rest = &tail[end..];
        }
        text.push_str(rest);
        // A request header (`Name: value`) keeps only its name.
        let redacted = text
            .split_once(':')
            .filter(|(name, _)| {
                !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && *name != "fatal"
            })
            .map(|(name, _)| format!("{name}: <redacted>"));
        let mut text = redacted.unwrap_or(text);
        // Credential-shaped runs are masked wherever they appear.
        for prefix in ["ryt_", "Bearer ", "token ", "password "] {
            while let Some(start) = text.find(prefix) {
                let end = text[start..].find(char::is_whitespace).map_or(text.len(), |end| start + end);
                text.replace_range(start..end, &format!("{prefix}<redacted>"));
            }
        }
        if text.len() > 300 {
            let mut end = 300;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        text
    }
    let lines = |bytes: &[u8]| {
        String::from_utf8_lossy(bytes)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(redact_line)
            .collect::<Vec<_>>()
            .join(" | ")
    };
    format!(
        "{label} exit={} stderr=`{}`",
        if output.success { "success" } else { "failure" },
        redact_line(&lines(&output.stderr)),
    )
}

/// A stock `git push` run on its own task so two clients can push at once. The
/// remote URL already carries the real credentials in the stock way. `pin` is
/// the operation id the case attaches to this client's receive-pack POST; it is
/// sent exactly as Git sends it: one extra request header. The lost-ACK case
/// arms its pin in the proxy, while the race case uses its pin only to correlate
/// the durable row with the client. Both stock clients share the advertised old
/// OID; the proxy only carries their complete requests concurrently.
fn spawn_push(
    git: &'static Git,
    dir: std::path::PathBuf,
    pin: Option<Uuid>,
) -> tokio::task::JoinHandle<Result<GitOutput>> {
    tokio::spawn(async move { push(git, &dir, pin, &["push", "origin", "HEAD:refs/heads/main"]).await })
}

async fn push(git: &Git, dir: &std::path::Path, pin: Option<Uuid>, args: &[&str]) -> Result<GitOutput> {
    match pin {
        Some(operation) => {
            let header = format!("http.extraHeader=X-Rootyard-Operation: {operation}");
            // Git's global `-c` must precede the subcommand; after `push` stock Git
            // rejects it as an unknown push option and never sends the POST.
            let mut full_args = vec!["-c", header.as_str()];
            full_args.extend_from_slice(args);
            git.run(dir, &full_args).await
        }
        None => git.run(dir, args).await,
    }
}

/// A parsed `report-status`: the `unpack` status and `(ref, ng reason)` per ref.
type GitReport = (String, Vec<(String, Option<String>)>);

/// The per-ref verdicts of a captured service response, parsed from its real
/// `report-status` pkt-lines. Anything that is not `unpack <status>` or
/// `ok|ng <ref> <reason>` followed by exactly one flush is refused, so a
/// sideband, an HTTP body or a truncated response can never pass as a report.
fn report_status(response: &[u8]) -> Result<GitReport> {
    anyhow::ensure!(!response.is_empty(), "service response is empty");
    let mut position = 0usize;
    let mut unpack = None;
    let mut results = Vec::new();
    loop {
        anyhow::ensure!(position + 4 <= response.len(), "report-status has no flush pkt-line");
        let length = usize::from_str_radix(&String::from_utf8_lossy(&response[position..position + 4]), 16)
            .map_err(|_| anyhow!("report-status pkt-line length is invalid"))?;
        position += 4;
        if length == 0 {
            anyhow::ensure!(position == response.len(), "report-status has bytes after its flush");
            break;
        }
        anyhow::ensure!(length >= 4 && position + length - 4 <= response.len(), "report-status pkt-line is malformed");
        let raw = std::str::from_utf8(&response[position..position + length - 4])
            .map_err(|_| anyhow!("report-status line is not UTF-8"))?;
        anyhow::ensure!(
            raw.ends_with('\n') && !raw[..raw.len() - 1].contains('\n') && !raw.contains('\r'),
            "report-status pkt-line must end in exactly one LF and contain no CR: {raw:?}"
        );
        let line = raw[..raw.len() - 1].to_owned();
        position += length - 4;
        if let Some(value) = line.strip_prefix("unpack ") {
            anyhow::ensure!(unpack.is_none(), "report-status repeats unpack");
            unpack = Some(value.to_owned());
        } else if let Some(rest) = line.strip_prefix("ok ") {
            results.push((rest.to_owned(), None));
        } else if let Some(rest) = line.strip_prefix("ng ") {
            let (name, reason) = rest.split_once(' ').ok_or_else(|| anyhow!("ng line has no reason: {line}"))?;
            results.push((name.to_owned(), Some(reason.to_owned())));
        } else {
            anyhow::bail!("unexpected report-status line: {line}");
        }
    }
    Ok((unpack.ok_or_else(|| anyhow!("report-status has no unpack line"))?, results))
}

/// Reasons the receive path emits from a durable terminal; every other text is
/// a failure that must not be accepted as a Git ref result.
const GIT_REASONS: &[&str] = &[
    "stale info",
    "missing necessary objects",
    "bad object type",
    "funny refname",
    "deletion of the current branch prohibited",
    "head target missing",
    "no refs applied",
    "policy denied",
    "internal error",
];

fn assert_git_report(label: &str, response: &[u8]) -> Result<GitReport> {
    let (unpack, results) = report_status(response).with_context(|| format!("{label}: not a Git report-status"))?;
    ensure!(unpack == "ok", "{label}: unpack failed: {unpack}");
    for (name, reason) in &results {
        ensure!(name.starts_with("refs/"), "{label}: report-status names {name:?}");
        if let Some(reason) = reason {
            ensure!(GIT_REASONS.contains(&reason.as_str()), "{label}: {reason:?} is not a Git ref result reason");
        }
    }
    Ok((unpack, results))
}

/// Durable state of one operation of this case's repository, re-read once.
async fn operation_state(case: &Case, operation: Uuid) -> Result<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if let Some((state, _)) = case.operation_row(operation).await? {
            return Ok(state);
        }
        ensure!(tokio::time::Instant::now() < deadline, "operation {operation} has no durable row");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Operation ids of the durable rows of this repository, newest first.
async fn operation_states(case: &Case) -> Result<Vec<(Uuid, String)>> {
    let rows = case
        .db
        .pool
        .get()
        .await?
        .query("SELECT operation_id, state FROM ref_store_operations WHERE repository_id=$1", &[&case.repository])
        .await?;
    Ok(rows.into_iter().map(|row| (row.get(0), row.get(1))).collect())
}

async fn race_case(case: &Case, git: &'static Git) -> Result<Value> {
    // Seed `refs/heads/main` with a real clone + push, then two further clones
    // that both advertise the same tip.
    let seed_dir = case.clone_seed(git, "seed", None).await?;
    let seed = git.commit(&seed_dir, "seed.txt", "seed\n", "seed commit").await?;
    git.ok(&seed_dir, &["push", "origin", "HEAD:refs/heads/main"]).await?;
    let (first_dir, advertised) = case.clone(git, "race-a").await?;
    let (second_dir, second_advertised) = case.clone(git, "race-b").await?;
    ensure!(advertised == seed && second_advertised == seed, "clones did not share the pushed tip");
    let first = git.commit(&first_dir, "a.txt", "from a\n", "commit from a").await?;
    let second = git.commit(&second_dir, "b.txt", "from b\n", "commit from b").await?;
    ensure!(first != second, "the two racers made the same commit");

    // Discard the seed push's empty-repository advertisement (and the clone
    // advertisements) so that the later inspection sees only race traffic.
    case.proxy.records().await;

    // Pin a separate operation id to each stock push so each durable terminal
    // can be correlated with the client that produced it.
    let operation_a = Uuid::new_v4();
    let operation_b = Uuid::new_v4();
    ensure!(operation_a != operation_b, "the race pins shared an operation id");

    // Arm the barrier, then start both real stock pushes. Nothing is released
    // before both complete request bodies sit in the proxy. A client that exits
    // before its POST reaches the proxy fails the case at once instead of
    // waiting out the barrier's bound.
    // The capture-enabled barrier also yields the exact raw service reply each
    // held POST received, so the verdict is parsed from the service response
    // rather than inferred from what the client printed.
    let mut captured = case.proxy.hold_connection_capturing(2).await?;
    let mut first_push = spawn_push(git, first_dir, Some(operation_a));
    let mut second_push = spawn_push(git, second_dir, Some(operation_b));
    tokio::select! {
        held = case.proxy.await_held(2) => {
            held?;
            case.proxy.resolve_held().await?;
        }
        exited = &mut first_push => {
            let output = exited.context("the first stock push task failed")??;
            case.proxy.resolve_held().await.ok();
            return Err(anyhow!(
                "the first stock push exited before its receive-pack POST reached the proxy: {}",
                redacted_git_output("client a", &output)
            ));
        }
        exited = &mut second_push => {
            let output = exited.context("the second stock push task failed")??;
            case.proxy.resolve_held().await.ok();
            return Err(anyhow!(
                "the second stock push exited before its receive-pack POST reached the proxy: {}",
                redacted_git_output("client b", &output)
            ));
        }
    }
    let first_output = first_push.await??;
    let second_output = second_push.await??;
    let records = case.proxy.records().await;

    // Both receive-pack advertisements shared the same old OID; the test pins a
    // separate operation id to each stock push rather than to the advertisement.
    let mut advertised_old = Vec::new();
    for record in records.iter().filter(|record| record.path.ends_with("/info/refs") && record.advertisement.is_some())
    {
        let body = record.advertisement.clone().ok_or_else(|| anyhow!("receive-pack advertisement was truncated"))?;
        let (refs, capabilities) = proxy::parse_advertisement(&body)?;
        ensure!(capabilities.contains("report-status"), "advertisement lacks report-status");
        let (oid, _) = refs
            .iter()
            .find(|(_, name)| name == "refs/heads/main")
            .ok_or_else(|| anyhow!("advertisement has no refs/heads/main"))?;
        advertised_old.push(oid.clone());
    }
    ensure!(advertised_old.len() >= 2, "fewer than two receive-pack advertisements were observed");
    ensure!(
        advertised_old.iter().all(|oid| *oid == advertised),
        "advertisements disagree with the shared old OID: {advertised_old:?}"
    );
    let used_a = operation_a;
    let used_b = operation_b;

    // Both real POSTs reached the service and carried each client's new commit.
    let pushes = records
        .iter()
        .filter(|record| record.method == "POST" && record.path.ends_with("/git-receive-pack"))
        .collect::<Vec<_>>();
    ensure!(pushes.len() == 2, "expected exactly two receive-pack POSTs, saw {}", pushes.len());
    for (index, push) in pushes.iter().enumerate() {
        ensure!(push.status == Some(200), "receive-pack POST {index} did not reach the service: {:?}", push.status);
        ensure!(!push.truncated, "receive-pack POST {index} record is truncated");
    }

    // Git verdicts: exactly one push succeeded.
    let outcomes = [(&first_output, &first), (&second_output, &second)];
    let winners = outcomes.iter().filter(|(output, _)| output.success).count();
    ensure!(
        winners == 1,
        "expected exactly one successful push, saw {winners}\n{}\n{}",
        redacted_git_output("client a", &first_output),
        redacted_git_output("client b", &second_output)
    );
    let (winner, loser_output, winner_is_a) =
        if first_output.success { (&first, &second_output, true) } else { (&second, &first_output, false) };
    let loser_label = if winner_is_a { "client b (loser)" } else { "client a (loser)" };
    // Raw output feeds the in-memory acceptance checks only.
    let loser_text = git_text(loser_output);
    for forbidden in ["409", "503", "non-fast-forward", "fetch first", "unexpected disconnect", "remote end hung up"] {
        ensure!(
            !loser_text.contains(forbidden),
            "loser saw `{forbidden}`, not a report-status: {}",
            redacted_git_output(loser_label, loser_output)
        );
    }
    // Stock Git prints this ref verdict on stderr as `! [rejected] HEAD -> main
    // (stale info)`, so match the combined raw output for the rejection marker
    // and the parsed stale-info reason rather than one exact line. Git 2.47.3
    // renders it as `[rejected] ... (stale info)` without the `remote` prefix.
    ensure!(
        loser_text.contains("[rejected]") && (loser_text.contains("stale info") || loser_text.contains("(stale info)")),
        "loser push output is not the parsed stale-info rejection: {}",
        redacted_git_output(loser_label, loser_output)
    );

    // The server's own report-status: the client line above is only a rendering,
    // so parse the exact raw replies the proxy received from the service. Each
    // captured reply must correlate, by request digest, with one of the two
    // receive-pack POSTs counted above.
    let mut captured_replies = Vec::with_capacity(2);
    for slot in 0..2 {
        let capture = tokio::time::timeout(Duration::from_secs(120), captured.recv())
            .await
            .map_err(|_| anyhow!("held receive-pack reply {slot} never reached the proxy"))?
            .ok_or_else(|| anyhow!("the proxy lost held receive-pack reply {slot}"))?;
        ensure!(capture.status == Some(200), "the service answered a held receive-pack POST with {:?}", capture.status);
        ensure!(!capture.truncated, "held receive-pack reply {slot} is truncated");
        let (unpack, verdicts) = assert_git_report("held receive-pack reply", &capture.response)?;
        ensure!(unpack == "ok", "a held receive-pack reply did not unpack: {unpack}");
        ensure!(
            pushes.iter().filter(|push| push.request_sha256 == capture.request_sha256).count() == 1,
            "a captured service reply does not correlate with exactly one receive-pack POST"
        );
        captured_replies.push((capture.request_sha256, verdicts));
    }
    ensure!(captured.is_empty(), "the service answered more held receive-pack POSTs than were armed");
    // Across both replies: exactly one `ok refs/heads/main` and exactly one
    // `ng refs/heads/main stale info`, and nothing else on any ref.
    let accepted = captured_replies
        .iter()
        .flat_map(|(_, verdicts)| verdicts.iter())
        .filter(|(name, reason)| name == "refs/heads/main" && reason.is_none())
        .count();
    let refused = captured_replies
        .iter()
        .flat_map(|(_, verdicts)| verdicts.iter())
        .filter(|(name, reason)| name == "refs/heads/main" && reason.as_deref() == Some("stale info"))
        .count();
    let verdict_total: usize = captured_replies.iter().map(|(_, verdicts)| verdicts.len()).sum();
    ensure!(
        accepted == 1 && refused == 1 && verdict_total == 2,
        "service report-status is not one `ok` and one `ng ... stale info` on main \
         (ok={accepted}, stale={refused}, total={verdict_total})"
    );
    ensure!(
        captured_replies[0].0 != captured_replies[1].0,
        "both held receive-pack POSTs carried the same request body"
    );

    // Terminal states of the two pinned race pushes (`used_a`, `used_b`) only:
    // the setup seed push also leaves a durable operation row, but it is not an
    // acceptance target. Exactly one pinned operation is committed and one is
    // rejected, and they are exactly the two rows read back separately below.
    let bound = tokio::time::Instant::now() + Duration::from_secs(120);
    let states = loop {
        let states = operation_states(case)
            .await?
            .into_iter()
            .filter(|(operation, _)| *operation == used_a || *operation == used_b)
            .collect::<Vec<_>>();
        if states.len() == 2 && states.iter().all(|(_, state)| matches!(state.as_str(), "committed" | "rejected")) {
            break states;
        }
        ensure!(tokio::time::Instant::now() < bound, "pushes did not settle as terminals: {states:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let state_a = operation_state(case, used_a).await?;
    let state_b = operation_state(case, used_b).await?;
    let mut settled = vec![(used_a, state_a), (used_b, state_b)];
    settled.sort();
    let mut observed = states.clone();
    observed.sort();
    ensure!(
        settled == observed,
        "the operations created by this case's own clones are not the two terminals: {settled:?} vs {observed:?}"
    );
    ensure!(
        settled.iter().filter(|(_, state)| state == "committed").count() == 1
            && settled.iter().filter(|(_, state)| state == "rejected").count() == 1,
        "expected one committed and one rejected operation: {settled:?}"
    );
    let winner_operation = if winner_is_a { used_a } else { used_b };
    let loser_operation = if winner_is_a { used_b } else { used_a };
    ensure!(operation_state(case, winner_operation).await? == "committed", "the winning push is not committed");
    ensure!(operation_state(case, loser_operation).await? == "rejected", "the losing push is not rejected");

    // A fresh clone reads the winner and the durable core agrees.
    let (_, readback) = case.clone(git, "readback").await?;
    ensure!(readback == *winner, "readback {readback} is not the winner {winner}");
    let durable = case.durable_refs().await?;
    ensure!(durable.get("refs/heads/main") == Some(winner), "durable main is not the winner: {durable:?}");

    // The rejected terminal is exactly `stale info` for main; the committed one
    // applied the commit the fresh clone read.
    let (_, terminal) =
        case.operation_row(loser_operation).await?.ok_or_else(|| anyhow!("rejected operation row disappeared"))?;
    let terminal = terminal.ok_or_else(|| anyhow!("rejected operation has no terminal"))?;
    let refs = terminal["refs"].as_array().ok_or_else(|| anyhow!("rejected terminal has no refs"))?;
    ensure!(refs.len() == 1, "rejected terminal does not cover exactly one ref: {terminal}");
    ensure!(refs[0]["name"].as_str() == Some("refs/heads/main"), "rejected terminal names another ref: {terminal}");
    let code = refs[0]["reason"]["code"].as_str().or_else(|| refs[0]["reason"].as_str()).unwrap_or_default();
    ensure!(
        code.contains("OldOidMismatch") || code.contains("old_oid_mismatch"),
        "rejected terminal carries {code:?}: {terminal}"
    );
    let (_, winning_terminal) =
        case.operation_row(winner_operation).await?.ok_or_else(|| anyhow!("committed operation row disappeared"))?;
    let winning_terminal = winning_terminal.ok_or_else(|| anyhow!("committed operation has no terminal"))?;
    let applied = winning_terminal["refs"]
        .as_array()
        .and_then(|refs| refs.iter().find(|result| result["name"].as_str() == Some("refs/heads/main")))
        .and_then(|result| result["new_oid"].as_str())
        .ok_or_else(|| anyhow!("committed terminal does not name the applied main OID: {winning_terminal}"))?;
    ensure!(applied == *winner, "committed operation applied {applied}, the clone read {winner}");

    Ok(json!({
        "advertised_old_oid": advertised,
        "advertised_count": advertised_old.len(),
        "pinned_operations": [operation_a.to_string(), operation_b.to_string()],
        "winner": winner,
        "loser": if winner_is_a { second.clone() } else { first.clone() },
        "winner_is_client_a": winner_is_a,
        "readback": readback,
        "loser_client_verdict": "rejected: stale info",
        "gate_revision": case.gate_revision().await?,
        "operation_states": states.iter().map(|(_, state)| state.clone()).collect::<Vec<_>>(),
        "pushes": pushes.iter().map(|push| json!({
            "status": push.status,
            "request_sha256": push.request_sha256,
            "request_bytes": push.request_bytes,
        })).collect::<Vec<_>>(),
        // Parsed server report-status of each held POST, keyed by request digest:
        // bounded verdict names/reasons only, never a raw response body.
        "service_report_status": captured_replies.iter().map(|(request_sha256, verdicts)| json!({
            "request_sha256": request_sha256,
            "status": 200,
            "unpack": "ok",
            "verdicts": verdicts.iter().map(|(name, reason)| json!({
                "ref": name,
                "reason": reason,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    }))
}

/// Issue-126 requirement 2: a stock `git push` (protocol v0, one round trip)
/// whose receive-pack response arrived and was durably committed is lost on the
/// wire. The client's exit status is a transport failure, never a ref refusal;
/// the pinned operation is terminal `committed`, `refs/heads/main` names the
/// pushed commit, and a fresh clone reads exactly that commit back.
///
/// The pinned id travels only in an `http.extraHeader`, i.e. exactly as a stock
/// client sends an `X-Rootyard-Operation`; the proxy forwards the parsed POST
/// byte for byte.
#[tokio::test]
#[ignore = "requires real PG/S3/Git, a built serve-blob binary and stock clients"]
async fn lost_receive_pack_ack_after_commit_resolves_committed_via_operation_get() -> Result<()> {
    let node = node().await?;
    let git: &'static Git = Box::leak(Box::new(Git::new()?));
    let owner = actor::owner(&node.db.pool).await?;
    let case = Case::new(node, owner, "lost-ack").await?;
    let result = lost_ack_case(&case, git).await;
    let value = case.finish(result).await?;
    println!("lost-ack: {}", serde_json::to_string(&value)?);
    Ok(())
}

async fn lost_ack_case(case: &Case, git: &'static Git) -> Result<Value> {
    // Each fixture Git stage fails with its own static message: the underlying
    // error is discarded (never chained) so no Git URL or stderr can escape.
    let seed_dir = case.clone_seed(git, "seed", Some("0")).await.map_err(|_| anyhow!("seed clone failed"))?;
    git.commit(&seed_dir, "seed.txt", "seed\n", "seed commit").await.map_err(|_| anyhow!("seed commit failed"))?;
    git.ok(&seed_dir, &["push", "origin", "HEAD:refs/heads/main"]).await.map_err(|_| anyhow!("seed push failed"))?;
    let (client_dir, advertised) =
        case.clone_protocol(git, "push", "0").await.map_err(|_| anyhow!("post-seed clone failed"))?;
    let pushed = git
        .commit(&client_dir, "ack.txt", "committed before the ACK was lost\n", "ack commit")
        .await
        .map_err(|_| anyhow!("target commit failed"))?;
    ensure!(advertised != pushed, "the clone already had the new commit");

    let pinned = Uuid::new_v4();
    let poll = proxy::Poll::new(case.db, &case.owner, case.name, pinned);
    let mut captured = case.proxy.drop_operation(&pinned.to_string(), Some(poll))?;
    let output = push(git, &client_dir, Some(pinned), &["push", "origin", "HEAD:refs/heads/main"])
        .await
        .map_err(|_| anyhow!("pinned push failed"))?;
    let text = git_text(&output);
    ensure!(
        !output.success,
        "the stock push succeeded although its response was dropped: {}",
        redacted_git_output("pinned push", &output)
    );
    for report in ["stale info", "rejected", "non-fast-forward", "403", "409", "503"] {
        ensure!(
            !text.contains(report),
            "the lost ACK was reported as a server verdict `{report}`: {}",
            redacted_git_output("pinned push", &output)
        );
    }
    let capture = tokio::time::timeout(Duration::from_secs(120), captured.recv())
        .await
        .map_err(|_| anyhow!("the armed receive-pack POST never reached the proxy"))?
        .ok_or_else(|| anyhow!("the proxy lost the captured receive-pack POST"))?;
    ensure!(capture.status == Some(200), "the service answered the captured POST with {:?}", capture.status);
    let records = case.proxy.records().await;
    let pushes = records
        .iter()
        .filter(|record| record.method == "POST" && record.path.ends_with("/git-receive-pack"))
        .collect::<Vec<_>>();
    let matching = pushes.iter().filter(|record| record.request_sha256 == capture.request_sha256).collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "expected exactly one receive-pack POST with the captured digest, saw {}",
        matching.len()
    );
    let matched = matching[0];
    ensure!(
        matched.status == Some(200),
        "the captured receive-pack POST did not reach the service: {:?}",
        matched.status
    );
    ensure!(!matched.truncated, "the captured receive-pack POST record is truncated");
    let (unpack, results) = assert_git_report("captured", &capture.response)?;
    ensure!(unpack == "ok", "the captured report did not unpack: {unpack}");
    ensure!(results == vec![("refs/heads/main".to_owned(), None)], "the captured report was not one `ok`: {results:?}");

    // Durable ref and the pinned operation terminal.
    let durable = case.durable_refs().await?;
    ensure!(durable.get("refs/heads/main") == Some(&pushed), "durable main is not the pushed commit: {durable:?}");
    let (state, terminal) =
        case.operation_row(pinned).await?.ok_or_else(|| anyhow!("the pinned operation has no durable row"))?;
    ensure!(state == "committed", "the pinned operation is {state}, not committed");
    let terminal = terminal.ok_or_else(|| anyhow!("the committed operation has no terminal"))?;
    let applied = terminal["refs"]
        .as_array()
        .and_then(|refs| refs.iter().find(|result| result["name"].as_str() == Some("refs/heads/main")))
        .and_then(|result| result["new_oid"].as_str())
        .ok_or_else(|| anyhow!("the committed terminal does not name main: {terminal}"))?;
    ensure!(applied == pushed, "the committed terminal applied {applied}, not {pushed}");

    // The operation read of the issuing client resolves the same terminal.
    let path = case.path(&format!("/operations/{pinned}"));
    let (status, view) = case.service.get(Some(&case.owner.token), &path).await?;
    ensure!(status == 200, "operation GET answered {status}: {view}");
    ensure!(
        view["operation_id"].as_str() == Some(pinned.to_string().as_str()),
        "operation GET named another id: {view}"
    );
    ensure!(view["state"].as_str() == Some("committed"), "operation GET state is not committed: {view}");
    ensure!(
        view["terminal"]["refs"][0]["new_oid"].as_str() == Some(pushed.as_str()),
        "operation GET terminal differs: {view}"
    );
    // A foreign actor never resolves this operation.
    let stranger = actor::stranger(&case.db.pool).await?;
    let (denied, _) = case.service.get(Some(&stranger.token), &path).await?;
    ensure!(denied == 403 || denied == 404, "a foreign actor resolved the operation with {denied}");

    let (_, readback) =
        case.clone_protocol(git, "readback", "0").await.map_err(|_| anyhow!("readback clone failed"))?;
    ensure!(readback == pushed, "the fresh clone read {readback}, not the committed {pushed}");
    Ok(json!({
        "pinned_operation": pinned.to_string(),
        "pushed_commit": pushed,
        "advertised_before": advertised,
        "client_transport_failure": redacted_git_output("pinned push", &output),
        "captured_report_sha256": capture.request_sha256,
        "operation_get_state": view["state"],
        "readback": readback,
    }))
}

// ---------------------------------------------------------------------------
// Issue #107, first normal service-route slice: POST
// /api/repos/{owner}/{name}/operations/{operation}/cancel.
//
// This is a narrow route regression, not completion of issue #107. It runs the
// real Axum router over a loopback TCP listener with real PostgreSQL (one
// disposable schema) and the real Blob profile, and drives real stock Git
// clients, so committed/rejected operation rows and the cancellation race come
// from the real gateway receive/decision pipeline.
//
// The repository lives in the owner fixture's namespace. A collaborator is only
// ever authenticated by its own token; every request still addresses the
// repository under its actual owner slug, never the collaborator's username.
//
// The embedded router is fixed (no test-only probe hook), and a push that is
// legitimately blocked before the service (outside this route's scope) must not
// leave a durable row behind. The pending rows these cases cancel are therefore
// registered by the fixture inside one caller-owned transaction exactly as the
// gateway's fresh receive path registers one (`reserve_sequence` +
// `PgRefStore::begin` + the migration-147 producer binding). The identity is
// explicit and no client request is claimed; the route is the only code that
// decides whether such a row may be cancelled.
// ---------------------------------------------------------------------------

/// Provision the same migration-144 decision realm the service provisions at
/// create time, for a repository that only its owner (and collaborators) sees.
async fn provision_decision_realm_for(
    db: &Db,
    backend: &BlobBackendIdentity,
    actor: &Actor,
    owner_slug: &str,
    name: &str,
) -> Result<()> {
    let serving = lookup(&db.pool, &actor.identity, owner_slug, name, true, backend, deadline())
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
    )?;
    let mut client = db.pool.get().await?;
    PgDecisionProtocol
        .provision(&mut client, &expectation, deadline())
        .await
        .map_err(|error| anyhow!("decision realm provisioning refused: {error}"))?;
    Ok(())
}

struct CancelRouteCase {
    name: &'static str,
    /// The namespace slug the repository actually lives in (the owner fixture's
    /// username). Collaborators never replace it in any URL or lookup.
    owner_slug: String,
    repository: Uuid,
    proxy: Proxy,
    address: std::net::SocketAddr,
    work: tempfile::TempDir,
    first: String,
    second: String,
}

impl CancelRouteCase {
    /// Real Smart HTTP setup: `first` is pushed and a second clone branches from
    /// it. Neither work tree is pushed again with new commits here, so a later
    /// pinned push of `seed` must first advance it.
    async fn new(
        name: &'static str,
        repository: Uuid,
        proxy: Proxy,
        address: std::net::SocketAddr,
        git: &Git,
        owner: &Actor,
    ) -> Result<Self> {
        let work = tempfile::tempdir()?;
        let url = proxy.url(owner, name);
        let seed = work.path().join("seed");
        let cloned = git.clone(work.path(), &url, "seed").await?;
        // The clone URL embeds the credential as userinfo, which stock Git may
        // echo on failure: only the redacted diagnostic is used.
        ensure!(cloned.success, "{}", redacted_git_output("first clone", &cloned));
        let first = git.commit(&seed, "a.txt", "first\n", "first commit").await?;
        let pushed = git.run(&seed, &["push", "origin", "HEAD:refs/heads/main"]).await?;
        ensure!(pushed.success, "the first push failed: {}", redacted_git_output("first push", &pushed));
        let divergence = work.path().join("diverged");
        let cloned = git.clone(work.path(), &url, "diverged").await?;
        ensure!(cloned.success, "{}", redacted_git_output("divergent clone", &cloned));
        let raced = git.text(&divergence, &["rev-parse", "refs/remotes/origin/main"]).await?;
        ensure!(raced == first, "the divergent clone read {raced} for main, not the pushed {first}");
        let second = git.commit(&divergence, "b.txt", "second\n", "second commit").await?;
        ensure!(first != second, "the fixture commits are not distinct");
        Ok(Self { name, owner_slug: owner.username.clone(), repository, proxy, address, work, first, second })
    }

    fn repo_path(&self) -> String {
        format!("/api/repos/{}/{}", self.owner_slug, self.name)
    }

    fn operation_path(&self, operation: Uuid) -> String {
        format!("{}/operations/{operation}", self.repo_path())
    }

    fn cancel_path(&self, operation: Uuid) -> String {
        format!("{}/operations/{operation}/cancel", self.repo_path())
    }

    fn url(&self, actor: &Actor) -> String {
        self.proxy.url(actor, self.name)
    }

    async fn operation_state(&self, db: &Db, operation: Uuid) -> Result<Option<String>> {
        Ok(db
            .pool
            .get()
            .await?
            .query_opt(
                "SELECT state FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2",
                &[&self.repository, &operation],
            )
            .await?
            .map(|row| row.get(0)))
    }
}

/// Give `member` the given collaborator role on the case repository (owner's
/// tenant column included), then prove the *collaborator's* identity resolves
/// this repository through the owner slug with the expected minimum role.
async fn grant_role(
    db: &Db,
    backend: &BlobBackendIdentity,
    case: &CancelRouteCase,
    member: &Actor,
    role: &'static str,
    writable: bool,
) -> Result<()> {
    let tenant: Uuid = db
        .pool
        .get()
        .await?
        .query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&case.repository])
        .await?
        .get(0);
    db.pool
        .get()
        .await?
        .execute(
            "INSERT INTO repository_collaborators (repository_id, tenant_id, user_id, role) VALUES ($1,$2,$3,$4)",
            &[&case.repository, &tenant, &member.identity.id, &role],
        )
        .await?;
    // The collaborator is authenticated as itself, but the repository is looked
    // up under its actual owner slug.
    let serving = lookup(&db.pool, &member.identity, &case.owner_slug, case.name, writable, backend, deadline())
        .await
        .map_err(|error| anyhow!("the {role} collaborator was refused the lookup: {}", error.1))?;
    ensure!(serving.gate.repository_id() == case.repository, "the collaborator resolved another repository");
    ensure!(
        serving.repository.owner == case.owner_slug,
        "the collaborator resolved the repository under another owner slug"
    );
    Ok(())
}

/// A real restricted token of `actor` granting exactly `actions` (`contents_*`)
/// on this repository, minted through `POST /api/tokens`. The secret is only
/// ever placed in an Authorization header, never formatted.
async fn scoped_token(
    pool: &deadpool_postgres::Pool,
    case: &CancelRouteCase,
    holder: &Actor,
    actions: &[&str],
) -> Result<String> {
    let body = json!({
        "display_name": "cancel-route fixture",
        "repository_grants": [{"repository_id": case.repository, "actions": actions}],
    });
    let (status, issued) = json_request(case.address, "POST", "/api/tokens", Some(&holder.token), Some(&body)).await?;
    ensure!(
        status == 201,
        "token creation answered {status}: {}",
        issued.get("error").and_then(Value::as_str).unwrap_or("invalid error body")
    );
    ensure!(
        issued["is_restricted"].as_bool() == Some(true) && issued["read_only"].as_bool() == Some(false),
        "the scoped token is not a restricted writable token"
    );
    let secret = issued["secret"].as_str().ok_or_else(|| anyhow!("the issued token has no secret"))?;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_str(&format!("Bearer {secret}"))
            .map_err(|_| anyhow!("the issued token is not a valid header"))?,
    );
    rootyard::auth::authenticate(pool, &headers)
        .await
        .map_err(|error| anyhow!("the issued token did not authenticate: {}", error.1))?;
    Ok(secret.to_owned())
}

/// Durable refs, gate and membership snapshot of one repository.
struct DurableState {
    refs: std::collections::BTreeMap<String, String>,
    gate_revision: i64,
    gate_digest: String,
    memberships: i64,
}

async fn durable_state(db: &Db, repository: Uuid) -> Result<DurableState> {
    let mut client = db.pool.get().await?;
    let refs = client
        .query("SELECT ref_name, oid FROM ref_store_core_refs WHERE repository_id=$1 ORDER BY ref_name", &[&repository])
        .await?
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    let tenant: Uuid = client.query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&repository]).await?.get(0);
    let (gate_revision, gate_digest) =
        match PgRefStoreCore.check_version(&mut client, repository, tenant, None, deadline()).await? {
            VersionCheck::Unchanged(version) | VersionCheck::Changed(version) => {
                (version.revision(), version.digest().as_hex())
            }
            VersionCheck::Unknown => return Err(anyhow!("the core gate of {repository} is missing")),
        };
    let memberships = client
        .query_one("SELECT count(*) FROM ref_store_core_pack_memberships WHERE repository_id=$1", &[&repository])
        .await?
        .get(0);
    Ok(DurableState { refs, gate_revision, gate_digest, memberships })
}

/// `true` when `refs` maps `name` to exactly `oid`.
fn first_ref_matches(refs: &std::collections::BTreeMap<String, String>, name: &str, oid: &str) -> bool {
    refs.get(name).is_some_and(|value| value == oid)
}

/// Refs, gate revision/digest and active pack membership are exactly unchanged.
/// Publication decisions are deliberately not compared: a terminal
/// rejected/cancelled decision may remain.
fn assert_unchanged(label: &str, before: &DurableState, after: &DurableState) -> Result<()> {
    ensure!(after.refs == before.refs, "{label} changed durable refs: {:?} -> {:?}", before.refs, after.refs);
    ensure!(after.gate_revision == before.gate_revision, "{label} moved the gate revision");
    ensure!(after.gate_digest == before.gate_digest, "{label} moved the gate digest");
    ensure!(after.memberships == before.memberships, "{label} changed active pack membership");
    Ok(())
}

const LEGACY_SQL: &str =
    "SELECT request_digest FROM ref_store_cancellations WHERE repository_id=$1 AND operation_id=$2";
const DECISION_SQL: &str =
    "SELECT request_digest FROM ref_store_decision_cancellations WHERE repository_id=$1 AND operation_id=$2";

/// The single migration-138 cancellation row of exactly this operation, if any.
async fn legacy_cancellation(db: &Db, repository: Uuid, operation: Uuid) -> Result<Option<String>> {
    cancellation_row(db, LEGACY_SQL, repository, operation).await
}

/// The single decision-level cancellation row of exactly this operation, if any.
async fn decision_cancellation(db: &Db, repository: Uuid, operation: Uuid) -> Result<Option<String>> {
    cancellation_row(db, DECISION_SQL, repository, operation).await
}

async fn cancellation_row(db: &Db, sql: &'static str, repository: Uuid, operation: Uuid) -> Result<Option<String>> {
    Ok(db.pool.get().await?.query_opt(sql, &[&repository, &operation]).await?.map(|row| row.get(0)))
}

/// Rows in **both** cancellation tables of the whole repository.
async fn tombstone_count(db: &Db, repository: Uuid) -> Result<i64> {
    Ok(db
        .pool
        .get()
        .await?
        .query_one(
            "SELECT (SELECT count(*) FROM ref_store_cancellations WHERE repository_id=$1)
                  + (SELECT count(*) FROM ref_store_decision_cancellations WHERE repository_id=$1)",
            &[&repository],
        )
        .await?
        .get(0))
}

/// Register one durable **pending** operation and its migration-147 producer
/// binding in a single caller-owned transaction, with the gateway's own core
/// writes: reserve the issuer sequence, insert the migration-138 operation row
/// (`PgRefStore::begin`), and insert the binding. The issuer is authenticated
/// as itself; the repository is resolved under its actual owner slug.
async fn insert_pending_fixture(
    db: &Db,
    backend: &BlobBackendIdentity,
    issuer: &Actor,
    case: &CancelRouteCase,
    operation: Uuid,
) -> Result<()> {
    let gate = lookup(&db.pool, &issuer.identity, &case.owner_slug, case.name, true, backend, deadline())
        .await
        .map_err(|error| anyhow!("serving lookup refused the pending fixture issuer: {}", error.1))?
        .gate;
    let lane = IssuerLane::new("blob-git-receive")?;
    let mut client = db.pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute("SET LOCAL synchronous_commit = 'on'", &[]).await?;
    let sequence = PgRefStore
        .reserve_sequence(&tx, gate.repository_id(), issuer.identity.id, operation, &lane, deadline())
        .await
        .map_err(|error| anyhow!("the fixture could not reserve an issuer sequence: {error}"))?;
    let identity = OperationIdentity::new(
        gate.repository_id(),
        issuer.identity.id,
        lane,
        sequence.sequence(),
        operation,
        RequestDigest::from_bytes([0x5a; 32]),
    )?;
    let begun = PgRefStore
        .begin(&tx, &identity, deadline())
        .await
        .map_err(|error| anyhow!("the fixture pending operation was refused: {error}"))?;
    ensure!(begun.created, "the fixture pending operation already existed");
    let inserted = tx
        .execute(
            "INSERT INTO ref_store_serving_operations
                 (repository_id,operation_id,issuer_id,producer_request_digest,plan_parent_digest)
             VALUES ($1,$2,$3,$4,$4)",
            &[&identity.repository_id(), &identity.operation_id(), &identity.issuer_id(), &identity.digest().as_hex()],
        )
        .await
        .map_err(|error| anyhow!("the fixture producer binding was refused: {error}"))?;
    ensure!(inserted == 1, "the fixture producer binding was not created");
    tx.commit().await?;
    Ok(())
}

fn assert_no_store(label: &str, headers: &reqwest::header::HeaderMap) -> Result<()> {
    ensure!(
        headers.get("cache-control").and_then(|value| value.to_str().ok()) == Some("no-store"),
        "the {label} response is not Cache-Control: no-store"
    );
    Ok(())
}

/// The success body is exactly this operation and an outcome from `allowed`.
fn assert_cancel_view(label: &str, body: &Value, operation: Uuid, allowed: &[&str]) -> Result<()> {
    let object = body.as_object().ok_or_else(|| anyhow!("the {label} body is not a JSON object: {body}"))?;
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    ensure!(keys == ["operation_id", "outcome"], "the {label} body is not minimal: {body}");
    ensure!(
        body["operation_id"].as_str() == Some(operation.to_string().as_str()),
        "the {label} body names another operation: {body}"
    );
    let outcome = body["outcome"].as_str().unwrap_or_default();
    ensure!(allowed.contains(&outcome), "the {label} outcome {outcome:?} is not one of {allowed:?}: {body}");
    Ok(())
}

/// One request through the real loopback listener. Only the status, parsed JSON
/// and headers are returned; the Authorization header and any body are never
/// logged or formatted.
async fn http_request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> Result<(u16, Value, reqwest::header::HeaderMap)> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(60)).no_proxy().build()?;
    let request = match method {
        "POST" => client.post(format!("http://{address}{path}")),
        "GET" => client.get(format!("http://{address}{path}")),
        _ => return Err(anyhow!("unsupported fixture HTTP method")),
    };
    let request = match token {
        Some(token) => request.bearer_auth(token),
        None => request,
    };
    let request = match body {
        Some(body) => request.json(body),
        None => request,
    };
    let response = request.send().await?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response.json().await.unwrap_or(Value::Null);
    Ok((status, body, headers))
}

async fn json_request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> Result<(u16, Value)> {
    let (status, body, _) = http_request(address, method, path, token, body).await?;
    Ok((status, body))
}

async fn get_json(address: std::net::SocketAddr, token: Option<&str>, path: &str) -> Result<(u16, Value)> {
    json_request(address, "GET", path, token, None).await
}

async fn post_cancel(
    address: std::net::SocketAddr,
    token: &str,
    path: &str,
) -> Result<(u16, Value, reqwest::header::HeaderMap)> {
    http_request(address, "POST", path, Some(token), None).await
}

/// `(clone succeeded, refs/heads/main OID of a fresh fsck'd clone or null)` of a
/// fresh authoritative read through the loopback proxy.
async fn clone_main(
    case: &CancelRouteCase,
    git: &Git,
    actor: &Actor,
    destination: &str,
) -> Result<(bool, Option<String>)> {
    let url = case.url(actor);
    let output = git.clone(case.work.path(), &url, destination).await?;
    if !output.success {
        return Ok((false, None));
    }
    let path = case.work.path().join(destination);
    git.ok(&path, &["fsck", "--strict"]).await?;
    let resolved = git.run(&path, &["rev-parse", "--verify", "--quiet", "refs/remotes/origin/main"]).await?;
    if !resolved.success {
        return Ok((true, None));
    }
    Ok((true, Some(String::from_utf8_lossy(&resolved.stdout).trim().to_owned())))
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and stock Git clients"]
async fn registered_operation_cancel_route_reports_the_persisted_outcome() -> Result<()> {
    let db = Db::setup().await?;
    let outcome = cancel_route_case(&db).await;
    db.finish(outcome).await
}

async fn cancel_route_case(db: &Db) -> Result<()> {
    const REPO: &str = "cancel-route";

    let store = open_store()?;
    let backend = store.backend_identity().clone();
    let git: &'static Git = Box::leak(Box::new(Git::new()?));
    let scratch = tempfile::tempdir()?;
    let owner = actor::owner(&db.pool).await?;
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
        .map_err(|error| anyhow!("gateway configuration was refused: {error}"))?,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = router(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let outcome = async {
        let created = create_repository(address, &owner, REPO).await?;
        let repository = Uuid::parse_str(created["id"].as_str().unwrap_or_default())?;
        provision_decision_realm_for(db, &backend, &owner, &owner.username, REPO).await?;
        let proxy = Proxy::start(address, proxy::Limits::default()).await?;
        let case = CancelRouteCase::new(REPO, repository, proxy, address, git, &owner).await?;
        let result = async {
            cancel_route_body(db, &case, &backend, git, &owner, &stranger).await?;
            terminal_race_body(db, &case, git, &owner).await
        }
        .await;
        let failure = case.proxy.failure();
        let _ = case.proxy.stop().await;
        match result {
            Ok(()) => {
                ensure!(
                    failure.is_none(),
                    "the loopback proxy failed during the case: {}",
                    failure.unwrap_or_default()
                );
                Ok(())
            }
            Err(error) => match failure {
                Some(failure) => Err(error.context(format!("proxy failure: {failure}"))),
                None => Err(error),
            },
        }
    }
    .await;
    server.abort();
    outcome
}

/// Steps 1-9: authorization, persistence and the reported outcomes of the
/// registered-operation cancel route, without any concurrent push.
async fn cancel_route_body(
    db: &Db,
    case: &CancelRouteCase,
    backend: &BlobBackendIdentity,
    git: &Git,
    owner: &Actor,
    stranger: &Actor,
) -> Result<()> {
    const MAIN: &str = "refs/heads/main";
    let address = case.address;

    // A committed operation from a real push. `seed` is advanced first, because
    // its last push was `first` and an unchanged work tree would be up-to-date
    // and register no operation.
    let seed = case.work.path().join("seed");
    let committed_oid = git.commit(&seed, "c.txt", "third\n", "third commit").await?;
    ensure!(committed_oid != case.first, "the seed was not advanced");
    let committed = Uuid::new_v4();
    let output = push(git, &seed, Some(committed), &["push", "origin", "HEAD:refs/heads/main"])
        .await
        .map_err(|_| anyhow!("the authorized push could not be run"))?;
    ensure!(output.success, "the authorized push failed: {}", redacted_git_output("authorized push", &output));
    ensure!(
        case.operation_state(db, committed).await?.as_deref() == Some("committed"),
        "the authorized push did not register a committed operation"
    );

    // A server-side rejected terminal from one real stock push. A divergent
    // local branch would be refused by stock Git after the advertisement,
    // before any receive-pack POST, leaving no durable operation. Instead the
    // proxy rewrites the old OID of the second command (`side`, absent, so the
    // client sends the zero OID) to a different valid OID, so the service itself
    // rejects the stale `side` command; the `main` command is sent untouched.
    // A fresh commit advances `seed` without being pushed by the mutation.
    let rejected = Uuid::new_v4();
    let zero = "0".repeat(40);
    let side = "refs/heads/side";
    let rejected_oid = git.commit(&seed, "d.txt", "fourth\n", "fourth commit").await?;
    ensure!(
        rejected_oid != committed_oid && rejected_oid != case.first && rejected_oid != case.second,
        "the rejected fixture commit is not distinct"
    );
    // Drop the setup pushes' records so later inspection sees only this push.
    case.proxy.records().await;
    let mut rewritten = case
        .proxy
        .arm_old_oid_rewrite(proxy::OldOidRewrite {
            ref_name: side.to_owned(),
            expected_old_oid: zero.clone(),
            new_old_oid: committed_oid.clone(),
        })
        .map_err(|error| anyhow!("the old-OID rewrite could not be armed: {error}"))?;
    let output = push(
        git,
        &seed,
        Some(rejected),
        &["push", "--atomic", "origin", "HEAD:refs/heads/main", "HEAD:refs/heads/side"],
    )
    .await
    .map_err(|_| anyhow!("the stale push could not be run"))?;
    ensure!(
        !output.success,
        "the stock push succeeded although the service saw a wrong old OID: {}",
        redacted_git_output("stale push", &output)
    );
    // The capture of the mutated request and the exact service reply.
    let capture = tokio::time::timeout(Duration::from_secs(120), rewritten.recv())
        .await
        .map_err(|_| anyhow!("the armed rewrite never saw a receive-pack POST"))?
        .ok_or_else(|| anyhow!("the proxy lost the rewritten receive-pack capture"))?;
    ensure!(capture.status == Some(200), "the service answered the rewritten POST with {:?}", capture.status);
    let (unpack, results) = assert_git_report("rejected capture", &capture.response)?;
    ensure!(unpack == "ok", "the rejected report did not unpack: {unpack}");
    ensure!(results.len() == 2, "the rejected report covers {} refs, not 2", results.len());
    let verdict = |name: &str| {
        results
            .iter()
            .find(|(ref_name, _)| ref_name == name)
            .map(|(_, reason)| reason.clone())
            .ok_or_else(|| anyhow!("the rejected report does not name {name}"))
    };
    let main_reason = verdict(MAIN)?;
    let side_reason = verdict(side)?;
    ensure!(main_reason.is_some(), "the rejected report still accepted refs/heads/main");
    ensure!(side_reason.as_deref() == Some("stale info"), "side was refused with {side_reason:?}, not stale info");

    // The rewrite proof: the original side command carried the zero old OID, the
    // rewritten one carries `committed_oid`, and only that old OID changed.
    let proof = &capture.rewrite;
    ensure!(proof.ref_name == side, "the rewrite proof names {:?}, not refs/heads/side", proof.ref_name);
    ensure!(proof.original_old_oid == zero, "the rewrite proof did not start from the zero old OID");
    ensure!(
        proof.rewritten_old_oid == committed_oid,
        "the rewrite proof did not write the current committed OID for side"
    );
    ensure!(proof.commands == 2, "the rewrite proof saw {} commands, not 2", proof.commands);
    ensure!(proof.command_index == 1, "the rewrite proof touched command {}, not the second", proof.command_index);
    ensure!(proof.only_old_oid_changed, "the rewrite changed bytes outside the old OID");
    ensure!(proof.unchanged_other_commands, "the rewrite changed another command");
    ensure!(proof.original_bytes == proof.rewritten_bytes, "the rewrite changed the request length");
    ensure!(proof.original_sha256 != proof.rewritten_sha256, "the rewritten bytes are unchanged");
    let original_tuples = vec![
        (MAIN.to_owned(), committed_oid.clone(), rejected_oid.clone()),
        (side.to_owned(), zero.clone(), rejected_oid.clone()),
    ];
    let rewritten_tuples = vec![
        (MAIN.to_owned(), committed_oid.clone(), rejected_oid.clone()),
        (side.to_owned(), committed_oid.clone(), rejected_oid.clone()),
    ];
    ensure!(
        proof.original_command_tuples == original_tuples,
        "the original push commands are not main and side from the zero and committed OIDs: {:?}",
        proof.original_command_tuples
    );
    ensure!(
        proof.rewritten_command_tuples == rewritten_tuples,
        "the rewritten push commands are not main unchanged plus side on the committed OID: {:?}",
        proof.rewritten_command_tuples
    );
    ensure!(
        case.operation_state(db, rejected).await?.as_deref() == Some("rejected"),
        "the stale push did not register a rejected operation"
    );
    let before = durable_state(db, case.repository).await?;
    ensure!(before.refs.get(MAIN) == Some(&committed_oid), "durable main is not the third commit");
    ensure!(
        !before.refs.values().any(|oid| oid == &case.first || oid == &case.second),
        "a durable ref still names a non-committed fixture commit"
    );
    ensure!(!before.refs.contains_key(side), "the rejected push created the side ref");
    ensure!(before.memberships >= 2, "the two successful pushes registered {} memberships", before.memberships);

    // A real non-admin actor with an effective `write` role on this repository,
    // plus a read-only token of the owner.
    let writer = actor::stranger(&db.pool).await?;
    grant_role(db, backend, case, &writer, "write", true).await?;
    let writer_scoped_read = scoped_token(&db.pool, case, &writer, &["contents_read"]).await?;
    let writer_scoped_write = scoped_token(&db.pool, case, &writer, &["contents_write"]).await?;
    let read_only_value = rootyard::db::issue_token(&db.pool, &owner.username, false, true).await?;
    let read_only = read_only_value["token"].as_str().ok_or_else(|| anyhow!("no read-only secret"))?.to_owned();

    // An admin collaborator using a restricted `contents_write`-only token of
    // its own; it is also the issuer of the operation it cancels below.
    let admin = actor::stranger(&db.pool).await?;
    grant_role(db, backend, case, &admin, "admin", true).await?;
    let scoped_admin = scoped_token(&db.pool, case, &admin, &["contents_write"]).await?;
    let scoped_admin_pending = Uuid::new_v4();
    insert_pending_fixture(db, backend, &admin, case, scoped_admin_pending).await?;

    // Every cancellation below is made from this baseline.
    let rows_before = tombstone_count(db, case.repository).await?;

    // 1. The issuer (owner) cancels a durably pending operation. Because the
    //    pending decision has not installed yet, this writes both rows.
    let pending = Uuid::new_v4();
    insert_pending_fixture(db, backend, owner, case, pending).await?;
    ensure!(
        case.operation_state(db, pending).await?.as_deref() == Some("pending"),
        "the fixture operation is not durably pending"
    );
    let (status, body, headers) = post_cancel(address, &owner.token, &case.cancel_path(pending)).await?;
    ensure!(status == 200, "cancel answered {status}: {body}");
    assert_no_store("cancel", &headers)?;
    ensure!(
        headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json")),
        "the cancel response is not JSON"
    );
    assert_cancel_view("cancel", &body, pending, &["cancelled"])?;
    assert_pending_cancelled_ledger(db, case.repository, pending).await?;
    ensure!(
        tombstone_count(db, case.repository).await? == rows_before + 2,
        "a pending cancellation did not write exactly its two cancellation rows"
    );
    let (status, view) = get_json(address, Some(&owner.token), &case.operation_path(pending)).await?;
    ensure!(status == 200, "operation GET answered {status}: {view}");
    ensure!(view["state"].as_str() == Some("cancelled"), "operation GET does not show cancelled: {view}");
    assert_unchanged("cancelling", &before, &durable_state(db, case.repository).await?)?;

    // 2. Identical replay of the same identity adds no row and writes no
    //    ref/membership/gate. A decision-less tombstone replays `cancelled`.
    let (status, body, headers) = post_cancel(address, &owner.token, &case.cancel_path(pending)).await?;
    ensure!(status == 200, "replayed cancel answered {status}: {body}");
    assert_no_store("replayed cancel", &headers)?;
    assert_cancel_view("replayed cancel", &body, pending, &["already_cancelled", "cancelled"])?;
    ensure!(
        tombstone_count(db, case.repository).await? == rows_before + 2,
        "the replayed cancel wrote another cancellation row"
    );
    assert_unchanged("the replayed cancel", &before, &durable_state(db, case.repository).await?)?;

    // 3. A committed operation is reported as committed (never cancelled). The
    //    coordinator still inserts its migration-138 cancellation row, but
    //    returns before any decision row; the terminal stays committed.
    let (status, body, headers) = post_cancel(address, &owner.token, &case.cancel_path(committed)).await?;
    ensure!(status == 200, "cancel of a committed operation answered {status}: {body}");
    assert_no_store("committed cancel", &headers)?;
    assert_cancel_view("committed cancel", &body, committed, &["committed"])?;
    assert_terminal_legacy_cancellation(db, case.repository, committed).await?;
    ensure!(
        tombstone_count(db, case.repository).await? == rows_before + 3,
        "cancelling a committed operation did not add exactly one migration-138 row"
    );
    ensure!(
        case.operation_state(db, committed).await?.as_deref() == Some("committed"),
        "cancelling a committed operation rewrote its durable state"
    );
    assert_unchanged("committed cancel", &before, &durable_state(db, case.repository).await?)?;

    // 4. A rejected operation is reported as rejected, same ledger shape.
    let (status, body, _) = post_cancel(address, &owner.token, &case.cancel_path(rejected)).await?;
    ensure!(status == 200, "cancel of a rejected operation answered {status}: {body}");
    assert_cancel_view("rejected cancel", &body, rejected, &["rejected"])?;
    assert_terminal_legacy_cancellation(db, case.repository, rejected).await?;
    ensure!(
        tombstone_count(db, case.repository).await? == rows_before + 4,
        "cancelling a rejected operation did not add exactly one migration-138 row"
    );
    ensure!(
        case.operation_state(db, rejected).await?.as_deref() == Some("rejected"),
        "cancelling a rejected operation rewrote its durable state"
    );

    // 5. A real non-admin issuer (write collaborator) registers a pending row and
    //    is refused when its own token cancels it through the repository owner's
    //    URL: the route and the A4 coordinator both require a current owner/admin.
    let foreign_pending = Uuid::new_v4();
    insert_pending_fixture(db, backend, &writer, case, foreign_pending).await?;
    ensure!(
        case.operation_state(db, foreign_pending).await?.as_deref() == Some("pending"),
        "the non-admin fixture operation is not durably pending"
    );
    for (label, token) in [
        ("non-admin issuer", writer.token.clone()),
        ("write-only non-admin", writer_scoped_write.clone()),
        ("read-scoped writer", writer_scoped_read.clone()),
    ] {
        let (status, body, headers) = post_cancel(address, &token, &case.cancel_path(foreign_pending)).await?;
        ensure!(status == 403, "a {label} cancel answered {status}: {body}");
        assert_no_store(&format!("{label} refusal"), &headers)?;
    }
    // A read-only owner token is refused by the writable lookup before any
    // operation is resolved, and a role-less stranger (no collaborator row)
    // cannot reach the repository.
    let (status, body, headers) = post_cancel(address, &read_only, &case.cancel_path(foreign_pending)).await?;
    ensure!(status == 403, "a read-only token's cancel answered {status}: {body}");
    assert_no_store("read-only refusal", &headers)?;
    let (status, body, _) = post_cancel(address, &stranger.token, &case.cancel_path(foreign_pending)).await?;
    ensure!(status == 403 || status == 404, "a role-less stranger's cancel answered {status}: {body}");
    ensure!(
        case.operation_state(db, foreign_pending).await?.as_deref() == Some("pending"),
        "a refused cancel changed the non-admin operation"
    );
    assert!(legacy_cancellation(db, case.repository, foreign_pending).await?.is_none());
    assert!(decision_cancellation(db, case.repository, foreign_pending).await?.is_none());
    assert_unchanged("refused cancels", &before, &durable_state(db, case.repository).await?)?;

    // 6. Malformed and nil identifiers are typed bad requests.
    for raw in ["not-a-uuid", "00000000-0000-0000-0000-000000000000"] {
        let path = format!("{}/operations/{raw}/cancel", case.repo_path());
        let (status, body, _) = post_cancel(address, &owner.token, &path).await?;
        ensure!(status == 400, "cancel of {raw:?} answered {status}: {body}");
        ensure!(
            body["error"].as_str() == Some("invalid operation identifier"),
            "the malformed refusal body changed: {body}"
        );
    }
    let (status, _) = get_json(address, None, &case.operation_path(committed)).await?;
    ensure!(status == 401, "an unauthenticated operation GET answered {status}");

    // 7. Unknown ids: a writable owner token is refused by the missing row (404),
    //    a read-only token is refused earlier by the writable lookup (403).
    //    Neither writes a row or a cancellation row.
    let rows_before_unknown = tombstone_count(db, case.repository).await?;
    let unknown = Uuid::new_v4();
    let (status, body, headers) = post_cancel(address, &owner.token, &case.cancel_path(unknown)).await?;
    ensure!(status == 404, "a writable owner cancel of an unknown operation answered {status}: {body}");
    assert_no_store("unknown cancel", &headers)?;
    let (status, body, headers) = post_cancel(address, &read_only, &case.cancel_path(unknown)).await?;
    ensure!(status == 403, "a read-only cancel of an unknown operation answered {status}: {body}");
    assert_no_store("read-only unknown cancel", &headers)?;
    ensure!(case.operation_state(db, unknown).await?.is_none(), "an unknown operation acquired a durable row");
    assert!(legacy_cancellation(db, case.repository, unknown).await?.is_none());
    assert!(decision_cancellation(db, case.repository, unknown).await?.is_none());
    ensure!(
        tombstone_count(db, case.repository).await? == rows_before_unknown,
        "an unknown-id cancel wrote a cancellation row"
    );

    // 8. A current admin using a restricted `contents_write`-only token that has
    //    no `contents_read` grant: GetOperation deliberately falls back to the
    //    writable lookup for its own issuer, so it reads `pending`; the cancel
    //    then succeeds through the same write-only serving path.
    let rows_before_admin_get = tombstone_count(db, case.repository).await?;
    let (status, view) = get_json(address, Some(&scoped_admin), &case.operation_path(scoped_admin_pending)).await?;
    ensure!(status == 200, "the contents_write-only admin GET answered {status}: {view}");
    ensure!(view["state"].as_str() == Some("pending"), "the contents_write-only admin GET is not pending: {view}");
    // Reading the identity never cancels anything by itself.
    ensure!(
        tombstone_count(db, case.repository).await? == rows_before_admin_get,
        "reading the pending operation wrote a cancellation row"
    );
    let (status, body, headers) = post_cancel(address, &scoped_admin, &case.cancel_path(scoped_admin_pending)).await?;
    ensure!(status == 200, "a contents_write-only admin cancel answered {status}: {body}");
    assert_no_store("scoped admin cancel", &headers)?;
    assert_cancel_view("scoped admin cancel", &body, scoped_admin_pending, &["cancelled"])?;
    assert_pending_cancelled_ledger(db, case.repository, scoped_admin_pending).await?;
    let (status, view) = get_json(address, Some(&scoped_admin), &case.operation_path(scoped_admin_pending)).await?;
    ensure!(
        status == 200 && view["state"].as_str() == Some("cancelled"),
        "the contents_write-only admin GET does not show cancelled ({status}): {view}"
    );

    // 9. Exactly six cancellation rows were added (2 + 0 + 1 + 1 + 0 + 2), no
    //    ref, gate revision/digest or membership moved, and a fresh read still
    //    sees exactly the committed tip.
    ensure!(
        tombstone_count(db, case.repository).await? == rows_before + 6,
        "the route sequence did not write exactly six cancellation rows"
    );
    let after = durable_state(db, case.repository).await?;
    assert_unchanged("the cancel route sequence", &before, &after)?;
    let (cloned, observed) = clone_main(case, git, owner, "readback").await?;
    ensure!(cloned, "the readback clone failed");
    ensure!(observed.as_deref() == Some(committed_oid.as_str()), "the readback clone did not read the committed tip");
    Ok(())
}

/// A durably pending operation cancelled through the route has both its
/// migration-138 tombstone and its decision-level row, bound to one digest.
async fn assert_pending_cancelled_ledger(db: &Db, repository: Uuid, operation: Uuid) -> Result<()> {
    let legacy = legacy_cancellation(db, repository, operation).await?;
    let decision = decision_cancellation(db, repository, operation).await?;
    match (legacy.as_deref(), decision.as_deref()) {
        (Some(legacy), Some(decision)) => {
            ensure!(legacy == decision, "the cancellation rows of {operation} bind different digests")
        }
        _ => return Err(anyhow!("a cancelled pending operation {operation} lacks one of its cancellation rows")),
    }
    Ok(())
}

/// Cancelling an already terminal operation still inserts the migration-138
/// cancellation row, but the coordinator returns before any decision row.
async fn assert_terminal_legacy_cancellation(db: &Db, repository: Uuid, operation: Uuid) -> Result<()> {
    ensure!(
        legacy_cancellation(db, repository, operation).await?.is_some(),
        "a terminal operation {operation} has no migration-138 cancellation row"
    );
    ensure!(
        decision_cancellation(db, repository, operation).await?.is_none(),
        "a terminal operation {operation} acquired a decision cancellation row"
    );
    Ok(())
}

/// A bounded concurrency proof between this route's POST cancel and one real
/// stock push carrying a single operation id.
///
/// The fixture creates concurrent route/service execution after a bounded
/// loopback barrier; it does not force which side wins.
///
/// * the stock push POST reaches the loopback proxy and stays there
///   ([`Proxy::await_held`]); registration of the operation happens only inside
///   the service, so the row genuinely does not exist yet;
/// * the cancel loop calls the real route while the push is still held; a 404 is
///   the route's genuine "not registered (yet)" answer (nothing is created on
///   the fixture side), and it is retried within a strict bound;
/// * a 503 is accepted only as the fixed `outcome_unknown` refusal, then resolved
///   through the authorized GET operation route until its durable state is a
///   terminal, and a repeated POST cancel must answer that exact terminal; any
///   other 503 and every other non-200/404 status fails. The 503 is never a
///   terminal winner;
/// * the release future is signalled by the first HTTP response or error of the
///   loop (so a 403/503/transport failure can never leave the push blocked),
///   waits the round's small bounded hold, then opens the barrier
///   ([`Proxy::resolve_held`]) concurrently with the remaining retries;
/// * the stock push finishes after the barrier is open, the `Captured` reply is
///   received, and exactly one durable terminal must exist, match the route's
///   outcome and be coherent with the cancellation ledger (`cancelled` adds
///   both rows, a per-operation check below; `committed`/`rejected` add only the
///   migration-138 row of its own coordinator cancel). A lost/unknown COMMIT is
///   never a winner.
const RACE_HOLDS: [Duration; 3] = [Duration::ZERO, Duration::from_millis(50), Duration::from_millis(200)];
/// Bound for the stock client to finish after the barrier opened, and for any
/// cleanup of a held or aborted push.
const RACE_STOCK_TIMEOUT: Duration = Duration::from_secs(120);
const RACE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);

async fn terminal_race_body(db: &Db, case: &CancelRouteCase, git: &'static Git, owner: &Actor) -> Result<()> {
    for (index, hold) in RACE_HOLDS.into_iter().enumerate() {
        let seed = case.work.path().join("seed");
        let target =
            git.commit(&seed, "race.txt", &format!("race step {index}\n"), &format!("race commit {index}")).await?;
        let operation = Uuid::new_v4();
        let before = durable_state(db, case.repository).await?;
        ensure!(
            !before.refs.values().any(|oid| oid == &target),
            "the race target {target} is already a durable ref value"
        );
        let rows_before = tombstone_count(db, case.repository).await?;

        // Arm the bounded barrier, then start the real stock push carrying this
        // operation id. It stops at the proxy: the service has not seen it.
        let mut captured = case.proxy.hold_connection_capturing(1).await?;
        let mut stock = {
            let seed = seed.clone();
            tokio::spawn(
                async move { push(git, &seed, Some(operation), &["push", "origin", "HEAD:refs/heads/main"]).await },
            )
        };
        let (outcome, service_reply, output) =
            match race_round(db, case, owner, operation, hold, &mut stock, &mut captured).await {
                // The barrier is open and the push was forwarded: the stock
                // client is a legitimate participant now and is never cancelled
                // here. Only a hung client (bounded) is aborted.
                Ok(round) => match tokio::time::timeout(RACE_STOCK_TIMEOUT, &mut stock).await {
                    Ok(joined) => (round.outcome, round.reply, joined.context("the race push task panicked")??),
                    Err(_) => {
                        stock.abort();
                        let _ = tokio::time::timeout(RACE_CLEANUP_TIMEOUT, &mut stock).await;
                        return Err(anyhow!("the forwarded race push did not finish its client transaction in time"));
                    }
                },
                // The round failed at any stage. Always attempt to open the
                // barrier (safe when nothing is held or it is already open), so
                // a held request is never left blocked. If the request had
                // reached the hold, drain its capture boundedly so the next
                // round never reads it. Only a stock task that is still running is
                // aborted; the round's own error is the result and expected
                // cleanup cancellation never replaces it.
                Err(RaceRoundError { error, held }) => {
                    case.proxy.resolve_held().await.ok();
                    if held {
                        let _ = tokio::time::timeout(RACE_CLEANUP_TIMEOUT, captured.recv()).await;
                    }
                    if !stock.is_finished() {
                        stock.abort();
                    }
                    let _ = tokio::time::timeout(RACE_CLEANUP_TIMEOUT, &mut stock).await;
                    return Err(error);
                }
            };
        let service_reply =
            service_reply.ok_or_else(|| anyhow!("the proxy did not capture the forwarded race push"))?;
        assert_race_terminal(
            db,
            case,
            git,
            owner,
            index,
            operation,
            &target,
            &before,
            rows_before,
            &outcome,
            &output,
            &service_reply,
        )
        .await?;
    }
    Ok(())
}

/// What a successful round produced: the route's outcome and the real
/// receive-pack reply of the forwarded push.
struct RaceRound {
    outcome: String,
    reply: Option<proxy::Captured>,
}

/// A failed round, and whether its request had reached the proxy hold (so a
/// capture may be in flight and the barrier may need opening).
struct RaceRoundError {
    error: anyhow::Error,
    held: bool,
}

/// A `503` from POST cancel is accepted only as the fixed
/// `GatewayError::OutcomeUnknown` refusal (`outcome_unknown`), resolved through
/// the authorized GET operation route with the same owner token, bounded by the
/// cancel loop's own deadline, until the durable `state` is exactly `cancelled`,
/// `committed` or `rejected`. `pending` is retried; every other status/state
/// fails. The 503 itself is never a terminal winner.
async fn resolve_unknown_cancel(
    case: &CancelRouteCase,
    owner: &Actor,
    operation: Uuid,
    body: &Value,
    deadline: tokio::time::Instant,
) -> anyhow::Result<String> {
    ensure!(
        race_reply_error_value(body) == "outcome_unknown",
        "the race cancel answered 503 with the `{}` gateway label, not `outcome_unknown`",
        race_reply_error_value(body)
    );
    let state = loop {
        ensure!(
            tokio::time::Instant::now() < deadline,
            "the unknown race cancel was never resolved to a durable terminal before the cancel deadline"
        );
        let (status, view) = get_json(case.address, Some(&owner.token), &case.operation_path(operation)).await?;
        ensure!(
            status == 200,
            "the race operation GET answered {status} with the `{}` gateway label",
            race_reply_error_value(&view)
        );
        ensure!(
            view["operation_id"].as_str() == Some(operation.to_string().as_str()),
            "the race operation GET named another operation"
        );
        match view["state"].as_str().unwrap_or_default() {
            state @ ("cancelled" | "committed" | "rejected") => break state.to_owned(),
            "pending" => tokio::time::sleep(Duration::from_millis(5)).await,
            state => return Err(anyhow!("the race operation GET reported the non-terminal state `{state}`")),
        }
    };
    // Repeating POST cancel now must answer its normal HTTP 200 canonical view,
    // naming exactly that terminal state.
    let (status, cancel, _) = post_cancel(case.address, &owner.token, &case.cancel_path(operation)).await?;
    ensure!(
        status == 200,
        "the post-of-unknown race cancel answered {status} with the `{}` gateway label",
        race_reply_error_value(&cancel)
    );
    assert_cancel_view(
        "resolved race cancel",
        &cancel,
        operation,
        &["cancelled", "already_cancelled", "committed", "rejected"],
    )?;
    let outcome = cancel["outcome"].as_str().unwrap_or_default().to_owned();
    let expected = match state.as_str() {
        "cancelled" => "already_cancelled",
        "committed" => "committed",
        "rejected" => "rejected",
        other => return Err(anyhow!("the operation GET resolved to `{other}`, not a terminal")),
    };
    ensure!(outcome == expected, "the race operation is durably {state} but the resolved cancel reported {outcome}");
    Ok(outcome)
}

/// One concurrency round: wait for the held push, then run the route's cancel
/// loop concurrently with the bounded barrier release, and return the route's
/// outcome. Nothing is created on the fixture side while the push is held.
///
/// On failure the helper neither aborts nor awaits the stock task: it reports
/// the error and whether the request had reached the hold, and the caller owns
/// its lifecycle (open the barrier, drain the capture when needed, abort only a
/// still-running client).
async fn race_round(
    db: &Db,
    case: &CancelRouteCase,
    owner: &Actor,
    operation: Uuid,
    hold: Duration,
    stock: &mut tokio::task::JoinHandle<Result<GitOutput>>,
    captured: &mut tokio::sync::mpsc::UnboundedReceiver<proxy::Captured>,
) -> Result<RaceRound, RaceRoundError> {
    // Before `await_held` no request is proven held; every later refusal happens
    // once the POST is known to be at the proxy.
    let fail = |error: anyhow::Error, held: bool| RaceRoundError { error, held };
    let address = case.address;
    // Only the wait for the barrier races the client's early exit: once
    // `await_held` returned, the POST is definitely held at the proxy.
    tokio::select! {
        held = case.proxy.await_held(1) => held.map_err(|error| fail(error, false))?,
        exited = &mut *stock => {
            return Err(fail(match exited {
                Ok(Ok(output)) => anyhow!(
                    "the race push exited before its POST was held: {}",
                    redacted_git_output("race push", &output)
                ),
                Ok(Err(error)) => error.context("the race push failed before its POST was held"),
                Err(error) => anyhow!("the race push task was cancelled before its POST was held: {error}"),
            }, false));
        }
    }
    if let Some(state) = case.operation_state(db, operation).await.map_err(|error| fail(error, true))? {
        return Err(fail(
            anyhow!("the held push already registered its operation ({state}) before the cancel started"),
            true,
        ));
    }

    let (started, arrived) = tokio::sync::watch::channel(false);
    let cancel = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        let mut attempts = 0usize;
        loop {
            attempts += 1;
            ensure!(attempts < 800, "the race cancel exceeded its attempt bound");
            ensure!(
                tokio::time::Instant::now() < deadline,
                "the race operation was never registered before the cancel deadline"
            );
            let attempt = post_cancel(address, &owner.token, &case.cancel_path(operation)).await;
            // The first HTTP answer (whatever it is, a transport error included)
            // releases the barrier, so the push can never stay held.
            started.send_replace(true);
            let (status, body, _) = attempt?;
            if status == 200 {
                assert_cancel_view(
                    "race cancel",
                    &body,
                    operation,
                    &["cancelled", "already_cancelled", "committed", "rejected"],
                )?;
                return Ok(body["outcome"].as_str().unwrap_or_default().to_owned());
            }
            if status == 503 {
                return resolve_unknown_cancel(case, owner, operation, &body, deadline).await;
            }
            ensure!(
                status == 404,
                "the race cancel answered {status} with the `{}` gateway label",
                race_reply_error_label(&body.to_string().into_bytes())
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    let release = async {
        let mut arrived = arrived;
        while !*arrived.borrow_and_update() {
            arrived.changed().await.map_err(|_| anyhow!("the cancel loop ended before reaching the route"))?;
        }
        tokio::time::sleep(hold).await;
        case.proxy.resolve_held().await
    };
    let (cancelled, released) = tokio::join!(cancel, release);
    if let Err(error) = released {
        // Reached the hold; the caller's cleanup opens the barrier again and
        // drains whatever may still be captured.
        return Err(fail(error.context("the race barrier could not be released"), true));
    }
    let outcome = match cancelled {
        Ok(outcome) => outcome,
        Err(error) => {
            // The barrier is open and the push was forwarded: drain its capture
            // boundedly so a later round never reads this round's reply.
            let _ = tokio::time::timeout(RACE_CLEANUP_TIMEOUT, captured.recv()).await;
            return Err(fail(error, true));
        }
    };
    let reply = match captured.recv().await {
        Some(reply) => reply,
        None => return Err(fail(anyhow!("the proxy did not capture the forwarded race push"), true)),
    };
    Ok(RaceRound { outcome, reply: Some(reply) })
}

/// The static label of the gateway error a raw HTTP reply body carries: the
/// fixed `GatewayError` messages map to their own labels, an unparseable body is
/// `non_json`, and no message text is ever echoed.
fn race_reply_error_label(response: &[u8]) -> &'static str {
    serde_json::from_slice::<Value>(response).map_or("non_json", |body| race_reply_error_value(&body))
}

/// [`race_reply_error_label`] for an already parsed body; a body that is not the
/// gateway's single `{"error": "<fixed label>"}` object is `other_gateway_error`.
///
/// Only exact, known fixed messages are labelled. The `GatewayError::Internal`
/// refusals of the receive path's A3 artifact hold, A3 protected upload/consume
/// and A4 publication-ledger verification each keep their own static label so a
/// diagnostic can tell them apart; any other text stays `other_gateway_error`.
/// The message itself is never printed or returned.
fn race_reply_error_value(value: &Value) -> &'static str {
    match value.get("error").and_then(Value::as_str) {
        Some("operation is durably cancelled") => "operation_durably_cancelled",
        Some("publication was rejected by the core ledger") => "publication_rejected",
        Some("publication outcome is unknown; query the operation or inspect refs") => "outcome_unknown",
        Some("service temporarily unavailable") => "service_unavailable",
        Some("Git gateway request exceeded its bounded deadline") => "gateway_timeout",
        Some("artifact hold acquisition was refused") => "artifact_hold_acquire_refused",
        Some("protected Blob upload was refused") => "protected_upload_refused",
        Some("publication ledger could not be verified") => "publication_ledger_refused",
        _ => "other_gateway_error",
    }
}

/// The receive-pack status of a captured race reply, or `none` when the service
/// never answered it.
fn race_reply_status(reply: &proxy::Captured) -> String {
    reply.status.map_or_else(|| "none".to_owned(), |status| status.to_string())
}

/// The only two wire answers of a durable cancellation: the fixed 409
/// `operation_durably_cancelled` refusal, or a 200 replay whose complete
/// report-status is exactly one `ng refs/heads/main operation was cancelled`.
/// The reason is matched here only, never added to [`GIT_REASONS`].
///
/// `canonical` is the durable state already verified by the caller; a failure
/// reports it as a literal field beside the HTTP status and static label, and
/// never the raw response body.
fn assert_cancelled_wire(reply: &proxy::Captured, canonical: &str) -> Result<()> {
    const CANCELLED_REASON: &str = "operation was cancelled";
    const MAIN: &str = "refs/heads/main";
    match reply.status {
        Some(409) => {
            let label = race_reply_error_label(&reply.response);
            ensure!(
                label == "operation_durably_cancelled",
                "the cancelled race answered HTTP 409 with the `{label}` gateway label, canonical_outcome={canonical}"
            );
        }
        Some(200) => {
            let (unpack, results) = report_status(&reply.response).with_context(|| {
                format!("the cancelled race reply is not a Git report-status, canonical_outcome={canonical}")
            })?;
            ensure!(unpack == "ok", "the cancelled race reply did not unpack: {unpack}, canonical_outcome={canonical}");
            ensure!(
                results == [(MAIN.to_owned(), Some(CANCELLED_REASON.to_owned()))],
                "the cancelled race reply is not exactly one `ng {MAIN} {CANCELLED_REASON}`: {results:?}, canonical_outcome={canonical}"
            );
        }
        _ => {
            return Err(anyhow!(
                "the cancelled race answered HTTP {} with the `{}` gateway label, neither 409 nor a 200 replay, canonical_outcome={canonical}",
                race_reply_status(reply),
                race_reply_error_label(&reply.response)
            ));
        }
    }
    Ok(())
}

/// The post-round proof: one coherent durable terminal, exactly the route's
/// outcome, the right cancellation-ledger rows, and refs/gate/membership
/// coherent with that terminal.
#[allow(clippy::too_many_arguments)]
async fn assert_race_terminal(
    db: &Db,
    case: &CancelRouteCase,
    git: &Git,
    owner: &Actor,
    index: usize,
    operation: Uuid,
    target: &str,
    before: &DurableState,
    rows_before: i64,
    outcome: &str,
    output: &GitOutput,
    service_reply: &proxy::Captured,
) -> Result<()> {
    const MAIN: &str = "refs/heads/main";
    let state = case
        .operation_state(db, operation)
        .await?
        .ok_or_else(|| anyhow!("the race operation has no durable row after both requests"))?;
    ensure!(
        matches!(state.as_str(), "committed" | "rejected" | "cancelled"),
        "the race operation is {state}, not a terminal"
    );
    let expected = match outcome {
        "cancelled" | "already_cancelled" => "cancelled",
        "committed" => "committed",
        "rejected" => "rejected",
        "unknown" => return Err(anyhow!("the race route reported an unknown outcome; not a winner")),
        other => return Err(anyhow!("the race route reported `{other}`, which is not a terminal")),
    };
    ensure!(state == expected, "the route reported {outcome} but the durable operation is {state}");

    // A real, complete service answer: never a truncated capture. The accepted
    // status is decided per durable state below (`cancelled` has the typed 409
    // winner; `committed`/`rejected` require exactly 200).
    ensure!(!service_reply.truncated, "the captured race reply is truncated");

    // Cancellation-ledger coherence for exactly this race operation.
    let legacy = legacy_cancellation(db, case.repository, operation).await?;
    let decision = decision_cancellation(db, case.repository, operation).await?;
    if state == "cancelled" {
        match (legacy.as_deref(), decision.as_deref()) {
            (Some(legacy), Some(decision)) => {
                ensure!(legacy == decision, "the A4 cancellation rows of the race operation bind different digests")
            }
            _ => return Err(anyhow!("a cancelled race operation lacks one of its cancellation rows")),
        }
    } else {
        ensure!(legacy.is_some(), "a {state} race operation has no migration-138 cancellation row");
        ensure!(decision.is_none(), "a {state} race operation acquired a decision cancellation row");
    }
    let after = durable_state(db, case.repository).await?;
    ensure!(
        tombstone_count(db, case.repository).await? == rows_before + if state == "cancelled" { 2 } else { 1 },
        "the race wrote an unexpected number of cancellation rows"
    );
    match state.as_str() {
        "committed" => {
            ensure!(
                output.success,
                "a committed race operation has no successful push: {}",
                redacted_git_output("race push", output)
            );
            // The wire answer of a committed terminal is its 200 replay: a
            // complete report-status with `unpack ok` and exactly one `ok` for
            // main carrying no reason.
            ensure!(
                service_reply.status == Some(200),
                "the committed race did not receive a receive-pack reply (status={})",
                race_reply_status(service_reply)
            );
            let (unpack, results) = report_status(&service_reply.response)
                .with_context(|| "the committed race reply is not a Git report-status")?;
            ensure!(unpack == "ok", "the committed race reply did not unpack: {unpack}");
            ensure!(
                results == [(MAIN.to_owned(), None)],
                "the committed race reply is not exactly one `ok` for {MAIN}: {results:?}"
            );
            ensure!(first_ref_matches(&after.refs, MAIN, target), "the committed race did not publish the pushed OID");
            ensure!(after.gate_revision > before.gate_revision, "the committed race did not advance the gate");
            ensure!(after.memberships > before.memberships, "the committed race added no pack membership");
            let (cloned, observed) = clone_main(case, git, owner, &format!("race-readback-{index}")).await?;
            ensure!(cloned, "the race readback clone failed");
            ensure!(observed.as_deref() == Some(target), "the race readback did not see the pushed OID");
        }
        "cancelled" | "rejected" => {
            assert_unchanged(&format!("the {state} race"), before, &after)?;
            ensure!(
                !after.refs.values().any(|oid| oid == target),
                "a {state} race operation left its commit on a durable ref"
            );
            // The client must have seen a failure: a false successful Git ACK
            // cannot pass even though no durable ref moved.
            ensure!(
                !output.success,
                "a {state} race push reported success: {}",
                redacted_git_output("race push", output)
            );
            if state == "cancelled" {
                assert_cancelled_wire(service_reply, &state)?;
            } else {
                // The client verdict must come from the captured report-status: one
                // result, for main, whose per-ref verdict is `ng` with a known reason.
                ensure!(
                    service_reply.status == Some(200),
                    "the rejected race did not receive a receive-pack reply (status={})",
                    race_reply_status(service_reply)
                );
                let (_, results) = assert_git_report("race receive-pack reply", &service_reply.response)?;
                ensure!(results.len() == 1, "the {state} race reply does not cover exactly one ref: {results:?}");
                let (ref_name, reason) = &results[0];
                ensure!(
                    ref_name == MAIN && reason.is_some(),
                    "the {state} race reply does not reject {MAIN} as `ng`: {results:?}"
                );
            }
            let text = git_text(output);
            for verdict in ["[new branch]", "Everything up-to-date"] {
                ensure!(
                    !text.contains(verdict),
                    "the {state} race push was reported as `{verdict}`: {}",
                    redacted_git_output("race push", output)
                );
            }
        }
        _ => unreachable!("the state was matched above"),
    }
    Ok(())
}
/// Issue-126 requirement 3: one real `git push --atomic` of two refs. Stock
/// Git's own local atomic preflight passes with the normally advertised old
/// OIDs; only after the client formed its receive-pack POST does the proxy
/// rewrite the old OID of the `refs/heads/side` command (never the
/// capability-carrying first command) to a different valid OID and forward that
/// single mutated request. The service refuses both refs of the atomic batch and
/// neither durable ref nor the gate revision moves; a fresh clone reads the
/// unchanged tips back.
#[tokio::test]
#[ignore = "requires real PG/S3/Git, a built serve-blob binary and stock clients"]
async fn atomic_push_with_rewritten_old_oid_rejects_both_refs_and_leaves_gate_unchanged() -> Result<()> {
    let node = node().await?;
    let git: &'static Git = Box::leak(Box::new(Git::new()?));
    let owner = actor::owner(&node.db.pool).await?;
    let case = Case::new(node, owner, "atomic-rewrite").await?;
    let result = atomic_rewrite_case(&case, git).await;
    let value = case.finish(result).await?;
    println!("atomic-rewrite: {}", serde_json::to_string(&value)?);
    Ok(())
}

async fn atomic_rewrite_case(case: &Case, git: &'static Git) -> Result<Value> {
    const MAIN: &str = "refs/heads/main";
    const SIDE: &str = "refs/heads/side";
    let zero = "0".repeat(40);

    // Real seed clone + push: both branches start at the same `base`.
    let seed_dir = case.clone_seed(git, "seed", None).await?;
    let base = git.commit(&seed_dir, "seed.txt", "seed\n", "seed commit").await?;
    git.ok(&seed_dir, &["push", "--atomic", "origin", "HEAD:refs/heads/main", "HEAD:refs/heads/side"]).await?;

    // A fresh stock client whose remote-tracking refs name both advertised tips.
    let (client, advertised) = case.clone(git, "client").await?;
    ensure!(advertised == base, "the client clone read {advertised} for main, not {base}");
    let side_advertised = git.text(&client, &["rev-parse", "refs/remotes/origin/side"]).await?;
    ensure!(side_advertised == base, "the client clone read {side_advertised} for side, not {base}");

    // Two distinct fast-forwards from `base`; nothing here rewrites history, so
    // stock Git's own atomic preflight accepts both updates.
    git.ok(&client, &["checkout", "-q", "-B", "main", "refs/remotes/origin/main"]).await?;
    let main_new = git.commit(&client, "main.txt", "main fast-forward\n", "main commit").await?;
    git.ok(&client, &["checkout", "-q", "-B", "side", "refs/remotes/origin/side"]).await?;
    let side_new = git.commit(&client, "side.txt", "side fast-forward\n", "side commit").await?;
    ensure!(
        main_new != side_new && main_new != base && side_new != base,
        "the two fast-forwards are not distinct commits ({main_new}, {side_new}, base {base})"
    );
    git.ok(&client, &["merge-base", "--is-ancestor", &base, &main_new]).await?;
    git.ok(&client, &["merge-base", "--is-ancestor", &base, &side_new]).await?;

    // Drop clone/seed traffic so the later inspection sees only the push.
    case.proxy.records().await;
    let refs_before = case.durable_refs().await?;
    ensure!(
        refs_before.get(MAIN) == Some(&base) && refs_before.get(SIDE) == Some(&base),
        "durable refs do not start at base: {refs_before:?}"
    );
    let refs_before_json = serde_json::to_value(&refs_before)?;
    let gate_before = case.gate_revision().await?;

    let pinned = Uuid::new_v4();
    let mut captured = case.proxy.arm_old_oid_rewrite(proxy::OldOidRewrite {
        ref_name: SIDE.to_owned(),
        expected_old_oid: base.clone(),
        new_old_oid: zero.clone(),
    })?;
    let output = push(
        git,
        &client,
        Some(pinned),
        &["push", "--atomic", "origin", "main:refs/heads/main", "side:refs/heads/side"],
    )
    .await
    .map_err(|_| anyhow!("the atomic push could not be run"))?;
    ensure!(
        !output.success,
        "the stock atomic push succeeded although one command named a wrong old OID: {}",
        redacted_git_output("atomic push", &output)
    );
    // Raw output feeds in-memory matching only; diagnostics use the redaction.
    let text = git_text(&output);
    ensure!(
        text.contains("[rejected]"),
        "the refused push is not a parsed rejection: {}",
        redacted_git_output("atomic push", &output)
    );
    for report in ["non-fast-forward", "fetch first", "unexpected disconnect", "remote end hung up"] {
        ensure!(
            !text.contains(report),
            "the refusal was reported as `{report}`, not a report-status: {}",
            redacted_git_output("atomic push", &output)
        );
    }

    // The exact service reply to the mutated bytes.
    let capture = tokio::time::timeout(Duration::from_secs(120), captured.recv())
        .await
        .map_err(|_| anyhow!("the armed rewrite never saw a receive-pack POST"))?
        .ok_or_else(|| anyhow!("the proxy lost the rewritten receive-pack capture"))?;
    ensure!(capture.status == Some(200), "the service answered the rewritten POST with {:?}", capture.status);
    let (unpack, results) = assert_git_report("captured", &capture.response)?;
    ensure!(unpack == "ok", "the captured report did not unpack: {unpack}");
    ensure!(results.len() == 2, "the captured report covers {} refs, not 2", results.len());
    let verdict = |name: &str| {
        results
            .iter()
            .find(|(ref_name, _)| ref_name == name)
            .map(|(_, reason)| reason.clone())
            .ok_or_else(|| anyhow!("the captured report does not name {name}"))
    };
    let main_reason = verdict(MAIN)?;
    let side_reason = verdict(SIDE)?;
    ensure!(main_reason.is_some(), "the captured report still accepted refs/heads/main");
    ensure!(side_reason.as_deref() == Some("stale info"), "side was refused with {side_reason:?}, not stale info");

    // The rewrite proof: exactly one 40-byte old-OID change in the body that
    // reached the service.
    let proof = capture.rewrite.clone();
    ensure!(proof.ref_name == SIDE, "the rewrite proof names {:?}, not refs/heads/side", proof.ref_name);
    ensure!(proof.original_old_oid == base, "the rewrite proof started from the wrong old OID");
    ensure!(proof.rewritten_old_oid == zero, "the rewrite proof wrote another OID");
    ensure!(proof.command_index >= 1, "the rewrite touched the capability-carrying first command");
    ensure!(proof.commands == 2, "the rewrite proof saw {} commands, not 2", proof.commands);
    ensure!(proof.old_oid_offset >= 4, "the rewrite proof has no plausible old-OID offset");
    ensure!(proof.original_bytes == proof.rewritten_bytes, "the rewrite changed the request length");
    ensure!(proof.original_sha256 != proof.rewritten_sha256, "the rewritten bytes are unchanged");
    ensure!(proof.only_old_oid_changed, "the rewrite changed bytes outside the old OID");
    ensure!(proof.unchanged_other_commands, "the rewrite changed another command");
    ensure!(proof.rewritten_sha256 == capture.request_sha256, "the capture digest is not the rewritten body");

    // Body-free command tuples: the client sent exactly main/base/main_new and
    // side/base/side_new; the rewritten request differs only in side's old OID.
    let original_tuples =
        vec![(MAIN.to_owned(), base.clone(), main_new.clone()), (SIDE.to_owned(), base.clone(), side_new.clone())];
    let rewritten_tuples =
        vec![(MAIN.to_owned(), base.clone(), main_new.clone()), (SIDE.to_owned(), zero.clone(), side_new.clone())];
    ensure!(
        proof.original_command_tuples == original_tuples,
        "the original push commands are not main/side from base: {:?}",
        proof.original_command_tuples
    );
    ensure!(
        proof.rewritten_command_tuples == rewritten_tuples,
        "the rewritten push commands are not main unchanged plus side on the zero old OID: {:?}",
        proof.rewritten_command_tuples
    );
    ensure!(
        proof
            .original_command_tuples
            .iter()
            .zip(proof.rewritten_command_tuples.iter())
            .enumerate()
            .all(|(index, (old, new))| (old != new) == (index == proof.command_index)),
        "the command tuples changed beyond the one armed command"
    );

    // The service saw exactly one receive-pack POST carrying the captured
    // (mutated) bytes: locate it by digest, then require it completed, was
    // answered with 200 and was recorded without truncation.
    let records = case.proxy.records().await;
    let pushes = records
        .iter()
        .filter(|record| record.method == "POST" && record.path.ends_with("/git-receive-pack"))
        .collect::<Vec<_>>();
    ensure!(pushes.len() == 1, "expected exactly one receive-pack POST, saw {}", pushes.len());
    let matching = pushes.iter().filter(|record| record.request_sha256 == capture.request_sha256).collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "expected exactly one receive-pack POST with the captured digest, saw {}",
        matching.len()
    );
    let matched = matching[0];
    ensure!(
        matched.status == Some(200),
        "the captured receive-pack POST did not reach the service: {:?}",
        matched.status
    );
    ensure!(!matched.truncated, "the captured receive-pack POST record is truncated");
    ensure!(matched.request_bytes == proof.rewritten_bytes, "the recorded request length is not the rewritten one");

    // Bind stock Git's expected old values to the advertisement it really saw:
    // exactly one receive-pack advertisement since the setup traffic was drained.
    let advertisements = records
        .iter()
        .filter(|record| {
            record.method == "GET" && record.path.ends_with("/info/refs") && record.advertisement.is_some()
        })
        .collect::<Vec<_>>();
    ensure!(advertisements.len() == 1, "expected exactly one receive-pack advertisement, saw {}", advertisements.len());
    let advertisement = advertisements[0];
    ensure!(!advertisement.truncated, "the receive-pack advertisement record is truncated");
    ensure!(advertisement.status == Some(200), "the advertisement answered {:?}", advertisement.status);
    let body =
        advertisement.advertisement.clone().ok_or_else(|| anyhow!("the receive-pack advertisement was truncated"))?;
    let (advertised_refs, capabilities) = proxy::parse_advertisement(&body)?;
    ensure!(capabilities.contains("report-status"), "the advertisement lacks report-status");
    ensure!(capabilities.contains("atomic"), "the advertisement lacks atomic");
    let mut advertised = advertised_refs.into_iter().collect::<Vec<_>>();
    advertised.sort_unstable();
    let mut expected_advertised = vec![(base.clone(), MAIN.to_owned()), (base.clone(), SIDE.to_owned())];
    expected_advertised.sort_unstable();
    ensure!(
        advertised == expected_advertised,
        "the advertisement is not exactly main and side at base: {advertised:?}"
    );

    // Nothing durable moved.
    let refs_after = case.durable_refs().await?;
    ensure!(refs_after == refs_before, "durable refs changed: before {refs_before:?}, after {refs_after:?}");
    let gate_after = case.gate_revision().await?;
    ensure!(gate_after == gate_before, "the gate revision moved from {gate_before} to {gate_after}");

    let (readback_dir, readback) = case.clone(git, "readback").await?;
    ensure!(readback == base, "the fresh clone read {readback} for main, not {base}");
    let readback_side = git.text(&readback_dir, &["rev-parse", "refs/remotes/origin/side"]).await?;
    ensure!(readback_side == base, "the fresh clone read {readback_side} for side, not {base}");

    // The pinned operation is terminal `rejected` and covers exactly both refs.
    let bound = tokio::time::Instant::now() + Duration::from_secs(120);
    let (state, terminal) = loop {
        let row = case.operation_row(pinned).await?;
        if let Some((state, Some(terminal))) = row
            && matches!(state.as_str(), "committed" | "rejected" | "cancelled")
        {
            break (state, terminal);
        }
        ensure!(tokio::time::Instant::now() < bound, "the pinned operation did not reach a durable terminal");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    ensure!(state == "rejected", "the pinned operation is {state}, not rejected");
    let terminal_refs = terminal["refs"].as_array().ok_or_else(|| anyhow!("rejected terminal has no refs"))?;
    let mut names = terminal_refs.iter().filter_map(|result| result["name"].as_str()).collect::<Vec<_>>();
    names.sort_unstable();
    let mut expected_names = vec![MAIN, SIDE];
    expected_names.sort_unstable();
    ensure!(names == expected_names, "the rejected terminal does not cover exactly both refs: {terminal}");
    let refusal = |name: &str| {
        let result = terminal_refs
            .iter()
            .find(|result| result["name"].as_str() == Some(name))
            .ok_or_else(|| anyhow!("the rejected terminal does not name {name}"))?;
        ensure!(result["outcome"].as_str() == Some("not_applied"), "the terminal applied {name}: {terminal}");
        let code =
            result["reason"]["code"].as_str().or_else(|| result["reason"].as_str()).unwrap_or_default().to_owned();
        Ok(code)
    };
    let side_code = refusal(SIDE)?;
    let main_code = refusal(MAIN)?;
    ensure!(side_code == "old_oid_mismatch", "side's terminal reason is {side_code:?}, not old_oid_mismatch");

    // The issuing client resolves the same rejection through the operation API.
    let path = case.path(&format!("/operations/{pinned}"));
    let (status, view) = case.service.get(Some(&case.owner.token), &path).await?;
    ensure!(status == 200, "operation GET answered {status}");
    ensure!(
        view["operation_id"].as_str() == Some(pinned.to_string().as_str()),
        "operation GET named another id: {view}"
    );
    ensure!(view["state"].as_str() == Some("rejected"), "operation GET state is not rejected: {view}");
    let view_refs = view["terminal"]["refs"].as_array().ok_or_else(|| anyhow!("operation GET has no terminal refs"))?;
    for name in [MAIN, SIDE] {
        ensure!(
            view_refs.iter().any(
                |result| result["name"].as_str() == Some(name) && result["outcome"].as_str() == Some("not_applied")
            ),
            "operation GET terminal does not refuse {name}: {view}"
        );
    }

    Ok(json!({
        "base": base,
        "main_new": main_new,
        "side_new": side_new,
        "pinned_operation": pinned.to_string(),
        "gate_revision_before": gate_before,
        "gate_revision_after": gate_after,
        "durable_refs_before": refs_before_json,
        "durable_refs_unchanged": true,
        "client_verdict": "rejected",
        "capture": {
            "request_sha256": capture.request_sha256,
            "request_bytes": capture.request_bytes,
            "status": capture.status,
            "unpack": unpack,
            "verdicts": results.iter().map(|(name, reason)| json!({
                "ref": name,
                "reason": reason,
            })).collect::<Vec<_>>(),
        },
        "rewrite": {
            "ref_name": proof.ref_name,
            "original_old_oid": proof.original_old_oid,
            "rewritten_old_oid": proof.rewritten_old_oid,
            "command_index": proof.command_index,
            "commands": proof.commands,
            "old_oid_offset": proof.old_oid_offset,
            "original_sha256": proof.original_sha256,
            "rewritten_sha256": proof.rewritten_sha256,
            "original_bytes": proof.original_bytes,
            "rewritten_bytes": proof.rewritten_bytes,
            "only_old_oid_changed": proof.only_old_oid_changed,
            "unchanged_other_commands": proof.unchanged_other_commands,
            "original_command_tuples": proof.original_command_tuples.iter().map(|(ref_name, old_oid, new_oid)| json!({
                "ref": ref_name,
                "old_oid": old_oid,
                "new_oid": new_oid,
            })).collect::<Vec<_>>(),
            "rewritten_command_tuples": proof.rewritten_command_tuples.iter().map(|(ref_name, old_oid, new_oid)| json!({
                "ref": ref_name,
                "old_oid": old_oid,
                "new_oid": new_oid,
            })).collect::<Vec<_>>(),
        },
        "advertisement": {
            "refs": advertised.iter().map(|(oid, name)| json!({
                "ref": name,
                "oid": oid,
            })).collect::<Vec<_>>(),
            "report_status": capabilities.contains("report-status"),
            "atomic": capabilities.contains("atomic"),
        },
        "record": {
            "request_sha256": matched.request_sha256,
            "request_bytes": matched.request_bytes,
            "status": matched.status,
            "truncated": matched.truncated,
        },
        "operation_state": state,
        "terminal_reasons": { "refs/heads/main": main_code, "refs/heads/side": side_code },
        "operation_get_state": view["state"],
        "readback_main": readback,
        "readback_side": readback_side,
    }))
}
