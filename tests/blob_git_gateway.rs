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
//! 3. a real `git push --atomic` of two refs where one command advertises a
//!    stale old OID: the service refuses both refs with parsed report-status
//!    lines and neither durable ref nor the gate revision moves.
//!
//! The case-3 fault is injected on the wire: stock Git's own atomic preflight
//! is satisfied and the proxy rewrites only the `old` OID of one real command
//! in the captured body before the requests reach the service concurrently.
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
use rootyard::ref_store::{
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
            .query_one("SELECT version FROM ref_store_core_gates WHERE repository_id=$1", &[&self.repository])
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
                git.run(
                    self.work.path(),
                    &["-c", &format!("protocol.version={version}"), "clone", &url, destination],
                )
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

/// A stock `git push` run on its own task so two clients can push at once. The
/// remote URL already carries the real credentials in the stock way. `pin` is
/// the operation id the case arms in the proxy and is sent exactly as Git sends
/// it: one extra request header. Both stock clients share the advertised old
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
            let mut args = args.iter().copied().collect::<Vec<_>>();
            args.splice(1..1, ["-c", header.as_str()]);
            git.run(dir, &args).await
        }
        None => git.run(dir, args).await,
    }
}

/// The per-ref verdicts of a captured service response, parsed from its real
/// `report-status` pkt-lines. Anything that is not `unpack <status>` or
/// `ok|ng <ref> <reason>` followed by exactly one flush is refused, so a
/// sideband, an HTTP body or a truncated response can never pass as a report.
fn report_status(response: &[u8]) -> Result<(String, Vec<(String, Option<String>)>)> {
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
        let line = std::str::from_utf8(&response[position..position + length - 4])
            .map_err(|_| anyhow!("report-status line is not UTF-8"))?
            .trim_end_matches('\n')
            .to_owned();
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

fn assert_git_report(label: &str, response: &[u8]) -> Result<(String, Vec<(String, Option<String>)>)> {
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

/// The operation id one advertisement created. The create through the case
/// proxy answered with that id; the case then confirms it by reading the very
/// row it pushed (`terminal_result.refs[0].new_oid`), never by pinning it.
async fn advertised_operation(record: &proxy::Record) -> Option<Uuid> {
    record
        .operation
        .as_ref()
        .map(|created| created.operation)
        .filter(|_| record.status == Some(200) && record.method == "POST")
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

    // Arm the barrier, then start both real stock pushes. Nothing is released
    // before both complete request bodies sit in the proxy.
    case.proxy.hold_connection(2).await?;
    let first_push = spawn_push(git, first_dir, None);
    let second_push = spawn_push(git, second_dir, None);
    case.proxy.await_held(2).await?;
    case.proxy.resolve_held().await?;
    let first_output = first_push.await??;
    let second_output = second_push.await??;
    let records = case.proxy.records().await;

    // Both real announcements advertised the same old OID, and each advertised
    // a fresh operation id that its own POST then carried.
    let mut advertised_old = Vec::new();
    let mut advertised_operations = Vec::new();
    for record in records.iter().filter(|record| record.path.ends_with("/info/refs")) {
        let body = record.advertisement.clone().ok_or_else(|| anyhow!("receive-pack advertisement was truncated"))?;
        let (refs, capabilities) = proxy::parse_advertisement(&body)?;
        ensure!(capabilities.contains("report-status"), "advertisement lacks report-status");
        let (_, oid) = refs
            .iter()
            .find(|(_, name)| name == "refs/heads/main")
            .ok_or_else(|| anyhow!("advertisement has no refs/heads/main"))?;
        advertised_old.push(oid.clone());
        advertised_operations.push(
            advertised_operation(record).await.ok_or_else(|| anyhow!("a case create did not name its operation"))?,
        );
    }
    ensure!(advertised_old.len() >= 2, "fewer than two receive-pack advertisements were observed");
    ensure!(
        advertised_old.iter().all(|oid| *oid == advertised),
        "advertisements disagree with the shared old OID: {advertised_old:?}"
    );
    let used_a = advertised_operations[0];
    let used_b = advertised_operations[1];
    ensure!(used_a != used_b, "the two advertisements shared an operation id");

    // Both real POSTs reached the service and carried each client's new commit.
    let pushes = records
        .iter()
        .filter(|record| record.method == "POST" && record.path.ends_with("/git-receive-pack"))
        .collect::<Vec<_>>();
    ensure!(pushes.len() == 2, "expected exactly two receive-pack POSTs, saw {}", pushes.len());
    for push in &pushes {
        ensure!(push.status == Some(200), "a receive-pack POST did not reach the service: {:?}", push.status);
    }

    // Git verdicts: exactly one push succeeded.
    let outcomes = [(&first_output, &first), (&second_output, &second)];
    let winners = outcomes.iter().filter(|(output, _)| output.success).count();
    ensure!(
        winners == 1,
        "expected exactly one successful push, saw {winners}\n{}\n{}",
        git_text(&first_output),
        git_text(&second_output)
    );
    let (winner, loser_output, winner_is_a) =
        if first_output.success { (&first, &second_output, true) } else { (&second, &first_output, false) };
    let loser_text = git_text(loser_output);
    for forbidden in ["409", "503", "non-fast-forward", "fetch first", "unexpected disconnect", "remote end hung up"] {
        ensure!(!loser_text.contains(forbidden), "loser saw `{forbidden}`, not a report-status: {loser_text}");
    }
    let stdout = String::from_utf8_lossy(&loser_output.stdout);
    ensure!(
        stdout.contains("! refs/heads/main:refs/heads/main [remote rejected] (stale info)"),
        "loser push summary is not the parsed stale-info rejection: {stdout}"
    );

    // Exactly one committed and one rejected durable operation, and this case's
    // own two creates are exactly those two terminals.
    let bound = tokio::time::Instant::now() + Duration::from_secs(120);
    let states = loop {
        let states = operation_states(case).await?;
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
        "advertised_operations": advertised_operations.iter().map(|operation| operation.to_string()).collect::<Vec<_>>(),
        "winner": winner,
        "loser": if winner_is_a { second.clone() } else { first.clone() },
        "winner_is_client_a": winner_is_a,
        "readback": readback,
        "loser_client_line": "! refs/heads/main:refs/heads/main [remote rejected] (stale info)",
        "gate_revision": case.gate_revision().await?,
        "operation_states": states.iter().map(|(_, state)| state.clone()).collect::<Vec<_>>(),
        "pushes": pushes.iter().map(|push| json!({
            "status": push.status,
            "request_sha256": push.request_sha256,
            "request_bytes": push.request_bytes,
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
    let seed_dir = case.clone_seed(git, "seed", Some("0")).await?;
    git.ok(&seed_dir, &["push", "origin", "HEAD:refs/heads/main"]).await?;
    let (client_dir, advertised) = case.clone_protocol(git, "push", "0").await?;
    let pushed = git.commit(&client_dir, "ack.txt", "committed before the ACK was lost\n", "ack commit").await?;
    ensure!(advertised != pushed, "the clone already had the new commit");

    let pinned = Uuid::new_v4();
    let poll = proxy::Poll::new(case.db, &case.owner, case.name, pinned);
    let mut captured = case.proxy.drop_operation(&pinned.to_string(), Some(poll))?;
    let output = push(git, &client_dir, Some(pinned), &["push", "origin", "HEAD:refs/heads/main"]).await?;
    ensure!(!output.success, "the stock push succeeded although its response was dropped: {}", git_text(&output));
    let text = git_text(&output);
    for report in ["stale info", "rejected", "non-fast-forward", "403", "409", "503"] {
        ensure!(!text.contains(report), "the lost ACK was reported as a server verdict `{report}`: {text}");
    }
    let capture = tokio::time::timeout(Duration::from_secs(120), captured.recv())
        .await
        .map_err(|_| anyhow!("the armed receive-pack POST never reached the proxy"))?
        .ok_or_else(|| anyhow!("the proxy lost the captured receive-pack POST"))?;
    ensure!(capture.status == Some(200), "the service answered the captured POST with {:?}", capture.status);
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

    let (_, readback) = case.clone_protocol(git, "readback", "0").await?;
    ensure!(readback == pushed, "the fresh clone read {readback}, not the committed {pushed}");
    Ok(json!({
        "pinned_operation": pinned.to_string(),
        "pushed_commit": pushed,
        "advertised_before": advertised,
        "client_transport_failure": text.lines().next().unwrap_or_default(),
        "captured_report_sha256": capture.request_sha256,
        "operation_get_state": view["state"],
        "readback": readback,
    }))
}
