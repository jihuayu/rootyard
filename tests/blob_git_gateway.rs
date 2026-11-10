//! Real end-to-end acceptance for the Blob-only Git gateway.
//!
//! Run explicitly by Root (all cases are `#[ignore]` and hard-fail on missing
//! services):
//!
//! ```text
//! ROOTYARD_TEST_DATABASE_URL=... ROOTYARD_BLOB_SERVICE=s3 ROOTYARD_BLOB_ENDPOINT=... \
//! ROOTYARD_BLOB_BUCKET=... ROOTYARD_BLOB_REGION=... ROOTYARD_BLOB_ACCESS_KEY_ID=... \
//! ROOTYARD_BLOB_SECRET_ACCESS_KEY=... ROOTYARD_TEST_GIT=/usr/bin/git \
//! cargo test --test blob_git_gateway -- --ignored --test-threads=1
//! ```
//!
//! The case creates a repository through the real create API, clones it over
//! real Smart HTTP, commits and pushes through the real receive pipeline,
//! asserts that every temporary compute view is gone, clones again from
//! PostgreSQL + Blob only, runs stock `git fsck --strict` and compares exact
//! OIDs. It also exercises a stale-CAS push and a wrong-token clone.
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
    db::{Db, deadline},
    git::{Git, assert_no_compute_views, clone_url},
};
use rootyard::blob_git_gateway::{BlobGitConfig, BlobGitState, router};
use rootyard::blob_store::{BlobProvider, config::BlobProfile, opendal::BlobStore};
use rootyard::ref_store::{
    core::decision_commit::{PgDecisionProtocol, RealmExpectation},
    serving::lookup,
};
use serde_json::json;
use tokio::net::TcpListener;
use uuid::Uuid;

fn open_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == BlobProvider::S3, "ROOTYARD_BLOB_SERVICE must be s3 for this suite");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
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
    // The production `blob_git_gateway::router` is mounted at its own root with
    // no prefix proxy, so fixtures must use its unprefixed `/api/...` and
    // `/git/{owner}/{name}/...` paths (not any gateway-prefixed routes).
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
