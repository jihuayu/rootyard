//! Real-PostgreSQL suite for the permanent artifact-hold ledger (A3/#113).
//!
//! Run explicitly by Root:
//! `ROOTYARD_TEST_DATABASE_URL=... cargo test --test ref_store_artifact_holds -- --ignored`.
//! Selecting this suite without a database panics; there is no in-memory fake.
//! Every test owns a random schema built only by `db::migrate` (migration 141 is
//! asserted, never re-applied from `include_str!`) and real pooled connections.
//!
//! The fixture-owned loopback listeners below only count connection attempts and
//! answer HTTP 503. They prove "no provider IO happened" and "an upload was
//! attempted"; they do NOT prove provider byte success or read-back. Real S3
//! success/read-back is a separate Root qualifier. No raw Authorization header,
//! credential or environment secret is logged by this file.
//!
//! The table-`SHARE` cut regression below is only an admission-vs-backup lock
//! cut over the new 141 tables. It does not qualify the backup CLI; Root runs
//! the actual format-17 backup/restore separately. No fake "backup passed" case
//! is added here.
#![allow(clippy::too_many_arguments)]

use anyhow::{Context, Result, anyhow, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_store::BlobBackendIdentity;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::blob_store::protected::{ProtectedUploadError, ProtectedUploader, UploadSource};
use rootyard::db;
use rootyard::ref_store::artifact_hold::{
    AcquireAck, AcquireArtifactHoldsRequest, AcquireLookup, AcquireOutcome, ArtifactHoldCapabilities,
    ArtifactHoldError, ArtifactHoldPurpose, ArtifactSpec, ConsumeAck, ConsumeLookup, HoldScope, PgArtifactHoldStore,
    ShardId,
};
use rootyard::ref_store::{
    CoreGateInit, GitObjectFormat, IssuerLane, OperationIdentity, OperationState, PgRefStore, PgRefStoreCore, RefName,
    RequestDigest, VersionCheck,
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

const OBSERVER_WAIT: Duration = Duration::from_secs(10);
const OP_DEADLINE: Duration = Duration::from_secs(30);
/// A deliberately short owned deadline only where the suite must force a
/// *sent* `COMMIT` to lose its client-side acknowledgement. The observer still
/// has `OBSERVER_WAIT` to prove the backend is parked before this expires.
const UNKNOWN_COMMIT_DEADLINE: Duration = Duration::from_secs(4);
const BLOB_MAX_OBJECT: u64 = 1024 * 1024;
/// Fixture bucket for the opened S3 store; the other bucket is the same
/// provider/endpoint/root/region/account with a different physical backend.
const TEST_BUCKET: &str = "artifact-hold-test-bucket";
const OTHER_BUCKET: &str = "artifact-hold-other-bucket";

fn database_url() -> String {
    // Serialize environment reads against the fixture-only Blob env writer.
    let _guard = BLOB_ENV.lock().unwrap_or_else(|poison| poison.into_inner());
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set when running the ignored ref_store_artifact_holds suite")
}

fn deadline() -> TokioInstant {
    TokioInstant::now() + OP_DEADLINE
}

fn std_deadline() -> StdInstant {
    StdInstant::now() + OP_DEADLINE
}

fn lane(value: &str) -> IssuerLane {
    IssuerLane::new(value).expect("valid lane")
}

fn format() -> GitObjectFormat {
    GitObjectFormat::Sha1
}

async fn setup() -> Result<(Pool, Pool, String, Uuid, Uuid)> {
    let url = database_url();
    let admin = db::pool(&url)?;
    let schema = format!("ref_store_hold_test_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000"));
    let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(16)
        .build()?;
    db::migrate(&pool).await?;
    let client = pool.get().await?;
    let installed: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=141)
                AND to_regclass('artifact_hold_requests') IS NOT NULL
                AND to_regclass('artifact_holds') IS NOT NULL
                AND to_regclass('artifact_hold_consume_receipts') IS NOT NULL
                AND to_regclass('artifact_hold_shards') IS NOT NULL
                AND to_regclass('artifact_hold_repo_usage') IS NOT NULL
                AND to_regclass('artifact_hold_tenant_usage') IS NOT NULL",
            &[],
        )
        .await?
        .get(0);
    ensure!(installed, "db::migrate did not install migration 141 or a real artifact-hold table is missing");
    drop(client);
    let (tenant, repo) = create_business(&pool).await?;
    Ok((admin, pool, schema, tenant, repo))
}

async fn create_business(pool: &Pool) -> Result<(Uuid, Uuid)> {
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO users(id,username) VALUES($1,$2)",
            &[&tenant, &format!("hold{}", &tenant.simple().to_string()[..12])],
        )
        .await?;
    client
        .execute(
            "INSERT INTO repositories(id,owner_id,name,state,object_format)
             VALUES($1,$2,$3,'provisioning','sha1')",
            &[&repo, &tenant, &format!("repo{}", &repo.simple().to_string()[..12])],
        )
        .await?;
    drop(client);
    Ok((tenant, repo))
}

async fn teardown(admin: &Pool, schema: &str) -> Result<()> {
    admin.get().await?.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await?;
    Ok(())
}

/// Always attempt teardown, but never hide the primary test failure.
async fn finish(admin: &Pool, schema: &str, outcome: Result<()>) -> Result<()> {
    match outcome {
        Ok(()) => teardown(admin, schema).await,
        Err(error) => {
            let _ = teardown(admin, schema).await;
            Err(error)
        }
    }
}

fn pool_error(error: deadpool_postgres::PoolError) -> ArtifactHoldError {
    ArtifactHoldError::Database(error.to_string())
}

async fn initialize_gate(
    pool: &Pool,
    repo: Uuid,
    tenant: Uuid,
    history: Uuid,
    object_format: GitObjectFormat,
) -> Result<RequestDigest> {
    let init = CoreGateInit::new(repo, tenant, object_format, history, 1, 1, RefName::branch("refs/heads/main")?)?;
    let mut client = pool.get().await?;
    let gate = PgRefStoreCore.initialize(&mut client, &init, deadline()).await?;
    Ok(*gate.digest())
}

async fn check_gate_digest(pool: &Pool, repo: Uuid, tenant: Uuid) -> Result<RequestDigest> {
    let mut client = pool.get().await?;
    match PgRefStoreCore.check_version(&mut client, repo, tenant, None, deadline()).await? {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => Ok(*version.digest()),
        VersionCheck::Unknown => Err(anyhow!("core gate disappeared")),
    }
}

fn operation(repo: Uuid, tenant: Uuid, lane_name: &str, sequence: i64, digest_byte: u8) -> OperationIdentity {
    OperationIdentity::new(
        repo,
        tenant,
        lane(lane_name),
        sequence,
        Uuid::new_v4(),
        RequestDigest::from_bytes([digest_byte; 32]),
    )
    .expect("valid operation identity")
}

async fn register_operation(pool: &Pool, identity: &OperationIdentity) -> Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let begun = PgRefStore.begin(&tx, identity, deadline()).await?;
    ensure!(begun.created, "new operation was not created");
    ensure!(begun.record.state() == OperationState::Pending, "operation is not pending");
    tx.commit().await?;
    Ok(())
}

async fn cancel_operation(pool: &Pool, identity: &OperationIdentity) -> Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    PgRefStore.cancel(&tx, identity, deadline()).await?;
    tx.commit().await?;
    Ok(())
}

fn hold_scope(repo: Uuid, tenant: Uuid, history: Uuid) -> HoldScope {
    HoldScope::new(repo, tenant, tenant, ArtifactHoldPurpose::RefPublication, format(), history, 1, 1)
        .expect("valid hold scope")
}

fn spec(namespace: &str, marker: u8, length: u64) -> ArtifactSpec {
    let digest = hex::encode(Sha256::digest([marker, length as u8, 0x5a]));
    ArtifactSpec::new(namespace, digest, length).expect("valid artifact spec")
}

fn content_spec(namespace: &str, bytes: &[u8]) -> ArtifactSpec {
    ArtifactSpec::new(namespace, hex::encode(Sha256::digest(bytes)), bytes.len() as u64).expect("valid content spec")
}

fn request(
    blob: &BlobStore,
    scope: HoldScope,
    operation: &OperationIdentity,
    request_id: Uuid,
    gate_digest: RequestDigest,
    artifacts: Vec<ArtifactSpec>,
) -> AcquireArtifactHoldsRequest {
    AcquireArtifactHoldsRequest::new(
        scope,
        operation.clone(),
        request_id,
        blob.backend_identity().clone(),
        Uuid::new_v4(),
        1,
        gate_digest,
        artifacts,
    )
    .expect("valid acquire request")
}

async fn acquire(
    pool: &Pool,
    blob: &BlobStore,
    request: &AcquireArtifactHoldsRequest,
) -> Result<AcquireOutcome, ArtifactHoldError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgArtifactHoldStore.acquire(&mut client, blob, request, deadline()).await
}

async fn acquire_receipt(pool: &Pool, scope: &HoldScope, request_id: Uuid) -> Result<AcquireLookup, ArtifactHoldError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgArtifactHoldStore.acquire_receipt(&mut client, scope, request_id, deadline()).await
}

async fn consume_receipt(
    pool: &Pool,
    scope: &HoldScope,
    acquire_request_id: Uuid,
    consume_request_id: Uuid,
) -> Result<ConsumeLookup, ArtifactHoldError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgArtifactHoldStore.consume_receipt(&mut client, scope, acquire_request_id, consume_request_id, deadline()).await
}

async fn ledger_counts(pool: &Pool, request_id: Uuid) -> Result<(i64, i64, i64)> {
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT (SELECT count(*) FROM artifact_hold_requests WHERE request_id=$1),
                    (SELECT count(*) FROM artifact_holds WHERE request_id=$1),
                    (SELECT count(*) FROM artifact_hold_consume_receipts WHERE request_id=$1)",
            &[&request_id],
        )
        .await?;
    Ok((row.get(0), row.get(1), row.get(2)))
}

async fn repo_usage(pool: &Pool, repo: Uuid) -> Result<(i64, i64, i64, i64)> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT hold_count,declared_bytes,logical_bytes,receipt_count FROM artifact_hold_repo_usage WHERE repository_id=$1",
            &[&repo],
        )
        .await?;
    Ok(row.map(|row| (row.get(0), row.get(1), row.get(2), row.get(3))).unwrap_or((0, 0, 0, 0)))
}

async fn tenant_usage(pool: &Pool, tenant: Uuid) -> Result<(i64, i64, i64, i64)> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT hold_count,declared_bytes,logical_bytes,receipt_count FROM artifact_hold_tenant_usage WHERE tenant_id=$1",
            &[&tenant],
        )
        .await?;
    Ok(row.map(|row| (row.get(0), row.get(1), row.get(2), row.get(3))).unwrap_or((0, 0, 0, 0)))
}

async fn shard_usage(pool: &Pool, shard: ShardId) -> Result<(i64, i64, i64, i64)> {
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT hold_count,declared_bytes,logical_bytes,receipt_count FROM artifact_hold_shards WHERE shard_id=$1",
            &[&shard.as_i32()],
        )
        .await?;
    Ok((row.get(0), row.get(1), row.get(2), row.get(3)))
}

static BLOB_ENV: Mutex<()> = Mutex::new(());

/// Fixture-scoped environment for the *production* profile factory
/// (`BlobProfile::from_env`). Nothing here is printed, and the guard is held
/// across profile construction and `BlobStore::open`, so no parallel test can
/// observe a half-written environment or a different process-wide budget.
fn fixture_blob_env(endpoint: &str) {
    unsafe {
        std::env::set_var("ROOTYARD_BLOB_DRIVER", "opendal");
        std::env::set_var("ROOTYARD_BLOB_ENDPOINT", endpoint);
        std::env::set_var("ROOTYARD_BLOB_REGION", "us-east-1");
        std::env::set_var("ROOTYARD_BLOB_ACCESS_KEY_ID", "fixture-access-key");
        std::env::set_var("ROOTYARD_BLOB_SECRET_ACCESS_KEY", "fixture-secret-key");
        std::env::set_var("ROOTYARD_BLOB_RETRY_MAX_TIMES", "0");
        std::env::set_var("ROOTYARD_BLOB_TIMEOUT_MS", "5000");
        std::env::set_var("ROOTYARD_BLOB_IO_TIMEOUT_MS", "5000");
        std::env::set_var("ROOTYARD_BLOB_ABORT_TIMEOUT_MS", "500");
        std::env::set_var("ROOTYARD_BLOB_MAX_OBJECT_BYTES", BLOB_MAX_OBJECT.to_string());
        std::env::remove_var("ROOTYARD_BLOB_SESSION_TOKEN");
        std::env::remove_var("ROOTYARD_BLOB_ROOT");
        std::env::remove_var("ROOTYARD_BLOB_DELETE");
        std::env::remove_var("ROOTYARD_BLOB_STAGING_BYTES");
        std::env::remove_var("ROOTYARD_BLOB_ACTIVE_UPLOADS");
        std::env::remove_var("ROOTYARD_BLOB_ACTIVE_READERS");
    }
}

/// Real S3 store opened through the production profile factory. Two calls that
/// differ only in `bucket` are the *same* provider/endpoint/root/region/account
/// with a different physical backend, and each store's identity is derived from
/// the profile whose operator was actually built.
fn store_for_bucket(endpoint: &str, bucket: &str) -> Result<BlobStore> {
    let guard = BLOB_ENV.lock().unwrap_or_else(|poison| poison.into_inner());
    fixture_blob_env(endpoint);
    unsafe {
        std::env::set_var("ROOTYARD_BLOB_SERVICE", "s3");
        std::env::set_var("ROOTYARD_BLOB_BUCKET", bucket);
        std::env::remove_var("ROOTYARD_BLOB_CONTAINER");
        std::env::remove_var("ROOTYARD_BLOB_ACCOUNT_NAME");
        std::env::remove_var("ROOTYARD_BLOB_ACCOUNT_KEY");
    }
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("fixture blob profile rejected: {error}"))?;
    let store = BlobStore::open(profile).map_err(|error| anyhow!("fixture blob store rejected: {error}"))?;
    drop(guard);
    Ok(store)
}

fn store_for_endpoint(endpoint: &str) -> Result<BlobStore> {
    store_for_bucket(endpoint, TEST_BUCKET)
}

#[cfg(feature = "blob-azblob")]
/// Negative-only Azure fixture: a real opened azblob store, used solely to prove
/// that a grant minted for the S3 fixture is refused. This never claims Azure
/// byte success, read-back or a working Azure publication.
fn store_for_azure_container(endpoint: &str, container: &str) -> Result<BlobStore> {
    let guard = BLOB_ENV.lock().unwrap_or_else(|poison| poison.into_inner());
    fixture_blob_env(endpoint);
    unsafe {
        std::env::set_var("ROOTYARD_BLOB_SERVICE", "azblob");
        std::env::set_var("ROOTYARD_BLOB_CONTAINER", container);
        std::env::set_var("ROOTYARD_BLOB_ACCOUNT_NAME", "fixtureaccount");
        std::env::set_var("ROOTYARD_BLOB_ACCOUNT_KEY", "Zml4dHVyZS1hY2NvdW50LWtleQ==");
        std::env::remove_var("ROOTYARD_BLOB_BUCKET");
    }
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("fixture azure profile rejected: {error}"))?;
    let store = BlobStore::open(profile).map_err(|error| anyhow!("fixture azure store rejected: {error}"))?;
    drop(guard);
    Ok(store)
}

/// Fixture-owned counting endpoint. It answers every accepted connection with
/// HTTP 503 and counts it. It never verifies provider bytes.
struct CountingEndpoint {
    address: String,
    accepted: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl CountingEndpoint {
    async fn start() -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let listener_address = listener.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { break };
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Ok(Self { address: format!("http://{listener_address}"), accepted, task })
    }

    fn endpoint(&self) -> &str {
        &self.address
    }

    fn count(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for CountingEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Owned fixture advisory barrier; dropping the sender releases it on error.
struct Barrier {
    release: Option<oneshot::Sender<()>>,
    unlock: Option<JoinHandle<()>>,
}

impl Barrier {
    async fn release(mut self) -> Result<()> {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(unlock) = self.unlock.take() {
            unlock.await.context("fixture barrier unlock task failed")?;
        }
        Ok(())
    }
}

impl Drop for Barrier {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

async fn acquire_barrier(pool: &Pool, key: i64) -> Result<Barrier> {
    let client = pool.get().await?;
    client.query_one("SELECT pg_advisory_lock($1)", &[&key]).await?;
    let (release, released) = oneshot::channel::<()>();
    let unlock = tokio::spawn(async move {
        let _ = released.await;
        let _ = client.query_one("SELECT pg_advisory_unlock($1)", &[&key]).await;
    });
    Ok(Barrier { release: Some(release), unlock: Some(unlock) })
}

async fn install_request_commit_barrier(pool: &Pool, key: i64) -> Result<()> {
    pool.get()
        .await?
        .batch_execute(&format!(
            "CREATE FUNCTION artifact_hold_request_park() RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN PERFORM pg_advisory_xact_lock({key}); RETURN NEW; END $$;
             CREATE CONSTRAINT TRIGGER artifact_hold_request_park AFTER INSERT ON artifact_hold_requests
               DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION artifact_hold_request_park();"
        ))
        .await?;
    Ok(())
}

async fn install_consume_commit_barrier(pool: &Pool, key: i64) -> Result<()> {
    pool.get()
        .await?
        .batch_execute(&format!(
            "CREATE FUNCTION artifact_hold_consume_park() RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN PERFORM pg_advisory_xact_lock({key}); RETURN NEW; END $$;
             CREATE CONSTRAINT TRIGGER artifact_hold_consume_park AFTER INSERT ON artifact_hold_consume_receipts
               DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION artifact_hold_consume_park();"
        ))
        .await?;
    Ok(())
}

async fn wait_for_commit_parked(pool: &Pool, pid: i32) -> Result<()> {
    let observer = pool.get().await?;
    tokio::time::timeout(OBSERVER_WAIT, async {
        loop {
            let parked: bool = observer
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                       WHERE pid=$1 AND state='active' AND wait_event_type='Lock'
                         AND query LIKE 'COMMIT%')",
                    &[&pid],
                )
                .await?
                .get(0);
            if parked {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("backend never parked in COMMIT on the fixture barrier")??;
    Ok(())
}

async fn wait_for_advisory_wait(pool: &Pool, pid: i32) -> Result<()> {
    let observer = pool.get().await?;
    tokio::time::timeout(OBSERVER_WAIT, async {
        loop {
            let waiting: bool = observer
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted)",
                    &[&pid],
                )
                .await?
                .get(0);
            if waiting {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("backend never waited on the fixture advisory lock")??;
    Ok(())
}

async fn wait_for_relation_wait(pool: &Pool, pid: i32, relation: &str) -> Result<()> {
    let observer = pool.get().await?;
    tokio::time::timeout(OBSERVER_WAIT, async {
        loop {
            let waiting: bool = observer
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_locks l JOIN pg_class c ON c.oid=l.relation
                       WHERE l.pid=$1 AND l.locktype='relation' AND NOT l.granted AND c.relname LIKE $2)",
                    &[&pid, &relation],
                )
                .await?
                .get(0);
            if waiting {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("backend never waited on the fixture table lock")??;
    Ok(())
}

async fn poll_acquire_found(
    pool: &Pool,
    scope: &HoldScope,
    request_id: Uuid,
) -> Result<rootyard::ref_store::artifact_hold::AcquireAck> {
    tokio::time::timeout(OBSERVER_WAIT, async {
        loop {
            match acquire_receipt(pool, scope, request_id).await? {
                AcquireLookup::Found(ack) => return Ok::<_, anyhow::Error>(ack),
                AcquireLookup::Unknown => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .context("acquire receipt never became visible after barrier release")?
}

async fn poll_consume_found(
    pool: &Pool,
    scope: &HoldScope,
    acquire_request_id: Uuid,
    consume_request_id: Uuid,
) -> Result<Vec<rootyard::ref_store::artifact_hold::ConsumeAck>> {
    tokio::time::timeout(OBSERVER_WAIT, async {
        loop {
            match consume_receipt(pool, scope, acquire_request_id, consume_request_id).await? {
                ConsumeLookup::Found(receipts) => return Ok::<_, anyhow::Error>(receipts),
                ConsumeLookup::Unknown => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .context("consume receipt never became visible after barrier release")?
}

async fn hold_state(pool: &Pool, hold_id: Uuid) -> Result<(String, i32)> {
    let row = pool
        .get()
        .await?
        .query_one("SELECT state,generation FROM artifact_holds WHERE hold_id=$1", &[&hold_id])
        .await?;
    Ok((row.get(0), row.get(1)))
}

fn assert_pg_guard(error: tokio_postgres::Error, message: &str) {
    let database = error.as_db_error().expect("expected a PostgreSQL trigger/check error");
    let code = database.code().code();
    assert!(
        code == "23514" || code == "P0001" || code == "23503",
        "unexpected SQLSTATE {code}: {}",
        database.message()
    );
    assert!(database.message().contains(message), "unexpected guard message: {}", database.message());
}

async fn fenced_repo(pool: &Pool) -> Result<(Uuid, Uuid, Uuid, RequestDigest)> {
    let (tenant, repo) = create_business(pool).await?;
    let history = Uuid::new_v4();
    let gate = initialize_gate(pool, repo, tenant, history, format()).await?;
    Ok((tenant, repo, history, gate))
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn fresh_batch_acquire_is_all_or_none_and_replay_returns_ack_without_grant_or_quota() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        assert_eq!(check_gate_digest(&pool, repo, tenant).await?, gate);
        let op = operation(repo, tenant, "batch", 1, 11);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let request_id = Uuid::new_v4();
        let batch = vec![spec("packs", 1, 10), spec("packs", 2, 20), spec("idxs", 3, 30)];
        let req = request(&blob, scope, &op, request_id, gate, batch);

        let (ack, grant) = match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Granted { ack, grant } => (ack, grant),
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh acquire unexpectedly replayed")),
        };
        assert_eq!(ack.artifact_count(), 3);
        assert_eq!(ack.request_id, request_id);
        assert_eq!(ack.request_digest, req.digest().as_hex());
        assert_eq!(ack.artifacts.iter().map(|hold| hold.slot).collect::<Vec<_>>(), vec![0, 1, 2]);
        assert_eq!(grant.request_id(), request_id);
        assert_eq!(grant.ack(), &ack);
        drop(grant);

        assert_eq!(ledger_counts(&pool, request_id).await?, (1, 3, 0));
        let repo_before = repo_usage(&pool, repo).await?;
        let tenant_before = tenant_usage(&pool, tenant).await?;
        let shard_before = shard_usage(&pool, ShardId::of(request_id)).await?;
        // Production charges exactly one retained ACK receipt per successful
        // ACQUIRE of a batch (independent of how many holds that batch has)
        // and exactly one receipt per CONSUME. So 3 holds + 0 consumes is
        // 3 holds, 60 declared bytes and 1 receipt - not 3 and not 0.
        assert_eq!(
            (repo_before.0, repo_before.1, repo_before.3),
            (3, 60, 1),
            "3 holds and exactly one acquire ACK receipt, no consume receipt yet"
        );
        assert_eq!(
            tenant_before,
            (3, 60, tenant_before.2, 1),
            "tenant: one acquire ACK receipt for the whole 3-hold batch"
        );
        assert_eq!(
            shard_before,
            (3, 60, shard_before.2, 1),
            "shard: one acquire ACK receipt for the whole 3-hold batch"
        );
        assert_eq!(endpoint.count(), 0, "acquire must not touch the provider");

        let replay = acquire(&pool, &blob, &req).await?;
        match replay {
            AcquireOutcome::Replayed { ack: replayed } => assert_eq!(replayed, ack),
            AcquireOutcome::Granted { .. } => return Err(anyhow!("exact replay minted another grant")),
        }
        assert_eq!(ledger_counts(&pool, request_id).await?, (1, 3, 0));
        assert_eq!(repo_usage(&pool, repo).await?, repo_before);
        assert_eq!(tenant_usage(&pool, tenant).await?, tenant_before);
        assert_eq!(shard_usage(&pool, ShardId::of(request_id)).await?, shard_before);

        let changed = request(
            &blob,
            scope,
            &op,
            request_id,
            gate,
            vec![spec("packs", 1, 10), spec("packs", 2, 20), spec("idxs", 4, 30)],
        );
        assert!(matches!(
            acquire(&pool, &blob, &changed).await,
            Err(ArtifactHoldError::DigestConflict { request_id: id }) if id == request_id
        ));
        assert_eq!(ledger_counts(&pool, request_id).await?, (1, 3, 0));

        let large = request(
            &blob,
            scope,
            &op,
            Uuid::new_v4(),
            gate,
            vec![spec("packs", 5, 10), spec("packs", 6, BLOB_MAX_OBJECT + 1)],
        );
        assert!(matches!(acquire(&pool, &blob, &large).await, Err(ArtifactHoldError::InvalidRequest(_))));
        assert_eq!(ledger_counts(&pool, large.request_id()).await?, (0, 0, 0));

        let too_many = (0..17).map(|index| spec("packs", index as u8, 1)).collect::<Vec<_>>();
        let blocked = AcquireArtifactHoldsRequest::new(
            scope,
            op.clone(),
            Uuid::new_v4(),
            blob.backend_identity().clone(),
            Uuid::new_v4(),
            1,
            gate,
            too_many,
        );
        assert!(matches!(blocked, Err(ArtifactHoldError::BatchTooLarge { artifacts: 17, max: 16 })));
        assert_eq!(repo_usage(&pool, repo).await?, repo_before);
        let full_batch = (0..16).map(|index| spec("packs", 100 + index as u8, 1)).collect::<Vec<_>>();
        let full = request(&blob, scope, &op, Uuid::new_v4(), gate, full_batch);
        let full_ack = match acquire(&pool, &blob, &full).await? {
            AcquireOutcome::Granted { ack, .. } => ack,
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh 16-artifact batch replayed")),
        };
        assert_eq!(full_ack.artifact_count(), 16);
        assert_eq!(ledger_counts(&pool, full.request_id()).await?, (1, 16, 0));
        let repo_full = repo_usage(&pool, repo).await?;
        assert_eq!(repo_full.0, repo_before.0 + 16, "every hold of the full batch is admitted");
        assert_eq!(
            repo_full.3,
            repo_before.3 + 1,
            "a second ACQUIRE batch charges exactly one more ACK receipt, not one per hold"
        );
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("fresh batch test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn global_request_identity_conflicts_across_repos_after_business_deletion() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "global", 1, 21);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let request_id = Uuid::new_v4();
        let req = request(&blob, scope, &op, request_id, gate, vec![spec("packs", 1, 7), spec("packs", 2, 9)]);
        let ack = match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Granted { ack, .. } => ack,
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh global request replayed")),
        };

        let deleted = pool.get().await?.execute("DELETE FROM repositories WHERE id=$1", &[&repo]).await?;
        assert_eq!(deleted, 1, "business repository must be deletable");
        assert_eq!(ledger_counts(&pool, request_id).await?, (1, 2, 0), "ledger has no business FK");
        assert_eq!(
            acquire_receipt(&pool, &scope, request_id).await?,
            AcquireLookup::Found(ack),
            "ACK must remain queryable after business deletion"
        );

        let different_digest =
            request(&blob, scope, &op, request_id, gate, vec![spec("packs", 1, 7), spec("packs", 3, 9)]);
        assert!(matches!(
            acquire(&pool, &blob, &different_digest).await,
            Err(ArtifactHoldError::DigestConflict { request_id: id }) if id == request_id
        ));

        let (other_tenant, other_repo) = create_business(&pool).await?;
        let other_history = Uuid::new_v4();
        let other_scope = hold_scope(other_repo, other_tenant, other_history);
        let other_op = operation(other_repo, other_tenant, "global-other", 1, 22);
        let cross_scope = request(
            &blob,
            other_scope,
            &other_op,
            request_id,
            RequestDigest::from_bytes([23; 32]),
            vec![spec("packs", 4, 11)],
        );
        assert!(matches!(
            acquire(&pool, &blob, &cross_scope).await,
            Err(ArtifactHoldError::IdentityConflict { request_id: id }) if id == request_id
        ));
        assert_eq!(ledger_counts(&pool, request_id).await?, (1, 2, 0));
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("global identity test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn registered_operation_and_scope_fences_are_exact() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "fence", 1, 31);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let baseline_repo = repo_usage(&pool, repo).await?;
        let baseline_tenant = tenant_usage(&pool, tenant).await?;

        let unregistered = operation(repo, tenant, "fence", 2, 32);
        let req = request(&blob, scope, &unregistered, Uuid::new_v4(), gate, vec![spec("packs", 1, 1)]);
        assert!(matches!(acquire(&pool, &blob, &req).await, Err(ArtifactHoldError::OperationNotPending { .. })));
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (0, 0, 0));

        let wrong_issuer = OperationIdentity::new(
            repo,
            Uuid::new_v4(),
            op.lane().clone(),
            op.sequence(),
            op.operation_id(),
            *op.digest(),
        )?;
        let req = request(&blob, scope, &wrong_issuer, Uuid::new_v4(), gate, vec![spec("packs", 2, 1)]);
        assert!(matches!(
            acquire(&pool, &blob, &req).await,
            Err(ArtifactHoldError::ScopeMismatch("parent operation identity"))
        ));
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (0, 0, 0));

        let wrong_lane =
            OperationIdentity::new(repo, tenant, lane("other-lane"), op.sequence(), op.operation_id(), *op.digest())?;
        let req = request(&blob, scope, &wrong_lane, Uuid::new_v4(), gate, vec![spec("packs", 3, 1)]);
        assert!(matches!(
            acquire(&pool, &blob, &req).await,
            Err(ArtifactHoldError::ScopeMismatch("parent operation identity"))
        ));

        let wrong_sequence = OperationIdentity::new(
            repo,
            tenant,
            op.lane().clone(),
            op.sequence() + 1,
            op.operation_id(),
            *op.digest(),
        )?;
        let req = request(&blob, scope, &wrong_sequence, Uuid::new_v4(), gate, vec![spec("packs", 4, 1)]);
        assert!(matches!(
            acquire(&pool, &blob, &req).await,
            Err(ArtifactHoldError::ScopeMismatch("parent operation identity"))
        ));

        let wrong_digest = OperationIdentity::new(
            repo,
            tenant,
            op.lane().clone(),
            op.sequence(),
            op.operation_id(),
            RequestDigest::from_bytes([33; 32]),
        )?;
        let req = request(&blob, scope, &wrong_digest, Uuid::new_v4(), gate, vec![spec("packs", 5, 1)]);
        assert!(matches!(
            acquire(&pool, &blob, &req).await,
            Err(ArtifactHoldError::ScopeMismatch("parent operation identity"))
        ));

        let other_history = Uuid::new_v4();
        let wrong_history_scope = hold_scope(repo, tenant, other_history);
        let req = request(&blob, wrong_history_scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 6, 1)]);
        assert!(matches!(
            acquire(&pool, &blob, &req).await,
            Err(ArtifactHoldError::ScopeMismatch("gate history incarnation"))
        ));

        let wrong_epoch_scope =
            HoldScope::new(repo, tenant, tenant, ArtifactHoldPurpose::RefPublication, format(), history, 2, 1)?;
        let req = request(&blob, wrong_epoch_scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 7, 1)]);
        assert!(matches!(
            acquire(&pool, &blob, &req).await,
            Err(ArtifactHoldError::ScopeMismatch("gate authority epoch"))
        ));

        let wrong_format_scope = HoldScope::new(
            repo,
            tenant,
            tenant,
            ArtifactHoldPurpose::RefPublication,
            GitObjectFormat::Sha256,
            history,
            1,
            1,
        )?;
        let req = request(&blob, wrong_format_scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 8, 1)]);
        assert!(matches!(
            acquire(&pool, &blob, &req).await,
            Err(ArtifactHoldError::ScopeMismatch("repository object format"))
        ));

        pool.get().await?.execute("UPDATE repositories SET state='ready' WHERE id=$1", &[&repo]).await?;
        let req = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 9, 1)]);
        assert!(matches!(acquire(&pool, &blob, &req).await, Err(ArtifactHoldError::Unsupported(_))));
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (0, 0, 0));
        assert_eq!(repo_usage(&pool, repo).await?, baseline_repo);
        assert_eq!(tenant_usage(&pool, tenant).await?, baseline_tenant);
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("operation/scope fence test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn cancel_before_register_blocks_acquire_without_rows_or_grant() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let scope = hold_scope(repo, tenant, history);
        let op = operation(repo, tenant, "cancel-first", 1, 41);

        cancel_operation(&pool, &op).await?;
        let first = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 1, 5)]);
        assert!(matches!(acquire(&pool, &blob, &first).await, Err(ArtifactHoldError::OperationNotPending { .. })));
        assert_eq!(ledger_counts(&pool, first.request_id()).await?, (0, 0, 0));

        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        let begun = PgRefStore.begin(&tx, &op, deadline()).await?;
        assert!(begun.created);
        assert_eq!(begun.record.state(), OperationState::Cancelled);
        tx.commit().await?;

        let second = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 2, 5)]);
        assert!(matches!(acquire(&pool, &blob, &second).await, Err(ArtifactHoldError::OperationNotPending { .. })));
        assert_eq!(ledger_counts(&pool, second.request_id()).await?, (0, 0, 0));
        assert_eq!(repo_usage(&pool, repo).await?, (0, 0, 0, 0));
        assert_eq!(tenant_usage(&pool, tenant).await?, (0, 0, 0, 0));
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("cancel-before-register test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn acquire_vs_cancel_two_client_barrier_keeps_hold_and_tombstone() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "acquire-cancel", 1, 51);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let req = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 1, 12), spec("packs", 2, 13)]);

        let key = 9_100_051_i64;
        let barrier = acquire_barrier(&pool, key).await?;
        install_request_commit_barrier(&pool, key).await?;
        let (pid_tx, pid_rx) = oneshot::channel();
        let acquire_pool = pool.clone();
        let acquire_blob = blob.clone();
        let acquire_req = req.clone();
        let acquire_task = tokio::spawn(async move {
            let mut client = acquire_pool.get().await?;
            let pid: i32 = client
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|error| ArtifactHoldError::Database(error.to_string()))?
                .get(0);
            pid_tx.send(pid).map_err(|_| ArtifactHoldError::Database("acquire pid receiver dropped".into()))?;
            PgArtifactHoldStore
                .acquire(&mut client, &acquire_blob, &acquire_req, deadline())
                .await
                .map_err(anyhow::Error::from)
        });
        let acquire_pid = pid_rx.await?;
        wait_for_commit_parked(&pool, acquire_pid).await?;
        assert!(!acquire_task.is_finished(), "acquire finished before the fixture barrier");

        let (cancel_pid_tx, cancel_pid_rx) = oneshot::channel();
        let cancel_pool = pool.clone();
        let cancel_op = op.clone();
        let cancel_task = tokio::spawn(async move {
            let mut client = cancel_pool.get().await?;
            let tx = client.transaction().await?;
            let pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            cancel_pid_tx.send(pid).map_err(|_| anyhow!("cancel pid receiver dropped"))?;
            let receipt = PgRefStore.cancel(&tx, &cancel_op, deadline()).await?;
            tx.commit().await?;
            Ok::<_, anyhow::Error>(receipt)
        });
        let cancel_pid = cancel_pid_rx.await?;
        wait_for_advisory_wait(&pool, cancel_pid).await?;
        assert!(!cancel_task.is_finished(), "cancel bypassed the shared 138 operation lock");

        barrier.release().await?;
        let granted = acquire_task.await.context("acquire task panicked")??;
        let ack = match granted {
            AcquireOutcome::Granted { ack, .. } => ack,
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("barrier acquire replayed unexpectedly")),
        };
        let cancelled = cancel_task.await.context("cancel task panicked")??;
        assert!(cancelled.tombstone_created);
        assert_eq!(cancelled.record.as_ref().map(|record| record.state()), Some(OperationState::Cancelled));

        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 0));
        for hold in ack.holds() {
            assert_eq!(hold_state(&pool, hold.hold_id).await?, ("active".into(), 1));
        }
        let row = pool
            .get()
            .await?
            .query_one(
                "SELECT state,(SELECT count(*) FROM ref_store_cancellations WHERE repository_id=$1 AND operation_id=$2)
                 FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2",
                &[&repo, &op.operation_id()],
            )
            .await?;
        assert_eq!(row.get::<_, String>(0), "cancelled");
        assert_eq!(row.get::<_, i64>(1), 1);
        assert_eq!(endpoint.count(), 0, "admission or cancellation attempted provider IO");
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("acquire-vs-cancel barrier test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn grant_consumes_once_and_receipt_queries_never_regrant() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "consume-once", 1, 61);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let req = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 7, 17), spec("idxs", 8, 19)]);
        let (ack, grant) = match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Granted { ack, grant } => (ack, grant),
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh consume request replayed")),
        };
        assert_eq!(grant.artifact_count(), 2);
        let mut client = pool.get().await?;
        let consumed = PgArtifactHoldStore.consume(&mut client, grant, deadline()).await?;
        drop(client);
        assert_eq!(consumed.artifact_count(), 2);
        assert_eq!(consumed.receipts().len(), 2);
        assert!(consumed.receipts().iter().all(|receipt| receipt.consume_request_id == consumed.consume_request_id()));
        let consume_request_id = consumed.consume_request_id();
        drop(consumed);

        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 2));
        let repo_counters = repo_usage(&pool, repo).await?;
        let tenant_counters = tenant_usage(&pool, tenant).await?;
        // One ACQUIRE ACK receipt for the 2-hold batch plus one CONSUME
        // receipt per consumed hold = 3 retained receipts.
        assert_eq!(repo_counters.3, 3, "repo: 1 acquire ACK receipt + 2 consume receipts");
        assert_eq!(tenant_counters.3, 3, "tenant: 1 acquire ACK receipt + 2 consume receipts");
        for hold in ack.holds() {
            assert_eq!(hold_state(&pool, hold.hold_id).await?, ("active".into(), 1));
        }

        assert_eq!(acquire_receipt(&pool, &scope, req.request_id()).await?, AcquireLookup::Found(ack.clone()));
        let replay = acquire(&pool, &blob, &req).await?;
        assert!(
            matches!(replay, AcquireOutcome::Replayed { ack: ref replayed } if replayed == &ack),
            "the replay must return the same immutable ACK without a second grant"
        );
        let receipts = poll_consume_found(&pool, &scope, req.request_id(), consume_request_id).await?;
        assert_eq!(receipts.len(), 2);
        assert!(receipts.iter().all(|receipt| receipt.consume_digest.len() == 64));
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 2));
        assert_eq!(repo_usage(&pool, repo).await?, repo_counters);
        assert_eq!(endpoint.count(), 0, "consume alone must not touch the provider");
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("consume-once test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn consume_vs_cancel_barrier_then_cancelled_parent_blocks_second_grant() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "consume-cancel", 1, 71);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let first = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 1, 21)]);
        let second = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 2, 22)]);
        let first_ack = match acquire(&pool, &blob, &first).await? {
            AcquireOutcome::Granted { ack, grant } => {
                // The grant is only handed out once its admission transaction is
                // committed; an independent lease must be obtainable right away.
                let client = pool.get().await?;
                drop(client);
                (ack, grant)
            }
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("first grant replayed")),
        };
        let second_ack = match acquire(&pool, &blob, &second).await? {
            AcquireOutcome::Granted { ack, grant } => (ack, grant),
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("second grant replayed")),
        };
        let (first_ack, first_grant) = first_ack;
        let (second_ack, second_grant) = second_ack;

        let key = 9_100_071_i64;
        let barrier = acquire_barrier(&pool, key).await?;
        install_consume_commit_barrier(&pool, key).await?;
        let (pid_tx, pid_rx) = oneshot::channel();
        let consume_pool = pool.clone();
        let consume_task = tokio::spawn(async move {
            let mut client = consume_pool.get().await?;
            let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            pid_tx.send(pid).map_err(|_| anyhow!("consume pid receiver dropped"))?;
            PgArtifactHoldStore.consume(&mut client, first_grant, deadline()).await.map_err(anyhow::Error::from)
        });
        let consume_pid = pid_rx.await?;
        wait_for_commit_parked(&pool, consume_pid).await?;
        assert!(!consume_task.is_finished());

        let (cancel_pid_tx, cancel_pid_rx) = oneshot::channel();
        let cancel_pool = pool.clone();
        let cancel_op = op.clone();
        let cancel_task = tokio::spawn(async move {
            let mut client = cancel_pool.get().await?;
            let tx = client.transaction().await?;
            let pid: i32 = tx.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            cancel_pid_tx.send(pid).map_err(|_| anyhow!("cancel pid receiver dropped"))?;
            let receipt = PgRefStore.cancel(&tx, &cancel_op, deadline()).await?;
            tx.commit().await?;
            Ok::<_, anyhow::Error>(receipt)
        });
        let cancel_pid = cancel_pid_rx.await?;
        wait_for_advisory_wait(&pool, cancel_pid).await?;
        assert!(!cancel_task.is_finished(), "cancel bypassed consume's 138 lock prefix");

        barrier.release().await?;
        let consumed = consume_task.await.context("consume task panicked")??;
        let consume_request_id = consumed.consume_request_id();
        assert_eq!(consumed.artifact_count(), 1);
        drop(consumed);
        let cancelled = cancel_task.await.context("cancel task panicked")??;
        assert!(cancelled.tombstone_created);
        assert_eq!(cancelled.record.as_ref().map(|record| record.state()), Some(OperationState::Cancelled));

        assert_eq!(ledger_counts(&pool, first.request_id()).await?, (1, 1, 1));
        assert_eq!(ledger_counts(&pool, second.request_id()).await?, (1, 1, 0));
        let mut client = pool.get().await?;
        let blocked = PgArtifactHoldStore
            .consume(&mut client, second_grant, deadline())
            .await
            .expect_err("cancelled parent must burn the second grant without a receipt");
        assert!(matches!(&blocked, ArtifactHoldError::OperationNotPending { .. }), "unexpected: {blocked}");
        assert_eq!(ledger_counts(&pool, second.request_id()).await?, (1, 1, 0));
        assert_eq!(hold_state(&pool, second_ack.holds()[0].hold_id).await?, ("active".into(), 1));
        // Two ACQUIRE batches charged two ACK receipts (one per batch, not
        // one per hold); consuming the first grant's single hold added one
        // CONSUME receipt, so 3 receipts are retained. The cancelled second
        // grant was never consumed and added none.
        assert_eq!(repo_usage(&pool, repo).await?.3, 3, "repo: 2 acquire ACK receipts + 1 consume receipt");
        let receipts = poll_consume_found(&pool, &scope, first.request_id(), consume_request_id).await?;
        assert_eq!(receipts.len(), 1);
        assert_eq!(first_ack.holds().len(), 1);
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("consume-vs-cancel barrier test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn unknown_acquire_commit_returns_no_grant_and_replay_returns_old_ack() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "unknown-acquire", 1, 81);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let req = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 1, 31)]);

        let key = 9_100_081_i64;
        let barrier = acquire_barrier(&pool, key).await?;
        install_request_commit_barrier(&pool, key).await?;
        let (pid_tx, pid_rx) = oneshot::channel();
        let acquire_pool = pool.clone();
        let acquire_blob = blob.clone();
        let acquire_req = req.clone();
        let acquire_task = tokio::spawn(async move {
            let mut client =
                acquire_pool.get().await.map_err(|error| ArtifactHoldError::Database(error.to_string()))?;
            let pid: i32 = client
                .query_one("SELECT pg_backend_pid()", &[])
                .await
                .map_err(|error| ArtifactHoldError::Database(error.to_string()))?
                .get(0);
            pid_tx.send(pid).map_err(|_| ArtifactHoldError::Database("acquire pid receiver dropped".into()))?;
            PgArtifactHoldStore
                .acquire(&mut client, &acquire_blob, &acquire_req, TokioInstant::now() + UNKNOWN_COMMIT_DEADLINE)
                .await
        });
        let pid = pid_rx.await?;
        wait_for_commit_parked(&pool, pid).await?;
        let error = tokio::time::timeout(OBSERVER_WAIT, acquire_task)
            .await
            .context("timed-out acquire never returned Unknown")?
            .context("acquire task panicked")?;
        match error {
            Err(ArtifactHoldError::AcquireUnknown { request_id }) => assert_eq!(request_id, req.request_id()),
            Ok(_) => return Err(anyhow!("a sent COMMIT without acknowledgement returned a grant")),
            Err(other) => return Err(anyhow!("unexpected acquire error: {other}")),
        }
        assert_eq!(endpoint.count(), 0, "unknown acquire attempted provider IO");
        assert_eq!(
            acquire_receipt(&pool, &scope, req.request_id()).await?,
            AcquireLookup::Unknown,
            "uncommitted row must not be visible before the parked COMMIT lands"
        );

        barrier.release().await?;
        let landed = poll_acquire_found(&pool, &scope, req.request_id()).await?;
        assert_eq!(landed.request_id, req.request_id());
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 1, 0));
        let replay = acquire(&pool, &blob, &req).await?;
        match replay {
            AcquireOutcome::Replayed { ack } => assert_eq!(ack, landed),
            AcquireOutcome::Granted { .. } => return Err(anyhow!("unknown retry minted a new grant")),
        }
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 1, 0));
        assert_eq!(repo_usage(&pool, repo).await?.0, 1);
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("unknown acquire test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

fn typed_pool(schema: &str, max_size: usize, application_name: &str) -> Result<Pool> {
    let url = database_url();
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!(
        "-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000 -c application_name={application_name}"
    ));
    Ok(Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(max_size)
        .build()?)
}

async fn wait_for_commit_parked_app(pool: &Pool, application_name: &str) -> Result<()> {
    let observer = pool.get().await?;
    tokio::time::timeout(OBSERVER_WAIT, async {
        loop {
            let parked: bool = observer
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity
                       WHERE application_name=$1 AND state='active' AND wait_event_type='Lock'
                         AND query LIKE 'COMMIT%')",
                    &[&application_name],
                )
                .await?
                .get(0);
            if parked {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("protected-upload consume backend never parked in COMMIT")??;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn unknown_consume_commit_returns_no_token_and_receipt_lookup_is_readonly() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let task_schema = schema.clone();
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "unknown-consume", 1, 91);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let bytes = b"artifact-hold-unknown-consume".to_vec();
        let req = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![content_spec("packs", &bytes)]);
        let grant = match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Granted { grant, .. } => grant,
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh consume request replayed")),
        };

        let temp = tempfile::tempdir()?;
        let source_path = temp.path().join("artifact.bin");
        std::fs::write(&source_path, &bytes)?;
        let sources = vec![UploadSource::new(source_path)];

        let key = 9_100_091_i64;
        let barrier = acquire_barrier(&pool, key).await?;
        install_consume_commit_barrier(&pool, key).await?;
        let upload_pool = typed_pool(&task_schema, 1, "hold_unknown_consume")?;
        let task_pool = upload_pool.clone();
        let uploader = ProtectedUploader::new(blob.clone());
        let task = tokio::spawn(async move {
            let result = uploader
                .consume_and_upload(&task_pool, grant, &sources, StdInstant::now() + UNKNOWN_COMMIT_DEADLINE)
                .await;
            drop(temp);
            result
        });
        wait_for_commit_parked_app(&pool, "hold_unknown_consume").await?;
        assert!(!task.is_finished());
        assert_eq!(endpoint.count(), 0, "provider IO happened before the consume ACK");
        let result = tokio::time::timeout(OBSERVER_WAIT, task)
            .await
            .context("timed-out protected consume never returned Unknown")?
            .context("protected consume task panicked")?;
        let (consume_request_id, hold_ids) = match result {
            Err(ProtectedUploadError::Consume(ArtifactHoldError::ConsumeUnknown { consume_request_id, hold_ids })) => {
                (consume_request_id, hold_ids)
            }
            Err(other) => return Err(anyhow!("unexpected protected upload error: {other}")),
            Ok(_) => return Err(anyhow!("a sent consume COMMIT without acknowledgement returned a token")),
        };
        assert_eq!(hold_ids.len(), 1);
        assert_eq!(endpoint.count(), 0, "unknown consume attempted provider IO");
        assert_eq!(consume_receipt(&pool, &scope, req.request_id(), consume_request_id).await?, ConsumeLookup::Unknown);
        drop(
            tokio::time::timeout(Duration::from_secs(2), upload_pool.get())
                .await
                .context("consume pool lease was not returned before provider IO")??,
        );

        barrier.release().await?;
        let receipts = poll_consume_found(&pool, &scope, req.request_id(), consume_request_id).await?;
        assert_eq!(receipts.len(), 1);
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 1, 1));
        assert_eq!(hold_state(&pool, receipts[0].hold_id).await?, ("active".into(), 1));
        assert_eq!(
            repo_usage(&pool, repo).await?.3,
            2,
            "repo: 1 acquire ACK receipt + 1 consumed (unknown-acked) hold receipt"
        );
        assert_eq!(endpoint.count(), 0, "receipt lookup must never produce a token or IO");
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("unknown consume test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn quota_boundaries_refuse_atomically_without_rows_or_refunds() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        // SYNTHETIC COUNTER SEED: only retained admission counters are written
        // directly, clearly labelled. Every request/hold/grant under test is
        // minted by the real API. Counters are never reset, refunded, or their
        // guard triggers disabled.
        let repo_seed = rootyard::ref_store::artifact_hold::REPO_MAX_HOLDS - 1;
        let tenant_seed = rootyard::ref_store::artifact_hold::TENANT_MAX_HOLDS - 1;
        let shard_seed = rootyard::ref_store::artifact_hold::SHARD_MAX_HOLDS - 1;

        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "quota-repo", 1, 101);
        register_operation(&pool, &op).await?;
        pool.get()
            .await?
            .execute(
                "INSERT INTO artifact_hold_repo_usage(repository_id,tenant_id,hold_count) VALUES($1,$2,$3)",
                &[&repo, &tenant, &repo_seed],
            )
            .await?;
        let req = request(
            &blob,
            hold_scope(repo, tenant, history),
            &op,
            Uuid::new_v4(),
            gate,
            vec![spec("packs", 1, 1), spec("packs", 2, 1)],
        );
        assert!(matches!(
            acquire(&pool, &blob, &req).await,
            Err(ArtifactHoldError::QuotaExceeded {
                scope: rootyard::ref_store::artifact_hold::HoldQuotaScope::Repository,
                resource: rootyard::ref_store::artifact_hold::HoldQuotaResource::Holds
            })
        ));
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (0, 0, 0));
        assert_eq!(repo_usage(&pool, repo).await?.0, repo_seed);

        let (tenant2, repo2, history2, gate2) = fenced_repo(&pool).await?;
        let op2 = operation(repo2, tenant2, "quota-tenant", 1, 102);
        register_operation(&pool, &op2).await?;
        pool.get()
            .await?
            .execute(
                "INSERT INTO artifact_hold_tenant_usage(tenant_id,hold_count) VALUES($1,$2)",
                &[&tenant2, &tenant_seed],
            )
            .await?;
        let req2 = request(
            &blob,
            hold_scope(repo2, tenant2, history2),
            &op2,
            Uuid::new_v4(),
            gate2,
            vec![spec("packs", 3, 1), spec("packs", 4, 1)],
        );
        assert!(matches!(
            acquire(&pool, &blob, &req2).await,
            Err(ArtifactHoldError::QuotaExceeded {
                scope: rootyard::ref_store::artifact_hold::HoldQuotaScope::Tenant,
                resource: rootyard::ref_store::artifact_hold::HoldQuotaResource::Holds
            })
        ));
        assert_eq!(ledger_counts(&pool, req2.request_id()).await?, (0, 0, 0));
        assert_eq!(tenant_usage(&pool, tenant2).await?.0, tenant_seed);

        let (tenant3, repo3, history3, gate3) = fenced_repo(&pool).await?;
        let op3 = operation(repo3, tenant3, "quota-shard", 1, 103);
        register_operation(&pool, &op3).await?;
        let req3 = request(
            &blob,
            hold_scope(repo3, tenant3, history3),
            &op3,
            Uuid::new_v4(),
            gate3,
            vec![spec("packs", 5, 1), spec("packs", 6, 1)],
        );
        let shard = ShardId::of(req3.request_id());
        pool.get()
            .await?
            .execute(
                "UPDATE artifact_hold_shards SET hold_count=$2,updated_at=clock_timestamp() WHERE shard_id=$1",
                &[&shard.as_i32(), &shard_seed],
            )
            .await?;
        assert!(matches!(
            acquire(&pool, &blob, &req3).await,
            Err(ArtifactHoldError::QuotaExceeded {
                scope: rootyard::ref_store::artifact_hold::HoldQuotaScope::Shard,
                resource: rootyard::ref_store::artifact_hold::HoldQuotaResource::Holds
            })
        ));
        assert_eq!(ledger_counts(&pool, req3.request_id()).await?, (0, 0, 0));
        assert_eq!(shard_usage(&pool, shard).await?.0, shard_seed);
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("quota boundary test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn quota_race_with_distinct_connections_has_exactly_one_winner() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op_a = operation(repo, tenant, "quota-race", 1, 111);
        let op_b = operation(repo, tenant, "quota-race", 2, 112);
        register_operation(&pool, &op_a).await?;
        register_operation(&pool, &op_b).await?;

        // SYNTHETIC COUNTER SEED: all three retained scopes are one below their
        // exact bound, so two distinct connections race for one remaining hold.
        let repo_seed = rootyard::ref_store::artifact_hold::REPO_MAX_HOLDS - 1;
        let tenant_seed = rootyard::ref_store::artifact_hold::TENANT_MAX_HOLDS - 1;
        let shard_seed = rootyard::ref_store::artifact_hold::SHARD_MAX_HOLDS - 1;
        let target = ShardId::of(Uuid::new_v4());
        let mut request_a = Uuid::new_v4();
        while ShardId::of(request_a) != target {
            request_a = Uuid::new_v4();
        }
        let mut request_b = Uuid::new_v4();
        while ShardId::of(request_b) != target || request_b == request_a {
            request_b = Uuid::new_v4();
        }
        pool.get()
            .await?
            .execute(
                "INSERT INTO artifact_hold_repo_usage(repository_id,tenant_id,hold_count) VALUES($1,$2,$3)",
                &[&repo, &tenant, &repo_seed],
            )
            .await?;
        pool.get()
            .await?
            .execute(
                "INSERT INTO artifact_hold_tenant_usage(tenant_id,hold_count) VALUES($1,$2)",
                &[&tenant, &tenant_seed],
            )
            .await?;
        pool.get()
            .await?
            .execute(
                "UPDATE artifact_hold_shards SET hold_count=$2,updated_at=clock_timestamp() WHERE shard_id=$1",
                &[&target.as_i32(), &shard_seed],
            )
            .await?;

        let scope = hold_scope(repo, tenant, history);
        let req_a = request(&blob, scope, &op_a, request_a, gate, vec![spec("packs", 1, 1)]);
        let req_b = request(&blob, scope, &op_b, request_b, gate, vec![spec("packs", 2, 1)]);

        // Both contenders are parked at one fixture admission barrier, on two
        // distinct PostgreSQL backends, before either may attempt admission.
        // Two bare `tokio::spawn`s could run sequentially and pass vacuously.
        let key = 9_100_111_i64;
        let admission_barrier = acquire_barrier(&pool, key).await?;
        let (pid_a_tx, pid_a_rx) = oneshot::channel();
        let (pid_b_tx, pid_b_rx) = oneshot::channel();
        let pool_a = pool.clone();
        let pool_b = pool.clone();
        let blob_a = blob.clone();
        let blob_b = blob.clone();
        let task_a = tokio::spawn(async move {
            let mut client = pool_a.get().await?;
            let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            pid_a_tx.send(pid).map_err(|_| anyhow!("quota race A pid receiver dropped"))?;
            client.query_one("SELECT pg_advisory_lock_shared($1)", &[&key]).await?;
            PgArtifactHoldStore.acquire(&mut client, &blob_a, &req_a, deadline()).await.map_err(anyhow::Error::from)
        });
        let task_b = tokio::spawn(async move {
            let mut client = pool_b.get().await?;
            let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            pid_b_tx.send(pid).map_err(|_| anyhow!("quota race B pid receiver dropped"))?;
            client.query_one("SELECT pg_advisory_lock_shared($1)", &[&key]).await?;
            PgArtifactHoldStore.acquire(&mut client, &blob_b, &req_b, deadline()).await.map_err(anyhow::Error::from)
        });
        let pid_a = pid_a_rx.await?;
        let pid_b = pid_b_rx.await?;
        assert_ne!(pid_a, pid_b, "the two contenders must run on distinct PostgreSQL backends");
        wait_for_advisory_wait(&pool, pid_a).await?;
        wait_for_advisory_wait(&pool, pid_b).await?;
        let parked: i64 = pool
            .get()
            .await?
            .query_one(
                "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND pid = ANY($1)",
                &[&vec![pid_a, pid_b]],
            )
            .await?
            .get(0);
        assert_eq!(parked, 2, "both contenders must be parked at the admission barrier");
        admission_barrier.release().await?;

        let outcome_a = task_a.await.context("quota race A panicked")?;
        let outcome_b = task_b.await.context("quota race B panicked")?;
        let mut granted = 0_i64;
        let mut refused = 0_i64;
        for outcome in [outcome_a, outcome_b] {
            match outcome {
                Ok(AcquireOutcome::Granted { .. }) => granted += 1,
                Ok(AcquireOutcome::Replayed { .. }) => {
                    return Err(anyhow!("fresh quota contender unexpectedly replayed"));
                }
                // The contender body reports its typed refusal through `anyhow`,
                // so downcast to keep the exact typed quota assertion instead of
                // accepting any error as a refusal.
                Err(error) => match error.downcast_ref::<ArtifactHoldError>() {
                    Some(ArtifactHoldError::QuotaExceeded {
                        scope: rootyard::ref_store::artifact_hold::HoldQuotaScope::Repository,
                        resource: rootyard::ref_store::artifact_hold::HoldQuotaResource::Holds,
                    }) => refused += 1,
                    _ => return Err(anyhow!("unexpected quota race outcome: {error}")),
                },
            }
        }
        assert_eq!((granted, refused), (1, 1), "exactly one distinct-connection admission must win");
        let ledgers_a = ledger_counts(&pool, request_a).await?;
        let ledgers_b = ledger_counts(&pool, request_b).await?;
        assert_eq!(ledgers_a.0 + ledgers_b.0, 1);
        assert_eq!(ledgers_a.1 + ledgers_b.1, 1);
        assert_eq!(ledgers_a.2 + ledgers_b.2, 0);
        assert_eq!(repo_usage(&pool, repo).await?.0, repo_seed + 1);
        assert_eq!(tenant_usage(&pool, tenant).await?.0, tenant_seed + 1);
        assert_eq!(shard_usage(&pool, target).await?.0, shard_seed + 1);
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("quota race test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

async fn expect_guard(
    pool: &Pool,
    sql: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    message: &str,
) -> Result<()> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    let error = tx.execute(sql, params).await.expect_err("direct DML guard did not fire");
    assert_pg_guard(error, message);
    tx.rollback().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn no_refunds_or_ledger_release_after_cancel_and_owner_tenant_deletion() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "no-refund", 1, 121);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let req = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 1, 41), spec("packs", 2, 42)]);
        let (ack, grant) = match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Granted { ack, grant } => (ack, grant),
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh no-refund request replayed")),
        };
        let mut client = pool.get().await?;
        let consumed = PgArtifactHoldStore.consume(&mut client, grant, deadline()).await?;
        drop(client);
        let consume_request_id = consumed.consume_request_id();
        drop(consumed);
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 2));
        let repo_before = repo_usage(&pool, repo).await?;
        let tenant_before = tenant_usage(&pool, tenant).await?;
        let shard_before = shard_usage(&pool, ShardId::of(req.request_id())).await?;
        // The 2-hold acquire charged one ACK receipt; consuming both holds
        // charged 2 more. Nothing below may refund any of the 3 receipts.
        assert_eq!(
            (repo_before.0, repo_before.3),
            (2, 3),
            "repo: 2 holds + 1 acquire ACK receipt + 2 consume receipts"
        );
        assert_eq!(
            (tenant_before.0, tenant_before.3),
            (2, 3),
            "tenant: 2 holds + 1 acquire ACK receipt + 2 consume receipts"
        );
        assert_eq!(
            (shard_before.0, shard_before.3),
            (2, 3),
            "shard: 2 holds + 1 acquire ACK receipt + 2 consume receipts"
        );

        cancel_operation(&pool, &op).await?;
        let denied = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 3, 43)]);
        assert!(matches!(acquire(&pool, &blob, &denied).await, Err(ArtifactHoldError::OperationNotPending { .. })));
        assert_eq!(ledger_counts(&pool, denied.request_id()).await?, (0, 0, 0));
        assert_eq!(repo_usage(&pool, repo).await?, repo_before);
        assert_eq!(tenant_usage(&pool, tenant).await?, tenant_before);
        assert_eq!(shard_usage(&pool, ShardId::of(req.request_id())).await?, shard_before);

        assert_eq!(pool.get().await?.execute("DELETE FROM repositories WHERE id=$1", &[&repo]).await?, 1);
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 2));
        assert_eq!(repo_usage(&pool, repo).await?, repo_before);
        assert_eq!(tenant_usage(&pool, tenant).await?, tenant_before);
        assert_eq!(shard_usage(&pool, ShardId::of(req.request_id())).await?, shard_before);

        assert_eq!(pool.get().await?.execute("DELETE FROM users WHERE id=$1", &[&tenant]).await?, 1);
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 2));
        assert_eq!(repo_usage(&pool, repo).await?, repo_before);
        assert_eq!(tenant_usage(&pool, tenant).await?, tenant_before);
        assert_eq!(shard_usage(&pool, ShardId::of(req.request_id())).await?, shard_before);

        assert_eq!(acquire_receipt(&pool, &scope, req.request_id()).await?, AcquireLookup::Found(ack.clone()));
        let receipts = poll_consume_found(&pool, &scope, req.request_id(), consume_request_id).await?;
        assert_eq!(receipts.len(), 2);
        let replay = acquire(&pool, &blob, &req).await?;
        match replay {
            AcquireOutcome::Replayed { ack: replayed } => assert_eq!(replayed, ack),
            AcquireOutcome::Granted { .. } => return Err(anyhow!("deleted owner retry minted a grant")),
        }
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 2));
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("no-refund/delete test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn direct_update_delete_and_expiry_attempts_are_refused() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "immutable", 1, 131);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let req = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 1, 51)]);
        let (ack, grant) = match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Granted { ack, grant } => (ack, grant),
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh guard request replayed")),
        };
        let mut client = pool.get().await?;
        let consumed = PgArtifactHoldStore.consume(&mut client, grant, deadline()).await?;
        let hold_id = consumed.receipts()[0].hold_id;
        drop(client);
        drop(consumed);
        let shard = ShardId::of(req.request_id());

        expect_guard(
            &pool,
            "UPDATE artifact_hold_requests SET ack_body='{}' WHERE request_id=$1",
            &[&req.request_id()],
            "immutable",
        )
        .await?;
        expect_guard(
            &pool,
            "DELETE FROM artifact_hold_requests WHERE request_id=$1",
            &[&req.request_id()],
            "permanent",
        )
        .await?;
        expect_guard(&pool, "UPDATE artifact_holds SET state='released' WHERE hold_id=$1", &[&hold_id], "immutable")
            .await?;
        expect_guard(&pool, "DELETE FROM artifact_holds WHERE hold_id=$1", &[&hold_id], "permanent").await?;
        expect_guard(
            &pool,
            "UPDATE artifact_hold_consume_receipts SET body='{}' WHERE hold_id=$1",
            &[&hold_id],
            "immutable",
        )
        .await?;
        expect_guard(&pool, "DELETE FROM artifact_hold_consume_receipts WHERE hold_id=$1", &[&hold_id], "permanent")
            .await?;
        expect_guard(
            &pool,
            "UPDATE artifact_hold_repo_usage SET hold_count=hold_count-1 WHERE repository_id=$1",
            &[&repo],
            "cannot decrease",
        )
        .await?;
        expect_guard(&pool, "DELETE FROM artifact_hold_repo_usage WHERE repository_id=$1", &[&repo], "permanent")
            .await?;
        expect_guard(
            &pool,
            "UPDATE artifact_hold_tenant_usage SET hold_count=hold_count-1 WHERE tenant_id=$1",
            &[&tenant],
            "cannot decrease",
        )
        .await?;
        expect_guard(&pool, "DELETE FROM artifact_hold_tenant_usage WHERE tenant_id=$1", &[&tenant], "permanent")
            .await?;
        expect_guard(
            &pool,
            "UPDATE artifact_hold_shards SET hold_count=hold_count-1 WHERE shard_id=$1",
            &[&shard.as_i32()],
            "cannot decrease",
        )
        .await?;
        expect_guard(
            &pool,
            "UPDATE artifact_hold_shards SET shard_id=(shard_id+1)%64 WHERE shard_id=$1",
            &[&shard.as_i32()],
            "identity is immutable",
        )
        .await?;
        expect_guard(&pool, "DELETE FROM artifact_hold_shards WHERE shard_id=$1", &[&shard.as_i32()], "permanent")
            .await?;

        let expiry_columns: i64 = pool
            .get()
            .await?
            .query_one(
                "SELECT count(*) FROM information_schema.columns
                 WHERE table_schema=current_schema() AND table_name LIKE 'artifact_hold%'
                   AND column_name IN ('expires_at','expiry','released_at','retired_at')",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(expiry_columns, 0, "no TTL/release column may exist");
        assert!(
            rootyard::ref_store::artifact_hold::AcquireAck::decode("{}").is_err(),
            "a malformed stored ACK body must never decode as a replay"
        );
        let fk_client = pool.get().await?;
        let hold_fk: String = fk_client
            .query_one(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint
                 WHERE conrelid='artifact_holds'::regclass AND contype='f'",
                &[],
            )
            .await?
            .get(0);
        assert!(hold_fk.contains("(request_id, repository_id, tenant_id)"), "unexpected hold FK: {hold_fk}");
        let receipt_fk: String = fk_client
            .query_one(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint
                 WHERE conrelid='artifact_hold_consume_receipts'::regclass AND contype='f'",
                &[],
            )
            .await?
            .get(0);
        assert!(receipt_fk.contains("(request_id, hold_id)"), "unexpected receipt FK: {receipt_fk}");
        drop(fk_client);
        let capabilities = ArtifactHoldCapabilities::artifact_hold_increment();
        assert!(!capabilities.artifact_release);
        assert!(!capabilities.ttl_expiry);
        assert!(!capabilities.retirement);
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 1, 1));
        assert_eq!(hold_state(&pool, ack.holds()[0].hold_id).await?, ("active".into(), 1));
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("direct guard/expiry test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn table_share_cut_parks_admission_and_exposes_only_acked_holds() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op_a = operation(repo, tenant, "backup-cut", 1, 141);
        let op_b = operation(repo, tenant, "backup-cut", 2, 142);
        register_operation(&pool, &op_a).await?;
        register_operation(&pool, &op_b).await?;
        let scope = hold_scope(repo, tenant, history);
        let first =
            request(&blob, scope, &op_a, Uuid::new_v4(), gate, vec![spec("packs", 1, 61), spec("packs", 2, 62)]);
        let second = request(&blob, scope, &op_b, Uuid::new_v4(), gate, vec![spec("packs", 3, 63)]);
        let first_ack = match acquire(&pool, &blob, &first).await? {
            AcquireOutcome::Granted { ack, .. } => ack,
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("ACK-first acquire replayed")),
        };
        assert_eq!(ledger_counts(&pool, first.request_id()).await?, (1, 2, 0));
        for hold in first_ack.holds() {
            assert_eq!(hold_state(&pool, hold.hold_id).await?, ("active".into(), 1));
        }

        // Fixture-owned backup-style cut over every new 141 table. This is only
        // a lock regression for admission-vs-cut; it is NOT the backup CLI and
        // does not qualify format-17 restore.
        let mut cut_client = pool.get().await?;
        let cut = cut_client.transaction().await?;
        cut.batch_execute(
            "LOCK TABLE artifact_hold_shards,artifact_hold_requests,artifact_holds,
                        artifact_hold_consume_receipts,artifact_hold_repo_usage,artifact_hold_tenant_usage
             IN SHARE MODE",
        )
        .await?;
        let prestate: (i64, i64, i64) = {
            let row = cut
                .query_one(
                    "SELECT (SELECT count(*) FROM artifact_hold_requests),
                            (SELECT count(*) FROM artifact_holds),
                            (SELECT count(*) FROM artifact_hold_consume_receipts)",
                    &[],
                )
                .await?;
            (row.get(0), row.get(1), row.get(2))
        };
        assert_eq!(prestate, (1, 2, 0), "cut must see the full ACK-first hold rows");

        let (pid_tx, pid_rx) = oneshot::channel();
        let acquire_pool = pool.clone();
        let acquire_blob = blob.clone();
        let acquire_req = second.clone();
        let task = tokio::spawn(async move {
            let mut client = acquire_pool.get().await?;
            let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            pid_tx.send(pid).map_err(|_| anyhow!("cut acquire pid receiver dropped"))?;
            PgArtifactHoldStore
                .acquire(&mut client, &acquire_blob, &acquire_req, deadline())
                .await
                .map_err(anyhow::Error::from)
        });
        let pid = pid_rx.await?;
        wait_for_relation_wait(&pool, pid, "artifact_hold%").await?;
        assert!(!task.is_finished(), "acquire finished against a SHARE table cut");
        assert_eq!(endpoint.count(), 0, "admission against the cut attempted provider IO");
        let during: (i64, i64, i64) = {
            let row = cut
                .query_one(
                    "SELECT (SELECT count(*) FROM artifact_hold_requests),
                            (SELECT count(*) FROM artifact_holds),
                            (SELECT count(*) FROM artifact_hold_consume_receipts)",
                    &[],
                )
                .await?;
            (row.get(0), row.get(1), row.get(2))
        };
        assert_eq!(during, prestate, "uncommitted admission must not leak into the cut");

        cut.rollback().await?;
        drop(cut_client);
        let granted = task.await.context("cut acquire task panicked")??;
        assert!(matches!(granted, AcquireOutcome::Granted { .. }));
        assert_eq!(ledger_counts(&pool, second.request_id()).await?, (1, 1, 0));
        let post: (i64, i64, i64) = {
            let row = pool
                .get()
                .await?
                .query_one(
                    "SELECT (SELECT count(*) FROM artifact_hold_requests),
                            (SELECT count(*) FROM artifact_holds),
                            (SELECT count(*) FROM artifact_hold_consume_receipts)",
                    &[],
                )
                .await?;
            (row.get(0), row.get(1), row.get(2))
        };
        assert_eq!(post, (2, 3, 0), "released cut must observe the full committed batch");
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("table SHARE cut test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

// ---------------------------------------------------------------------------
// Luna P2 regressions: physical backend binding, full scope, real pending IO
// pool lease, synchronized quota admission, stable consume id/recovery with
// corrupt-ledger fixtures, and TRUNCATE denial.
//
// Everything below reuses the real API (opened stores, registered 138 pending
// operations, the real core gate, the real ledger adapter). The only directly
// written SQL is (a) clearly labelled synthetic admission-counter seeds, and
// (b) clearly labelled CORRUPT ledger *fixtures* built by INSERT only, from
// fresh ids derived from actually stored rows. No trigger is ever disabled, no
// immutable row is updated, no 138 pending row is fabricated and no grant is
// forged. A corrupt fixture is never described as a legitimate ACK.
// ---------------------------------------------------------------------------

/// Fixture-owned provider endpoint that parks the *first* accepted provider
/// request and later answers every parked request with HTTP 503. It proves that
/// a real provider request was in flight while the observer ran, and that a 503
/// can never mint a byte receipt. It does NOT prove provider S3 success or
/// read-back; that stays a separate Root qualifier.
struct StallingEndpoint {
    address: String,
    accepted: Arc<AtomicUsize>,
    started: Arc<tokio::sync::watch::Sender<bool>>,
    release: Arc<tokio::sync::watch::Sender<bool>>,
    task: JoinHandle<()>,
}

impl StallingEndpoint {
    async fn start() -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let listener_address = listener.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::watch::channel(false).0);
        let release = Arc::new(tokio::sync::watch::channel(false).0);
        let counter = Arc::clone(&accepted);
        let started_task = Arc::clone(&started);
        let release_task = Arc::clone(&release);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { break };
                let ordinal = counter.fetch_add(1, Ordering::SeqCst);
                let started = Arc::clone(&started_task);
                let mut released = release_task.subscribe();
                tokio::spawn(async move {
                    if ordinal == 0 {
                        let _ = started.send(true);
                    }
                    // Park the provider request with no response at all until the
                    // test releases the endpoint.
                    while !*released.borrow() {
                        if released.changed().await.is_err() {
                            break;
                        }
                    }
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Ok(Self { address: format!("http://{listener_address}"), accepted, started, release, task })
    }

    fn endpoint(&self) -> &str {
        &self.address
    }

    fn count(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    async fn wait_for_first_request(&self) -> Result<()> {
        let mut started = self.started.subscribe();
        tokio::time::timeout(OBSERVER_WAIT, async move {
            while !*started.borrow() {
                started.changed().await.map_err(|_| anyhow!("fixture endpoint was dropped"))?;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("protected uploader never issued a provider request")??;
        Ok(())
    }

    fn release(&self) {
        let _ = self.release.send(true);
    }
}

impl Drop for StallingEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Re-key an *actually stored* ACK into a fresh-id fixture value: new global
/// request id, new stable consume id, new hold ids, new attempt ids, recomputed
/// shard. Nothing else changes, so the caller can apply exactly one deliberate
/// corruption. This is fixture data, never a legitimate ACK.
fn rekey_ack(source: &AcquireAck) -> AcquireAck {
    let request_id = Uuid::new_v4();
    let mut ack = source.clone();
    ack.request_id = request_id;
    ack.consume_request_id = Uuid::new_v4();
    ack.shard = ShardId::of(request_id).as_i32();
    for (index, hold) in ack.artifacts.iter_mut().enumerate() {
        hold.hold_id = Uuid::new_v4();
        hold.slot = index as i32;
        hold.artifact.attempt_id = Uuid::new_v4();
    }
    ack
}

/// INSERT-only corrupt-ledger fixture: the request row and its stored body come
/// from `request` + `body`, the hold rows from `holds` (same request/hold ids,
/// possibly a deliberately different physical identity). No UPDATE, no DELETE,
/// no disabled trigger and no legitimate ACK claim.
async fn insert_fixture_ledger(pool: &Pool, request: &AcquireAck, body: &str, holds: &AcquireAck) -> Result<()> {
    let artifact_count = i32::try_from(request.artifacts.len())?;
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute(
        "INSERT INTO artifact_hold_requests(
             request_id,request_digest,repository_id,tenant_id,owner_id,purpose,object_format,
             history_incarnation,authority_epoch,group_epoch,operation_issuer_id,operation_lane,
             operation_sequence,operation_id,operation_digest,gate_revision,gate_digest,shard_id,
             backend_identity,consume_request_id,artifact_count,declared_bytes,logical_bytes,ack_body)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)",
        &[
            &request.request_id,
            &request.request_digest,
            &request.repository_id,
            &request.tenant_id,
            &request.owner_id,
            &request.purpose.as_str(),
            &request.object_format.as_str(),
            &request.history_incarnation,
            &request.authority_epoch,
            &request.group_epoch,
            &request.issuer_id,
            &request.lane,
            &request.sequence,
            &request.operation_id,
            &request.operation_digest,
            &request.gate_revision,
            &request.gate_digest,
            &request.shard,
            &request.backend_identity,
            &request.consume_request_id,
            &artifact_count,
            &request.declared_bytes,
            &request.logical_bytes,
            &body,
        ],
    )
    .await?;
    for hold in &holds.artifacts {
        let content_length = i64::try_from(hold.artifact.length)?;
        tx.execute(
            "INSERT INTO artifact_holds(
                 hold_id,request_id,slot,repository_id,tenant_id,owner_id,purpose,operation_id,
                 operation_digest,provider,backend_identity,storage_tenant_id,authority_id,
                 authority_generation,attempt_id,namespace,sha256,content_length,declared_bytes,
                 logical_bytes)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
            &[
                &hold.hold_id,
                &request.request_id,
                &hold.slot,
                &request.repository_id,
                &request.tenant_id,
                &request.owner_id,
                &request.purpose.as_str(),
                &request.operation_id,
                &request.operation_digest,
                &hold.artifact.provider,
                &hold.artifact.backend_identity,
                &hold.artifact.tenant_id,
                &hold.artifact.authority_id,
                &hold.artifact.authority_generation,
                &hold.artifact.attempt_id,
                &hold.artifact.namespace,
                &hold.artifact.sha256,
                &content_length,
                &hold.declared_bytes,
                &hold.logical_bytes,
            ],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Derive one corrupt consume-receipt fixture from a *real* stored receipt: the
/// scope/parent/gate/digest fields come from the fixture ACK (so the only
/// disagreement is the one the caller then introduces), the hold slot decides
/// the hold id and slot.
fn derive_fixture_receipt(source: &ConsumeAck, ack: &AcquireAck, slot: usize) -> ConsumeAck {
    let hold = &ack.artifacts[slot];
    let mut receipt = source.clone();
    receipt.consume_request_id = ack.consume_request_id;
    receipt.request_id = ack.request_id;
    receipt.consume_digest = ack.consume_digest().as_hex();
    receipt.hold_id = hold.hold_id;
    receipt.slot = hold.slot;
    receipt.repository_id = ack.repository_id;
    receipt.tenant_id = ack.tenant_id;
    receipt.owner_id = ack.owner_id;
    receipt.purpose = ack.purpose;
    receipt.object_format = ack.object_format;
    receipt.history_incarnation = ack.history_incarnation;
    receipt.authority_epoch = ack.authority_epoch;
    receipt.group_epoch = ack.group_epoch;
    receipt.issuer_id = ack.issuer_id;
    receipt.lane = ack.lane.clone();
    receipt.sequence = ack.sequence;
    receipt.operation_id = ack.operation_id;
    receipt.operation_digest = ack.operation_digest.clone();
    receipt.gate_revision = ack.gate_revision;
    receipt.gate_digest = ack.gate_digest.clone();
    receipt.consumed_at_unix_micros = 1_700_000_000_000_000;
    receipt.artifact = hold.artifact.clone();
    receipt
}

/// INSERT-only corrupt consume receipt row (fresh ids, never a legitimate ACK).
/// The stored body is passed separately so a fixture can also disagree with its
/// own duplicated columns (for example the recorded consumption instant).
async fn insert_fixture_receipt(pool: &Pool, receipt: &ConsumeAck, body: &str) -> Result<()> {
    pool.get()
        .await?
        .execute(
            "INSERT INTO artifact_hold_consume_receipts(
                 hold_id,request_id,consume_request_id,consume_digest,slot,repository_id,tenant_id,
                 owner_id,operation_id,operation_digest,gate_revision,gate_digest,body,
                 consumed_at_unix_micros)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            &[
                &receipt.hold_id,
                &receipt.request_id,
                &receipt.consume_request_id,
                &receipt.consume_digest,
                &receipt.slot,
                &receipt.repository_id,
                &receipt.tenant_id,
                &receipt.owner_id,
                &receipt.operation_id,
                &receipt.operation_digest,
                &receipt.gate_revision,
                &receipt.gate_digest,
                &body,
                &receipt.consumed_at_unix_micros,
            ],
        )
        .await?;
    Ok(())
}

/// One typed, non-`Found`, non-`Unknown` ledger-integrity refusal.
fn assert_ledger_integrity<T: std::fmt::Debug>(result: Result<T, ArtifactHoldError>, what: &str) {
    match result {
        Err(ArtifactHoldError::LedgerIntegrity(field)) => assert!(!field.is_empty(), "{what}: empty integrity field"),
        other => panic!("{what}: expected a typed ledger-integrity refusal, got {other:?}"),
    }
}

/// Aggregate ledger row counts of every new table, used to prove that a refused
/// TRUNCATE/DELETE left each table byte-for-byte unchanged.
async fn ledger_totals(pool: &Pool) -> Result<(i64, i64, i64, i64, i64, i64)> {
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT (SELECT count(*) FROM artifact_hold_requests),
                    (SELECT count(*) FROM artifact_holds),
                    (SELECT count(*) FROM artifact_hold_consume_receipts),
                    (SELECT count(*) FROM artifact_hold_shards),
                    (SELECT count(*) FROM artifact_hold_repo_usage),
                    (SELECT count(*) FROM artifact_hold_tenant_usage)",
            &[],
        )
        .await?;
    Ok((row.get(0), row.get(1), row.get(2), row.get(3), row.get(4), row.get(5)))
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn foreign_backend_grants_are_refused_before_consume_pool_and_provider_io() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let task_schema = schema.clone();
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        // Same provider, endpoint, root, region and account; only the bucket
        // differs. Both stores are really opened through the production profile
        // factory, so their physical identities must differ.
        let store_a = store_for_bucket(endpoint.endpoint(), TEST_BUCKET)?;
        let store_b = store_for_bucket(endpoint.endpoint(), OTHER_BUCKET)?;
        assert_eq!(store_a.provider().as_str(), store_b.provider().as_str());
        assert_eq!(store_a.backend_identity().as_hex().len(), 64);
        assert_eq!(store_b.backend_identity().as_hex().len(), 64);
        assert_ne!(
            store_a.backend_identity().as_hex(),
            store_b.backend_identity().as_hex(),
            "a different bucket on the same provider must be a different physical backend"
        );

        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "backend-binding", 1, 151);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let req = request(&store_a, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 1, 11), spec("packs", 2, 12)]);
        let (ack, grant) = match acquire(&pool, &store_a, &req).await? {
            AcquireOutcome::Granted { ack, grant } => (ack, grant),
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh backend-binding acquire replayed")),
        };
        // The typed identity can only be produced by an actually opened store.
        let opened: &BlobBackendIdentity = store_a.backend_identity();
        assert_eq!(
            ack.backend_identity_hex(),
            opened.as_hex(),
            "the ACK must record the actually opened store, not a caller-chosen identity"
        );
        assert_ne!(opened.as_hex(), store_b.backend_identity().as_hex());
        assert_eq!(grant.consume_request_id(), ack.consume_request_id());

        let repo_before = repo_usage(&pool, repo).await?;
        let tenant_before = tenant_usage(&pool, tenant).await?;
        let shard_before = shard_usage(&pool, ShardId::of(req.request_id())).await?;
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 0));

        // The only pooled connection is checked out, so a refusal that even
        // tried to take a connection would block here instead of returning the
        // typed backend refusal. Correct source count + nonexistent paths make
        // sure the refusal cannot be `SourceCount`/`MissingSource` either.
        let busy_pool = typed_pool(&task_schema, 1, "hold_foreign_pool")?;
        let busy = busy_pool.get().await?;
        let sources = vec![
            UploadSource::new("/nonexistent/artifact-hold-foreign-0"),
            UploadSource::new("/nonexistent/artifact-hold-foreign-1"),
        ];
        assert_eq!(sources.len(), grant.artifact_count());
        let foreign = ProtectedUploader::new(store_b.clone());
        let refused = tokio::time::timeout(
            Duration::from_secs(5),
            foreign.consume_and_upload(&busy_pool, grant, &sources, std_deadline()),
        )
        .await
        .context("foreign-backend refusal waited for the busy pool instead of refusing first")?;
        let error = refused.expect_err("a same-provider/other-bucket store must never consume a foreign grant");
        assert!(matches!(error, ProtectedUploadError::ForeignBackend), "unexpected refusal: {error}");
        drop(busy);

        assert_eq!(
            ledger_counts(&pool, req.request_id()).await?,
            (1, 2, 0),
            "a rejected foreign backend must not insert a consume receipt"
        );
        assert_eq!(repo_usage(&pool, repo).await?, repo_before, "no extra admission charge");
        assert_eq!(tenant_usage(&pool, tenant).await?, tenant_before);
        assert_eq!(shard_usage(&pool, ShardId::of(req.request_id())).await?, shard_before);
        assert_eq!(endpoint.count(), 0, "a foreign grant must not open any provider connection");

        // The acquire path refuses a request bound to another opened store
        // before any database transaction, row or provider connection.
        let (other_tenant, other_repo, other_history, other_gate) = fenced_repo(&pool).await?;
        let other_op = operation(other_repo, other_tenant, "backend-binding-acquire", 1, 152);
        register_operation(&pool, &other_op).await?;
        let wrong = request(
            &store_b,
            hold_scope(other_repo, other_tenant, other_history),
            &other_op,
            Uuid::new_v4(),
            other_gate,
            vec![spec("packs", 3, 13)],
        );
        assert!(
            matches!(acquire(&pool, &store_a, &wrong).await, Err(ArtifactHoldError::BackendMismatch)),
            "a request bound to another bucket must be refused before any database work"
        );
        assert_eq!(ledger_counts(&pool, wrong.request_id()).await?, (0, 0, 0));
        assert_eq!(repo_usage(&pool, other_repo).await?, (0, 0, 0, 0));
        assert_eq!(tenant_usage(&pool, other_tenant).await?, (0, 0, 0, 0));
        assert_eq!(endpoint.count(), 0);

        #[cfg(feature = "blob-azblob")]
        {
            // Negative-only Azure case: a really opened azblob store must refuse
            // an S3-bound grant. No Azure byte success or read-back is claimed.
            let azure = store_for_azure_container(endpoint.endpoint(), "artifact-hold-azure-container")?;
            assert_eq!(azure.provider().as_str(), "azblob");
            assert_ne!(azure.backend_identity().as_hex(), store_a.backend_identity().as_hex());
            let (az_tenant, az_repo, az_history, az_gate) = fenced_repo(&pool).await?;
            let az_op = operation(az_repo, az_tenant, "backend-binding-azure", 2, 153);
            register_operation(&pool, &az_op).await?;
            let az_req = request(
                &store_a,
                hold_scope(az_repo, az_tenant, az_history),
                &az_op,
                Uuid::new_v4(),
                az_gate,
                vec![spec("packs", 4, 14)],
            );
            let az_grant = match acquire(&pool, &store_a, &az_req).await? {
                AcquireOutcome::Granted { grant, .. } => grant,
                AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh azure-negative acquire replayed")),
            };
            let uploader = ProtectedUploader::new(azure);
            let refused = tokio::time::timeout(
                Duration::from_secs(5),
                uploader.consume_and_upload(
                    &busy_pool,
                    az_grant,
                    &[UploadSource::new("/nonexistent/artifact-hold-azure")],
                    std_deadline(),
                ),
            )
            .await
            .context("azure foreign-backend refusal waited for the pool")?;
            assert!(
                matches!(
                    refused.expect_err("an azblob store must refuse an S3-bound grant"),
                    ProtectedUploadError::ForeignBackend
                ),
                "unexpected azure refusal"
            );
            assert_eq!(ledger_counts(&pool, az_req.request_id()).await?, (1, 1, 0));
            assert_eq!(repo_usage(&pool, az_repo).await?.0, 1, "azure-negative grant stays admitted and unrefunded");
            assert_eq!(endpoint.count(), 0);
        }
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("foreign backend test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn full_scope_fences_and_unrepresentable_purpose_are_typed_refusals() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "scope-full", 1, 161);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let baseline_repo = repo_usage(&pool, repo).await?;
        let baseline_tenant = tenant_usage(&pool, tenant).await?;
        assert_eq!((baseline_repo.0, baseline_tenant.0), (0, 0));

        // Another tenant cannot address this repository at all, so no hold,
        // receipt or counter may be created for it.
        let foreign_tenant = Uuid::new_v4();
        let tenant_scope =
            HoldScope::new(repo, foreign_tenant, tenant, ArtifactHoldPurpose::RefPublication, format(), history, 1, 1)?;
        let req = request(&blob, tenant_scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 1, 1)]);
        assert!(matches!(acquire(&pool, &blob, &req).await, Err(ArtifactHoldError::RepositoryNotFound)));
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (0, 0, 0));
        assert_eq!(repo_usage(&pool, repo).await?, baseline_repo);
        assert_eq!(tenant_usage(&pool, tenant).await?, baseline_tenant);
        assert_eq!(tenant_usage(&pool, foreign_tenant).await?, (0, 0, 0, 0));

        // The group epoch is part of the trusted scope and of the core gate
        // proof; a different value is refused before any row is written.
        let group_scope =
            HoldScope::new(repo, tenant, tenant, ArtifactHoldPurpose::RefPublication, format(), history, 1, 2)?;
        let req = request(&blob, group_scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 2, 2)]);
        assert!(matches!(acquire(&pool, &blob, &req).await, Err(ArtifactHoldError::ScopeMismatch("gate group epoch"))));
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (0, 0, 0));
        assert_eq!(repo_usage(&pool, repo).await?, baseline_repo);
        assert_eq!(tenant_usage(&pool, tenant).await?, baseline_tenant);
        assert_eq!(endpoint.count(), 0, "scope refusals must not touch the provider");

        // Real admitted history, then owner-mismatched receipt reads.
        let req = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 3, 3), spec("packs", 4, 4)]);
        let (ack, grant) = match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Granted { ack, grant } => (ack, grant),
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh scope-fence acquire replayed")),
        };
        let consume_id = ack.consume_request_id();
        drop(grant);
        let repo_after = repo_usage(&pool, repo).await?;
        let tenant_after = tenant_usage(&pool, tenant).await?;
        let shard_after = shard_usage(&pool, ShardId::of(req.request_id())).await?;
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 0));

        let owner_scope =
            HoldScope::new(repo, tenant, Uuid::new_v4(), ArtifactHoldPurpose::RefPublication, format(), history, 1, 1)?;
        // Owner is a trusted producer identity. A different fresh producer may
        // be valid, but it must never rewrite this globally stable request.
        // Keep every other semantic field identical (the fixture request helper
        // generates a new authority id and would obscure this specific fence).
        let changed_owner = AcquireArtifactHoldsRequest::new(
            owner_scope,
            req.operation().clone(),
            req.request_id(),
            req.backend_identity().clone(),
            req.authority_id(),
            req.authority_generation(),
            *req.expected_gate_digest(),
            req.artifacts().to_vec(),
        )?;
        assert!(matches!(
            acquire(&pool, &blob, &changed_owner).await,
            Err(ArtifactHoldError::DigestConflict { request_id }) if request_id == req.request_id()
        ));
        assert!(matches!(
            acquire_receipt(&pool, &owner_scope, req.request_id()).await,
            Err(ArtifactHoldError::ScopeMismatch("request owner"))
        ));
        assert!(matches!(
            consume_receipt(&pool, &owner_scope, req.request_id(), consume_id).await,
            Err(ArtifactHoldError::ScopeMismatch("request owner"))
        ));
        assert_eq!(
            acquire_receipt(&pool, &scope, req.request_id()).await?,
            AcquireLookup::Found(ack.clone()),
            "the trusted owner still resolves the same immutable ACK"
        );
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 0));
        assert_eq!(repo_usage(&pool, repo).await?, repo_after);
        assert_eq!(tenant_usage(&pool, tenant).await?, tenant_after);
        assert_eq!(shard_usage(&pool, ShardId::of(req.request_id())).await?, shard_after);
        assert_eq!(endpoint.count(), 0);

        // Purpose: this slice has exactly one production variant, so an invalid
        // purpose is unrepresentable in Rust and no enum value is invented here.
        // The durable bounded-value CHECK is therefore asserted directly with a
        // clearly invalid plain SQL value, and the row must never land.
        assert!(ArtifactHoldPurpose::parse("not-a-production-purpose").is_err());
        let bounded_checks: i64 = pool
            .get()
            .await?
            .query_one(
                "SELECT count(*) FROM pg_constraint WHERE contype='c'
                   AND conrelid IN ('artifact_hold_requests'::regclass,'artifact_holds'::regclass)
                   AND pg_get_constraintdef(oid) LIKE '%ref_publication%'",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(bounded_checks, 2, "both request and hold tables must bound the stored purpose");
        let totals_before = ledger_totals(&pool).await?;
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        let invalid = Uuid::new_v4();
        let invalid_consume = Uuid::new_v4();
        let error = tx
            .execute(
                "INSERT INTO artifact_hold_requests(
                     request_id,request_digest,repository_id,tenant_id,owner_id,purpose,object_format,
                     history_incarnation,authority_epoch,group_epoch,operation_issuer_id,operation_lane,
                     operation_sequence,operation_id,operation_digest,gate_revision,gate_digest,shard_id,
                     backend_identity,consume_request_id,artifact_count,declared_bytes,logical_bytes,ack_body)
                 SELECT $2,request_digest,repository_id,tenant_id,owner_id,'not-a-production-purpose',object_format,
                     history_incarnation,authority_epoch,group_epoch,operation_issuer_id,operation_lane,
                     operation_sequence,operation_id,operation_digest,gate_revision,gate_digest,shard_id,
                     backend_identity,$3,artifact_count,declared_bytes,logical_bytes,ack_body
                 FROM artifact_hold_requests WHERE request_id=$1",
                &[&req.request_id(), &invalid, &invalid_consume],
            )
            .await
            .expect_err("an unbounded stored purpose must be refused by the SQL CHECK");
        assert_pg_guard(error, "purpose_check");
        tx.rollback().await?;
        assert_eq!(ledger_totals(&pool).await?, totals_before);
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 0));
        assert_eq!(repo_usage(&pool, repo).await?, repo_after);
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("full scope fence test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn pool_lease_and_consume_ack_are_visible_while_a_provider_write_is_parked() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let task_schema = schema.clone();
    let outcome = tokio::spawn(async move {
        let endpoint = StallingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "pool-lease", 1, 171);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let bytes = b"artifact-hold-parked-provider-write".to_vec();
        let req = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![content_spec("packs", &bytes)]);
        let (ack, grant) = match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Granted { ack, grant } => (ack, grant),
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh pool-lease acquire replayed")),
        };
        // The stable consume id is readable *before* the grant is moved.
        let consume_id = ack.consume_request_id();
        assert_eq!(grant.consume_request_id(), consume_id);
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 1, 0));

        let temp = tempfile::tempdir()?;
        let source = temp.path().join("artifact.bin");
        std::fs::write(&source, &bytes)?;
        let sources = vec![UploadSource::new(source)];
        let upload_pool = typed_pool(&task_schema, 1, "hold_pool_lease")?;
        let task_pool = upload_pool.clone();
        let uploader = ProtectedUploader::new(blob.clone());
        let task =
            tokio::spawn(async move { uploader.consume_and_upload(&task_pool, grant, &sources, std_deadline()).await });

        // A real provider request must arrive and then stay parked.
        endpoint.wait_for_first_request().await?;
        assert!(!task.is_finished(), "the uploader must still be inside provider IO");
        assert_eq!(
            ledger_counts(&pool, req.request_id()).await?,
            (1, 1, 1),
            "the consume ACK row must be durable before any provider IO"
        );

        // The uploader's max_size=1 pool must already have its single lease
        // back: an independent borrow and query must succeed while the provider
        // write is still parked, and the same committed consume row is visible.
        let observer = tokio::time::timeout(Duration::from_secs(5), upload_pool.get())
            .await
            .context("max_size=1 pool lease was not returned before provider IO")??;
        let one: i32 = observer.query_one("SELECT 1", &[]).await?.get(0);
        assert_eq!(one, 1);
        let visible: i64 = observer
            .query_one(
                "SELECT count(*) FROM artifact_hold_consume_receipts WHERE consume_request_id=$1",
                &[&consume_id],
            )
            .await?
            .get(0);
        assert_eq!(visible, 1, "the consume ACK must be visible while the provider write is parked");
        drop(observer);
        assert!(endpoint.count() >= 1, "at least one provider request must have been attempted");

        // Release with HTTP 503: no byte receipt, but the receipt row and the
        // permanent hold stay retained and are never charged twice.
        endpoint.release();
        let result = tokio::time::timeout(OBSERVER_WAIT, task)
            .await
            .context("parked upload never returned after the fixture 503")?
            .context("parked upload task panicked")?;
        let error = result.expect_err("a 503 provider write must never mint a byte receipt");
        assert!(matches!(error, ProtectedUploadError::Blob { .. }), "unexpected error: {error}");
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 1, 1));
        assert_eq!(hold_state(&pool, ack.holds()[0].hold_id).await?, ("active".into(), 1));
        let repo_after = repo_usage(&pool, repo).await?;
        assert_eq!(repo_after.0, 1);
        assert_eq!(repo_after.3, 2, "1 acquire ACK receipt + one durable consume receipt, never a double charge");
        drop(temp);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("pool lease / parked provider test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn stable_consume_id_recovery_and_corrupt_ledger_fixtures_are_typed() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "stable-consume", 1, 191);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let req = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 1, 21), spec("packs", 2, 22)]);
        let (ack, grant) = match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Granted { ack, grant } => (ack, grant),
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh stable-consume acquire replayed")),
        };
        // The stable consume id is allocated by the first acquire and is
        // readable, and queryable, *before* the grant is moved.
        let stable_id = ack.consume_request_id();
        assert!(!stable_id.is_nil());
        assert_ne!(stable_id, req.request_id());
        assert_eq!(grant.consume_request_id(), stable_id);
        assert_eq!(ack.consume_request_id(), stable_id);
        assert_eq!(acquire_receipt(&pool, &scope, req.request_id()).await?, AcquireLookup::Found(ack.clone()));
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 0), "no receipt before consume");

        // A consume COMMIT whose acknowledgement is lost: typed Unknown, no
        // token, stable id preserved, and the same id resolves the receipts
        // after the parked COMMIT lands. The future yielded no token either way.
        let key = 9_100_191_i64;
        let barrier = acquire_barrier(&pool, key).await?;
        install_consume_commit_barrier(&pool, key).await?;
        let (pid_tx, pid_rx) = oneshot::channel();
        let consume_pool = pool.clone();
        let task = tokio::spawn(async move {
            let mut client = consume_pool.get().await?;
            let pid: i32 = client.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
            pid_tx.send(pid).map_err(|_| anyhow!("stable-consume pid receiver dropped"))?;
            PgArtifactHoldStore
                .consume(&mut client, grant, TokioInstant::now() + UNKNOWN_COMMIT_DEADLINE)
                .await
                .map_err(anyhow::Error::from)
        });
        let pid = pid_rx.await?;
        wait_for_commit_parked(&pool, pid).await?;
        let result = tokio::time::timeout(OBSERVER_WAIT, task)
            .await
            .context("timed-out consume never returned Unknown")?
            .context("consume task panicked")?;
        let expected_holds = ack.holds().iter().map(|hold| hold.hold_id).collect::<Vec<_>>();
        match result {
            // The consume worker reports its typed refusal through `anyhow`; the
            // downcast keeps the exact `ConsumeUnknown` payload assertions.
            Err(error) => match error.downcast_ref::<ArtifactHoldError>() {
                Some(ArtifactHoldError::ConsumeUnknown { consume_request_id, hold_ids }) => {
                    assert_eq!(consume_request_id, &stable_id, "Unknown must carry the stable consume id");
                    assert_eq!(hold_ids, &expected_holds);
                }
                _ => return Err(anyhow!("a sent consume COMMIT without acknowledgement returned {error:?}")),
            },
            other => return Err(anyhow!("a sent consume COMMIT without acknowledgement returned {other:?}")),
        }
        assert_eq!(
            consume_receipt(&pool, &scope, req.request_id(), stable_id).await?,
            ConsumeLookup::Unknown,
            "an uncommitted receipt set is the only legitimate Unknown"
        );
        barrier.release().await?;
        let receipts = poll_consume_found(&pool, &scope, req.request_id(), stable_id).await?;
        assert_eq!(receipts.len(), 2, "the full acquire batch must be receipted, never a partial batch");
        assert_eq!(receipts.iter().map(|receipt| receipt.slot).collect::<Vec<_>>(), vec![0, 1]);
        assert!(receipts.iter().all(|receipt| receipt.consume_request_id == stable_id));
        assert_eq!(receipts.iter().map(|receipt| receipt.hold_id).collect::<Vec<_>>(), expected_holds);
        assert!(receipts.iter().all(|receipt| receipt.consume_digest == ack.consume_digest().as_hex()));
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 2));
        let repo_receipts = repo_usage(&pool, repo).await?.3;
        assert_eq!(repo_receipts, 3, "1 acquire ACK receipt + one consume receipt per hold, never a double charge");
        for hold in ack.holds() {
            assert_eq!(hold_state(&pool, hold.hold_id).await?, ("active".into(), 1));
        }
        let replay = acquire(&pool, &blob, &req).await?;
        match replay {
            AcquireOutcome::Replayed { ack: replayed } => {
                assert_eq!(replayed, ack, "the replay must return the same immutable ACK and id");
                assert_eq!(replayed.consume_request_id(), stable_id);
            }
            AcquireOutcome::Granted { .. } => return Err(anyhow!("replay minted another grant")),
        }
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 2), "no extra rows or charge");
        expect_guard(
            &pool,
            "UPDATE artifact_hold_consume_receipts SET consumed_at_unix_micros=consumed_at_unix_micros+1 WHERE hold_id=$1",
            &[&receipts[0].hold_id],
            "immutable",
        )
        .await?;

        // CORRUPT LEDGER FIXTURES: INSERT-only, fresh ids derived from the real
        // stored ACK/receipts above, no trigger disabled and no immutable row
        // updated. Each fixture is deliberately inconsistent and is NEVER a
        // legitimate ACK; the real read path must answer with a typed
        // ledger-integrity error, never `Found` and never `Unknown`.
        let totals_before = ledger_totals(&pool).await?;
        let repo_before = repo_usage(&pool, repo).await?;
        let tenant_before = tenant_usage(&pool, tenant).await?;
        let shard_before = shard_usage(&pool, ShardId::of(req.request_id())).await?;
        let receipt_source = receipts[0].clone();

        // (a) the body claims a different physical backend than its own outer
        // row and holds.
        let outer = rekey_ack(&ack);
        let mut body_ack = outer.clone();
        let foreign = "f".repeat(64);
        body_ack.backend_identity = foreign.clone();
        for hold in body_ack.artifacts.iter_mut() {
            hold.artifact.backend_identity = foreign.clone();
        }
        insert_fixture_ledger(&pool, &outer, &body_ack.encode()?, &outer).await?;
        assert_ledger_integrity(acquire_receipt(&pool, &scope, outer.request_id).await, "wrong-backend acquire body");
        assert_ledger_integrity(
            consume_receipt(&pool, &scope, outer.request_id, outer.consume_request_id).await,
            "wrong-backend consume body",
        );

        // (b) the stored body disagrees with its own outer row on the gate proof.
        let outer = rekey_ack(&ack);
        let mut body_ack = outer.clone();
        body_ack.gate_revision += 1;
        insert_fixture_ledger(&pool, &outer, &body_ack.encode()?, &outer).await?;
        assert_ledger_integrity(acquire_receipt(&pool, &scope, outer.request_id).await, "outer/body gate mismatch");

        // (c) a partial consume batch: only slot 0 has a durable receipt.
        let partial = rekey_ack(&ack);
        insert_fixture_ledger(&pool, &partial, &partial.encode()?, &partial).await?;
        let first = derive_fixture_receipt(&receipt_source, &partial, 0);
        insert_fixture_receipt(&pool, &first, &first.encode()?).await?;
        assert_ledger_integrity(
            consume_receipt(&pool, &scope, partial.request_id, partial.consume_request_id).await,
            "partial consume batch",
        );

        // (d) a complete-looking receipt set whose stored hold identity and
        // recorded consumption instant disagree with the immutable ACK.
        let body = rekey_ack(&ack);
        let mut hold_rows = body.clone();
        hold_rows.artifacts[0].artifact.sha256 = "e".repeat(64);
        insert_fixture_ledger(&pool, &body, &body.encode()?, &hold_rows).await?;
        let mut matched = derive_fixture_receipt(&receipt_source, &body, 0);
        matched.artifact = hold_rows.artifacts[0].artifact.clone();
        insert_fixture_receipt(&pool, &matched, &matched.encode()?).await?;
        let mut skewed = derive_fixture_receipt(&receipt_source, &body, 1);
        skewed.artifact = hold_rows.artifacts[1].artifact.clone();
        let mut skewed_body = skewed.clone();
        skewed_body.consumed_at_unix_micros += 1;
        insert_fixture_receipt(&pool, &skewed, &skewed_body.encode()?).await?;
        assert_ledger_integrity(
            consume_receipt(&pool, &scope, body.request_id, body.consume_request_id).await,
            "ACK body vs hold identity/time",
        );

        let totals_after = ledger_totals(&pool).await?;
        assert_eq!(totals_after.0, totals_before.0 + 4, "only the four labelled fixtures were inserted");
        assert_eq!(totals_after.1, totals_before.1 + 8, "two fixture hold rows per fixture batch");
        assert_eq!(totals_after.2, totals_before.2 + 3, "one partial plus two skewed receipts");
        assert_eq!(
            (totals_after.3, totals_after.4, totals_after.5),
            (totals_before.3, totals_before.4, totals_before.5)
        );
        assert_eq!(repo_usage(&pool, repo).await?, repo_before, "a corrupt fixture never charges admission");
        assert_eq!(tenant_usage(&pool, tenant).await?, tenant_before);
        assert_eq!(shard_usage(&pool, ShardId::of(req.request_id())).await?, shard_before);
        assert_eq!(
            acquire_receipt(&pool, &scope, req.request_id()).await?,
            AcquireLookup::Found(ack.clone()),
            "the real, API-minted ACK still resolves after the fixtures"
        );
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 2));
        assert_eq!(endpoint.count(), 0, "no receipt lookup or corrupt-fixture check may produce IO");
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("stable consume id / corrupt ledger test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}

/// A TRUNCATE (optionally CASCADE) of one permanent ledger/quota table must be
/// refused and must leave every row of that table in place.
///
/// The expected refusal is the table-local `BEFORE TRUNCATE` statement guard
/// (`rootyard_artifact_hold_no_truncate`: `RAISE EXCEPTION` => SQLSTATE P0001,
/// "permanent and cannot be truncated"). A *plain* (non-CASCADE) TRUNCATE can
/// legitimately be refused earlier by PostgreSQL's own dependency check with
/// SQLSTATE 0A000 ("cannot truncate a table referenced in a foreign key
/// constraint"): that check runs before any statement trigger, so exactly that
/// FK-first variant is accepted for non-CASCADE only. CASCADE removes the FK
/// objection and reaches the statement guards of the tables in the cascade, so
/// a CASCADE refusal must be the guard itself (P0001) - never a generic error
/// and never the FK dependency error.
async fn expect_truncate_denied(pool: &Pool, table: &str, cascade: bool) -> Result<()> {
    let statement = if cascade { format!("TRUNCATE TABLE {table} CASCADE") } else { format!("TRUNCATE TABLE {table}") };
    let client = pool.get().await?;
    let rows_before: i64 = client.query_one(&format!("SELECT count(*) FROM {table}"), &[]).await?.get(0);
    let error =
        client.batch_execute(&statement).await.expect_err("TRUNCATE of a permanent ledger/quota table was accepted");
    let database = error.as_db_error().expect("expected a PostgreSQL refusal for a ledger/quota TRUNCATE");
    let code = database.code().code();
    if code == "0A000" && !cascade {
        assert!(
            database.message().contains("foreign key constraint"),
            "{table}: only PostgreSQL's FK-first refusal may bypass the guard here, got: {}",
            database.message()
        );
    } else {
        assert_eq!(
            code,
            "P0001",
            "{table}: a ledger/quota TRUNCATE must hit the TRUNCATE guard itself, got SQLSTATE {code}: {}",
            database.message()
        );
        assert!(
            database.message().contains("permanent and cannot be truncated"),
            "{table}: unexpected TRUNCATE guard message: {}",
            database.message()
        );
    }
    let rows_after: i64 = client.query_one(&format!("SELECT count(*) FROM {table}"), &[]).await?.get(0);
    assert_eq!(rows_after, rows_before, "{table}: a refused TRUNCATE must leave every row in place");
    Ok(())
}

/// Privilege/ACL fingerprint of the new tables, used to prove the suite never
/// changed a grant or a table owner while proving the deny paths.
async fn ledger_acl_fingerprint(pool: &Pool, tables: &[&str]) -> Result<String> {
    let names = tables.iter().map(|table| (*table).to_string()).collect::<Vec<_>>();
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT coalesce(string_agg(c.relname||':'||c.relowner::text||':'||coalesce(c.relacl::text,'-'),','
                                       ORDER BY c.relname),'')
             FROM pg_class c
             WHERE c.relnamespace=current_schema()::regnamespace AND c.relname = ANY($1)",
            &[&names],
        )
        .await?;
    Ok(row.get(0))
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL"]
async fn truncate_of_every_new_ledger_table_is_denied_and_rows_survive() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup().await?;
    let outcome = tokio::spawn(async move {
        let endpoint = CountingEndpoint::start().await?;
        let blob = store_for_endpoint(endpoint.endpoint())?;
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, format()).await?;
        let op = operation(repo, tenant, "truncate-guard", 1, 201);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);
        let req = request(&blob, scope, &op, Uuid::new_v4(), gate, vec![spec("packs", 1, 31), spec("packs", 2, 32)]);
        let (ack, grant) = match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Granted { ack, grant } => (ack, grant),
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh truncate-guard acquire replayed")),
        };
        let mut client = pool.get().await?;
        let consumed = PgArtifactHoldStore.consume(&mut client, grant, deadline()).await?;
        drop(consumed);
        drop(client);
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 2));

        let tables = [
            "artifact_hold_requests",
            "artifact_holds",
            "artifact_hold_consume_receipts",
            "artifact_hold_shards",
            "artifact_hold_repo_usage",
            "artifact_hold_tenant_usage",
        ];
        let names = tables.iter().map(|table| (*table).to_string()).collect::<Vec<_>>();
        let totals_before = ledger_totals(&pool).await?;
        let repo_before = repo_usage(&pool, repo).await?;
        let tenant_before = tenant_usage(&pool, tenant).await?;
        let shard_before = shard_usage(&pool, ShardId::of(req.request_id())).await?;
        let acl_before = ledger_acl_fingerprint(&pool, &tables).await?;
        assert!(!acl_before.is_empty());

        // Static catalog coverage: all six tables exist here and every one of
        // them carries its own BEFORE TRUNCATE statement guard, so this case
        // cannot silently miss a table and rely on a child-FK error instead.
        let present: i64 = pool
            .get()
            .await?
            .query_one(
                "SELECT count(*) FROM unnest($1::text[]) AS t(name) WHERE to_regclass(t.name) IS NOT NULL",
                &[&names],
            )
            .await?
            .get(0);
        assert_eq!(present, 6, "a new ledger/quota table is missing from the schema");
        let guarded: i64 = pool
            .get()
            .await?
            .query_one(
                "SELECT count(DISTINCT c.relname) FROM pg_trigger t
                   JOIN pg_class c ON c.oid=t.tgrelid
                 WHERE NOT t.tgisinternal AND c.relnamespace=current_schema()::regnamespace
                   AND c.relname = ANY($1) AND pg_get_triggerdef(t.oid) LIKE '%TRUNCATE%'",
                &[&names],
            )
            .await?
            .get(0);
        assert_eq!(guarded, 6, "every new ledger/quota table needs its own statement-level TRUNCATE guard");

        for table in tables {
            // The fixture role is allowed to truncate, so a refusal here is the
            // statement guard rather than a missing privilege.
            let can_truncate: bool = pool
                .get()
                .await?
                .query_one("SELECT has_table_privilege(current_user,$1,'TRUNCATE')", &[&table])
                .await?
                .get(0);
            assert!(can_truncate, "{table}: fixture role unexpectedly lacks TRUNCATE privilege");
            expect_truncate_denied(&pool, table, false).await?;
            expect_truncate_denied(&pool, table, true).await?;
        }

        assert_eq!(ledger_totals(&pool).await?, totals_before, "a refused TRUNCATE must not change any row");
        assert_eq!(repo_usage(&pool, repo).await?, repo_before);
        assert_eq!(tenant_usage(&pool, tenant).await?, tenant_before);
        assert_eq!(shard_usage(&pool, ShardId::of(req.request_id())).await?, shard_before);
        assert_eq!(ledger_counts(&pool, req.request_id()).await?, (1, 2, 2));
        assert_eq!(hold_state(&pool, ack.holds()[0].hold_id).await?, ("active".into(), 1));
        assert_eq!(ledger_acl_fingerprint(&pool, &tables).await?, acl_before, "no privilege or owner change");
        assert_eq!(endpoint.count(), 0);
        Ok::<(), anyhow::Error>(())
    });
    let outcome = match outcome.await {
        Ok(result) => result,
        Err(error) => Err(anyhow!("TRUNCATE denial test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}
