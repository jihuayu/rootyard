//! Real PostgreSQL + real S3 protected-upload acceptance for #105/#107 A3.
//!
//! This suite is intentionally `#[ignore]`d. Root runs it explicitly with a
//! disposable PostgreSQL URL and a real `ROOTYARD_BLOB_*` S3 profile:
//!
//! `ROOTYARD_TEST_DATABASE_URL=... ROOTYARD_BLOB_*=<real s3 profile> \
//!    cargo test --test ref_store_holds_provider -- --ignored`
//!
//! Missing configuration panics; there is no in-memory provider or SQL fake.
//! Every test creates and drops its own random schema through `db::migrate`.
//! The provider bytes are real S3 objects under Root's per-run profile root;
//! permanent holds mean this file never deletes them. No DSN, credential,
//! Authorization header or provider request detail is printed or embedded in a
//! failure message. No production encryption/key-provider, GC, serving route or
//! backup-byte claim is made here.

use anyhow::{Result, anyhow, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::blob_store::protected::{ProtectedUploader, UploadSource};
use rootyard::db;
use rootyard::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireLookup, AcquireOutcome, ArtifactHoldError, ArtifactHoldPurpose, ArtifactSpec,
    ConsumeLookup, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::{
    CoreGateInit, GitObjectFormat, IssuerLane, OperationIdentity, OperationState, PgRefStore, PgRefStoreCore, RefName,
    RequestDigest, VersionCheck,
};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant as StdInstant};
use tokio::time::Instant as TokioInstant;
use uuid::Uuid;

const PROVIDER_DEADLINE: Duration = Duration::from_secs(120);

fn database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set; this suite never skips or fakes PostgreSQL")
}

fn deadline() -> TokioInstant {
    TokioInstant::now() + PROVIDER_DEADLINE
}

fn std_deadline() -> StdInstant {
    StdInstant::now() + PROVIDER_DEADLINE
}

fn lane(value: &str) -> IssuerLane {
    IssuerLane::new(value).expect("valid issuer lane")
}

fn object_format() -> GitObjectFormat {
    GitObjectFormat::Sha1
}

/// Real S3 store opened through the production profile factory. The
/// `ROOTYARD_BLOB_*` environment is supplied by Root; this test never writes
/// environment variables and treats any missing/unsupported setting as a hard
/// failure. No credential or endpoint value is echoed.
fn open_real_s3_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env()
        .expect("ROOTYARD_BLOB_* real S3 provider environment must be set; this suite never skips");
    ensure!(
        profile.provider().as_str() == "s3",
        "this acceptance test requires ROOTYARD_BLOB_SERVICE=s3, got `{}`",
        profile.provider().as_str()
    );
    BlobStore::open(profile).map_err(|error| anyhow!("real S3 provider store could not be opened: {error}"))
}

struct Fixture {
    admin: Pool,
    pool: Pool,
    schema: String,
    tenant: Uuid,
    repo: Uuid,
}

/// Random schema, migrated only through `db::migrate`. If anything after
/// `CREATE SCHEMA` fails, the just-created schema is dropped before returning.
async fn setup() -> Result<Fixture> {
    let url = database_url();
    let admin = db::pool(&url)?;
    let schema = format!("ref_store_holds_provider_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    match setup_schema(&url, &schema).await {
        Ok((pool, tenant, repo)) => Ok(Fixture { admin, pool, schema, tenant, repo }),
        Err(error) => {
            if let Ok(client) = admin.get().await {
                let _ = client.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await;
            }
            Err(error)
        }
    }
}

async fn setup_schema(url: &str, schema: &str) -> Result<(Pool, Uuid, Uuid)> {
    let mut config: tokio_postgres::Config =
        url.parse().map_err(|_| anyhow!("ROOTYARD_TEST_DATABASE_URL is not a valid connection string"))?;
    config.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000"));
    let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(8)
        .build()?;
    db::migrate(&pool).await?;
    let client = pool.get().await?;
    let installed: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=141)
                AND to_regclass('artifact_hold_requests') IS NOT NULL
                AND to_regclass('artifact_holds') IS NOT NULL
                AND to_regclass('artifact_hold_consume_receipts') IS NOT NULL",
            &[],
        )
        .await?
        .get(0);
    ensure!(installed, "db::migrate did not install the real migration-141 artifact-hold tables");
    drop(client);
    let (tenant, repo) = create_business(&pool).await?;
    Ok((pool, tenant, repo))
}

async fn create_business(pool: &Pool) -> Result<(Uuid, Uuid)> {
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let client = pool.get().await?;
    client
        .execute(
            "INSERT INTO users(id,username) VALUES($1,$2)",
            &[&tenant, &format!("holdprovider{}", &tenant.simple().to_string()[..12])],
        )
        .await?;
    client
        .execute(
            "INSERT INTO repositories(id,owner_id,name,state,object_format)
             VALUES($1,$2,$3,'provisioning','sha1')",
            &[&repo, &tenant, &format!("holdproviderrepo{}", &repo.simple().to_string()[..12])],
        )
        .await?;
    drop(client);
    Ok((tenant, repo))
}

async fn teardown(admin: &Pool, schema: &str) -> Result<()> {
    admin.get().await?.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await?;
    Ok(())
}

/// Always attempt owned-schema cleanup, but never hide the primary failure.
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
    ensure!(begun.created, "new parent operation was not created");
    ensure!(begun.record.state() == OperationState::Pending, "parent operation is not pending");
    tx.commit().await?;
    Ok(())
}

fn hold_scope(repo: Uuid, tenant: Uuid, history: Uuid) -> HoldScope {
    HoldScope::new(repo, tenant, tenant, ArtifactHoldPurpose::RefPublication, object_format(), history, 1, 1)
        .expect("valid hold scope")
}

fn content_spec(namespace: &str, bytes: &[u8]) -> ArtifactSpec {
    ArtifactSpec::new(namespace, hex::encode(Sha256::digest(bytes)), bytes.len() as u64).expect("valid artifact spec")
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

async fn hold_state(pool: &Pool, hold_id: Uuid) -> Result<(String, i32)> {
    let row = pool
        .get()
        .await?
        .query_one("SELECT state,generation FROM artifact_holds WHERE hold_id=$1", &[&hold_id])
        .await?;
    Ok((row.get(0), row.get(1)))
}

async fn repo_usage(pool: &Pool, repo: Uuid) -> Result<(i64, i64, i64, i64)> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT hold_count,declared_bytes,logical_bytes,receipt_count
               FROM artifact_hold_repo_usage WHERE repository_id=$1",
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
            "SELECT hold_count,declared_bytes,logical_bytes,receipt_count
               FROM artifact_hold_tenant_usage WHERE tenant_id=$1",
            &[&tenant],
        )
        .await?;
    Ok(row.map(|row| (row.get(0), row.get(1), row.get(2), row.get(3))).unwrap_or((0, 0, 0, 0)))
}

fn assert_active_generation_one(state: &(String, i32)) {
    assert_eq!(state.0, "active", "holds are permanent and must never leave active state");
    assert_eq!(state.1, 1, "A3 holds are permanent active generation-1 holds");
}

/// One comprehensive real-provider case: a known two-artifact local source
/// becomes a real acquire grant, the protected uploader durably consumes it and
/// publishes/read-backs both objects to real S3. The returned receipts are
/// checked against the real source bytes, every slot's locator and physical
/// backend, the permanent active generation-1 hold rows, and the full consume
/// receipt query.
#[tokio::test]
#[ignore = "requires real PostgreSQL and ROOTYARD_BLOB_* provider"]
async fn postgres_s3_protected_upload_readback_is_real_and_holds_stay_permanent() -> Result<()> {
    let Fixture { admin, pool, schema, tenant, repo } = setup().await?;
    let outcome = tokio::spawn(async move {
        let capabilities = PgArtifactHoldStore.capabilities();
        ensure!(capabilities.global_artifact_hold_ledger, "artifact-hold ledger capability is required");
        ensure!(capabilities.private_upload_grant, "private upload grant capability is required");
        ensure!(capabilities.durable_one_shot_consume, "durable one-shot consume capability is required");
        ensure!(capabilities.protected_upload_readback, "protected read-back capability is required");
        ensure!(capabilities.permanent_active_holds, "permanent active holds capability is required");
        ensure!(!capabilities.artifact_release, "A3 must not declare an artifact release path");
        ensure!(!capabilities.ttl_expiry, "A3 must not declare TTL expiry");
        ensure!(!capabilities.physical_gc, "A3 must not declare physical GC");
        ensure!(!capabilities.serving_profile, "A3 must not declare a serving profile");

        let blob = open_real_s3_store()?;
        let backend_hex = blob.backend_identity().as_hex().to_owned();
        let history = Uuid::new_v4();
        let gate = initialize_gate(&pool, repo, tenant, history, object_format()).await?;
        ensure!(check_gate_digest(&pool, repo, tenant).await? == gate, "typed core gate digest changed before acquire");
        let op = operation(repo, tenant, "provider-a3", 1, 211);
        register_operation(&pool, &op).await?;
        let scope = hold_scope(repo, tenant, history);

        // Known real local sources: the request digest and later receipt proof
        // are derived from these exact bytes, not from invented metadata.
        let artifacts: Vec<(&str, Vec<u8>)> = vec![
            ("packs", b"rootyard A3 real S3 provider acceptance slot 0\n".to_vec()),
            ("idxs", b"rootyard A3 real S3 provider acceptance slot 1 with verified range\n".to_vec()),
        ];
        let specs =
            artifacts.iter().map(|(namespace, bytes)| content_spec(namespace, bytes.as_slice())).collect::<Vec<_>>();
        let total_declared: i64 = artifacts.iter().map(|(_, bytes)| bytes.len() as i64).sum();

        let req = request(&blob, scope, &op, Uuid::new_v4(), gate, specs);
        let request_id = req.request_id();
        assert_eq!(ledger_counts(&pool, request_id).await?, (0, 0, 0), "acquire ledger must start empty");
        assert_eq!(repo_usage(&pool, repo).await?, (0, 0, 0, 0), "repo usage must start empty");
        assert_eq!(tenant_usage(&pool, tenant).await?, (0, 0, 0, 0), "tenant usage must start empty");

        let (ack, grant) = match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Granted { ack, grant } => (ack, grant),
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh provider acquire unexpectedly replayed")),
        };
        ensure!(ack.artifact_count() == artifacts.len(), "acquire ACK batch length mismatch");
        assert_eq!(ack.backend_identity_hex(), backend_hex, "ACK must name the real opened backend");
        assert_eq!(ledger_counts(&pool, request_id).await?, (1, artifacts.len() as i64, 0));
        let repo_after_acquire = repo_usage(&pool, repo).await?;
        let tenant_after_acquire = tenant_usage(&pool, tenant).await?;
        // One successful ACQUIRE of the 2-hold batch charges exactly one
        // retained ACK receipt (not one per hold); nothing is consumed yet.
        assert_eq!(
            (repo_after_acquire.0, repo_after_acquire.1, repo_after_acquire.3),
            (2, total_declared, 1),
            "repo: 2 holds, declared bytes and one acquire ACK receipt"
        );
        assert_eq!(
            (tenant_after_acquire.0, tenant_after_acquire.1, tenant_after_acquire.3),
            (2, total_declared, 1),
            "tenant: 2 holds, declared bytes and one acquire ACK receipt"
        );
        for hold in ack.holds() {
            assert_eq!(hold.artifact.backend_identity, backend_hex);
            assert_eq!(hold.artifact.provider, "s3");
            assert_active_generation_one(&hold_state(&pool, hold.hold_id).await?);
        }

        let consume_id = ack.consume_request_id();
        assert_eq!(grant.consume_request_id(), consume_id, "consume id is stable from acquire");

        // Exact replay must return the immutable ACK and no grant/token, and
        // must not charge or insert anything again.
        match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Replayed { ack: replayed } => assert_eq!(replayed, ack),
            AcquireOutcome::Granted { .. } => return Err(anyhow!("an acquire replay minted another upload grant")),
        }
        assert_eq!(ledger_counts(&pool, request_id).await?, (1, 2, 0));
        assert_eq!(repo_usage(&pool, repo).await?, repo_after_acquire);
        assert_eq!(tenant_usage(&pool, tenant).await?, tenant_after_acquire);

        let temp = tempfile::tempdir()?;
        let mut sources = Vec::with_capacity(artifacts.len());
        for (index, (_, bytes)) in artifacts.iter().enumerate() {
            let path = temp.path().join(format!("source-slot-{index}.bin"));
            std::fs::write(&path, bytes)?;
            let metadata = std::fs::metadata(&path)?;
            ensure!(metadata.is_file(), "source slot {index} is not a regular file");
            assert_eq!(metadata.len(), bytes.len() as u64);
            assert_eq!(hex::encode(Sha256::digest(bytes)), hex::encode(Sha256::digest(std::fs::read(&path)?)));
            sources.push(UploadSource::new(path));
        }

        let publication = ProtectedUploader::new(blob.clone())
            .consume_and_upload(&pool, grant, &sources, std_deadline())
            .await
            .map_err(|error| anyhow!("protected upload failed: {error}"))?;
        ensure!(publication.is_complete(), "protected upload returned no verified publication");
        assert_eq!(publication.consume_request_id(), consume_id);
        assert_eq!(publication.receipts().len(), artifacts.len());

        // Durable consume ACK and permanent hold ledger after real provider I/O.
        assert_eq!(ledger_counts(&pool, request_id).await?, (1, 2, 2));
        let repo_after_consume = repo_usage(&pool, repo).await?;
        let tenant_after_consume = tenant_usage(&pool, tenant).await?;
        // One acquire ACK receipt for the batch plus one consume receipt per
        // consumed hold (2) = 3 retained receipts.
        assert_eq!(
            (repo_after_consume.0, repo_after_consume.1, repo_after_consume.3),
            (2, total_declared, 3),
            "repo: 2 holds, declared bytes, 1 acquire ACK + 2 consume receipts"
        );
        assert_eq!(
            (tenant_after_consume.0, tenant_after_consume.1, tenant_after_consume.3),
            (2, total_declared, 3),
            "tenant: 2 holds, declared bytes, 1 acquire ACK + 2 consume receipts"
        );
        for hold in ack.holds() {
            assert_active_generation_one(&hold_state(&pool, hold.hold_id).await?);
        }

        // A replay after consumption still cannot mint a token or mutate the
        // permanent ledger.
        match acquire(&pool, &blob, &req).await? {
            AcquireOutcome::Replayed { ack: replayed } => assert_eq!(replayed, ack),
            AcquireOutcome::Granted { .. } => return Err(anyhow!("a post-consume acquire replay minted a grant")),
        }
        assert_eq!(ledger_counts(&pool, request_id).await?, (1, 2, 2));
        assert_eq!(repo_usage(&pool, repo).await?, repo_after_consume);
        assert_eq!(acquire_receipt(&pool, &scope, request_id).await?, AcquireLookup::Found(ack.clone()));

        // Full-batch consume query under the exact immutable scope.
        let queried = match consume_receipt(&pool, &scope, request_id, consume_id).await? {
            ConsumeLookup::Found(receipts) => receipts,
            ConsumeLookup::Unknown => return Err(anyhow!("consume receipt was not durable after publication")),
        };
        assert_eq!(queried.len(), ack.artifact_count(), "consume query must return the full batch");
        let queried_slots = queried.iter().map(|receipt| receipt.slot).collect::<Vec<_>>();
        assert_eq!(queried_slots, vec![0, 1], "consume query must return the complete stable slot order");
        for receipt in &queried {
            receipt.ensure_scope(&scope)?;
            receipt.ensure_acquire_ack(&ack)?;
        }
        let wrong_scope = hold_scope(repo, tenant, Uuid::new_v4());
        assert!(
            matches!(
                consume_receipt(&pool, &wrong_scope, request_id, consume_id).await,
                Err(ArtifactHoldError::ScopeMismatch(_))
            ),
            "consume query must refuse a different immutable scope"
        );

        // Validate every returned receipt against the real source and then read
        // the object back through the public BlobStore read APIs.
        let mut seen_slots = Vec::new();
        for protected in publication.receipts() {
            let index =
                usize::try_from(protected.slot()).map_err(|_| anyhow!("provider receipt reported a negative slot"))?;
            ensure!(index < artifacts.len(), "provider receipt reported an unknown slot");
            let receipt = protected.receipt();
            let hold = ack
                .hold(protected.hold_id())
                .ok_or_else(|| anyhow!("provider receipt names a hold outside the acquire ACK"))?;
            assert_eq!(hold.slot, protected.slot());
            let locator = hold.artifact.locator()?;
            let expected_namespace = artifacts[index].0;
            let expected = &artifacts[index].1;
            let expected_sha = hex::encode(Sha256::digest(expected));

            assert_eq!(hold.artifact.backend_identity, backend_hex);
            assert_eq!(hold.artifact.provider, "s3");
            assert_eq!(locator.namespace(), expected_namespace);
            assert_eq!(locator.sha256(), expected_sha);
            assert_eq!(locator.length(), expected.len() as u64);
            assert_eq!(receipt.locator(), &locator);
            assert!(receipt.matches(&locator));
            assert_eq!(receipt.provider(), blob.provider());
            assert_eq!(receipt.backend_identity().as_hex(), backend_hex);
            assert_eq!(receipt.verified_sha256(), expected_sha);
            assert_eq!(receipt.verified_length(), expected.len() as u64);

            assert_eq!(
                blob.head(&locator, std_deadline())
                    .await
                    .map_err(|error| anyhow!("real S3 head for slot {index} failed: {error}"))?,
                Some(expected.len() as u64)
            );
            let readback_path = temp.path().join(format!("readback-slot-{index}.bin"));
            blob.get_to_file(&locator, &readback_path, std_deadline())
                .await
                .map_err(|error| anyhow!("real S3 verified read-back for slot {index} failed: {error}"))?;
            let readback = std::fs::read(&readback_path)?;
            assert_eq!(readback.as_slice(), expected.as_slice(), "read-back bytes differ from source slot {index}");
            assert_eq!(
                hex::encode(Sha256::digest(&readback)),
                expected_sha,
                "read-back SHA-256 differs from source slot {index}"
            );

            let range_len = expected.len().min(23) as u64;
            let range = blob
                .get_range(&locator, 0, range_len, std_deadline())
                .await
                .map_err(|error| anyhow!("real S3 verified range read for slot {index} failed: {error}"))?;
            assert_eq!(range.as_slice(), &expected.as_slice()[..range_len as usize]);
            seen_slots.push(protected.slot());
        }
        seen_slots.sort_unstable();
        assert_eq!(seen_slots, vec![0, 1], "every granted slot must have a verified real-S3 receipt");

        // No delete is ever attempted: these holds and objects are permanent for
        // this A3 slice. The local temp file is dropped here; remote objects remain in Root's per-run prefix.
        // The test records its assertions, then finish() drops the owned PG schema.
        drop(temp);
        Ok::<(), anyhow::Error>(())
    })
    .await;
    let outcome = match outcome {
        Ok(result) => result,
        Err(error) => Err(anyhow!("real provider acceptance test panicked: {error}")),
    };
    finish(&admin, &schema, outcome).await
}
