//! Root-selected companion fixture for the populated schema-141 artifact-hold
//! backup drill (#105/#107 A3).
//!
//! Only `tests/backup_refstore_holds141.py` selects this integration-test
//! executable. It never creates a database/schema and never runs a migration:
//! the parent owns one fresh migrated database and first seeds the inherited
//! migration-139 gate/refs fixture. This helper then adds one **plain-SQL**
//! pending migration-138 parent operation + issuer lane (explicitly a metadata
//! fixture, not an adapter or Git ACK), reads the real inherited 139 gate
//! through `PgRefStoreCore::check_version`, and produces every migration-141
//! request/hold/consume row through the real typed `PgArtifactHoldStore`.
//!
//! Seed mode acquires one batch and consumes it (durable receipts), then
//! acquires a second batch and deliberately drops that grant without consuming
//! it. Replaying the second request must return the old immutable ACK and must
//! never mint another grant. Verify mode runs against the restored database,
//! rebuilds both typed requests from the private manifest through public
//! constructors, and proves exact replay, receipt lookup, unknown consume,
//! scope denial and zero row/quota writes.
//!
//! Blob profile: a fixed, non-secret synthetic S3 identity only. No provider
//! endpoint is contacted, no raw upload/read-back is attempted, and no Blob
//! byte presence, protection or physical backup closure is claimed.

use anyhow::{Context, Result, bail, ensure};
use deadpool_postgres::Pool;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db;
use rootyard::ref_store::artifact_hold::{
    AcquireAck, AcquireArtifactHoldsRequest, AcquireLookup, AcquireOutcome, ArtifactHoldError, ArtifactHoldPurpose,
    ArtifactSpec, ConsumeAck, ConsumeLookup, GLOBAL_SHARDS, HoldScope, PgArtifactHoldStore, SHARD_MAX_DECLARED_BYTES,
    SHARD_MAX_HOLDS, SHARD_MAX_LOGICAL_BYTES, SHARD_MAX_RECEIPTS,
};
use rootyard::ref_store::{
    CoreGateVersion, GitObjectFormat, IssuerLane, OperationIdentity, PgRefStoreCore, RequestDigest, VersionCheck,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

const MARKER: &str = "ROOTYARD-ARTIFACT-HOLD-FIXTURE-METADATA";
const MANIFEST_KIND: &str = "rootyard/ref-store-artifact-holds-backup-fixture";
const DEADLINE_SECONDS: u64 = 25;
const TABLES: [&str; 6] = [
    "artifact_hold_requests",
    "artifact_holds",
    "artifact_hold_consume_receipts",
    "artifact_hold_shards",
    "artifact_hold_repo_usage",
    "artifact_hold_tenant_usage",
];

struct Fixture {
    url: String,
    output: PathBuf,
    repository: Uuid,
    tenant: Uuid,
    owner: Uuid,
}

impl Fixture {
    fn from_env() -> Self {
        Self {
            url: required("ROOTYARD_TEST_DATABASE_URL"),
            output: PathBuf::from(required("ROOTYARD_HOLDS_FIXTURE_OUTPUT")),
            repository: required_uuid("ROOTYARD_HOLDS_FIXTURE_REPOSITORY"),
            tenant: required_uuid("ROOTYARD_HOLDS_FIXTURE_TENANT"),
            owner: required_uuid("ROOTYARD_HOLDS_FIXTURE_OWNER"),
        }
    }
}

enum Mode {
    Seed,
    Verify,
}

impl Mode {
    fn from_env() -> Self {
        match required("ROOTYARD_HOLDS_FIXTURE_MODE").as_str() {
            "seed" => Self::Seed,
            "verify" => Self::Verify,
            other => panic!("ROOTYARD_HOLDS_FIXTURE_MODE must be 'seed' or 'verify', not {other:?}"),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Verify => "verify",
        }
    }
}

fn required(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => panic!(
            "{name} is required: this fixture only runs under the owning artifact-hold backup drill, \
             never from a routine test command"
        ),
    }
}

fn required_uuid(name: &str) -> Uuid {
    Uuid::parse_str(&required(name)).unwrap_or_else(|error| panic!("{name} must be a UUID: {error}"))
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(DEADLINE_SECONDS)
}

#[derive(Clone)]
struct ParentFixture {
    issuer_id: Uuid,
    lane: String,
    sequence: i64,
    operation_id: Uuid,
    digest: RequestDigest,
}

/// Fixed non-secret synthetic S3 identity. No request is sent by this helper;
/// the store exists only because acquire validates the typed physical identity.
fn fixture_blob_store() -> Result<BlobStore> {
    unsafe {
        std::env::set_var("ROOTYARD_BLOB_DRIVER", "opendal");
        std::env::set_var("ROOTYARD_BLOB_SERVICE", "s3");
        std::env::set_var("ROOTYARD_BLOB_ENDPOINT", "http://127.0.0.1:9");
        std::env::set_var("ROOTYARD_BLOB_REGION", "us-east-1");
        std::env::set_var("ROOTYARD_BLOB_BUCKET", "artifact-hold-backup-fixture");
        std::env::set_var("ROOTYARD_BLOB_ROOT", "artifact-hold-backup-fixture");
        std::env::set_var("ROOTYARD_BLOB_ACCESS_KEY_ID", "fixture-artifact-hold-access-key");
        std::env::set_var("ROOTYARD_BLOB_SECRET_ACCESS_KEY", "fixture-artifact-hold-secret-key");
        std::env::set_var("ROOTYARD_BLOB_RETRY_MAX_TIMES", "0");
        std::env::set_var("ROOTYARD_BLOB_TIMEOUT_MS", "1000");
        std::env::set_var("ROOTYARD_BLOB_IO_TIMEOUT_MS", "1000");
        std::env::set_var("ROOTYARD_BLOB_ABORT_TIMEOUT_MS", "100");
        std::env::set_var("ROOTYARD_BLOB_MAX_OBJECT_BYTES", "1048576");
        for name in [
            "ROOTYARD_BLOB_SESSION_TOKEN",
            "ROOTYARD_BLOB_DELETE",
            "ROOTYARD_BLOB_STAGING_BYTES",
            "ROOTYARD_BLOB_ACTIVE_UPLOADS",
            "ROOTYARD_BLOB_ACTIVE_READERS",
            "ROOTYARD_BLOB_CONTAINER",
            "ROOTYARD_BLOB_ACCOUNT_NAME",
            "ROOTYARD_BLOB_ACCOUNT_KEY",
        ] {
            std::env::remove_var(name);
        }
    }
    let profile = BlobProfile::from_env().context("build the fixed synthetic S3 fixture profile")?;
    BlobStore::open(profile).context("open the synthetic S3 fixture identity (no provider IO)")
}

async fn gate_version(pool: &Pool, fixture: &Fixture) -> Result<CoreGateVersion> {
    let mut client = pool.get().await.context("checkout a gate reader connection")?;
    let checked = PgRefStoreCore
        .check_version(&mut client, fixture.repository, fixture.tenant, None, deadline())
        .await
        .context("read the inherited migration-139 core gate")?;
    let version = match checked {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => version,
        VersionCheck::Unknown => bail!(
            "repository {} has no core gate; the parent drill must run seed_core_fixture() first",
            fixture.repository
        ),
    };
    if version.repository_id() != fixture.repository || version.tenant_id() != fixture.tenant {
        bail!("the inherited core gate does not belong to the fixture repository and tenant");
    }
    if version.revision() <= 0 || version.object_format() != GitObjectFormat::Sha1 {
        bail!("the inherited core gate has an unexpected revision or object format");
    }
    Ok(version)
}

fn hold_scope(fixture: &Fixture, version: &CoreGateVersion) -> Result<HoldScope> {
    Ok(HoldScope::new(
        fixture.repository,
        fixture.tenant,
        fixture.owner,
        ArtifactHoldPurpose::RefPublication,
        version.object_format(),
        version.history_incarnation(),
        version.authority_epoch(),
        version.group_epoch(),
    )?)
}

/// Direct-SQL metadata fixture only: one issuer lane plus one *pending* parent
/// operation against the inherited 139 gate. It is not an adapter/Git ACK.
async fn seed_pending_parent(pool: &Pool, fixture: &Fixture, version: &CoreGateVersion) -> Result<ParentFixture> {
    let issuer_id = fixture.tenant;
    let lane = format!("artifact-hold-backup-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let lane = IssuerLane::new(lane).context("build the fixture issuer lane")?;
    let sequence = 1_i64;
    let operation_id = Uuid::new_v4();
    let mut digest = RequestDigest::from_bytes([0x42; 32]);
    if digest.as_bytes() == version.digest().as_bytes() {
        digest = RequestDigest::from_bytes([0x43; 32]);
    }
    let operation = OperationIdentity::new(fixture.repository, issuer_id, lane.clone(), sequence, operation_id, digest)
        .context("build the fixture parent operation identity")?;
    let lane_text = lane.as_str().to_owned();
    let digest_hex = digest.as_hex();
    let mut client = pool.get().await.context("checkout the parent fixture writer")?;
    let tx = client.transaction().await.context("begin the parent fixture insert")?;
    tx.execute(
        "INSERT INTO public.ref_store_issuer_lanes(repository_id,issuer_id,lane,last_reserved_sequence) VALUES($1,$2,$3,$4)",
        &[&fixture.repository, &issuer_id, &lane_text, &sequence],
    )
    .await
    .context("insert the fixture issuer lane")?;
    tx.execute(
        "INSERT INTO public.ref_store_operations(repository_id,issuer_id,lane,sequence,operation_id,request_digest,state,terminal_result) VALUES($1,$2,$3,$4,$5,$6,'pending',NULL)",
        &[&fixture.repository, &issuer_id, &lane_text, &sequence, &operation_id, &digest_hex],
    )
    .await
    .context("insert the fixture pending parent operation")?;
    tx.commit().await.context("commit the parent fixture insert")?;
    let parent = ParentFixture { issuer_id, lane: lane_text, sequence, operation_id, digest };
    check_parent_tuple(pool, fixture, &parent, version).await?;
    let _ = operation;
    Ok(parent)
}

async fn check_parent_tuple(
    pool: &Pool,
    fixture: &Fixture,
    parent: &ParentFixture,
    version: &CoreGateVersion,
) -> Result<()> {
    let client = pool.get().await.context("checkout the parent tuple reader")?;
    let row = client
        .query_one(
            "SELECT o.state,o.issuer_id,o.lane,o.sequence,o.operation_id,o.request_digest,l.last_reserved_sequence,
                    (SELECT count(*) FROM public.ref_store_cancellations c
                     WHERE c.repository_id=o.repository_id AND c.operation_id=o.operation_id)
             FROM public.ref_store_operations o
             JOIN public.ref_store_issuer_lanes l
               ON l.repository_id=o.repository_id AND l.issuer_id=o.issuer_id AND l.lane=o.lane
             WHERE o.repository_id=$1 AND o.operation_id=$2",
            &[&fixture.repository, &parent.operation_id],
        )
        .await
        .context("read the fixture pending parent operation")?;
    let state: String = row.get(0);
    ensure!(state == "pending", "the fixture parent operation is not pending");
    ensure!(row.get::<_, Uuid>(1) == parent.issuer_id, "the fixture issuer id changed");
    ensure!(row.get::<_, String>(2) == parent.lane, "the fixture lane changed");
    ensure!(row.get::<_, i64>(3) == parent.sequence, "the fixture sequence changed");
    ensure!(row.get::<_, Uuid>(4) == parent.operation_id, "the fixture operation id changed");
    ensure!(row.get::<_, String>(5) == parent.digest.as_hex(), "the fixture operation digest changed");
    ensure!(row.get::<_, i64>(6) >= parent.sequence, "the fixture lane did not reserve the sequence");
    ensure!(row.get::<_, i64>(7) == 0, "the fixture parent has a cancellation tombstone");
    let gate = client
        .query_one(
            "SELECT revision,object_format,history_incarnation,authority_epoch,group_epoch,head_ref
             FROM public.ref_store_core_gates WHERE repository_id=$1 AND tenant_id=$2",
            &[&fixture.repository, &fixture.tenant],
        )
        .await
        .context("read the inherited core gate row")?;
    ensure!(gate.get::<_, i64>(0) == version.revision(), "the inherited gate revision changed");
    ensure!(gate.get::<_, String>(1) == version.object_format().as_str(), "the inherited gate format changed");
    ensure!(gate.get::<_, Uuid>(2) == version.history_incarnation(), "the inherited gate history changed");
    ensure!(gate.get::<_, i64>(3) == version.authority_epoch(), "the inherited gate authority epoch changed");
    ensure!(gate.get::<_, i64>(4) == version.group_epoch(), "the inherited gate group epoch changed");
    ensure!(gate.get::<_, String>(5) == version.head_ref().as_str(), "the inherited gate HEAD changed");
    Ok(())
}

fn pool_error(error: deadpool_postgres::PoolError) -> ArtifactHoldError {
    ArtifactHoldError::Database(error.to_string())
}

async fn acquire(
    pool: &Pool,
    blob: &BlobStore,
    request: &AcquireArtifactHoldsRequest,
) -> Result<AcquireOutcome, ArtifactHoldError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgArtifactHoldStore.acquire(&mut client, blob, request, deadline()).await
}

async fn consume(
    pool: &Pool,
    grant: rootyard::ref_store::artifact_hold::ArtifactGrant,
) -> Result<rootyard::ref_store::artifact_hold::ConsumedArtifacts, ArtifactHoldError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgArtifactHoldStore.consume(&mut client, grant, deadline()).await
}

async fn acquire_receipt(pool: &Pool, scope: &HoldScope, request_id: Uuid) -> Result<AcquireLookup, ArtifactHoldError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgArtifactHoldStore.acquire_receipt(&mut client, scope, request_id, deadline()).await
}

async fn consume_receipt(
    pool: &Pool,
    scope: &HoldScope,
    request_id: Uuid,
    consume_request_id: Uuid,
) -> Result<ConsumeLookup, ArtifactHoldError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgArtifactHoldStore.consume_receipt(&mut client, scope, request_id, consume_request_id, deadline()).await
}

fn fixture_artifacts(labels: &[&[u8]]) -> Result<Vec<ArtifactSpec>> {
    labels
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            let namespace = if index % 2 == 0 { "packs" } else { "idxs" };
            ArtifactSpec::new(namespace, hex::encode(Sha256::digest(bytes)), bytes.len() as u64)
                .context("build a fixture artifact spec")
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn acquire_request(
    scope: HoldScope,
    operation: OperationIdentity,
    request_id: Uuid,
    backend: rootyard::blob_store::BlobBackendIdentity,
    authority_id: Uuid,
    authority_generation: i64,
    gate_digest: RequestDigest,
    artifacts: Vec<ArtifactSpec>,
) -> Result<AcquireArtifactHoldsRequest> {
    AcquireArtifactHoldsRequest::new(
        scope,
        operation,
        request_id,
        backend,
        authority_id,
        authority_generation,
        gate_digest,
        artifacts,
    )
    .context("build the typed artifact-hold acquire request")
}

fn check_ack(
    ack: &AcquireAck,
    request: &AcquireArtifactHoldsRequest,
    parent: &ParentFixture,
    version: &CoreGateVersion,
) -> Result<()> {
    ensure!(ack.request_id == request.request_id(), "ACK request id differs");
    ensure!(ack.request_digest == request.digest().as_hex(), "ACK request digest differs");
    ensure!(ack.repository_id == request.scope().repository_id(), "ACK repository differs");
    ensure!(ack.tenant_id == request.scope().tenant_id(), "ACK tenant differs");
    ensure!(ack.owner_id == request.scope().owner_id(), "ACK owner differs");
    ensure!(ack.purpose == request.scope().purpose(), "ACK purpose differs");
    ensure!(ack.object_format == request.scope().object_format(), "ACK format differs");
    ensure!(ack.history_incarnation == request.scope().history_incarnation(), "ACK history differs");
    ensure!(ack.authority_epoch == request.scope().authority_epoch(), "ACK authority epoch differs");
    ensure!(ack.group_epoch == request.scope().group_epoch(), "ACK group epoch differs");
    ensure!(ack.issuer_id == parent.issuer_id, "ACK issuer differs from the fixture parent tuple");
    ensure!(ack.lane == parent.lane, "ACK lane differs from the fixture parent tuple");
    ensure!(ack.sequence == parent.sequence, "ACK sequence differs from the fixture parent tuple");
    ensure!(ack.operation_id == parent.operation_id, "ACK operation id differs from the fixture parent tuple");
    ensure!(
        ack.operation_digest == parent.digest.as_hex(),
        "ACK operation digest differs from the fixture parent tuple"
    );
    ensure!(ack.gate_revision == version.revision(), "ACK gate revision differs");
    ensure!(ack.gate_digest == version.digest().as_hex(), "ACK gate digest differs");
    ensure!(ack.artifact_count() == request.artifact_count(), "ACK batch length differs");
    ensure!(ack.consume_request_id != Uuid::nil(), "ACK has no stable consume id");
    ensure!(ack.shard_id()?.as_i32() == ack.shard, "ACK shard helper disagrees with its field");
    ensure!((0..GLOBAL_SHARDS as i32).contains(&ack.shard), "ACK shard is outside the fixed 64 shards");
    for (index, hold) in ack.artifacts.iter().enumerate() {
        ensure!(hold.slot == index as i32, "ACK slot is not canonical");
        ensure!(hold.artifact.backend_identity == ack.backend_identity, "ACK hold backend differs");
        ensure!(hold.declared_bytes == request.artifacts()[index].declared_bytes(), "ACK declared bytes differ");
    }
    Ok(())
}

async fn ledger_counts(pool: &Pool, request_id: Uuid) -> Result<(i64, i64, i64)> {
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT (SELECT count(*) FROM public.artifact_hold_requests WHERE request_id=$1),
                    (SELECT count(*) FROM public.artifact_holds WHERE request_id=$1),
                    (SELECT count(*) FROM public.artifact_hold_consume_receipts WHERE request_id=$1)",
            &[&request_id],
        )
        .await?;
    Ok((row.get(0), row.get(1), row.get(2)))
}

struct SeededAcquire {
    label: &'static str,
    request: AcquireArtifactHoldsRequest,
    ack: AcquireAck,
    consumed: Option<Vec<ConsumeAck>>,
    grant_dropped: bool,
    replay_after_drop: bool,
}

async fn seed(pool: &Pool, fixture: &Fixture, scope: &HoldScope, version: &CoreGateVersion, mode: &str) -> Result<()> {
    let parent = seed_pending_parent(pool, fixture, version).await?;
    let blob = fixture_blob_store()?;
    let backend = blob.backend_identity().clone();
    let gate_digest = *version.digest();
    let authority_id = Uuid::new_v4();
    let authority_generation = 1_i64;
    let first_request = acquire_request(
        *scope,
        OperationIdentity::new(
            fixture.repository,
            parent.issuer_id,
            IssuerLane::new(parent.lane.clone())?,
            parent.sequence,
            parent.operation_id,
            parent.digest,
        )?,
        Uuid::new_v4(),
        backend.clone(),
        authority_id,
        authority_generation,
        gate_digest,
        fixture_artifacts(&[b"artifact-hold-backup-first-0", b"artifact-hold-backup-first-1"])?,
    )?;
    let (first_ack, first_grant) = match acquire(pool, &blob, &first_request).await? {
        AcquireOutcome::Granted { ack, grant } => (ack, grant),
        AcquireOutcome::Replayed { .. } => bail!("a fresh first acquire unexpectedly replayed"),
    };
    check_ack(&first_ack, &first_request, &parent, version)?;
    ensure!(first_ack.artifact_count() == 2, "the consumed batch must hold two artifacts");
    let consumed = consume(pool, first_grant).await.context("consume the first grant")?;
    ensure!(consumed.artifact_count() == 2, "the consumed token lost an artifact");
    ensure!(consumed.receipts().len() == 2, "consume did not return two receipts");
    ensure!(
        consumed.receipts().iter().all(|receipt| receipt.consume_request_id == first_ack.consume_request_id),
        "consume receipts do not bind the stable consume id"
    );
    let first_receipts = consumed.receipts().to_vec();
    drop(consumed);
    let first_replay = match acquire(pool, &blob, &first_request).await? {
        AcquireOutcome::Replayed { ack } => ack,
        AcquireOutcome::Granted { .. } => bail!("an exact consumed acquire replay minted another grant"),
    };
    ensure!(first_replay == first_ack, "the consumed acquire replay returned a different ACK");

    let second_request = acquire_request(
        *scope,
        OperationIdentity::new(
            fixture.repository,
            parent.issuer_id,
            IssuerLane::new(parent.lane.clone())?,
            parent.sequence,
            parent.operation_id,
            parent.digest,
        )?,
        Uuid::new_v4(),
        backend.clone(),
        authority_id,
        authority_generation,
        gate_digest,
        fixture_artifacts(&[b"artifact-hold-backup-dropped-0"])?,
    )?;
    let second_ack = match acquire(pool, &blob, &second_request).await? {
        AcquireOutcome::Granted { ack, grant } => {
            drop(grant);
            ack
        }
        AcquireOutcome::Replayed { .. } => bail!("a fresh second acquire unexpectedly replayed"),
    };
    check_ack(&second_ack, &second_request, &parent, version)?;
    let second_replay = match acquire(pool, &blob, &second_request).await? {
        AcquireOutcome::Replayed { ack } => ack,
        AcquireOutcome::Granted { .. } => bail!("a dropped grant was reminted by an exact replay"),
    };
    ensure!(second_replay == second_ack, "the dropped-grant replay returned a different ACK");
    ensure!(ledger_counts(pool, first_request.request_id()).await? == (1, 2, 2), "first ledger counts are wrong");
    ensure!(ledger_counts(pool, second_request.request_id()).await? == (1, 1, 0), "second ledger counts are wrong");
    match consume_receipt(pool, scope, second_request.request_id(), second_ack.consume_request_id).await? {
        ConsumeLookup::Unknown => {}
        ConsumeLookup::Found(_) => bail!("the unconsumed dropped grant has a consume receipt"),
    }
    expect_scope_denials(pool, fixture, scope, &first_request, &first_ack).await?;
    let tables = table_rows(pool).await?;
    assert_ledger(&tables)?;
    let table_counts = counts(&tables)?;
    let acquires = [
        SeededAcquire {
            label: "consumed",
            request: first_request,
            ack: first_ack,
            consumed: Some(first_receipts),
            grant_dropped: false,
            replay_after_drop: false,
        },
        SeededAcquire {
            label: "dropped-grant",
            request: second_request,
            ack: second_ack,
            consumed: None,
            grant_dropped: true,
            replay_after_drop: true,
        },
    ];
    let manifest = json!({
        "kind": MANIFEST_KIND,
        "version": 1,
        "mode": mode,
        "scope": scope_json(fixture, scope, version),
        "parent_operation": parent_json(&parent, version),
        "backend_identity": blob.backend_identity().as_hex(),
        "authority_id": authority_id,
        "authority_generation": authority_generation,
        "acquires": acquires.iter().map(acquire_json).collect::<Result<Vec<Value>>>()?,
        "counts": table_counts,
        "tables": tables,
        "parent_operation_seeded_by_direct_sql_fixture": true,
        "parent_operation_is_adapter_or_git_ack": false,
        "provider_io_attempted": false,
        "raw_upload_attempted": false,
        "restored_blob_bytes_qualified": false,
        "restored_blob_bytes_denied": true,
        "physical_backup_closure": false,
    });
    std::fs::write(&fixture.output, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("write the private fixture manifest to {}", fixture.output.display()))?;
    println!("{MARKER} {}", serde_json::to_string(&manifest)?);
    Ok(())
}

#[tokio::test]
#[ignore = "root-selected only: needs the parent Python fixture database plus ROOTYARD_HOLDS_FIXTURE_* env, and panics without them"]
async fn artifact_hold_backup_metadata_fixture() -> Result<()> {
    let fixture = Fixture::from_env();
    let mode = Mode::from_env();
    let pool = db::pool(&fixture.url).context("connect to the parent fixture database")?;
    let version = gate_version(&pool, &fixture).await?;
    let scope = hold_scope(&fixture, &version)?;
    match mode {
        Mode::Seed => seed(&pool, &fixture, &scope, &version, mode.as_str()).await,
        Mode::Verify => verify(&pool, &fixture, &scope, &version, mode.as_str()).await,
    }
}

async fn verify(
    pool: &Pool,
    fixture: &Fixture,
    scope: &HoldScope,
    version: &CoreGateVersion,
    mode: &str,
) -> Result<()> {
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(&fixture.output)
            .with_context(|| format!("read the private fixture manifest {}", fixture.output.display()))?,
    )
    .context("parse the private fixture manifest")?;
    ensure!(field(&manifest, "kind")?.as_str() == Some(MANIFEST_KIND), "manifest kind differs");
    ensure!(field(&manifest, "mode")?.as_str() == Some("seed"), "verify needs the seed manifest");
    ensure!(
        *field(&manifest, "scope")? == scope_json(fixture, scope, version),
        "restored gate/scope differs from seed"
    );
    let blob = fixture_blob_store()?;
    let backend = blob.backend_identity().clone();
    ensure!(
        text_field(&manifest, "backend_identity")? == backend.as_hex(),
        "restored synthetic backend identity differs"
    );
    let gate_digest = RequestDigest::from_str(&text_field(field(&manifest, "scope")?, "gate_digest")?)?;
    let parent = parent_from_manifest(&manifest)?;
    check_parent_tuple(pool, fixture, &parent, version).await?;
    let authority_id = uuid_field(&manifest, "authority_id")?;
    let authority_generation = int_field(&manifest, "authority_generation")?;
    let before = table_rows(pool).await?;
    ensure!(before == *field(&manifest, "tables")?, "restored 141 rows differ from the seed rows");
    let mut checks = Vec::new();
    for entry in array_field(&manifest, "acquires")?.iter() {
        let request = request_from_manifest(
            scope,
            fixture,
            &parent,
            &backend,
            authority_id,
            authority_generation,
            gate_digest,
            entry,
        )?;
        let expected_ack: AcquireAck = serde_json::from_value(field(entry, "ack")?.clone())?;
        check_ack(&expected_ack, &request, &parent, version)?;
        let replayed = match acquire(pool, &blob, &request).await? {
            AcquireOutcome::Replayed { ack } => ack,
            AcquireOutcome::Granted { .. } => bail!("restored replay minted a grant/token"),
        };
        ensure!(replayed == expected_ack, "restored replay returned a different ACK");
        match acquire_receipt(pool, scope, request.request_id()).await? {
            AcquireLookup::Found(ack) if ack == expected_ack => {}
            other => bail!("restored acquire receipt is not the original ACK: {other:?}"),
        }
        let consumed = optional_section(entry, "consumed")?;
        let has_receipts = consumed.is_some();
        let labels = if let Some(consumed) = consumed {
            let receipts: Vec<ConsumeAck> = serde_json::from_value(field(consumed, "receipts")?.clone())?;
            let expected_id = uuid_field(consumed, "consume_request_id")?;
            ensure!(expected_id == expected_ack.consume_request_id, "manifest consume id differs from ACK");
            match consume_receipt(pool, scope, request.request_id(), expected_id).await? {
                ConsumeLookup::Found(restored) => ensure!(restored == receipts, "restored consume receipts differ"),
                ConsumeLookup::Unknown => bail!("restored consume receipts are missing"),
            }
            json!({"label": text_field(entry, "label")?, "replayed": true, "receipts": receipts.len(), "consume_lookup": "found"})
        } else {
            let consume_id = expected_ack.consume_request_id;
            match consume_receipt(pool, scope, request.request_id(), consume_id).await? {
                ConsumeLookup::Unknown => {}
                ConsumeLookup::Found(_) => bail!("an unconsumed dropped grant has a receipt"),
            }
            json!({"label": text_field(entry, "label")?, "replayed": true, "receipts": 0, "consume_lookup": "unknown"})
        };
        ensure!(
            ledger_counts(pool, request.request_id()).await? == if has_receipts { (1, 2, 2) } else { (1, 1, 0) },
            "restored ledger counts differ"
        );
        checks.push(labels);
        expect_scope_denials(pool, fixture, scope, &request, &expected_ack).await?;
    }
    let after = table_rows(pool).await?;
    ensure!(after == before, "an exact replay or receipt lookup mutated restored rows, counters or timestamps");
    assert_ledger(&after)?;
    let marker = json!({
        "kind": MANIFEST_KIND,
        "version": 1,
        "mode": mode,
        "scope": scope_json(fixture, scope, version),
        "parent_operation": parent_json(&parent, version),
        "checks": checks,
        "counts": counts(&after)?,
        "restored_rows_equal_pre_backup_rows": true,
        "exact_replay_returned_original_ack_without_grant": true,
        "exact_replay_returned_original_consume_receipts": true,
        "replay_mutated_rows_counters_or_timestamps": false,
        "unconsumed_consume_lookup": "unknown",
        "scope_mismatch_denied": true,
        "provider_io_attempted": false,
        "raw_upload_attempted": false,
        "restored_blob_bytes_qualified": false,
        "restored_blob_bytes_denied": true,
        "physical_backup_closure": false,
    });
    println!("{MARKER} {}", serde_json::to_string(&marker)?);
    Ok(())
}

async fn expect_scope_denials(
    pool: &Pool,
    fixture: &Fixture,
    scope: &HoldScope,
    request: &AcquireArtifactHoldsRequest,
    ack: &AcquireAck,
) -> Result<()> {
    let wrong_owner = HoldScope::new(
        scope.repository_id(),
        scope.tenant_id(),
        Uuid::new_v4(),
        scope.purpose(),
        scope.object_format(),
        scope.history_incarnation(),
        scope.authority_epoch(),
        scope.group_epoch(),
    )?;
    let wrong_history = HoldScope::new(
        scope.repository_id(),
        scope.tenant_id(),
        scope.owner_id(),
        scope.purpose(),
        scope.object_format(),
        Uuid::new_v4(),
        scope.authority_epoch(),
        scope.group_epoch(),
    )?;
    for (wrong, expected) in [(&wrong_owner, "request owner"), (&wrong_history, "request history incarnation")] {
        match acquire_receipt(pool, wrong, request.request_id()).await {
            Err(ArtifactHoldError::ScopeMismatch(reason)) if reason == expected => {}
            other => bail!("wrong-scope acquire receipt was not denied as {expected}: {other:?}"),
        }
        match consume_receipt(pool, wrong, request.request_id(), ack.consume_request_id).await {
            Err(ArtifactHoldError::ScopeMismatch(reason)) if reason == expected => {}
            other => bail!("wrong-scope consume receipt was not denied as {expected}: {other:?}"),
        }
    }
    ensure!(
        acquire_receipt(pool, scope, Uuid::new_v4()).await? == AcquireLookup::Unknown,
        "missing acquire was not Unknown"
    );
    ensure!(fixture.owner == scope.owner_id(), "fixture owner differs from the trusted scope");
    Ok(())
}

fn scope_json(fixture: &Fixture, scope: &HoldScope, version: &CoreGateVersion) -> Value {
    json!({
        "repository_id": fixture.repository.to_string(),
        "tenant_id": scope.tenant_id().to_string(),
        "owner_id": scope.owner_id().to_string(),
        "purpose": scope.purpose().as_str(),
        "object_format": scope.object_format().as_str(),
        "history_incarnation": scope.history_incarnation().to_string(),
        "authority_epoch": scope.authority_epoch(),
        "group_epoch": scope.group_epoch(),
        "gate_revision": version.revision(),
        "gate_digest": version.digest().as_hex(),
        "head_ref": version.head_ref().as_str(),
    })
}

fn parent_json(parent: &ParentFixture, version: &CoreGateVersion) -> Value {
    json!({
        "issuer_id": parent.issuer_id.to_string(),
        "lane": parent.lane.clone(),
        "sequence": parent.sequence,
        "operation_id": parent.operation_id.to_string(),
        "operation_digest": parent.digest.as_hex(),
        "gate_revision": version.revision(),
        "gate_digest": version.digest().as_hex(),
        "seeded_by": "direct_sql_metadata_fixture",
        "adapter_or_git_ack": false,
    })
}

fn parent_from_manifest(manifest: &Value) -> Result<ParentFixture> {
    let parent = field(manifest, "parent_operation")?;
    ensure!(
        parent.get("seeded_by").and_then(Value::as_str) == Some("direct_sql_metadata_fixture"),
        "parent seed kind differs"
    );
    ensure!(
        parent.get("adapter_or_git_ack").and_then(Value::as_bool) == Some(false),
        "parent fixture must not claim an adapter ACK"
    );
    Ok(ParentFixture {
        issuer_id: uuid_field(parent, "issuer_id")?,
        lane: text_field(parent, "lane")?,
        sequence: int_field(parent, "sequence")?,
        operation_id: uuid_field(parent, "operation_id")?,
        digest: RequestDigest::from_str(&text_field(parent, "operation_digest")?)?,
    })
}

fn acquire_json(acquire: &SeededAcquire) -> Result<Value> {
    let consumed = match &acquire.consumed {
        Some(receipts) => {
            let values = receipts
                .iter()
                .map(serde_json::to_value)
                .collect::<std::result::Result<Vec<Value>, serde_json::Error>>()?;
            json!({
                "consume_request_id": acquire.ack.consume_request_id.to_string(),
                "receipts": values,
            })
        }
        None => Value::Null,
    };
    Ok(json!({
        "label": acquire.label,
        "request_id": acquire.request.request_id().to_string(),
        "operation": {
            "issuer_id": acquire.request.operation().issuer_id().to_string(),
            "lane": acquire.request.operation().lane().as_str(),
            "sequence": acquire.request.operation().sequence(),
            "operation_id": acquire.request.operation().operation_id().to_string(),
            "operation_digest": acquire.request.operation().digest().as_hex(),
        },
        "authority_id": acquire.request.authority_id().to_string(),
        "authority_generation": acquire.request.authority_generation(),
        "artifacts": acquire.request.artifacts().iter().map(|artifact| json!({
            "namespace": artifact.namespace(),
            "sha256": artifact.sha256(),
            "length": artifact.length(),
        })).collect::<Vec<Value>>(),
        "ack": serde_json::to_value(&acquire.ack)?,
        "consumed": consumed,
        "grant_dropped": acquire.grant_dropped,
        "replay_after_drop": acquire.replay_after_drop,
    }))
}

#[allow(clippy::too_many_arguments)]
fn request_from_manifest(
    scope: &HoldScope,
    fixture: &Fixture,
    parent: &ParentFixture,
    backend: &rootyard::blob_store::BlobBackendIdentity,
    authority_id: Uuid,
    authority_generation: i64,
    gate_digest: RequestDigest,
    entry: &Value,
) -> Result<AcquireArtifactHoldsRequest> {
    let operation = field(entry, "operation")?;
    ensure!(uuid_field(operation, "issuer_id")? == parent.issuer_id, "manifest operation issuer differs");
    ensure!(text_field(operation, "lane")? == parent.lane, "manifest operation lane differs");
    ensure!(int_field(operation, "sequence")? == parent.sequence, "manifest operation sequence differs");
    ensure!(uuid_field(operation, "operation_id")? == parent.operation_id, "manifest parent operation id differs");
    let identity = OperationIdentity::new(
        fixture.repository,
        parent.issuer_id,
        IssuerLane::new(parent.lane.clone())?,
        parent.sequence,
        parent.operation_id,
        RequestDigest::from_str(&text_field(operation, "operation_digest")?)?,
    )?;
    let artifacts = array_field(entry, "artifacts")?
        .iter()
        .map(|artifact| {
            Ok(ArtifactSpec::new(
                text_field(artifact, "namespace")?,
                text_field(artifact, "sha256")?,
                u64::try_from(int_field(artifact, "length")?)?,
            )?)
        })
        .collect::<Result<Vec<ArtifactSpec>>>()?;
    acquire_request(
        *scope,
        identity,
        uuid_field(entry, "request_id")?,
        backend.clone(),
        authority_id,
        authority_generation,
        gate_digest,
        artifacts,
    )
}

async fn table_rows(pool: &Pool) -> Result<Value> {
    let client = pool.get().await.context("checkout a catalog reader connection")?;
    client.batch_execute("SET TIME ZONE 'UTC'").await.context("normalize fixture JSON timestamps to UTC")?;
    let row = client
        .query_one(
            "SELECT json_build_object(
                 'artifact_hold_requests', (SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)
                     FROM public.artifact_hold_requests t),
                 'artifact_holds', (SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)
                     FROM public.artifact_holds t),
                 'artifact_hold_consume_receipts', (SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)
                     FROM public.artifact_hold_consume_receipts t),
                 'artifact_hold_shards', (SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)
                     FROM public.artifact_hold_shards t),
                 'artifact_hold_repo_usage', (SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)
                     FROM public.artifact_hold_repo_usage t),
                 'artifact_hold_tenant_usage', (SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)
                     FROM public.artifact_hold_tenant_usage t))",
            &[],
        )
        .await
        .context("capture the six migration-141 artifact-hold tables")?;
    Ok(row.get(0))
}

fn counts(tables: &Value) -> Result<Value> {
    let mut object = serde_json::Map::new();
    for name in TABLES {
        object.insert(name.to_owned(), json!(table(tables, name)?.len()));
    }
    Ok(Value::Object(object))
}

fn assert_ledger(tables: &Value) -> Result<()> {
    for name in TABLES {
        ensure!(!table(tables, name)?.is_empty(), "migration-141 table {name} is empty");
    }
    let requests = table(tables, "artifact_hold_requests")?;
    let holds = table(tables, "artifact_holds")?;
    let receipts = table(tables, "artifact_hold_consume_receipts")?;
    let shards = table(tables, "artifact_hold_shards")?;
    ensure!(requests.len() == 2, "the fixture must retain exactly two acquire requests");
    ensure!(holds.len() == 3, "the fixture must retain exactly three holds");
    ensure!(receipts.len() == 2, "the fixture must retain exactly two consume receipts");
    ensure!(shards.len() == GLOBAL_SHARDS as usize, "migration 141 must retain exactly 64 shard rows");
    ensure!(table(tables, "artifact_hold_repo_usage")?.len() == 1, "one repository usage row is required");
    ensure!(table(tables, "artifact_hold_tenant_usage")?.len() == 1, "one tenant usage row is required");
    let mut ids = BTreeSet::new();
    let mut shard_rows: BTreeMap<i64, (i64, i64, i64, i64)> = BTreeMap::new();
    for shard in shards.iter() {
        let id = int_field(shard, "shard_id")?;
        ensure!((0..GLOBAL_SHARDS as i64).contains(&id), "shard id is outside 0..64");
        ensure!(ids.insert(id), "duplicate shard row");
        let counters = (
            int_field(shard, "hold_count")?,
            int_field(shard, "declared_bytes")?,
            int_field(shard, "logical_bytes")?,
            int_field(shard, "receipt_count")?,
        );
        ensure!(counters.0 >= 0 && counters.0 <= SHARD_MAX_HOLDS, "shard hold counter is outside its ceiling");
        ensure!(
            counters.1 >= 0 && counters.1 <= SHARD_MAX_DECLARED_BYTES,
            "shard declared counter is outside its ceiling"
        );
        ensure!(
            counters.2 >= 0 && counters.2 <= SHARD_MAX_LOGICAL_BYTES,
            "shard logical counter is outside its ceiling"
        );
        ensure!(counters.3 >= 0 && counters.3 <= SHARD_MAX_RECEIPTS, "shard receipt counter is outside its ceiling");
        ensure!(shard_rows.insert(id, counters).is_none(), "duplicate shard row");
    }
    let expected_ids: BTreeSet<i64> = (0..GLOBAL_SHARDS as i64).collect();
    ensure!(ids == expected_ids, "the fixed 64 shard identities changed");
    let mut request_meta: HashMap<Uuid, (i64, i64, i64, i64)> = HashMap::new();
    for request in requests.iter() {
        let request_id = uuid_json(request, "request_id")?;
        let shard = int_field(request, "shard_id")?;
        ensure!((0..GLOBAL_SHARDS as i64).contains(&shard), "request shard is outside 0..64");
        let count = int_field(request, "artifact_count")?;
        ensure!((1..=16).contains(&count), "request artifact count is not bounded");
        ensure!(
            request_meta
                .insert(
                    request_id,
                    (shard, count, int_field(request, "declared_bytes")?, int_field(request, "logical_bytes")?)
                )
                .is_none(),
            "duplicate request row"
        );
    }
    let mut computed = BTreeMap::<i64, (i64, i64, i64, i64)>::new();
    for id in 0..GLOBAL_SHARDS as i64 {
        computed.insert(id, (0, 0, 0, 0));
    }
    // Each acquire ACK is itself one retained receipt and charges its UTF-8
    // ACK body plus 128 bytes of bounded logical overhead.
    for request in requests.iter() {
        let request_id = uuid_json(request, "request_id")?;
        let shard_id = request_meta.get(&request_id).context("request shard is missing")?.0;
        let ack_body = text_field(request, "ack_body")?;
        ensure!(!ack_body.is_empty() && ack_body.len() <= 65536, "request ACK body is not bounded");
        let shard = computed.get_mut(&shard_id).context("request shard is missing")?;
        shard.2 += ack_body.len() as i64 + 128;
        shard.3 += 1;
    }
    let mut per_request_holds = HashMap::<Uuid, (i64, i64, i64)>::new();
    for hold in holds.iter() {
        ensure!(
            text_field(hold, "state")? == "active" && int_field(hold, "generation")? == 1,
            "a hold is not permanent active generation 1"
        );
        let request_id = uuid_json(hold, "request_id")?;
        let request = request_meta.get(&request_id).context("hold names an unknown request")?;
        let declared = int_field(hold, "declared_bytes")?;
        let logical = int_field(hold, "logical_bytes")?;
        ensure!(declared >= 0 && logical > 0, "hold byte accounting is invalid");
        let entry = per_request_holds.entry(request_id).or_insert((0, 0, 0));
        entry.0 += 1;
        entry.1 += declared;
        entry.2 += logical;
        let shard = computed.get_mut(&request.0).context("request shard is missing")?;
        shard.0 += 1;
        shard.1 += declared;
        shard.2 += logical;
    }
    for (request_id, request) in &request_meta {
        let actual = per_request_holds.get(request_id).copied().unwrap_or((0, 0, 0));
        ensure!(actual == (request.1, request.2, request.3), "request row counters differ from its holds");
    }
    for receipt in receipts.iter() {
        let request_id = uuid_json(receipt, "request_id")?;
        let request = request_meta.get(&request_id).context("consume receipt names an unknown request")?;
        let body = text_field(receipt, "body")?;
        ensure!(!body.is_empty() && body.len() <= 65536, "consume receipt body is not bounded");
        let shard = computed.get_mut(&request.0).context("request shard is missing")?;
        shard.2 += body.len() as i64 + 128;
        shard.3 += 1;
        ensure!(text_field(receipt, "consume_digest")?.len() == 64, "consume digest is not sha256 hex");
    }
    for (id, expected) in computed {
        ensure!(shard_rows.get(&id).copied() == Some(expected), "shard {id} counters do not equal its retained rows");
    }
    let repo = table(tables, "artifact_hold_repo_usage")?.first().context("repository usage is missing")?;
    let tenant = table(tables, "artifact_hold_tenant_usage")?.first().context("tenant usage is missing")?;
    let total_holds = holds.len() as i64;
    let total_declared: i64 = holds.iter().map(|row| int_field(row, "declared_bytes").unwrap_or(0)).sum();
    let mut total_logical: i64 = holds.iter().map(|row| int_field(row, "logical_bytes").unwrap_or(0)).sum();
    for request in requests.iter() {
        total_logical += text_field(request, "ack_body")?.len() as i64 + 128;
    }
    for receipt in receipts.iter() {
        total_logical += text_field(receipt, "body")?.len() as i64 + 128;
    }
    // The acquire ACK is a retained receipt too; consume adds one per hold.
    let total_receipts = requests.len() as i64 + receipts.len() as i64;
    for usage in [repo, tenant] {
        ensure!(int_field(usage, "hold_count")? == total_holds, "retained hold counter differs from hold rows");
        ensure!(int_field(usage, "declared_bytes")? == total_declared, "retained declared counter differs");
        ensure!(int_field(usage, "logical_bytes")? == total_logical, "retained logical counter differs");
        ensure!(int_field(usage, "receipt_count")? == total_receipts, "retained receipt counter differs");
    }
    Ok(())
}

fn optional_section<'a>(value: &'a Value, key: &str) -> Result<Option<&'a Value>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(section) => Ok(Some(section)),
    }
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).with_context(|| format!("fixture metadata field {key:?} is missing"))
}

fn text_field(value: &Value, key: &str) -> Result<String> {
    Ok(field(value, key)?
        .as_str()
        .with_context(|| format!("fixture metadata field {key:?} must be a string"))?
        .to_owned())
}

fn uuid_field(value: &Value, key: &str) -> Result<Uuid> {
    Uuid::parse_str(&text_field(value, key)?).with_context(|| format!("fixture metadata field {key:?} is not a UUID"))
}

fn uuid_json(value: &Value, key: &str) -> Result<Uuid> {
    uuid_field(value, key)
}

fn int_field(value: &Value, key: &str) -> Result<i64> {
    field(value, key)?.as_i64().with_context(|| format!("fixture metadata field {key:?} must be an integer"))
}

fn array_field<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    field(value, key)?.as_array().with_context(|| format!("fixture metadata field {key:?} must be an array"))
}

fn table<'a>(tables: &'a Value, name: &str) -> Result<&'a Vec<Value>> {
    array_field(tables, name)
}
