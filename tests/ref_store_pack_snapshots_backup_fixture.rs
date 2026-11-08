//! Root-selected companion fixture for the populated schema-143 A5a pack-snapshot
//! backup drill (#105/#107).
//!
//! Only `tests/backup_refstore_pack_snapshots143.py` selects this integration-test
//! executable. It never creates a database/schema and never runs a migration: the
//! parent owns one fresh migrated database, seeds the inherited plain-SQL
//! migration-139 metadata gate/ref fixture and then runs this helper.
//!
//! Seed mode is the real typed pipeline, modelled on the retained A4a
//! `tests/ref_store_packs_backup_fixture.rs` but extended with A5a:
//!
//! 1. one random unserved `provisioning`/`gitfs` repository gets an own typed gate
//!    through `PgRefStoreCore::initialize`;
//! 2. mature Git writes a real `.pack`/`.idx` from a synthetic native commit, A3
//!    acquires two holds, the protected uploader consumes them and uploads the
//!    exact bytes to the configured **real S3** store, A4 registers the
//!    publication, captures the closure context, runs the real `PackVerifier`
//!    against the S3 bytes and performs the verified PG commit (gate revision 2,
//!    `pack_verified`);
//! 3. BEFORE activation one genuine A2 metadata-only snapshot/pin/receipt is
//!    created at gate revision 1 so the restored archive proves old A2 rows stay
//!    `metadata_only`/`unavailable` and remain readable;
//! 4. AFTER activation A5 snapshots/pins/history are created under a **separate
//!    producer identity B** (a different user row) while the A4 publisher identity
//!    A stays the repository owner/tenant. Four scenarios are seeded:
//!    `active` (long TTL), `renewed` (generation 2), `released`, and — created
//!    last with a 1s lease — `expired` by DB clock; the helper polls
//!    `clock_timestamp()` (bounded) until the short lease really elapsed and then
//!    proves the typed read refusal.
//!
//! No ACK, proof, token, receipt or hash is fabricated from SQL: every digest in
//! the marker comes from the normalized typed request/plan values. The marker is
//! secret-free (no DSN/token/credential) and carries full rows, the full typed
//! scope, refs/HEAD, pack identities, digests, pin generation/expiry, history and
//! the charged counters.
//!
//! Verify mode runs against the restored database and uses only typed read-only
//! paths: `PgPackSnapshot::read` (complete registered pack metadata,
//! `complete_git_read_snapshot()==false`), `query_receipt` (historical create ->
//! `Found`, renew/release -> `FoundPin`, no live lease) and the A2 page reader for
//! the old metadata-only snapshot. It re-reads the external S3 originals and
//! hashes them, compares every captured row family exactly before/after (no new
//! row, charge or grant), and needs no source-only pack/idx tempfile.
//!
//! Not claimed: Blob byte backup. The S3 originals are external, only re-read, and
//! no held remote object is deleted. `complete_git_read_snapshot()` is false
//! everywhere (A5b only).

use anyhow::{Context, Result, anyhow, bail, ensure};
use deadpool_postgres::Pool;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::blob_store::protected::{ProtectedPublication, ProtectedUploader, UploadSource};
use rootyard::db;
use rootyard::ref_store::artifact_hold::{
    AcquireAck, AcquireArtifactHoldsRequest, AcquireLookup, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec,
    ConsumeAck, ConsumeLookup, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::core::pack_commit::{
    ContentDigest, PackArtifactRole, PackClosureContext, PackClosureProof, PackCommitExpectation, PackCommitPlan,
    PackCommitReceipt, PackCommitScope, PackMode, PackPendingToken, PackRegistrationReceipt, PackRegistrationRequest,
    PackVerifier, PgPackCommit, PlannedArtifact, PlannedPack, RegisteredPack,
};
use rootyard::ref_store::core::{
    CreateMetadataSnapshotOutcome, CreateMetadataSnapshotRequest, CreatePackSnapshotRequest, MetadataPinOutcome,
    MetadataPinReceipt, MetadataSnapshotPage, MetadataSnapshotReceipt, MetadataSnapshotScope, PackReadSnapshot,
    PackSnapshotExpectation, PackSnapshotLookup, PackSnapshotOutcome, PackSnapshotReceipt, PackSnapshotReceiptQuery,
    PackSnapshotRef, PgPackSnapshot, PgRefStoreCore, ReadMetadataSnapshotPageRequest, ReleaseMetadataPinRequest,
    RenewMetadataPinRequest,
};
use rootyard::ref_store::{
    CoreGateInit, CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, MetadataMutationAction,
    MetadataPinPurpose, OperationIdentity, OperationLookup, OperationState, PgRefStore, PinReleaseReason, RefName,
    RefPrecondition, RefStoreError, RefTarget, RefUpdate, RequestDigest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant as StdInstant};
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;
use uuid::Uuid;

const MARKER: &str = "ROOTYARD-REF-STORE-PACK-SNAPSHOTS-FIXTURE-METADATA";
const MANIFEST_KIND: &str = "rootyard/ref-store-core-pack-snapshots-backup-fixture";
const LANE: &str = "pack-snapshot-backup-drill";
const HOLD_NAMESPACE: &str = "core-pack";
const DEADLINE_SECONDS: u64 = 60;
const EXPIRY_POLL_SECONDS: u64 = 30;

#[derive(Clone, Copy)]
enum Owner {
    Repo,
    Tenant,
    All,
}

/// The four migration-143 A5 tables owned by this drill.
const SNAPSHOT_TABLES: [(&str, Owner); 4] = [
    ("ref_store_core_snapshot_packs", Owner::Repo),
    ("ref_store_core_pack_snapshot_history", Owner::Repo),
    ("ref_store_core_pack_snapshot_repo_usage", Owner::Repo),
    ("ref_store_core_pack_snapshot_tenant_usage", Owner::Tenant),
];

/// The complete migration-140 A2 snapshot ledger (old metadata + A5 pack rows).
const A2_TABLES: [(&str, Owner); 6] = [
    ("ref_store_core_snapshots", Owner::Repo),
    ("ref_store_core_snapshot_refs", Owner::All),
    ("ref_store_core_pins", Owner::Repo),
    ("ref_store_core_receipts", Owner::Repo),
    ("ref_store_core_repo_usage", Owner::Repo),
    ("ref_store_core_tenant_usage", Owner::Tenant),
];

/// The six migration-142 A4 tables populated by the verified pack commit.
const PACK_TABLES: [(&str, Owner); 6] = [
    ("ref_store_core_pack_publications", Owner::Repo),
    ("ref_store_core_pack_artifacts", Owner::Repo),
    ("ref_store_core_pack_memberships", Owner::Repo),
    ("ref_store_core_pack_history", Owner::Repo),
    ("ref_store_core_pack_repo_usage", Owner::Repo),
    ("ref_store_core_pack_tenant_usage", Owner::Tenant),
];

/// The complete migration-141 A3 hold ledger of the verified upload.
const HOLD_TABLES: [(&str, Owner); 6] = [
    ("artifact_hold_requests", Owner::Repo),
    ("artifact_holds", Owner::Repo),
    ("artifact_hold_consume_receipts", Owner::Repo),
    ("artifact_hold_shards", Owner::All),
    ("artifact_hold_repo_usage", Owner::Repo),
    ("artifact_hold_tenant_usage", Owner::Tenant),
];

/// The six migration-139 registry/gate tables, scoped to the drill repository.
const CORE_TABLES: [(&str, Owner); 6] = [
    ("ref_store_issuer_lanes", Owner::Repo),
    ("ref_store_operations", Owner::Repo),
    ("ref_store_cancellations", Owner::Repo),
    ("ref_store_core_gates", Owner::Repo),
    ("ref_store_core_refs", Owner::Repo),
    ("ref_store_core_events", Owner::Repo),
];

enum Mode {
    Seed,
    Verify,
}

impl Mode {
    fn from_env() -> Self {
        match std::env::var("ROOTYARD_PACK_SNAPSHOTS_FIXTURE_MODE").as_deref() {
            Ok("seed") => Self::Seed,
            Ok("verify") => Self::Verify,
            other => panic!("ROOTYARD_PACK_SNAPSHOTS_FIXTURE_MODE must be seed|verify, got {other:?}"),
        }
    }
}

struct Fixture {
    url: String,
    output: PathBuf,
    git: PathBuf,
    format: GitObjectFormat,
}

impl Fixture {
    fn from_env() -> Self {
        let format = match std::env::var("ROOTYARD_PACK_SNAPSHOTS_FIXTURE_FORMAT") {
            Ok(value) => GitObjectFormat::parse(&value)
                .unwrap_or_else(|error| panic!("ROOTYARD_PACK_SNAPSHOTS_FIXTURE_FORMAT is invalid: {error}")),
            Err(_) => GitObjectFormat::Sha1,
        };
        Self {
            url: required("ROOTYARD_TEST_DATABASE_URL"),
            output: PathBuf::from(required("ROOTYARD_PACK_SNAPSHOTS_FIXTURE_OUTPUT")),
            git: git_binary(),
            format,
        }
    }
}

fn required(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => panic!(
            "{name} is required: this fixture only runs under the owning pack-snapshot backup drill, \
             never from a routine test command"
        ),
    }
}

fn git_binary() -> PathBuf {
    let path = match std::env::var("ROOTYARD_TEST_GIT") {
        Ok(value) => PathBuf::from(value),
        Err(_) => PathBuf::from("/usr/bin/git"),
    };
    assert!(path.is_absolute(), "ROOTYARD_TEST_GIT must be an absolute path");
    assert!(path.is_file(), "the configured absolute git binary does not exist");
    path
}

/// Real S3 is mandatory: a missing/invalid profile or another provider is a hard
/// failure, never a skip. Credentials are inherited and never printed.
fn open_store() -> Result<BlobStore> {
    let profile =
        BlobProfile::from_env().map_err(|error| anyhow!("configured ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(
        profile.provider() == rootyard::blob_store::BlobProvider::S3,
        "pack snapshot backup qualification requires real S3"
    );
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(DEADLINE_SECONDS)
}

fn std_deadline() -> StdInstant {
    StdInstant::now() + Duration::from_secs(DEADLINE_SECONDS)
}

fn digest_file(path: &Path) -> Result<(String, u64)> {
    let bytes = std::fs::read(path)?;
    Ok((hex::encode(Sha256::digest(&bytes)), bytes.len() as u64))
}

fn main_update(format: GitObjectFormat, commit: &str) -> Result<RefUpdate> {
    Ok(RefUpdate::new(
        RefName::branch("refs/heads/main")?,
        RefPrecondition::Absent,
        RefTarget::Oid(GitOid::parse(format, commit)?),
    ))
}

fn hold_scope(plan: &PackCommitPlan) -> Result<HoldScope> {
    HoldScope::new(
        plan.repository_id(),
        plan.tenant_id(),
        plan.owner_id(),
        ArtifactHoldPurpose::RefPublication,
        plan.object_format(),
        plan.history_incarnation(),
        plan.authority_epoch(),
        plan.group_epoch(),
    )
    .map_err(|error| anyhow!("hold scope rejected: {error}"))
}

/// Fixture-only business rows: one internal producer identity (also the
/// repository owner/tenant/publisher A) and one separate A5 producer B row.
async fn create_business(pool: &Pool, repository: Uuid, tenant: Uuid, format: GitObjectFormat) -> Result<()> {
    let object_format = format.as_str().to_owned();
    let username = format!("snapdrill{}", &tenant.simple().to_string()[..12]);
    let name = format!("snapdrill{}", &repository.simple().to_string()[..12]);
    let client = pool.get().await?;
    client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&tenant, &username]).await?;
    client
        .execute(
            "INSERT INTO repositories(id,owner_id,name,state,storage_backend,storage_generation,next_retry_at,
                 provision_attempts,object_format)
             VALUES($1,$2,$3,'provisioning','gitfs',1,clock_timestamp()+interval '100 years',0,$4)",
            &[&repository, &tenant, &name, &object_format],
        )
        .await?;
    drop(client);
    Ok(())
}

/// A distinct A5 snapshot producer identity B (a real `users` row). It is neither
/// the repository owner nor the A4 publication owner A.
async fn create_producer(pool: &Pool, producer: Uuid) -> Result<()> {
    let username = format!("snapproducer{}", &producer.simple().to_string()[..12]);
    let client = pool.get().await?;
    client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&producer, &username]).await?;
    drop(client);
    Ok(())
}

async fn initialize_gate(
    pool: &Pool,
    repository: Uuid,
    tenant: Uuid,
    format: GitObjectFormat,
) -> Result<CoreGateVersion> {
    let init =
        CoreGateInit::new(repository, tenant, format, Uuid::new_v4(), 1, 1, RefName::branch("refs/heads/main")?)?;
    let mut client = pool.get().await?;
    let gate = PgRefStoreCore.initialize(&mut client, &init, deadline()).await?;
    drop(client);
    ensure!(gate.revision() == 1, "a fresh typed gate is not revision 1");
    ensure!(gate.tenant_id() == tenant && gate.repository_id() == repository, "typed gate scope differs");
    Ok(gate.version())
}

async fn gate_state(pool: &Pool, repository: Uuid) -> Result<(i64, String)> {
    let row = pool
        .get()
        .await?
        .query_one("SELECT revision,pack_mode FROM ref_store_core_gates WHERE repository_id=$1", &[&repository])
        .await?;
    Ok((row.get(0), row.get(1)))
}

async fn pack_usage(pool: &Pool, repository: Uuid) -> Result<Option<[i64; 7]>> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT snapshot_count,snapshot_ref_count,binding_count,pin_count,history_count,receipt_count,
                    logical_bytes
             FROM ref_store_core_pack_snapshot_repo_usage WHERE repository_id=$1",
            &[&repository],
        )
        .await?;
    Ok(row.map(|r| [r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5), r.get(6)]))
}

async fn pack_tenant_usage(pool: &Pool, tenant: Uuid) -> Result<Option<[i64; 7]>> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT snapshot_count,snapshot_ref_count,binding_count,pin_count,history_count,receipt_count,
                    logical_bytes
             FROM ref_store_core_pack_snapshot_tenant_usage WHERE tenant_id=$1",
            &[&tenant],
        )
        .await?;
    Ok(row.map(|r| [r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5), r.get(6)]))
}

async fn a2_usage(pool: &Pool, repository: Uuid) -> Result<[i64; 4]> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT snapshot_count,snapshot_ref_count,logical_bytes,receipt_count
             FROM ref_store_core_repo_usage WHERE repository_id=$1",
            &[&repository],
        )
        .await?;
    Ok(row.map(|r| [r.get(0), r.get(1), r.get(2), r.get(3)]).unwrap_or([0; 4]))
}

async fn snapshot_counts(pool: &Pool, repository: Uuid) -> Result<(i64, i64, i64, i64, i64)> {
    let row = pool
        .get()
        .await?
        .query_one(
            "SELECT (SELECT count(*) FROM ref_store_core_snapshots WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_snapshot_refs r
                       JOIN ref_store_core_snapshots s USING(snapshot_id) WHERE s.repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_pins WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_receipts WHERE repository_id=$1),
                    (SELECT count(*) FROM ref_store_core_snapshot_packs WHERE repository_id=$1)",
            &[&repository],
        )
        .await?;
    Ok((row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
}

/// Observation-only JSON capture of one table (never an ACK, proof or grant).
async fn rows_json(pool: &Pool, table: &str, owner: Owner, repository: Uuid, tenant: Uuid) -> Result<Value> {
    let client = pool.get().await?;
    let text: String = match owner {
        Owner::Repo => client
            .query_one(
                &format!(
                    "SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)::text \
                         FROM public.\"{table}\" t WHERE t.repository_id=$1"
                ),
                &[&repository],
            )
            .await?
            .get(0),
        Owner::Tenant => client
            .query_one(
                &format!(
                    "SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)::text \
                         FROM public.\"{table}\" t WHERE t.tenant_id=$1"
                ),
                &[&tenant],
            )
            .await?
            .get(0),
        Owner::All => client
            .query_one(
                &format!(
                    "SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)::text FROM public.\"{table}\" t"
                ),
                &[],
            )
            .await?
            .get(0),
    };
    Ok(serde_json::from_str(&text)?)
}

async fn capture(pool: &Pool, tables: &[(&str, Owner)], repository: Uuid, tenant: Uuid) -> Result<Value> {
    let mut object = serde_json::Map::new();
    for &(table, owner) in tables {
        object.insert(table.to_owned(), rows_json(pool, table, owner, repository, tenant).await?);
    }
    Ok(Value::Object(object))
}

fn counts(rows: &Value) -> Value {
    let mut object = serde_json::Map::new();
    if let Value::Object(tables) = rows {
        for (name, value) in tables {
            object.insert(name.clone(), json!(value.as_array().map(Vec::len).unwrap_or(0)));
        }
    }
    Value::Object(object)
}

fn value_of<T: serde::Serialize>(value: &T) -> Result<Value> {
    Ok(serde_json::to_value(value)?)
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

fn int_field(value: &Value, key: &str) -> Result<i64> {
    field(value, key)?.as_i64().with_context(|| format!("fixture metadata field {key:?} must be an integer"))
}

fn array_field<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    field(value, key)?.as_array().with_context(|| format!("fixture metadata field {key:?} must be an array"))
}

fn table<'a>(rows: &'a Value, name: &str) -> Result<&'a Vec<Value>> {
    array_field(rows, name)
}

fn json_array_fixed<const N: usize>(value: &Value) -> Result<[i64; N]> {
    let items = json_array_i64(value)?;
    ensure!(items.len() == N, "fixture metadata array does not have the expected fixed length");
    let mut fixed = [0_i64; N];
    for (slot, item) in fixed.iter_mut().zip(items.iter()) {
        *slot = *item;
    }
    Ok(fixed)
}

fn json_array_i64(value: &Value) -> Result<Vec<i64>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("fixture metadata value is not an array"))?
        .iter()
        .map(|item| item.as_i64().ok_or_else(|| anyhow!("fixture metadata array item is not an integer")))
        .collect()
}

fn receipt_json(receipt: &PackSnapshotReceipt) -> Value {
    json!({
        "request_id": receipt.request_id().to_string(),
        "snapshot_id": receipt.snapshot_id().to_string(),
        "pin_id": receipt.pin_id().to_string(),
        "pin_generation": receipt.pin_generation(),
        "repository_id": receipt.repository_id().to_string(),
        "tenant_id": receipt.tenant_id().to_string(),
        "owner_id": receipt.owner_id().to_string(),
        "gate_revision": receipt.gate_revision(),
        "gate_digest": receipt.gate_digest_hex(),
        "pack_mode": receipt.pack_mode(),
        "head_ref": receipt.head_ref(),
        "head_oid": receipt.head_oid_hex(),
        "ref_count": receipt.ref_count(),
        "refs_digest": receipt.refs_digest_hex(),
        "membership_digest": receipt.membership_digest_hex(),
        "pack_count": receipt.pack_count(),
        "snapshot_digest": receipt.snapshot_digest_hex(),
        "logical_bytes": receipt.logical_bytes(),
        "expires_at_unix_micros": receipt.expires_at_unix_micros(),
        "complete_git_read_snapshot": receipt.complete_git_read_snapshot(),
        "complete_registered_pack_membership": receipt.complete_registered_pack_membership(),
    })
}

fn pin_receipt_json(receipt: &MetadataPinReceipt) -> Value {
    // The typed A2 lifecycle result is `MetadataPinReceipt`; the historical
    // lookup returns the sealed `PackPinReceipt`.  Record the canonical public
    // fields of the A2 receipt (never a structural equality across wrappers).
    let history_kind = match receipt.action() {
        MetadataMutationAction::Renew => "renewed",
        MetadataMutationAction::Release => "released",
        MetadataMutationAction::Create => "created",
    };
    json!({
        "request_id": receipt.request_id().to_string(),
        "action": receipt.action().as_str(),
        "history_kind": history_kind,
        "snapshot_id": receipt.snapshot_id().to_string(),
        "pin_id": receipt.pin_id().to_string(),
        "pin_generation": receipt.pin_generation(),
        "expires_at_unix_micros": receipt.expires_at_unix_micros(),
        "released_at_unix_micros": receipt.released_at_unix_micros(),
        "release_reason": receipt.release_reason().map(PinReleaseReason::as_str),
        // A historical metadata receipt is not a live lease or a Git-read proof.
        "grants_live_lease": false,
        "complete_git_read_snapshot": false,
    })
}

fn page_refs(page: &MetadataSnapshotPage) -> Value {
    Value::Array(
        page.refs()
            .iter()
            .map(|reference| json!({"name": reference.name().as_str(), "oid": reference.oid().as_hex()}))
            .collect(),
    )
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

async fn a2_page(
    pool: &Pool,
    scope: MetadataSnapshotScope,
    snapshot_id: Uuid,
    pin_id: Uuid,
    generation: i64,
) -> Result<MetadataSnapshotPage, RefStoreError> {
    let request = ReadMetadataSnapshotPageRequest::new(scope, snapshot_id, pin_id, generation, None, None, 128)?;
    let mut client = pool.get().await.map_err(|error| RefStoreError::Database(error.to_string()))?;
    PgRefStoreCore.read_metadata_snapshot_page(&mut client, &request, deadline()).await
}

async fn a5_create(pool: &Pool, request: &CreatePackSnapshotRequest) -> Result<PackSnapshotOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(|error| RefStoreError::Database(error.to_string()))?;
    PgPackSnapshot.create(&mut client, request, deadline()).await
}

async fn a5_read(
    pool: &Pool,
    repository: Uuid,
    tenant: Uuid,
    snapshot_id: Uuid,
    pin_id: Uuid,
    generation: i64,
) -> Result<PackReadSnapshot, RefStoreError> {
    let reference = PackSnapshotRef::new(repository, tenant, snapshot_id, pin_id, generation)?;
    let mut client = pool.get().await.map_err(|error| RefStoreError::Database(error.to_string()))?;
    PgPackSnapshot.read(&mut client, &reference, deadline()).await
}

async fn a5_query(
    pool: &Pool,
    scope: MetadataSnapshotScope,
    request_id: Uuid,
) -> Result<PackSnapshotLookup, RefStoreError> {
    let query = PackSnapshotReceiptQuery::new(scope, request_id)?;
    let mut client = pool.get().await.map_err(|error| RefStoreError::Database(error.to_string()))?;
    PgPackSnapshot.query_receipt(&mut client, &query, deadline()).await
}

async fn a2_renew(pool: &Pool, request: &RenewMetadataPinRequest) -> Result<MetadataPinOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(|error| RefStoreError::Database(error.to_string()))?;
    PgRefStoreCore.renew_metadata_pin(&mut client, request, deadline()).await
}

async fn a2_release(pool: &Pool, request: &ReleaseMetadataPinRequest) -> Result<MetadataPinOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(|error| RefStoreError::Database(error.to_string()))?;
    PgRefStoreCore.release_metadata_pin(&mut client, request, deadline()).await
}

/// Harden fixture Git: owned HOME/template, empty environment, known author,
/// closed argv and a bounded timeout. All fixture bytes are synthetic.
struct GitRepo {
    _root: tempfile::TempDir,
    bare: PathBuf,
    home: PathBuf,
    template: PathBuf,
    git: PathBuf,
    format: GitObjectFormat,
}

impl GitRepo {
    async fn new(git: PathBuf, object_format: GitObjectFormat) -> Result<Self> {
        let root = tempfile::tempdir()?;
        let home = root.path().join("home");
        let template = root.path().join("template");
        std::fs::create_dir_all(&home)?;
        std::fs::create_dir_all(&template)?;
        let repo =
            Self { bare: root.path().join("fixture.git"), home, template, git, format: object_format, _root: root };
        let object_format = format!("--object-format={}", object_format.as_str());
        let template_arg = format!("--template={}", repo.template.display());
        repo.run(&["init", "--bare", "--quiet", object_format.as_str(), template_arg.as_str()], None).await?;
        Ok(repo)
    }

    async fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
        let with_repo = self.bare.is_dir();
        let mut command = tokio::process::Command::new(&self.git);
        command
            .current_dir(self._root.path())
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TEMPLATE_DIR", &self.template)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C")
            .env("GIT_AUTHOR_NAME", "Rootyard Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@rootyard.invalid")
            .env("GIT_COMMITTER_NAME", "Rootyard Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@rootyard.invalid")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("gc.auto=0")
            .arg("--no-replace-objects")
            .args(args)
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if with_repo {
            command.env("GIT_DIR", &self.bare);
        }
        let mut child = command.spawn()?;
        if let Some(bytes) = stdin {
            let mut pipe = child.stdin.take().ok_or_else(|| anyhow!("fixture git stdin is not piped"))?;
            pipe.write_all(bytes).await?;
            drop(pipe);
        }
        let output = tokio::time::timeout(Duration::from_secs(DEADLINE_SECONDS), child.wait_with_output())
            .await
            .map_err(|_| anyhow!("fixture native git command timed out"))??;
        ensure!(
            output.status.success(),
            "fixture native git `{}` failed with {:?}: {}",
            args.first().copied().unwrap_or("<none>"),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(output.stdout)
    }

    fn text(bytes: &[u8]) -> Result<String> {
        Ok(std::str::from_utf8(bytes)?.trim().to_owned())
    }

    async fn add_blob(&self, bytes: &[u8]) -> Result<String> {
        Self::text(&self.run(&["hash-object", "-w", "--stdin"], Some(bytes)).await?)
    }

    async fn mktree(&self, file: &str, blob: &str) -> Result<String> {
        Self::text(&self.run(&["mktree"], Some(format!("100644 blob {blob}\t{file}\n").as_bytes())).await?)
    }

    async fn commit_tree(&self, tree: &str, message: &str) -> Result<String> {
        Self::text(&self.run(&["commit-tree", tree, "-m", message], None).await?)
    }

    async fn update_ref(&self, name: &str, oid: &str) -> Result<()> {
        self.run(&["update-ref", name, oid], None).await?;
        Ok(())
    }

    fn artifacts_dir(&self) -> Result<PathBuf> {
        let parent = self.bare.parent().ok_or_else(|| anyhow!("fixture repository has no parent"))?;
        let dir = parent.join("artifacts");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Let mature Git write the actual `.pack` stream and the matching `.idx`.
    async fn pack_all(&self, name: &str) -> Result<PairFiles> {
        let bytes = self.run(&["pack-objects", "--stdout", "--all"], None).await?;
        ensure!(bytes.starts_with(b"PACK"), "git pack-objects did not produce a pack stream");
        let pack = self.artifacts_dir()?.join(format!("{name}.pack"));
        std::fs::write(&pack, &bytes)?;
        let pack_arg = pack.to_str().ok_or_else(|| anyhow!("fixture pack path is not UTF-8"))?.to_owned();
        self.run(&["index-pack", pack_arg.as_str()], None).await?;
        PairFiles::new(pack, self.artifacts_dir()?.join(format!("{name}.idx")))
    }
}

struct PairFiles {
    pack: PathBuf,
    idx: PathBuf,
}

impl PairFiles {
    fn new(pack: PathBuf, idx: PathBuf) -> Result<Self> {
        ensure!(pack.is_file(), "fixture pack file is missing");
        ensure!(idx.is_file(), "fixture idx file is missing");
        Ok(Self { pack, idx })
    }
}

struct Draft {
    plan: PackCommitPlan,
    token: PackPendingToken,
}

/// Read-only verified remote GET of every registered artifact.
async fn readback(store: &BlobStore, packs: &[RegisteredPack], work: &Path) -> Result<()> {
    for pack in packs {
        for artifact in pack.artifacts() {
            let locator = artifact.locator().blob_locator()?;
            let destination = work.join(format!("readback-{}-{}", artifact.slot(), Uuid::new_v4()));
            store.get_to_file(&locator, &destination, std_deadline()).await?;
            let (sha256, length) = digest_file(&destination)?;
            ensure!(
                sha256 == artifact.verified_sha256().as_str() && length == artifact.verified_length(),
                "independent remote read-back differs from the registered artifact"
            );
            std::fs::remove_file(&destination)?;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "root-selected only: needs the parent Python fixture database plus ROOTYARD_PACK_SNAPSHOTS_FIXTURE_* and real Blob/Git env"]
async fn ref_store_pack_snapshot_backup_metadata_fixture() -> Result<()> {
    let fixture = Fixture::from_env();
    let mode = Mode::from_env();
    let store = open_store()?;
    let pool = db::pool(&fixture.url).context("connect to the parent fixture database")?;
    match mode {
        Mode::Seed => seed(&pool, &store, &fixture).await,
        Mode::Verify => verify(&pool, &store, &fixture).await,
    }
}

/// One A5 scenario seeded through the typed API.
struct Scenario {
    label: &'static str,
    request: CreatePackSnapshotRequest,
    outcome: PackSnapshotOutcome,
    generation: i64,
    state: &'static str,
    renew: Option<(Uuid, RenewMetadataPinRequest, MetadataPinOutcome)>,
    release: Option<(Uuid, ReleaseMetadataPinRequest, MetadataPinOutcome)>,
}

fn assert_read_matches(read: &PackReadSnapshot, receipt: &PackSnapshotReceipt) -> Result<()> {
    ensure!(read.snapshot_id() == receipt.snapshot_id() && read.pin_id() == receipt.pin_id(), "read ids differ");
    ensure!(
        read.repository_id() == receipt.repository_id() && read.tenant_id() == receipt.tenant_id(),
        "read scope differs"
    );
    ensure!(read.owner_id() == receipt.owner_id(), "read producer owner differs");
    ensure!(read.gate_revision() == receipt.gate_revision(), "read gate revision differs");
    ensure!(read.gate_digest_hex() == receipt.gate_digest_hex(), "read gate digest differs");
    ensure!(read.pack_mode() == "pack_verified", "read pack mode differs");
    ensure!(read.head_ref() == receipt.head_ref(), "read HEAD ref differs");
    ensure!(read.head_oid_hex() == receipt.head_oid_hex(), "read HEAD oid differs");
    ensure!(
        read.ref_count() == receipt.ref_count() && read.refs().len() as i64 == receipt.ref_count(),
        "read refs differ"
    );
    ensure!(
        read.pack_count() == receipt.pack_count() && read.packs().len() as i64 == receipt.pack_count(),
        "read packs differ"
    );
    ensure!(read.membership_digest_hex() == receipt.membership_digest_hex(), "read membership digest differs");
    ensure!(read.snapshot_digest_hex() == receipt.snapshot_digest_hex(), "read snapshot digest differs");
    ensure!(is_hex64(&read.read_digest_hex()), "read digest is not sha256 hex");
    ensure!(read.logical_bytes() == receipt.logical_bytes(), "read logical bytes differ");
    ensure!(read.complete_registered_pack_membership(), "read did not claim complete registered membership");
    ensure!(!read.complete_git_read_snapshot(), "read claimed a complete Git read snapshot");
    ensure!(read.packs_complete(), "read packs are not complete");
    for pack in read.packs() {
        ensure!(pack.joined_revision() == Some(read.gate_revision()), "read pack joined revision differs");
        ensure!(pack.artifacts().len() == 2, "read pack is not a pack/idx pair");
        ensure!(is_hex64(&pack.artifact_set_digest().as_hex()), "read artifact-set digest is not sha256 hex");
        for artifact in pack.artifacts() {
            ensure!(is_hex64(artifact.verified_sha256().as_str()), "read artifact sha256 is not hex");
            ensure!(artifact.verified_length() > 0, "read artifact length is zero");
        }
    }
    Ok(())
}

async fn assert_query_matches(pool: &Pool, scope: MetadataSnapshotScope, scenario: &Scenario) -> Result<()> {
    match a5_query(pool, scope, scenario.request.request_id()).await? {
        PackSnapshotLookup::Found(receipt) => {
            ensure!(receipt == scenario.outcome.receipt, "historical create receipt differs from the typed create");
            ensure!(receipt.request_id() == scenario.request.request_id(), "historical create request id differs");
            ensure!(!receipt.complete_git_read_snapshot(), "historical create receipt claimed a Git read snapshot");
        }
        other => bail!("historical create receipt did not resolve as Found: {other:?}"),
    }
    for (request_id, receipt) in [
        scenario.renew.as_ref().map(|(id, _, outcome)| (*id, &outcome.receipt)),
        scenario.release.as_ref().map(|(id, _, outcome)| (*id, &outcome.receipt)),
    ]
    .into_iter()
    .flatten()
    {
        match a5_query(pool, scope, request_id).await? {
            PackSnapshotLookup::FoundPin(found) => {
                // PackPinReceipt and MetadataPinReceipt are different sealed
                // wrappers; compare the canonical public data field by field.
                let expected_kind = match receipt.action() {
                    MetadataMutationAction::Renew => "renewed",
                    MetadataMutationAction::Release => "released",
                    MetadataMutationAction::Create => bail!("a lifecycle receipt is a create receipt"),
                };
                ensure!(
                    found.request_id() == receipt.request_id()
                        && found.snapshot_id() == receipt.snapshot_id()
                        && found.pin_id() == receipt.pin_id()
                        && found.pin_generation() == receipt.pin_generation()
                        && found.expires_at_unix_micros() == receipt.expires_at_unix_micros()
                        && found.released_at_unix_micros() == receipt.released_at_unix_micros(),
                    "historical pin receipt differs from the typed mutation"
                );
                ensure!(found.history_kind() == expected_kind, "historical pin receipt kind differs");
                ensure!(!found.grants_live_lease(), "historical pin receipt granted a live lease");
                ensure!(found.snapshot_id() == scenario.outcome.receipt.snapshot_id(), "pin receipt snapshot differs");
            }
            other => bail!("historical pin receipt did not resolve as FoundPin: {other:?}"),
        }
    }
    Ok(())
}

/// Bounded DB-clock poll: the typed `expires_at` really elapsed, not a mocked clock.
async fn wait_db_clock_expiry(pool: &Pool, pin_id: Uuid) -> Result<()> {
    let started = StdInstant::now();
    loop {
        let expired: bool = pool
            .get()
            .await?
            .query_one("SELECT clock_timestamp() >= expires_at FROM ref_store_core_pins WHERE pin_id=$1", &[&pin_id])
            .await?
            .get(0);
        if expired {
            return Ok(());
        }
        if started.elapsed() > Duration::from_secs(EXPIRY_POLL_SECONDS) {
            bail!("the short pack-snapshot lease did not expire on the database clock within the bound");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn write_marker(output: &Path, marker: &Value) -> Result<()> {
    std::fs::write(output, serde_json::to_vec_pretty(marker)?)
        .with_context(|| format!("write the private fixture manifest to {}", output.display()))?;
    println!("{MARKER} {}", serde_json::to_string(marker)?);
    Ok(())
}

async fn seed(pool: &Pool, store: &BlobStore, fixture: &Fixture) -> Result<()> {
    let format = fixture.format;
    let tenant = Uuid::new_v4();
    let repository = Uuid::new_v4();
    let producer = Uuid::new_v4();
    create_business(pool, repository, tenant, format).await?;
    create_producer(pool, producer).await?;
    let gate = initialize_gate(pool, repository, tenant, format).await?;

    // (1) One genuine A2 metadata-only snapshot BEFORE pack activation.
    let old_scope = MetadataSnapshotScope::new(
        repository,
        tenant,
        tenant,
        MetadataPinPurpose::Verification,
        format,
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let old_request = CreateMetadataSnapshotRequest::new(
        old_scope,
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        3600,
        *gate.digest(),
    )?;
    let old: CreateMetadataSnapshotOutcome = {
        let mut client = pool.get().await?;
        PgRefStoreCore.create_metadata_snapshot(&mut client, &old_request, deadline()).await?
    };
    ensure!(!old.replayed, "fresh A2 metadata snapshot replayed");
    let old_receipt: &MetadataSnapshotReceipt = &old.receipt;
    let old_page = a2_page(pool, old_scope, old_receipt.snapshot_id(), old_receipt.pin_id(), 1).await?;
    // Measured A2 fixed charge (pin + receipt overhead) from the actual typed create.
    let a2_after_old = a2_usage(pool, repository).await?;
    ensure!(
        old_page.complete() && old_page.packs() == rootyard::ref_store::core::PackMembershipDescriptor::unavailable(),
        "the pre-activation A2 page is not a complete metadata-only page"
    );
    ensure!(
        old_receipt.ref_count() == 0 && old_page.ref_count() == 0 && old_page.refs().is_empty(),
        "the pre-activation A2 snapshot captured refs receipt={} page={} rows={} (expected none before the A4 commit)",
        old_receipt.ref_count(),
        old_page.ref_count(),
        old_page.refs().len()
    );

    // (2) Real typed A4 verified commit (A4a pipeline).
    let git = GitRepo::new(fixture.git.clone(), format).await?;
    ensure!(git.format == format, "fixture git object format differs from the gate");
    let content = b"rootyard ref-store pack snapshot backup fixture\n";
    let content_sha256 = hex::encode(Sha256::digest(content));
    let blob_oid = git.add_blob(content).await?;
    let tree_oid = git.mktree("pack-snapshot.txt", &blob_oid).await?;
    let commit_oid = git.commit_tree(&tree_oid, "fixture pack snapshot backup").await?;
    git.update_ref("refs/heads/main", &commit_oid).await?;
    let files = git.pack_all("snapshot-closure").await?;
    let (pack_sha, pack_len) = digest_file(&files.pack)?;
    let (idx_sha, idx_len) = digest_file(&files.idx)?;

    let baseline = {
        let mut client = pool.get().await?;
        PgPackCommit.capture_baseline(&mut client, repository, tenant, deadline()).await?
    };
    ensure!(baseline.mode() == PackMode::MetadataOnly, "fresh gate is not metadata_only");
    ensure!(baseline.gate().revision() == 1, "fresh gate revision is not 1");
    ensure!(baseline.refs().is_empty() && baseline.old_packs().is_empty(), "fresh gate is not empty");

    let pack_id = Uuid::new_v4();
    let registration_id = Uuid::new_v4();
    let planned = PlannedPack::new(
        pack_id,
        registration_id,
        PlannedArtifact::new(PackArtifactRole::Pack, ContentDigest::parse(pack_sha.clone())?, pack_len)?,
        PlannedArtifact::new(PackArtifactRole::Idx, ContentDigest::parse(idx_sha.clone())?, idx_len)?,
    )?;
    let scope = PackCommitScope::new(
        repository,
        tenant,
        tenant,
        format,
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let operation_id = Uuid::new_v4();
    let operation_digest = RequestDigest::from_bytes([0x5a; 32]);
    let identity =
        OperationIdentity::new(repository, tenant, IssuerLane::new(LANE)?, 1, operation_id, operation_digest)?;
    let expectation = PackCommitExpectation::new(gate.revision(), *gate.digest(), baseline.mode())?;
    let plan = PackCommitPlan::new(
        scope.clone(),
        identity,
        expectation,
        HeadUpdate::Keep,
        vec![main_update(format, &commit_oid)?],
        baseline.membership_digest(),
        Vec::new(),
        vec![planned],
    )?;
    let token = {
        let mut client = pool.get().await?;
        PgPackCommit.begin_pending(&mut client, &plan, deadline()).await?
    };
    let draft = Draft { plan, token };
    let plan = &draft.plan;

    // A3: real acquire, protected consume+upload of the exact pack/idx bytes.
    let request = AcquireArtifactHoldsRequest::new(
        hold_scope(plan)?,
        plan.identity().clone(),
        Uuid::new_v4(),
        store.backend_identity().clone(),
        Uuid::new_v4(),
        1,
        *plan.expected().gate_digest(),
        vec![
            ArtifactSpec::new(HOLD_NAMESPACE, pack_sha.clone(), pack_len)?,
            ArtifactSpec::new(HOLD_NAMESPACE, idx_sha.clone(), idx_len)?,
        ],
    )?;
    let acquire_request_id = request.request_id();
    let grant = {
        let mut client = pool.get().await?;
        match PgArtifactHoldStore.acquire(&mut client, store, &request, deadline()).await? {
            AcquireOutcome::Granted { grant, .. } => grant,
            AcquireOutcome::Replayed { .. } => bail!("fresh A3 acquire unexpectedly replayed"),
        }
    };
    let uploader = ProtectedUploader::new(store.clone());
    let sources = [UploadSource::new(files.pack.clone()), UploadSource::new(files.idx.clone())];
    let publication: ProtectedPublication = uploader
        .consume_and_upload(pool, grant, &sources, std_deadline())
        .await
        .map_err(|_| anyhow!("protected upload refused by the protected uploader"))?;
    ensure!(publication.receipts().len() == 2, "publication is not exactly a two-artifact pair");
    ensure!(publication.acquire_request_id() == acquire_request_id, "publication acquire id differs");

    // A4: durable registration bound to the exact A3 pair.
    let registration: PackRegistrationReceipt = {
        let mut client = pool.get().await?;
        let request = PackRegistrationRequest::new(plan, pack_id, &publication)?;
        PgPackCommit.register_publication(&mut client, request, deadline()).await?
    };
    ensure!(!registration.replayed, "fresh registration replayed an old ACK");
    ensure!(
        registration.ack.registration_id == registration_id && registration.ack.pack_id == pack_id,
        "registration ACK names another identity"
    );
    ensure!(registration.ack.consume_request_id == publication.consume_request_id(), "ACK consume id differs");

    // Closure context, verified S3 read-back, real native PackVerifier proof.
    let context: PackClosureContext = {
        let mut client = pool.get().await?;
        PgPackCommit.capture_context(&mut client, plan, deadline()).await?
    };
    ensure!(context.new_packs().len() == 1 && context.old_packs().is_empty(), "closure pack set differs");
    let readback_dir = tempfile::tempdir()?;
    readback(store, context.new_packs(), readback_dir.path()).await?;
    let proof: PackClosureProof =
        PackVerifier::new(store.clone(), fixture.git.clone())?.verify(plan, &context, std_deadline()).await?;
    let receipt: PackCommitReceipt = {
        let mut client = pool.get().await?;
        PgPackCommit.commit_verified_pending(&mut client, plan, &draft.token, &proof, deadline()).await?
    };
    ensure!(receipt.is_committed() && !receipt.replayed, "fresh verified commit did not commit");

    let (revision, pack_mode) = gate_state(pool, repository).await?;
    ensure!(revision == 2 && pack_mode == "pack_verified", "gate did not move to pack_verified revision 2");
    let after = {
        let mut client = pool.get().await?;
        PgPackCommit.capture_baseline(&mut client, repository, tenant, deadline()).await?
    };
    ensure!(after.mode() == PackMode::PackVerified && after.gate().revision() == 2, "committed baseline differs");
    ensure!(
        after.refs().len() == 1
            && after.refs()[0].name() == "refs/heads/main"
            && after.refs()[0].oid_hex() == commit_oid.as_str(),
        "committed refs/heads/main is not the fixture commit"
    );
    ensure!(after.old_packs().len() == 1, "committed membership is not exactly one pack");
    let active = &after.old_packs()[0];
    ensure!(
        active.pack_id() == pack_id
            && active.registration_id() == registration_id
            && active.joined_revision() == Some(2)
            && active.artifact_set_digest().as_hex() == registration.ack.artifact_set_digest,
        "committed membership identity differs"
    );
    let committed_membership = after.membership_digest().as_hex();
    let record = {
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        let lookup = PgRefStore.get(&tx, repository, operation_id, deadline()).await?;
        let _ = tx.rollback().await;
        match lookup {
            OperationLookup::Known(record) => record,
            OperationLookup::Unknown => bail!("the committed pack operation is missing from the 138 registry"),
        }
    };
    ensure!(record.state() == OperationState::Committed, "operation terminal is not committed");
    ensure!(record.identity() == plan.identity(), "operation identity differs from the plan");
    let terminal_value = value_of(&receipt.terminal)?;
    match record.terminal_result() {
        Some(stored) => {
            ensure!(stored.value() == &terminal_value, "stored terminal differs from the committed receipt")
        }
        None => bail!("committed operation has no terminal result"),
    }

    // (3) A5 snapshots under producer B, different from A4 publisher A (= tenant).
    ensure!(producer != tenant && producer != plan.owner_id(), "A5 producer B must differ from publisher A");
    let snap_scope = MetadataSnapshotScope::new(
        repository,
        tenant,
        producer,
        MetadataPinPurpose::Verification,
        format,
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let expected = PackSnapshotExpectation::new(after.gate().revision(), *after.gate().digest())?;

    let mut scenarios: Vec<Scenario> = Vec::new();
    for label in ["active", "renewed", "released"] {
        let request =
            CreatePackSnapshotRequest::new(snap_scope, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 3600, expected)?;
        let outcome = a5_create(pool, &request).await?;
        ensure!(!outcome.replayed, "fresh A5 pack snapshot replayed");
        let receipt = &outcome.receipt;
        ensure!(
            receipt.request_id() == request.request_id()
                && receipt.snapshot_id() == request.snapshot_id()
                && receipt.pin_id() == request.pin_id(),
            "A5 receipt ids differ from the request"
        );
        ensure!(
            receipt.repository_id() == repository && receipt.tenant_id() == tenant && receipt.owner_id() == producer,
            "A5 receipt scope differs"
        );
        ensure!(receipt.gate_revision() == 2 && receipt.pack_mode() == "pack_verified", "A5 gate/mode differs");
        ensure!(receipt.pack_count() == 1 && receipt.ref_count() == 1, "A5 pack/ref count differs");
        ensure!(
            is_hex64(receipt.membership_digest_hex())
                && is_hex64(receipt.snapshot_digest_hex())
                && is_hex64(receipt.refs_digest_hex()),
            "A5 receipt digest is not sha256 hex"
        );
        ensure!(
            !receipt.complete_registered_pack_membership() && !receipt.complete_git_read_snapshot(),
            "an A5 create receipt claimed data authority"
        );
        scenarios.push(Scenario {
            label,
            request,
            outcome,
            generation: 1,
            state: "active",
            renew: None,
            release: None,
        });
    }

    // Renewed scenario: generation 1 -> 2, still live.  The exact lifecycle
    // charge is measured from the actual permanent counter delta of this typed
    // renew, so no implementation constant is guessed in the harness.
    let usage_before_renew = pack_usage(pool, repository).await?.ok_or_else(|| anyhow!("pack usage missing"))?;
    let lifecycle_bytes;
    {
        let scenario = &mut scenarios[1];
        let request_id = Uuid::new_v4();
        let renew = RenewMetadataPinRequest::new(snap_scope, request_id, scenario.outcome.receipt.pin_id(), 1, 3600)?;
        let renewed = a2_renew(pool, &renew).await?;
        ensure!(!renewed.replayed && renewed.receipt.pin_generation() == 2, "pack-aware renew did not advance");
        let read = a5_read(
            pool,
            repository,
            tenant,
            scenario.outcome.receipt.snapshot_id(),
            scenario.outcome.receipt.pin_id(),
            2,
        )
        .await?;
        ensure!(read.pin_generation() == 2, "renewed snapshot read generation differs");
        assert_read_matches(&read, &scenario.outcome.receipt)?;
        scenario.generation = 2;
        scenario.state = "renewed";
        scenario.renew = Some((request_id, renew, renewed));
    }
    {
        let usage_after_renew = pack_usage(pool, repository).await?.ok_or_else(|| anyhow!("pack usage missing"))?;
        ensure!(
            usage_after_renew[4] == usage_before_renew[4] + 1
                && usage_after_renew[5] == usage_before_renew[5] + 1
                && usage_after_renew[0] == usage_before_renew[0]
                && usage_after_renew[1] == usage_before_renew[1]
                && usage_after_renew[2] == usage_before_renew[2]
                && usage_after_renew[3] == usage_before_renew[3],
            "pack-aware renew did not charge exactly one permanent history row and receipt"
        );
        lifecycle_bytes = usage_after_renew[6] - usage_before_renew[6];
        ensure!(lifecycle_bytes > 0, "the measured lifecycle charge is not positive");
    }
    // Released scenario: terminal release at generation 1.
    {
        let scenario = &mut scenarios[2];
        let request_id = Uuid::new_v4();
        let release = ReleaseMetadataPinRequest::new(
            snap_scope,
            request_id,
            scenario.outcome.receipt.pin_id(),
            1,
            PinReleaseReason::ClientDone,
        )?;
        let released = a2_release(pool, &release).await?;
        ensure!(
            !released.replayed && released.receipt.released_at_unix_micros().is_some(),
            "pack-aware release did not record"
        );
        match a5_read(
            pool,
            repository,
            tenant,
            scenario.outcome.receipt.snapshot_id(),
            scenario.outcome.receipt.pin_id(),
            1,
        )
        .await
        {
            Err(RefStoreError::MetadataPinReleased { pin_id, .. }) if pin_id == scenario.outcome.receipt.pin_id() => {}
            other => bail!("released pack pin still served a read: {other:?}"),
        }
        scenario.state = "released";
        scenario.release = Some((request_id, release, released));
    }

    // Expired scenario LAST: short lease, then a bounded DB-clock poll.
    {
        let request =
            CreatePackSnapshotRequest::new(snap_scope, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), 1, expected)?;
        let outcome = a5_create(pool, &request).await?;
        ensure!(!outcome.replayed, "fresh short-lease A5 snapshot replayed");
        wait_db_clock_expiry(pool, outcome.receipt.pin_id()).await?;
        match a5_read(pool, repository, tenant, outcome.receipt.snapshot_id(), outcome.receipt.pin_id(), 1).await {
            Err(RefStoreError::MetadataPinExpired { pin_id, .. }) if pin_id == outcome.receipt.pin_id() => {}
            other => bail!("DB-clock-expired pack pin still served a read: {other:?}"),
        }
        scenarios.push(Scenario {
            label: "expired",
            request,
            outcome,
            generation: 1,
            state: "expired",
            renew: None,
            release: None,
        });
    }

    // Every typed historical lookup resolves `Found`/`FoundPin` before backup.
    for scenario in &scenarios {
        assert_query_matches(pool, snap_scope, scenario).await?;
    }

    // One typed read of the still-live snapshots (full registered metadata).
    for scenario in &scenarios {
        if scenario.state == "active" || scenario.state == "renewed" {
            let read = a5_read(
                pool,
                repository,
                tenant,
                scenario.outcome.receipt.snapshot_id(),
                scenario.outcome.receipt.pin_id(),
                scenario.generation,
            )
            .await?;
            assert_read_matches(&read, &scenario.outcome.receipt)?;
        }
    }

    let usage = pack_usage(pool, repository).await?.ok_or_else(|| anyhow!("pack snapshot repo usage row missing"))?;
    let tenant_usage =
        pack_tenant_usage(pool, tenant).await?.ok_or_else(|| anyhow!("pack snapshot tenant usage row missing"))?;
    ensure!(usage == tenant_usage, "permanent pack-snapshot counters differ between repository and tenant");
    ensure!(
        usage[0] == 4 && usage[1] == 4 && usage[2] == 4 && usage[3] == 4 && usage[4] == 6 && usage[5] == 6,
        "permanent pack-snapshot counters are not four snapshots/refs/bindings/pins and six history/receipts"
    );
    let a2 = a2_usage(pool, repository).await?;
    let row_counts = snapshot_counts(pool, repository).await?;
    ensure!(
        row_counts == (5, 4, 5, 7, 4),
        "A2/A5 row cardinalities differ from the drill shape (one old A2 receipt, four A5 ref captures plus six A5 receipts): actual {row_counts:?}"
    );

    // Exact charge accounting from TYPED receipt bytes + the implementation's
    // documented fixed row overheads (never an arbitrary estimate).
    let create_receipt_bytes: Vec<i64> =
        scenarios.iter().map(|scenario| scenario.outcome.receipt.logical_bytes()).collect();
    ensure!(create_receipt_bytes.len() == 4, "not all four create receipts carry typed logical bytes");
    let a2_fixed_bytes = a2_after_old[2] - old_receipt.logical_bytes();
    ensure!(a2_fixed_bytes > 0, "the measured A2 fixed charge is not positive");
    // PackSnapshotReceipt.logical_bytes already includes the captured binding
    // rows (PgPackSnapshot::create adds them to snapshot_bytes). Adding that
    // charge again here would double-count every binding.
    let create_fixed_bytes = a2_fixed_bytes + lifecycle_bytes;
    let expected_logical = create_receipt_bytes.iter().sum::<i64>() + 4 * create_fixed_bytes + 2 * lifecycle_bytes;
    ensure!(usage[6] == expected_logical, "permanent logical bytes do not equal the exact typed charge");

    let pack_rows = capture(pool, &PACK_TABLES, repository, tenant).await?;
    let hold_rows = capture(pool, &HOLD_TABLES, repository, tenant).await?;
    let core_rows = capture(pool, &CORE_TABLES, repository, tenant).await?;
    let a2_rows = capture(pool, &A2_TABLES, repository, tenant).await?;
    let snapshot_rows = capture(pool, &SNAPSHOT_TABLES, repository, tenant).await?;
    ensure!(table(&pack_rows, "ref_store_core_pack_publications")?.len() == 1, "publication row count differs");
    ensure!(table(&pack_rows, "ref_store_core_pack_artifacts")?.len() == 2, "artifact row count differs");
    ensure!(table(&pack_rows, "ref_store_core_pack_memberships")?.len() == 1, "membership row count differs");
    ensure!(table(&pack_rows, "ref_store_core_pack_history")?.len() == 2, "A4 history row count differs");
    ensure!(table(&hold_rows, "artifact_hold_requests")?.len() == 1, "A3 request row count differs");
    ensure!(table(&hold_rows, "artifact_holds")?.len() == 2, "A3 hold row count differs");
    ensure!(table(&hold_rows, "artifact_hold_consume_receipts")?.len() == 2, "A3 consume receipt count differs");
    ensure!(table(&hold_rows, "artifact_hold_shards")?.len() == 64, "the fixed 64 A3 shard rows changed");
    ensure!(table(&core_rows, "ref_store_core_gates")?.len() == 1, "core gate row count differs");
    ensure!(table(&core_rows, "ref_store_core_refs")?.len() == 1, "core ref row count differs");
    ensure!(table(&core_rows, "ref_store_core_events")?.len() == 1, "core event row count differs");
    ensure!(table(&core_rows, "ref_store_core_cancellations")?.is_empty(), "a cancellation tombstone was written");
    ensure!(table(&snapshot_rows, "ref_store_core_snapshot_packs")?.len() == 4, "snapshot pack bindings differ");
    ensure!(table(&snapshot_rows, "ref_store_core_pack_snapshot_history")?.len() == 6, "history rows differ");
    ensure!(table(&snapshot_rows, "ref_store_core_pack_snapshot_repo_usage")?.len() == 1, "repo usage row missing");
    ensure!(table(&snapshot_rows, "ref_store_core_pack_snapshot_tenant_usage")?.len() == 1, "tenant usage row missing");
    ensure!(table(&a2_rows, "ref_store_core_snapshots")?.len() == 5, "A2 snapshot rows differ");
    ensure!(table(&a2_rows, "ref_store_core_pins")?.len() == 5, "A2 pin rows differ");
    ensure!(
        table(&a2_rows, "ref_store_core_receipts")?.len() == 7,
        "A2 receipt rows differ (the old metadata create plus six A5 receipts)"
    );

    let scope_json = json!({
        "repository_id": repository.to_string(),
        "tenant_id": tenant.to_string(),
        "owner_id": producer.to_string(),
        "publisher_owner_id": tenant.to_string(),
        "purpose": MetadataPinPurpose::Verification.as_str(),
        "object_format": format.as_str(),
        "history_incarnation": gate.history_incarnation().to_string(),
        "authority_epoch": gate.authority_epoch(),
        "group_epoch": gate.group_epoch(),
    });
    let plan_json = json!({
        "operation": {
            "issuer_id": tenant.to_string(),
            "lane": LANE,
            "sequence": 1,
            "operation_id": operation_id.to_string(),
            "operation_digest": plan.identity().digest().as_hex(),
        },
        "parent_digest": plan.parent_digest().as_hex(),
        "old_membership_digest": plan.old_membership_digest().as_hex(),
        "expected_gate_revision": plan.expected().revision(),
        "expected_gate_digest": plan.expected().gate_digest().as_hex(),
        "expected_mode": plan.expected().mode().as_str(),
        "refs": [{"name": "refs/heads/main", "old_oid": Value::Null, "new_oid": commit_oid.clone()}],
        "packs": [{
            "pack_id": pack_id.to_string(),
            "registration_id": registration_id.to_string(),
            "pack_sha256": pack_sha,
            "pack_length": pack_len,
            "idx_sha256": idx_sha,
            "idx_length": idx_len,
        }],
    });
    let seed_holds = hold_scope(plan)?;
    let acquire: AcquireAck = {
        let mut client = pool.get().await?;
        match PgArtifactHoldStore.acquire_receipt(&mut client, &seed_holds, acquire_request_id, deadline()).await? {
            AcquireLookup::Found(ack) => ack,
            AcquireLookup::Unknown => bail!("the just-committed A3 acquire receipt is missing"),
        }
    };
    let consumed: Vec<ConsumeAck> = {
        let mut client = pool.get().await?;
        match PgArtifactHoldStore
            .consume_receipt(&mut client, &seed_holds, acquire_request_id, acquire.consume_request_id, deadline())
            .await?
        {
            ConsumeLookup::Found(receipts) => receipts,
            ConsumeLookup::Unknown => bail!("the just-committed A3 consume receipts are missing"),
        }
    };

    let snapshots_json: Vec<Value> = scenarios
        .iter()
        .map(|scenario| {
            let mut value = json!({
                "label": scenario.label,
                "state": scenario.state,
                "lease_seconds": scenario.request.lease_seconds(),
                "request_id": scenario.request.request_id().to_string(),
                "request_digest": scenario.request.digest().as_hex(),
                "snapshot_id": scenario.request.snapshot_id().to_string(),
                "pin_id": scenario.request.pin_id().to_string(),
                "pin_generation": scenario.generation,
                "receipt": receipt_json(&scenario.outcome.receipt),
            });
            if let Some((request_id, request, outcome)) = &scenario.renew {
                value["renew"] = json!({
                    "request_id": request_id.to_string(),
                    "request_digest": request.digest().as_hex(),
                    "expected_generation": request.expected_generation(),
                    "receipt": pin_receipt_json(&outcome.receipt),
                });
            }
            if let Some((request_id, request, outcome)) = &scenario.release {
                value["release"] = json!({
                    "request_id": request_id.to_string(),
                    "request_digest": request.digest().as_hex(),
                    "expected_generation": request.expected_generation(),
                    "receipt": pin_receipt_json(&outcome.receipt),
                });
            }
            value
        })
        .collect();

    let marker = json!({
        "kind": MANIFEST_KIND,
        "version": 1,
        "mode": "seed",
        "scope": scope_json,
        "gate": {
            "initial": {"revision": plan.expected().revision(), "digest": plan.expected().gate_digest().as_hex()},
            "committed": {
                "revision": revision,
                "digest": after.gate().digest().as_hex(),
                "pack_mode": pack_mode,
                "head_ref": "refs/heads/main",
                "ref_oid": commit_oid,
                "membership_digest": committed_membership,
            },
        },
        "old_a2": {
            "request_id": old_request.request_id().to_string(),
            "request_digest": old_request.digest().as_hex(),
            "snapshot_id": old_receipt.snapshot_id().to_string(),
            "pin_id": old_receipt.pin_id().to_string(),
            "pin_generation": old_receipt.pin_generation(),
            "gate_revision": old_receipt.gate_revision(),
            "gate_digest": old_receipt.gate_digest_hex(),
            "pack_mode": old_receipt.pack_mode(),
            "pack_count": old_receipt.pack_count(),
            "membership_digest": old_receipt.membership_digest_hex(),
            "snapshot_digest": old_receipt.snapshot_digest_hex(),
            "logical_bytes": old_receipt.logical_bytes(),
            "expires_at_unix_micros": old_receipt.expires_at_unix_micros(),
            "page": {
                "gate_revision": old_page.gate_revision(),
                "refs": page_refs(&old_page),
                "complete": old_page.complete(),
                "pack_membership": "unavailable",
            },
        },
        "plan": plan_json,
        "source": {
            "file": "pack-snapshot.txt",
            "content_sha256": content_sha256,
            "content_length": content.len(),
            "blob_oid": blob_oid,
            "tree_oid": tree_oid,
            "commit_oid": commit_oid,
            "pack_sha256": plan.packs()[0].artifact(PackArtifactRole::Pack).content().as_str(),
            "pack_length": plan.packs()[0].artifact(PackArtifactRole::Pack).length(),
            "idx_sha256": plan.packs()[0].artifact(PackArtifactRole::Idx).content().as_str(),
            "idx_length": plan.packs()[0].artifact(PackArtifactRole::Idx).length(),
        },
        "context_digest": proof.context_digest().as_hex(),
        "verified_pairs": proof.verified_pairs(),
        "verified_bytes": proof.verified_bytes(),
        "backend_identity": store.backend_identity().as_hex(),
        "acquire_request_id": acquire_request_id.to_string(),
        "consume_request_id": acquire.consume_request_id.to_string(),
        "a3": {"ack": value_of(&acquire)?, "receipts": value_of(&consumed)?},
        "registration": {"ack": value_of(&registration.ack)?},
        "terminal": terminal_value,
        "snapshots": snapshots_json,
        "usage": usage,
        "tenant_usage": tenant_usage,
        "a2_usage": a2,
        "snapshot_counts": [row_counts.0, row_counts.1, row_counts.2, row_counts.3, row_counts.4],
        "logical_accounting": {
            "create_receipt_logical_bytes": create_receipt_bytes,
            "a2_fixed_charge_bytes": a2_fixed_bytes,
            "lifecycle_charge_bytes": lifecycle_bytes,
            "create_fixed_charge_bytes": create_fixed_bytes,
            "expected_logical_bytes": expected_logical,
        },
        "counts": {
            "snapshot_packs": counts(&snapshot_rows),
            "a2": counts(&a2_rows),
            "pack": counts(&pack_rows),
            "holds": counts(&hold_rows),
            "core": counts(&core_rows),
        },
        "rows": {
            "snapshot_packs": snapshot_rows,
            "a2": a2_rows,
            "pack": pack_rows,
            "holds": hold_rows,
            "core": core_rows,
        },
        "provider_io_attempted": true,
        "protected_upload_attempted": true,
        "s3_original_bytes_read_back_after_upload": true,
        "restored_blob_bytes_backed_up": false,
        "restored_blob_bytes_qualified": false,
        "physical_blob_backup_closure": false,
        "held_remote_objects_deleted": false,
        "complete_git_read_snapshot_claimed": false,
    });
    write_marker(&fixture.output, &marker)?;
    Ok(())
}

fn scope_from(manifest: &Value) -> Result<MetadataSnapshotScope> {
    let scope = field(manifest, "scope")?;
    let purpose = match text_field(scope, "purpose")?.as_str() {
        "verification" => MetadataPinPurpose::Verification,
        "maintenance" => MetadataPinPurpose::Maintenance,
        "backup" => MetadataPinPurpose::Backup,
        "export" => MetadataPinPurpose::Export,
        "operator_audit" => MetadataPinPurpose::OperatorAudit,
        other => bail!("fixture metadata purpose {other:?} is unknown"),
    };
    Ok(MetadataSnapshotScope::new(
        uuid_field(scope, "repository_id")?,
        uuid_field(scope, "tenant_id")?,
        uuid_field(scope, "owner_id")?,
        purpose,
        GitObjectFormat::parse(&text_field(scope, "object_format")?)?,
        uuid_field(scope, "history_incarnation")?,
        int_field(scope, "authority_epoch")?,
        int_field(scope, "group_epoch")?,
    )?)
}

fn kind_of(kind: &str) -> Result<&'static str> {
    match kind {
        "renew" => Ok("renewed"),
        "release" => Ok("released"),
        other => bail!("fixture mutation kind {other:?} is unknown"),
    }
}

async fn verify(pool: &Pool, store: &BlobStore, fixture: &Fixture) -> Result<()> {
    let manifest: Value = serde_json::from_slice(&std::fs::read(&fixture.output)?)?;
    ensure!(field(&manifest, "kind")?.as_str() == Some(MANIFEST_KIND), "private manifest kind differs");
    ensure!(field(&manifest, "mode")?.as_str() == Some("seed"), "private manifest is not a seed manifest");
    let scope = scope_from(&manifest)?;
    let repository = scope.repository_id();
    let tenant = scope.tenant_id();

    let before = json!({
        "snapshot_packs": capture(pool, &SNAPSHOT_TABLES, repository, tenant).await?,
        "a2": capture(pool, &A2_TABLES, repository, tenant).await?,
        "pack": capture(pool, &PACK_TABLES, repository, tenant).await?,
        "holds": capture(pool, &HOLD_TABLES, repository, tenant).await?,
        "core": capture(pool, &CORE_TABLES, repository, tenant).await?,
    });
    let usage_before = pack_usage(pool, repository).await?;
    let tenant_usage_before = pack_tenant_usage(pool, tenant).await?;
    let a2_usage_before = a2_usage(pool, repository).await?;
    let counts_before = snapshot_counts(pool, repository).await?;

    ensure!(before["snapshot_packs"] == manifest["rows"]["snapshot_packs"], "restored A5 rows differ from seed");
    ensure!(before["a2"] == manifest["rows"]["a2"], "restored A2 rows differ from seed");
    ensure!(before["pack"] == manifest["rows"]["pack"], "restored A4 rows differ from seed");
    ensure!(before["holds"] == manifest["rows"]["holds"], "restored A3 rows differ from seed");
    ensure!(before["core"] == manifest["rows"]["core"], "restored A1/core rows differ from seed");
    ensure!(usage_before == Some(json_array_fixed::<7>(&manifest["usage"])?), "restored pack-snapshot counters differ");
    ensure!(
        tenant_usage_before == Some(json_array_fixed::<7>(&manifest["tenant_usage"])?),
        "restored pack-snapshot tenant counters differ"
    );
    ensure!(a2_usage_before == json_array_fixed::<4>(&manifest["a2_usage"])?, "restored A2 counters differ");
    let counts_expected: [i64; 5] = json_array_fixed::<5>(&manifest["snapshot_counts"])?;
    ensure!(
        [counts_before.0, counts_before.1, counts_before.2, counts_before.3, counts_before.4] == counts_expected,
        "restored A2/A5 row cardinalities differ"
    );

    // Typed historical create/pin lookups (no current authority, no live lease).
    let snapshots = array_field(&manifest, "snapshots")?;
    let mut active_reads = Vec::new();
    for scenario in snapshots {
        let snapshot_id = uuid_field(scenario, "snapshot_id")?;
        let pin_id = uuid_field(scenario, "pin_id")?;
        let request_id = uuid_field(scenario, "request_id")?;
        let generation = int_field(scenario, "pin_generation")?;
        let state = text_field(scenario, "state")?;
        let expected_create = field(scenario, "receipt")?;
        match a5_query(pool, scope, request_id).await? {
            PackSnapshotLookup::Found(receipt) => {
                ensure!(receipt.request_id() == request_id, "restored create receipt request id differs");
                ensure!(
                    receipt.snapshot_id() == snapshot_id && receipt.pin_id() == pin_id,
                    "restored create ids differ"
                );
                ensure!(receipt.owner_id() == scope.owner_id(), "restored create producer owner differs");
                ensure!(
                    receipt.gate_revision() == int_field(expected_create, "gate_revision")?,
                    "restored gate revision differs"
                );
                ensure!(
                    receipt.gate_digest_hex() == text_field(expected_create, "gate_digest")?,
                    "restored gate digest differs"
                );
                ensure!(
                    receipt.membership_digest_hex() == text_field(expected_create, "membership_digest")?,
                    "restored membership digest differs"
                );
                ensure!(
                    receipt.snapshot_digest_hex() == text_field(expected_create, "snapshot_digest")?,
                    "restored snapshot digest differs"
                );
                ensure!(
                    receipt.refs_digest_hex() == text_field(expected_create, "refs_digest")?,
                    "restored refs digest differs"
                );
                ensure!(receipt.head_ref() == text_field(expected_create, "head_ref")?, "restored HEAD ref differs");
                ensure!(
                    receipt.pack_count() == int_field(expected_create, "pack_count")?,
                    "restored pack count differs"
                );
                ensure!(
                    receipt.logical_bytes() == int_field(expected_create, "logical_bytes")?,
                    "restored logical bytes differ"
                );
                ensure!(
                    receipt.expires_at_unix_micros() == int_field(expected_create, "expires_at_unix_micros")?,
                    "restored expiry differs"
                );
                ensure!(!receipt.complete_git_read_snapshot(), "restored create receipt claimed a Git read snapshot");
            }
            other => bail!("restored historical create receipt is not Found: {other:?}"),
        }
        for kind in ["renew", "release"] {
            let Some(mutation) = scenario.get(kind) else { continue };
            let mutation_id = uuid_field(mutation, "request_id")?;
            let expected_pin = field(mutation, "receipt")?;
            match a5_query(pool, scope, mutation_id).await? {
                PackSnapshotLookup::FoundPin(receipt) => {
                    ensure!(receipt.request_id() == mutation_id, "restored pin receipt request id differs");
                    ensure!(
                        receipt.snapshot_id() == snapshot_id && receipt.pin_id() == pin_id,
                        "restored pin ids differ"
                    );
                    ensure!(receipt.history_kind() == kind_of(kind)?, "restored pin receipt kind differs");
                    ensure!(
                        receipt.pin_generation() == int_field(expected_pin, "pin_generation")?,
                        "restored pin generation differs"
                    );
                    ensure!(
                        receipt.released_at_unix_micros() == expected_pin["released_at_unix_micros"].as_i64(),
                        "restored release time differs"
                    );
                    ensure!(!receipt.grants_live_lease(), "restored pin receipt granted a live lease");
                }
                other => bail!("restored historical pin receipt is not FoundPin: {other:?}"),
            }
        }
        match state.as_str() {
            "active" | "renewed" => {
                let read = a5_read(pool, repository, tenant, snapshot_id, pin_id, generation).await?;
                ensure!(
                    read.complete_registered_pack_membership() && !read.complete_git_read_snapshot(),
                    "restored read claims differ"
                );
                ensure!(
                    read.gate_revision() == 2 && read.pack_count() == 1 && read.ref_count() == 1,
                    "restored read shape differs"
                );
                ensure!(read.owner_id() == scope.owner_id(), "restored read producer owner differs");
                ensure!(
                    read.snapshot_digest_hex() == text_field(expected_create, "snapshot_digest")?,
                    "restored read snapshot digest differs"
                );
                ensure!(
                    read.membership_digest_hex() == text_field(expected_create, "membership_digest")?,
                    "restored read membership digest differs"
                );
                ensure!(
                    read.head_ref() == "refs/heads/main" && read.head_oid_hex().is_some(),
                    "restored read HEAD differs"
                );
                active_reads.push(read);
            }
            "released" => match a5_read(pool, repository, tenant, snapshot_id, pin_id, generation).await {
                Err(RefStoreError::MetadataPinReleased { pin_id: id, .. }) if id == pin_id => {}
                other => bail!("restored released pin served a read: {other:?}"),
            },
            "expired" => match a5_read(pool, repository, tenant, snapshot_id, pin_id, generation).await {
                Err(RefStoreError::MetadataPinExpired { pin_id: id, .. }) if id == pin_id => {}
                other => bail!("restored expired pin served a read: {other:?}"),
            },
            other => bail!("fixture manifest scenario state {other:?} is unknown"),
        }
    }

    // The genuine old A2 metadata-only snapshot is still readable and unchanged.
    let old = field(&manifest, "old_a2")?;
    let old_page = a2_page(
        pool,
        scope,
        uuid_field(old, "snapshot_id")?,
        uuid_field(old, "pin_id")?,
        int_field(old, "pin_generation")?,
    )
    .await?;
    let expected_page = field(old, "page")?;
    ensure!(
        old_page.gate_revision() == int_field(expected_page, "gate_revision")?,
        "restored old A2 gate revision differs"
    );
    ensure!(page_refs(&old_page) == field(expected_page, "refs")?.clone(), "restored old A2 refs differ");
    ensure!(
        old_page.complete() == field(expected_page, "complete")?.as_bool().unwrap_or(false),
        "restored old A2 page is incomplete"
    );
    ensure!(
        old_page.packs() == rootyard::ref_store::core::PackMembershipDescriptor::unavailable(),
        "restored old A2 page is not metadata-only"
    );
    ensure!(!old_page.packs().complete_git_read_snapshot(), "restored old A2 page claimed a Git read snapshot");

    // External S3 originals: re-read and hash the complete registered metadata.
    ensure!(!active_reads.is_empty(), "no live restored snapshot was read back");
    let readback_dir = tempfile::tempdir()?;
    for read in &active_reads {
        readback(store, read.packs(), readback_dir.path()).await?;
    }

    // The whole verification is read-only: no row, counter or grant changed.
    let after = json!({
        "snapshot_packs": capture(pool, &SNAPSHOT_TABLES, repository, tenant).await?,
        "a2": capture(pool, &A2_TABLES, repository, tenant).await?,
        "pack": capture(pool, &PACK_TABLES, repository, tenant).await?,
        "holds": capture(pool, &HOLD_TABLES, repository, tenant).await?,
        "core": capture(pool, &CORE_TABLES, repository, tenant).await?,
    });
    ensure!(after == before, "the read-only restored verification mutated rows or counters");
    ensure!(pack_usage(pool, repository).await? == usage_before, "restored verification charged pack-snapshot quota");
    ensure!(
        pack_tenant_usage(pool, tenant).await? == tenant_usage_before,
        "restored verification charged tenant quota"
    );
    ensure!(a2_usage(pool, repository).await? == a2_usage_before, "restored verification charged A2 quota");
    ensure!(snapshot_counts(pool, repository).await? == counts_before, "restored verification wrote an A2/A5 row");

    let marker = json!({
        "kind": MANIFEST_KIND,
        "version": 1,
        "mode": "verify",
        "scope": manifest["scope"],
        "gate": manifest["gate"],
        "plan": manifest["plan"],
        "source": manifest["source"],
        "context_digest": manifest["context_digest"],
        "verified_pairs": manifest["verified_pairs"],
        "verified_bytes": manifest["verified_bytes"],
        "backend_identity": manifest["backend_identity"],
        "registration_ack": manifest["registration"]["ack"],
        "a3_ack": manifest["a3"]["ack"],
        "a3_receipts": manifest["a3"]["receipts"],
        "terminal": manifest["terminal"],
        "snapshots": manifest["snapshots"],
        "old_a2": manifest["old_a2"],
        "usage": usage_before,
        "tenant_usage": tenant_usage_before,
        "a2_usage": a2_usage_before,
        "snapshot_counts": [counts_before.0, counts_before.1, counts_before.2, counts_before.3, counts_before.4],
        "logical_accounting": manifest["logical_accounting"],
        "counts": manifest["counts"],
        "checks": {
            "restored_rows_equal_pre_backup_rows": true,
            "historical_create_lookup_found": true,
            "historical_renew_release_lookup_found_pin": true,
            "active_and_renewed_read_complete_registered_membership": true,
            "complete_git_read_snapshot_false": true,
            "released_and_expired_read_refused": true,
            "old_a2_metadata_snapshot_still_readable": true,
            "permanent_and_transient_counters_unchanged": true,
            "no_new_authority_charge_or_grant": true,
            "s3_original_bytes_read_back_unchanged": true,
            "source_only_tempfiles_required": false,
            "quota_charged_by_replay": false,
        },
        "provider_io_attempted": true,
        "protected_upload_attempted": false,
        "restored_blob_bytes_backed_up": false,
        "restored_blob_bytes_qualified": false,
        "physical_blob_backup_closure": false,
        "held_remote_objects_deleted": false,
        "complete_git_read_snapshot_claimed": false,
    });
    write_marker(&fixture.output, &marker)?;
    Ok(())
}
