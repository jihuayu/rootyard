//! Root-selected companion fixture for the populated schema-140 backup drill.
//!
//! This file is **only** run by the owning Python drill
//! (`tests/backup_refstore_snapshot140.py`) through an explicitly selected
//! integration-test executable. Routine CI never selects this target, so the
//! single `#[ignore]`d test below is not part of the ordinary ignored suite.
//!
//! It deliberately does **not** create a database or a schema and never runs a
//! migration: the parent harness owns one fresh disposable database, migrates
//! it, seeds the migration-139 gate/refs fixture
//! (`BackupRefStoreCore139Harness.seed_core_fixture`, plainly a direct-SQL
//! metadata fixture, *not* an adapter or protocol acknowledgement) and then
//! hands this helper that database URL plus explicit repository/tenant/owner
//! ids. Everything migration 140 adds — snapshots, snapshot refs, pins,
//! receipts, repository usage and tenant usage — is produced here by the real
//! typed `PgRefStoreCore` adapter (`create_metadata_snapshot`,
//! `renew_metadata_pin`, `release_metadata_pin`), never by hand-written SQL.
//!
//! Two modes, both selected through a mandatory environment enum:
//!
//! * `seed` writes the three pin lifecycles required by the drill (one renewed
//!   active pin with a 3600 s TTL, one exactly released pin and one pin left to
//!   expire through a 1 s lease plus a bounded real-database-clock wait), checks
//!   pages, receipt lookups and typed denials, then writes a fixture manifest to
//!   a private path and prints exactly one public marker line. The marker holds
//!   ids, digests, scopes, request ids and receipt bodies only: never the DSN,
//!   credentials or any environment value.
//! * `verify` runs against the **restored** database, rebuilds the same typed
//!   requests from that manifest through the public constructors (no
//!   `Deserialize` bypass of private request state), replays create/renew/release
//!   exactly, and proves the replay returned the original receipts without
//!   writing, refunding or reviving anything. The active pin still pages (through
//!   a real keyset cursor), the released pin denies as `MetadataPinReleased` and
//!   the expired pin denies as `MetadataPinExpired`.
//!
//! Limits: metadata rows only. No Git object, pack membership, physical GC,
//! object protection or serving claim is made; `pack_membership_state` stays
//! `unavailable` and the drill repository stays unserved.

use anyhow::{Context, Result, bail};
use deadpool_postgres::Pool;
use rootyard::db;
use rootyard::ref_store::{
    CoreGateVersion, CreateMetadataSnapshotOutcome, CreateMetadataSnapshotRequest, MetadataMutationAction,
    MetadataPinOutcome, MetadataPinPurpose, MetadataPinReceipt, MetadataReceipt, MetadataReceiptLookup,
    MetadataSnapshotCursor, MetadataSnapshotPage, MetadataSnapshotReceipt, MetadataSnapshotScope, PgRefStoreCore,
    PinReleaseReason, ReadMetadataSnapshotPageRequest, RefStoreError, ReleaseMetadataPinRequest,
    RenewMetadataPinRequest, RequestDigest, VersionCheck,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::Instant;
use uuid::Uuid;

/// The one public marker line. Everything after the marker is metadata-only
/// JSON: ids, digests, request ids and receipt bodies (never a DSN or token).
const MARKER: &str = "ROOTYARD-SNAPSHOT-FIXTURE-METADATA";
const MANIFEST_KIND: &str = "rootyard/ref-store-snapshot-backup-fixture";
const ACTIVE_LEASE_SECONDS: i64 = 3600;
const RELEASED_LEASE_SECONDS: i64 = 600;
const EXPIRED_LEASE_SECONDS: i64 = 1;
const EXPIRY_WAIT_SECONDS: u64 = 25;
const REQUEST_DEADLINE_SECONDS: u64 = 20;
const SINGLE_PAGE_LIMIT: u32 = 256;
const CURSOR_PAGE_LIMIT: u32 = 1;
const TABLES: [&str; 6] = [
    "ref_store_core_snapshots",
    "ref_store_core_snapshot_refs",
    "ref_store_core_pins",
    "ref_store_core_receipts",
    "ref_store_core_repo_usage",
    "ref_store_core_tenant_usage",
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
            output: PathBuf::from(required("ROOTYARD_SNAPSHOT_FIXTURE_OUTPUT")),
            repository: required_uuid("ROOTYARD_SNAPSHOT_FIXTURE_REPOSITORY"),
            tenant: required_uuid("ROOTYARD_SNAPSHOT_FIXTURE_TENANT"),
            owner: required_uuid("ROOTYARD_SNAPSHOT_FIXTURE_OWNER"),
        }
    }
}

enum Mode {
    Seed,
    Verify,
}

impl Mode {
    fn from_env() -> Self {
        match required("ROOTYARD_SNAPSHOT_FIXTURE_MODE").as_str() {
            "seed" => Self::Seed,
            "verify" => Self::Verify,
            other => panic!("ROOTYARD_SNAPSHOT_FIXTURE_MODE must be 'seed' or 'verify', not {other:?}"),
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
            "{name} is required: this fixture only runs under the owning snapshot backup drill, \
             never from a routine test command"
        ),
    }
}

fn required_uuid(name: &str) -> Uuid {
    Uuid::parse_str(&required(name)).unwrap_or_else(|error| panic!("{name} must be a UUID: {error}"))
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(REQUEST_DEADLINE_SECONDS)
}

/// One snapshot/pin lifecycle seeded by the real adapter.
struct Lifecycle {
    /// `"active"`, `"released"` or `"expired"`.
    kind: &'static str,
    /// Retained `ref_store_core_pins.state`: expiry is a database-clock
    /// observation of an `active` row, never a stored state.
    state: &'static str,
    expired: bool,
    lease_seconds: i64,
    generation: i64,
    creation: Creation,
    renewal: Option<Renewal>,
    release: Option<Release>,
}

struct Creation {
    request_id: Uuid,
    snapshot_id: Uuid,
    pin_id: Uuid,
    receipt: MetadataSnapshotReceipt,
}

struct Renewal {
    request_id: Uuid,
    expected_generation: i64,
    lease_seconds: i64,
    receipt: MetadataPinReceipt,
}

struct Release {
    request_id: Uuid,
    expected_generation: i64,
    reason: PinReleaseReason,
    receipt: MetadataPinReceipt,
}

#[tokio::test]
#[ignore = "root-selected only: needs the parent Python fixture database (ROOTYARD_TEST_DATABASE_URL) plus \
            ROOTYARD_SNAPSHOT_FIXTURE_* env, and deliberately panics without them"]
async fn snapshot_backup_metadata_fixture() -> Result<()> {
    let fixture = Fixture::from_env();
    let mode = Mode::from_env();
    // Connect only to the database the parent drill owns. No DDL, no migration,
    // no schema creation, no volume or service interaction.
    let pool = db::pool(&fixture.url).context("connect to the parent fixture database")?;
    let version = gate_version(&pool, &fixture).await?;
    let scope = metadata_scope(&fixture, &version)?;
    let mode_name = mode.as_str();
    match mode {
        Mode::Seed => seed(&pool, &fixture, &scope, &version, mode_name).await,
        Mode::Verify => verify(&pool, &fixture, &scope, &version, mode_name).await,
    }
}

async fn gate_version(pool: &Pool, fixture: &Fixture) -> Result<CoreGateVersion> {
    let mut client = pool.get().await.context("checkout a fixture connection")?;
    let checked = PgRefStoreCore
        .check_version(&mut client, fixture.repository, fixture.tenant, None, deadline())
        .await
        .context("read the actual migration-139 core gate version")?;
    let version = match checked {
        VersionCheck::Changed(version) | VersionCheck::Unchanged(version) => version,
        VersionCheck::Unknown => bail!(
            "repository {} has no core gate; the parent drill must run seed_core_fixture() first",
            fixture.repository
        ),
    };
    if version.repository_id() != fixture.repository || version.tenant_id() != fixture.tenant {
        bail!("the seeded core gate does not belong to the fixture repository and tenant");
    }
    Ok(version)
}

fn metadata_scope(fixture: &Fixture, version: &CoreGateVersion) -> Result<MetadataSnapshotScope> {
    Ok(MetadataSnapshotScope::new(
        fixture.repository,
        fixture.tenant,
        fixture.owner,
        MetadataPinPurpose::Backup,
        version.object_format(),
        version.history_incarnation(),
        version.authority_epoch(),
        version.group_epoch(),
    )?)
}

async fn create(
    pool: &Pool,
    request: &CreateMetadataSnapshotRequest,
) -> Result<CreateMetadataSnapshotOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(|error| RefStoreError::Database(error.to_string()))?;
    PgRefStoreCore.create_metadata_snapshot(&mut client, request, deadline()).await
}

async fn page(pool: &Pool, request: &ReadMetadataSnapshotPageRequest) -> Result<MetadataSnapshotPage, RefStoreError> {
    let mut client = pool.get().await.map_err(|error| RefStoreError::Database(error.to_string()))?;
    PgRefStoreCore.read_metadata_snapshot_page(&mut client, request, deadline()).await
}

async fn renew(pool: &Pool, request: &RenewMetadataPinRequest) -> Result<MetadataPinOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(|error| RefStoreError::Database(error.to_string()))?;
    PgRefStoreCore.renew_metadata_pin(&mut client, request, deadline()).await
}

async fn release_pin(pool: &Pool, request: &ReleaseMetadataPinRequest) -> Result<MetadataPinOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(|error| RefStoreError::Database(error.to_string()))?;
    PgRefStoreCore.release_metadata_pin(&mut client, request, deadline()).await
}

async fn lookup(
    pool: &Pool,
    scope: &MetadataSnapshotScope,
    request_id: Uuid,
) -> Result<MetadataReceiptLookup, RefStoreError> {
    let mut client = pool.get().await.map_err(|error| RefStoreError::Database(error.to_string()))?;
    PgRefStoreCore.metadata_receipt(&mut client, scope, request_id, deadline()).await
}

/// Seed the three lifecycles, validate them and publish the manifest.
async fn seed(
    pool: &Pool,
    fixture: &Fixture,
    scope: &MetadataSnapshotScope,
    version: &CoreGateVersion,
    mode: &str,
) -> Result<()> {
    let captured = core_refs(pool, fixture.repository).await?;
    if captured.is_empty() {
        bail!("the SQL fixture must seed at least one ref_store_core_refs row before the A2 drill");
    }
    let mut active = new_snapshot(pool, scope, version, "active", ACTIVE_LEASE_SECONDS).await?;
    let mut released = new_snapshot(pool, scope, version, "released", RELEASED_LEASE_SECONDS).await?;
    check_creation(pool, scope, version, &active, &captured).await?;
    check_creation(pool, scope, version, &released, &captured).await?;
    renew_active(pool, scope, &mut active).await?;
    release_exactly(pool, scope, &mut released).await?;
    // The one-second pin is created only after every live page proof, so its
    // short lease cannot lapse before the checks that need a live pin.
    let mut expired = new_snapshot(pool, scope, version, "expired", EXPIRED_LEASE_SECONDS).await?;
    check_creation(pool, scope, version, &expired, &captured).await?;
    wait_until_expired(pool, fixture.repository, expired.creation.pin_id).await?;
    expired.expired = true;
    expect_expired_denial(pool, scope, &expired).await?;
    for lifecycle in [&active, &released, &expired] {
        for (request_id, receipt) in receipts_of(lifecycle)? {
            check_lookup(pool, scope, request_id, &receipt).await?;
        }
    }
    expect_unknown_lookup(pool, scope).await?;
    let tables = table_rows(pool, fixture).await?;
    assert_populated(&tables)?;
    for lifecycle in [&active, &released, &expired] {
        assert_pin_row(&tables, lifecycle.creation.pin_id, lifecycle.state, lifecycle.generation)?;
    }
    assert_usage(&tables)?;
    let manifest = json!({
        "kind": MANIFEST_KIND,
        "version": 1,
        "mode": mode,
        "scope": scope_json(fixture, scope, version),
        "captured_refs": captured.iter()
            .map(|(name, oid)| json!({"name": name, "oid": oid}))
            .collect::<Vec<Value>>(),
        "lifecycles": ([&active, &released, &expired]
            .iter()
            .map(|lifecycle| lifecycle_json(lifecycle))
            .collect::<Result<Vec<Value>>>()?),
        "empty_six_table_catalog": false,
        "pack_membership_state": "unavailable",
        "serving_claim": false,
        "counts": counts(&tables)?,
        "tables": tables,
    });
    std::fs::write(&fixture.output, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("write the private fixture manifest to {}", fixture.output.display()))?;
    println!("{MARKER} {}", serde_json::to_string(&manifest)?);
    Ok(())
}

async fn new_snapshot(
    pool: &Pool,
    scope: &MetadataSnapshotScope,
    version: &CoreGateVersion,
    kind: &'static str,
    lease_seconds: i64,
) -> Result<Lifecycle> {
    let (request_id, snapshot_id, pin_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let request =
        CreateMetadataSnapshotRequest::new(*scope, request_id, pin_id, snapshot_id, lease_seconds, *version.digest())?;
    let outcome = create(pool, &request).await.context("create_metadata_snapshot")?;
    if outcome.replayed {
        bail!("a freshly chosen create request id must never replay an existing receipt");
    }
    Ok(Lifecycle {
        kind,
        state: "active",
        expired: false,
        lease_seconds,
        generation: 1,
        creation: Creation { request_id, snapshot_id, pin_id, receipt: outcome.receipt },
        renewal: None,
        release: None,
    })
}

async fn check_creation(
    pool: &Pool,
    scope: &MetadataSnapshotScope,
    version: &CoreGateVersion,
    lifecycle: &Lifecycle,
    captured: &[(String, String)],
) -> Result<()> {
    let creation = &lifecycle.creation;
    let receipt = &creation.receipt;
    if receipt.request_id() != creation.request_id
        || receipt.snapshot_id() != creation.snapshot_id
        || receipt.pin_id() != creation.pin_id
    {
        bail!("the creation receipt does not bind the request/snapshot/pin ids that were sent");
    }
    if receipt.repository_id() != scope.repository_id()
        || receipt.tenant_id() != scope.tenant_id()
        || receipt.owner_id() != scope.owner_id()
        || receipt.purpose() != MetadataPinPurpose::Backup
        || receipt.object_format() != scope.object_format()
    {
        bail!("the creation receipt does not bind the trusted backup metadata scope");
    }
    if receipt.history_incarnation() != scope.history_incarnation()
        || receipt.authority_epoch() != scope.authority_epoch()
        || receipt.group_epoch() != scope.group_epoch()
    {
        bail!("the creation receipt does not bind the seeded gate epochs");
    }
    if receipt.gate_revision() != version.revision() || receipt.gate_digest_hex() != version.digest().as_hex() {
        bail!("the creation receipt does not bind the actual core gate revision/digest");
    }
    if receipt.head_ref() != version.head_ref().as_str() {
        bail!("the creation receipt HEAD does not match the core gate HEAD");
    }
    if receipt.pin_generation() != 1 || receipt.ref_count() != captured.len() as i64 {
        bail!("the creation receipt generation/ref count does not match the seeded core refs");
    }
    if receipt.refs_digest_hex().len() != 64 || receipt.logical_bytes() <= 0 || receipt.expires_at_unix_micros() <= 0 {
        bail!("the creation receipt did not retain refs bytes and a database-clock lease");
    }
    if receipt.complete_git_read_snapshot() {
        bail!("a metadata snapshot must never claim a complete Git read snapshot");
    }
    // A one-second pin has no live page to prove: it is created last, checked
    // for its receipt/scope here, then left to expire on the database clock and
    // denied as a typed expired state. The active and released lifecycles above
    // provide the positive page proof.
    if lifecycle.kind != "expired" {
        let captured_page =
            read_all_refs(pool, scope, creation.snapshot_id, creation.pin_id, 1, SINGLE_PAGE_LIMIT).await?;
        if captured_page != captured {
            bail!("the immutable metadata page does not equal the seeded ref_store_core_refs rows");
        }
    }
    Ok(())
}

async fn renew_active(pool: &Pool, scope: &MetadataSnapshotScope, lifecycle: &mut Lifecycle) -> Result<()> {
    let request_id = Uuid::new_v4();
    let request = RenewMetadataPinRequest::new(*scope, request_id, lifecycle.creation.pin_id, 1, ACTIVE_LEASE_SECONDS)?;
    let outcome = renew(pool, &request).await.context("renew_metadata_pin")?;
    if outcome.replayed {
        bail!("a fresh renewal request id must not replay");
    }
    let receipt = outcome.receipt;
    if receipt.action() != MetadataMutationAction::Renew || receipt.pin_generation() != 2 {
        bail!("the renewal did not advance the live pin generation by exactly one");
    }
    if receipt.snapshot_id() != lifecycle.creation.snapshot_id || receipt.pin_id() != lifecycle.creation.pin_id {
        bail!("the renewal receipt does not bind the renewed snapshot/pin");
    }
    if receipt.released_at_unix_micros().is_some() || receipt.release_reason().is_some() {
        bail!("a renewed pin must not record release fields");
    }
    // The pre-renewal generation is stale now and must be denied, typed.
    let stale = ReadMetadataSnapshotPageRequest::new(
        *scope,
        lifecycle.creation.snapshot_id,
        lifecycle.creation.pin_id,
        1,
        None,
        None,
        SINGLE_PAGE_LIMIT,
    )?;
    match page(pool, &stale).await {
        Err(RefStoreError::MetadataPinGenerationMismatch { .. }) => {}
        other => bail!("a page at the pre-renewal generation was not denied as a generation mismatch: {other:?}"),
    }
    lifecycle.renewal =
        Some(Renewal { request_id, expected_generation: 1, lease_seconds: ACTIVE_LEASE_SECONDS, receipt });
    lifecycle.generation = 2;
    Ok(())
}

async fn release_exactly(pool: &Pool, scope: &MetadataSnapshotScope, lifecycle: &mut Lifecycle) -> Result<()> {
    let request = ReleaseMetadataPinRequest::new(
        *scope,
        Uuid::new_v4(),
        lifecycle.creation.pin_id,
        1,
        PinReleaseReason::ClientDone,
    )?;
    let outcome = release_pin(pool, &request).await.context("release_metadata_pin")?;
    if outcome.replayed {
        bail!("a fresh release request id must not replay");
    }
    let receipt = outcome.receipt;
    if receipt.action() != MetadataMutationAction::Release
        || receipt.pin_generation() != 1
        || receipt.released_at_unix_micros().is_none()
        || receipt.release_reason() != Some(PinReleaseReason::ClientDone)
    {
        bail!("the exact release did not record the terminal generation, timestamp and bounded reason");
    }
    let denied = ReadMetadataSnapshotPageRequest::new(
        *scope,
        lifecycle.creation.snapshot_id,
        lifecycle.creation.pin_id,
        1,
        None,
        None,
        SINGLE_PAGE_LIMIT,
    )?;
    match page(pool, &denied).await {
        Err(RefStoreError::MetadataPinReleased { pin_id, .. }) if pin_id == lifecycle.creation.pin_id => {}
        other => bail!("a released pin page was not denied with the typed released state: {other:?}"),
    }
    lifecycle.state = "released";
    lifecycle.release = Some(Release {
        request_id: request.request_id(),
        expected_generation: request.expected_generation(),
        reason: request.reason(),
        receipt,
    });
    Ok(())
}

/// Bounded wait on the real PostgreSQL clock. It only reads `expires_at`; it
/// never overwrites the lease and never fakes a clock.
async fn wait_until_expired(pool: &Pool, repository: Uuid, pin_id: Uuid) -> Result<()> {
    let observer = pool.get().await.context("checkout an expiry observer connection")?;
    let deadline = Instant::now() + Duration::from_secs(EXPIRY_WAIT_SECONDS);
    loop {
        let row = observer
            .query_one(
                "SELECT expires_at <= clock_timestamp() FROM public.ref_store_core_pins
                 WHERE repository_id=$1 AND pin_id=$2",
                &[&repository, &pin_id],
            )
            .await
            .context("observe the one-second metadata pin against the database clock")?;
        if row.get::<_, bool>(0) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the one-second metadata pin did not reach database-clock expiry in {EXPIRY_WAIT_SECONDS}s");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn expect_expired_denial(pool: &Pool, scope: &MetadataSnapshotScope, lifecycle: &Lifecycle) -> Result<()> {
    let request = ReadMetadataSnapshotPageRequest::new(
        *scope,
        lifecycle.creation.snapshot_id,
        lifecycle.creation.pin_id,
        1,
        None,
        None,
        SINGLE_PAGE_LIMIT,
    )?;
    match page(pool, &request).await {
        Err(RefStoreError::MetadataPinExpired { pin_id, .. }) if pin_id == lifecycle.creation.pin_id => Ok(()),
        other => bail!("an expired pin page was not denied with the typed expired state: {other:?}"),
    }
}

async fn check_lookup(pool: &Pool, scope: &MetadataSnapshotScope, request_id: Uuid, expected: &Value) -> Result<()> {
    match lookup(pool, scope, request_id).await.context("metadata_receipt")? {
        MetadataReceiptLookup::Found(receipt) => {
            let actual = match receipt {
                MetadataReceipt::Snapshot(receipt) => serde_json::to_value(receipt)?,
                MetadataReceipt::Pin(receipt) => serde_json::to_value(receipt)?,
            };
            if actual != *expected {
                bail!("the durable receipt for request {request_id} does not match the returned receipt");
            }
            Ok(())
        }
        MetadataReceiptLookup::Unknown => bail!("the durable receipt ledger lost request {request_id}"),
    }
}

async fn expect_unknown_lookup(pool: &Pool, scope: &MetadataSnapshotScope) -> Result<()> {
    match lookup(pool, scope, Uuid::new_v4()).await.context("metadata_receipt for an unknown request")? {
        MetadataReceiptLookup::Unknown => Ok(()),
        MetadataReceiptLookup::Found(_) => bail!("an unknown metadata request id resolved to a receipt"),
    }
}

/// Verify the restored database: exact replays, retained rows and typed states.
async fn verify(
    pool: &Pool,
    fixture: &Fixture,
    scope: &MetadataSnapshotScope,
    version: &CoreGateVersion,
    mode: &str,
) -> Result<()> {
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(&fixture.output)
            .with_context(|| format!("read the private fixture manifest {}", fixture.output.display()))?,
    )
    .context("parse the private fixture manifest")?;
    if field(&manifest, "kind")?.as_str() != Some(MANIFEST_KIND) {
        bail!("the fixture manifest has an unexpected kind");
    }
    if field(&manifest, "mode")?.as_str() != Some("seed") {
        bail!("verify mode needs the manifest written by seed mode");
    }
    let recorded_scope = field(&manifest, "scope")?;
    if *recorded_scope != scope_json(fixture, scope, version) {
        bail!("the restored core gate/scope does not equal the scope captured before the backup");
    }
    let gate_digest = RequestDigest::from_str(&text_field(recorded_scope, "gate_digest")?)?;
    let captured = captured_refs(&manifest)?;
    let recorded_tables = field(&manifest, "tables")?.clone();
    assert_populated(&recorded_tables)?;
    let before = table_rows(pool, fixture).await?;
    if before != recorded_tables {
        bail!("the restored migration-140 rows differ from the rows captured before the backup");
    }
    let mut checks = Vec::new();
    for lifecycle in lifecycles(&manifest)? {
        replay_lifecycle(pool, scope, &gate_digest, &lifecycle).await?;
        for (request_id, receipt) in receipts_of_json(&lifecycle)? {
            check_lookup(pool, scope, request_id, &receipt).await?;
        }
        expect_unknown_lookup(pool, scope).await?;
        assert_pin_row(
            &before,
            uuid_field(&lifecycle, "pin_id")?,
            &text_field(&lifecycle, "final_state")?,
            int_field(&lifecycle, "final_generation")?,
        )?;
        checks.push(check_pages(pool, scope, &lifecycle, &captured).await?);
    }
    assert_usage(&before)?;
    let after = table_rows(pool, fixture).await?;
    if after != before {
        bail!("an exact create/renew/release replay mutated retained rows, counters or timestamps");
    }
    let marker = json!({
        "kind": MANIFEST_KIND,
        "version": 1,
        "mode": mode,
        "scope": recorded_scope,
        "counts": counts(&before)?,
        "lifecycles": checks,
        "restored_rows_equal_pre_backup_rows": true,
        "exact_replay_returned_original_receipts": true,
        "replay_mutated_rows_counters_or_timestamps": false,
        "pack_membership_state": "unavailable",
        "serving_claim": false,
    });
    println!("{MARKER} {}", serde_json::to_string(&marker)?);
    Ok(())
}

async fn replay_lifecycle(
    pool: &Pool,
    scope: &MetadataSnapshotScope,
    gate_digest: &RequestDigest,
    lifecycle: &Value,
) -> Result<()> {
    let snapshot_id = uuid_field(lifecycle, "snapshot_id")?;
    let pin_id = uuid_field(lifecycle, "pin_id")?;
    let create_request = CreateMetadataSnapshotRequest::new(
        *scope,
        uuid_field(lifecycle, "create_request_id")?,
        pin_id,
        snapshot_id,
        int_field(lifecycle, "lease_seconds")?,
        *gate_digest,
    )?;
    let created = create(pool, &create_request).await.context("exact create replay")?;
    if !created.replayed {
        bail!("an exact create replay did not report a replay for snapshot {snapshot_id}");
    }
    if serde_json::to_value(&created.receipt)? != *field(lifecycle, "create_receipt")? {
        bail!("an exact create replay returned a different receipt for snapshot {snapshot_id}");
    }
    if let Some(renewal) = optional_section(lifecycle, "renew")? {
        let request = RenewMetadataPinRequest::new(
            *scope,
            uuid_field(renewal, "request_id")?,
            pin_id,
            int_field(renewal, "expected_generation")?,
            int_field(renewal, "lease_seconds")?,
        )?;
        let replayed = renew(pool, &request).await.context("exact renewal replay")?;
        if !replayed.replayed {
            bail!("an exact renewal replay did not report a replay for pin {pin_id}");
        }
        if serde_json::to_value(&replayed.receipt)? != *field(renewal, "receipt")? {
            bail!("an exact renewal replay returned a different receipt for pin {pin_id}");
        }
    }
    if let Some(release) = optional_section(lifecycle, "release")? {
        let request = ReleaseMetadataPinRequest::new(
            *scope,
            uuid_field(release, "request_id")?,
            pin_id,
            int_field(release, "expected_generation")?,
            PinReleaseReason::parse(&text_field(release, "reason")?)?,
        )?;
        let replayed = release_pin(pool, &request).await.context("exact release replay")?;
        if !replayed.replayed {
            bail!("an exact release replay did not report a replay for pin {pin_id}");
        }
        if serde_json::to_value(&replayed.receipt)? != *field(release, "receipt")? {
            bail!("an exact release replay returned a different receipt for pin {pin_id}");
        }
    }
    Ok(())
}

/// The active pin must still page (through a real cursor), while the released
/// and expired pins must deny their exact typed state.
async fn check_pages(
    pool: &Pool,
    scope: &MetadataSnapshotScope,
    lifecycle: &Value,
    captured: &[(String, String)],
) -> Result<Value> {
    let snapshot_id = uuid_field(lifecycle, "snapshot_id")?;
    let pin_id = uuid_field(lifecycle, "pin_id")?;
    let generation = int_field(lifecycle, "final_generation")?;
    let kind = text_field(lifecycle, "kind")?;
    let request =
        ReadMetadataSnapshotPageRequest::new(*scope, snapshot_id, pin_id, generation, None, None, CURSOR_PAGE_LIMIT)?;
    match kind.as_str() {
        "active" => {
            let refs = read_all_refs(pool, scope, snapshot_id, pin_id, generation, CURSOR_PAGE_LIMIT).await?;
            if &refs != captured {
                bail!("the restored active pin page does not equal the refs captured before the backup");
            }
            Ok(json!({"kind": kind, "snapshot_id": snapshot_id, "refs": refs.len(), "typed_state": "live"}))
        }
        "released" => {
            match page(pool, &request).await {
                Err(RefStoreError::MetadataPinReleased { pin_id: denied, .. }) if denied == pin_id => {}
                other => bail!("the restored released pin page was not denied as released: {other:?}"),
            }
            Ok(json!({"kind": kind, "snapshot_id": snapshot_id, "typed_state": "released"}))
        }
        "expired" => {
            match page(pool, &request).await {
                Err(RefStoreError::MetadataPinExpired { pin_id: denied, .. }) if denied == pin_id => {}
                other => bail!("the restored expired pin page was not denied as expired: {other:?}"),
            }
            Ok(json!({"kind": kind, "snapshot_id": snapshot_id, "typed_state": "expired"}))
        }
        other => bail!("the fixture manifest has an unknown lifecycle kind {other:?}"),
    }
}

async fn read_all_refs(
    pool: &Pool,
    scope: &MetadataSnapshotScope,
    snapshot_id: Uuid,
    pin_id: Uuid,
    generation: i64,
    limit: u32,
) -> Result<Vec<(String, String)>> {
    let mut cursor: Option<MetadataSnapshotCursor> = None;
    let mut refs = Vec::new();
    for _ in 0..64 {
        let request =
            ReadMetadataSnapshotPageRequest::new(*scope, snapshot_id, pin_id, generation, None, cursor.clone(), limit)?;
        let snapshot_page = page(pool, &request).await.context("read a metadata snapshot page")?;
        for row in snapshot_page.refs() {
            refs.push((row.name().as_str().to_owned(), row.oid().as_hex()));
        }
        match snapshot_page.next() {
            Some(next) => cursor = Some(next.clone()),
            None => return Ok(refs),
        }
    }
    bail!("a metadata snapshot page sequence never completed inside 64 bounded pages");
}

async fn core_refs(pool: &Pool, repository: Uuid) -> Result<Vec<(String, String)>> {
    let client = pool.get().await.context("checkout a refs reader connection")?;
    let rows = client
        .query(
            "SELECT ref_name, oid FROM public.ref_store_core_refs WHERE repository_id=$1 ORDER BY ref_name COLLATE \"C\"",
            &[&repository],
        )
        .await
        .context("read the seeded migration-139 core refs")?;
    Ok(rows.iter().map(|row| (row.get(0), row.get(1))).collect())
}

/// Exact JSON rows of the six migration-140 tables for this fixture scope. The
/// ordering is canonical text so the same rows compare byte-for-byte before and
/// after the restore and around every replay.
async fn table_rows(pool: &Pool, fixture: &Fixture) -> Result<Value> {
    let client = pool.get().await.context("checkout a catalog reader connection")?;
    client.batch_execute("SET TIME ZONE 'UTC'").await.context("normalize fixture JSON timestamps to UTC")?;
    let row = client
        .query_one(
            "SELECT json_build_object(
                 'ref_store_core_snapshots', (SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)
                     FROM public.ref_store_core_snapshots t WHERE t.repository_id=$1),
                 'ref_store_core_snapshot_refs', (SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)
                     FROM public.ref_store_core_snapshot_refs t
                     JOIN public.ref_store_core_snapshots s ON s.snapshot_id=t.snapshot_id WHERE s.repository_id=$1),
                 'ref_store_core_pins', (SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)
                     FROM public.ref_store_core_pins t WHERE t.repository_id=$1),
                 'ref_store_core_receipts', (SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)
                     FROM public.ref_store_core_receipts t WHERE t.repository_id=$1),
                 'ref_store_core_repo_usage', (SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)
                     FROM public.ref_store_core_repo_usage t WHERE t.repository_id=$1),
                 'ref_store_core_tenant_usage', (SELECT COALESCE(json_agg(t ORDER BY to_jsonb(t)::text),'[]'::json)
                     FROM public.ref_store_core_tenant_usage t WHERE t.tenant_id=$2))",
            &[&fixture.repository, &fixture.tenant],
        )
        .await
        .context("capture the six migration-140 metadata tables")?;
    Ok(row.get(0))
}

fn scope_json(fixture: &Fixture, scope: &MetadataSnapshotScope, version: &CoreGateVersion) -> Value {
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

fn lifecycle_json(lifecycle: &Lifecycle) -> Result<Value> {
    Ok(json!({
        "kind": lifecycle.kind,
        "final_state": lifecycle.state,
        "expired": lifecycle.expired,
        "lease_seconds": lifecycle.lease_seconds,
        "final_generation": lifecycle.generation,
        "snapshot_id": lifecycle.creation.snapshot_id.to_string(),
        "pin_id": lifecycle.creation.pin_id.to_string(),
        "create_request_id": lifecycle.creation.request_id.to_string(),
        "create_receipt": serde_json::to_value(&lifecycle.creation.receipt)?,
        "renew": match &lifecycle.renewal {
            Some(renewal) => json!({
                "request_id": renewal.request_id.to_string(),
                "expected_generation": renewal.expected_generation,
                "lease_seconds": renewal.lease_seconds,
                "receipt": serde_json::to_value(&renewal.receipt)?,
            }),
            None => Value::Null,
        },
        "release": match &lifecycle.release {
            Some(release) => json!({
                "request_id": release.request_id.to_string(),
                "expected_generation": release.expected_generation,
                "reason": release.reason.as_str(),
                "receipt": serde_json::to_value(&release.receipt)?,
            }),
            None => Value::Null,
        },
    }))
}

fn counts(tables: &Value) -> Result<Value> {
    let mut object = serde_json::Map::new();
    for name in TABLES {
        object.insert(name.to_owned(), json!(table(tables, name)?.len()));
    }
    Ok(Value::Object(object))
}

fn assert_populated(tables: &Value) -> Result<()> {
    for name in TABLES {
        if table(tables, name)?.is_empty() {
            bail!("migration-140 metadata table {name} is empty for the fixture scope");
        }
    }
    Ok(())
}

fn assert_pin_row(tables: &Value, pin_id: Uuid, state: &str, generation: i64) -> Result<()> {
    let wanted = pin_id.to_string();
    let row = table(tables, "ref_store_core_pins")?
        .iter()
        .find(|row| row.get("pin_id").and_then(Value::as_str) == Some(wanted.as_str()))
        .with_context(|| format!("pin {wanted} is missing from the fixture rows"))?;
    if row.get("state").and_then(Value::as_str) != Some(state) {
        bail!("pin {wanted} has an unexpected retained state");
    }
    if row.get("generation").and_then(Value::as_i64) != Some(generation) {
        bail!("pin {wanted} has an unexpected retained generation");
    }
    Ok(())
}

fn assert_usage(tables: &Value) -> Result<()> {
    let repo = table(tables, "ref_store_core_repo_usage")?
        .first()
        .context("the retained repository usage row is missing")?
        .clone();
    let tenant = table(tables, "ref_store_core_tenant_usage")?
        .first()
        .context("the retained tenant usage row is missing")?
        .clone();
    let expected = [
        ("snapshot_count", table(tables, "ref_store_core_snapshots")?.len() as i64),
        ("snapshot_ref_count", table(tables, "ref_store_core_snapshot_refs")?.len() as i64),
        ("receipt_count", table(tables, "ref_store_core_receipts")?.len() as i64),
    ];
    for (name, count) in expected {
        if repo.get(name).and_then(Value::as_i64) != Some(count) {
            bail!("retained repository usage {name} does not equal the retained rows");
        }
        // The drill tenant owns no other migration-140 rows: nothing else in
        // this drill creates A2 metadata, so the tenant rollup is exactly this
        // repository's retained total.
        if tenant.get(name).and_then(Value::as_i64) != Some(count) {
            bail!("retained tenant usage {name} does not equal the retained repository rows");
        }
    }
    if repo.get("logical_bytes").and_then(Value::as_i64).unwrap_or(0) <= 0
        || tenant.get("logical_bytes").and_then(Value::as_i64).unwrap_or(0) <= 0
    {
        bail!("retained usage logical bytes must be positive after a successful snapshot");
    }
    Ok(())
}

fn lifecycles(manifest: &Value) -> Result<Vec<Value>> {
    Ok(array_field(manifest, "lifecycles")?.clone())
}

fn captured_refs(manifest: &Value) -> Result<Vec<(String, String)>> {
    array_field(manifest, "captured_refs")?
        .iter()
        .map(|row| Ok((text_field(row, "name")?, text_field(row, "oid")?)))
        .collect()
}

fn receipts_of(lifecycle: &Lifecycle) -> Result<Vec<(Uuid, Value)>> {
    let mut receipts = vec![(lifecycle.creation.request_id, serde_json::to_value(&lifecycle.creation.receipt)?)];
    if let Some(renewal) = &lifecycle.renewal {
        receipts.push((renewal.request_id, serde_json::to_value(&renewal.receipt)?));
    }
    if let Some(release) = &lifecycle.release {
        receipts.push((release.request_id, serde_json::to_value(&release.receipt)?));
    }
    Ok(receipts)
}

fn receipts_of_json(lifecycle: &Value) -> Result<Vec<(Uuid, Value)>> {
    let mut receipts = vec![(uuid_field(lifecycle, "create_request_id")?, field(lifecycle, "create_receipt")?.clone())];
    for key in ["renew", "release"] {
        if let Some(section) = optional_section(lifecycle, key)? {
            receipts.push((uuid_field(section, "request_id")?, field(section, "receipt")?.clone()));
        }
    }
    Ok(receipts)
}

/// A manifest section that is either a real object or the JSON `null` placeholder.
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

fn int_field(value: &Value, key: &str) -> Result<i64> {
    field(value, key)?.as_i64().with_context(|| format!("fixture metadata field {key:?} must be an integer"))
}

fn array_field<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    field(value, key)?.as_array().with_context(|| format!("fixture metadata field {key:?} must be an array"))
}

fn table<'a>(tables: &'a Value, name: &str) -> Result<&'a Vec<Value>> {
    array_field(tables, name)
}
