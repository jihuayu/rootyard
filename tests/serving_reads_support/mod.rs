//! Shared real-PostgreSQL fixture for the bounded transient serving read suite.
//!
//! Everything here is real: the schema is migrated by the production
//! `db::migrate`, the repository is created by the production
//! `ref_store::serving::provision` path, and the Blob backend identity comes from
//! opening the production Blob profile. No provider IO, Git child or GitFS
//! directory is created by this module.
//!
//! The suite fails loudly when migration 146 is not wired into `db::migrate`
//! instead of silently testing a schema without the transient tables.
#![allow(dead_code)]

use super::serving_support::{Fixture, backend_identity, deadline};
use anyhow::{Context, Result, anyhow, ensure};
use rootyard::blob_store::BlobBackendIdentity;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db;
use rootyard::ref_store::core::MetadataSnapshotScope;
use rootyard::ref_store::core::pack_snapshot::PgPackSnapshotMaterializer;
use rootyard::ref_store::serving::{ProvisionRequest, provision};
use rootyard::ref_store::{GitObjectFormat, MetadataPinPurpose};
use std::path::PathBuf;
use uuid::Uuid;

pub const DEADLINE_SECONDS: u64 = 30;

pub fn operation_deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + std::time::Duration::from_secs(DEADLINE_SECONDS)
}

/// One provisioned, ready `pg_refstore` repository with its exact gate realm.
#[derive(Clone, Copy, Debug)]
pub struct ReadyRepo {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub gate_revision: i64,
}

impl ReadyRepo {
    pub fn scope(&self) -> Result<MetadataSnapshotScope> {
        MetadataSnapshotScope::new(
            self.repository_id,
            self.tenant_id,
            self.owner_id,
            MetadataPinPurpose::Verification,
            self.object_format,
            self.history_incarnation,
            self.authority_epoch,
            self.group_epoch,
        )
        .map_err(|error| anyhow!("scope rejected: {error}"))
    }

    pub fn with_history(&self, history: Uuid) -> Result<MetadataSnapshotScope> {
        MetadataSnapshotScope::new(
            self.repository_id,
            self.tenant_id,
            self.owner_id,
            MetadataPinPurpose::Verification,
            self.object_format,
            history,
            self.authority_epoch,
            self.group_epoch,
        )
        .map_err(|error| anyhow!("scope rejected: {error}"))
    }
}

/// Open the configured production Blob profile (no provider IO is performed).
pub fn open_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

/// The trusted Git binary, exactly as the A5b materializer requires it.
pub fn git_binary() -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var("ROOTYARD_TEST_GIT").unwrap_or_else(|_| "/usr/bin/git".into()));
    ensure!(path.is_absolute() && path.is_file(), "ROOTYARD_TEST_GIT must be an absolute existing git binary");
    Ok(path)
}

pub struct RepoFixture {
    pub store: BlobStore,
    pub backend: BlobBackendIdentity,
    pub ready: ReadyRepo,
}

impl RepoFixture {
    pub fn materializer(&self) -> Result<PgPackSnapshotMaterializer> {
        PgPackSnapshotMaterializer::new(self.store.clone(), git_binary()?)
            .map_err(|error| anyhow!("materializer rejected: {error}"))
    }
}

/// Provision one ready repository through the production serving path and read
/// its exact durable realm back through SQL.
pub async fn provision_ready(fixture: &Fixture, actor: &db::Identity, name: &str) -> Result<RepoFixture> {
    let store = open_store()?;
    let backend = store.backend_identity().clone();
    let request = ProvisionRequest { owner: None, name: name.to_owned(), object_format: GitObjectFormat::Sha1 };
    let receipt = provision(&fixture.pool, actor, request, &backend, deadline())
        .await
        .map_err(|error| anyhow!("provision failed: {error}"))?;
    ensure!(receipt.created, "provision unexpectedly reused an existing repository");
    let repository_id = receipt.repository.id;
    let client = fixture.pool.get().await?;
    let owner_id: Uuid =
        client.query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&repository_id]).await?.get(0);
    let gate = client
        .query_one(
            "SELECT tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,revision
             FROM ref_store_core_gates WHERE repository_id=$1",
            &[&repository_id],
        )
        .await
        .context("a provisioned serving repository must have a core gate")?;
    let format: String = gate.get(1);
    let ready = ReadyRepo {
        repository_id,
        tenant_id: gate.get(0),
        owner_id,
        object_format: GitObjectFormat::parse(&format).map_err(|error| anyhow!("stored format: {error}"))?,
        history_incarnation: gate.get(2),
        authority_epoch: gate.get(3),
        group_epoch: gate.get(4),
        gate_revision: gate.get(5),
    };
    Ok(RepoFixture { store, backend, ready })
}

/// Migration 146 must be part of `db::migrate`. Called by every case so a
/// missing Root wiring fails loudly instead of silently testing nothing.
pub async fn ensure_migration_146(fixture: &Fixture) -> Result<()> {
    let client = fixture.pool.get().await?;
    let installed: bool = client
        .query_one(
            "SELECT to_regclass('ref_store_core_serving_reads') IS NOT NULL
                    AND to_regclass('ref_store_core_serving_read_refs') IS NOT NULL
                    AND to_regclass('ref_store_core_serving_read_packs') IS NOT NULL
                    AND to_regclass('ref_store_core_serving_read_artifacts') IS NOT NULL
                    AND to_regclass('ref_store_core_serving_read_repo_usage') IS NOT NULL
                    AND to_regclass('ref_store_core_serving_read_tenant_usage') IS NOT NULL",
            &[],
        )
        .await?
        .get(0);
    ensure!(installed, "migration 146 is not wired into db::migrate; the transient serving read tables are missing");
    Ok(())
}

/// Count rows in one of the two families for one repository.
pub async fn count_for_repo(fixture: &Fixture, table: &str, repository_id: Uuid) -> Result<i64> {
    let sql = format!("SELECT count(*)::bigint FROM {table} WHERE repository_id=$1");
    Ok(fixture.pool.get().await?.query_one(&sql, &[&repository_id]).await?.get(0))
}

pub fn backend_for_bucket(bucket: &str) -> Result<BlobBackendIdentity> {
    backend_identity(bucket)
}

pub fn purpose_verification() -> MetadataPinPurpose {
    MetadataPinPurpose::Verification
}

// ---------------------------------------------------------------------------
// Fault injection in this suite's OWN migration-146 tables.
//
// The registered capture path needs the A4 S3+Git fixture, so the reclaim,
// deadline and cascade regressions below seed transient rows directly with SQL.
// Every row still has to satisfy the real migration-146 CHECKs and foreign keys,
// and every assertion is made against the production adapters.
// ---------------------------------------------------------------------------

const HEADER_INSERT: &str = "
INSERT INTO ref_store_core_serving_reads(
    pin_id,snapshot_id,generation,repository_id,tenant_id,owner_id,purpose,object_format,
    history_incarnation,authority_epoch,group_epoch,backend_identity,gate_revision,gate_digest,
    head_ref,head_oid,ref_count,refs_digest,pack_count,membership_digest,snapshot_digest,
    logical_bytes,lease_seconds,expires_at)
VALUES($1,$2,1,$3,$4,$5,'verification','sha1',$6,$7,$8,$9,$10,$11,
       'refs/heads/main',$12,1,$13,1,$14,$15,$16,60,
       clock_timestamp() + ($17::bigint * interval '1 microsecond'))";

fn digest_hex(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

/// Insert `count` transient header rows for one provisioned repository.
///
/// `expires_offset_micros` is negative for an already expired lease and positive
/// for a live one. Returns the minted pin ids.
pub async fn insert_serving_read_headers(
    fixture: &Fixture,
    ready: &ReadyRepo,
    backend_hex: &str,
    count: usize,
    logical_bytes: i64,
    expires_offset_micros: i64,
) -> Result<Vec<Uuid>> {
    let client = fixture.pool.get().await?;
    let gate_digest = digest_hex('b');
    let refs_digest = digest_hex('c');
    let membership_digest = digest_hex('d');
    let snapshot_digest = digest_hex('e');
    let head_oid = "a".repeat(40);
    let mut pins = Vec::with_capacity(count);
    for _ in 0..count {
        let pin_id = Uuid::new_v4();
        let snapshot_id = Uuid::new_v4();
        client
            .execute(
                HEADER_INSERT,
                &[
                    &pin_id,
                    &snapshot_id,
                    &ready.repository_id,
                    &ready.tenant_id,
                    &ready.owner_id,
                    &ready.history_incarnation,
                    &ready.authority_epoch,
                    &ready.group_epoch,
                    &backend_hex,
                    &ready.gate_revision,
                    &gate_digest,
                    &head_oid,
                    &refs_digest,
                    &membership_digest,
                    &snapshot_digest,
                    &logical_bytes,
                    &expires_offset_micros,
                ],
            )
            .await?;
        pins.push(pin_id);
    }
    Ok(pins)
}

/// Add one captured ref, one pack descriptor and both artifact rows to a header
/// that was seeded directly. Returns `(pack_id, registration_id)`.
pub async fn add_serving_read_children(
    fixture: &Fixture,
    ready: &ReadyRepo,
    pin_id: Uuid,
    backend_hex: &str,
) -> Result<(Uuid, Uuid)> {
    let client = fixture.pool.get().await?;
    let pack_id = Uuid::new_v4();
    let registration_id = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO ref_store_core_serving_read_refs(pin_id,ref_name,oid)
             VALUES($1,'refs/heads/main',$2)",
            &[&pin_id, &"a".repeat(40)],
        )
        .await?;
    client
        .execute(
            "INSERT INTO ref_store_core_serving_read_packs(
                 pin_id,pack_id,registration_id,artifact_set_digest,joined_revision)
             VALUES($1,$2,$3,$4,2)",
            &[&pin_id, &pack_id, &registration_id, &digest_hex('f')],
        )
        .await?;
    let sha = "1".repeat(64);
    for (role, slot) in [("pack", 0_i32), ("idx", 1_i32)] {
        client
            .execute(
                "INSERT INTO ref_store_core_serving_read_artifacts(
                     pin_id,pack_id,role,slot,hold_id,locator_tenant_id,locator_authority_id,
                     locator_authority_generation,locator_attempt_id,locator_namespace,locator_sha256,
                     locator_length,provider,backend_identity,verified_sha256,verified_length)
                 VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,'serving-reads',$9,4096,'s3',$10,$9,4096)",
                &[
                    &pin_id,
                    &pack_id,
                    &role,
                    &slot,
                    &Uuid::new_v4(),
                    &ready.tenant_id,
                    &Uuid::new_v4(),
                    &Uuid::new_v4(),
                    &sha,
                    &backend_hex,
                ],
            )
            .await?;
    }
    Ok((pack_id, registration_id))
}

/// Count the expired transient headers of one repository.
pub async fn expired_row_count(fixture: &Fixture, repository_id: Uuid) -> Result<i64> {
    Ok(fixture
        .pool
        .get()
        .await?
        .query_one(
            "SELECT count(*)::bigint FROM ref_store_core_serving_reads
             WHERE repository_id=$1 AND expires_at <= clock_timestamp()",
            &[&repository_id],
        )
        .await?
        .get(0))
}

/// Count child rows of one transient header.
pub async fn child_row_count(fixture: &Fixture, table: &str, pin_id: Uuid) -> Result<i64> {
    let sql = format!("SELECT count(*)::bigint FROM {table} WHERE pin_id=$1");
    Ok(fixture.pool.get().await?.query_one(&sql, &[&pin_id]).await?.get(0))
}

/// Count the packs one repository's live transient reads currently protect.
pub async fn protection_count(fixture: &Fixture, repository_id: Uuid) -> Result<i64> {
    Ok(fixture
        .pool
        .get()
        .await?
        .query_one("SELECT count(*)::bigint FROM ref_store_core_serving_read_protection($1)", &[&repository_id])
        .await?
        .get(0))
}

/// Fault injection: activate `pack_verified` on a provisioned gate so the
/// registered capture path (and therefore its admission/cleanup order) is
/// reachable without the A4 S3+Git fixture. The real migration-142 fence still
/// applies: the activation must happen inside a revision increment.
pub async fn force_gate_pack_verified(fixture: &Fixture, repository_id: Uuid) -> Result<i64> {
    Ok(fixture
        .pool
        .get()
        .await?
        .query_one(
            "UPDATE ref_store_core_gates SET pack_mode='pack_verified',revision=revision+1
             WHERE repository_id=$1 AND pack_mode='metadata_only' RETURNING revision",
            &[&repository_id],
        )
        .await?
        .get(0))
}

/// Hold the tenant transient usage row `FOR UPDATE` on a second connection, so a
/// concurrent capture/release has to wait on it. The caller must `ROLLBACK`.
pub async fn hold_tenant_usage_lock(fixture: &Fixture, tenant_id: Uuid) -> Result<deadpool_postgres::Client> {
    let client = fixture.pool.get().await?;
    client.batch_execute("BEGIN").await?;
    client
        .execute(
            "INSERT INTO ref_store_core_serving_read_tenant_usage(tenant_id) VALUES($1)
             ON CONFLICT(tenant_id) DO NOTHING",
            &[&tenant_id],
        )
        .await?;
    client
        .query_one(
            "SELECT active_count FROM ref_store_core_serving_read_tenant_usage WHERE tenant_id=$1 FOR UPDATE",
            &[&tenant_id],
        )
        .await?;
    Ok(client)
}
