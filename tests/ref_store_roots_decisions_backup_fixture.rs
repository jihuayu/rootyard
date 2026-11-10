//! Root-selected companion fixture for the populated schema-144
//! roots + publication-decisions backup drill (#105/#107).
//!
//! Only `tests/backup_refstore_roots_decisions144.py` (current format20) and
//! `tests/backup_legacy143_roots_decisions.py` (verify half of the genuine
//! format19 upgrade) select this integration-test executable. The helper never
//! creates a database/schema and never runs a migration: the parent owns one
//! fresh migrated database (or the restored upgrade target) and seeds the
//! inherited plain-SQL migration-139 metadata gate/ref fixture before running
//! this helper.
//!
//! Seed mode is the real typed pipeline: A3 protected upload -> real S3, A4
//! verified pack commits, A5 pack snapshot/pin, three real retention roots
//! (active, released, release-before-register tombstone) and the real staged
//! publication-decision facade (`prepare` -> `select` -> `verify` -> `commit`,
//! plus post-install cancel and cancel-before-install). No ACK, proof,
//! registration, decision row or capability is fabricated with SQL.
//!
//! Verify mode runs against the restored database with typed read-only paths
//! only (`PgRetentionRoots::{get,query_receipt,materialize}`,
//! `PgDecisionProtocol::read`, historical decision rows) plus an independent
//! S3 read-back of the retained locators, and refuses if any canonical table
//! digest changed.
//!
//! Not claimed: Blob byte backup. The S3 originals are external, re-read and
//! never deleted; only PostgreSQL metadata is archived and restored.
use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;

#[path = "roots_decisions_backup_support/mod.rs"]
mod support;

/// Real S3 is mandatory: a missing/invalid profile or another provider is a
/// hard failure, never a skip. Credentials are inherited and never printed.
fn open_store() -> Result<BlobStore> {
    let profile =
        BlobProfile::from_env().map_err(|error| anyhow!("configured ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(
        profile.provider() == rootyard::blob_store::BlobProvider::S3,
        "the roots/decisions backup qualification requires real S3"
    );
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

#[tokio::test]
#[ignore = "root-selected only: needs the parent Python drill database plus ROOTYARD_ROOTS_DECISIONS_FIXTURE_* and real Blob/Git env"]
async fn ref_store_roots_decisions_backup_metadata_fixture() -> Result<()> {
    let fixture = support::marker::Fixture::from_env();
    let mode = std::env::var("ROOTYARD_ROOTS_DECISIONS_FIXTURE_MODE")
        .expect("ROOTYARD_ROOTS_DECISIONS_FIXTURE_MODE must be seed|verify");
    let store = open_store()?;
    let db = support::db::Db::attach(8).await?;
    match mode.as_str() {
        "seed" => support::seed::seed(&db, &store, &fixture).await,
        "verify" => support::verify::verify(&db, &store, &fixture).await,
        other => panic!("ROOTYARD_ROOTS_DECISIONS_FIXTURE_MODE must be seed|verify, got {other:?}"),
    }
}
