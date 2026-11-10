//! Small shared helpers for the retention-root integration target.
use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::BlobProvider;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::GitObjectFormat;
use rootyard::ref_store::core::PackReadSnapshot;
use rootyard::ref_store::core::retention_root::{PgRetentionRoots, RootRecord};

use super::db::Db;
use super::git::assert_pack_identity;
use super::pack::{SourceSnapshot, Verified, create_snapshot, verify_new};

pub fn open_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == BlobProvider::S3, "ROOTYARD_BLOB_SERVICE must be s3 for this suite");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

pub fn adapter(store: &BlobStore, git: &std::path::Path) -> Result<PgRetentionRoots> {
    Ok(PgRetentionRoots::new(store.clone(), git.to_path_buf())?)
}

pub fn missing_oid(format: GitObjectFormat) -> String {
    let width = if format == GitObjectFormat::Sha1 { 20 } else { 32 };
    hex::encode(vec![0xab; width])
}

pub fn assert_record_matches_source(record: &RootRecord, source: &PackReadSnapshot) -> Result<()> {
    record.verify()?;
    ensure!(record.state() == "active" && record.generation() == 1, "root is not active generation 1");
    ensure!(record.refs() == source.refs(), "retained refs differ from the captured source");
    ensure!(record.head_ref() == source.head_ref(), "retained HEAD ref differs");
    ensure!(record.head_oid_hex() == source.head_oid_hex(), "retained HEAD oid differs");
    ensure!(record.pack_count() == source.pack_count(), "retained pack count differs");
    ensure!(record.oid_count() >= 1 && !record.root_oids().is_empty(), "retained selector is empty");
    ensure!(record.source_snapshot_id() == source.snapshot_id(), "source snapshot id differs");
    ensure!(record.source_pin_id() == source.pin_id(), "source pin id differs");
    ensure!(record.source_read_digest_hex().len() == 64, "source read digest is not sha256 hex");
    for expected in source.packs() {
        let actual = record
            .packs()
            .iter()
            .find(|pack| pack.pack_id() == expected.pack_id())
            .ok_or_else(|| anyhow!("root locator set omitted a registered pack"))?;
        assert_pack_identity(expected, actual)?;
    }
    Ok(())
}

pub async fn one_verified(db: &Db, store: &BlobStore, git: &std::path::Path) -> Result<(Verified, SourceSnapshot)> {
    let verified = verify_new(db, store, git, GitObjectFormat::Sha1).await?;
    let source = create_snapshot(db, &verified, 300).await?;
    Ok((verified, source))
}
