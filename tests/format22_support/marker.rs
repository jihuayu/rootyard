//! Secret-free seed marker for the issue #169 format22 fixture.
//!
//! The marker carries ids, digests, counts and states only: no DSN, token,
//! endpoint or S3 credential. The Python drill validates it with
//! `backup_blob_serving169_support.native_marker_checks` before it runs, and
//! derives the expected positive identities from it.
use anyhow::{Result, ensure};
use deadpool_postgres::Pool;
use rootyard::ref_store::RequestDigest;
use serde_json::{Value, json};
use std::path::Path;
use uuid::Uuid;

pub const KIND: &str = "rootyard/format22-backup-fixture-seed";

/// COUNT-only retainable check: the pack sets that still declare this
/// registration after the source pin was released. No row identity decides.
pub async fn retainable_counts(pool: &Pool, registration: Uuid) -> Result<Value> {
    let client = pool.get().await?;
    let root_packs: i64 = client
        .query_one("SELECT count(*) FROM ref_store_core_root_packs WHERE registration_id=$1", &[&registration])
        .await?
        .get(0);
    let snapshot_packs: i64 = client
        .query_one("SELECT count(*) FROM ref_store_core_snapshot_packs WHERE registration_id=$1", &[&registration])
        .await?
        .get(0);
    let read_packs: i64 = client
        .query_one("SELECT count(*) FROM ref_store_core_serving_read_packs WHERE registration_id=$1", &[&registration])
        .await?
        .get(0);
    Ok(json!({"root_packs": root_packs, "snapshot_packs": snapshot_packs, "serving_read_packs": read_packs}))
}

pub fn write(path: &Path, marker: &Value) -> Result<()> {
    let text = serde_json::to_vec_pretty(marker)?;
    ensure!(!text.is_empty(), "seed marker is empty");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, text)?;
    Ok(())
}

/// Deterministic but distinct release intent digest for one release request
/// (the release digest is caller-supplied intent, never a stored proof).
pub fn release_digest(label: &str) -> String {
    let mut seed = [0x5a; 32];
    for (index, byte) in label.as_bytes().iter().enumerate() {
        seed[index % 32] ^= *byte;
    }
    RequestDigest::from_bytes(seed).as_hex()
}
