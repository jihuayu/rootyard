//! Secret-free seed marker for the issue #169 format22 fixture.
//!
//! The marker carries ids, digests, counts and states only: no DSN, token,
//! endpoint or S3 credential. The Python drill validates it with
//! `backup_blob_serving169_support.native_marker_checks` before it runs, and
//! derives the expected positive identities from it.
use anyhow::{Result, anyhow, ensure};
use deadpool_postgres::Pool;
use serde_json::{Value, json};
use std::path::Path;
use uuid::Uuid;

pub const KIND: &str = "rootyard/format22-backup-fixture-seed";

/// Read-only badge of one registration, checked against the real publication
/// and artifact rows (never trusted on its own).
pub struct RegistrationBadge {
    pub registration_id: Uuid,
    pub pack_id: Uuid,
    pub pack_sha256: String,
    pub idx_sha256: String,
}

pub async fn registration_badges(pool: &Pool, registrations: &[Uuid]) -> Result<Vec<RegistrationBadge>> {
    let client = pool.get().await?;
    let mut out = Vec::with_capacity(registrations.len());
    for registration in registrations {
        let rows = client
            .query(
                "SELECT p.pack_id, a.role, a.sha256
                   FROM ref_store_core_pack_publications p
                   JOIN ref_store_core_pack_artifacts a ON a.registration_id=p.registration_id
                  WHERE p.registration_id=$1 ORDER BY a.role",
                &[registration],
            )
            .await?;
        ensure!(rows.len() == 2, "a registration does not expose exactly two artifact rows");
        let pack_id: Uuid = rows[0].get(0);
        let mut pack = None;
        let mut idx = None;
        for row in &rows {
            let role: String = row.get(1);
            let sha: String = row.get(2);
            match role.as_str() {
                "pack" => pack = Some(sha),
                "idx" => idx = Some(sha),
                other => return Err(anyhow!("unexpected artifact role {other}")),
            }
        }
        out.push(RegistrationBadge {
            registration_id: *registration,
            pack_id,
            pack_sha256: pack.ok_or_else(|| anyhow!("registration has no pack row"))?,
            idx_sha256: idx.ok_or_else(|| anyhow!("registration has no idx row"))?,
        });
    }
    Ok(out)
}

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
