//! Verify body of the roots+decisions drill: typed read-only replay against the
//! restored database, then an exact comparison with the seed marker.
//!
//! Only read paths run here: `PgRetentionRoots::{get,query_receipt,materialize}`,
//! `PgDecisionProtocol::read`, an independent S3 read-back of the retained
//! locators, and read-only reads of the historical decision rows. No proof,
//! grant, authority or quota charge is minted, and every canonical table digest
//! must be identical before and after the replay.
use anyhow::{Result, anyhow};
use rootyard::blob_store::opendal::BlobStore;
use serde_json::Value;

use super::db::Db;
use super::{decisions, marker};

const COMPARED: [&str; 11] = [
    "scope",
    "source",
    "gate",
    "roots",
    "materialized",
    "root_counts",
    "quota",
    "tables",
    "root_family_counts",
    "decision_family_counts",
    "protocol",
];

pub async fn verify(db: &Db, store: &BlobStore, fixture: &marker::Fixture) -> Result<()> {
    let seed_path = fixture.seed.as_ref().ok_or_else(|| {
        anyhow!("ROOTYARD_ROOTS_DECISIONS_FIXTURE_SEED (the seed manifest) is required in verify mode")
    })?;
    let text = std::fs::read_to_string(seed_path)
        .map_err(|error| anyhow!("the verify run needs the seed manifest: {error}"))?;
    let seed: Value = serde_json::from_str(&text).map_err(|error| anyhow!("seed manifest is not JSON: {error}"))?;
    let scope = seed.get("scope").ok_or_else(|| anyhow!("seed manifest has no scope object"))?;
    let repo = marker::uuid_field(scope, "repository_id")?;
    let tenant = marker::uuid_field(scope, "tenant_id")?;
    let scenarios = marker::scenarios_from(&seed)?;

    let protocol = decisions::read_protocol(&db.pool, repo)
        .await?
        .ok_or_else(|| anyhow!("the restored database lost the migration-144 protocol realm"))?;
    if marker::protocol_json(&protocol) != seed["protocol"] {
        return Err(anyhow!("the restored protocol realm differs from the seed marker"));
    }
    if !protocol.decision_required() {
        return Err(anyhow!("the restored protocol realm lost the one-way decision fence"));
    }

    let decision_rows = decision_rows_json(db, &seed).await?;
    if decision_rows != seed["decisions"]["rows"] {
        return Err(anyhow!("the restored historical decision rows differ from the seed marker"));
    }

    let mut base = seed.clone();
    base["mode"] = Value::String("verify".to_owned());
    let marker_out = marker::finish_marker(db, store, fixture, base, repo, tenant, &scenarios).await?;

    for key in COMPARED {
        if marker_out.get(key) != seed.get(key) {
            return Err(anyhow!("restored {key} differs from the seed marker"));
        }
    }
    let roots =
        marker_out.get("roots").and_then(Value::as_array).ok_or_else(|| anyhow!("verify marker has no roots array"))?;
    if roots.len() != 3 {
        return Err(anyhow!("the drill must retain exactly three root scenarios"));
    }
    if roots[0].get("binding_digest").is_none() || roots[0]["state"] != Value::String("active".to_owned()) {
        return Err(anyhow!("the active root lost its retained capture"));
    }
    if roots[1].get("binding_digest").is_none() || roots[1]["state"] != Value::String("released".to_owned()) {
        return Err(anyhow!("the released root lost its retained capture or release state"));
    }
    if roots[2].get("record").is_none() || !roots[2]["record"].is_null() {
        return Err(anyhow!("the release-before-register tombstone gained a fabricated capture"));
    }
    let materialized =
        marker_out.get("materialized").ok_or_else(|| anyhow!("verify marker has no materialized object"))?;
    for key in ["verified_pairs", "verified_bytes", "binding_digest", "readback_digest", "readback_bytes"] {
        if materialized.get(key).is_none() {
            return Err(anyhow!("materialized root evidence is missing {key}"));
        }
    }
    let decisions = marker_out.get("decisions").ok_or_else(|| anyhow!("verify marker has no decisions object"))?;
    if decisions["consumed"] != 1u64
        || decisions["cancelled"] != 1u64
        || decisions["cancel_before_install_count"] != 1u64
    {
        return Err(anyhow!("the restored decision scenarios are not the seeded three"));
    }
    Ok(())
}

/// Read-only read of the historical decision rows (state + per-ref verdicts).
/// No authority is replayed, no decision is consumed and nothing is charged.
async fn decision_rows_json(db: &Db, seed: &Value) -> Result<Value> {
    let mut out = Vec::new();
    for entry in seed["decisions"]["rows"].as_array().ok_or_else(|| anyhow!("seed marker has no decision rows"))? {
        let decision_id = marker::uuid_field(entry, "decision_id")?;
        let client = db.pool.get().await?;
        let header = client
            .query_opt(
                "SELECT state, action, coalesce(merge_pull_number,0), coalesce(merge_version,0)
                 FROM ref_store_publication_decisions WHERE decision_id=$1",
                &[&decision_id],
            )
            .await?
            .ok_or_else(|| anyhow!("the restored decision row is missing"))?;
        let verdicts = client
            .query(
                "SELECT ref_name, verdict, reject_code FROM ref_store_decision_refs
                 WHERE decision_id=$1 ORDER BY ref_name",
                &[&decision_id],
            )
            .await?
            .iter()
            .map(|row| {
                serde_json::json!({
                    "ref_name": row.get::<_, String>(0),
                    "verdict": row.get::<_, String>(1),
                    "reject_code": row.get::<_, Option<String>>(2),
                })
            })
            .collect::<Vec<_>>();
        drop(client);
        out.push(serde_json::json!({
            "decision_id": decision_id.to_string(),
            "state": header.get::<_, String>(0),
            "action": header.get::<_, String>(1),
            "merge_pull_number": header.get::<_, i64>(2),
            "merge_version": header.get::<_, i64>(3),
            "verdicts": verdicts,
        }));
    }
    Ok(Value::Array(out))
}
