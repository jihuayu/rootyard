//! Canonical, secret-free row-set capture for every table of the drill schema.
//!
//! The drill never writes a raw decision row into a marker, a log or a report:
//! `ref_store_publication_decisions`/`ref_store_decision_scopes` carry the
//! PG-only `token_digest`, so only a count plus a SHA-256 over the canonically
//! ordered `to_jsonb(t)::text` rows is retained. The same statement is executed
//! independently by the Python harness, so the two implementations cross-check
//! each other instead of trusting one capture.
//!
//! The table list is **read from PostgreSQL** (`pg_tables`), never invented:
//! the 144 catalog delta is asserted by the harness against the generated
//! `schema/144_catalog.json` / `schema/143_catalog.json` fixtures.
use anyhow::{Result, anyhow};
use deadpool_postgres::Pool;
use serde_json::{Map, Value, json};

/// The ten migration-144 root tables this drill populates.
pub const ROOT_TABLES: [&str; 10] = [
    "ref_store_core_root_heads",
    "ref_store_core_roots",
    "ref_store_core_root_refs",
    "ref_store_core_root_oids",
    "ref_store_core_root_packs",
    "ref_store_core_root_tombstones",
    "ref_store_core_root_receipts",
    "ref_store_core_root_repo_usage",
    "ref_store_core_root_tenant_usage",
    "ref_store_core_protocol_repos",
];

/// The seven migration-144 publication-decision tables.
pub const DECISION_TABLES: [&str; 7] = [
    "ref_store_decision_scopes",
    "ref_store_publication_decisions",
    "ref_store_decision_dependencies",
    "ref_store_decision_refs",
    "ref_store_decision_cancellations",
    "ref_store_decision_repo_usage",
    "ref_store_decision_tenant_usage",
];

/// Every regular table in the parent-owned `public` schema, in name order.
pub async fn table_names(pool: &Pool) -> Result<Vec<String>> {
    let client = pool.get().await?;
    let rows =
        client.query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename", &[]).await?;
    let names = rows.iter().map(|row| row.get::<_, String>(0)).collect::<Vec<_>>();
    if names.is_empty() {
        return Err(anyhow!("the inherited database has no public tables"));
    }
    Ok(names)
}

/// One canonical row-set digest: `count`, SHA-256 and exact byte length of the
/// canonically ordered JSON text of every row. Identical in Python.
fn digest_sql(table: &str) -> String {
    format!(
        "SELECT count(*)::bigint, \
         coalesce(encode(sha256(convert_to(coalesce(string_agg(to_jsonb(t)::text, E'\\n' ORDER BY to_jsonb(t)::text), ''), 'UTF8')), 'hex'), ''), \
         coalesce(octet_length(convert_to(coalesce(string_agg(to_jsonb(t)::text, E'\\n' ORDER BY to_jsonb(t)::text), ''), 'UTF8')), 0) \
         FROM public.\"{table}\" t"
    )
}

pub async fn table_digest(pool: &Pool, table: &str) -> Result<(i64, String, i64)> {
    let client = pool.get().await?;
    let row = client.query_one(&digest_sql(table), &[]).await?;
    Ok((row.get(0), row.get(1), row.get(2)))
}

/// Exact digests for every table of the drill schema (no raw rows).
pub async fn table_digests(pool: &Pool) -> Result<Value> {
    let mut map = Map::new();
    for table in table_names(pool).await? {
        let (rows, sha256, bytes) = table_digest(pool, &table).await?;
        map.insert(table, json!({"rows": rows, "sha256": sha256, "bytes": bytes}));
    }
    Ok(Value::Object(map))
}

/// Row counts of the ten root and seven decision tables (the drill's own
/// families). A missing table is an error, never a zero.
pub async fn family_counts(pool: &Pool, tables: &[&str]) -> Result<Value> {
    let mut map = Map::new();
    for table in tables {
        let client = pool.get().await?;
        let row = client
            .query_opt("SELECT count(*)::bigint FROM pg_tables WHERE schemaname='public' AND tablename=$1", &[&table])
            .await?;
        let present = row.map(|row| row.get::<_, i64>(0)).unwrap_or(0);
        if present != 1 {
            return Err(anyhow!("fixture table {table} is missing from the migrated schema"));
        }
        let row = client.query_one(&format!("SELECT count(*)::bigint FROM public.\"{table}\""), &[]).await?;
        drop(client);
        map.insert((*table).to_owned(), json!(row.get::<_, i64>(0)));
    }
    Ok(Value::Object(map))
}

/// Non-secret typed semantic identity of one retained root receipt/record.
///
/// Locators/digests/ids are public fixture metadata; the module never touches a
/// credential or a decision row here.
pub fn pack_identity(pack: &rootyard::ref_store::core::pack_commit::RegisteredPack) -> Value {
    use rootyard::ref_store::core::pack_commit::PackArtifactRole;
    let mut artifacts = Vec::new();
    for role in [PackArtifactRole::Pack, PackArtifactRole::Idx] {
        let artifact = pack.artifact(role);
        let locator = artifact.locator();
        artifacts.push(json!({
            "role": format!("{role:?}").to_ascii_lowercase(),
            "slot": artifact.slot().to_string(),
            "verified_sha256": artifact.verified_sha256().as_str(),
            "verified_length": artifact.verified_length(),
            "namespace": locator.namespace(),
            "tenant_id": locator.tenant_id().to_string(),
            "authority_id": locator.authority_id().to_string(),
            "authority_generation": locator.authority_generation(),
            "attempt_id": locator.attempt_id().to_string(),
        }));
    }
    json!({
        "pack_id": pack.pack_id().to_string(),
        "registration_id": pack.registration_id().to_string(),
        "artifact_set_digest": pack.artifact_set_digest().as_hex(),
        "joined_revision": pack.joined_revision(),
        "artifacts": artifacts,
    })
}
