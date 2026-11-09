//! Shared marker/read primitives for the roots+decisions backup drill.
//!
//! Seed and verify mode build the *same* marker shape from typed read paths so
//! the Python harness can compare them field by field. No credential, token or
//! `token_digest` is ever placed in a marker: decision rows are represented by
//! the canonical table digests only (see [`super::rows`]).
use anyhow::{Context, Result, anyhow};
use deadpool_postgres::Pool;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::CoreGateVersion;
use rootyard::ref_store::core::decision_commit::ProtocolRepoRealm;
use rootyard::ref_store::core::pack_commit::PackArtifactRole;
use rootyard::ref_store::core::retention_root::RootReadView;
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::time::{Duration as StdDuration, Instant as StdInstant};
use uuid::Uuid;

use super::db::{self, Db, deadline};
use super::pack;
use super::roots;
use super::rows;

const IO_SECONDS: u64 = 120;

pub const MARKER: &str = "ROOTYARD-REF-STORE-ROOTS-DECISIONS-FIXTURE-METADATA";
pub const MANIFEST_KIND: &str = "rootyard/ref-store-core-roots-decisions-backup-fixture";
pub const CANCELLED_REASON: &str = "drill cancel before decision install";

pub struct Fixture {
    pub output: PathBuf,
    pub seed: Option<PathBuf>,
    pub git: PathBuf,
    pub format: rootyard::ref_store::GitObjectFormat,
}

impl Fixture {
    pub fn from_env() -> Self {
        let format = match std::env::var("ROOTYARD_ROOTS_DECISIONS_FIXTURE_FORMAT") {
            Ok(value) => rootyard::ref_store::GitObjectFormat::parse(&value)
                .unwrap_or_else(|error| panic!("ROOTYARD_ROOTS_DECISIONS_FIXTURE_FORMAT is invalid: {error}")),
            Err(_) => rootyard::ref_store::GitObjectFormat::Sha1,
        };
        Self {
            output: PathBuf::from(required("ROOTYARD_ROOTS_DECISIONS_FIXTURE_OUTPUT")),
            seed: std::env::var("ROOTYARD_ROOTS_DECISIONS_FIXTURE_SEED").ok().map(PathBuf::from),
            git: git_binary(),
            format,
        }
    }
}

pub fn required(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => panic!(
            "{name} is required: this fixture only runs under the owning roots/decisions backup drill, \
             never from a routine test command"
        ),
    }
}

pub fn git_binary() -> PathBuf {
    let path = match std::env::var("ROOTYARD_TEST_GIT") {
        Ok(value) => PathBuf::from(value),
        Err(_) => PathBuf::from("/usr/bin/git"),
    };
    assert!(path.is_absolute(), "ROOTYARD_TEST_GIT must be an absolute path");
    assert!(path.is_file(), "the configured absolute git binary does not exist");
    path
}

pub fn std_deadline() -> StdInstant {
    StdInstant::now() + StdDuration::from_secs(IO_SECONDS)
}

pub fn hex_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

pub fn digest_of(value: &Value) -> String {
    hex_of(value.to_string().as_bytes())
}

fn role_name(role: PackArtifactRole) -> String {
    format!("{role:?}").to_ascii_lowercase()
}

/// Real branch update through the public plan constructors.
pub fn branch_update(
    format: rootyard::ref_store::GitObjectFormat,
    name: &str,
    old: Option<&str>,
    new: Option<&str>,
) -> Result<rootyard::ref_store::RefUpdate> {
    use rootyard::ref_store::{GitOid, RefName, RefPrecondition, RefTarget, RefUpdate};
    let precondition = match old {
        Some(oid) => RefPrecondition::Present(GitOid::parse(format, oid)?),
        None => RefPrecondition::Absent,
    };
    let target = match new {
        Some(oid) => RefTarget::Oid(GitOid::parse(format, oid)?),
        None => RefTarget::Delete,
    };
    Ok(RefUpdate::new(RefName::branch(name)?, precondition, target))
}

/// Independent read-only remote GET of every retained pack/idx locator: the
/// fixture hashes the S3 originals itself instead of trusting the adapter.
pub async fn readback(store: &BlobStore, view: &RootReadView) -> Result<(String, u64, u64)> {
    let work = tempfile::tempdir()?;
    let mut pairs = 0u64;
    let mut total = 0u64;
    let mut hashes = Vec::new();
    for pack in view.packs() {
        for role in [PackArtifactRole::Pack, PackArtifactRole::Idx] {
            let artifact = pack.artifact(role);
            let locator = artifact.locator().blob_locator()?;
            let destination = work.path().join(format!("readback-{}-{}", artifact.slot(), Uuid::new_v4()));
            store.get_to_file(&locator, &destination, std_deadline()).await?;
            let bytes = std::fs::read(&destination)?;
            let sha = hex_of(&bytes);
            if sha != artifact.verified_sha256().as_str() || bytes.len() as u64 != artifact.verified_length() {
                return Err(anyhow!("independent S3 read-back differs from the retained artifact locator"));
            }
            hashes.push(format!("{}:{}", role_name(role), sha));
            total += bytes.len() as u64;
            std::fs::remove_file(&destination)?;
        }
        pairs += 1;
    }
    hashes.sort();
    Ok((digest_of(&json!(hashes)), pairs, total))
}

pub struct RootScenario {
    pub label: &'static str,
    pub root_id: Uuid,
    pub operation_id: Uuid,
    pub prepare_request_id: Uuid,
    pub register_request_id: Option<Uuid>,
    pub release_request_id: Option<Uuid>,
    pub release_digest: Option<String>,
    pub register_digest: String,
    pub state: &'static str,
}

/// Typed read of the retained root rows (get + historical receipts + package
/// locators). Used identically by seed and verify.
pub async fn roots_json(
    pool: &Pool,
    store: &BlobStore,
    git: &Path,
    repo: Uuid,
    tenant: Uuid,
    gate: &CoreGateVersion,
    scenarios: &[RootScenario],
) -> Result<Value> {
    use rootyard::ref_store::core::retention_root::{PgRetentionRoots, RootRef};
    let adapter = PgRetentionRoots::new(store.clone(), git.to_path_buf())
        .map_err(|error| anyhow!("retention roots adapter rejected the Blob/Git configuration: {error:?}"))?;
    let scope = roots::scope(repo, tenant, gate)?;
    let mut entries = Vec::new();
    for scenario in scenarios {
        let record = adapter
            .get(pool, RootRef::new(repo, scenario.root_id, 1)?, deadline())
            .await
            .map_err(|error| anyhow!("retained root get refused for {}: {error:?}", scenario.label))?;
        let mut receipts = Map::new();
        for (label, request_id, required) in [
            ("register", scenario.register_request_id, scenario.label != "tombstone"),
            ("release", scenario.release_request_id, false),
        ] {
            let Some(request_id) = request_id else { continue };
            let found = adapter
                .query_receipt(pool, roots::receipt_query(scope, request_id)?, deadline())
                .await
                .map_err(|error| anyhow!("historical root receipt refused for {}: {error:?}", scenario.label))?;
            let Some(receipt) = found else {
                if required {
                    return Err(anyhow!("historical root receipt {label} is missing for {}", scenario.label));
                }
                continue;
            };
            receipts.insert(
                label.to_owned(),
                json!({
                    "action": receipt.action().as_str(),
                    "state": receipt.state(),
                    "generation": receipt.generation(),
                    "request_digest": receipt.request_digest().as_hex(),
                    "created_at_unix_micros": receipt.created_at_unix_micros(),
                    "replayed": receipt.replayed(),
                    "body_digest": digest_of(receipt.body()),
                }),
            );
        }
        let entry = match &record {
            Some(record) => json!({
                "label": scenario.label,
                "root_id": scenario.root_id.to_string(),
                "operation_id": scenario.operation_id.to_string(),
                "prepare_request_id": scenario.prepare_request_id.to_string(),
                "register_request_id": scenario.register_request_id.map(|id| id.to_string()),
                "release_request_id": scenario.release_request_id.map(|id| id.to_string()),
                "register_digest": record.register_digest_hex(),
                "expected_register_digest": scenario.register_digest,
                "state": record.state(),
                "generation": record.generation(),
                "binding_digest": record.binding_digest_hex(),
                "refs_digest": record.refs_digest_hex(),
                "head_ref": record.head_ref(),
                "head_oid": record.head_oid_hex(),
                "ref_count": record.ref_count(),
                "oid_count": record.oid_count(),
                "pack_count": record.pack_count(),
                "pack_set_digest": record.pack_set_digest_hex(),
                "roots_revision": record.roots_revision(),
                "packs": record.packs().iter().map(rows::pack_identity).collect::<Vec<_>>(),
                "receipts": Value::Object(receipts),
            }),
            None => json!({
                "label": scenario.label,
                "root_id": scenario.root_id.to_string(),
                "operation_id": scenario.operation_id.to_string(),
                "prepare_request_id": scenario.prepare_request_id.to_string(),
                "register_request_id": scenario.register_request_id.map(|id| id.to_string()),
                "release_request_id": scenario.release_request_id.map(|id| id.to_string()),
                "register_digest": scenario.register_digest,
                "expected_register_digest": scenario.register_digest,
                "state": scenario.state,
                "record": Value::Null,
                "receipts": Value::Object(receipts),
            }),
        };
        entries.push(entry);
    }
    Ok(Value::Array(entries))
}

/// Typed materialization of the active root and an independent S3 read-back.
pub async fn materialized_json(
    pool: &Pool,
    store: &BlobStore,
    git: &Path,
    repo: Uuid,
    tenant: Uuid,
    gate: &CoreGateVersion,
    root_id: Uuid,
) -> Result<(Value, RootReadView)> {
    use rootyard::ref_store::core::retention_root::PgRetentionRoots;
    let adapter = PgRetentionRoots::new(store.clone(), git.to_path_buf())
        .map_err(|error| anyhow!("retention roots adapter rejected the Blob/Git configuration: {error:?}"))?;
    let request = roots::read_request(repo, tenant, gate, root_id)?;
    let view = adapter
        .materialize(pool, request, deadline())
        .await
        .map_err(|error| anyhow!("active root materialization refused: {error:?}"))?;
    let (readback_digest, readback_pairs, readback_bytes) = readback(store, &view).await?;
    let value = json!({
        "root_id": root_id.to_string(),
        "verified_pairs": view.verified_pairs(),
        "verified_bytes": view.verified_bytes(),
        "binding_digest": view.binding_digest_hex(),
        "register_digest": view.register_digest_hex(),
        "source_read_digest": view.source_read_digest_hex(),
        "head_ref": view.head_ref(),
        "head_oid": view.head_oid_hex(),
        "pack_count": view.packs().len(),
        "ref_count": view.refs().len(),
        "oid_count": view.root_oids().len(),
        "readback_digest": readback_digest,
        "readback_pairs": readback_pairs,
        "readback_bytes": readback_bytes,
    });
    Ok((value, view))
}

pub fn protocol_json(protocol: &ProtocolRepoRealm) -> Value {
    json!({
        "repository_id": protocol.repository_id().to_string(),
        "tenant_id": protocol.tenant_id().to_string(),
        "object_format": protocol.object_format().as_str(),
        "history_incarnation": protocol.history_incarnation().to_string(),
        "authority_epoch": protocol.authority_epoch(),
        "group_epoch": protocol.group_epoch(),
        "decision_required": protocol.decision_required(),
        "roots_revision": protocol.roots_revision(),
    })
}

pub fn usage_json(usage: Option<db::Usage>) -> Value {
    match usage {
        Some(usage) => json!({
            "roots": usage.roots,
            "root_oid_refs": usage.root_oid_refs,
            "pack_bindings": usage.pack_bindings,
            "receipts": usage.receipts,
            "logical_bytes": usage.logical_bytes,
        }),
        None => Value::Null,
    }
}

pub async fn root_counts_json(pool: &Pool, repo: Uuid) -> Result<Value> {
    let counts = db::root_counts(pool, repo).await?;
    Ok(json!({
        "heads": counts.heads,
        "captures": counts.captures,
        "refs": counts.refs,
        "oids": counts.oids,
        "packs": counts.packs,
        "tombstones": counts.tombstones,
        "receipts": counts.receipts,
    }))
}

/// Add the read-only capture (all-table digests, per-family counts, quota and
/// typed root reads) and write the marker. Seed and verify use exactly this
/// function so both markers are directly comparable.
pub async fn finish_marker(
    db: &Db,
    store: &BlobStore,
    fixture: &Fixture,
    base: Value,
    repo: Uuid,
    tenant: Uuid,
    scenarios: &[RootScenario],
) -> Result<Value> {
    let gate = db::gate_version(&db.pool, repo, tenant).await?;
    let protocol = super::decisions::read_protocol(&db.pool, repo)
        .await?
        .ok_or_else(|| anyhow!("fixture protocol realm missing after publication"))?;
    let mut marker = base;
    let roots_value = roots_json(&db.pool, store, &fixture.git, repo, tenant, &gate, scenarios).await?;
    let (materialized, _view) =
        materialized_json(&db.pool, store, &fixture.git, repo, tenant, &gate, scenarios[0].root_id).await?;
    let object = marker.as_object_mut().ok_or_else(|| anyhow!("marker is not an object"))?;
    object.insert("protocol".to_owned(), protocol_json(&protocol));
    object.insert(
        "gate".to_owned(),
        json!({
            "revision": gate.revision(),
            "digest": gate.digest().as_hex(),
            "object_format": gate.object_format().as_str(),
            "history_incarnation": gate.history_incarnation().to_string(),
            "authority_epoch": gate.authority_epoch(),
            "group_epoch": gate.group_epoch(),
        }),
    );
    object.insert("roots".to_owned(), roots_value);
    object.insert("materialized".to_owned(), materialized);
    object.insert("root_counts".to_owned(), root_counts_json(&db.pool, repo).await?);
    object.insert(
        "quota".to_owned(),
        json!({
            "repo": usage_json(db::repo_usage(&db.pool, repo).await?),
            "tenant": usage_json(db::tenant_usage(&db.pool, tenant).await?),
            "roots_revision": db::roots_revision(&db.pool, repo).await?,
        }),
    );
    object.insert("tables".to_owned(), rows::table_digests(&db.pool).await?);
    object.insert("root_family_counts".to_owned(), rows::family_counts(&db.pool, &rows::ROOT_TABLES).await?);
    object.insert("decision_family_counts".to_owned(), rows::family_counts(&db.pool, &rows::DECISION_TABLES).await?);
    object.insert("claims".to_owned(), claims());
    write_marker(&fixture.output, &marker)?;
    Ok(marker)
}

pub fn claims() -> Value {
    json!({
        "restored_blob_bytes_backed_up": false,
        "physical_blob_backup_closure": false,
        "complete_git_read_snapshot_claimed": false,
        "decision_consumed_via_authorized_facade": true,
        "decision_consume_claimed": true,
        "decision_or_receipt_fabricated_by_sql": false,
        "sql_faked_ack_or_proof_or_registration": false,
        "held_remote_objects_deleted": false,
        "s3_originals_external_and_unchanged": true,
        "read_only_replay_charges_quota": false,
        "marker_contains_credential_or_token_digest": false,
    })
}

pub fn write_marker(output: &Path, marker: &Value) -> Result<()> {
    let text = serde_json::to_string_pretty(marker)?;
    std::fs::write(output, text.as_bytes()).with_context(|| format!("cannot write fixture marker {output:?}"))?;
    println!("{MARKER} {}", serde_json::to_string(marker)?);
    Ok(())
}

/// Rebuild the scenario list from the seed marker for verify mode.
pub fn scenarios_from(marker: &Value) -> Result<Vec<RootScenario>> {
    let mut out = Vec::new();
    let roots =
        marker.get("roots").and_then(Value::as_array).ok_or_else(|| anyhow!("seed marker has no roots array"))?;
    for entry in roots {
        let label = match entry.get("label").and_then(Value::as_str) {
            Some("active") => "active",
            Some("released") => "released",
            Some("tombstone") => "tombstone",
            other => return Err(anyhow!("seed marker has an unknown root label {other:?}")),
        };
        out.push(RootScenario {
            label,
            root_id: uuid_field(entry, "root_id")?,
            operation_id: uuid_field(entry, "operation_id")?,
            prepare_request_id: uuid_field(entry, "prepare_request_id")?,
            register_request_id: match entry.get("register_request_id") {
                Some(Value::Null) | None => None,
                Some(_) => Some(uuid_field(entry, "register_request_id")?),
            },
            release_request_id: match entry.get("release_request_id") {
                Some(Value::Null) | None => None,
                Some(_) => Some(uuid_field(entry, "release_request_id")?),
            },
            release_digest: None,
            register_digest: text_field(entry, "register_digest")
                .or_else(|_| text_field(entry, "expected_register_digest"))?,
            state: match label {
                "active" => "active",
                _ => "released",
            },
        });
    }
    Ok(out)
}

pub fn text_field(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("marker field {key} is not a string"))
}

pub fn uuid_field(value: &Value, key: &str) -> Result<Uuid> {
    Uuid::parse_str(&text_field(value, key)?).map_err(|error| anyhow!("marker field {key} is not a uuid: {error}"))
}

pub fn pack_count(verified: &pack::Verified) -> usize {
    verified.new_packs.len()
}
