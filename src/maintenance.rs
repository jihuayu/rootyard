//! Offline, explicit acknowledgment of a GitFS audit gap. Never assigns a
//! successful outcome to an unknown push and never replays that push.
use crate::{config::Config, git_http, journal, storage::Storage};
use anyhow::{Context, Result, ensure};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, os::unix::fs::MetadataExt};
use tokio_postgres::GenericClient;
use uuid::Uuid;

const MAX_BYTES: usize = 64 * 1024 * 1024;
const MAX_REFS: usize = 100_000;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeRef {
    pub name: String,
    pub oid: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeSnapshot {
    pub head: Value,
    pub refs: Vec<NativeRef>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InspectedOperation {
    pub id: Uuid,
    pub operation: Value,
    pub operation_digest: String,
    pub journal_evidence: Option<Value>,
    pub journal_digest: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Inspection {
    pub version: u32,
    pub repository_id: Uuid,
    pub volume_id: Uuid,
    pub volume_device: u64,
    pub volume_inode: u64,
    pub storage_generation: i64,
    pub incident_revision: i64,
    pub state: String,
    pub recovery_reason: Option<String>,
    pub native: NativeSnapshot,
    pub operations: Vec<InspectedOperation>,
    pub journal_sequence: i64,
}
pub fn digest(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}
impl Inspection {
    pub fn fingerprint(&self) -> Result<String> {
        let value = serde_json::to_value(self)?;
        ensure!(serde_json::to_vec(&value)?.len() <= MAX_BYTES, "inspection exceeds 64 MiB limit");
        digest(&value)
    }
    pub fn summary(&self) -> Result<Value> {
        Ok(
            serde_json::json!({"version":self.version,"repository_id":self.repository_id,"volume_id":self.volume_id,"storage_generation":self.storage_generation,"incident_revision":self.incident_revision,"state":self.state,"recovery_reason":self.recovery_reason,"head":self.native.head,"refs":self.native.refs,"unknown_operations":self.operations.iter().map(|o|serde_json::json!({"id":o.id,"operation_digest":o.operation_digest,"journal_digest":o.journal_digest})).collect::<Vec<_>>(),"fingerprint":self.fingerprint()?,"fsck":"passed","effect":"acknowledge audit gap; preserve unknown history; establish a new observed baseline"}),
        )
    }
}
async fn git(storage: &Storage, config: &Config, repo: Uuid, args: &[&str]) -> Result<Vec<u8>> {
    let mut command = storage.git(config);
    command.arg("--git-dir").arg(storage.verify_path(repo)?).args(args);
    git_http::collect_git_output(command, 16 * 1024 * 1024, config.git_timeout).await
}
fn no_locks_or_links(root: &std::path::Path) -> Result<()> {
    let mut todo = vec![root.to_path_buf()];
    let mut count = 0;
    while let Some(path) = todo.pop() {
        count += 1;
        ensure!(count <= 1_000_000, "repository inventory exceeds limit");
        let meta = std::fs::symlink_metadata(&path)?;
        ensure!(!meta.file_type().is_symlink(), "repository contains an unsupported symbolic link");
        ensure!(meta.is_dir() || meta.is_file(), "repository contains a special file");
        ensure!(
            !path.file_name().is_some_and(|n| n.as_encoded_bytes().ends_with(b".lock")),
            "repository has a Git lock file; investigate without deleting active locks"
        );
        if meta.is_dir() {
            for entry in std::fs::read_dir(path)? {
                todo.push(entry?.path());
            }
        }
    }
    Ok(())
}
async fn native_snapshot(storage: &Storage, config: &Config, repo: Uuid) -> Result<NativeSnapshot> {
    no_locks_or_links(&storage.verify_path(repo)?)?;
    let identity = git(storage, config, repo, &["config", "--get", "rootyard.repositoryId"]).await?;
    ensure!(std::str::from_utf8(&identity)?.trim() == repo.to_string(), "repository identity mismatch");
    git(storage, config, repo, &["fsck", "--full", "--no-dangling"]).await.context("native integrity check failed")?;
    let raw = git(
        storage,
        config,
        repo,
        &["for-each-ref", "--sort=refname", "--format=%(refname)%00%(objectname)%00%(symref)"],
    )
    .await?;
    let mut refs = Vec::new();
    for line in std::str::from_utf8(&raw)?.lines() {
        let fields: Vec<_> = line.split('\0').collect();
        ensure!(
            fields.len() == 3 && fields[0].starts_with("refs/") && fields[0].len() <= 1024 && fields[2].is_empty(),
            "unsupported native reference"
        );
        ensure!(
            matches!(fields[1].len(), 40 | 64) && fields[1].bytes().all(|b| b.is_ascii_hexdigit()),
            "unsupported object ID"
        );
        refs.push(NativeRef { name: fields[0].into(), oid: fields[1].into() });
        ensure!(refs.len() <= MAX_REFS, "too many native refs");
    }
    ensure!(refs.windows(2).all(|pair| pair[0].name < pair[1].name), "duplicate or unsorted native refs");
    let head_bytes = std::fs::read(storage.verify_path(repo)?.join("HEAD"))?;
    ensure!(head_bytes.len() <= 8192, "HEAD exceeds limit");
    let text = std::str::from_utf8(&head_bytes)?.trim_end_matches('\n');
    let head = if let Some(target) = text.strip_prefix("ref: ") {
        ensure!(target.starts_with("refs/") && !target.contains(['\r', '\n', '\0']), "invalid symbolic HEAD");
        let oid = refs.iter().find(|r| r.name == target).map(|r| r.oid.clone());
        serde_json::json!({"kind":if oid.is_some(){"symbolic"}else{"unborn"},"target":target,"oid":oid})
    } else {
        ensure!(matches!(text.len(), 40 | 64) && text.bytes().all(|b| b.is_ascii_hexdigit()), "invalid detached HEAD");
        serde_json::json!({"kind":"detached","oid":text})
    };
    Ok(NativeSnapshot { head, refs })
}
async fn inspect_locked<C: GenericClient + Sync>(
    config: &Config,
    storage: &Storage,
    client: &C,
    repo: Uuid,
) -> Result<Inspection> {
    let row = client
        .query_one(
            "SELECT state,recovery_reason,storage_generation,incident_revision FROM repositories WHERE id=$1",
            &[&repo],
        )
        .await?;
    let row_generation: i64 = row.get(2);
    let native = native_snapshot(storage, config, repo).await?;
    let rows=client.query("SELECT to_jsonb(o) FROM git_operations o WHERE repository_id=$1 AND outcome='unknown' AND NOT EXISTS(SELECT 1 FROM operation_resolutions r WHERE r.operation_id=o.id) ORDER BY storage_generation,sequence,id LIMIT 65",&[&repo]).await?;
    ensure!(rows.len() <= 64, "too many unknown operations for one resolution");
    let mut pending: HashMap<Uuid, journal::Operation> = HashMap::new();
    for operation in journal::pending(&storage.root, repo)? {
        ensure!(pending.insert(operation.id, operation).is_none(), "duplicate pending journal identity");
    }
    let mut operations = Vec::new();
    for row in rows {
        let operation: Value = row.get(0);
        let id: Uuid = serde_json::from_value(operation["id"].clone())?;
        ensure!(
            operation["storage_generation"].as_i64() == Some(row_generation),
            "unknown operation generation does not match repository; investigate mixed storage history"
        );
        let (journal_evidence, journal_digest) = if let Some(op) = pending.remove(&id) {
            ensure!(journal::is_finished(&op)?, "unfinished journal; run offline reconcile before inspection");
            let metadata = serde_json::to_value(&op)?;
            for key in ["id", "repository_id", "actor_id", "actor_name", "token_id", "sequence", "storage_generation"] {
                ensure!(operation[key] == metadata[key], "journal operation metadata mismatch");
            }
            (Some(journal::evidence(&op)?), Some(journal::evidence_digest(&op)?))
        } else {
            (None, None)
        };
        operations.push(InspectedOperation {
            id,
            operation_digest: digest(&operation)?,
            operation,
            journal_evidence,
            journal_digest,
        });
    }
    ensure!(pending.is_empty(), "unsettled journal not imported as unknown; run offline reconcile first");
    let journal_sequence = journal::sequence(&storage.root, repo)?;
    let maximum: i64 = client
        .query_one("SELECT COALESCE(max(sequence),0) FROM git_operations WHERE repository_id=$1", &[&repo])
        .await?
        .get(0);
    ensure!(
        journal_sequence >= maximum,
        "journal sequence missing or behind PostgreSQL history; restore matching storage before resolution"
    );
    let meta = storage.root.metadata()?;
    let result = Inspection {
        version: 1,
        repository_id: repo,
        volume_id: storage.volume_id,
        volume_device: meta.dev(),
        volume_inode: meta.ino(),
        storage_generation: row.get(2),
        incident_revision: row.get(3),
        state: row.get(0),
        recovery_reason: row.get(1),
        native,
        operations,
        journal_sequence,
    };
    result.fingerprint()?;
    Ok(result)
}
pub async fn inspect(config: &Config, pool: &Pool, repo: Uuid) -> Result<Value> {
    let storage = Storage::open(config)?;
    let client = pool.get().await?;
    inspect_locked(config, &storage, &**client, repo).await?.summary()
}

pub async fn resolve(
    config: &Config,
    pool: &Pool,
    repo: Uuid,
    expected_generation: i64,
    expected_fingerprint: &str,
    reason: &str,
) -> Result<Value> {
    ensure!(
        !reason.trim().is_empty() && reason.len() <= 4096 && !reason.contains('\0'),
        "reason must contain 1-4096 bytes and no NUL"
    );
    ensure!(
        expected_fingerprint.len() == 64 && expected_fingerprint.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid inspection fingerprint"
    );
    let storage = Storage::open(config)?;
    let mut client = pool.get().await?;
    // A lost commit acknowledgment can be retried without reclassifying history.
    if let Some(row)=client.query_opt("SELECT to_jsonb(r) FROM recovery_resolutions r WHERE repository_id=$1 AND old_generation=$2 AND inspected_fingerprint=$3",&[&repo,&expected_generation,&expected_fingerprint]).await? {
        let resolution:Value=row.get(0);
        ensure!(resolution["reason"]==reason,"resolution replay reason mismatch");
        ensure!(resolution["volume_id"]==storage.volume_id.to_string(),"resolution belongs to another storage volume");
        retire_resolved_journals(pool,&storage,repo).await?;
        return Ok(serde_json::json!({"already_applied":true,"resolution":resolution}));
    }
    let observed = inspect_locked(config, &storage, &**client, repo).await?;
    ensure!(
        observed.storage_generation == expected_generation && observed.fingerprint()? == expected_fingerprint,
        "inspection changed; inspect again before acknowledging an audit gap"
    );
    ensure!(
        observed.state == "recovering" && observed.recovery_reason.as_deref() == Some("push_outcome_unknown"),
        "only the unknown-push incident can be resolved here"
    );
    ensure!(!observed.operations.is_empty(), "no unresolved unknown operations");
    let tx = client.transaction().await?;
    tx.query_one("SELECT id FROM repositories WHERE id=$1 FOR UPDATE", &[&repo]).await?;
    // Re-read filesystem plus every SQL operation after the common repository
    // fence. Workers use FOR SHARE before their delivery/projection effect.
    let locked = inspect_locked(config, &storage, &*tx, repo).await?;
    ensure!(locked.fingerprint()? == expected_fingerprint, "inspection changed while acquiring repository fence");
    let new_generation = expected_generation.checked_add(1).context("generation exhausted")?;
    let id = Uuid::new_v4();
    let snapshot = serde_json::to_value(&locked.native)?;
    tx.execute("INSERT INTO recovery_resolutions(id,repository_id,old_generation,new_generation,incident_revision,inspected_fingerprint,volume_id,snapshot,reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",&[&id,&repo,&expected_generation,&new_generation,&locked.incident_revision,&expected_fingerprint,&storage.volume_id,&snapshot,&reason]).await?;
    for op in &locked.operations {
        tx.execute("INSERT INTO operation_resolutions(operation_id,repository_id,resolution_id,operation_digest,journal_digest,journal_evidence) VALUES($1,$2,$3,$4,$5,$6)",&[&op.id,&repo,&id,&op.operation_digest,&op.journal_digest,&op.journal_evidence]).await?;
    }
    // Candidate events from an unknown operation are not successes. Complete
    // their queues explicitly as discarded, preserving original event evidence.
    tx.execute("UPDATE event_deliveries d SET state='delivered',effect='discarded_unknown',lease_owner=NULL,lease_until=NULL,lease_generation=lease_generation+1,delivered_at=clock_timestamp(),last_error_code=NULL FROM outbox_events e JOIN operation_resolutions covered ON covered.operation_id=e.operation_id WHERE d.event_id=e.event_id AND covered.resolution_id=$1",&[&id]).await?;
    tx.execute(
        "UPDATE repositories SET state='ready',recovery_reason=NULL,storage_generation=$2 WHERE id=$1",
        &[&repo, &new_generation],
    )
    .await?;
    tx.execute("DELETE FROM repository_ref_projection WHERE repository_id=$1", &[&repo]).await?;
    for item in &locked.native.refs {
        tx.execute("INSERT INTO repository_ref_projection(repository_id,ref_name,oid,deleted,storage_generation,operation_sequence,transaction_sequence,event_id,source_kind,resolution_id) VALUES($1,$2,$3,false,$4,0,0,NULL,'recovery_snapshot',$5)",&[&repo,&item.name,&item.oid,&new_generation,&id]).await?;
    }

    tx.commit().await?;
    retire_resolved_journals(pool, &storage, repo).await?;
    Ok(
        serde_json::json!({"already_applied":false,"resolution_id":id,"repository_id":repo,"old_generation":expected_generation,"new_generation":new_generation,"audit_gap_acknowledged":true,"unknown_history_preserved":true}),
    )
}

/// Idempotent post-commit cleanup. Changed evidence creates a new incident;
/// resolution never authorizes discarding a different or later journal.
pub async fn retire_resolved_journals(pool: &Pool, storage: &Storage, repo: Uuid) -> Result<()> {
    for op in journal::pending(&storage.root, repo)? {
        let _ = retire_if_resolved(pool, storage, &op).await?;
    }
    Ok(())
}
pub async fn retire_if_resolved(pool: &Pool, storage: &Storage, op: &journal::Operation) -> Result<bool> {
    let client = pool.get().await?;
    let row=client.query_opt("SELECT r.journal_digest,r.operation_digest,to_jsonb(o),resolution.volume_id FROM operation_resolutions r JOIN git_operations o ON o.id=r.operation_id JOIN recovery_resolutions resolution ON resolution.id=r.resolution_id WHERE r.operation_id=$1 AND r.repository_id=$2",&[&op.id,&op.repository_id]).await?;
    let Some(row) = row else {
        return Ok(false);
    };
    ensure!(row.get::<_, Uuid>(3) == storage.volume_id, "resolution belongs to another storage volume");
    let expected: Option<String> = row.get(0);
    ensure!(
        expected.as_deref() == Some(&journal::evidence_digest(op)?),
        "resolved journal changed; preserve evidence and investigate"
    );
    let operation: Value = row.get(2);
    ensure!(digest(&operation)? == row.get::<_, String>(1), "resolved operation history changed");
    journal::retire(op)?;
    Ok(true)
}
