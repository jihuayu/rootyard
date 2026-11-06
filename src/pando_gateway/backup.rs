//! Offline Pando backup closure. Caller owns a consistent PostgreSQL snapshot,
//! volume flock and global migration barrier; this code opens no new DB lease.
use super::pack_store::{ArtifactReceipt, PackManifest};
use crate::storage::remote_objects::{ObjectKey, RemoteObjectStore};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, os::unix::fs::DirBuilderExt, path::Path};
use tokio::{fs::{self, File}, io::AsyncWriteExt, time::Instant};
use tokio_postgres::GenericClient;
use uuid::Uuid;

const MAX_PACKS: usize = 256;
const MAX_REFS: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PandoBackupManifest {
    pub version: u32,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub storage_generation: i64,
    pub ref_generation: i64,
    pub object_format: String,
    pub refs: BTreeMap<String, String>,
    pub packs: Vec<PackManifest>,
}

async fn inventory<C: GenericClient + Sync>(client: &C, repo_id: Uuid) -> Result<PandoBackupManifest> {
    let level: String = client.query_one("SHOW transaction_isolation",&[]).await?.get(0);
    ensure!(matches!(level.as_str(), "repeatable read" | "serializable"),
        "Pando backup requires a repeatable-read caller transaction");
    // A bare Client in autocommit mode can report repeatable-read as its
    // default yet use a different snapshot for every query. Force an XID and
    // require the same transaction at the end of enumeration.
    let transaction_id: String = client.query_one("SELECT txid_current()::text",&[]).await?.get(0);
    let row = client.query_one("SELECT r.owner_id,r.storage_backend,r.storage_generation,r.object_format, \
        s.state,s.ref_generation,s.pack_ids FROM repositories r \
        JOIN pando_repository_states s ON s.repository_id=r.id AND s.tenant_id=r.owner_id \
        WHERE r.id=$1 AND s.storage_generation=r.storage_generation",
        &[&repo_id]).await?;
    ensure!(row.get::<_,&str>("storage_backend") == "pando" &&
        row.get::<_,&str>("state") == "serving", "Pando backup requires a serving PG snapshot");
    let tenant_id: Uuid = row.get("owner_id");
    let pack_ids: Vec<Uuid> = row.get("pack_ids");
    ensure!(!pack_ids.is_empty() && pack_ids.len() <= MAX_PACKS,
        "Pando pack closure exceeds bound");
    let mut packs = Vec::with_capacity(pack_ids.len());
    for id in pack_ids {
        let record = client.query_one("SELECT tenant_id,storage_generation,object_format,manifest \
            FROM pando_pack_manifests WHERE repository_id=$1 AND id=$2",
            &[&repo_id,&id]).await?;
        let manifest: PackManifest = serde_json::from_value(record.get("manifest"))?;
        ensure!(manifest.version == 1 && manifest.id == id && manifest.repository_id == repo_id &&
            manifest.tenant_id == tenant_id && record.get::<_,Uuid>("tenant_id") == tenant_id &&
            manifest.storage_generation == record.get::<_,i64>("storage_generation") &&
            manifest.object_format == row.get::<_,String>("object_format") &&
            manifest.object_format == record.get::<_,String>("object_format"),
            "Pando pack manifest differs from PostgreSQL row");
        packs.push(manifest);
    }
    let records = client.query("SELECT ref_name,oid FROM pando_refs WHERE repository_id=$1 ORDER BY ref_name",
        &[&repo_id]).await?;
    ensure!(records.len() <= MAX_REFS, "Pando ref closure exceeds bound");
    let mut refs = BTreeMap::new();
    for record in records { refs.insert(record.get(0), record.get(1)); }
    let after_id: String = client.query_one("SELECT txid_current()::text",&[]).await?.get(0);
    ensure!(transaction_id == after_id,
        "Pando backup caller changed PostgreSQL snapshots during enumeration");
    Ok(PandoBackupManifest { version: 1, repository_id: repo_id, tenant_id,
        storage_generation: row.get("storage_generation"),
        ref_generation: row.get("ref_generation"), object_format: row.get("object_format"),
        refs, packs })
}

fn keys(tenant_id: Uuid, artifact: &ArtifactReceipt) -> Result<[ObjectKey;2]> {
    ensure!(artifact.envelope.ciphertext_sha256 == artifact.ciphertext_sha256 &&
        artifact.envelope.ciphertext_bytes == artifact.ciphertext_bytes &&
        artifact.envelope.plaintext_sha256 == artifact.plaintext_sha256 &&
        artifact.envelope.plaintext_bytes == artifact.plaintext_bytes &&
        artifact.envelope.provider == "vault-transit", "invalid Pando encrypted artifact");
    Ok([ObjectKey::new(tenant_id,"pando-cipher",&artifact.ciphertext_sha256)?,
        ObjectKey::new(tenant_id,"pando-envelope",&artifact.envelope_sha256)?])
}

async fn copy_artifact(remote: &RemoteObjectStore, root: &Path, tenant_id: Uuid,
    artifact: &ArtifactReceipt, deadline: Instant, upload: bool) -> Result<()> {
    let [cipher,envelope] = keys(tenant_id,artifact)?;
    for (key,size) in [(&cipher,artifact.ciphertext_bytes),(&envelope,artifact.envelope_bytes)] {
        let path = root.join(key.path());
        if upload {
            ensure!(fs::symlink_metadata(&path).await?.is_file(), "backup object is not a regular file");
            remote.put_file(key,&path,size,deadline).await?;
        } else {
            remote.get_to_file(key,&path,size,deadline).await?;
        }
    }
    let envelope_path = root.join(envelope.path());
    let bytes = fs::read(envelope_path).await?;
    ensure!(hex::encode(Sha256::digest(&bytes)) == artifact.envelope_sha256 &&
        serde_json::from_slice::<serde_json::Value>(&bytes)? == serde_json::to_value(&artifact.envelope)?,
        "Pando backup envelope differs from PostgreSQL manifest");
    Ok(())
}

/// Copy exact committed encrypted bytes from remote storage. The caller must
/// pass its existing REPEATABLE READ/SHARE-all-tables backup transaction.
pub async fn export_closure<C: GenericClient + Sync>(client: &C,
    remote: &RemoteObjectStore, repo_id: Uuid, destination: &Path,
    deadline: Instant) -> Result<PandoBackupManifest> {
    let manifest = Box::pin(inventory(client,repo_id)).await?;
    std::fs::DirBuilder::new().mode(0o700).create(destination)?;
    let result = async {
        for pack in &manifest.packs {
            Box::pin(copy_artifact(remote,destination,manifest.tenant_id,&pack.pack,deadline,false)).await?;
            Box::pin(copy_artifact(remote,destination,manifest.tenant_id,&pack.index,deadline,false)).await?;
        }
        let bytes = serde_json::to_vec(&manifest)?;
        let temp = destination.join(".manifest.tmp");
        let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp).await?;
        file.write_all(&bytes).await?;
        file.sync_all().await?;
        fs::rename(temp,destination.join("manifest.json")).await?;
        File::open(destination).await?.sync_all().await?;
        Ok::<(),anyhow::Error>(())
    }.await;
    if result.is_err() { let _ = fs::remove_dir_all(destination).await; }
    result?;
    Ok(manifest)
}

/// Restore remote bytes from an offline backup before any Pando serving
/// transition. PostgreSQL rows must already be restored in the caller's tx.
pub async fn import_closure<C: GenericClient + Sync>(client: &C,
    remote: &RemoteObjectStore, repo_id: Uuid, source: &Path,
    deadline: Instant) -> Result<PandoBackupManifest> {
    let expected: PandoBackupManifest = serde_json::from_slice(&fs::read(source.join("manifest.json")).await?)?;
    let actual = Box::pin(inventory(client,repo_id)).await?;
    ensure!(serde_json::to_value(&expected)? == serde_json::to_value(&actual)?,
        "Pando restore manifest differs from restored PostgreSQL snapshot");
    for pack in &actual.packs {
        Box::pin(copy_artifact(remote,source,actual.tenant_id,&pack.pack,deadline,true)).await?;
        Box::pin(copy_artifact(remote,source,actual.tenant_id,&pack.index,deadline,true)).await?;
    }
    Ok(actual)
}
