//! Verified encrypted pack publication. Local files are staging/cache only;
//! the PostgreSQL manifest is the sole authority for a ready pack set.
use crate::{git_http, storage::{encrypted_objects::{self, Envelope, VaultTransit}, remote_objects::{ObjectKey, RemoteObjectStore}}};
use anyhow::{Context, Result, ensure};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::{Path, PathBuf}, process::Stdio, time::Duration};
use tokio::{fs, process::Command, time::Instant};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactReceipt {
    pub plaintext_sha256: String,
    pub plaintext_bytes: u64,
    pub ciphertext_sha256: String,
    pub ciphertext_bytes: u64,
    pub envelope_sha256: String,
    pub envelope_bytes: u64,
    pub envelope: Envelope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackManifest {
    pub version: u32,
    pub id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub storage_generation: i64,
    pub object_format: String,
    pub pack: ArtifactReceipt,
    pub index: ArtifactReceipt,
}

pub struct PackStore {
    remote: RemoteObjectStore,
    kms: VaultTransit,
    work_root: PathBuf,
    git: PathBuf,
}

struct WorkDir(PathBuf);
impl Drop for WorkDir {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

impl PackStore {
    pub fn from_env(work_root: PathBuf, git: PathBuf) -> Result<Self> {
        // Production Pando cannot silently fall back to node-local CAS.
        ensure!(std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_some(),
            "production Pando requires a remote object-store endpoint");
        ensure!(git.is_absolute(), "production Pando Git path must be absolute");
        std::fs::create_dir_all(&work_root)?;
        let remote = RemoteObjectStore::from_env(work_root.join("unused-local-store"))?;
        let kms = VaultTransit::from_env()?;
        Ok(Self { remote, kms, work_root, git })
    }

    fn work_dir(&self) -> Result<WorkDir> {
        let path = self.work_root.join(format!(".pando-pack-{}", Uuid::new_v4()));
        std::fs::create_dir(&path)?;
        Ok(WorkDir(path))
    }

    fn key(tenant_id: Uuid, namespace: &str, sha256: &str) -> Result<ObjectKey> {
        ObjectKey::new(tenant_id, namespace, sha256)
    }

    async fn verify_git_pack(&self, pack: &Path, deadline: Instant) -> Result<()> {
        let mut cmd = Command::new(&self.git);
        cmd.env_clear().env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .args(["index-pack", "--verify"]).arg(pack)
            .stdin(Stdio::null());
        let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
        ensure!(!timeout.is_zero(), "Pando pack verification deadline elapsed");
        git_http::collect_git_output(cmd, 4096, timeout).await?;
        Ok(())
    }

    async fn publish_artifact(&self, work: &Path, label: &str, source: &Path,
        tenant_id: Uuid, deadline: Instant) -> Result<ArtifactReceipt> {
        let ciphertext = work.join(format!("{label}.cipher"));
        let envelopes = work.join(format!("{label}-envelopes"));
        let envelope = encrypted_objects::encrypt_file(&self.kms, source, &ciphertext,
            &envelopes, deadline).await?;
        let envelope_path = envelopes.join(format!("envelope-{:020}.json", envelope.generation));
        let envelope_bytes = fs::read(&envelope_path).await?;
        ensure!(envelope_bytes.len() <= 64 * 1024, "Pando envelope exceeds limit");
        let envelope_sha256 = hex::encode(Sha256::digest(&envelope_bytes));
        let cipher_key = Self::key(tenant_id, "pando-cipher", &envelope.ciphertext_sha256)?;
        let envelope_key = Self::key(tenant_id, "pando-envelope", &envelope_sha256)?;
        self.remote.put_file(&cipher_key, &ciphertext, envelope.ciphertext_bytes, deadline).await?;
        self.remote.put_file(&envelope_key, &envelope_path, envelope_bytes.len() as u64, deadline).await?;
        Ok(ArtifactReceipt {
            plaintext_sha256: envelope.plaintext_sha256.clone(),
            plaintext_bytes: envelope.plaintext_bytes,
            ciphertext_sha256: envelope.ciphertext_sha256.clone(),
            ciphertext_bytes: envelope.ciphertext_bytes,
            envelope_sha256, envelope_bytes: envelope_bytes.len() as u64, envelope,
        })
    }

    /// Publish a verified pack/index pair. The database INSERT occurs only
    /// after both remote ciphertexts and envelopes pass read-back verification.
    pub async fn publish(&self, pool: &Pool, repository_id: Uuid, tenant_id: Uuid,
        storage_generation: i64, object_format: &str, pack: &Path, index: &Path,
        deadline: Instant) -> Result<PackManifest> {
        ensure!(matches!(object_format, "sha1" | "sha256") && storage_generation > 0,
            "invalid Pando repository identity");
        ensure!(pack.extension().is_some_and(|v| v == "pack") &&
            index == pack.with_extension("idx"), "Pando pack and index paths differ");
        self.verify_git_pack(pack, deadline).await?;
        let work = self.work_dir()?;
        let pack_receipt = self.publish_artifact(&work.0, "pack", pack, tenant_id, deadline).await?;
        let index_receipt = self.publish_artifact(&work.0, "index", index, tenant_id, deadline).await?;
        let manifest = PackManifest { version: 1, id: Uuid::new_v4(), repository_id,
            tenant_id, storage_generation, object_format: object_format.into(),
            pack: pack_receipt, index: index_receipt };
        let client = pool.get().await?;
        let value = serde_json::to_value(&manifest)?;
        let rows = client.execute(
            "INSERT INTO pando_pack_manifests(id,repository_id,tenant_id,storage_generation,object_format,manifest) \
             SELECT $1,r.id,r.owner_id,r.storage_generation,r.object_format,$2 \
             FROM repositories r WHERE r.id=$3 AND r.owner_id=$4 \
             AND r.storage_generation=$5 AND r.object_format=$6 AND r.state='ready'",
            &[&manifest.id, &value, &repository_id, &tenant_id, &storage_generation, &object_format]).await?;
        ensure!(rows == 1, "Pando pack publication lost repository generation or ownership");
        Ok(manifest)
    }

    async fn recover_artifact(&self, work: &Path, label: &str, tenant_id: Uuid,
        receipt: &ArtifactReceipt, deadline: Instant) -> Result<PathBuf> {
        let cipher_key = Self::key(tenant_id, "pando-cipher", &receipt.ciphertext_sha256)?;
        let envelope_key = Self::key(tenant_id, "pando-envelope", &receipt.envelope_sha256)?;
        let ciphertext = work.join(format!("{label}.cipher"));
        let envelope_file = work.join(format!("{label}.json"));
        self.remote.get_to_file(&cipher_key, &ciphertext, receipt.ciphertext_bytes, deadline).await?;
        self.remote.get_to_file(&envelope_key, &envelope_file, receipt.envelope_bytes, deadline).await?;
        let envelope_bytes = fs::read(&envelope_file).await?;
        ensure!(hex::encode(Sha256::digest(&envelope_bytes)) == receipt.envelope_sha256,
            "Pando remote envelope digest mismatch");
        let envelope: Envelope = serde_json::from_slice(&envelope_bytes)?;
        ensure!(serde_json::to_value(&envelope)? == serde_json::to_value(&receipt.envelope)? &&
            envelope.ciphertext_sha256 == receipt.ciphertext_sha256 &&
            envelope.ciphertext_bytes == receipt.ciphertext_bytes &&
            envelope.plaintext_sha256 == receipt.plaintext_sha256 &&
            envelope.plaintext_bytes == receipt.plaintext_bytes,
            "Pando envelope differs from PostgreSQL manifest");
        let envelopes = work.join(format!("{label}-envelopes"));
        fs::create_dir(&envelopes).await?;
        fs::copy(&envelope_file, envelopes.join(format!("envelope-{:020}.json", envelope.generation))).await?;
        fs::write(envelopes.join("CURRENT"), format!("{}\n", envelope.generation)).await?;
        let output = work.join(if label == "pack" { "output.pack" } else { "output.idx" });
        encrypted_objects::decrypt_file(&self.kms, &ciphertext, &envelopes,
            Some(envelope.generation), &output, deadline).await?;
        Ok(output)
    }

    /// Recover exclusively from PostgreSQL + remote storage into a fresh
    /// destination. Partial output is removed on failure; no local cache is an
    /// authority for refs or pack existence.
    pub async fn recover(&self, pool: &Pool, repository_id: Uuid, pack_id: Uuid,
        destination: &Path, deadline: Instant) -> Result<PackManifest> {
        let client = pool.get().await?;
        let row = client.query_one("SELECT tenant_id,storage_generation,object_format,manifest \
            FROM pando_pack_manifests WHERE repository_id=$1 AND id=$2",
            &[&repository_id, &pack_id]).await?;
        let manifest: PackManifest = serde_json::from_value(row.get("manifest"))?;
        ensure!(manifest.version == 1 && manifest.id == pack_id &&
            manifest.repository_id == repository_id && manifest.tenant_id == row.get::<_, Uuid>("tenant_id") &&
            manifest.storage_generation == row.get::<_, i64>("storage_generation") &&
            manifest.object_format == row.get::<_, String>("object_format"),
            "Pando manifest identity mismatch");
        let work = self.work_dir()?;
        let pack = self.recover_artifact(&work.0, "pack", manifest.tenant_id, &manifest.pack, deadline).await?;
        let index = self.recover_artifact(&work.0, "index", manifest.tenant_id, &manifest.index, deadline).await?;
        self.verify_git_pack(&pack, deadline).await?;
        fs::create_dir_all(destination).await?;
        let target_pack = destination.join(format!("pack-{}.pack", pack_id));
        let target_index = destination.join(format!("pack-{}.idx", pack_id));
        ensure!(!target_pack.exists() && !target_index.exists(), "Pando cache target already exists");
        fs::rename(&pack, &target_pack).await?;
        if let Err(error) = fs::rename(&index, &target_index).await {
            let _ = fs::remove_file(&target_pack).await;
            return Err(error).context("Pando index cache publication failed");
        }
        Ok(manifest)
    }
}
