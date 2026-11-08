//! Verified encrypted pack publication. Local files are staging/cache only;
//! the PostgreSQL manifest is the sole authority for a ready pack set.
use super::retention::{self, Slot};
use crate::{
    baseline_metrics::{Phase, timed_result},
    git_http,
    storage::{
        encrypted_objects::{self, Envelope, VaultTransit},
        remote_objects::RemoteObjectStore,
    },
};
use anyhow::{Context, Result, bail, ensure};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
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
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl PackStore {
    /// Disposable local cache of verified plaintext packs. It is never an
    /// authority: every cache hit is copied into a snapshot that is checked by
    /// `git fsck` against the PostgreSQL manifest and ref closure.
    pub fn cache_dir(storage_root: &Path, repository_id: Uuid) -> PathBuf {
        storage_root.join("pando-cache").join(repository_id.to_string())
    }

    fn prepare_cache_dir(cache_dir: &Path) -> Result<()> {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(cache_dir)?;
        let meta = std::fs::symlink_metadata(cache_dir)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink() && meta.uid() == unsafe { libc::geteuid() },
            "Pando cache root is not a private owned directory"
        );
        std::fs::set_permissions(cache_dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn cache_paths(cache_dir: &Path, repository_id: Uuid, pack_id: Uuid) -> (PathBuf, PathBuf) {
        let _ = repository_id;
        (cache_dir.join(format!("pack-{pack_id}.pack")), cache_dir.join(format!("pack-{pack_id}.idx")))
    }

    fn link_or_copy(source: &Path, target: &Path) -> Result<()> {
        if target.exists() {
            std::fs::remove_file(target)?;
        }
        match std::fs::hard_link(source, target) {
            Ok(()) => Ok(()),
            Err(_) => std::fs::copy(source, target).map(|_| ()).map_err(Into::into),
        }
    }

    pub fn from_env(work_root: PathBuf, git: PathBuf) -> Result<Self> {
        // Production Pando cannot silently fall back to node-local CAS.
        ensure!(
            std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_some(),
            "production Pando requires a remote object-store endpoint"
        );
        ensure!(git.is_absolute(), "production Pando Git path must be absolute");
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&work_root)?;
        let meta = std::fs::symlink_metadata(&work_root)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink() && meta.uid() == unsafe { libc::geteuid() },
            "Pando scratch root is not a private owned directory"
        );
        std::fs::set_permissions(&work_root, std::fs::Permissions::from_mode(0o700))?;
        let remote = RemoteObjectStore::from_env(work_root.join("unused-local-store"))?;
        let kms = VaultTransit::from_env()?;
        Ok(Self { remote, kms, work_root, git })
    }

    fn work_dir(&self) -> Result<WorkDir> {
        let path = self.work_root.join(format!(".pando-pack-{}", Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(WorkDir(path))
    }

    async fn verify_git_pack(&self, pack: &Path, object_format: &str, deadline: Instant) -> Result<()> {
        ensure!(matches!(object_format, "sha1" | "sha256"), "invalid Pando object format");
        let work = self.work_dir()?;
        let verify_repo = work.0.join("verify.git");
        let format_arg = format!("--object-format={object_format}");
        let mut init = Command::new(&self.git);
        init.env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["init", "--bare", &format_arg])
            .arg(&verify_repo)
            .stdin(Stdio::null());
        let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
        ensure!(!timeout.is_zero(), "Pando pack verification deadline elapsed");
        git_http::collect_git_output(init, 4096, timeout).await?;
        let mut cmd = Command::new(&self.git);
        cmd.env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .arg("--git-dir")
            .arg(&verify_repo)
            .args(["index-pack", "--verify"])
            .arg(pack)
            .stdin(Stdio::null());
        let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
        ensure!(!timeout.is_zero(), "Pando pack verification deadline elapsed");
        git_http::collect_git_output(cmd, 4096, timeout).await?;
        Ok(())
    }

    async fn encrypt_artifact(
        &self,
        work: &Path,
        label: &str,
        source: &Path,
        deadline: Instant,
    ) -> Result<(ArtifactReceipt, PathBuf, PathBuf)> {
        let ciphertext = work.join(format!("{label}.cipher"));
        let envelopes = work.join(format!("{label}-envelopes"));
        let envelope = encrypted_objects::encrypt_file(&self.kms, source, &ciphertext, &envelopes, deadline).await?;
        let envelope_path = envelopes.join(format!("envelope-{:020}.json", envelope.generation));
        let envelope_bytes = fs::read(&envelope_path).await?;
        ensure!(envelope_bytes.len() <= 64 * 1024, "Pando envelope exceeds limit");
        let envelope_sha256 = hex::encode(Sha256::digest(&envelope_bytes));
        Ok((
            ArtifactReceipt {
                plaintext_sha256: envelope.plaintext_sha256.clone(),
                plaintext_bytes: envelope.plaintext_bytes,
                ciphertext_sha256: envelope.ciphertext_sha256.clone(),
                ciphertext_bytes: envelope.ciphertext_bytes,
                envelope_sha256,
                envelope_bytes: envelope_bytes.len() as u64,
                envelope,
            },
            ciphertext,
            envelope_path,
        ))
    }

    async fn insert_ready_manifest_in<C: tokio_postgres::GenericClient + Sync>(
        client: &C,
        manifest: &PackManifest,
    ) -> Result<()> {
        // FOR SHARE conflicts with generation-changing UPDATE's NO KEY UPDATE
        // lock. A concurrent cutover cannot commit between this recheck and
        // the ready manifest INSERT.
        let current = client
            .query_one(
                "SELECT owner_id,storage_generation,object_format,state             FROM repositories WHERE id=$1 FOR SHARE",
                &[&manifest.repository_id],
            )
            .await?;
        ensure!(
            current.get::<_, Uuid>("owner_id") == manifest.tenant_id
                && current.get::<_, i64>("storage_generation") == manifest.storage_generation
                && current.get::<_, &str>("object_format") == manifest.object_format
                && current.get::<_, &str>("state") == "ready",
            "Pando pack publication lost repository generation or ownership"
        );
        let value = serde_json::to_value(manifest)?;
        client
            .execute(
                "INSERT INTO pando_pack_manifests             (id,repository_id,tenant_id,storage_generation,object_format,manifest)             VALUES($1,$2,$3,$4,$5,$6)",
                &[
                    &manifest.id,
                    &manifest.repository_id,
                    &manifest.tenant_id,
                    &manifest.storage_generation,
                    &manifest.object_format,
                    &value,
                ],
            )
            .await?;
        Ok(())
    }

    async fn upload_slot(&self, slot: &Slot, source: &Path, size: u64, deadline: Instant) -> Result<()> {
        self.remote.put_file(slot.key(), source, size, deadline).await?;
        Ok(())
    }

    /// Publish a verified pack/index pair. Reservations are committed before
    /// bulk upload; the ready manifest, artifact activation and immutable
    /// retention links commit in one PostgreSQL transaction only after every
    /// remote object passed read-back verification.
    pub async fn publish(
        &self,
        pool: &Pool,
        repository_id: Uuid,
        tenant_id: Uuid,
        storage_generation: i64,
        object_format: &str,
        pack: &Path,
        index: &Path,
        deadline: Instant,
    ) -> Result<PackManifest> {
        ensure!(
            matches!(object_format, "sha1" | "sha256") && storage_generation > 0,
            "invalid Pando repository identity"
        );
        ensure!(
            pack.extension().is_some_and(|v| v == "pack") && index == pack.with_extension("idx"),
            "Pando pack and index paths differ"
        );
        self.verify_git_pack(pack, object_format, deadline).await?;
        let work = self.work_dir()?;
        let (pack_receipt, pack_ciphertext, pack_envelope) =
            Box::pin(self.encrypt_artifact(&work.0, "pack", pack, deadline)).await?;
        let (index_receipt, index_ciphertext, index_envelope) =
            Box::pin(self.encrypt_artifact(&work.0, "index", index, deadline)).await?;
        let manifest = PackManifest {
            version: 1,
            id: Uuid::new_v4(),
            repository_id,
            tenant_id,
            storage_generation,
            object_format: object_format.into(),
            pack: pack_receipt.clone(),
            index: index_receipt.clone(),
        };
        for _ in 0..3 {
            let (cipher_slot, pack_envelope_slot, index_cipher_slot, index_envelope_slot) = {
                let mut client = timed_result(Phase::PoolCheckout, pool.get()).await?;
                let tx = client.transaction().await?;
                let (cipher, envelope) = retention::reserve_pair(
                    &*tx,
                    tenant_id,
                    Some(manifest.id),
                    &pack_receipt.ciphertext_sha256,
                    &pack_receipt.envelope_sha256,
                )
                .await?;
                let (index_cipher, index_envelope) = retention::reserve_pair(
                    &*tx,
                    tenant_id,
                    Some(manifest.id),
                    &index_receipt.ciphertext_sha256,
                    &index_receipt.envelope_sha256,
                )
                .await?;
                tx.commit().await?;
                (cipher, envelope, index_cipher, index_envelope)
            };
            Box::pin(self.upload_slot(&cipher_slot, &pack_ciphertext, pack_receipt.ciphertext_bytes, deadline)).await?;
            Box::pin(self.upload_slot(&pack_envelope_slot, &pack_envelope, pack_receipt.envelope_bytes, deadline))
                .await?;
            Box::pin(self.upload_slot(&index_cipher_slot, &index_ciphertext, index_receipt.ciphertext_bytes, deadline))
                .await?;
            Box::pin(self.upload_slot(&index_envelope_slot, &index_envelope, index_receipt.envelope_bytes, deadline))
                .await?;
            let mut client = timed_result(Phase::PoolCheckout, pool.get()).await?;
            let tx = client.transaction().await?;
            let authority = retention::authority(&*tx).await?;
            let active = retention::activate(
                &*tx,
                tenant_id,
                retention::NAMESPACE_CIPHER,
                &pack_receipt.ciphertext_sha256,
                pack_receipt.ciphertext_bytes,
                &cipher_slot,
            )
            .await?
                && retention::activate(
                    &*tx,
                    tenant_id,
                    retention::NAMESPACE_ENVELOPE,
                    &pack_receipt.envelope_sha256,
                    pack_receipt.envelope_bytes,
                    &pack_envelope_slot,
                )
                .await?
                && retention::activate(
                    &*tx,
                    tenant_id,
                    retention::NAMESPACE_CIPHER,
                    &index_receipt.ciphertext_sha256,
                    index_receipt.ciphertext_bytes,
                    &index_cipher_slot,
                )
                .await?
                && retention::activate(
                    &*tx,
                    tenant_id,
                    retention::NAMESPACE_ENVELOPE,
                    &index_receipt.envelope_sha256,
                    index_receipt.envelope_bytes,
                    &index_envelope_slot,
                )
                .await?;
            if !active {
                continue;
            }
            // All four remote objects passed read-back verification and are
            // active: extend the pending-publication lease before the manifest
            // row is acknowledged. A publisher paused past the old lease must
            // still fail serving-CAS proof later rather than get a free pass.
            retention::renew_publication(&*tx, manifest.id).await?;
            Self::insert_ready_manifest_in(&*tx, &manifest).await?;
            retention::record_manifest(&*tx, &manifest, authority.id).await?;
            tx.commit().await?;
            return Ok(manifest);
        }
        bail!("Pando pack publication reservations were repeatedly superseded")
    }

    async fn recover_artifact(
        &self,
        work: &Path,
        label: &str,
        cipher_key: &crate::storage::remote_objects::ObjectKey,
        envelope_key: &crate::storage::remote_objects::ObjectKey,
        receipt: &ArtifactReceipt,
        deadline: Instant,
    ) -> Result<PathBuf> {
        let ciphertext = work.join(format!("{label}.cipher"));
        let envelope_file = work.join(format!("{label}.json"));
        self.remote.get_to_file(cipher_key, &ciphertext, receipt.ciphertext_bytes, deadline).await?;
        self.remote.get_to_file(envelope_key, &envelope_file, receipt.envelope_bytes, deadline).await?;
        let envelope_bytes = fs::read(&envelope_file).await?;
        ensure!(
            hex::encode(Sha256::digest(&envelope_bytes)) == receipt.envelope_sha256,
            "Pando remote envelope digest mismatch"
        );
        let envelope: Envelope = serde_json::from_slice(&envelope_bytes)?;
        ensure!(
            serde_json::to_value(&envelope)? == serde_json::to_value(&receipt.envelope)?
                && envelope.ciphertext_sha256 == receipt.ciphertext_sha256
                && envelope.ciphertext_bytes == receipt.ciphertext_bytes
                && envelope.plaintext_sha256 == receipt.plaintext_sha256
                && envelope.plaintext_bytes == receipt.plaintext_bytes,
            "Pando envelope differs from PostgreSQL manifest"
        );
        let envelopes = work.join(format!("{label}-envelopes"));
        fs::create_dir(&envelopes).await?;
        fs::copy(&envelope_file, envelopes.join(format!("envelope-{:020}.json", envelope.generation))).await?;
        fs::write(envelopes.join("CURRENT"), format!("{}\n", envelope.generation)).await?;
        let output = work.join(if label == "pack" { "output.pack" } else { "output.idx" });
        encrypted_objects::decrypt_file(
            &self.kms,
            &ciphertext,
            &envelopes,
            Some(envelope.generation),
            &output,
            deadline,
        )
        .await?;
        Ok(output)
    }

    async fn load_manifest(&self, pool: &Pool, repository_id: Uuid, pack_id: Uuid) -> Result<PackManifest> {
        let client = timed_result(Phase::PoolCheckout, pool.get()).await?;
        let row = client
            .query_one(
                "SELECT tenant_id,storage_generation,object_format,manifest             FROM pando_pack_manifests WHERE repository_id=$1 AND id=$2",
                &[&repository_id, &pack_id],
            )
            .await?;
        let manifest: PackManifest = serde_json::from_value(row.get("manifest"))?;
        ensure!(
            manifest.version == 1
                && manifest.id == pack_id
                && manifest.repository_id == repository_id
                && manifest.tenant_id == row.get::<_, Uuid>("tenant_id")
                && manifest.storage_generation == row.get::<_, i64>("storage_generation")
                && manifest.object_format == row.get::<_, String>("object_format"),
            "Pando manifest identity mismatch"
        );
        Ok(manifest)
    }

    fn file_sha256(path: &Path) -> Result<String> {
        let meta = std::fs::symlink_metadata(path)?;
        ensure!(meta.is_file() && !meta.file_type().is_symlink(), "Pando cache entry is not a regular file");
        let mut file = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    fn cache_pair_valid(pack: &Path, index: &Path, manifest: &PackManifest) -> Result<bool> {
        let pack_meta = match std::fs::symlink_metadata(pack) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        let index_meta = match std::fs::symlink_metadata(index) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if !pack_meta.is_file()
            || pack_meta.file_type().is_symlink()
            || !index_meta.is_file()
            || index_meta.file_type().is_symlink()
            || pack_meta.len() != manifest.pack.plaintext_bytes
            || index_meta.len() != manifest.index.plaintext_bytes
        {
            return Ok(false);
        }
        Ok(Self::file_sha256(pack)? == manifest.pack.plaintext_sha256
            && Self::file_sha256(index)? == manifest.index.plaintext_sha256)
    }

    /// Populate the disposable local cache for one committed pack. Cache
    /// publication is atomic per file; concurrent readers either observe a
    /// complete pair or fall back to an exact remote recovery.
    pub async fn recover_to_cache(
        &self,
        pool: &Pool,
        repository_id: Uuid,
        pack_id: Uuid,
        cache_dir: &Path,
        deadline: Instant,
    ) -> Result<PackManifest> {
        Self::prepare_cache_dir(cache_dir)?;
        let manifest = self.load_manifest(pool, repository_id, pack_id).await?;
        let (target_pack, target_index) = Self::cache_paths(cache_dir, repository_id, pack_id);
        if Self::cache_pair_valid(&target_pack, &target_index, &manifest)? {
            return Ok(manifest);
        }
        let _ = std::fs::remove_file(&target_pack);
        let _ = std::fs::remove_file(&target_index);
        let temporary = WorkDir(cache_dir.join(format!(".tmp-{}", Uuid::new_v4())));
        Box::pin(self.recover(pool, repository_id, pack_id, &temporary.0, deadline)).await?;
        std::fs::rename(temporary.0.join(format!("pack-{pack_id}.pack")), &target_pack)?;
        std::fs::rename(temporary.0.join(format!("pack-{pack_id}.idx")), &target_index)?;
        ensure!(
            Self::cache_pair_valid(&target_pack, &target_index, &manifest)?,
            "Pando cache publication did not match the committed manifest"
        );
        Ok(manifest)
    }

    /// Recover a committed pack into a snapshot pack directory, preferring the
    /// disposable local cache. A cache miss or link failure falls back to an
    /// exact remote recovery so cache state can never make a valid read fail.
    pub async fn recover_cached(
        &self,
        pool: &Pool,
        repository_id: Uuid,
        pack_id: Uuid,
        destination: &Path,
        cache_dir: &Path,
        deadline: Instant,
    ) -> Result<PackManifest> {
        let manifest = Box::pin(self.recover_to_cache(pool, repository_id, pack_id, cache_dir, deadline)).await?;
        let (source_pack, source_index) = Self::cache_paths(cache_dir, repository_id, pack_id);
        let target_pack = destination.join(format!("pack-{pack_id}.pack"));
        let target_index = destination.join(format!("pack-{pack_id}.idx"));
        let linked = Self::link_or_copy(&source_pack, &target_pack)
            .and_then(|_| Self::link_or_copy(&source_index, &target_index));
        if linked.is_ok() && Self::cache_pair_valid(&target_pack, &target_index, &manifest)? {
            return Ok(manifest);
        }
        let _ = std::fs::remove_file(&target_pack);
        let _ = std::fs::remove_file(&target_index);
        Box::pin(self.recover(pool, repository_id, pack_id, destination, deadline)).await
    }

    /// Recover exclusively from PostgreSQL + remote storage into a fresh
    /// destination. Partial output is removed on failure; no local cache is an
    /// authority for refs or pack existence.
    pub async fn recover(
        &self,
        pool: &Pool,
        repository_id: Uuid,
        pack_id: Uuid,
        destination: &Path,
        deadline: Instant,
    ) -> Result<PackManifest> {
        let manifest = self.load_manifest(pool, repository_id, pack_id).await?;
        let (pack_cipher, pack_envelope, index_cipher, index_envelope) = {
            let client = timed_result(Phase::PoolCheckout, pool.get()).await?;
            let pack_cipher = retention::resolve_artifact(
                &**client,
                manifest.tenant_id,
                retention::NAMESPACE_CIPHER,
                &manifest.pack.ciphertext_sha256,
            )
            .await?;
            let pack_envelope = retention::resolve_artifact(
                &**client,
                manifest.tenant_id,
                retention::NAMESPACE_ENVELOPE,
                &manifest.pack.envelope_sha256,
            )
            .await?;
            let index_cipher = retention::resolve_artifact(
                &**client,
                manifest.tenant_id,
                retention::NAMESPACE_CIPHER,
                &manifest.index.ciphertext_sha256,
            )
            .await?;
            let index_envelope = retention::resolve_artifact(
                &**client,
                manifest.tenant_id,
                retention::NAMESPACE_ENVELOPE,
                &manifest.index.envelope_sha256,
            )
            .await?;
            (pack_cipher.key, pack_envelope.key, index_cipher.key, index_envelope.key)
        };
        let work = self.work_dir()?;
        let pack =
            Box::pin(self.recover_artifact(&work.0, "pack", &pack_cipher, &pack_envelope, &manifest.pack, deadline))
                .await?;
        let index = Box::pin(self.recover_artifact(
            &work.0,
            "index",
            &index_cipher,
            &index_envelope,
            &manifest.index,
            deadline,
        ))
        .await?;
        self.verify_git_pack(&pack, &manifest.object_format, deadline).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generation_update_fences_ready_manifest_insert() {
        let Ok(url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else {
            return;
        };
        let pool = crate::db::pool(&url).unwrap();
        crate::db::migrate(&pool).await.unwrap();
        let tenant = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let username = format!("pando{}", &tenant.simple().to_string()[..12]);
        let seed = pool.get().await.unwrap();
        seed.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&tenant, &username]).await.unwrap();
        seed.execute(
            "INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'fencetest','ready')",
            &[&repo, &tenant],
        )
        .await
        .unwrap();
        drop(seed);
        let envelope = Envelope {
            version: 1,
            generation: 1,
            object_id: Uuid::new_v4(),
            cipher: "AES-256-GCM-CHUNKED".into(),
            provider: "vault-transit".into(),
            key_name: "test".into(),
            wrapped_key: "test".into(),
            plaintext_sha256: "0".repeat(64),
            plaintext_bytes: 1,
            ciphertext_sha256: "1".repeat(64),
            ciphertext_bytes: 64,
            chunk_bytes: 65536,
        };
        let artifact = ArtifactReceipt {
            plaintext_sha256: envelope.plaintext_sha256.clone(),
            plaintext_bytes: 1,
            ciphertext_sha256: envelope.ciphertext_sha256.clone(),
            ciphertext_bytes: 64,
            envelope_sha256: "2".repeat(64),
            envelope_bytes: 128,
            envelope,
        };
        let manifest = PackManifest {
            version: 1,
            id: Uuid::new_v4(),
            repository_id: repo,
            tenant_id: tenant,
            storage_generation: 1,
            object_format: "sha1".into(),
            pack: artifact.clone(),
            index: artifact,
        };
        let mut blocker = pool.get().await.unwrap();
        let tx = blocker.transaction().await.unwrap();
        tx.execute("UPDATE repositories SET storage_generation=2 WHERE id=$1", &[&repo]).await.unwrap();
        let publishing_pool = pool.clone();
        let publishing = tokio::spawn(async move {
            let mut client = publishing_pool.get().await.unwrap();
            let tx = client.transaction().await.unwrap();
            match PackStore::insert_ready_manifest_in(&*tx, &manifest).await {
                Ok(()) => tx.commit().await.map_err(|error| anyhow::anyhow!(error)),
                Err(error) => Err(error),
            }
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!publishing.is_finished(), "manifest insert did not wait for generation writer");
        tx.commit().await.unwrap();
        assert!(publishing.await.unwrap().is_err(), "stale generation published a manifest");
        let count: i64 = pool
            .get()
            .await
            .unwrap()
            .query_one("SELECT count(*) FROM pando_pack_manifests WHERE repository_id=$1", &[&repo])
            .await
            .unwrap()
            .get(0);
        assert_eq!(count, 0);
    }
}
