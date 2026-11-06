//! Real network CAS for Pando pack and index artifacts. PostgreSQL publication
//! follows verified remote objects; local pack files are only a read cache.
use super::*;
use rootyard::storage::remote_objects::{ObjectKey, RemoteObjectStore};
use object_store::{CasPackManifest, ChunkPartReceipt, ObjectStoreGetReport,
    ObjectStorePutOptions, ObjectStorePutReport, ObjectStoreVerifyReport};
use sha2::{Digest, Sha256};
use std::process::Stdio;
use tokio::{fs::{self, File}, io::{AsyncReadExt, AsyncWriteExt}, time::{Duration, Instant}};

fn deadline() -> Instant { Instant::now() + Duration::from_secs(300) }
fn remote_store(config: &Config) -> Result<RemoteObjectStore> {
    RemoteObjectStore::from_env(config.root.join("remote-cas"))
}
fn key(repo: Uuid, namespace: &str, digest: &str) -> Result<ObjectKey> {
    ObjectKey::new(repo, namespace, digest)
}
fn local_paths(config: &Config, repo: Uuid, pack_id: Uuid) -> (PathBuf, PathBuf) {
    let base = config.root.join("objects").join(repo.to_string()).join(pack_id.to_string());
    (base.with_extension("pack"), base.with_extension("idx"))
}

async fn scan(path: &Path, chunk_size: usize) -> Result<(String, u64, Vec<ChunkPartReceipt>)> {
    ensure!((4096..=8 * 1024 * 1024).contains(&chunk_size),
        "remote pack chunk size must be 4 KiB through 8 MiB");
    let mut source = File::open(path).await?;
    let mut whole = Sha256::new();
    let mut chunks = Vec::new();
    let mut buf = vec![0u8; chunk_size];
    let mut offset = 0u64;
    loop {
        let mut used = 0;
        while used < buf.len() {
            let n = source.read(&mut buf[used..]).await?;
            if n == 0 { break; }
            used += n;
        }
        if used == 0 { break; }
        ensure!(chunks.len() < 10_000, "remote pack has too many chunks");
        whole.update(&buf[..used]);
        let at = usize::try_from(offset).context("pack offset exceeds address space")?;
        chunks.push(ChunkPartReceipt { part_number: chunks.len() + 1,
            offset: at, size_bytes: used, sha256: hex::encode(Sha256::digest(&buf[..used])) });
        offset = offset.checked_add(used as u64).context("pack length overflow")?;
        if used < buf.len() { break; }
    }
    ensure!(offset == source.metadata().await?.len(), "pack changed while scanning");
    Ok((hex::encode(whole.finalize()), offset, chunks))
}

async fn pack_object_count(config: &Config, pack: &Path) -> Result<usize> {
    let mut file = File::open(pack).await?;
    let mut header = [0u8; 12];
    file.read_exact(&mut header).await?;
    ensure!(&header[..4] == b"PACK" && u32::from_be_bytes(header[4..8].try_into()?) == 2,
        "unsupported Git pack header");
    let count = u32::from_be_bytes(header[8..12].try_into()?) as usize;
    ensure!(count <= delta::MAX_OBJECTS, "Git pack object count exceeds limit");
    let status = tokio::time::timeout(Duration::from_secs(120),
        tokio::process::Command::new(&config.git)
            .env_clear().env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["index-pack", "--verify"]).arg(pack)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .kill_on_drop(true).status()).await??;
    ensure!(status.success(), "Git pack/index verification failed");
    Ok(count)
}

pub(super) async fn put(config: &Config, repo: Uuid, pack_id: Uuid,
    opts: &ObjectStorePutOptions) -> Result<ObjectStorePutReport> {
    ensure!(opts.fail_after_chunks.is_none() && opts.corrupt_chunk_part.is_none(),
        "local multipart fault flags do not apply to network S3");
    ensure!(opts.bucket == std::env::var("ROOTYARD_OBJECT_STORE_BUCKET")?,
        "Pando bucket differs from configured object-store bucket");
    let (pack, idx) = local_paths(config, repo, pack_id);
    let object_count = pack_object_count(config, &pack).await?;
    let (pack_sha256, pack_bytes, pack_chunks) = scan(&pack, opts.chunk_size).await?;
    let (idx_sha256, idx_bytes, idx_chunks) = scan(&idx, opts.chunk_size).await?;
    if let Some(expected) = &opts.expected_pack_sha256 {
        ensure!(expected == &pack_sha256, "expected pack SHA-256 mismatch");
    }
    if let Some(expected) = opts.expected_pack_bytes {
        ensure!(expected == pack_bytes, "expected pack byte length mismatch");
    }
    let store = remote_store(config)?;
    let pack_key = key(repo, "pando-pack", &pack_sha256)?;
    let idx_key = key(repo, "pando-index", &idx_sha256)?;
    store.put_file(&pack_key, &pack, pack_bytes, deadline()).await?;
    store.put_file(&idx_key, &idx, idx_bytes, deadline()).await?;
    let mut manifest = CasPackManifest {
        schema: object_store::MANIFEST_SCHEMA.into(), bucket: opts.bucket.clone(),
        backend: object_store::BACKEND_KIND.into(), repo, pack_id,
        pack_key: pack_key.path(), idx_key: idx_key.path(),
        manifest_key: object_store::manifest_key(repo, pack_id),
        pack_sha256: pack_sha256.clone(), idx_sha256: idx_sha256.clone(),
        pack_bytes, idx_bytes, object_count, chunk_size: opts.chunk_size,
        pack_chunks, idx_chunks, manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&manifest)?));
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    ensure!(bytes.len() <= 2 * 1024 * 1024, "Pando manifest exceeds limit");
    let manifest_digest = hex::encode(Sha256::digest(&bytes));
    let manifest_key = key(repo, "pando-manifest", &manifest_digest)?;
    let temp = config.root.join(format!(".pando-manifest-{}", Uuid::new_v4()));
    let publication = async {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temp).await?;
        file.write_all(&bytes).await?;
        file.sync_all().await?;
        store.put_file(&manifest_key, &temp, bytes.len() as u64, deadline()).await?;
        let client = config.db().await?;
        let value = serde_json::to_value(&manifest)?;
        client.execute(
            "INSERT INTO pando_lab.object_store_manifests(repo,pack_id,bucket,pack_key,idx_key,manifest_key,pack_sha256,idx_sha256,pack_bytes,idx_bytes,object_count,chunk_size,chunk_count,manifest_json) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(repo,pack_id) DO NOTHING",
            &[&repo,&pack_id,&opts.bucket,&manifest.pack_key,&manifest.idx_key,&manifest_key.path(),
                &pack_sha256,&idx_sha256,&(pack_bytes as i64),&(idx_bytes as i64),
                &(object_count as i64),&(opts.chunk_size as i64),&(manifest.pack_chunks.len() as i64),&value]).await?;
        let row = client.query_one("SELECT manifest_json FROM pando_lab.object_store_manifests WHERE repo=$1 AND pack_id=$2",
            &[&repo,&pack_id]).await?;
        ensure!(row.get::<_, serde_json::Value>(0) == value,
            "immutable Pando manifest collision");
        Ok::<(), anyhow::Error>(())
    }.await;
    let _ = fs::remove_file(&temp).await;
    publication?;
    Ok(ObjectStorePutReport { repo, pack_id, bucket: opts.bucket.clone(),
        // The legacy report field describes local multipart attempts. S3 owns
        // its upload IDs internally, so nil is the explicit not-applicable value.
        backend: "s3-compatible-cas".into(), upload_id: Uuid::nil(),
        pack_key: pack_key.path(), idx_key: idx_key.path(), manifest_key: manifest_key.path(),
        bucket_pack_path: pack_key.path(), bucket_idx_path: idx_key.path(),
        manifest_path: manifest_key.path(), pack_sha256, idx_sha256,
        pack_bytes, idx_bytes, object_count, chunk_size: opts.chunk_size,
        chunk_count: manifest.pack_chunks.len(),
        total_chunks_uploaded: manifest.pack_chunks.len() + manifest.idx_chunks.len(),
        immutable_mode: "remote-cas".into(), status: "published".into() })
}

pub(super) async fn get(config: &Config, repo: Uuid, pack_id: Uuid) -> Result<ObjectStoreGetReport> {
    let client = config.db().await?;
    let row = client.query_one("SELECT manifest_json,manifest_key FROM pando_lab.object_store_manifests WHERE repo=$1 AND pack_id=$2",
        &[&repo,&pack_id]).await?;
    let manifest: CasPackManifest = serde_json::from_value(row.get(0))?;
    let mut unsigned = manifest.clone();
    unsigned.manifest_sha256.clear();
    ensure!(manifest.schema == object_store::MANIFEST_SCHEMA && manifest.repo == repo
        && manifest.pack_id == pack_id && manifest.backend == object_store::BACKEND_KIND
        && manifest.manifest_sha256 == hex::encode(Sha256::digest(serde_json::to_vec(&unsigned)?)),
        "Pando remote manifest identity or digest mismatch");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let manifest_digest = hex::encode(Sha256::digest(&manifest_bytes));
    let manifest_key = key(repo, "pando-manifest", &manifest_digest)?;
    ensure!(row.get::<_, String>(1) == manifest_key.path(), "Pando remote manifest key mismatch");
    let store = remote_store(config)?;
    let temp = config.root.join(format!(".pando-verify-{}", Uuid::new_v4()));
    let verified = async {
        store.get_to_file(&manifest_key, &temp, manifest_bytes.len() as u64, deadline()).await?;
        ensure!(fs::read(&temp).await? == manifest_bytes,
            "remote Pando manifest differs from database");
        Ok::<(), anyhow::Error>(())
    }.await;
    let _ = fs::remove_file(&temp).await;
    verified?;
    let (pack, idx) = local_paths(config, repo, pack_id);
    let pack_key = key(repo, "pando-pack", &manifest.pack_sha256)?;
    let idx_key = key(repo, "pando-index", &manifest.idx_sha256)?;
    ensure!(manifest.pack_key == pack_key.path() && manifest.idx_key == idx_key.path(),
        "Pando remote artifact key mismatch");
    let cache_hit = pack.is_file() && idx.is_file() &&
        scan(&pack, manifest.chunk_size).await.ok().is_some_and(|x| x.0 == manifest.pack_sha256 && x.1 == manifest.pack_bytes) &&
        scan(&idx, manifest.chunk_size).await.ok().is_some_and(|x| x.0 == manifest.idx_sha256 && x.1 == manifest.idx_bytes);
    if !cache_hit {
        store.get_to_file(&pack_key, &pack, manifest.pack_bytes, deadline()).await?;
        store.get_to_file(&idx_key, &idx, manifest.idx_bytes, deadline()).await?;
    }
    ensure!(pack_object_count(config, &pack).await? == manifest.object_count,
        "remote Pando pack object count mismatch");
    Ok(ObjectStoreGetReport { repo, pack_id, bucket: manifest.bucket,
        pack_sha256: manifest.pack_sha256, idx_sha256: manifest.idx_sha256,
        pack_bytes: manifest.pack_bytes, idx_bytes: manifest.idx_bytes,
        cache_hit, rehydrated_from_object_store: !cache_hit,
        local_pack_path: pack.to_string_lossy().into_owned(),
        local_idx_path: idx.to_string_lossy().into_owned(), verified: true })
}

pub(super) async fn verify(config: &Config, repo: Uuid) -> Result<ObjectStoreVerifyReport> {
    let client = config.db().await?;
    let rows = client.query("SELECT pack_id FROM pando_lab.object_store_manifests WHERE repo=$1",
        &[&repo]).await?;
    let mut result = ObjectStoreVerifyReport { repo,
        bucket: std::env::var("ROOTYARD_OBJECT_STORE_BUCKET")?,
        manifests_checked: 0, packs_verified: 0,
        total_pack_bytes: 0, total_idx_bytes: 0,
        orphan_staging_cleaned: 0, verified: true };
    for row in rows {
        let report = get(config, repo, row.get(0)).await?;
        result.manifests_checked += 1;
        result.packs_verified += 1;
        result.total_pack_bytes += report.pack_bytes;
        result.total_idx_bytes += report.idx_bytes;
    }
    Ok(result)
}
