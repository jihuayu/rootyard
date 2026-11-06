use super::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
};

pub const DEFAULT_BUCKET: &str = "pando-default";
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
pub const MANIFEST_SCHEMA: &str = "rootyard.pando.cas-pack-manifest.v1";
pub const BACKEND_KIND: &str = "s3-compatible-cas";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkPartReceipt {
    pub part_number: usize,
    pub offset: usize,
    pub size_bytes: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasPackManifest {
    pub schema: String,
    pub bucket: String,
    pub backend: String,
    pub repo: Uuid,
    pub pack_id: Uuid,
    pub pack_key: String,
    pub idx_key: String,
    pub manifest_key: String,
    pub pack_sha256: String,
    pub idx_sha256: String,
    pub pack_bytes: u64,
    pub idx_bytes: u64,
    pub object_count: usize,
    pub chunk_size: usize,
    pub pack_chunks: Vec<ChunkPartReceipt>,
    pub idx_chunks: Vec<ChunkPartReceipt>,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStorePutOptions {
    pub bucket: String,
    pub chunk_size: usize,
    pub fail_after_chunks: Option<usize>,
    pub corrupt_chunk_part: Option<usize>,
    pub expected_pack_sha256: Option<String>,
    pub expected_pack_bytes: Option<u64>,
}

impl Default for ObjectStorePutOptions {
    fn default() -> Self {
        Self {
            bucket: default_bucket(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            fail_after_chunks: None,
            corrupt_chunk_part: None,
            expected_pack_sha256: None,
            expected_pack_bytes: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStorePutReport {
    pub repo: Uuid,
    pub pack_id: Uuid,
    pub bucket: String,
    pub backend: String,
    pub upload_id: Uuid,
    pub pack_key: String,
    pub idx_key: String,
    pub manifest_key: String,
    pub bucket_pack_path: String,
    pub bucket_idx_path: String,
    pub manifest_path: String,
    pub pack_sha256: String,
    pub idx_sha256: String,
    pub pack_bytes: u64,
    pub idx_bytes: u64,
    pub object_count: usize,
    pub chunk_size: usize,
    pub chunk_count: usize,
    pub total_chunks_uploaded: usize,
    pub immutable_mode: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStoreGetReport {
    pub repo: Uuid,
    pub pack_id: Uuid,
    pub bucket: String,
    pub pack_sha256: String,
    pub idx_sha256: String,
    pub pack_bytes: u64,
    pub idx_bytes: u64,
    pub cache_hit: bool,
    pub rehydrated_from_object_store: bool,
    pub local_pack_path: String,
    pub local_idx_path: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStoreVerifyReport {
    pub repo: Uuid,
    pub bucket: String,
    pub manifests_checked: usize,
    pub packs_verified: usize,
    pub total_pack_bytes: u64,
    pub total_idx_bytes: u64,
    pub orphan_staging_cleaned: usize,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStoreStatusReport {
    pub repo: Uuid,
    pub bucket: String,
    pub backend: String,
    pub committed_manifests: usize,
    pub object_store_manifests: usize,
    pub local_cached_packs: usize,
    pub fully_replicated: bool,
    pub active_multipart_uploads: usize,
    pub packs: Vec<serde_json::Value>,
}

pub fn default_bucket() -> String {
    std::env::var("PANDO_OBJECT_STORE_BUCKET").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| DEFAULT_BUCKET.to_owned())
}
fn remote_enabled() -> bool { std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_some() }

pub(super) fn store_root(config: &Config) -> PathBuf {
    std::env::var("PANDO_OBJECT_STORE_ROOT").ok().filter(|s| !s.trim().is_empty()).map(PathBuf::from).unwrap_or_else(|| config.root.clone())
}

pub fn valid_bucket_name(bucket: &str) -> bool {
    !bucket.is_empty() && bucket.len() <= 128 && !bucket.starts_with('.') && !bucket.ends_with('.') && !bucket.contains("..")
        && bucket.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

pub fn pack_key(bucket: &str, repo: Uuid, pack_id: Uuid) -> String {
    format!("buckets/{bucket}/repos/{repo}/packs/{pack_id}.pack")
}
pub fn idx_key(bucket: &str, repo: Uuid, pack_id: Uuid) -> String {
    format!("buckets/{bucket}/repos/{repo}/packs/{pack_id}.idx")
}
pub fn manifest_key(repo: Uuid, pack_id: Uuid) -> String {
    format!("manifests/{repo}/{pack_id}.json")
}

fn stage_and_reassemble_multipart(
    root: &Path,
    upload_id: Uuid,
    payload: &[u8],
    expected_sha256: &str,
    expected_bytes: u64,
    opts: &ObjectStorePutOptions,
    chunks_uploaded: &mut usize,
) -> Result<(Vec<ChunkPartReceipt>, Vec<u8>)> {
    ensure!(opts.chunk_size >= 1 && opts.chunk_size <= LIMIT, "invalid chunk_size {}", opts.chunk_size);
    let staging_dir = root.join("multipart").join(upload_id.to_string());
    std::fs::create_dir_all(&staging_dir)?;
    let res = (|| -> Result<(Vec<ChunkPartReceipt>, Vec<u8>)> {
        let mut receipts = Vec::new();
        let slices: Vec<&[u8]> = if payload.is_empty() { vec![&[][..]] } else { payload.chunks(opts.chunk_size).collect() };
        let mut offset = 0usize;
        for (idx, chunk) in slices.iter().enumerate() {
            let part_number = idx + 1;
            if opts.fail_after_chunks.is_some_and(|lim| *chunks_uploaded >= lim) {
                bail!("fault injection: multipart upload {upload_id} aborted after {} chunks", *chunks_uploaded);
            }
            let expected_part_sha = delta::sha256_hex(chunk);
            let part_path = staging_dir.join(format!("part-{part_number}"));
            let mut f = OpenOptions::new().write(true).create_new(true).open(&part_path)?;
            f.write_all(chunk)?;
            f.sync_all()?;
            *chunks_uploaded += 1;
            if opts.corrupt_chunk_part == Some(part_number) {
                let mut tampered = std::fs::read(&part_path)?;
                if tampered.is_empty() { tampered.push(0xff); } else { tampered[0] ^= 0xff; }
                std::fs::write(&part_path, &tampered)?;
            }
            let staged = std::fs::read(&part_path)?;
            let actual_sha = delta::sha256_hex(&staged);
            ensure!(staged.len() == chunk.len() && actual_sha == expected_part_sha, "multipart chunk {part_number} digest or size mismatch");
            receipts.push(ChunkPartReceipt { part_number, offset, size_bytes: chunk.len(), sha256: actual_sha });
            offset += chunk.len();
        }
        let mut reassembled = Vec::with_capacity(payload.len());
        for r in &receipts {
            let part_bytes = std::fs::read(staging_dir.join(format!("part-{}", r.part_number)))?;
            ensure!(part_bytes.len() == r.size_bytes && delta::sha256_hex(&part_bytes) == r.sha256, "reassembly mismatch at part {}", r.part_number);
            reassembled.extend_from_slice(&part_bytes);
        }
        ensure!(reassembled.len() as u64 == expected_bytes && delta::sha256_hex(&reassembled) == expected_sha256, "complete object digest/size mismatch");
        Ok((receipts, reassembled))
    })();
    let _ = std::fs::remove_dir_all(&staging_dir);
    res
}

fn write_immutable_cas_file(target: &Path, data: &[u8], expected_sha256: &str) -> Result<()> {
    ensure!(delta::sha256_hex(data) == expected_sha256, "CAS payload digest mismatch");
    let parent = target.parent().context("missing CAS parent")?;
    std::fs::create_dir_all(parent)?;
    if target.exists() {
        let existing = std::fs::read(target)?;
        ensure!(existing.len() == data.len() && delta::sha256_hex(&existing) == expected_sha256, "immutable object store key collision on {}", target.display());
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o444))?;
        return Ok(());
    }
    let tmp = parent.join(format!(".tmp-{}", Uuid::new_v4()));
    let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    f.set_permissions(std::fs::Permissions::from_mode(0o444))?;
    drop(f);
    std::fs::rename(&tmp, target)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn write_atomic_local_cache_file(target: &Path, data: &[u8], expected_sha256: &str) -> Result<()> {
    let parent = target.parent().context("missing local cache parent")?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".cache-tmp-{}", Uuid::new_v4()));
    let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, target)?;
    ensure!(delta::sha256_hex(&std::fs::read(target)?) == expected_sha256, "local cache read-back mismatch");
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub fn put_pack_files(
    store_root_dir: &Path,
    local_objects_root: &Path,
    repo: Uuid,
    pack_id: Uuid,
    opts: &ObjectStorePutOptions,
) -> Result<(ObjectStorePutReport, CasPackManifest)> {
    ensure!(valid_bucket_name(&opts.bucket), "invalid bucket '{}'", opts.bucket);
    let local_dir = local_objects_root.join(repo.to_string());
    let pack_bytes = std::fs::read(local_dir.join(format!("{pack_id}.pack")))?;
    let idx_bytes = std::fs::read(local_dir.join(format!("{pack_id}.idx")))?;
    ensure!(pack_bytes.len() <= LIMIT && idx_bytes.len() <= LIMIT, "pack/idx exceeds limit");
    let pack_report = delta::verify_pack(&pack_bytes, &delta::Limits::default())?;
    let pack_sha256 = pack_report.pack_sha256.clone();
    let idx_sha256 = delta::sha256_hex(&idx_bytes);
    if let Some(ref exp_sha) = opts.expected_pack_sha256 { ensure!(exp_sha == &pack_sha256, "expected pack SHA-256 mismatch"); }
    if let Some(exp_len) = opts.expected_pack_bytes { ensure!(exp_len == pack_bytes.len() as u64, "expected pack byte length mismatch"); }

    let upload_id = Uuid::new_v4();
    let mut chunks_uploaded = 0usize;
    let (pack_chunks, ver_pack) = stage_and_reassemble_multipart(store_root_dir, upload_id, &pack_bytes, &pack_sha256, pack_bytes.len() as u64, opts, &mut chunks_uploaded)?;
    let idx_opts = ObjectStorePutOptions { corrupt_chunk_part: None, expected_pack_sha256: None, expected_pack_bytes: None, ..opts.clone() };
    let (idx_chunks, ver_idx) = stage_and_reassemble_multipart(store_root_dir, Uuid::new_v4(), &idx_bytes, &idx_sha256, idx_bytes.len() as u64, &idx_opts, &mut chunks_uploaded)?;

    let (p_key, i_key, m_key) = (pack_key(&opts.bucket, repo, pack_id), idx_key(&opts.bucket, repo, pack_id), manifest_key(repo, pack_id));
    let (b_pack, b_idx, m_path) = (store_root_dir.join(&p_key), store_root_dir.join(&i_key), store_root_dir.join(&m_key));
    write_immutable_cas_file(&b_pack, &ver_pack, &pack_sha256)?;
    write_immutable_cas_file(&b_idx, &ver_idx, &idx_sha256)?;

    let mut manifest = CasPackManifest {
        schema: MANIFEST_SCHEMA.to_owned(), bucket: opts.bucket.clone(), backend: BACKEND_KIND.to_owned(),
        repo, pack_id, pack_key: p_key.clone(), idx_key: i_key.clone(), manifest_key: m_key.clone(),
        pack_sha256: pack_sha256.clone(), idx_sha256: idx_sha256.clone(), pack_bytes: ver_pack.len() as u64,
        idx_bytes: ver_idx.len() as u64, object_count: pack_report.object_count, chunk_size: opts.chunk_size,
        pack_chunks, idx_chunks, manifest_sha256: String::new(),
    };
    manifest.manifest_sha256 = delta::sha256_hex(&serde_json::to_vec(&manifest)?);
    let m_bytes = serde_json::to_vec_pretty(&manifest)?;
    write_immutable_cas_file(&m_path, &m_bytes, &delta::sha256_hex(&m_bytes))?;

    let report = ObjectStorePutReport {
        repo, pack_id, bucket: opts.bucket.clone(), backend: BACKEND_KIND.to_owned(), upload_id,
        pack_key: p_key, idx_key: i_key, manifest_key: m_key,
        bucket_pack_path: b_pack.to_string_lossy().into_owned(), bucket_idx_path: b_idx.to_string_lossy().into_owned(),
        manifest_path: m_path.to_string_lossy().into_owned(), pack_sha256, idx_sha256,
        pack_bytes: manifest.pack_bytes, idx_bytes: manifest.idx_bytes, object_count: manifest.object_count,
        chunk_size: opts.chunk_size, chunk_count: manifest.pack_chunks.len(),
        total_chunks_uploaded: manifest.pack_chunks.len() + manifest.idx_chunks.len(),
        immutable_mode: "0444".to_owned(), status: "published".to_owned(),
    };
    Ok((report, manifest))
}

pub fn get_pack_files(
    store_root_dir: &Path,
    local_objects_root: &Path,
    bucket: &str,
    repo: Uuid,
    pack_id: Uuid,
    expected_pack_sha256: Option<&str>,
    expected_idx_sha256: Option<&str>,
) -> Result<ObjectStoreGetReport> {
    let local_dir = local_objects_root.join(repo.to_string());
    let (local_pack, local_idx) = (local_dir.join(format!("{pack_id}.pack")), local_dir.join(format!("{pack_id}.idx")));
    if local_pack.is_file() && local_idx.is_file() {
        let (p_b, i_b) = (std::fs::read(&local_pack)?, std::fs::read(&local_idx)?);
        let (p_sha, i_sha) = (delta::sha256_hex(&p_b), delta::sha256_hex(&i_b));
        if expected_pack_sha256.is_none_or(|e| e == p_sha) && expected_idx_sha256.is_none_or(|e| e == i_sha) {
            return Ok(ObjectStoreGetReport {
                repo, pack_id, bucket: bucket.to_owned(), pack_sha256: p_sha, idx_sha256: i_sha,
                pack_bytes: p_b.len() as u64, idx_bytes: i_b.len() as u64, cache_hit: true,
                rehydrated_from_object_store: false, local_pack_path: local_pack.to_string_lossy().into_owned(),
                local_idx_path: local_idx.to_string_lossy().into_owned(), verified: true,
            });
        }
    }
    let m_path = store_root_dir.join(manifest_key(repo, pack_id));
    ensure!(m_path.is_file(), "local pack cache miss for {pack_id} and pack is not present in object store");
    let manifest: CasPackManifest = serde_json::from_slice(&std::fs::read(&m_path)?)?;
    let mut check = manifest.clone();
    check.manifest_sha256 = String::new();
    ensure!(manifest.repo == repo && manifest.pack_id == pack_id && delta::sha256_hex(&serde_json::to_vec(&check)?) == manifest.manifest_sha256, "CAS manifest verification failed");
    if let Some(ep) = expected_pack_sha256 { ensure!(manifest.pack_sha256 == ep, "manifest pack_sha256 mismatch"); }
    if let Some(ei) = expected_idx_sha256 { ensure!(manifest.idx_sha256 == ei, "manifest idx_sha256 mismatch"); }

    let p_bytes = std::fs::read(store_root_dir.join(&manifest.pack_key))?;
    let i_bytes = std::fs::read(store_root_dir.join(&manifest.idx_key))?;
    ensure!(p_bytes.len() as u64 == manifest.pack_bytes && delta::sha256_hex(&p_bytes) == manifest.pack_sha256, "object store pack mismatch");
    ensure!(i_bytes.len() as u64 == manifest.idx_bytes && delta::sha256_hex(&i_bytes) == manifest.idx_sha256, "object store idx mismatch");
    let rep = delta::verify_pack(&p_bytes, &delta::Limits::default())?;
    ensure!(rep.object_count == manifest.object_count, "object store pack object_count mismatch");
    write_atomic_local_cache_file(&local_pack, &p_bytes, &manifest.pack_sha256)?;
    write_atomic_local_cache_file(&local_idx, &i_bytes, &manifest.idx_sha256)?;
    Ok(ObjectStoreGetReport {
        repo, pack_id, bucket: manifest.bucket, pack_sha256: manifest.pack_sha256, idx_sha256: manifest.idx_sha256,
        pack_bytes: manifest.pack_bytes, idx_bytes: manifest.idx_bytes, cache_hit: false,
        rehydrated_from_object_store: true, local_pack_path: local_pack.to_string_lossy().into_owned(),
        local_idx_path: local_idx.to_string_lossy().into_owned(), verified: true,
    })
}

pub(super) async fn ensure_local_pack_cached(config: &Config, repo: Uuid, pack: &Pack) -> Result<ObjectStoreGetReport> {
    if remote_enabled() { return super::remote::get(config, repo, pack.id).await; }
    get_pack_files(&store_root(config), &config.root.join("objects"), &default_bucket(), repo, pack.id, Some(&pack.pack_sha256), Some(&pack.idx_sha256))
}

pub fn verify_repo_files(store_root_dir: &Path, bucket: &str, repo: Uuid) -> Result<ObjectStoreVerifyReport> {
    let mut orphan_staging_cleaned = 0usize;
    let mp_dir = store_root_dir.join("multipart");
    if mp_dir.is_dir() {
        for e in std::fs::read_dir(&mp_dir)? {
            let p = e?.path();
            if p.is_dir() { std::fs::remove_dir_all(&p)?; orphan_staging_cleaned += 1; }
        }
    }
    let m_dir = store_root_dir.join("manifests").join(repo.to_string());
    let (mut checked, mut verified, mut p_bytes_sum, mut i_bytes_sum) = (0usize, 0usize, 0u64, 0u64);
    if m_dir.is_dir() {
        for e in std::fs::read_dir(&m_dir)? {
            let path = e?.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") { continue; }
            checked += 1;
            let m: CasPackManifest = serde_json::from_slice(&std::fs::read(&path)?)?;
            let (pb, ib) = (std::fs::read(store_root_dir.join(&m.pack_key))?, std::fs::read(store_root_dir.join(&m.idx_key))?);
            ensure!(pb.len() as u64 == m.pack_bytes && delta::sha256_hex(&pb) == m.pack_sha256 && ib.len() as u64 == m.idx_bytes && delta::sha256_hex(&ib) == m.idx_sha256, "bucket object mismatch");
            let rep = delta::verify_pack(&pb, &delta::Limits::default())?;
            ensure!(rep.object_count == m.object_count, "bucket object_count mismatch");
            verified += 1;
            p_bytes_sum += m.pack_bytes;
            i_bytes_sum += m.idx_bytes;
        }
    }
    Ok(ObjectStoreVerifyReport { repo, bucket: bucket.to_owned(), manifests_checked: checked, packs_verified: verified, total_pack_bytes: p_bytes_sum, total_idx_bytes: i_bytes_sum, orphan_staging_cleaned, verified: true })
}

pub(super) async fn put_pack(config: &Config, repo: Uuid, pack_id: Uuid, opts: &ObjectStorePutOptions) -> Result<ObjectStorePutReport> {
    if remote_enabled() { return super::remote::put(config, repo, pack_id, opts).await; }
    let (report, manifest) = put_pack_files(&store_root(config), &config.root.join("objects"), repo, pack_id, opts)?;
    let c = config.db().await?;
    c.execute(
        "INSERT INTO pando_lab.object_store_manifests(repo,pack_id,bucket,pack_key,idx_key,manifest_key,pack_sha256,idx_sha256,pack_bytes,idx_bytes,object_count,chunk_size,chunk_count,manifest_json) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) \
         ON CONFLICT(repo,pack_id) DO UPDATE SET bucket=EXCLUDED.bucket,manifest_json=EXCLUDED.manifest_json",
        &[&repo, &pack_id, &report.bucket, &report.pack_key, &report.idx_key, &report.manifest_key, &report.pack_sha256, &report.idx_sha256, &(report.pack_bytes as i64), &(report.idx_bytes as i64), &(report.object_count as i64), &(report.chunk_size as i64), &(report.chunk_count as i64), &serde_json::to_value(&manifest)?],
    ).await?;
    Ok(report)
}

pub(super) async fn get_pack(config: &Config, repo: Uuid, pack_id: Uuid) -> Result<ObjectStoreGetReport> {
    if remote_enabled() { return super::remote::get(config, repo, pack_id).await; }
    let c = config.db().await?;
    let row = c.query_opt("SELECT pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo=$1 AND pack_id=$2", &[&repo, &pack_id]).await?;
    let (ep, ei) = match row { Some(r) => (Some(r.get::<_, String>(0)), Some(r.get::<_, String>(1))), None => (None, None) };
    get_pack_files(&store_root(config), &config.root.join("objects"), &default_bucket(), repo, pack_id, ep.as_deref(), ei.as_deref())
}

pub(super) async fn verify_repo_store(config: &Config, repo: Uuid) -> Result<ObjectStoreVerifyReport> {
    if remote_enabled() { return super::remote::verify(config, repo).await; }
    let report = verify_repo_files(&store_root(config), &default_bucket(), repo)?;
    let c = config.db().await?;
    for r in c.query("SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.object_store_manifests WHERE repo=$1", &[&repo]).await? {
        let pid: Uuid = r.get(0);
        let m: CasPackManifest = serde_json::from_slice(&std::fs::read(store_root(config).join(manifest_key(repo, pid)))?)?;
        ensure!(m.pack_sha256 == r.get::<_, String>(1) && m.idx_sha256 == r.get::<_, String>(2), "DB object_store_manifests mismatch for {pid}");
    }
    Ok(report)
}

pub(super) async fn status(config: &Config, repo: Uuid) -> Result<ObjectStoreStatusReport> {
    let c = config.db().await?;
    let committed = c.query("SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo=$1 ORDER BY pack_id", &[&repo]).await?;
    let os_rows = c.query("SELECT pack_id,bucket,pack_key,idx_key,manifest_key,pack_bytes,idx_bytes,object_count,chunk_count FROM pando_lab.object_store_manifests WHERE repo=$1 ORDER BY pack_id", &[&repo]).await?;
    let mut os_map = BTreeMap::new();
    for r in &os_rows {
        let pid: Uuid = r.get(0);
        os_map.insert(pid, serde_json::json!({"pack_id": pid, "bucket": r.get::<_, String>(1), "pack_key": r.get::<_, String>(2), "idx_key": r.get::<_, String>(3), "manifest_key": r.get::<_, String>(4), "pack_bytes": r.get::<_, i64>(5), "idx_bytes": r.get::<_, i64>(6), "object_count": r.get::<_, i64>(7), "chunk_count": r.get::<_, i64>(8)}));
    }
    let (mut local_cached, mut all_rep, mut packs) = (0usize, true, Vec::new());
    for r in &committed {
        let pid: Uuid = r.get(0);
        let pfx = config.root.join("objects").join(repo.to_string()).join(pid.to_string());
        let cached = pfx.with_extension("pack").is_file() && pfx.with_extension("idx").is_file();
        if cached { local_cached += 1; }
        let in_os = os_map.contains_key(&pid);
        if !in_os { all_rep = false; }
        packs.push(serde_json::json!({"pack_id": pid, "pack_sha256": r.get::<_, String>(1), "idx_sha256": r.get::<_, String>(2), "local_cached": cached, "in_object_store": in_os, "object_store": os_map.get(&pid)}));
    }
    let mp_dir = store_root(config).join("multipart");
    let active_mp = if mp_dir.is_dir() { std::fs::read_dir(&mp_dir)?.count() } else { 0 };
    Ok(ObjectStoreStatusReport { repo, bucket: default_bucket(), backend: BACKEND_KIND.to_owned(), committed_manifests: committed.len(), object_store_manifests: os_rows.len(), local_cached_packs: local_cached, fully_replicated: all_rep, active_multipart_uploads: active_mp, packs })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multipart_cas_upload_fault_injection_and_cache_rehydration() {
        let tmp = std::env::temp_dir().join(format!("pando-os-test-{}", Uuid::new_v4()));
        let objects_root = tmp.join("objects");
        let (repo, pack_id) = (Uuid::new_v4(), Uuid::new_v4());
        let dir = objects_root.join(repo.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let mut pack = Vec::from(&b"PACK\x00\x00\x00\x02\x00\x00\x00\x01\x34"[..]);
        pack.extend_from_slice(&delta::compress_zlib_stored(b"test"));
        let tr = delta::sha1_digest(&pack);
        pack.extend_from_slice(&tr);
        std::fs::write(dir.join(format!("{pack_id}.pack")), &pack).unwrap();
        std::fs::write(dir.join(format!("{pack_id}.idx")), b"idx-bytes").unwrap();

        let fail_opts = ObjectStorePutOptions { bucket: "b1".into(), chunk_size: 8, fail_after_chunks: Some(1), ..Default::default() };
        assert!(put_pack_files(&tmp, &objects_root, repo, pack_id, &fail_opts).is_err());
        let ok_opts = ObjectStorePutOptions { bucket: "b1".into(), chunk_size: 8, ..Default::default() };
        let (rep, m) = put_pack_files(&tmp, &objects_root, repo, pack_id, &ok_opts).unwrap();
        assert_eq!(rep.status, "published");
        std::fs::remove_file(dir.join(format!("{pack_id}.pack"))).unwrap();
        let get_rep = get_pack_files(&tmp, &objects_root, "b1", repo, pack_id, Some(&m.pack_sha256), Some(&m.idx_sha256)).unwrap();
        assert!(get_rep.rehydrated_from_object_store);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
