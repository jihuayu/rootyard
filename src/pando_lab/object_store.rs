use super::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

mod authority;
mod publication;
pub(crate) use publication::{PreparedPackPublication, PublicationReceipt, prepare_pack_files_sealed};
#[cfg(test)]
mod pg_receipt_tests;
#[cfg(test)]
mod pg_tests;
#[cfg(test)]
mod publication_tests;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectStorePutOptions {
    pub bucket: String,
    pub chunk_size: usize,
    pub fail_after_chunks: Option<usize>,
    pub corrupt_chunk_part: Option<usize>,
    pub expected_pack_sha256: Option<String>,
    pub expected_pack_bytes: Option<u64>,
    #[serde(default)]
    pub cipher_suite: Option<String>,
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
            cipher_suite: None,
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
    std::env::var("PANDO_OBJECT_STORE_BUCKET")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_BUCKET.to_owned())
}
pub(crate) fn remote_enabled() -> bool {
    std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_some()
}

pub(super) fn store_root(config: &Config) -> PathBuf {
    std::env::var("PANDO_OBJECT_STORE_ROOT")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| config.root.clone())
}

pub fn valid_bucket_name(bucket: &str) -> bool {
    !bucket.is_empty()
        && bucket.len() <= 128
        && !bucket.starts_with('.')
        && !bucket.ends_with('.')
        && !bucket.contains("..")
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

pub(super) fn stage_and_reassemble_multipart(
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
        let slices: Vec<&[u8]> =
            if payload.is_empty() { vec![&[][..]] } else { payload.chunks(opts.chunk_size).collect() };
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
                if tampered.is_empty() {
                    tampered.push(0xff);
                } else {
                    tampered[0] ^= 0xff;
                }
                std::fs::write(&part_path, &tampered)?;
            }
            let staged = std::fs::read(&part_path)?;
            let actual_sha = delta::sha256_hex(&staged);
            ensure!(
                staged.len() == chunk.len() && actual_sha == expected_part_sha,
                "multipart chunk {part_number} digest or size mismatch"
            );
            receipts.push(ChunkPartReceipt { part_number, offset, size_bytes: chunk.len(), sha256: actual_sha });
            offset += chunk.len();
        }
        let mut reassembled = Vec::with_capacity(payload.len());
        for r in &receipts {
            let part_bytes = std::fs::read(staging_dir.join(format!("part-{}", r.part_number)))?;
            ensure!(
                part_bytes.len() == r.size_bytes && delta::sha256_hex(&part_bytes) == r.sha256,
                "reassembly mismatch at part {}",
                r.part_number
            );
            reassembled.extend_from_slice(&part_bytes);
        }
        ensure!(
            reassembled.len() as u64 == expected_bytes && delta::sha256_hex(&reassembled) == expected_sha256,
            "complete object digest/size mismatch"
        );
        Ok((receipts, reassembled))
    })();
    let _ = std::fs::remove_dir_all(&staging_dir);
    res
}

struct ImmutableInstallTemp {
    path: PathBuf,
    armed: bool,
}

impl ImmutableInstallTemp {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ImmutableInstallTemp {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn read_regular_immutable_file_without_following(path: &Path) -> Result<Vec<u8>> {
    let link_metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        link_metadata.file_type().is_file(),
        "immutable object store target is not a regular file: {}",
        path.display()
    );
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_type().is_file(),
        "immutable object store target changed to a non-regular file: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

pub(super) fn write_immutable_cas_file_with_before_link(
    target: &Path,
    data: &[u8],
    expected_sha256: &str,
    before_link: impl FnOnce(),
) -> Result<()> {
    ensure!(delta::sha256_hex(data) == expected_sha256, "CAS payload digest mismatch");
    let parent = target.parent().context("missing CAS parent")?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".tmp-{}", Uuid::new_v4()));
    let mut temp = ImmutableInstallTemp::new(tmp.clone());
    {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(data)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o444))?;
        file.sync_all()?;
    }
    before_link();
    // hard_link is the no-clobber linearization point. The final name never
    // exposes an incomplete temp, and an existing final is never replaced.
    match std::fs::hard_link(&tmp, target) {
        Ok(()) => {
            let sync = File::open(parent).and_then(|dir| dir.sync_all());
            let cleanup = std::fs::remove_file(&tmp);
            if cleanup.is_ok() {
                temp.disarm();
            }
            sync.context("failed to sync the immutable CAS parent directory")?;
            cleanup.context("failed to remove the immutable CAS temporary file")?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let cleanup = std::fs::remove_file(&tmp);
            if cleanup.is_ok() {
                temp.disarm();
            }
            cleanup.context("failed to remove the immutable CAS temporary file after collision")?;
            let existing = read_regular_immutable_file_without_following(target)?;
            ensure!(
                existing.len() == data.len() && delta::sha256_hex(&existing) == expected_sha256,
                "immutable object store key collision on {}",
                target.display()
            );
            Ok(())
        }
        Err(error) => {
            if std::fs::remove_file(&tmp).is_ok() {
                temp.disarm();
            }
            Err(error).with_context(|| format!("failed to install immutable CAS file {}", target.display()))
        }
    }
}

pub(super) fn write_immutable_cas_file(target: &Path, data: &[u8], expected_sha256: &str) -> Result<()> {
    write_immutable_cas_file_with_before_link(target, data, expected_sha256, || {})
}

#[cfg(test)]
pub(crate) fn write_immutable_cas_file_with_barrier(
    target: &Path,
    data: &[u8],
    expected_sha256: &str,
    barrier: &std::sync::Barrier,
) -> Result<()> {
    write_immutable_cas_file_with_before_link(target, data, expected_sha256, || {
        barrier.wait();
    })
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

pub(super) fn infer_base_root<'a>(store_root_dir: &'a Path, objects_root: Option<&'a Path>) -> &'a Path {
    if store_root_dir.file_name().and_then(|s| s.to_str()) == Some("object_store")
        && let Some(parent) = store_root_dir.parent()
    {
        return parent;
    }
    if let Some(obj) = objects_root
        && obj.file_name().and_then(|s| s.to_str()) == Some("objects")
        && let Some(parent) = obj.parent()
    {
        return parent;
    }
    store_root_dir
}

async fn decrypt_verified_store_pack(
    store_root_dir: &Path,
    base_root: &Path,
    manifest: &CasPackManifest,
    client: Option<&Client>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut check = manifest.clone();
    check.manifest_sha256 = String::new();
    ensure!(
        delta::sha256_hex(&serde_json::to_vec(&check)?) == manifest.manifest_sha256,
        "CAS manifest verification failed"
    );
    ensure!(
        manifest.encryption_mode.as_deref() == Some(lifecycle::crypto::AUTHENTICATED_ENVELOPE_MODE),
        "object store pack {} lacks authenticated encryption mode",
        manifest.pack_id
    );
    let cipher_sha = manifest.ciphertext_sha256.as_deref().context("missing ciphertext_sha256 in CAS manifest")?;
    let cipher_len = manifest.ciphertext_bytes.context("missing ciphertext_bytes in CAS manifest")?;
    let c_bytes = std::fs::read(store_root_dir.join(&manifest.pack_key))?;
    let i_bytes = std::fs::read(store_root_dir.join(&manifest.idx_key))?;
    ensure!(
        c_bytes.len() as u64 == cipher_len && delta::sha256_hex(&c_bytes) == cipher_sha,
        "object store ciphertext mismatch"
    );
    ensure!(
        i_bytes.len() as u64 == manifest.idx_bytes && delta::sha256_hex(&i_bytes) == manifest.idx_sha256,
        "object store idx mismatch"
    );
    let pack = Pack {
        id: manifest.pack_id,
        pack_sha256: manifest.pack_sha256.clone(),
        idx_sha256: manifest.idx_sha256.clone(),
    };
    let env = if let Some(client) = client {
        lifecycle::rotation::load_authoritative_envelope(client, base_root, manifest.repo, &pack).await?
    } else {
        lifecycle::read_and_verify_envelope_file(base_root, manifest.repo, manifest.pack_id)?
    };
    let p_bytes =
        lifecycle::rotation::verify_and_decrypt_pack_bytes(base_root, manifest.repo, &pack, &env, &c_bytes).await?;
    ensure!(
        p_bytes.len() as u64 == manifest.pack_bytes && delta::sha256_hex(&p_bytes) == manifest.pack_sha256,
        "decrypted pack digest or length mismatch"
    );
    let rep = delta::verify_pack(&p_bytes, &delta::Limits::default())?;
    ensure!(rep.object_count == manifest.object_count, "object store pack object_count mismatch");
    Ok((p_bytes, i_bytes))
}

fn ensure_encrypted_hook_backend_supported(remote: bool) -> Result<()> {
    ensure!(
        !remote,
        "encrypted Git-hook publication is unsupported with ROOTYARD_OBJECT_STORE_ENDPOINT; local CAS cannot be committed as a remote-backed object-store publication"
    );
    Ok(())
}

pub(crate) async fn prepare_known_pack_publication(
    config: &Config,
    client: &Client,
    repo: Uuid,
    pack: &Pack,
    checkpoint: Option<&lifecycle::rotation::KmsRotationCheckpoint>,
    storage_tier: &str,
) -> Result<PreparedPackPublication> {
    // The encrypted prepared hook currently produces local CAS only. Use the
    // exact same backend switch as ordinary put/get/verify before provider
    // selection, local sealing, or authoritative SQL publication.
    ensure_encrypted_hook_backend_supported(remote_enabled())?;
    let local_root = config.root.join("objects");
    let pack_bytes = std::fs::read(local_root.join(repo.to_string()).join(format!("{}.pack", pack.id)))?;
    let idx_bytes = std::fs::read(local_root.join(repo.to_string()).join(format!("{}.idx", pack.id)))?;
    ensure!(
        delta::sha256_hex(&pack_bytes) == pack.pack_sha256 && delta::sha256_hex(&idx_bytes) == pack.idx_sha256,
        "prepared pack or index digest does not match the known pack identity"
    );
    let opts = ObjectStorePutOptions {
        expected_pack_sha256: Some(pack.pack_sha256.clone()),
        expected_pack_bytes: Some(pack_bytes.len() as u64),
        ..Default::default()
    };
    let prepared = prepare_pack_files_sealed(
        &store_root(config),
        &local_root,
        repo,
        pack.id,
        &opts,
        storage_tier,
        checkpoint,
        Some(client),
    )
    .await?;
    let manifest = prepared.manifest();
    let envelope = prepared.envelope();
    ensure!(
        manifest.repo == repo
            && manifest.pack_id == pack.id
            && manifest.pack_sha256 == pack.pack_sha256
            && manifest.idx_sha256 == pack.idx_sha256,
        "prepared object-store manifest identity mismatch"
    );
    ensure!(
        envelope.encryption_mode == lifecycle::crypto::AUTHENTICATED_ENVELOPE_MODE,
        "prepared envelope is not authenticated"
    );
    if let Some(cp) = checkpoint {
        ensure!(
            envelope.provider_kind == cp.to_provider_kind
                && envelope.key_id == cp.to_key_id
                && envelope.key_version == cp.expected_version(),
            "prepared envelope does not match the authoritative rotation target"
        );
    }
    Ok(prepared)
}

pub async fn put_pack_files(
    store_root_dir: &Path,
    local_objects_root: &Path,
    repo: Uuid,
    pack_id: Uuid,
    opts: &ObjectStorePutOptions,
) -> Result<(ObjectStorePutReport, CasPackManifest)> {
    ensure!(
        lifecycle::provider_selection::selected_kind()? == lifecycle::provider_selection::PandoProviderSelection::Local,
        "raw Local object-store helper cannot publish unterminated Vault writes"
    );
    let prepared =
        prepare_pack_files_sealed(store_root_dir, local_objects_root, repo, pack_id, opts, "hot", None, None).await?;
    // This raw path has no DB authority, so its verified envelope file is the
    // only metadata authority. The staged prepare itself never writes a mirror.
    prepared.write_file_only_mirror()?;
    Ok((prepared.report().clone(), prepared.manifest().clone()))
}

pub async fn get_pack_files(
    store_root_dir: &Path,
    local_objects_root: &Path,
    bucket: &str,
    repo: Uuid,
    pack_id: Uuid,
    expected_pack_sha256: Option<&str>,
    expected_idx_sha256: Option<&str>,
) -> Result<ObjectStoreGetReport> {
    get_pack_files_inner(
        store_root_dir,
        local_objects_root,
        bucket,
        repo,
        pack_id,
        expected_pack_sha256,
        expected_idx_sha256,
        None,
    )
    .await
}

pub(crate) async fn get_pack_files_with_client(
    store_root_dir: &Path,
    local_objects_root: &Path,
    bucket: &str,
    repo: Uuid,
    pack_id: Uuid,
    expected_pack_sha256: Option<&str>,
    expected_idx_sha256: Option<&str>,
    client: &Client,
) -> Result<ObjectStoreGetReport> {
    get_pack_files_inner(
        store_root_dir,
        local_objects_root,
        bucket,
        repo,
        pack_id,
        expected_pack_sha256,
        expected_idx_sha256,
        Some(client),
    )
    .await
}

async fn get_pack_files_inner(
    store_root_dir: &Path,
    local_objects_root: &Path,
    bucket: &str,
    repo: Uuid,
    pack_id: Uuid,
    expected_pack_sha256: Option<&str>,
    expected_idx_sha256: Option<&str>,
    client: Option<&Client>,
) -> Result<ObjectStoreGetReport> {
    let local_dir = local_objects_root.join(repo.to_string());
    let (local_pack, local_idx) = (local_dir.join(format!("{pack_id}.pack")), local_dir.join(format!("{pack_id}.idx")));
    if local_pack.is_file() && local_idx.is_file() {
        let (p_b, i_b) = (std::fs::read(&local_pack)?, std::fs::read(&local_idx)?);
        let (p_sha, i_sha) = (delta::sha256_hex(&p_b), delta::sha256_hex(&i_b));
        if expected_pack_sha256.is_none_or(|e| e == p_sha) && expected_idx_sha256.is_none_or(|e| e == i_sha) {
            return Ok(ObjectStoreGetReport {
                repo,
                pack_id,
                bucket: bucket.to_owned(),
                pack_sha256: p_sha,
                idx_sha256: i_sha,
                pack_bytes: p_b.len() as u64,
                idx_bytes: i_b.len() as u64,
                cache_hit: true,
                rehydrated_from_object_store: false,
                local_pack_path: local_pack.to_string_lossy().into_owned(),
                local_idx_path: local_idx.to_string_lossy().into_owned(),
                verified: true,
            });
        }
    }
    let m_path = store_root_dir.join(manifest_key(repo, pack_id));
    ensure!(m_path.is_file(), "local pack cache miss for {pack_id} and pack is not present in object store");
    let manifest: CasPackManifest = serde_json::from_slice(&std::fs::read(&m_path)?)?;
    ensure!(manifest.repo == repo && manifest.pack_id == pack_id, "CAS manifest identity mismatch");
    if let Some(ep) = expected_pack_sha256 {
        ensure!(manifest.pack_sha256 == ep, "manifest pack_sha256 mismatch");
    }
    if let Some(ei) = expected_idx_sha256 {
        ensure!(manifest.idx_sha256 == ei, "manifest idx_sha256 mismatch");
    }
    let base_root = infer_base_root(store_root_dir, Some(local_objects_root));
    let (p_bytes, i_bytes) = decrypt_verified_store_pack(store_root_dir, base_root, &manifest, client).await?;
    write_atomic_local_cache_file(&local_pack, &p_bytes, &manifest.pack_sha256)?;
    write_atomic_local_cache_file(&local_idx, &i_bytes, &manifest.idx_sha256)?;
    Ok(ObjectStoreGetReport {
        repo,
        pack_id,
        bucket: manifest.bucket,
        pack_sha256: manifest.pack_sha256,
        idx_sha256: manifest.idx_sha256,
        pack_bytes: manifest.pack_bytes,
        idx_bytes: manifest.idx_bytes,
        cache_hit: false,
        rehydrated_from_object_store: true,
        local_pack_path: local_pack.to_string_lossy().into_owned(),
        local_idx_path: local_idx.to_string_lossy().into_owned(),
        verified: true,
    })
}

pub(super) async fn ensure_local_pack_cached(config: &Config, repo: Uuid, pack: &Pack) -> Result<ObjectStoreGetReport> {
    if remote_enabled() {
        return super::remote::get(config, repo, pack.id).await;
    }
    let c = config.db().await?;
    get_pack_files_with_client(
        &store_root(config),
        &config.root.join("objects"),
        &default_bucket(),
        repo,
        pack.id,
        Some(&pack.pack_sha256),
        Some(&pack.idx_sha256),
        &c,
    )
    .await
}

async fn verify_repo_files_with_base(
    store_root_dir: &Path,
    base_root: &Path,
    bucket: &str,
    repo: Uuid,
) -> Result<ObjectStoreVerifyReport> {
    verify_repo_files_with_base_inner(store_root_dir, base_root, bucket, repo, None).await
}

async fn verify_repo_files_with_client(
    store_root_dir: &Path,
    base_root: &Path,
    bucket: &str,
    repo: Uuid,
    client: &Client,
) -> Result<ObjectStoreVerifyReport> {
    verify_repo_files_with_base_inner(store_root_dir, base_root, bucket, repo, Some(client)).await
}

async fn verify_repo_files_with_base_inner(
    store_root_dir: &Path,
    base_root: &Path,
    bucket: &str,
    repo: Uuid,
    client: Option<&Client>,
) -> Result<ObjectStoreVerifyReport> {
    let mut orphan_staging_cleaned = 0usize;
    let mp_dir = store_root_dir.join("multipart");
    if mp_dir.is_dir() {
        for e in std::fs::read_dir(&mp_dir)? {
            let p = e?.path();
            if p.is_dir() {
                std::fs::remove_dir_all(&p)?;
                orphan_staging_cleaned += 1;
            }
        }
    }
    let m_dir = store_root_dir.join("manifests").join(repo.to_string());
    let (mut checked, mut verified, mut p_bytes_sum, mut i_bytes_sum) = (0usize, 0usize, 0u64, 0u64);
    if m_dir.is_dir() {
        for e in std::fs::read_dir(&m_dir)? {
            let path = e?.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            checked += 1;
            let m: CasPackManifest = serde_json::from_slice(&std::fs::read(&path)?)?;
            decrypt_verified_store_pack(store_root_dir, base_root, &m, client).await?;
            verified += 1;
            p_bytes_sum += m.pack_bytes;
            i_bytes_sum += m.idx_bytes;
        }
    }
    Ok(ObjectStoreVerifyReport {
        repo,
        bucket: bucket.to_owned(),
        manifests_checked: checked,
        packs_verified: verified,
        total_pack_bytes: p_bytes_sum,
        total_idx_bytes: i_bytes_sum,
        orphan_staging_cleaned,
        verified: true,
    })
}

pub async fn verify_repo_files(store_root_dir: &Path, bucket: &str, repo: Uuid) -> Result<ObjectStoreVerifyReport> {
    verify_repo_files_with_base(store_root_dir, infer_base_root(store_root_dir, None), bucket, repo).await
}

async fn put_pack_db_inner(
    config: &Config,
    repo: Uuid,
    pack_id: Uuid,
    opts: &ObjectStorePutOptions,
    storage_tier: &str,
) -> Result<(ObjectStorePutReport, lifecycle::KmsEnvelopeRecord)> {
    // Composed remote publication is not this primitive. Keep the boundary
    // explicit instead of silently committing local CAS under an S3 endpoint.
    ensure!(
        !remote_enabled(),
        "direct local CAS publication is unsupported with ROOTYARD_OBJECT_STORE_ENDPOINT; standalone remote put must use the remote publication path"
    );
    let mut session = lifecycle::publication::writer_session(config, repo).await?;
    let checkpoint = lifecycle::publication::active_rotation(session.client(), repo).await?;
    // Provider selection, sealing and immutable CAS writes happen while this
    // dedicated session owns the shared publication gate, but outside SQL.
    let prepared = prepare_pack_files_sealed(
        &store_root(config),
        &config.root.join("objects"),
        repo,
        pack_id,
        opts,
        storage_tier,
        checkpoint.as_ref(),
        Some(session.client()),
    )
    .await?;
    let t = session.client_mut().transaction().await?;
    let receipt = prepared.publish_in(&t).await?;
    t.commit().await?;
    // The receipt is the DB winner. Mirror only after the known commit and
    // derive the returned report/envelope from the receipt, never the losing
    // prepared value.
    receipt.refresh_mirrors();
    Ok((receipt.report(), receipt.envelope().clone()))
}

pub(super) async fn put_pack(
    config: &Config,
    repo: Uuid,
    pack_id: Uuid,
    opts: &ObjectStorePutOptions,
) -> Result<ObjectStorePutReport> {
    if remote_enabled() {
        return super::remote::put(config, repo, pack_id, opts).await;
    }
    Ok(put_pack_db_inner(config, repo, pack_id, opts, "hot").await?.0)
}

pub(crate) async fn put_pack_and_seal_with_suite(
    config: &Config,
    repo: Uuid,
    pack_id: Uuid,
    cipher_suite: &str,
    storage_tier: &str,
) -> Result<lifecycle::KmsEnvelopeRecord> {
    let opts = ObjectStorePutOptions { cipher_suite: Some(cipher_suite.to_owned()), ..Default::default() };
    Ok(put_pack_db_inner(config, repo, pack_id, &opts, storage_tier).await?.1)
}

pub(super) async fn get_pack(config: &Config, repo: Uuid, pack_id: Uuid) -> Result<ObjectStoreGetReport> {
    if remote_enabled() {
        return super::remote::get(config, repo, pack_id).await;
    }
    let c = config.db().await?;
    let row = c
        .query_opt(
            "SELECT pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo=$1 AND pack_id=$2",
            &[&repo, &pack_id],
        )
        .await?;
    let (ep, ei) = match row {
        Some(r) => (Some(r.get::<_, String>(0)), Some(r.get::<_, String>(1))),
        None => (None, None),
    };
    get_pack_files_with_client(
        &store_root(config),
        &config.root.join("objects"),
        &default_bucket(),
        repo,
        pack_id,
        ep.as_deref(),
        ei.as_deref(),
        &c,
    )
    .await
}

pub(super) async fn verify_repo_store(config: &Config, repo: Uuid) -> Result<ObjectStoreVerifyReport> {
    if remote_enabled() {
        return super::remote::verify(config, repo).await;
    }
    let c = config.db().await?;
    let report = verify_repo_files_with_client(&store_root(config), &config.root, &default_bucket(), repo, &c).await?;
    for r in c
        .query("SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.object_store_manifests WHERE repo=$1", &[&repo])
        .await?
    {
        let pid: Uuid = r.get(0);
        let m: CasPackManifest =
            serde_json::from_slice(&std::fs::read(store_root(config).join(manifest_key(repo, pid)))?)?;
        ensure!(
            m.pack_sha256 == r.get::<_, String>(1) && m.idx_sha256 == r.get::<_, String>(2),
            "DB object_store_manifests mismatch for {pid}"
        );
    }
    Ok(report)
}

pub(super) async fn status(config: &Config, repo: Uuid) -> Result<ObjectStoreStatusReport> {
    let c = config.db().await?;
    let committed = c
        .query(
            "SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo=$1 ORDER BY pack_id",
            &[&repo],
        )
        .await?;
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
        if cached {
            local_cached += 1;
        }
        let in_os = os_map.contains_key(&pid);
        if !in_os {
            all_rep = false;
        }
        packs.push(serde_json::json!({"pack_id": pid, "pack_sha256": r.get::<_, String>(1), "idx_sha256": r.get::<_, String>(2), "local_cached": cached, "in_object_store": in_os, "object_store": os_map.get(&pid)}));
    }
    let mp_dir = store_root(config).join("multipart");
    let active_mp = if mp_dir.is_dir() { std::fs::read_dir(&mp_dir)?.count() } else { 0 };
    Ok(ObjectStoreStatusReport {
        repo,
        bucket: default_bucket(),
        backend: BACKEND_KIND.to_owned(),
        committed_manifests: committed.len(),
        object_store_manifests: os_rows.len(),
        local_cached_packs: local_cached,
        fully_replicated: all_rep,
        active_multipart_uploads: active_mp,
        packs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_hook_factory_is_local_cas_only_and_fails_before_remote_side_effects() {
        // Both real Local-CAS encrypted modes (pinned Local and Vault without a
        // checkpoint / with a compatible checkpoint) share this local factory.
        assert!(ensure_encrypted_hook_backend_supported(false).is_ok());
        // Remote endpoint mode must not silently commit local CAS metadata.
        assert!(ensure_encrypted_hook_backend_supported(true).is_err());
    }

    #[tokio::test]
    async fn multipart_cas_upload_fault_injection_and_cache_rehydration() {
        let tmp = std::env::temp_dir().join(format!("pando-os-test-{}", Uuid::new_v4()));
        let objects_root = tmp.join("objects");
        let (repo, pack_id) = (Uuid::new_v4(), Uuid::new_v4());
        let dir = objects_root.join(repo.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let payload = b"test-secret-payload";
        let mut pack = Vec::from(&b"PACK\x00\x00\x00\x02\x00\x00\x00\x01"[..]);
        pack.push(0x80 | 0x30 | ((payload.len() & 0x0f) as u8));
        pack.push((payload.len() >> 4) as u8);
        pack.extend_from_slice(&delta::compress_zlib_stored(payload));
        let tr = delta::sha1_digest(&pack);
        pack.extend_from_slice(&tr);
        std::fs::write(dir.join(format!("{pack_id}.pack")), &pack).unwrap();
        std::fs::write(dir.join(format!("{pack_id}.idx")), b"idx-bytes").unwrap();

        let fail_opts = ObjectStorePutOptions {
            bucket: "b1".into(),
            chunk_size: 8,
            fail_after_chunks: Some(1),
            ..Default::default()
        };
        assert!(put_pack_files(&tmp, &objects_root, repo, pack_id, &fail_opts).await.is_err());
        let ok_opts = ObjectStorePutOptions { bucket: "b1".into(), chunk_size: 8, ..Default::default() };
        let (rep, m) = put_pack_files(&tmp, &objects_root, repo, pack_id, &ok_opts).await.unwrap();
        assert_eq!(rep.status, "published");
        assert!(!std::fs::read(&rep.bucket_pack_path).unwrap().windows(19).any(|w| w == b"test-secret-payload"));
        std::fs::remove_file(dir.join(format!("{pack_id}.pack"))).unwrap();
        let get_rep =
            get_pack_files(&tmp, &objects_root, "b1", repo, pack_id, Some(&m.pack_sha256), Some(&m.idx_sha256))
                .await
                .unwrap();
        assert!(
            get_rep.rehydrated_from_object_store && std::fs::read(dir.join(format!("{pack_id}.pack"))).unwrap() == pack
        );
        assert!(verify_repo_files(&tmp, "b1", repo).await.unwrap().verified);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
