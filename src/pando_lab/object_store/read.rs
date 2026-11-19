use super::super::{Config, Pack, delta, lifecycle};
use super::{
    CasPackManifest, ObjectStoreGetReport, ObjectStoreVerifyReport, default_bucket, get_pack_files_with_client,
    infer_base_root, manifest_key, remote_enabled, store_root,
};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};
use tokio_postgres::Client;
use uuid::Uuid;

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

pub(super) async fn get_pack_files_inner(
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

pub(in super::super) async fn ensure_local_pack_cached(
    config: &Config,
    repo: Uuid,
    pack: &Pack,
) -> Result<ObjectStoreGetReport> {
    if remote_enabled() {
        return super::super::remote::get(config, repo, pack.id).await;
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

pub(super) async fn verify_repo_files_with_base(
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

pub(in super::super) async fn get_pack(config: &Config, repo: Uuid, pack_id: Uuid) -> Result<ObjectStoreGetReport> {
    if remote_enabled() {
        return super::super::remote::get(config, repo, pack_id).await;
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

pub(in super::super) async fn verify_repo_store(config: &Config, repo: Uuid) -> Result<ObjectStoreVerifyReport> {
    if remote_enabled() {
        return super::super::remote::verify(config, repo).await;
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
