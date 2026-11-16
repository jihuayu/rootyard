//! Real network CAS for Pando pack and index artifacts. PostgreSQL publication
//! follows verified remote objects; local pack files are only a read cache.
use super::*;
use object_store::{
    CasPackManifest, ChunkPartReceipt, ObjectStoreGetReport, ObjectStorePutOptions, ObjectStorePutReport,
    ObjectStoreVerifyReport,
};
use rootyard::storage::remote_objects::{ObjectKey, RemoteObjectStore};
use sha2::{Digest, Sha256};
use std::process::Stdio;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Duration, Instant},
};
use tokio_postgres::Client;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(300)
}
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

fn remote_manifest_key(repo: Uuid, manifest: &CasPackManifest) -> Result<ObjectKey> {
    let digest = hex::encode(Sha256::digest(serde_json::to_vec_pretty(manifest)?));
    key(repo, "pando-manifest", &digest)
}

/// Validate the immutable manifest bytes and the artifact keys they bind.
/// This is the collision oracle used both to publish and to recover an
/// already-committed publication.
fn validate_manifest_record(manifest: &CasPackManifest, repo: Uuid, pack_id: Uuid) -> Result<(String, u64)> {
    let mut unsigned = manifest.clone();
    unsigned.manifest_sha256.clear();
    ensure!(
        manifest.schema == object_store::MANIFEST_SCHEMA
            && manifest.repo == repo
            && manifest.pack_id == pack_id
            && manifest.backend == object_store::BACKEND_KIND
            && manifest.manifest_sha256 == hex::encode(Sha256::digest(serde_json::to_vec(&unsigned)?)),
        "Pando remote manifest identity or digest mismatch"
    );
    ensure!(
        manifest.encryption_mode.as_deref() == Some(lifecycle::crypto::AUTHENTICATED_ENVELOPE_MODE),
        "remote Pando manifest lacks authenticated encryption mode"
    );
    let cipher_sha = manifest.ciphertext_sha256.as_deref().context("missing remote ciphertext_sha256")?.to_owned();
    let cipher_bytes = manifest.ciphertext_bytes.context("missing remote ciphertext_bytes")?;
    ensure!(
        manifest.pack_key == key(repo, "pando-pack", &cipher_sha)?.path()
            && manifest.idx_key == key(repo, "pando-index", &manifest.idx_sha256)?.path()
            && manifest.manifest_key == object_store::manifest_key(repo, pack_id),
        "Pando remote artifact key mismatch"
    );
    Ok((cipher_sha, cipher_bytes))
}

fn validate_db_envelope(
    env: &lifecycle::KmsEnvelopeRecord,
    repo: Uuid,
    pack_id: Uuid,
    pack_sha256: &str,
    idx_sha256: &str,
    manifest: &CasPackManifest,
) -> Result<()> {
    ensure!(env.repo == repo && env.pack_id == pack_id, "DB KMS envelope repo/pack_id mismatch");
    lifecycle::verify_envelope_record(env)?;
    ensure!(
        env.pack_sha256 == pack_sha256 && env.idx_sha256 == idx_sha256 && env.plaintext_sha256 == pack_sha256,
        "DB KMS envelope does not bind the immutable pack/idx digests"
    );
    ensure!(
        lifecycle::crypto::is_authenticated_mode(&env.encryption_mode),
        "DB KMS envelope lacks authenticated encryption mode"
    );
    ensure!(
        env.ciphertext_sha256.as_deref() == manifest.ciphertext_sha256.as_deref()
            && env.ciphertext_bytes == manifest.ciphertext_bytes,
        "DB KMS envelope ciphertext identity diverges from the manifest"
    );
    if let Some(suite) = manifest.cipher_suite.as_deref() {
        ensure!(env.cipher_suite == suite, "DB KMS envelope cipher suite diverges from the manifest");
    }
    Ok(())
}

struct DbManifestRow {
    manifest: CasPackManifest,
    manifest_key: String,
    pack_sha256: String,
    idx_sha256: String,
}

async fn load_manifest_row(client: &Client, repo: Uuid, pack_id: Uuid) -> Result<Option<DbManifestRow>> {
    let row = client
        .query_opt(
            "SELECT manifest_json,manifest_key,pack_sha256,idx_sha256 FROM pando_lab.object_store_manifests WHERE repo=$1 AND pack_id=$2",
            &[&repo, &pack_id],
        )
        .await?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(DbManifestRow {
        manifest: serde_json::from_value(row.get(0))?,
        manifest_key: row.get(1),
        pack_sha256: row.get(2),
        idx_sha256: row.get(3),
    }))
}

fn recovered_report(repo: Uuid, pack_id: Uuid, manifest: &CasPackManifest) -> Result<ObjectStorePutReport> {
    let manifest_object_key = remote_manifest_key(repo, manifest)?;
    Ok(ObjectStorePutReport {
        repo,
        pack_id,
        bucket: manifest.bucket.clone(),
        backend: "s3-compatible-cas".into(),
        // S3 owns its upload IDs; a recovered publication has no local upload.
        upload_id: Uuid::nil(),
        pack_key: manifest.pack_key.clone(),
        idx_key: manifest.idx_key.clone(),
        manifest_key: manifest_object_key.path(),
        bucket_pack_path: manifest.pack_key.clone(),
        bucket_idx_path: manifest.idx_key.clone(),
        manifest_path: manifest_object_key.path(),
        pack_sha256: manifest.pack_sha256.clone(),
        idx_sha256: manifest.idx_sha256.clone(),
        pack_bytes: manifest.pack_bytes,
        idx_bytes: manifest.idx_bytes,
        object_count: manifest.object_count,
        chunk_size: manifest.chunk_size,
        chunk_count: manifest.pack_chunks.len(),
        total_chunks_uploaded: manifest.pack_chunks.len() + manifest.idx_chunks.len(),
        immutable_mode: "remote-cas".into(),
        status: "published".into(),
    })
}

async fn insert_envelope_if_absent(client: &Client, env: &lifecycle::KmsEnvelopeRecord) -> Result<()> {
    client
        .execute(
            "INSERT INTO pando_lab.kms_envelopes(repo,pack_id,key_id,key_version,cipher_suite,plaintext_sha256,envelope_mac,storage_tier,\
             encryption_mode,envelope_id,nonce_prefix,wrapped_key_json,ciphertext_sha256,ciphertext_bytes,provider_kind) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) \
             ON CONFLICT(repo,pack_id) DO NOTHING",
            &[
                &env.repo,
                &env.pack_id,
                &env.key_id,
                &env.key_version,
                &env.cipher_suite,
                &env.plaintext_sha256,
                &env.envelope_mac,
                &env.storage_tier,
                &env.encryption_mode,
                &env.envelope_id,
                &env.nonce_prefix,
                &env.wrapped_key_json,
                &env.ciphertext_sha256,
                &(env.ciphertext_bytes.map(|v| v as i64)),
                &env.provider_kind,
            ],
        )
        .await?;
    Ok(())
}

/// A completed publication is recovered instead of regenerating randomized
/// ciphertext. No row is overwritten, so a retry can never change the immutable
/// manifest/envelope pair observed by readers.
async fn check_existing_publication(
    client: &Client,
    config: &Config,
    repo: Uuid,
    pack_id: Uuid,
    pack_sha256: &str,
    idx_sha256: &str,
    bucket: &str,
) -> Result<Option<ObjectStorePutReport>> {
    let pack = Pack { id: pack_id, pack_sha256: pack_sha256.to_owned(), idx_sha256: idx_sha256.to_owned() };
    let manifest_row = load_manifest_row(client, repo, pack_id).await?;
    let envelope = lifecycle::load_envelope_from_db(client, repo, &pack).await?;
    match (manifest_row, envelope) {
        (None, None) => Ok(None),
        (Some(row), Some(envelope)) => {
            validate_manifest_record(&row.manifest, repo, pack_id)?;
            ensure!(
                row.pack_sha256 == row.manifest.pack_sha256 && row.idx_sha256 == row.manifest.idx_sha256,
                "DB Pando manifest columns diverge from the immutable manifest"
            );
            ensure!(row.manifest.bucket == bucket, "Pando manifest bucket differs from the requested bucket");
            ensure!(
                row.manifest.pack_sha256 == pack_sha256 && row.manifest.idx_sha256 == idx_sha256,
                "immutable Pando pack digest collision"
            );
            ensure!(
                row.manifest_key == remote_manifest_key(repo, &row.manifest)?.path(),
                "Pando remote manifest key mismatch"
            );
            validate_db_envelope(&envelope, repo, pack_id, pack_sha256, idx_sha256, &row.manifest)?;
            let _ = lifecycle::write_envelope_file(&config.root, &envelope);
            Ok(Some(recovered_report(repo, pack_id, &row.manifest)?))
        }
        _ => bail!(
            "inconsistent Pando publication rows for pack {pack_id}: the manifest and DB KMS envelope must both exist"
        ),
    }
}

/// Publish the manifest, Local policy and envelope in one short transaction on
/// the already-owned writer session. S3/Vault work has completed before this is
/// called. A connection loss drops the owned session and rolls the transaction
/// back; retries recover the durable pair instead of replacing it.
async fn publish_on_writer_session(
    client: &Client,
    config: &Config,
    repo: Uuid,
    pack_id: Uuid,
    opts: &ObjectStorePutOptions,
    manifest: &CasPackManifest,
    env: &lifecycle::KmsEnvelopeRecord,
    local_policy: Option<&lifecycle::provider::KmsKeyPolicy>,
    pack_sha256: &str,
    idx_sha256: &str,
) -> Result<ObjectStorePutReport> {
    let pack = Pack { id: pack_id, pack_sha256: pack_sha256.to_owned(), idx_sha256: idx_sha256.to_owned() };
    client.batch_execute("BEGIN").await.context("failed to open the Pando publication transaction")?;
    let result = async {
        let existing_manifest = load_manifest_row(client, repo, pack_id).await?;
        let existing_envelope = lifecycle::load_envelope_from_db(client, repo, &pack).await?;
        match (existing_manifest, existing_envelope) {
            (None, None) => {
                let value = serde_json::to_value(manifest)?;
                client
                    .execute(
                        "INSERT INTO pando_lab.object_store_manifests(repo,pack_id,bucket,pack_key,idx_key,manifest_key,pack_sha256,idx_sha256,pack_bytes,idx_bytes,object_count,chunk_size,chunk_count,manifest_json) \
                         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(repo,pack_id) DO NOTHING",
                        &[&repo,&pack_id,&opts.bucket,&manifest.pack_key,&manifest.idx_key,&remote_manifest_key(repo, manifest)?.path(),
                            pack_sha256,idx_sha256,&(manifest.pack_bytes as i64),&(manifest.idx_bytes as i64),
                            &(manifest.object_count as i64),&(manifest.chunk_size as i64),
                            &(manifest.pack_chunks.len() as i64),&value],
                    )
                    .await?;
                if let Some(policy) = local_policy {
                    lifecycle::rotation::sync_kms_policy_to_db(client, repo, policy).await?;
                }
                insert_envelope_if_absent(client, env).await?;
                let row = load_manifest_row(client, repo, pack_id)
                    .await?
                    .context("Pando manifest vanished inside its publication transaction")?;
                let stored_envelope = lifecycle::load_envelope_from_db(client, repo, &pack)
                    .await?
                    .context("Pando KMS envelope vanished inside its publication transaction")?;
                validate_manifest_record(&row.manifest, repo, pack_id)?;
                ensure!(
                    row.manifest.bucket == opts.bucket
                        && row.manifest.pack_sha256 == pack_sha256
                        && row.manifest.idx_sha256 == idx_sha256,
                    "Pando manifest publication lost its immutable identity"
                );
                ensure!(
                    row.pack_sha256 == pack_sha256 && row.idx_sha256 == idx_sha256,
                    "Pando manifest columns lost their immutable identity"
                );
                ensure!(
                    row.manifest_key == remote_manifest_key(repo, &row.manifest)?.path(),
                    "Pando remote manifest key mismatch"
                );
                validate_db_envelope(
                    &stored_envelope,
                    repo,
                    pack_id,
                    pack_sha256,
                    idx_sha256,
                    &row.manifest,
                )?;
                Ok((recovered_report(repo, pack_id, &row.manifest)?, stored_envelope))
            }
            (Some(row), Some(stored_envelope)) => {
                validate_manifest_record(&row.manifest, repo, pack_id)?;
                ensure!(
                    row.manifest.bucket == opts.bucket
                        && row.manifest.pack_sha256 == pack_sha256
                        && row.manifest.idx_sha256 == idx_sha256,
                    "immutable Pando pack digest or bucket collision"
                );
                ensure!(
                    row.pack_sha256 == pack_sha256 && row.idx_sha256 == idx_sha256,
                    "immutable Pando manifest columns diverged"
                );
                ensure!(
                    row.manifest_key == remote_manifest_key(repo, &row.manifest)?.path(),
                    "Pando remote manifest key mismatch"
                );
                validate_db_envelope(
                    &stored_envelope,
                    repo,
                    pack_id,
                    pack_sha256,
                    idx_sha256,
                    &row.manifest,
                )?;
                Ok((recovered_report(repo, pack_id, &row.manifest)?, stored_envelope))
            }
            _ => bail!(
                "inconsistent Pando publication rows for pack {pack_id}: refusing to publish a partial manifest/envelope pair"
            ),
        }
    }
    .await;

    match result {
        Ok((report, stored_envelope)) => {
            client.batch_execute("COMMIT").await.context("Pando publication commit failed")?;
            // The DB pair is authoritative; a mirror failure cannot make the
            // retry generate replacement ciphertext.
            let _ = lifecycle::write_envelope_file(&config.root, &stored_envelope);
            Ok(report)
        }
        Err(err) => {
            let _ = client.batch_execute("ROLLBACK").await;
            Err(err)
        }
    }
}

async fn scan(path: &Path, chunk_size: usize) -> Result<(String, u64, Vec<ChunkPartReceipt>)> {
    ensure!((4096..=8 * 1024 * 1024).contains(&chunk_size), "remote pack chunk size must be 4 KiB through 8 MiB");
    let mut source = File::open(path).await?;
    let mut whole = Sha256::new();
    let mut chunks = Vec::new();
    let mut buf = vec![0u8; chunk_size];
    let mut offset = 0u64;
    loop {
        let mut used = 0;
        while used < buf.len() {
            let n = source.read(&mut buf[used..]).await?;
            if n == 0 {
                break;
            }
            used += n;
        }
        if used == 0 {
            break;
        }
        ensure!(chunks.len() < 10_000, "remote pack has too many chunks");
        whole.update(&buf[..used]);
        let at = usize::try_from(offset).context("pack offset exceeds address space")?;
        chunks.push(ChunkPartReceipt {
            part_number: chunks.len() + 1,
            offset: at,
            size_bytes: used,
            sha256: hex::encode(Sha256::digest(&buf[..used])),
        });
        offset = offset.checked_add(used as u64).context("pack length overflow")?;
        if used < buf.len() {
            break;
        }
    }
    ensure!(offset == source.metadata().await?.len(), "pack changed while scanning");
    Ok((hex::encode(whole.finalize()), offset, chunks))
}

async fn pack_object_count(config: &Config, pack: &Path) -> Result<usize> {
    let mut file = File::open(pack).await?;
    let mut header = [0u8; 12];
    file.read_exact(&mut header).await?;
    ensure!(
        &header[..4] == b"PACK" && u32::from_be_bytes(header[4..8].try_into()?) == 2,
        "unsupported Git pack header"
    );
    let count = u32::from_be_bytes(header[8..12].try_into()?) as usize;
    ensure!(count <= delta::MAX_OBJECTS, "Git pack object count exceeds limit");
    let status = tokio::time::timeout(
        Duration::from_secs(120),
        tokio::process::Command::new(&config.git)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(["index-pack", "--verify"])
            .arg(pack)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .status(),
    )
    .await??;
    ensure!(status.success(), "Git pack/index verification failed");
    Ok(count)
}

pub(super) async fn put(
    config: &Config,
    repo: Uuid,
    pack_id: Uuid,
    opts: &ObjectStorePutOptions,
) -> Result<ObjectStorePutReport> {
    ensure!(
        opts.fail_after_chunks.is_none() && opts.corrupt_chunk_part.is_none(),
        "local multipart fault flags do not apply to network S3"
    );
    ensure!(
        opts.bucket == std::env::var("ROOTYARD_OBJECT_STORE_BUCKET")?,
        "Pando bucket differs from configured object-store bucket"
    );
    let (pack, idx) = local_paths(config, repo, pack_id);
    let object_count = pack_object_count(config, &pack).await?;
    let (pack_sha256, pack_bytes, _plain_chunks) = scan(&pack, opts.chunk_size).await?;
    let (idx_sha256, idx_bytes, idx_chunks) = scan(&idx, opts.chunk_size).await?;
    if let Some(expected) = &opts.expected_pack_sha256 {
        ensure!(expected == &pack_sha256, "expected pack SHA-256 mismatch");
    }
    if let Some(expected) = opts.expected_pack_bytes {
        ensure!(expected == pack_bytes, "expected pack byte length mismatch");
    }
    let suite = opts.cipher_suite.as_deref().unwrap_or(lifecycle::DEFAULT_CIPHER_SUITE);
    let session = lifecycle::publication::writer_session(config, repo).await?;
    let checkpoint = lifecycle::publication::active_rotation(session.client(), repo).await?;
    // A retry of an already-committed publication is recovered before provider
    // selection or any network upload, so randomized ciphertext is never
    // regenerated for an immutable pack.
    if let Some(report) =
        check_existing_publication(session.client(), config, repo, pack_id, &pack_sha256, &idx_sha256, &opts.bucket)
            .await?
    {
        return Ok(report);
    }
    let provider = lifecycle::provider_selection::for_write(&config.root, repo, checkpoint.as_ref())?;
    let plain_bytes = fs::read(&pack).await?;
    let sealed = lifecycle::crypto::seal_pack_bytes(
        provider.provider(),
        repo,
        pack_id,
        &idx_sha256,
        suite,
        provider.key_version_hint(),
        &plain_bytes,
    )
    .await?;
    let local_policy = provider.into_local_policy();
    let env = lifecycle::build_authenticated_envelope_record(
        repo,
        &Pack { id: pack_id, pack_sha256: pack_sha256.clone(), idx_sha256: idx_sha256.clone() },
        &sealed,
        "hot",
    )?;
    let store = remote_store(config)?;
    let pack_key = key(repo, "pando-pack", &sealed.ciphertext_sha256)?;
    let idx_key = key(repo, "pando-index", &idx_sha256)?;
    let enc_temp = config.root.join(format!(".pando-enc-{}", Uuid::new_v4()));
    let enc_res = async {
        fs::write(&enc_temp, &sealed.ciphertext).await?;
        let (_cs, _cl, enc_chunks) = scan(&enc_temp, opts.chunk_size).await?;
        store.put_file(&pack_key, &enc_temp, sealed.ciphertext_bytes, deadline()).await?;
        Ok::<Vec<ChunkPartReceipt>, anyhow::Error>(enc_chunks)
    }
    .await;
    let _ = fs::remove_file(&enc_temp).await;
    let pack_chunks = enc_res?;
    store.put_file(&idx_key, &idx, idx_bytes, deadline()).await?;
    let mut manifest = CasPackManifest {
        schema: object_store::MANIFEST_SCHEMA.into(),
        bucket: opts.bucket.clone(),
        backend: object_store::BACKEND_KIND.into(),
        repo,
        pack_id,
        pack_key: pack_key.path(),
        idx_key: idx_key.path(),
        manifest_key: object_store::manifest_key(repo, pack_id),
        pack_sha256: pack_sha256.clone(),
        idx_sha256: idx_sha256.clone(),
        pack_bytes,
        idx_bytes,
        object_count,
        chunk_size: opts.chunk_size,
        pack_chunks,
        idx_chunks,
        manifest_sha256: String::new(),
        encryption_mode: Some(lifecycle::crypto::AUTHENTICATED_ENVELOPE_MODE.into()),
        ciphertext_sha256: Some(sealed.ciphertext_sha256.clone()),
        ciphertext_bytes: Some(sealed.ciphertext_bytes),
        cipher_suite: Some(sealed.cipher_suite.clone()),
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
        publish_on_writer_session(
            session.client(),
            config,
            repo,
            pack_id,
            opts,
            &manifest,
            &env,
            local_policy.as_ref(),
            &pack_sha256,
            &idx_sha256,
        )
        .await
    }
    .await;
    let _ = fs::remove_file(&temp).await;
    publication
}

pub(super) async fn get(config: &Config, repo: Uuid, pack_id: Uuid) -> Result<ObjectStoreGetReport> {
    let client = config.db().await?;
    let row = client
        .query_one(
            "SELECT manifest_json,manifest_key FROM pando_lab.object_store_manifests WHERE repo=$1 AND pack_id=$2",
            &[&repo, &pack_id],
        )
        .await?;
    let manifest: CasPackManifest = serde_json::from_value(row.get(0))?;
    let (cipher_sha, cipher_bytes) = validate_manifest_record(&manifest, repo, pack_id)?;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    let manifest_digest = hex::encode(Sha256::digest(&manifest_bytes));
    let manifest_key = key(repo, "pando-manifest", &manifest_digest)?;
    ensure!(row.get::<_, String>(1) == manifest_key.path(), "Pando remote manifest key mismatch");
    let store = remote_store(config)?;
    let temp = config.root.join(format!(".pando-verify-{}", Uuid::new_v4()));
    let verified = async {
        store.get_to_file(&manifest_key, &temp, manifest_bytes.len() as u64, deadline()).await?;
        ensure!(fs::read(&temp).await? == manifest_bytes, "remote Pando manifest differs from database");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let _ = fs::remove_file(&temp).await;
    verified?;
    let (pack, idx) = local_paths(config, repo, pack_id);
    let pack_key = key(repo, "pando-pack", &cipher_sha)?;
    let idx_key = key(repo, "pando-index", &manifest.idx_sha256)?;
    ensure!(
        manifest.pack_key == pack_key.path() && manifest.idx_key == idx_key.path(),
        "Pando remote artifact key mismatch"
    );
    let pack_obj =
        Pack { id: pack_id, pack_sha256: manifest.pack_sha256.clone(), idx_sha256: manifest.idx_sha256.clone() };
    // The committed DB envelope is the read authority. A missing or stale file
    // mirror must never select an older wrapper or fail this read.
    let env = lifecycle::load_envelope_from_db(&client, repo, &pack_obj)
        .await?
        .context("missing DB KMS envelope for a published Pando pack")?;
    validate_db_envelope(&env, repo, pack_id, &manifest.pack_sha256, &manifest.idx_sha256, &manifest)?;
    // Repair the private file mirror best-effort after the DB authority and
    // record identity have been verified.
    let _ = lifecycle::write_envelope_file(&config.root, &env);
    let cache_hit = pack.is_file()
        && idx.is_file()
        && scan(&pack, manifest.chunk_size)
            .await
            .ok()
            .is_some_and(|x| x.0 == manifest.pack_sha256 && x.1 == manifest.pack_bytes)
        && scan(&idx, manifest.chunk_size)
            .await
            .ok()
            .is_some_and(|x| x.0 == manifest.idx_sha256 && x.1 == manifest.idx_bytes);
    if !cache_hit {
        let cipher_tmp = config.root.join(format!(".pando-dec-{}", Uuid::new_v4()));
        let dec_res = async {
            store.get_to_file(&pack_key, &cipher_tmp, cipher_bytes, deadline()).await?;
            let c_bytes = fs::read(&cipher_tmp).await?;
            lifecycle::rotation::verify_and_decrypt_pack_bytes(&config.root, repo, &pack_obj, &env, &c_bytes).await
        }
        .await;
        let _ = fs::remove_file(&cipher_tmp).await;
        let plain = dec_res?;
        if let Some(parent) = pack.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&pack, &plain).await?;
        store.get_to_file(&idx_key, &idx, manifest.idx_bytes, deadline()).await?;
    }
    ensure!(
        pack_object_count(config, &pack).await? == manifest.object_count,
        "remote Pando pack object count mismatch"
    );
    Ok(ObjectStoreGetReport {
        repo,
        pack_id,
        bucket: manifest.bucket,
        pack_sha256: manifest.pack_sha256,
        idx_sha256: manifest.idx_sha256,
        pack_bytes: manifest.pack_bytes,
        idx_bytes: manifest.idx_bytes,
        cache_hit,
        rehydrated_from_object_store: !cache_hit,
        local_pack_path: pack.to_string_lossy().into_owned(),
        local_idx_path: idx.to_string_lossy().into_owned(),
        verified: true,
    })
}

pub(super) async fn verify(config: &Config, repo: Uuid) -> Result<ObjectStoreVerifyReport> {
    let client = config.db().await?;
    let rows = client.query("SELECT pack_id FROM pando_lab.object_store_manifests WHERE repo=$1", &[&repo]).await?;
    let mut result = ObjectStoreVerifyReport {
        repo,
        bucket: std::env::var("ROOTYARD_OBJECT_STORE_BUCKET")?,
        manifests_checked: 0,
        packs_verified: 0,
        total_pack_bytes: 0,
        total_idx_bytes: 0,
        orphan_staging_cleaned: 0,
        verified: true,
    };
    for row in rows {
        let report = get(config, repo, row.get(0)).await?;
        result.manifests_checked += 1;
        result.packs_verified += 1;
        result.total_pack_bytes += report.pack_bytes;
        result.total_idx_bytes += report.idx_bytes;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_fixture(repo: Uuid, pack_id: Uuid) -> CasPackManifest {
        let pack_sha256 = "11".repeat(32);
        let idx_sha256 = "22".repeat(32);
        let ciphertext_sha256 = "33".repeat(32);
        let mut manifest = CasPackManifest {
            schema: object_store::MANIFEST_SCHEMA.into(),
            bucket: object_store::DEFAULT_BUCKET.into(),
            backend: object_store::BACKEND_KIND.into(),
            repo,
            pack_id,
            pack_key: key(repo, "pando-pack", &ciphertext_sha256).unwrap().path(),
            idx_key: key(repo, "pando-index", &idx_sha256).unwrap().path(),
            manifest_key: object_store::manifest_key(repo, pack_id),
            pack_sha256,
            idx_sha256,
            pack_bytes: 123,
            idx_bytes: 45,
            object_count: 1,
            chunk_size: 4096,
            pack_chunks: Vec::new(),
            idx_chunks: Vec::new(),
            manifest_sha256: String::new(),
            encryption_mode: Some(lifecycle::crypto::AUTHENTICATED_ENVELOPE_MODE.into()),
            ciphertext_sha256: Some(ciphertext_sha256),
            ciphertext_bytes: Some(234),
            cipher_suite: Some(lifecycle::DEFAULT_CIPHER_SUITE.into()),
        };
        let mut unsigned = manifest.clone();
        unsigned.manifest_sha256.clear();
        manifest.manifest_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&unsigned).unwrap()));
        manifest
    }

    #[test]
    fn immutable_manifest_identity_binds_repo_pack_digest_and_ciphertext_keys() {
        let repo = Uuid::new_v4();
        let pack_id = Uuid::new_v4();
        let manifest = manifest_fixture(repo, pack_id);
        let (cipher_sha256, ciphertext_bytes) = validate_manifest_record(&manifest, repo, pack_id).unwrap();
        assert_eq!(cipher_sha256, "33".repeat(32));
        assert_eq!(ciphertext_bytes, 234);

        let mut wrong_pack = manifest.clone();
        wrong_pack.pack_id = Uuid::new_v4();
        assert!(validate_manifest_record(&wrong_pack, repo, pack_id).is_err());

        let mut wrong_digest = manifest.clone();
        wrong_digest.pack_sha256 = "44".repeat(32);
        assert!(validate_manifest_record(&wrong_digest, repo, pack_id).is_err());

        let mut wrong_ciphertext_key = manifest.clone();
        wrong_ciphertext_key.ciphertext_sha256 = Some("55".repeat(32));
        assert!(validate_manifest_record(&wrong_ciphertext_key, repo, pack_id).is_err());
    }
}
