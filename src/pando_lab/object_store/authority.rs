//! DB pair validation and transaction helpers for staged local-CAS publication.

use super::super::{LIMIT, Pack, delta, lifecycle};
use super::{BACKEND_KIND, CasPackManifest, MANIFEST_SCHEMA, ObjectStorePutReport, idx_key, manifest_key, pack_key};
use anyhow::{Context, Result, bail, ensure};
use std::path::Path;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

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

/// Load and validate an existing authoritative pair. A manifest-only or
/// envelope-only state is never repaired or overwritten by a writer.
pub(super) async fn load_existing_pair(
    client: &Client,
    repo: Uuid,
    pack_id: Uuid,
    bucket: &str,
    pack_sha256: &str,
    idx_sha256: &str,
) -> Result<Option<(CasPackManifest, lifecycle::KmsEnvelopeRecord)>> {
    let manifest_row = load_manifest_row(client, repo, pack_id).await?;
    let pack = Pack { id: pack_id, pack_sha256: pack_sha256.to_owned(), idx_sha256: idx_sha256.to_owned() };
    let envelope = lifecycle::load_envelope_from_db(client, repo, &pack).await?;
    match (manifest_row, envelope) {
        (None, None) => Ok(None),
        (Some(row), Some(envelope)) => {
            validate_manifest_record(&row.manifest, repo, pack_id, bucket, pack_sha256, idx_sha256)?;
            ensure!(
                row.manifest_key == row.manifest.manifest_key
                    && row.pack_sha256 == row.manifest.pack_sha256
                    && row.idx_sha256 == row.manifest.idx_sha256,
                "DB Pando manifest columns diverge from the immutable manifest"
            );
            validate_envelope_record(&envelope, &row.manifest, repo, pack_id)?;
            Ok(Some((row.manifest, envelope)))
        }
        _ => bail!(
            "inconsistent Pando publication rows for pack {pack_id}: the manifest and DB KMS envelope must both exist"
        ),
    }
}

pub(super) async fn insert_envelope_if_absent_in_tx(
    t: &Transaction<'_>,
    env: &lifecycle::KmsEnvelopeRecord,
) -> Result<u64> {
    let inserted = t.execute(
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
    Ok(inserted)
}

pub(super) fn verify_fresh_target(
    prepared: Option<&lifecycle::rotation::KmsRotationCheckpoint>,
    fresh: Option<&lifecycle::rotation::KmsRotationCheckpoint>,
    envelope: &lifecycle::KmsEnvelopeRecord,
) -> Result<()> {
    match (prepared, fresh) {
        (None, None) => Ok(()),
        (Some(prepared), Some(fresh)) => {
            ensure!(
                prepared.rotation_id == fresh.rotation_id
                    && prepared.state == fresh.state
                    && prepared.write_epoch == fresh.write_epoch,
                "Pando rotation checkpoint changed after publication preparation"
            );
            ensure!(
                envelope.provider_kind == fresh.to_provider_kind
                    && envelope.key_id == fresh.to_key_id
                    && envelope.key_version == fresh.expected_version(),
                "prepared Pando envelope does not match the fresh rotation target"
            );
            Ok(())
        }
        (None, Some(_)) => bail!("an active Pando rotation checkpoint appeared after publication preparation"),
        (Some(_), None) => bail!("the active Pando rotation checkpoint disappeared after publication preparation"),
    }
}

/// Validate the immutable local manifest record and every key it binds.
pub(crate) fn validate_manifest_record(
    manifest: &CasPackManifest,
    repo: Uuid,
    pack_id: Uuid,
    bucket: &str,
    pack_sha256: &str,
    idx_sha256: &str,
) -> Result<()> {
    let mut unsigned = manifest.clone();
    unsigned.manifest_sha256.clear();
    ensure!(
        manifest.schema == MANIFEST_SCHEMA
            && manifest.backend == BACKEND_KIND
            && manifest.repo == repo
            && manifest.pack_id == pack_id,
        "Pando local manifest identity or schema mismatch"
    );
    ensure!(
        manifest.manifest_sha256 == delta::sha256_hex(&serde_json::to_vec(&unsigned)?),
        "Pando local manifest digest mismatch"
    );
    ensure!(
        manifest.encryption_mode.as_deref() == Some(lifecycle::crypto::AUTHENTICATED_ENVELOPE_MODE),
        "Pando local manifest lacks authenticated encryption mode"
    );
    let ciphertext_sha = manifest.ciphertext_sha256.as_deref().context("missing local ciphertext_sha256")?;
    let ciphertext_bytes = manifest.ciphertext_bytes.context("missing local ciphertext_bytes")?;
    ensure!(
        lifecycle::valid_sha256_hex(ciphertext_sha)
            && ciphertext_bytes <= LIMIT as u64
            && manifest.pack_bytes <= LIMIT as u64
            && manifest.idx_bytes <= LIMIT as u64,
        "Pando local manifest carries invalid ciphertext or size fields"
    );
    ensure!(
        manifest.bucket == bucket
            && manifest.pack_key == pack_key(bucket, repo, pack_id)
            && manifest.idx_key == idx_key(bucket, repo, pack_id)
            && manifest.manifest_key == manifest_key(repo, pack_id),
        "Pando local artifact key mismatch"
    );
    ensure!(
        manifest.pack_sha256 == pack_sha256 && manifest.idx_sha256 == idx_sha256,
        "Pando local manifest does not bind the requested pack identity"
    );
    ensure!(
        manifest.chunk_size >= 1 && !manifest.pack_chunks.is_empty() && !manifest.idx_chunks.is_empty(),
        "Pando local manifest has invalid chunk metadata"
    );
    Ok(())
}

/// Validate that an authenticated envelope is the exact wrapper for the
/// manifest/ciphertext pair. This deliberately repeats the immutable binding
/// checks rather than trusting the DB row alone.
pub(crate) fn validate_envelope_record(
    env: &lifecycle::KmsEnvelopeRecord,
    manifest: &CasPackManifest,
    repo: Uuid,
    pack_id: Uuid,
) -> Result<()> {
    ensure!(env.repo == repo && env.pack_id == pack_id, "DB KMS envelope repo/pack_id mismatch");
    lifecycle::verify_envelope_record(env)?;
    ensure!(
        env.pack_sha256 == manifest.pack_sha256
            && env.idx_sha256 == manifest.idx_sha256
            && env.plaintext_sha256 == manifest.pack_sha256,
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

pub(super) fn report_from_manifest(store_root_dir: &Path, manifest: &CasPackManifest) -> ObjectStorePutReport {
    ObjectStorePutReport {
        repo: manifest.repo,
        pack_id: manifest.pack_id,
        bucket: manifest.bucket.clone(),
        backend: BACKEND_KIND.to_owned(),
        // A recovered publication has no local upload identifier.
        upload_id: Uuid::nil(),
        pack_key: manifest.pack_key.clone(),
        idx_key: manifest.idx_key.clone(),
        manifest_key: manifest.manifest_key.clone(),
        bucket_pack_path: store_root_dir.join(&manifest.pack_key).to_string_lossy().into_owned(),
        bucket_idx_path: store_root_dir.join(&manifest.idx_key).to_string_lossy().into_owned(),
        manifest_path: store_root_dir.join(&manifest.manifest_key).to_string_lossy().into_owned(),
        pack_sha256: manifest.pack_sha256.clone(),
        idx_sha256: manifest.idx_sha256.clone(),
        pack_bytes: manifest.pack_bytes,
        idx_bytes: manifest.idx_bytes,
        object_count: manifest.object_count,
        chunk_size: manifest.chunk_size,
        chunk_count: manifest.pack_chunks.len(),
        total_chunks_uploaded: manifest.pack_chunks.len() + manifest.idx_chunks.len(),
        immutable_mode: "0444".to_owned(),
        status: "published".to_owned(),
    }
}

pub(super) fn verify_existing_cas_bytes(store_root_dir: &Path, manifest: &CasPackManifest) -> Result<Vec<u8>> {
    let ciphertext_sha =
        manifest.ciphertext_sha256.as_deref().context("missing ciphertext_sha256 in immutable CAS manifest")?;
    let ciphertext_bytes = manifest.ciphertext_bytes.context("missing ciphertext_bytes in immutable CAS manifest")?;
    let cipher = std::fs::read(store_root_dir.join(&manifest.pack_key))?;
    let idx = std::fs::read(store_root_dir.join(&manifest.idx_key))?;
    ensure!(
        cipher.len() as u64 == ciphertext_bytes && delta::sha256_hex(&cipher) == ciphertext_sha,
        "immutable CAS ciphertext no longer matches its manifest"
    );
    ensure!(
        idx.len() as u64 == manifest.idx_bytes && delta::sha256_hex(&idx) == manifest.idx_sha256,
        "immutable CAS index no longer matches its manifest"
    );
    Ok(cipher)
}
