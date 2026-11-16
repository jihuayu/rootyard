//! Staged, reusable local-CAS publication for Pando packs.
//!
//! Provider selection, sealing and immutable CAS writes happen before any SQL
//! transaction. `PreparedPackPublication::publish_in` then commits the
//! manifest, optional Local policy and authenticated envelope as one caller
//! owned transaction. The DB pair is authoritative; the envelope file is a
//! post-commit mirror only.

use super::super::{LIMIT, Pack, delta, lifecycle};
use super::authority::{
    insert_envelope_if_absent_in_tx, load_existing_pair, report_from_manifest, validate_envelope_record,
    validate_manifest_record, verify_existing_cas_artifacts, verify_existing_cas_bytes, verify_fresh_target,
};
use super::{
    BACKEND_KIND, CasPackManifest, MANIFEST_SCHEMA, ObjectStorePutOptions, ObjectStorePutReport, idx_key,
    infer_base_root, manifest_key, pack_key, stage_and_reassemble_multipart, write_immutable_cas_file,
};
use anyhow::{Context, Result, bail, ensure};
use std::path::{Path, PathBuf};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

/// Complete, authenticated local-CAS artifacts prepared outside SQL. Holding
/// this value never implies the DB pair exists.
pub(crate) struct PreparedPackPublication {
    repo: Uuid,
    pack_id: Uuid,
    report: ObjectStorePutReport,
    manifest: CasPackManifest,
    envelope: lifecycle::KmsEnvelopeRecord,
    local_policy: Option<lifecycle::provider::KmsKeyPolicy>,
    base_root: PathBuf,
    expected_checkpoint: Option<lifecycle::rotation::KmsRotationCheckpoint>,
}

impl PreparedPackPublication {
    pub(crate) fn report(&self) -> &ObjectStorePutReport {
        &self.report
    }

    pub(crate) fn manifest(&self) -> &CasPackManifest {
        &self.manifest
    }

    pub(crate) fn envelope(&self) -> &lifecycle::KmsEnvelopeRecord {
        &self.envelope
    }

    /// Commit the manifest, Local policy and authenticated envelope together.
    /// An existing complete pair is recovered without overwriting randomized
    /// ciphertext; a partial pair or a changed rotation target fails closed.
    pub(crate) async fn publish_in(&self, t: &Transaction<'_>) -> Result<lifecycle::KmsEnvelopeRecord> {
        let c = t.client();
        let pack_sha256 = &self.manifest.pack_sha256;
        let idx_sha256 = &self.manifest.idx_sha256;
        if let Some((_, envelope)) =
            load_existing_pair(c, self.repo, self.pack_id, &self.manifest.bucket, pack_sha256, idx_sha256).await?
        {
            return Ok(envelope);
        }

        // A first publication re-reads the authoritative checkpoint in this
        // exact transaction. The shared publication lock held by the caller
        // keeps rotation from changing it, but a stale prepared target must
        // still never commit.
        let fresh = lifecycle::publication::active_rotation(c, self.repo).await?;
        verify_fresh_target(self.expected_checkpoint.as_ref(), fresh.as_ref(), &self.envelope)?;

        let manifest_value = serde_json::to_value(&self.manifest)?;
        let inserted_manifest = t
            .execute(
                "INSERT INTO pando_lab.object_store_manifests(repo,pack_id,bucket,pack_key,idx_key,manifest_key,pack_sha256,idx_sha256,pack_bytes,idx_bytes,object_count,chunk_size,chunk_count,manifest_json) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(repo,pack_id) DO NOTHING",
                &[
                    &self.repo,
                    &self.pack_id,
                    &self.manifest.bucket,
                    &self.manifest.pack_key,
                    &self.manifest.idx_key,
                    &self.manifest.manifest_key,
                    pack_sha256,
                    idx_sha256,
                    &(self.manifest.pack_bytes as i64),
                    &(self.manifest.idx_bytes as i64),
                    &(self.manifest.object_count as i64),
                    &(self.manifest.chunk_size as i64),
                    &(self.manifest.pack_chunks.len() as i64),
                    &manifest_value,
                ],
            )
            .await?;
        // A concurrent complete pair won the insert. Its durable pair is
        // authority, so recover it and never overwrite a newer key policy.
        if inserted_manifest == 0 {
            let recovered =
                load_existing_pair(c, self.repo, self.pack_id, &self.manifest.bucket, pack_sha256, idx_sha256)
                    .await?
                    .context("Pando manifest appeared without an envelope inside the publication transaction")?;
            return Ok(recovered.1);
        }
        let inserted_envelope = insert_envelope_if_absent_in_tx(t, &self.envelope).await?;
        if inserted_envelope != 1 {
            bail!(
                "Pando KMS envelope appeared without a manifest inside the publication transaction; refusing to complete a partial pair"
            );
        }
        if let Some(policy) = &self.local_policy {
            lifecycle::rotation::sync_kms_policy_in_tx(t, self.repo, policy).await?;
        }

        let recovered = load_existing_pair(c, self.repo, self.pack_id, &self.manifest.bucket, pack_sha256, idx_sha256)
            .await?
            .context("Pando publication rows vanished inside their transaction")?;
        ensure!(
            recovered.0.pack_sha256 == self.manifest.pack_sha256 && recovered.0.idx_sha256 == self.manifest.idx_sha256,
            "Pando publication transaction lost its immutable pack identity"
        );
        Ok(recovered.1)
    }

    pub(super) fn write_mirror(&self) -> Result<()> {
        lifecycle::write_envelope_file(&self.base_root, &self.envelope)?;
        Ok(())
    }

    /// Best-effort mirror repair after the authoritative transaction commits.
    pub(crate) fn refresh_mirrors(&self) {
        let _ = self.write_mirror();
    }
}

/// Prepare immutable local CAS bytes and the complete authenticated metadata
/// without authority DB rows or an envelope mirror. A retry recovers an
/// existing complete pair before provider selection or resealing.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_pack_files_sealed(
    store_root_dir: &Path,
    local_objects_root: &Path,
    repo: Uuid,
    pack_id: Uuid,
    opts: &ObjectStorePutOptions,
    storage_tier: &str,
    checkpoint: Option<&lifecycle::rotation::KmsRotationCheckpoint>,
    client: Option<&Client>,
) -> Result<PreparedPackPublication> {
    // This primitive stages local CAS only. Composed S3 producers must use an
    // explicit remote prepare path; never let them silently fall back here.
    ensure!(
        !super::remote_enabled(),
        "staged local CAS publication is unsupported with ROOTYARD_OBJECT_STORE_ENDPOINT; composed remote publication must use an explicit remote prepare path"
    );
    ensure!(super::valid_bucket_name(&opts.bucket), "invalid bucket '{}'", opts.bucket);
    let suite = opts.cipher_suite.as_deref().unwrap_or(lifecycle::DEFAULT_CIPHER_SUITE);
    let local_dir = local_objects_root.join(repo.to_string());
    let pack_bytes = std::fs::read(local_dir.join(format!("{pack_id}.pack")))?;
    let idx_bytes = std::fs::read(local_dir.join(format!("{pack_id}.idx")))?;
    ensure!(pack_bytes.len() <= LIMIT && idx_bytes.len() <= LIMIT, "pack/idx exceeds limit");
    let pack_report = delta::verify_pack(&pack_bytes, &delta::Limits::default())?;
    let pack_sha256 = pack_report.pack_sha256.clone();
    let idx_sha256 = delta::sha256_hex(&idx_bytes);
    if let Some(ref exp_sha) = opts.expected_pack_sha256 {
        ensure!(exp_sha == &pack_sha256, "expected pack SHA-256 mismatch");
    }
    if let Some(exp_len) = opts.expected_pack_bytes {
        ensure!(exp_len == pack_bytes.len() as u64, "expected pack byte length mismatch");
    }

    let base_root = infer_base_root(store_root_dir, Some(local_objects_root)).to_path_buf();

    // Exact retry recovery happens before provider selection, sealing or any
    // randomized DEK/ciphertext regeneration.
    if let Some(c) = client {
        if let Some((manifest, envelope)) =
            load_existing_pair(c, repo, pack_id, &opts.bucket, &pack_sha256, &idx_sha256).await?
        {
            verify_existing_cas_artifacts(store_root_dir, &manifest)?;
            return Ok(PreparedPackPublication {
                repo,
                pack_id,
                report: report_from_manifest(store_root_dir, &manifest),
                manifest,
                envelope,
                local_policy: None,
                base_root,
                expected_checkpoint: checkpoint.cloned(),
            });
        }
    }

    let (p_key, i_key, m_key) =
        (pack_key(&opts.bucket, repo, pack_id), idx_key(&opts.bucket, repo, pack_id), manifest_key(repo, pack_id));
    let (b_pack, b_idx, m_path) =
        (store_root_dir.join(&p_key), store_root_dir.join(&i_key), store_root_dir.join(&m_key));

    if m_path.is_file() {
        ensure!(
            b_pack.is_file() && b_idx.is_file(),
            "partial immutable CAS artifacts for pack {pack_id}; refusing to reseal or overwrite"
        );
        let manifest: CasPackManifest = serde_json::from_slice(&std::fs::read(&m_path)?)?;
        validate_manifest_record(&manifest, repo, pack_id, &opts.bucket, &pack_sha256, &idx_sha256)?;
        let cipher = verify_existing_cas_bytes(store_root_dir, &manifest)?;
        let envelope = match client {
            // A DB envelope without a manifest row would have failed the pair
            // check above. Never adopt a file mirror as DB authority.
            Some(_) => bail!(
                "immutable CAS artifacts for pack {pack_id} exist without an authoritative DB manifest/envelope pair; refusing to reseal or overwrite"
            ),
            None => lifecycle::read_and_verify_envelope_file(&base_root, repo, pack_id)
                .context("immutable CAS artifacts exist without a verified envelope mirror")?,
        };
        validate_envelope_record(&envelope, &manifest, repo, pack_id)?;
        let pack =
            Pack { id: pack_id, pack_sha256: manifest.pack_sha256.clone(), idx_sha256: manifest.idx_sha256.clone() };
        let plaintext =
            lifecycle::rotation::verify_and_decrypt_pack_bytes(&base_root, repo, &pack, &envelope, &cipher).await?;
        ensure!(
            plaintext.len() as u64 == manifest.pack_bytes && delta::sha256_hex(&plaintext) == manifest.pack_sha256,
            "immutable CAS plaintext digest or length mismatch"
        );
        let reopened = delta::verify_pack(&plaintext, &delta::Limits::default())?;
        ensure!(reopened.object_count == manifest.object_count, "immutable CAS object count mismatch");
        return Ok(PreparedPackPublication {
            repo,
            pack_id,
            report: report_from_manifest(store_root_dir, &manifest),
            manifest,
            envelope,
            local_policy: None,
            base_root,
            expected_checkpoint: checkpoint.cloned(),
        });
    }

    ensure!(
        !b_pack.exists() && !b_idx.exists(),
        "orphan immutable CAS artifacts for pack {pack_id} exist without a manifest; refusing to overwrite"
    );

    let provider = lifecycle::provider_selection::for_write(&base_root, repo, checkpoint)?;
    let sealed = lifecycle::crypto::seal_pack_bytes(
        provider.provider(),
        repo,
        pack_id,
        &idx_sha256,
        suite,
        provider.key_version_hint(),
        &pack_bytes,
    )
    .await?;

    let upload_id = Uuid::new_v4();
    let mut chunks_uploaded = 0usize;
    let (pack_chunks, ver_cipher) = stage_and_reassemble_multipart(
        store_root_dir,
        upload_id,
        &sealed.ciphertext,
        &sealed.ciphertext_sha256,
        sealed.ciphertext_bytes,
        opts,
        &mut chunks_uploaded,
    )?;
    let idx_opts = ObjectStorePutOptions {
        corrupt_chunk_part: None,
        expected_pack_sha256: None,
        expected_pack_bytes: None,
        ..opts.clone()
    };
    let (idx_chunks, ver_idx) = stage_and_reassemble_multipart(
        store_root_dir,
        Uuid::new_v4(),
        &idx_bytes,
        &idx_sha256,
        idx_bytes.len() as u64,
        &idx_opts,
        &mut chunks_uploaded,
    )?;

    write_immutable_cas_file(&b_pack, &ver_cipher, &sealed.ciphertext_sha256)?;
    write_immutable_cas_file(&b_idx, &ver_idx, &idx_sha256)?;
    let mut manifest = CasPackManifest {
        schema: MANIFEST_SCHEMA.to_owned(),
        bucket: opts.bucket.clone(),
        backend: BACKEND_KIND.to_owned(),
        repo,
        pack_id,
        pack_key: p_key,
        idx_key: i_key,
        manifest_key: m_key,
        pack_sha256: pack_sha256.clone(),
        idx_sha256: idx_sha256.clone(),
        pack_bytes: pack_bytes.len() as u64,
        idx_bytes: ver_idx.len() as u64,
        object_count: pack_report.object_count,
        chunk_size: opts.chunk_size,
        pack_chunks,
        idx_chunks,
        manifest_sha256: String::new(),
        encryption_mode: Some(lifecycle::crypto::AUTHENTICATED_ENVELOPE_MODE.to_owned()),
        ciphertext_sha256: Some(sealed.ciphertext_sha256.clone()),
        ciphertext_bytes: Some(sealed.ciphertext_bytes),
        cipher_suite: Some(sealed.cipher_suite.clone()),
    };
    manifest.manifest_sha256 = delta::sha256_hex(&serde_json::to_vec(&manifest)?);
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    write_immutable_cas_file(&m_path, &manifest_bytes, &delta::sha256_hex(&manifest_bytes))?;
    verify_existing_cas_artifacts(store_root_dir, &manifest)?;
    let envelope = lifecycle::build_authenticated_envelope_record(
        repo,
        &Pack { id: pack_id, pack_sha256: pack_sha256.clone(), idx_sha256: idx_sha256.clone() },
        &sealed,
        storage_tier,
    )?;
    validate_manifest_record(&manifest, repo, pack_id, &opts.bucket, &pack_sha256, &idx_sha256)?;
    validate_envelope_record(&envelope, &manifest, repo, pack_id)?;
    if let Some(cp) = checkpoint {
        ensure!(
            envelope.provider_kind == cp.to_provider_kind
                && envelope.key_id == cp.to_key_id
                && envelope.key_version == cp.expected_version(),
            "prepared envelope does not match the authoritative rotation target"
        );
    }
    let local_policy = provider.into_local_policy();
    let mut report = report_from_manifest(store_root_dir, &manifest);
    report.upload_id = upload_id;
    Ok(PreparedPackPublication {
        repo,
        pack_id,
        report,
        manifest,
        envelope,
        local_policy,
        base_root,
        expected_checkpoint: checkpoint.cloned(),
    })
}
