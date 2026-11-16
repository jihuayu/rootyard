use super::{
    ENVELOPE_SCHEMA, KmsEnvelopeRecord, crypto, valid_cipher_suite,
    valid_encryption_mode, valid_kms_key_id, valid_sha256_hex, valid_storage_tier,
};
use super::wrapped_dek::PandoWrappedDek;
use super::super::{Pack, delta};
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub fn compute_envelope_mac(
    key_id: &str,
    key_version: i32,
    pack_sha256: &str,
    idx_sha256: &str,
) -> Result<String> {
    let trimmed = key_id.trim();
    ensure!(
        valid_kms_key_id(trimmed) && key_version >= 1,
        "invalid kms key parameters"
    );
    ensure!(
        valid_sha256_hex(pack_sha256) && valid_sha256_hex(idx_sha256),
        "invalid pack/idx sha256"
    );
    Ok(delta::sha256_hex(
        format!("{trimmed}||{key_version}||{pack_sha256}||{idx_sha256}").as_bytes(),
    ))
}

/// Builds an explicitly labeled synthetic metadata-only lab envelope (does NOT encrypt pack bytes).
pub fn build_envelope_record(
    repo: Uuid,
    pack: &Pack,
    key_id: &str,
    key_version: i32,
    cipher_suite: &str,
    storage_tier: &str,
) -> Result<KmsEnvelopeRecord> {
    let trimmed = key_id.trim();
    ensure!(
        valid_kms_key_id(trimmed)
            && valid_cipher_suite(cipher_suite)
            && valid_storage_tier(storage_tier),
        "invalid envelope parameters"
    );
    let envelope_mac =
        compute_envelope_mac(trimmed, key_version, &pack.pack_sha256, &pack.idx_sha256)?;
    Ok(KmsEnvelopeRecord {
        schema: ENVELOPE_SCHEMA.to_owned(),
        repo,
        pack_id: pack.id,
        key_id: trimmed.to_owned(),
        key_version,
        cipher_suite: cipher_suite.to_owned(),
        pack_sha256: pack.pack_sha256.clone(),
        idx_sha256: pack.idx_sha256.clone(),
        plaintext_sha256: pack.pack_sha256.clone(),
        envelope_mac,
        storage_tier: storage_tier.to_owned(),
        encryption_mode: crypto::SYNTHETIC_METADATA_MODE.to_owned(),
        envelope_id: None,
        nonce_prefix: None,
        wrapped_key_json: None,
        ciphertext_sha256: None,
        ciphertext_bytes: None,
        provider_kind: crypto::SYNTHETIC_METADATA_MODE.to_owned(),
    })
}

pub fn build_authenticated_envelope_record(
    repo: Uuid,
    pack: &Pack,
    sealed: &crypto::SealedPackArtifact,
    storage_tier: &str,
) -> Result<KmsEnvelopeRecord> {
    ensure!(
        valid_kms_key_id(&sealed.key_id)
            && sealed.key_version >= 1
            && valid_cipher_suite(&sealed.cipher_suite)
            && valid_storage_tier(storage_tier)
            && sealed.plaintext_sha256 == pack.pack_sha256,
        "invalid authenticated envelope parameters"
    );
    PandoWrappedDek::from_json(sealed.wrapped_key_json.as_bytes())
        .map_err(|err| anyhow::anyhow!("invalid wrapped DEK in envelope: {err}"))?
        .validate_binding(&sealed.provider_kind, &sealed.key_id, sealed.key_version)
        .map_err(|err| anyhow::anyhow!("wrapped DEK does not match envelope identity: {err}"))?;
    let mac = crypto::compute_authenticated_envelope_mac(&crypto::EnvelopeMacInputs {
        encryption_mode: crypto::AUTHENTICATED_ENVELOPE_MODE,
        repo,
        pack_id: pack.id,
        key_id: &sealed.key_id,
        key_version: sealed.key_version,
        cipher_suite: &sealed.cipher_suite,
        pack_sha256: &pack.pack_sha256,
        idx_sha256: &pack.idx_sha256,
        ciphertext_sha256: &sealed.ciphertext_sha256,
        ciphertext_bytes: sealed.ciphertext_bytes,
        envelope_id: sealed.envelope_id,
        nonce_prefix: &sealed.nonce_prefix_hex,
        wrapped_key_json: &sealed.wrapped_key_json,
    });
    Ok(KmsEnvelopeRecord {
        schema: ENVELOPE_SCHEMA.to_owned(),
        repo,
        pack_id: pack.id,
        key_id: sealed.key_id.clone(),
        key_version: sealed.key_version,
        cipher_suite: sealed.cipher_suite.clone(),
        pack_sha256: pack.pack_sha256.clone(),
        idx_sha256: pack.idx_sha256.clone(),
        plaintext_sha256: pack.pack_sha256.clone(),
        envelope_mac: mac,
        storage_tier: storage_tier.to_owned(),
        encryption_mode: crypto::AUTHENTICATED_ENVELOPE_MODE.to_owned(),
        envelope_id: Some(sealed.envelope_id),
        nonce_prefix: Some(sealed.nonce_prefix_hex.clone()),
        wrapped_key_json: Some(sealed.wrapped_key_json.clone()),
        ciphertext_sha256: Some(sealed.ciphertext_sha256.clone()),
        ciphertext_bytes: Some(sealed.ciphertext_bytes),
        provider_kind: sealed.provider_kind.clone(),
    })
}

pub fn verify_envelope_record(env: &KmsEnvelopeRecord) -> Result<()> {
    ensure!(
        env.schema == ENVELOPE_SCHEMA
            && valid_kms_key_id(&env.key_id)
            && env.key_version >= 1
            && valid_cipher_suite(&env.cipher_suite)
            && valid_storage_tier(&env.storage_tier)
            && env.plaintext_sha256 == env.pack_sha256
            && valid_encryption_mode(&env.encryption_mode),
        "invalid KMS envelope fields"
    );
    if crypto::is_authenticated_mode(&env.encryption_mode) {
        let envelope_id = env.envelope_id.context("missing envelope_id in envelope")?;
        let nonce = env.nonce_prefix.as_deref().context("missing nonce_prefix")?;
        let wrapped = env
            .wrapped_key_json
            .as_deref()
            .context("missing wrapped_key_json")?;
        let cipher_sha = env
            .ciphertext_sha256
            .as_deref()
            .context("missing ciphertext_sha256")?;
        let cipher_len = env.ciphertext_bytes.context("missing ciphertext_bytes")?;
        ensure!(valid_sha256_hex(cipher_sha), "invalid ciphertext_sha256");
        PandoWrappedDek::from_json(wrapped.as_bytes())
            .map_err(|err| anyhow::anyhow!("invalid wrapped DEK in envelope: {err}"))?
            .validate_binding(&env.provider_kind, &env.key_id, env.key_version)
            .map_err(|err| anyhow::anyhow!("wrapped DEK does not match envelope identity: {err}"))?;
        let expected = crypto::compute_authenticated_envelope_mac(&crypto::EnvelopeMacInputs {
            encryption_mode: &env.encryption_mode,
            repo: env.repo,
            pack_id: env.pack_id,
            key_id: &env.key_id,
            key_version: env.key_version,
            cipher_suite: &env.cipher_suite,
            pack_sha256: &env.pack_sha256,
            idx_sha256: &env.idx_sha256,
            ciphertext_sha256: cipher_sha,
            ciphertext_bytes: cipher_len,
            envelope_id,
            nonce_prefix: nonce,
            wrapped_key_json: wrapped,
        });
        ensure!(env.envelope_mac == expected, "authenticated KMS envelope MAC mismatch");
    } else {
        let expected =
            compute_envelope_mac(&env.key_id, env.key_version, &env.pack_sha256, &env.idx_sha256)?;
        ensure!(
            env.envelope_mac == expected,
            "KMS envelope MAC verification failed for pack {}",
            env.pack_id
        );
    }
    Ok(())
}

pub fn envelope_file_path(root: &Path, repo: Uuid, pack_id: Uuid) -> PathBuf {
    root.join("object_store")
        .join("envelopes")
        .join(repo.to_string())
        .join(format!("{pack_id}.json"))
}

pub fn write_envelope_file(root: &Path, env: &KmsEnvelopeRecord) -> Result<PathBuf> {
    verify_envelope_record(env)?;
    let path = envelope_file_path(root, env.repo, env.pack_id);
    let parent = path.parent().context("missing envelope parent directory")?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".env-tmp-{}", Uuid::new_v4()));
    let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(env)?)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, &path)?;
    File::open(parent)?.sync_all()?;
    Ok(path)
}

pub fn read_and_verify_envelope_file(
    root: &Path,
    repo: Uuid,
    pack_id: Uuid,
) -> Result<KmsEnvelopeRecord> {
    let path = envelope_file_path(root, repo, pack_id);
    ensure!(path.is_file(), "missing KMS envelope file for pack {pack_id}");
    let env: KmsEnvelopeRecord = serde_json::from_slice(&std::fs::read(&path)?)?;
    ensure!(
        env.repo == repo && env.pack_id == pack_id,
        "KMS envelope repo/pack_id mismatch"
    );
    verify_envelope_record(&env)?;
    Ok(env)
}
