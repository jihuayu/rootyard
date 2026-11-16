use super::super::super::{Pack, object_store};
use super::super::{
    ENVELOPE_SCHEMA, KmsEnvelopeRecord, provider,
    provider::PandoKeyProvider,
    vault_provider::VaultTransitProvider,
    wrapped_dek::PandoWrappedDek,
};
use anyhow::{Context, Result, ensure};
use std::path::Path;
use uuid::Uuid;

pub async fn verify_and_decrypt_pack_bytes(
    base_root: &Path,
    repo: Uuid,
    pack: &Pack,
    env: &KmsEnvelopeRecord,
    cipher_bytes: &[u8],
) -> Result<Vec<u8>> {
    let provider = super::provider_selection::for_envelope(base_root, repo, &env.provider_kind)?;
    provider.ensure_key_readable(&env.key_id, env.key_version)?;
    verify_with_provider(provider.as_key_provider(), repo, pack, env, cipher_bytes).await
}

async fn verify_with_provider(
    provider: &dyn super::provider::PandoKeyProvider,
    repo: Uuid,
    pack: &Pack,
    env: &KmsEnvelopeRecord,
    cipher_bytes: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        super::crypto::is_authenticated_mode(&env.encryption_mode),
        "pack {} uses synthetic mode '{}' instead of authenticated encryption",
        pack.id,
        env.encryption_mode
    );
    let exp_cipher_sha = env
        .ciphertext_sha256
        .as_deref()
        .context("missing ciphertext_sha256 in authenticated envelope")?;
    let exp_cipher_len = env
        .ciphertext_bytes
        .context("missing ciphertext_bytes in authenticated envelope")?;
    ensure!(
        cipher_bytes.len() as u64 == exp_cipher_len
            && super::crypto::sha256_hex(cipher_bytes) == exp_cipher_sha,
        "object-store ciphertext digest or length mismatch for pack {}",
        pack.id
    );
    let wrapped = env
        .wrapped_key_json
        .as_deref()
        .context("missing wrapped_key_json in authenticated envelope")?;
    super::crypto::open_sealed_pack_bytes(
        provider,
        &super::crypto::OpenSealedRequest {
            repo,
            pack_id: pack.id,
            expected_plaintext_sha256: &pack.pack_sha256,
            expected_idx_sha256: &pack.idx_sha256,
            expected_cipher_suite: &env.cipher_suite,
            expected_envelope_id: env.envelope_id,
            expected_nonce_prefix: env.nonce_prefix.as_deref(),
            wrapped_key_json: wrapped,
        },
        cipher_bytes,
    ).await
}

pub(in crate::pando_lab::lifecycle) async fn verify_pack_ciphertext_open(
    provider: &super::provider::PandoKmsProvider,
    s_root: &Path,
    repo: Uuid,
    pack: &Pack,
    env: &KmsEnvelopeRecord,
) -> Result<()> {
    let manifest_path = s_root.join(object_store::manifest_key(repo, pack.id));
    ensure!(
        manifest_path.is_file(),
        "missing object-store manifest for encrypted pack {}",
        pack.id
    );
    let manifest: object_store::CasPackManifest =
        serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    let cipher_bytes = std::fs::read(s_root.join(&manifest.pack_key))?;
    provider.ensure_key_readable(&env.key_id, env.key_version)?;
    let _plain = verify_with_provider(provider, repo, pack, env, &cipher_bytes).await?;
    Ok(())
}

pub(super) async fn rewrap_existing_envelope(
    provider: &super::provider::PandoKmsProvider,
    s_root: &Path,
    repo: Uuid,
    pack: &Pack,
    old_env: &KmsEnvelopeRecord,
    to_key_id: &str,
    to_key_version: i32,
) -> Result<KmsEnvelopeRecord> {
    verify_pack_ciphertext_open(provider, s_root, repo, pack, old_env).await?;
    let envelope_id = old_env
        .envelope_id
        .context("missing envelope_id during DEK rewrap")?;
    let nonce_prefix = old_env
        .nonce_prefix
        .as_deref()
        .context("missing nonce_prefix during DEK rewrap")?;
    let ciphertext_sha256 = old_env
        .ciphertext_sha256
        .as_deref()
        .context("missing ciphertext_sha256 during DEK rewrap")?;
    let ciphertext_bytes = old_env
        .ciphertext_bytes
        .context("missing ciphertext_bytes during DEK rewrap")?;
    let wrapped_json = old_env
        .wrapped_key_json
        .as_deref()
        .context("missing wrapped_key_json during DEK rewrap")?;

    let (rewrapped_key_id, new_wrapped_json) = super::crypto::rewrap_pack_dek(
        provider,
        repo,
        pack.id,
        envelope_id,
        &pack.pack_sha256,
        wrapped_json,
    ).await?;
    ensure!(
        rewrapped_key_id == to_key_id,
        "rewrapped key_id '{}' != target '{to_key_id}'",
        rewrapped_key_id
    );
    let mac = super::crypto::compute_authenticated_envelope_mac(
        &super::crypto::EnvelopeMacInputs {
            encryption_mode: super::crypto::AUTHENTICATED_ENVELOPE_MODE,
            repo,
            pack_id: pack.id,
            key_id: to_key_id,
            key_version: to_key_version,
            cipher_suite: &old_env.cipher_suite,
            pack_sha256: &pack.pack_sha256,
            idx_sha256: &pack.idx_sha256,
            ciphertext_sha256,
            ciphertext_bytes,
            envelope_id,
            nonce_prefix,
            wrapped_key_json: &new_wrapped_json,
        },
    );
    let updated = KmsEnvelopeRecord {
        schema: ENVELOPE_SCHEMA.to_owned(),
        repo,
        pack_id: pack.id,
        key_id: to_key_id.to_owned(),
        key_version: to_key_version,
        cipher_suite: old_env.cipher_suite.clone(),
        pack_sha256: pack.pack_sha256.clone(),
        idx_sha256: pack.idx_sha256.clone(),
        plaintext_sha256: pack.pack_sha256.clone(),
        envelope_mac: mac,
        storage_tier: old_env.storage_tier.clone(),
        encryption_mode: super::crypto::AUTHENTICATED_ENVELOPE_MODE.to_owned(),
        envelope_id: Some(envelope_id),
        nonce_prefix: Some(nonce_prefix.to_owned()),
        wrapped_key_json: Some(new_wrapped_json),
        ciphertext_sha256: Some(ciphertext_sha256.to_owned()),
        ciphertext_bytes: Some(ciphertext_bytes),
        provider_kind: super::provider::PROVIDER_KIND_LOCAL.to_owned(),
    };
    verify_pack_ciphertext_open(provider, s_root, repo, pack, &updated).await?;
    Ok(updated)
}

fn same_dek(left: &super::data_key::PandoDataKey, right: &super::data_key::PandoDataKey) -> bool {
    ring::constant_time::verify_slices_are_equal(left.expose_secret(), right.expose_secret()).is_ok()
}

pub(super) fn read_pack_cipher(s_root: &Path, repo: Uuid, pack: &Pack) -> Result<Vec<u8>> {
    let manifest_path = s_root.join(object_store::manifest_key(repo, pack.id));
    ensure!(manifest_path.is_file(), "missing object-store manifest for encrypted pack {}", pack.id);
    let manifest: object_store::CasPackManifest =
        serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
    ensure!(
        manifest.repo == repo && manifest.pack_id == pack.id,
        "object-store manifest identity mismatch for pack {}",
        pack.id
    );
    let cipher = std::fs::read(s_root.join(&manifest.pack_key))?;
    let cipher_sha = manifest.ciphertext_sha256.as_deref().context("manifest missing ciphertext_sha256")?;
    ensure!(
        cipher.len() as u64 == manifest.ciphertext_bytes.context("manifest missing ciphertext_bytes")?
            && super::crypto::sha256_hex(&cipher) == cipher_sha,
        "object-store ciphertext digest or length mismatch for pack {}",
        pack.id
    );
    Ok(cipher)
}

fn envelope_with_wrapped_key(
    old_env: &KmsEnvelopeRecord,
    new_wrapped_json: String,
    new_provider_kind: &str,
    new_key_id: &str,
    new_key_version: i32,
) -> Result<KmsEnvelopeRecord> {
    let envelope_id = old_env.envelope_id.context("missing envelope_id during Vault rewrap")?;
    let nonce_prefix = old_env.nonce_prefix.as_deref().context("missing nonce_prefix during Vault rewrap")?;
    let ciphertext_sha256 = old_env
        .ciphertext_sha256
        .as_deref()
        .context("missing ciphertext_sha256 during Vault rewrap")?;
    let ciphertext_bytes = old_env.ciphertext_bytes.context("missing ciphertext_bytes during Vault rewrap")?;
    PandoWrappedDek::from_json(new_wrapped_json.as_bytes())?
        .validate_binding(new_provider_kind, new_key_id, new_key_version)?;
    let mac = super::crypto::compute_authenticated_envelope_mac(&super::crypto::EnvelopeMacInputs {
        encryption_mode: super::crypto::AUTHENTICATED_ENVELOPE_MODE,
        repo: old_env.repo,
        pack_id: old_env.pack_id,
        key_id: new_key_id,
        key_version: new_key_version,
        cipher_suite: &old_env.cipher_suite,
        pack_sha256: &old_env.pack_sha256,
        idx_sha256: &old_env.idx_sha256,
        ciphertext_sha256,
        ciphertext_bytes,
        envelope_id,
        nonce_prefix,
        wrapped_key_json: &new_wrapped_json,
    });
    let updated = KmsEnvelopeRecord {
        schema: ENVELOPE_SCHEMA.to_owned(),
        repo: old_env.repo,
        pack_id: old_env.pack_id,
        key_id: new_key_id.to_owned(),
        key_version: new_key_version,
        cipher_suite: old_env.cipher_suite.clone(),
        pack_sha256: old_env.pack_sha256.clone(),
        idx_sha256: old_env.idx_sha256.clone(),
        plaintext_sha256: old_env.pack_sha256.clone(),
        envelope_mac: mac,
        storage_tier: old_env.storage_tier.clone(),
        encryption_mode: super::crypto::AUTHENTICATED_ENVELOPE_MODE.to_owned(),
        envelope_id: Some(envelope_id),
        nonce_prefix: Some(nonce_prefix.to_owned()),
        wrapped_key_json: Some(new_wrapped_json),
        ciphertext_sha256: Some(ciphertext_sha256.to_owned()),
        ciphertext_bytes: Some(ciphertext_bytes),
        provider_kind: new_provider_kind.to_owned(),
    };
    super::envelopes::verify_envelope_record(&updated)?;
    Ok(updated)
}

pub(super) async fn verify_rewrapped_pack(
    base_root: &Path,
    repo: Uuid,
    pack: &Pack,
    env: &KmsEnvelopeRecord,
    cipher: &[u8],
) -> Result<()> {
    super::envelopes::verify_envelope_record(env)?;
    let plain = verify_and_decrypt_pack_bytes(base_root, repo, pack, env, cipher).await?;
    ensure!(
        super::crypto::sha256_hex(&plain) == pack.pack_sha256,
        "rewrapped pack plaintext digest mismatch"
    );
    Ok(())
}

pub(super) async fn rewrap_vault_envelope(
    vault: &VaultTransitProvider,
    base_root: &Path,
    s_root: &Path,
    repo: Uuid,
    pack: &Pack,
    old_env: &KmsEnvelopeRecord,
    target_version: i32,
) -> Result<KmsEnvelopeRecord> {
    ensure!(
        old_env.provider_kind == provider::PROVIDER_KIND_VAULT,
        "Vault rewrap source is not a Vault envelope"
    );
    let cipher = read_pack_cipher(s_root, repo, pack)?;
    verify_rewrapped_pack(base_root, repo, pack, old_env, &cipher).await?;
    let old_wrapped = old_env.wrapped_key_json.as_deref().context("missing old wrapped_key_json")?;
    let old_dto = PandoWrappedDek::from_json(old_wrapped.as_bytes())?;
    let envelope_id = old_env.envelope_id.context("missing envelope_id during Vault rewrap")?;
    let context = super::crypto::pack_wrap_context(repo, pack.id, envelope_id, &pack.pack_sha256)?;
    let new_dto = vault.rewrap_at_version(&old_dto, &context, Some(target_version)).await?;
    let old_key = vault.unwrap(&old_dto, &context).await?;
    let new_key = vault.unwrap(&new_dto, &context).await?;
    ensure!(same_dek(&old_key, &new_key), "Vault rewrap changed the data key");
    let new_json = new_dto.to_json()?;
    let new_key_id = new_dto.key_id().to_owned();
    let updated = envelope_with_wrapped_key(
        old_env,
        new_json,
        provider::PROVIDER_KIND_VAULT,
        &new_key_id,
        target_version,
    )?;
    verify_rewrapped_pack(base_root, repo, pack, &updated, &cipher).await?;
    Ok(updated)
}

pub(super) async fn migrate_local_envelope_to_vault(
    vault: &VaultTransitProvider,
    base_root: &Path,
    s_root: &Path,
    repo: Uuid,
    pack: &Pack,
    old_env: &KmsEnvelopeRecord,
    target_version: i32,
) -> Result<KmsEnvelopeRecord> {
    ensure!(
        old_env.provider_kind == provider::PROVIDER_KIND_LOCAL,
        "Vault migration source is not a Local envelope"
    );
    let cipher = read_pack_cipher(s_root, repo, pack)?;
    verify_rewrapped_pack(base_root, repo, pack, old_env, &cipher).await?;
    let local_dir = provider::resolve_kms_dir(base_root, repo);
    let local = provider::PandoKmsProvider::open_existing(&local_dir)?;
    let old_dto = PandoWrappedDek::from_json(
        old_env.wrapped_key_json.as_deref().context("missing local wrapped_key_json")?.as_bytes(),
    )?;
    let envelope_id = old_env.envelope_id.context("missing envelope_id during migration")?;
    let context = super::crypto::pack_wrap_context(repo, pack.id, envelope_id, &pack.pack_sha256)?;
    let data_key = local.unwrap_data_key(&old_dto, &context).await?;
    let new_dto = vault.wrap_at_version(&data_key, &context, Some(target_version)).await?;
    let migrated_key = vault.unwrap(&new_dto, &context).await?;
    ensure!(same_dek(&data_key, &migrated_key), "Local-to-Vault migration changed the data key");
    let new_json = new_dto.to_json()?;
    let new_key_id = new_dto.key_id().to_owned();
    let updated = envelope_with_wrapped_key(
        old_env,
        new_json,
        provider::PROVIDER_KIND_VAULT,
        &new_key_id,
        target_version,
    )?;
    verify_rewrapped_pack(base_root, repo, pack, &updated, &cipher).await?;
    Ok(updated)
}
