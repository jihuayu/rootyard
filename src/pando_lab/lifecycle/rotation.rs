use super::super::{Config, Pack, object_store};
use super::{
    DEFAULT_CIPHER_SUITE, DEFAULT_KMS_KEY_ID, ENVELOPE_SCHEMA, KmsEnvelopeRecord,
    KmsRotationReport,
    db::{load_envelope_from_db, persist_checkpoint},
    envelope_file_path, load_repo_packs, provider,
    provider::PandoKeyProvider,
    provider_selection::{self, PandoProviderSelection},
    read_and_verify_envelope_file, valid_kms_key_id,
    vault_provider::VaultTransitProvider,
    wrapped_dek::PandoWrappedDek,
    write_envelope_file,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio_postgres::Client;
use uuid::Uuid;

pub use super::cli::{kms_status, run_kms_cli};
pub use super::db::{sync_kms_policy_to_db, upsert_envelope_in_db};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsRotateOptions {
    #[serde(default)]
    pub resume: bool,
    #[serde(default)]
    pub fail_after_packs: Option<usize>,
    #[serde(default)]
    pub revoke_previous: bool,
    #[serde(default)]
    pub target_key_id: Option<String>,
    #[serde(default)]
    pub target_version: Option<i32>,
}

fn default_checkpoint_provider_kind() -> String {
    super::provider::PROVIDER_KIND_LOCAL.to_owned()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KmsReconcileStage {
    #[default]
    NotIssued,
    RotateIssued,
    TargetObserved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsRotationCheckpoint {
    pub rotation_id: Uuid,
    pub repo: Uuid,
    pub from_key_id: String,
    pub from_key_version: i32,
    pub to_key_id: String,
    pub to_key_version: i32,
    pub state: String,
    pub revoke_previous: bool,
    pub target_pack_ids: Vec<Uuid>,
    pub completed_pack_ids: Vec<Uuid>,
    pub failed_pack_id: Option<Uuid>,
    #[serde(default = "default_checkpoint_provider_kind")]
    pub from_provider_kind: String,
    #[serde(default = "default_checkpoint_provider_kind")]
    pub to_provider_kind: String,
    #[serde(default)]
    pub expected_to_version: i32,
    #[serde(default)]
    pub external_rotate_issued: bool,
    #[serde(default)]
    pub reconcile_stage: KmsReconcileStage,
    #[serde(default)]
    pub target_contract: String,
}

impl KmsRotationCheckpoint {
    pub(crate) fn expected_version(&self) -> i32 {
        if self.expected_to_version > 0 { self.expected_to_version } else { self.to_key_version }
    }

    pub(crate) fn is_vault_target(&self) -> bool {
        self.to_provider_kind == super::provider::PROVIDER_KIND_VAULT
    }
}

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

pub(super) async fn verify_pack_ciphertext_open(
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

async fn rewrap_existing_envelope(
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

fn read_pack_cipher(s_root: &Path, repo: Uuid, pack: &Pack) -> Result<Vec<u8>> {
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

async fn verify_rewrapped_pack(
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

async fn rewrap_vault_envelope(
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

async fn migrate_local_envelope_to_vault(
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

pub(crate) const EXISTING_TARGET_CONTRACT: &str = "existing-vault-version/v1";

fn ensure_existing_target_contract(cp: &KmsRotationCheckpoint) -> Result<()> {
    ensure!(
        cp.target_contract == EXISTING_TARGET_CONTRACT,
        "unsupported legacy automatic-rotate Vault checkpoint; refusing to adopt it"
    );
    Ok(())
}

fn ensure_target_available(target_version: i32, latest: i32, min_encryption: i32) -> Result<()> {
    ensure!(
        target_version >= 1 && target_version <= latest && target_version >= min_encryption,
        "Vault target version is unavailable or below min_encryption_version"
    );
    Ok(())
}

fn ensure_vault_retention_option(opts: &KmsRotateOptions) -> Result<()> {
    ensure!(
        !opts.revoke_previous,
        "Vault retained-version retirement is not implemented; refusing explicit retirement"
    );
    Ok(())
}

async fn resolve_vault_rotation_checkpoint(
    c: &Client,
    kms_dir: &Path,
    config: &Config,
    repo: Uuid,
    opts: &KmsRotateOptions,
    packs: &[Pack],
    vault: &VaultTransitProvider,
) -> Result<KmsRotationCheckpoint> {
    ensure_vault_retention_option(opts)?;
    let existing = super::db::load_db_checkpoint(c, repo).await?;
    if let Some(mut cp) = existing
        && cp.state == "IN_PROGRESS"
    {
        ensure!(
            cp.target_contract == EXISTING_TARGET_CONTRACT,
            "unsupported legacy automatic-rotate Vault checkpoint; refusing to adopt it"
        );
        ensure!(cp.is_vault_target(), "active checkpoint target is not vault-transit");
        ensure!(!cp.revoke_previous, "Vault checkpoint retirement is unsupported");
        ensure!(cp.to_key_id == vault.key_name(), "active checkpoint target is a different Vault key");
        if let Some(version) = opts.target_version {
            ensure!(version == cp.expected_version(), "active Vault target version changed");
        }
        ensure_existing_target_contract(&cp)?;
        let (latest, min_encryption) = vault.latest_and_min_encryption().await?;
        ensure_target_available(cp.expected_version(), latest, min_encryption)?;
        let mut added_pack = false;
        for pack in packs {
            if !cp.target_pack_ids.contains(&pack.id) {
                cp.target_pack_ids.push(pack.id);
                added_pack = true;
            }
        }
        if added_pack {
            persist_checkpoint(c, kms_dir, &cp).await?;
        }
        return Ok(cp);
    }
    ensure!(!opts.resume, "no IN_PROGRESS Vault rotation checkpoint found to resume for repository {repo}");
    if let Some(ref target) = opts.target_key_id {
        ensure!(target.trim() == vault.key_name(), "Vault rotation target must be the configured key name");
    }
    let target_version = opts
        .target_version
        .context("Vault rotation requires --target-version for an existing Transit key version")?;
    ensure!(target_version >= 1, "Vault target version must be >= 1");
    let (latest, min_encryption) = vault.latest_and_min_encryption().await?;
    ensure_target_available(target_version, latest, min_encryption)?;
    let mut from_provider_kind = provider::PROVIDER_KIND_VAULT.to_owned();
    for pack in packs {
        let on_disk = envelope_file_path(&config.root, repo, pack.id);
        let env = if on_disk.is_file() {
            Some(read_and_verify_envelope_file(&config.root, repo, pack.id)?)
        } else {
            load_envelope_from_db(c, repo, pack).await?
        };
        if let Some(env) = env {
            ensure!(
                env.provider_kind == provider::PROVIDER_KIND_LOCAL
                    || env.provider_kind == provider::PROVIDER_KIND_VAULT,
                "unsupported source provider kind during Vault rotation"
            );
            if env.provider_kind == provider::PROVIDER_KIND_LOCAL {
                from_provider_kind = provider::PROVIDER_KIND_LOCAL.to_owned();
            }
        }
    }
    let cp = KmsRotationCheckpoint {
        rotation_id: Uuid::new_v4(),
        repo,
        from_key_id: vault.key_name().to_owned(),
        from_key_version: latest,
        to_key_id: vault.key_name().to_owned(),
        to_key_version: target_version,
        state: "IN_PROGRESS".to_owned(),
        revoke_previous: false,
        target_pack_ids: packs.iter().map(|p| p.id).collect(),
        completed_pack_ids: Vec::new(),
        failed_pack_id: None,
        from_provider_kind,
        to_provider_kind: provider::PROVIDER_KIND_VAULT.to_owned(),
        expected_to_version: target_version,
        external_rotate_issued: false,
        reconcile_stage: KmsReconcileStage::TargetObserved,
        target_contract: EXISTING_TARGET_CONTRACT.to_owned(),
    };
    persist_checkpoint(c, kms_dir, &cp).await?;
    Ok(cp)
}

async fn rotate_vault_kms_key_with_options(
    config: &Config,
    repo: Uuid,
    opts: &KmsRotateOptions,
    c: &Client,
) -> Result<KmsRotationReport> {
    ensure!(
        provider_selection::selected_kind()? == PandoProviderSelection::VaultTransit,
        "Vault rotation requires PANDO_KMS_PROVIDER=vault-transit"
    );
    ensure_vault_retention_option(opts)?;
    let vault = VaultTransitProvider::from_env()?;
    let kms_dir = provider::resolve_kms_dir(&config.root, repo);
    let s_root = object_store::store_root(config);
    let packs = load_repo_packs(&c, repo).await?;
    let mut cp =
        resolve_vault_rotation_checkpoint(&c, &kms_dir, config, repo, opts, &packs, &vault).await?;
    ensure!(
        cp.expected_version() == cp.to_key_version,
        "Vault rotation checkpoint version mismatch"
    );
    let mut envelopes = Vec::with_capacity(packs.len());
    let mut rewrapped_this_run = 0usize;
    for pack in &packs {
        let (latest, min_encryption) = vault.latest_and_min_encryption().await?;
        ensure_target_available(cp.expected_version(), latest, min_encryption)?;
        let on_disk = envelope_file_path(&config.root, repo, pack.id);
        let existing = if on_disk.is_file() {
            Some(read_and_verify_envelope_file(&config.root, repo, pack.id)?)
        } else {
            load_envelope_from_db(&c, repo, pack).await?
        };
        if let Some(ref env) = existing
            && env.provider_kind == provider::PROVIDER_KIND_VAULT
            && env.key_id == cp.to_key_id
            && env.key_version == cp.expected_version()
        {
            let cipher = read_pack_cipher(&s_root, repo, pack)?;
            verify_rewrapped_pack(&config.root, repo, pack, env, &cipher).await?;
            if !cp.completed_pack_ids.contains(&pack.id) {
                cp.completed_pack_ids.push(pack.id);
                persist_checkpoint(&c, &kms_dir, &cp).await?;
            }
            envelopes.push(env.clone());
            continue;
        }
        if let Some(limit) = opts.fail_after_packs
            && rewrapped_this_run >= limit
        {
            cp.failed_pack_id = Some(pack.id);
            persist_checkpoint(&c, &kms_dir, &cp).await?;
            bail!(
                "fault injection: Vault kms-rotate interrupted after {rewrapped_this_run} pack(s) before {} (state=IN_PROGRESS, resumable)",
                pack.id
            );
        }
        let updated = match existing {
            Some(ref env) if env.provider_kind == provider::PROVIDER_KIND_LOCAL => {
                migrate_local_envelope_to_vault(
                    &vault,
                    &config.root,
                    &s_root,
                    repo,
                    pack,
                    env,
                    cp.expected_version(),
                ).await?
            }
            Some(ref env) if env.provider_kind == provider::PROVIDER_KIND_VAULT => {
                rewrap_vault_envelope(
                    &vault,
                    &config.root,
                    &s_root,
                    repo,
                    pack,
                    env,
                    cp.expected_version(),
                ).await?
            }
            None => {
                let tier = "hot";
                let suite = DEFAULT_CIPHER_SUITE;
                let updated = object_store::put_pack_and_seal_with_suite(config, repo, pack.id, suite, tier).await?;
                ensure!(
                    updated.provider_kind == provider::PROVIDER_KIND_VAULT
                        && updated.key_id == cp.to_key_id
                        && updated.key_version == cp.expected_version(),
                    "new pack write did not use the active Vault rotation target"
                );
                let cipher = read_pack_cipher(&s_root, repo, pack)?;
                verify_rewrapped_pack(&config.root, repo, pack, &updated, &cipher).await?;
                updated
            }
            Some(_) => bail!("unsupported source provider kind during Vault rotation"),
        };
        upsert_envelope_in_db(&c, &updated).await?;
        write_envelope_file(&config.root, &updated)?;
        rewrapped_this_run += 1;
        cp.failed_pack_id = None;
        if !cp.completed_pack_ids.contains(&pack.id) {
            cp.completed_pack_ids.push(pack.id);
        }
        persist_checkpoint(&c, &kms_dir, &cp).await?;
        envelopes.push(updated);
    }
    let (latest, min_encryption) = vault.latest_and_min_encryption().await?;
    ensure_target_available(cp.expected_version(), latest, min_encryption)?;
    cp.state = "COMPLETED".to_owned();
    cp.reconcile_stage = KmsReconcileStage::TargetObserved;
    cp.failed_pack_id = None;
    persist_checkpoint(&c, &kms_dir, &cp).await?;
    Ok(KmsRotationReport {
        repo,
        previous_key_id: cp.from_key_id,
        previous_key_version: cp.from_key_version,
        new_key_id: cp.to_key_id,
        new_key_version: cp.to_key_version,
        envelopes_rewrapped: envelopes.len(),
        envelopes_verified: envelopes.len(),
        envelopes,
    })
}

async fn resolve_rotation_checkpoint(
    c: &Client,
    kms_dir: &Path,
    repo: Uuid,
    opts: &KmsRotateOptions,
    packs: &[Pack],
) -> Result<(KmsRotationCheckpoint, super::provider::KmsKeyPolicy)> {
    let existing = super::db::load_db_checkpoint(c, repo).await?;
    if let Some(mut cp) = existing
        && cp.state == "IN_PROGRESS"
    {
        if let Some(ref target) = opts.target_key_id {
            let t = target.trim();
            ensure!(
                t == cp.to_key_id,
                "cannot start KMS rotation to '{t}' while rotation {} to '{}' is IN_PROGRESS; pass --resume",
                cp.rotation_id,
                cp.to_key_id
            );
        }
        cp.revoke_previous = cp.revoke_previous || opts.revoke_previous;
        for pack in packs {
            if !cp.target_pack_ids.contains(&pack.id) {
                cp.target_pack_ids.push(pack.id);
            }
        }
        let (policy, _) = super::provider::prepare_rotation_target_key(
            kms_dir,
            &cp.to_key_id,
            DEFAULT_KMS_KEY_ID,
        )?;
        sync_kms_policy_to_db(c, repo, &policy).await?;
        persist_checkpoint(c, kms_dir, &cp).await?;
        return Ok((cp, policy));
    }

    ensure!(
        !opts.resume,
        "no IN_PROGRESS KMS rotation checkpoint found to resume for repository {repo}"
    );
    let target = opts
        .target_key_id
        .as_deref()
        .context("kms-rotate requires <new_key_id> or --resume")?
        .trim();
    ensure!(valid_kms_key_id(target), "invalid kms_key_id '{target}'");

    super::provider::PandoKmsProvider::open_or_init(kms_dir, DEFAULT_KMS_KEY_ID)?;
    let prev_policy = super::provider::load_policy(kms_dir)?;
    ensure!(
        target != prev_policy.active_key_id,
        "KMS key '{target}' is already active; provide a distinct target key id"
    );
    let (from_key_id, from_key_version) =
        (prev_policy.active_key_id, prev_policy.active_key_version);
    let (policy, new_ver) =
        super::provider::prepare_rotation_target_key(kms_dir, target, DEFAULT_KMS_KEY_ID)?;
    sync_kms_policy_to_db(c, repo, &policy).await?;

    let cp = KmsRotationCheckpoint {
        rotation_id: Uuid::new_v4(),
        repo,
        from_key_id,
        from_key_version,
        to_key_id: target.to_owned(),
        to_key_version: new_ver,
        state: "IN_PROGRESS".to_owned(),
        revoke_previous: opts.revoke_previous,
        target_pack_ids: packs.iter().map(|p| p.id).collect(),
        completed_pack_ids: Vec::new(),
        failed_pack_id: None,
        from_provider_kind: super::provider::PROVIDER_KIND_LOCAL.to_owned(),
        to_provider_kind: super::provider::PROVIDER_KIND_LOCAL.to_owned(),
        expected_to_version: new_ver,
        external_rotate_issued: false,
        reconcile_stage: KmsReconcileStage::NotIssued,
        target_contract: String::new(),
    };
    persist_checkpoint(c, kms_dir, &cp).await?;
    Ok((cp, policy))
}

pub async fn rotate_kms_key_with_options(
    config: &Config,
    repo: Uuid,
    opts: &KmsRotateOptions,
) -> Result<KmsRotationReport> {
    ensure!(
        !object_store::remote_enabled(),
        "S3 remote rotation is not implemented; refusing unsupported remote-rotation mode"
    );
    let session = super::publication::runner_session(config, repo).await?;
    session.acquire_publication_exclusive(repo).await?;
    let c = session.client();
    if provider_selection::selected_kind()? == PandoProviderSelection::VaultTransit {
        return rotate_vault_kms_key_with_options(config, repo, opts, c).await;
    }
    let kms_dir = provider::resolve_kms_dir(&config.root, repo);
    if let Some(cp) = super::db::load_db_checkpoint(c, repo).await?
        && cp.state == "IN_PROGRESS"
        && cp.to_provider_kind != provider::PROVIDER_KIND_LOCAL
    {
        bail!("active Vault rotation requires PANDO_KMS_PROVIDER=vault-transit; refusing local-file mutation");
    }
    let s_root = object_store::store_root(config);
    let packs = load_repo_packs(&c, repo).await?;
    for pack in &packs {
        let on_disk = envelope_file_path(&config.root, repo, pack.id);
        let existing = if on_disk.is_file() {
            Some(read_and_verify_envelope_file(&config.root, repo, pack.id)?)
        } else {
            load_envelope_from_db(&c, repo, pack).await?
        };
        if let Some(env) = existing {
            ensure!(
                env.provider_kind == super::provider::PROVIDER_KIND_LOCAL,
                "Pando KMS rotation across nonlocal provider kinds is not implemented yet; refusing local-file mutation"
            );
        }
    }
    let (mut cp, _policy) = resolve_rotation_checkpoint(&c, &kms_dir, repo, opts, &packs).await?;
    let provider = super::provider::PandoKmsProvider::open_existing(&kms_dir)?;

    let mut envelopes = Vec::with_capacity(packs.len());
    let mut rewrapped_this_run = 0usize;
    for pack in &packs {
        let on_disk = envelope_file_path(&config.root, repo, pack.id);
        let existing_env = if on_disk.is_file() {
            Some(read_and_verify_envelope_file(&config.root, repo, pack.id)?)
        } else {
            load_envelope_from_db(&c, repo, pack).await?
        };
        if let Some(ref env) = existing_env
            && env.key_id == cp.to_key_id
            && env.key_version == cp.to_key_version
            && super::crypto::is_authenticated_mode(&env.encryption_mode)
        {
            verify_pack_ciphertext_open(&provider, &s_root, repo, pack, env).await?;
            if !cp.completed_pack_ids.contains(&pack.id) {
                cp.completed_pack_ids.push(pack.id);
                persist_checkpoint(&c, &kms_dir, &cp).await?;
            }
            envelopes.push(env.clone());
            continue;
        }
        if let Some(limit) = opts.fail_after_packs
            && rewrapped_this_run >= limit
        {
            cp.failed_pack_id = Some(pack.id);
            persist_checkpoint(&c, &kms_dir, &cp).await?;
            bail!(
                "fault injection: kms-rotate interrupted after {rewrapped_this_run} pack(s) before {} (state=IN_PROGRESS, resumable)",
                pack.id
            );
        }

        let updated = match existing_env {
            Some(ref old_env) if super::crypto::is_authenticated_mode(&old_env.encryption_mode) => {
                rewrap_existing_envelope(
                    &provider,
                    &s_root,
                    repo,
                    pack,
                    old_env,
                    &cp.to_key_id,
                    cp.to_key_version,
                ).await?
            }
            _ => {
                let tier = existing_env
                    .as_ref()
                    .map(|e| e.storage_tier.as_str())
                    .unwrap_or("hot");
                let suite = existing_env
                    .as_ref()
                    .map(|e| e.cipher_suite.as_str())
                    .unwrap_or(DEFAULT_CIPHER_SUITE);
                object_store::put_pack_and_seal_with_suite(config, repo, pack.id, suite, tier)
                    .await?
            }
        };
        upsert_envelope_in_db(&c, &updated).await?;
        write_envelope_file(&config.root, &updated)?;
        rewrapped_this_run += 1;
        cp.failed_pack_id = None;
        if !cp.completed_pack_ids.contains(&pack.id) {
            cp.completed_pack_ids.push(pack.id);
        }
        persist_checkpoint(&c, &kms_dir, &cp).await?;
        envelopes.push(updated);
    }

    cp.state = "COMPLETED".to_owned();
    cp.failed_pack_id = None;
    persist_checkpoint(&c, &kms_dir, &cp).await?;
    if cp.revoke_previous {
        let updated_policy = super::provider::revoke_key_in_dir(&kms_dir, &cp.from_key_id)?;
        sync_kms_policy_to_db(&c, repo, &updated_policy).await?;
    }

    Ok(KmsRotationReport {
        repo,
        previous_key_id: cp.from_key_id,
        previous_key_version: cp.from_key_version,
        new_key_id: cp.to_key_id,
        new_key_version: cp.to_key_version,
        envelopes_rewrapped: envelopes.len(),
        envelopes_verified: envelopes.len(),
        envelopes,
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_checkpoint() -> KmsRotationCheckpoint {
        serde_json::from_value(serde_json::json!({
            "rotation_id": "00000000-0000-0000-0000-000000000001",
            "repo": "00000000-0000-0000-0000-000000000002",
            "from_key_id": "kms-local-a",
            "from_key_version": 1,
            "to_key_id": "kms-local-b",
            "to_key_version": 2,
            "state": "IN_PROGRESS",
            "revoke_previous": false,
            "target_pack_ids": [],
            "completed_pack_ids": [],
            "failed_pack_id": null
        }))
        .unwrap()
    }

    fn vault_checkpoint(issued: bool, stage: KmsReconcileStage) -> KmsRotationCheckpoint {
        KmsRotationCheckpoint {
            rotation_id: Uuid::new_v4(),
            repo: Uuid::new_v4(),
            from_key_id: "pando-vault-key".to_owned(),
            from_key_version: 3,
            to_key_id: "pando-vault-key".to_owned(),
            to_key_version: 4,
            state: "IN_PROGRESS".to_owned(),
            revoke_previous: false,
            target_pack_ids: Vec::new(),
            completed_pack_ids: Vec::new(),
            failed_pack_id: None,
            from_provider_kind: super::super::provider::PROVIDER_KIND_VAULT.to_owned(),
            to_provider_kind: super::super::provider::PROVIDER_KIND_VAULT.to_owned(),
            expected_to_version: 4,
            external_rotate_issued: issued,
            reconcile_stage: stage,
            target_contract: "existing-vault-version/v1".to_owned(),
        }
    }

    #[test]
    fn old_local_checkpoint_defaults_are_compatible() {
        let cp = legacy_checkpoint();
        assert_eq!(cp.from_provider_kind, super::super::provider::PROVIDER_KIND_LOCAL);
        assert_eq!(cp.to_provider_kind, super::super::provider::PROVIDER_KIND_LOCAL);
        assert_eq!(cp.expected_version(), 2);
        assert!(!cp.external_rotate_issued);
        assert_eq!(cp.reconcile_stage, KmsReconcileStage::NotIssued);
        assert!(!cp.is_vault_target());
    }

    #[test]
    fn vault_checkpoint_roundtrips_through_json() {
        let cp = vault_checkpoint(true, KmsReconcileStage::RotateIssued);
        let encoded = serde_json::to_vec(&cp).unwrap();
        let decoded: KmsRotationCheckpoint = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.from_provider_kind, super::super::provider::PROVIDER_KIND_VAULT);
        assert_eq!(decoded.to_provider_kind, super::super::provider::PROVIDER_KIND_VAULT);
        assert_eq!(decoded.expected_to_version, 4);
        assert!(decoded.external_rotate_issued);
        assert_eq!(decoded.reconcile_stage, KmsReconcileStage::RotateIssued);
    }

    #[test]
    fn existing_target_contract_versions_and_legacy_checkpoints_are_checked() {
        let cp = vault_checkpoint(false, KmsReconcileStage::TargetObserved);
        assert!(ensure_existing_target_contract(&cp).is_ok());
        assert!(ensure_target_available(4, 4, 0).is_ok());
        assert!(ensure_target_available(4, 6, 0).is_ok());
        assert!(ensure_target_available(4, 6, 4).is_ok());
        assert!(ensure_target_available(4, 3, 0).is_err());
        assert!(ensure_target_available(4, 6, 5).is_err());
        let mut legacy = cp;
        legacy.target_contract.clear();
        assert!(ensure_existing_target_contract(&legacy).is_err());
    }

    #[test]
    fn vault_retention_changes_are_refused() {
        let mut opts = KmsRotateOptions::default();
        assert!(ensure_vault_retention_option(&opts).is_ok());
        opts.revoke_previous = true;
        assert!(ensure_vault_retention_option(&opts).is_err());
    }

}
