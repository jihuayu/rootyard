use super::super::{Config, Pack, object_store};
use super::{
    DEFAULT_CIPHER_SUITE, DEFAULT_KMS_KEY_ID, ENVELOPE_SCHEMA, KmsEnvelopeRecord,
    KmsRotationReport,
    crypto, data_key, envelopes,
    db::{load_envelope_from_db, persist_checkpoint},
    load_repo_packs, provider,
    provider::PandoKeyProvider,
    provider_selection::{self, PandoProviderSelection},
    valid_kms_key_id,
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

mod crypto_ops;

use crypto_ops::{
    migrate_local_envelope_to_vault, read_pack_cipher, rewrap_existing_envelope,
    rewrap_vault_envelope, verify_rewrapped_pack,
};

pub use crypto_ops::verify_and_decrypt_pack_bytes;
pub(super) use crypto_ops::verify_pack_ciphertext_open;

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
    #[serde(default)]
    pub write_epoch: u64,
}

impl KmsRotationCheckpoint {
    pub(crate) fn expected_version(&self) -> i32 {
        if self.expected_to_version > 0 { self.expected_to_version } else { self.to_key_version }
    }

    pub(crate) fn is_vault_target(&self) -> bool {
        self.to_provider_kind == super::provider::PROVIDER_KIND_VAULT
    }
}

pub(crate) async fn insert_envelope_in_tx(
    t: &tokio_postgres::Transaction<'_>,
    env: &KmsEnvelopeRecord,
) -> Result<()> {
    super::db::insert_envelope_in_tx(t, env).await
}

pub(crate) async fn sync_kms_policy_in_tx(
    t: &tokio_postgres::Transaction<'_>,
    repo: Uuid,
    policy: &super::provider::KmsKeyPolicy,
) -> Result<()> {
    super::db::sync_kms_policy_in_tx(t, repo, policy).await
}

pub(crate) async fn load_authoritative_envelope_optional(
    c: &Client,
    base_root: &Path,
    repo: Uuid,
    pack: &Pack,
) -> Result<Option<KmsEnvelopeRecord>> {
    let Some(env) = load_envelope_from_db(c, repo, pack).await? else {
        return Ok(None);
    };
    super::envelopes::verify_envelope_record(&env)?;
    ensure!(
        env.repo == repo && env.pack_id == pack.id
            && env.pack_sha256 == pack.pack_sha256
            && env.idx_sha256 == pack.idx_sha256,
        "committed DB KMS envelope identity mismatch"
    );
    let _ = write_envelope_file(base_root, &env);
    Ok(Some(env))
}

pub(crate) async fn load_authoritative_envelope(
    c: &Client,
    base_root: &Path,
    repo: Uuid,
    pack: &Pack,
) -> Result<KmsEnvelopeRecord> {
    load_authoritative_envelope_optional(c, base_root, repo, pack)
        .await?
        .context("missing committed DB KMS envelope for pack")
}

pub(crate) const EXISTING_TARGET_CONTRACT: &str = "existing-vault-version/v1";

fn ensure_existing_target_contract(cp: &KmsRotationCheckpoint) -> Result<()> {
    ensure!(
        cp.target_contract == EXISTING_TARGET_CONTRACT,
        "unsupported legacy automatic-rotate Vault checkpoint; refusing to adopt it"
    );
    Ok(())
}

fn ensure_no_version_downgrade(
    provider_kind: &str,
    key_id: &str,
    key_version: i32,
    target_key_id: &str,
    target_version: i32,
) -> Result<()> {
    if provider_kind == provider::PROVIDER_KIND_VAULT && key_id == target_key_id {
        ensure!(
            key_version <= target_version,
            "refusing same-key Vault downgrade from version {key_version} to {target_version}"
        );
    }
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
            if let Some(env) = load_authoritative_envelope_optional(c, &config.root, repo, pack).await? {
                ensure_no_version_downgrade(&env.provider_kind, &env.key_id, env.key_version, &cp.to_key_id, cp.expected_version())?;
            }
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
        let env = load_authoritative_envelope_optional(c, &config.root, repo, pack).await?;
        if let Some(env) = env {
            ensure_no_version_downgrade(
                &env.provider_kind,
                &env.key_id,
                env.key_version,
                vault.key_name(),
                target_version,
            )?;
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
    let mut cp = KmsRotationCheckpoint {
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
        write_epoch: 0,
    };
    cp.write_epoch = super::db::next_write_epoch(c, repo).await?;
    persist_checkpoint(c, kms_dir, &cp).await?;
    Ok(cp)
}

async fn rotate_vault_kms_key_with_options(
    config: &Config,
    repo: Uuid,
    opts: &KmsRotateOptions,
    c: &Client,
    session: &super::publication::PgSession,
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
    session.unlock_publication_exclusive(repo).await?;
    ensure!(
        cp.expected_version() == cp.to_key_version,
        "Vault rotation checkpoint version mismatch"
    );
    let mut envelopes = Vec::with_capacity(packs.len());
    let mut rewrapped_this_run = 0usize;
    for pack in &packs {
        let (latest, min_encryption) = vault.latest_and_min_encryption().await?;
        ensure_target_available(cp.expected_version(), latest, min_encryption)?;
        let existing = load_authoritative_envelope_optional(c, &config.root, repo, pack).await?;
        if let Some(ref env) = existing {
            ensure_no_version_downgrade(&env.provider_kind, &env.key_id, env.key_version, &cp.to_key_id, cp.expected_version())?;
        }
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
    session.acquire_publication_exclusive(repo).await?;
    let fresh_packs = load_repo_packs(c, repo).await?;
    cp.target_pack_ids = fresh_packs.iter().map(|pack| pack.id).collect();
    cp.completed_pack_ids.clear();
    let mut verified_envelopes = Vec::with_capacity(fresh_packs.len());
    for pack in &fresh_packs {
        let result = async {
            let env = load_authoritative_envelope(c, &config.root, repo, pack).await?;
            ensure!(
                env.provider_kind == provider::PROVIDER_KIND_VAULT
                    && env.key_id == cp.to_key_id
                    && env.key_version == cp.expected_version(),
                "final Vault envelope target mismatch for pack {}",
                pack.id
            );
            let cipher = read_pack_cipher(&s_root, repo, pack)?;
            verify_rewrapped_pack(&config.root, repo, pack, &env, &cipher).await?;
            Ok::<_, anyhow::Error>(env)
        }
        .await;
        match result {
            Ok(env) => {
                cp.completed_pack_ids.push(pack.id);
                verified_envelopes.push(env);
            }
            Err(error) => {
                cp.failed_pack_id = Some(pack.id);
                persist_checkpoint(c, kms_dir, &cp).await?;
                return Err(error.context(format!("final Vault rotation rescan remains resumable at pack {}", pack.id)));
            }
        }
    }
    envelopes = verified_envelopes;
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
        envelopes_rewrapped: rewrapped_this_run,
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

    let mut cp = KmsRotationCheckpoint {
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
        write_epoch: 0,
    };
    cp.write_epoch = super::db::next_write_epoch(c, repo).await?;
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
        return rotate_vault_kms_key_with_options(config, repo, opts, c, &session).await;
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
        let existing = load_authoritative_envelope_optional(c, &config.root, repo, pack).await?;
        if let Some(env) = existing {
            ensure!(
                env.provider_kind == super::provider::PROVIDER_KIND_LOCAL,
                "Pando KMS rotation across nonlocal provider kinds is not implemented yet; refusing local-file mutation"
            );
        }
    }
    let (mut cp, _policy) = resolve_rotation_checkpoint(&c, &kms_dir, repo, opts, &packs).await?;
    session.unlock_publication_exclusive(repo).await?;
    let provider = super::provider::PandoKmsProvider::open_existing(&kms_dir)?;

    let mut envelopes = Vec::with_capacity(packs.len());
    let mut rewrapped_this_run = 0usize;
    for pack in &packs {
        let existing_env = load_authoritative_envelope_optional(&c, &config.root, repo, pack).await?;
        if let Some(ref env) = existing_env {
            ensure_no_version_downgrade(&env.provider_kind, &env.key_id, env.key_version, &cp.to_key_id, cp.to_key_version)?;
        }
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

    session.acquire_publication_exclusive(repo).await?;
    let base_client = session.client();
    let fresh_packs = load_repo_packs(base_client, repo).await?;
    cp.target_pack_ids = fresh_packs.iter().map(|pack| pack.id).collect();
    cp.completed_pack_ids.clear();
    let mut verified_envelopes = Vec::with_capacity(fresh_packs.len());
    for pack in &fresh_packs {
        let result = async {
            let env = load_authoritative_envelope(base_client, &config.root, repo, pack).await?;
            ensure!(
                env.provider_kind == super::provider::PROVIDER_KIND_LOCAL
                    && env.key_id == cp.to_key_id
                    && env.key_version == cp.to_key_version,
                "final Local envelope target mismatch for pack {}",
                pack.id
            );
            verify_pack_ciphertext_open(&provider, &s_root, repo, pack, &env).await?;
            Ok::<_, anyhow::Error>(env)
        }
        .await;
        match result {
            Ok(env) => {
                cp.completed_pack_ids.push(pack.id);
                verified_envelopes.push(env);
            }
            Err(error) => {
                cp.failed_pack_id = Some(pack.id);
                persist_checkpoint(base_client, kms_dir, &cp).await?;
                return Err(error.context(format!("final Local rotation rescan remains resumable at pack {}", pack.id)));
            }
        }
    }
    envelopes = verified_envelopes;
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
        envelopes_rewrapped: rewrapped_this_run,
        envelopes_verified: envelopes.len(),
        envelopes,
    })
}


#[cfg(test)]
mod tests;
