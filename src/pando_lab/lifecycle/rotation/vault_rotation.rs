use super::super::super::{Config, Pack, object_store};
use super::super::{
    DEFAULT_CIPHER_SUITE, db::{persist_checkpoint, upsert_envelope_in_db},
    envelopes::write_envelope_file, load_repo_packs, provider,
    provider_selection::{self, PandoProviderSelection},
    vault_provider::VaultTransitProvider,
};
use super::crypto_ops::{
    migrate_local_envelope_to_vault, read_pack_cipher, rewrap_vault_envelope,
    verify_rewrapped_pack,
};
use super::{
    KmsReconcileStage, KmsRotateOptions, KmsRotationCheckpoint, KmsRotationReport,
    load_authoritative_envelope, load_authoritative_envelope_optional,
};
use anyhow::{Context, Result, bail, ensure};
use std::path::Path;
use tokio_postgres::Client;
use uuid::Uuid;

pub(crate) const EXISTING_TARGET_CONTRACT: &str = "existing-vault-version/v1";

pub(super) fn ensure_existing_target_contract(cp: &KmsRotationCheckpoint) -> Result<()> {
    ensure!(
        cp.target_contract == EXISTING_TARGET_CONTRACT,
        "unsupported legacy automatic-rotate Vault checkpoint; refusing to adopt it"
    );
    Ok(())
}

pub(super) fn ensure_no_version_downgrade(
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

pub(super) fn ensure_target_available(target_version: i32, latest: i32, min_encryption: i32) -> Result<()> {
    ensure!(
        target_version >= 1 && target_version <= latest && target_version >= min_encryption,
        "Vault target version is unavailable or below min_encryption_version"
    );
    Ok(())
}

pub(super) fn ensure_vault_retention_option(opts: &KmsRotateOptions) -> Result<()> {
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

pub(super) async fn rotate_vault_kms_key_with_options(
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
