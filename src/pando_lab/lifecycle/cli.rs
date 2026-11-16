use super::super::{Config, object_store};
use super::vault_provider::VaultTransitProvider;
use super::{
    DEFAULT_KMS_KEY_ID, db, load_repo_packs, provider, provider_selection,
    rotation::{KmsRotateOptions, KmsRotationCheckpoint, rotate_kms_key_with_options},
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsVerifyReport {
    pub repo: Uuid,
    pub verified: bool,
    pub encryption_mode: String,
    pub authenticated_encryption: bool,
    pub packs_checked: usize,
    pub packs_verified: usize,
    pub active_key_id: String,
    pub active_key_version: i32,
    pub provider_revoked: bool,
    pub keys: Vec<provider::ManagedKeyEntry>,
    #[serde(default)]
    pub provider_kind: String,
    #[serde(default)]
    pub provider_latest_version: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsStatusReport {
    pub repo: Uuid,
    pub policy: Option<provider::KmsKeyPolicy>,
    pub active_rotation: Option<KmsRotationCheckpoint>,
    pub envelope_count: usize,
    #[serde(default)]
    pub provider_kind: String,
    #[serde(default)]
    pub provider_latest_version: Option<i32>,
    #[serde(default)]
    pub rotation_total_packs: usize,
    #[serde(default)]
    pub rotation_completed_packs: usize,
}

pub async fn verify_repo_encryption(config: &Config, repo: Uuid) -> Result<KmsVerifyReport> {
    let c = config.db().await?;
    let kms_dir = provider::resolve_kms_dir(&config.root, repo);
    let packs = load_repo_packs(&c, repo).await?;
    let s_root = object_store::store_root(config);
    let selected = provider_selection::selected_kind()?;
    let (provider_kind, provider_latest_version, active_key_id, active_key_version, provider_revoked, keys) =
        if selected == provider_selection::PandoProviderSelection::VaultTransit {
            let vault = VaultTransitProvider::from_env()?;
            let latest = vault.latest_version().await?;
            (
                provider::PROVIDER_KIND_VAULT.to_owned(),
                Some(latest),
                vault.key_name().to_owned(),
                latest,
                false,
                Vec::<provider::ManagedKeyEntry>::new(),
            )
        } else {
            let prov = provider::PandoKmsProvider::open_existing(&kms_dir)?;
            let _active = prov.active_entry()?;
            let p = prov.policy();
            (
                provider::PROVIDER_KIND_LOCAL.to_owned(),
                None,
                p.active_key_id.clone(),
                p.active_key_version,
                p.provider_revoked,
                p.keys.clone(),
            )
        };
    for pack in &packs {
        let env = super::rotation::load_authoritative_envelope(&c, &config.root, repo, pack).await?;
        let manifest_path = s_root.join(object_store::manifest_key(repo, pack.id));
        ensure!(manifest_path.is_file(), "missing object-store manifest for pack {}", pack.id);
        let manifest: object_store::CasPackManifest = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
        ensure!(
            manifest.repo == repo && manifest.pack_id == pack.id,
            "object-store manifest identity mismatch for pack {}",
            pack.id
        );
        let cipher = std::fs::read(s_root.join(&manifest.pack_key))?;
        super::rotation::verify_and_decrypt_pack_bytes(&config.root, repo, pack, &env, &cipher).await?;
    }
    Ok(KmsVerifyReport {
        repo,
        verified: true,
        encryption_mode: super::crypto::AUTHENTICATED_ENVELOPE_MODE.to_owned(),
        authenticated_encryption: true,
        packs_checked: packs.len(),
        packs_verified: packs.len(),
        active_key_id,
        active_key_version,
        provider_revoked,
        keys,
        provider_kind,
        provider_latest_version,
    })
}

pub async fn kms_status(config: &Config, repo: Uuid) -> Result<KmsStatusReport> {
    let c = config.db().await?;
    let kms_dir = provider::resolve_kms_dir(&config.root, repo);
    let active_rotation = db::load_db_checkpoint(&c, repo).await?;
    let rotation_total_packs = active_rotation.as_ref().map_or(0, |cp| cp.target_pack_ids.len());
    let rotation_completed_packs = active_rotation.as_ref().map_or(0, |cp| cp.completed_pack_ids.len());
    let row = c.query_one("SELECT count(*) FROM pando_lab.kms_envelopes WHERE repo=$1", &[&repo]).await?;
    let envelope_count = row.get::<_, i64>(0) as usize;
    if provider_selection::selected_kind()? == provider_selection::PandoProviderSelection::VaultTransit {
        let vault = VaultTransitProvider::from_env()?;
        return Ok(KmsStatusReport {
            repo,
            policy: None,
            active_rotation,
            envelope_count,
            provider_kind: provider::PROVIDER_KIND_VAULT.to_owned(),
            provider_latest_version: Some(vault.latest_version().await?),
            rotation_total_packs,
            rotation_completed_packs,
        });
    }
    let policy = if kms_dir.join(provider::POLICY_FILE_NAME).is_file() {
        provider::load_policy(&kms_dir)?
    } else {
        provider::PandoKmsProvider::open_or_init(&kms_dir, DEFAULT_KMS_KEY_ID)?.policy().clone()
    };
    Ok(KmsStatusReport {
        repo,
        policy: Some(policy),
        active_rotation,
        envelope_count,
        provider_kind: provider::PROVIDER_KIND_LOCAL.to_owned(),
        provider_latest_version: None,
        rotation_total_packs,
        rotation_completed_packs,
    })
}

pub async fn run_kms_cli(config: &Config, args: &[String]) -> Result<()> {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let repo: Uuid = args.get(1).with_context(|| format!("missing <repo> for {cmd}"))?.parse()?;
    let kms_dir = provider::resolve_kms_dir(&config.root, repo);
    if provider_selection::selected_kind()? == provider_selection::PandoProviderSelection::VaultTransit
        && matches!(cmd, "kms-revoke-key" | "kms-revoke-provider" | "kms-grant-provider" | "kms-policy")
    {
        bail!("Pando local KMS mutation is unsupported while vault-transit is selected; refusing local-file mutation");
    }
    match cmd {
        "kms-rotate" => {
            let mut opts = KmsRotateOptions::default();
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--resume" => {
                        opts.resume = true;
                        i += 1;
                    }
                    "--revoke-previous" => {
                        opts.revoke_previous = true;
                        i += 1;
                    }
                    "--fail-after-packs" => {
                        opts.fail_after_packs =
                            Some(args.get(i + 1).context("missing value for --fail-after-packs")?.parse()?);
                        i += 2;
                    }
                    "--target-version" => {
                        opts.target_version =
                            Some(args.get(i + 1).context("missing value for --target-version")?.parse()?);
                        i += 2;
                    }
                    flag if flag.starts_with("--") => bail!("unknown kms-rotate flag '{flag}'"),
                    val if opts.target_key_id.is_none() => {
                        opts.target_key_id = Some(val.to_owned());
                        i += 1;
                    }
                    extra => bail!("unexpected kms-rotate argument '{extra}'"),
                }
            }
            let report = rotate_kms_key_with_options(config, repo, &opts).await?;
            println!("{}", serde_json::to_string(&report)?);
        }
        "kms-status" => println!("{}", serde_json::to_string(&kms_status(config, repo).await?)?),
        "kms-verify" => {
            println!("{}", serde_json::to_string(&verify_repo_encryption(config, repo).await?)?);
        }
        "kms-revoke-key" => {
            let key_id = args.get(2).context("kms-revoke-key requires <key_id>")?;
            let policy = provider::revoke_key_in_dir(&kms_dir, key_id)?;
            db::sync_kms_policy_to_db(&config.db().await?, repo, &policy).await?;
            println!("{}", serde_json::to_string(&policy)?);
        }
        "kms-revoke-provider" | "kms-grant-provider" => {
            let policy = provider::set_provider_revoked_in_dir(&kms_dir, cmd == "kms-revoke-provider")?;
            db::sync_kms_policy_to_db(&config.db().await?, repo, &policy).await?;
            println!("{}", serde_json::to_string(&policy)?);
        }
        "kms-policy" => {
            let (mut retain_prev, mut min_ver) = (None, None);
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--retain-previous" => {
                        retain_prev = Some(args.get(i + 1).context("missing value for --retain-previous")?.parse()?);
                        i += 2;
                    }
                    "--min-readable-version" => {
                        min_ver = Some(args.get(i + 1).context("missing value for --min-readable-version")?.parse()?);
                        i += 2;
                    }
                    other => bail!("unknown kms-policy flag '{other}'"),
                }
            }
            let policy = provider::update_policy_in_dir(&kms_dir, retain_prev, min_ver)?;
            db::sync_kms_policy_to_db(&config.db().await?, repo, &policy).await?;
            println!("{}", serde_json::to_string(&policy)?);
        }
        _ => bail!("unsupported kms CLI command '{cmd}'"),
    }
    Ok(())
}
