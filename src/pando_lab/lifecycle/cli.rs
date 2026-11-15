use super::{
    DEFAULT_KMS_KEY_ID, db, envelope_file_path, load_repo_packs, provider,
    read_and_verify_envelope_file,
    rotation::{
        KmsRotateOptions, KmsRotationCheckpoint, rotate_kms_key_with_options,
        verify_pack_ciphertext_open,
    },
};
use super::super::{Config, object_store};
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsStatusReport {
    pub repo: Uuid,
    pub policy: provider::KmsKeyPolicy,
    pub active_rotation: Option<KmsRotationCheckpoint>,
    pub envelope_count: usize,
}

pub async fn verify_repo_encryption(config: &Config, repo: Uuid) -> Result<KmsVerifyReport> {
    let c = config.db().await?;
    let kms_dir = provider::resolve_kms_dir(&config.root, repo);
    let prov = provider::PandoKmsProvider::open_existing(&kms_dir)?;
    let _active = prov.active_entry()?;
    let packs = load_repo_packs(&c, repo).await?;
    let s_root = object_store::store_root(config);
    for pack in &packs {
        let disk_path = envelope_file_path(&config.root, repo, pack.id);
        ensure!(disk_path.is_file(), "missing KMS envelope file for pack {}", pack.id);
        let env = read_and_verify_envelope_file(&config.root, repo, pack.id)?;
        if let Some(db_env) = db::load_envelope_from_db(&c, repo, pack).await? {
            ensure!(
                db_env.envelope_mac == env.envelope_mac && db_env.key_id == env.key_id,
                "DB KMS envelope diverges from verified on-disk envelope for pack {}",
                pack.id
            );
        }
        verify_pack_ciphertext_open(&prov, &s_root, repo, pack, &env)?;
    }
    let p = prov.policy();
    Ok(KmsVerifyReport {
        repo,
        verified: true,
        encryption_mode: super::crypto::AUTHENTICATED_ENVELOPE_MODE.to_owned(),
        authenticated_encryption: true,
        packs_checked: packs.len(),
        packs_verified: packs.len(),
        active_key_id: p.active_key_id.clone(),
        active_key_version: p.active_key_version,
        provider_revoked: p.provider_revoked,
        keys: p.keys.clone(),
    })
}

pub async fn kms_status(config: &Config, repo: Uuid) -> Result<KmsStatusReport> {
    let c = config.db().await?;
    let kms_dir = provider::resolve_kms_dir(&config.root, repo);
    let policy = if kms_dir.join(provider::POLICY_FILE_NAME).is_file() {
        provider::load_policy(&kms_dir)?
    } else {
        provider::PandoKmsProvider::open_or_init(&kms_dir, DEFAULT_KMS_KEY_ID)?
            .policy()
            .clone()
    };
    let active_rotation = db::load_file_checkpoint(&kms_dir)?;
    let row = c
        .query_one(
            "SELECT count(*) FROM pando_lab.kms_envelopes WHERE repo=$1",
            &[&repo],
        )
        .await?;
    Ok(KmsStatusReport {
        repo,
        policy,
        active_rotation,
        envelope_count: row.get::<_, i64>(0) as usize,
    })
}

pub async fn run_kms_cli(config: &Config, args: &[String]) -> Result<()> {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let repo: Uuid = args
        .get(1)
        .with_context(|| format!("missing <repo> for {cmd}"))?
        .parse()?;
    let kms_dir = provider::resolve_kms_dir(&config.root, repo);
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
                        opts.fail_after_packs = Some(
                            args.get(i + 1)
                                .context("missing value for --fail-after-packs")?
                                .parse()?,
                        );
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
            let policy =
                provider::set_provider_revoked_in_dir(&kms_dir, cmd == "kms-revoke-provider")?;
            db::sync_kms_policy_to_db(&config.db().await?, repo, &policy).await?;
            println!("{}", serde_json::to_string(&policy)?);
        }
        "kms-policy" => {
            let (mut retain_prev, mut min_ver) = (None, None);
            let mut i = 2usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--retain-previous" => {
                        retain_prev = Some(
                            args.get(i + 1)
                                .context("missing value for --retain-previous")?
                                .parse()?,
                        );
                        i += 2;
                    }
                    "--min-readable-version" => {
                        min_ver = Some(
                            args.get(i + 1)
                                .context("missing value for --min-readable-version")?
                                .parse()?,
                        );
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
