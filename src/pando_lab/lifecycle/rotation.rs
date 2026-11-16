use super::super::{Config, Pack, object_store};
use super::{
    DEFAULT_CIPHER_SUITE, DEFAULT_KMS_KEY_ID, ENVELOPE_SCHEMA, KmsEnvelopeRecord,
    KmsRotationReport,
    db::{load_envelope_from_db, load_file_checkpoint, persist_checkpoint},
    envelope_file_path, load_repo_packs, read_and_verify_envelope_file, valid_kms_key_id,
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
}

pub async fn verify_and_decrypt_pack_bytes(
    base_root: &Path,
    repo: Uuid,
    pack: &Pack,
    env: &KmsEnvelopeRecord,
    cipher_bytes: &[u8],
) -> Result<Vec<u8>> {
    let kms_dir = super::provider::resolve_kms_dir(base_root, repo);
    let provider = super::provider::PandoKmsProvider::open_existing(&kms_dir)?;
    verify_with_provider(&provider, repo, pack, env, cipher_bytes).await
}

async fn verify_with_provider(
    provider: &super::provider::PandoKmsProvider,
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
    provider.ensure_key_readable(&env.key_id, env.key_version)?;
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

async fn resolve_rotation_checkpoint(
    c: &Client,
    kms_dir: &Path,
    repo: Uuid,
    opts: &KmsRotateOptions,
    packs: &[Pack],
) -> Result<(KmsRotationCheckpoint, super::provider::KmsKeyPolicy)> {
    let existing = load_file_checkpoint(kms_dir)?;
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
    };
    persist_checkpoint(c, kms_dir, &cp).await?;
    Ok((cp, policy))
}

pub async fn rotate_kms_key_with_options(
    config: &Config,
    repo: Uuid,
    opts: &KmsRotateOptions,
) -> Result<KmsRotationReport> {
    let c = config.db().await?;
    let kms_dir = super::provider::resolve_kms_dir(&config.root, repo);
    let s_root = object_store::store_root(config);
    let packs = load_repo_packs(&c, repo).await?;
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
