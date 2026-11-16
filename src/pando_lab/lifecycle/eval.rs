use super::{
    DEFAULT_CIPHER_SUITE, KmsEnvelopeRecord, LifecycleEvaluateOptions, LifecycleEvaluationReport,
    LifecyclePolicy, LifecycleStatusReport, build_envelope_record, compute_fragmentation_metrics,
    crypto, db, envelope_file_path, evict_cold_pack_local, provider,
    rotate_kms_key, valid_cipher_suite, valid_encryption_mode,
    valid_kms_key_id, verify_envelope_record, write_envelope_file,
};
use super::super::{Config, Pack, object_store, repack};
use anyhow::{Context, Result, ensure};
use std::path::Path;
use tokio_postgres::Client;
use uuid::Uuid;

pub(crate) async fn load_repo_packs(c: &Client, repo: Uuid) -> Result<Vec<Pack>> {
    Ok(c.query(
        "SELECT pack_id,pack_sha256,idx_sha256 FROM pando_lab.manifests WHERE repo=$1 ORDER BY pack_id",
        &[&repo],
    )
    .await?
    .into_iter()
    .map(|r| Pack {
        id: r.get(0),
        pack_sha256: r.get(1),
        idx_sha256: r.get(2),
    })
    .collect())
}

async fn ensure_no_authenticated_envelope(
    c: &Client,
    root: &Path,
    s_root: &Path,
    repo: Uuid,
    pack: &Pack,
) -> Result<()> {
    if let Some(db_env) = db::load_envelope_from_db(c, repo, pack).await? {
        ensure!(
            !crypto::is_authenticated_mode(&db_env.encryption_mode),
            "refusing to overwrite authenticated DB envelope for pack {} with {}",
            pack.id,
            crypto::SYNTHETIC_METADATA_MODE
        );
    }
    let disk = envelope_file_path(root, repo, pack.id);
    if disk.is_file() {
        let existing: KmsEnvelopeRecord = serde_json::from_slice(&std::fs::read(&disk)?)?;
        ensure!(
            !crypto::is_authenticated_mode(&existing.encryption_mode),
            "refusing to overwrite authenticated disk envelope for pack {} with {}",
            pack.id,
            crypto::SYNTHETIC_METADATA_MODE
        );
    }
    let manifest_path = s_root.join(object_store::manifest_key(repo, pack.id));
    if manifest_path.is_file() {
        let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(&manifest_path)?)?;
        let manifest_mode = manifest.get("encryption_mode").and_then(|v| v.as_str());
        ensure!(
            !manifest_mode.is_some_and(crypto::is_authenticated_mode),
            "refusing to downgrade authenticated object-store pack {} to {}",
            pack.id,
            crypto::SYNTHETIC_METADATA_MODE
        );
    }
    Ok(())
}

/// Explicit typed refusal for lifecycle evaluation that would otherwise
/// downgrade a DB-authoritative provider/target choice.
#[derive(Debug)]
struct LifecycleEvaluationFenced {
    detail: String,
}

impl std::fmt::Display for LifecycleEvaluationFenced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for LifecycleEvaluationFenced {}

fn fenced(detail: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(LifecycleEvaluationFenced { detail: detail.into() })
}

async fn load_db_envelope_authority(
    c: &Client,
    repo: Uuid,
    pack: &Pack,
) -> Result<Option<KmsEnvelopeRecord>> {
    let env = db::load_envelope_from_db(c, repo, pack).await?;
    if let Some(env) = &env {
        ensure!(
            env.repo == repo && env.pack_id == pack.id,
            "DB KMS envelope identity mismatch for pack {}",
            pack.id
        );
        verify_envelope_record(env)
            .with_context(|| format!("invalid DB KMS envelope for pack {}", pack.id))?;
    }
    Ok(env)
}

pub(super) async fn evaluate_lifecycle_inner(
    config: &Config,
    repo: Uuid,
    opts: &LifecycleEvaluateOptions,
) -> Result<LifecycleEvaluationReport> {
    if super::provider_selection::selected_kind()?
        == super::provider_selection::PandoProviderSelection::VaultTransit
    {
        return Err(fenced(
            "Pando lifecycle evaluation is local-only in this checkpoint; refusing local KMS mutation",
        ));
    }
    if let Some(m) = opts.max_active_packs {
        ensure!((1..=1000).contains(&m), "max_active_packs must be within 1..=1000");
    }
    if let Some(age) = opts.cold_transition_age_secs {
        ensure!(age >= 0, "cold_transition_age_secs must be >= 0");
    }
    if let Some(ref k) = opts.kms_key_id {
        ensure!(valid_kms_key_id(k), "invalid kms_key_id");
    }
    let suite = opts.cipher_suite.as_deref().unwrap_or(DEFAULT_CIPHER_SUITE);
    ensure!(valid_cipher_suite(suite), "invalid cipher_suite");
    let mode = opts
        .encryption_mode
        .as_deref()
        .unwrap_or(crypto::AUTHENTICATED_ENVELOPE_MODE);
    ensure!(valid_encryption_mode(mode), "invalid encryption_mode '{mode}'");

    // Hold one owned publication session for every lifecycle read and
    // mutation. Repack/object-store publishers may acquire another shared
    // session; shared/shared is allowed. The session is scoped so it is dropped
    // before the runner-owned rotation at the end.
    let (
        mut policy,
        fragmentation_before,
        compaction_triggered,
        repack_report,
        fragmentation_after,
        mut envelopes,
        cold_count,
        evicted_count,
    ) = {
        let session = super::publication::writer_session(config, repo).await?;
        let c = session.client();
        if let Some(cp) = super::publication::active_rotation(c, repo).await?
            && cp.is_vault_target()
        {
            return Err(fenced(format!(
                "Pando lifecycle evaluation refuses repository {repo}: rotation {} state '{}' has a Vault Transit write target; refusing local KMS mutation",
                cp.rotation_id, cp.state
            )));
        }
        let meta = c
            .query_one(
                "SELECT storage_backend,write_paused FROM pando_lab.repositories WHERE id=$1",
                &[&repo],
            )
            .await?;
        ensure!(
            !meta.get::<_, bool>(1) && meta.get::<_, String>(0) == "pando",
            "lifecycle evaluation requires active pando repository"
        );

        c.execute(
            "INSERT INTO pando_lab.lifecycle_policies(repo) VALUES($1) ON CONFLICT(repo) DO NOTHING",
            &[&repo],
        )
        .await?;
        let cur = c
            .query_one(
                "SELECT max_active_packs,cold_transition_age_secs,auto_repack_enabled,kms_key_id,kms_key_version FROM pando_lab.lifecycle_policies WHERE repo=$1",
                &[&repo],
            )
            .await?;
        let mut policy = LifecyclePolicy {
            repo,
            max_active_packs: opts.max_active_packs.unwrap_or_else(|| cur.get(0)),
            cold_transition_age_secs: opts.cold_transition_age_secs.unwrap_or_else(|| cur.get(1)),
            auto_repack_enabled: opts.auto_repack_enabled.unwrap_or_else(|| cur.get(2)),
            kms_key_id: cur.get(3),
            kms_key_version: cur.get(4),
        };
        c.execute(
            "UPDATE pando_lab.lifecycle_policies SET max_active_packs=$2,cold_transition_age_secs=$3,auto_repack_enabled=$4,updated_at=now() WHERE repo=$1",
            &[&repo, &policy.max_active_packs, &policy.cold_transition_age_secs, &policy.auto_repack_enabled],
        )
        .await?;

        let kms_dir = provider::resolve_kms_dir(&config.root, repo);
        if crypto::is_authenticated_mode(mode) {
            let kms_prov = provider::PandoKmsProvider::open_or_init(&kms_dir, &policy.kms_key_id)?;
            let active = kms_prov.active_entry()?;
            policy.kms_key_id = active.key_id.clone();
            policy.kms_key_version = active.key_version;
            db::sync_kms_policy_to_db(c, repo, kms_prov.policy()).await?;
        }

        let s_root = object_store::store_root(config);
        let packs_before = load_repo_packs(c, repo).await?;
        let fragmentation_before =
            compute_fragmentation_metrics(&config.root, &s_root, repo, &packs_before).await?;
        let (compaction_triggered, repack_report) = if policy.auto_repack_enabled
            && (packs_before.len() as i32) > policy.max_active_packs
        {
            let rep = repack::repack_repo(
                config,
                repo,
                &repack::RepackOptions {
                    prune_superseded: true,
                    pin_oids: Vec::new(),
                    sync_object_store: true,
                },
            )
            .await?;
            (true, Some(rep))
        } else {
            (false, None)
        };

        let packs_after = load_repo_packs(c, repo).await?;
        let fragmentation_after =
            compute_fragmentation_metrics(&config.root, &s_root, repo, &packs_after).await?;
        let active_ids: Vec<Uuid> = packs_after.iter().map(|p| p.id).collect();
        c.execute(
            "DELETE FROM pando_lab.kms_envelopes WHERE repo=$1 AND NOT (pack_id = ANY($2))",
            &[&repo, &active_ids],
        )
        .await?;

        let tier = if opts.cold_evict_local || policy.cold_transition_age_secs == 0 {
            "cold_archive"
        } else {
            "hot"
        };
        let (mut envelopes, mut cold_count, mut evicted_count) = (Vec::new(), 0usize, 0usize);
        for pack in &packs_after {
            let env = if crypto::is_authenticated_mode(mode) {
                // The committed DB row is authoritative. Only a DB-absent
                // legacy row may read the file, and it is published to the DB
                // before the mirror is refreshed.
                if let Some(mut cur_env) = load_db_envelope_authority(c, repo, pack).await? {
                    if cur_env.storage_tier != tier
                        && crypto::is_authenticated_mode(&cur_env.encryption_mode)
                    {
                        cur_env.storage_tier = tier.to_owned();
                        cur_env.envelope_mac =
                            crypto::compute_authenticated_envelope_mac(&crypto::EnvelopeMacInputs {
                                encryption_mode: &cur_env.encryption_mode,
                                repo,
                                pack_id: pack.id,
                                key_id: &cur_env.key_id,
                                key_version: cur_env.key_version,
                                cipher_suite: &cur_env.cipher_suite,
                                pack_sha256: &cur_env.pack_sha256,
                                idx_sha256: &cur_env.idx_sha256,
                                ciphertext_sha256: cur_env.ciphertext_sha256.as_deref().unwrap_or(""),
                                ciphertext_bytes: cur_env.ciphertext_bytes.unwrap_or(0),
                                envelope_id: cur_env.envelope_id.context("missing envelope_id")?,
                                nonce_prefix: cur_env.nonce_prefix.as_deref().unwrap_or(""),
                                wrapped_key_json: cur_env.wrapped_key_json.as_deref().unwrap_or(""),
                            });
                        db::upsert_envelope_in_db(c, &cur_env).await?;
                    }
                    let _ = write_envelope_file(&config.root, &cur_env);
                    cur_env
                } else {
                    // Config-backed DB authority has no implicit legacy-file
                    // adoption. A store manifest or envelope file without a
                    // committed DB row is a partial prior publication and must
                    // fail closed rather than overwrite DB authority.
                    let store_manifest = s_root.join(object_store::manifest_key(repo, pack.id));
                    let disk = envelope_file_path(&config.root, repo, pack.id);
                    if store_manifest.is_file() || disk.is_file() {
                        return Err(fenced(format!(
                            "DB-authoritative lifecycle evaluation refuses pack {}: a store manifest or KMS envelope file exists without a committed DB envelope; refusing implicit legacy-file adoption",
                            pack.id
                        )));
                    }
                    // A brand-new unpublished pack may create a fresh
                    // authority through the ordinary checkpoint-aware gated
                    // publisher; it never adopts an existing file envelope.
                    object_store::put_pack_and_seal_with_suite(config, repo, pack.id, suite, tier).await?
                }
            } else {
                ensure_no_authenticated_envelope(c, &config.root, &s_root, repo, pack).await?;
                let syn =
                    build_envelope_record(repo, pack, &policy.kms_key_id, policy.kms_key_version, suite, tier)?;
                db::upsert_envelope_in_db(c, &syn).await?;
                let _ = write_envelope_file(&config.root, &syn);
                syn
            };
            if tier == "cold_archive" {
                cold_count += 1;
                if opts.cold_evict_local && evict_cold_pack_local(&config.root, &s_root, repo, pack)? {
                    evicted_count += 1;
                }
            }
            envelopes.push(env);
        }
        (
            policy,
            fragmentation_before,
            compaction_triggered,
            repack_report,
            fragmentation_after,
            envelopes,
            cold_count,
            evicted_count,
        )
    };

    // rotate_kms_key needs the runner lock plus the exclusive publication
    // lock; it must never run while this invocation owns the shared session.
    let rotate_target = opts
        .kms_key_id
        .as_deref()
        .map(str::trim)
        .filter(|requested| {
            *requested != policy.kms_key_id.as_str() && crypto::is_authenticated_mode(mode)
        })
        .map(str::to_owned);
    if let Some(requested_key) = rotate_target {
        let rot = rotate_kms_key(config, repo, &requested_key).await?;
        policy.kms_key_id = rot.new_key_id;
        policy.kms_key_version = rot.new_key_version;
        envelopes = rot.envelopes;
    }

    Ok(LifecycleEvaluationReport {
        repo,
        policy,
        fragmentation_before,
        fragmentation_after,
        compaction_triggered,
        repack_report,
        envelopes_recorded: envelopes.len(),
        cold_archive_packs: cold_count,
        local_packs_evicted: evicted_count,
        envelopes,
        encryption_mode: mode.to_owned(),
        authenticated_encryption: crypto::is_authenticated_mode(mode),
    })
}

pub(super) async fn status_inner(config: &Config, repo: Uuid) -> Result<LifecycleStatusReport> {
    let c = config.db().await?;
    c.execute(
        "INSERT INTO pando_lab.lifecycle_policies(repo) VALUES($1) ON CONFLICT(repo) DO NOTHING",
        &[&repo],
    )
    .await?;
    let p = c
        .query_one(
            "SELECT max_active_packs,cold_transition_age_secs,auto_repack_enabled,kms_key_id,kms_key_version FROM pando_lab.lifecycle_policies WHERE repo=$1",
            &[&repo],
        )
        .await?;
    let policy = LifecyclePolicy {
        repo,
        max_active_packs: p.get(0),
        cold_transition_age_secs: p.get(1),
        auto_repack_enabled: p.get(2),
        kms_key_id: p.get(3),
        kms_key_version: p.get(4),
    };
    let packs = load_repo_packs(&c, repo).await?;
    let fragmentation =
        compute_fragmentation_metrics(&config.root, &object_store::store_root(config), repo, &packs).await?;
    let (mut envelopes, mut hot_packs, mut cold_packs, mut all_verified, mut all_auth) =
        (Vec::new(), 0usize, 0usize, true, !packs.is_empty());
    for pack in &packs {
        if let Some(env) = db::load_envelope_from_db(&c, repo, pack).await? {
            if verify_envelope_record(&env).is_err() {
                all_verified = false;
            }
            if !crypto::is_authenticated_mode(&env.encryption_mode) {
                all_auth = false;
            }
            if env.storage_tier == "cold_archive" {
                cold_packs += 1;
            } else {
                hot_packs += 1;
            }
            envelopes.push(env);
        } else {
            all_auth = false;
        }
    }
    Ok(LifecycleStatusReport {
        repo,
        policy,
        fragmentation,
        envelopes,
        hot_packs,
        cold_archive_packs: cold_packs,
        all_envelopes_verified: all_verified,
        authenticated_encryption: all_auth,
    })
}
