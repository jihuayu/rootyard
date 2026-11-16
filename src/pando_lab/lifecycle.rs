use super::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs::File};

mod cli;
pub mod crypto;
mod data_key;
mod db;
pub mod envelopes;
mod eval;
pub mod provider;
pub(crate) mod provider_selection;
pub(crate) mod publication;
pub mod rotation;
mod vault_provider;
mod wrapped_dek;

pub use envelopes::{
    build_authenticated_envelope_record, build_envelope_record, envelope_file_path,
    read_and_verify_envelope_file, verify_envelope_record, write_envelope_file,
};
pub(crate) use eval::load_repo_packs;

pub const DEFAULT_MAX_ACTIVE_PACKS: i32 = 4;
pub const DEFAULT_COLD_TRANSITION_AGE_SECS: i64 = 86_400;
pub const DEFAULT_KMS_KEY_ID: &str = "kms-local-default-v1";
pub const DEFAULT_KMS_KEY_VERSION: i32 = 1;
pub const DEFAULT_CIPHER_SUITE: &str = "AES-256-GCM-HMAC-SHA256";
pub const ENVELOPE_SCHEMA: &str = "rootyard.pando.kms-envelope.v1";

fn default_synthetic_mode() -> String {
    crypto::SYNTHETIC_METADATA_MODE.to_owned()
}
fn default_authenticated_mode() -> String {
    crypto::AUTHENTICATED_ENVELOPE_MODE.to_owned()
}
fn default_provider_kind() -> String {
    provider::PROVIDER_KIND_LOCAL.to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecyclePolicy {
    pub repo: Uuid,
    pub max_active_packs: i32,
    pub cold_transition_age_secs: i64,
    pub auto_repack_enabled: bool,
    pub kms_key_id: String,
    pub kms_key_version: i32,
}

impl LifecyclePolicy {
    pub fn default_for_repo(repo: Uuid) -> Self {
        Self {
            repo,
            max_active_packs: DEFAULT_MAX_ACTIVE_PACKS,
            cold_transition_age_secs: DEFAULT_COLD_TRANSITION_AGE_SECS,
            auto_repack_enabled: true,
            kms_key_id: DEFAULT_KMS_KEY_ID.to_owned(),
            kms_key_version: DEFAULT_KMS_KEY_VERSION,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleEvaluateOptions {
    #[serde(default)]
    pub max_active_packs: Option<i32>,
    #[serde(default)]
    pub cold_transition_age_secs: Option<i64>,
    #[serde(default)]
    pub auto_repack_enabled: Option<bool>,
    #[serde(default)]
    pub cold_evict_local: bool,
    #[serde(default)]
    pub kms_key_id: Option<String>,
    #[serde(default)]
    pub cipher_suite: Option<String>,
    #[serde(default)]
    pub encryption_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FragmentationMetrics {
    pub active_packs: usize,
    pub total_pack_bytes: u64,
    pub total_idx_bytes: u64,
    pub total_objects_across_packs: usize,
    pub unique_objects: usize,
    pub duplicate_objects: usize,
    pub duplicate_object_ratio: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsEnvelopeRecord {
    pub schema: String,
    pub repo: Uuid,
    pub pack_id: Uuid,
    pub key_id: String,
    pub key_version: i32,
    pub cipher_suite: String,
    pub pack_sha256: String,
    pub idx_sha256: String,
    pub plaintext_sha256: String,
    pub envelope_mac: String,
    pub storage_tier: String,
    #[serde(default = "default_synthetic_mode")]
    pub encryption_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_key_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_bytes: Option<u64>,
    #[serde(default = "default_provider_kind")]
    pub provider_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleEvaluationReport {
    pub repo: Uuid,
    pub policy: LifecyclePolicy,
    pub fragmentation_before: FragmentationMetrics,
    pub fragmentation_after: FragmentationMetrics,
    pub compaction_triggered: bool,
    pub repack_report: Option<repack::RepackReport>,
    pub envelopes_recorded: usize,
    pub cold_archive_packs: usize,
    pub local_packs_evicted: usize,
    pub envelopes: Vec<KmsEnvelopeRecord>,
    #[serde(default = "default_authenticated_mode")]
    pub encryption_mode: String,
    #[serde(default)]
    pub authenticated_encryption: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsRotationReport {
    pub repo: Uuid,
    pub previous_key_id: String,
    pub previous_key_version: i32,
    pub new_key_id: String,
    pub new_key_version: i32,
    pub envelopes_rewrapped: usize,
    pub envelopes_verified: usize,
    pub envelopes: Vec<KmsEnvelopeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleStatusReport {
    pub repo: Uuid,
    pub policy: LifecyclePolicy,
    pub fragmentation: FragmentationMetrics,
    pub envelopes: Vec<KmsEnvelopeRecord>,
    pub hot_packs: usize,
    pub cold_archive_packs: usize,
    pub all_envelopes_verified: bool,
    #[serde(default)]
    pub authenticated_encryption: bool,
}

pub fn valid_kms_key_id(key_id: &str) -> bool {
    let t = key_id.trim();
    t.len() >= 3
        && t.len() <= 128
        && rootyard::blob_store::key_provider::KeyId::parse(t).is_ok()
}
pub fn valid_cipher_suite(suite: &str) -> bool {
    matches!(
        suite,
        "AES-256-GCM-HMAC-SHA256" | "CHACHA20-POLY1305-SHA256"
    )
}
pub fn valid_storage_tier(tier: &str) -> bool {
    matches!(tier, "hot" | "cold_archive")
}
pub fn valid_sha256_hex(hex_str: &str) -> bool {
    crypto::is_valid_sha256_hex(hex_str)
}
pub fn valid_encryption_mode(mode: &str) -> bool {
    matches!(
        mode,
        crypto::AUTHENTICATED_ENVELOPE_MODE | crypto::SYNTHETIC_METADATA_MODE
    )
}

pub async fn compute_fragmentation_metrics(
    root: &Path,
    store_root_dir: &Path,
    repo: Uuid,
    packs: &[Pack],
) -> Result<FragmentationMetrics> {
    let objects_root = root.join("objects");
    let bucket = object_store::default_bucket();
    let (mut total_pack_bytes, mut total_idx_bytes, mut total_objs) = (0u64, 0u64, 0usize);
    let mut unique_oids = BTreeSet::new();
    for pack in packs {
        object_store::get_pack_files(
            store_root_dir,
            &objects_root,
            &bucket,
            repo,
            pack.id,
            Some(&pack.pack_sha256),
            Some(&pack.idx_sha256),
        ).await?;
        let pfx = objects_root.join(repo.to_string()).join(pack.id.to_string());
        let (pb, ib) = (
            std::fs::read(pfx.with_extension("pack"))?,
            std::fs::read(pfx.with_extension("idx"))?,
        );
        total_pack_bytes += pb.len() as u64;
        total_idx_bytes += ib.len() as u64;
        let rep = delta::verify_pack(&pb, &delta::Limits::default())?;
        total_objs += rep.object_count;
        unique_oids.extend(rep.objects.into_iter().map(|o| o.oid));
    }
    let unique_objects = unique_oids.len();
    let duplicate_objects = total_objs.saturating_sub(unique_objects);
    let duplicate_object_ratio = if total_objs == 0 {
        0.0
    } else {
        (duplicate_objects as f64) / (total_objs as f64)
    };
    Ok(FragmentationMetrics {
        active_packs: packs.len(),
        total_pack_bytes,
        total_idx_bytes,
        total_objects_across_packs: total_objs,
        unique_objects,
        duplicate_objects,
        duplicate_object_ratio,
    })
}

pub fn evict_cold_pack_local(root: &Path, store_root_dir: &Path, repo: Uuid, pack: &Pack) -> Result<bool> {
    let env = read_and_verify_envelope_file(root, repo, pack.id)?;
    ensure!(
        env.storage_tier == "cold_archive"
            && env.pack_sha256 == pack.pack_sha256
            && env.idx_sha256 == pack.idx_sha256,
        "pack not eligible for cold eviction"
    );
    ensure!(
        store_root_dir
            .join(object_store::manifest_key(repo, pack.id))
            .is_file(),
        "remote object-store manifest required before evicting local pack"
    );
    let repo_dir = root.join("objects").join(repo.to_string());
    let (local_idx, local_pack) = (
        repo_dir.join(format!("{}.idx", pack.id)),
        repo_dir.join(format!("{}.pack", pack.id)),
    );
    ensure!(
        local_idx.is_file() && delta::sha256_hex(&std::fs::read(&local_idx)?) == pack.idx_sha256,
        "local .idx missing or corrupt for cold pack"
    );
    if local_pack.is_file() {
        std::fs::remove_file(&local_pack)?;
        File::open(&repo_dir)?.sync_all()?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub async fn hydrate_cold_pack_verified(
    root: &Path,
    store_root_dir: &Path,
    bucket: &str,
    repo: Uuid,
    pack: &Pack,
) -> Result<object_store::ObjectStoreGetReport> {
    let env = read_and_verify_envelope_file(root, repo, pack.id)?;
    ensure!(
        crypto::is_authenticated_mode(&env.encryption_mode),
        "cold hydration rejects synthetic metadata-only mode '{}'",
        env.encryption_mode
    );
    ensure!(
        env.pack_sha256 == pack.pack_sha256 && env.idx_sha256 == pack.idx_sha256,
        "KMS envelope digest mismatch against pack manifest"
    );
    let local_idx = root
        .join("objects")
        .join(repo.to_string())
        .join(format!("{}.idx", pack.id));
    ensure!(
        local_idx.is_file() && delta::sha256_hex(&std::fs::read(&local_idx)?) == pack.idx_sha256,
        "local .idx missing or corrupt before cold pack hydration"
    );
    object_store::get_pack_files(
        store_root_dir,
        &root.join("objects"),
        bucket,
        repo,
        pack.id,
        Some(&pack.pack_sha256),
        Some(&pack.idx_sha256),
    ).await
}

pub(super) async fn evaluate_lifecycle(
    config: &Config,
    repo: Uuid,
    opts: &LifecycleEvaluateOptions,
) -> Result<LifecycleEvaluationReport> {
    eval::evaluate_lifecycle_inner(config, repo, opts).await
}

pub(super) async fn rotate_kms_key(
    config: &Config,
    repo: Uuid,
    new_key_id: &str,
) -> Result<KmsRotationReport> {
    rotation::rotate_kms_key_with_options(
        config,
        repo,
        &rotation::KmsRotateOptions {
            target_key_id: Some(new_key_id.to_owned()),
            ..Default::default()
        },
    )
    .await
}

pub(super) async fn status(config: &Config, repo: Uuid) -> Result<LifecycleStatusReport> {
    eval::status_inner(config, repo).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn authenticated_pack_encryption_rotation_revocation_and_tamper_rejection() {
        let tmp = std::env::temp_dir().join(format!("pando-lifecycle-test-{}", Uuid::new_v4()));
        let objects_root = tmp.join("objects");
        let (repo, pack_id) = (Uuid::new_v4(), Uuid::new_v4());
        let dir = objects_root.join(repo.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        let payload = b"rootyard-secret-pack-payload";
        let mut pack_bytes = Vec::from(&b"PACK\x00\x00\x00\x02\x00\x00\x00\x01"[..]);
        pack_bytes.push(0x80 | 0x30 | ((payload.len() & 0x0f) as u8));
        pack_bytes.push((payload.len() >> 4) as u8);
        pack_bytes.extend_from_slice(&delta::compress_zlib_stored(payload));
        let tr = delta::sha1_digest(&pack_bytes);
        pack_bytes.extend_from_slice(&tr);
        let idx_bytes = b"idx-cold-tier-test".to_vec();
        std::fs::write(dir.join(format!("{pack_id}.pack")), &pack_bytes).unwrap();
        std::fs::write(dir.join(format!("{pack_id}.idx")), &idx_bytes).unwrap();

        let pack = Pack { id: pack_id, pack_sha256: delta::sha256_hex(&pack_bytes), idx_sha256: delta::sha256_hex(&idx_bytes) };
        let (put_rep, _) = object_store::put_pack_files(&tmp, &objects_root, repo, pack_id, &Default::default()).await.unwrap();
        let cipher_on_disk = std::fs::read(&put_rep.bucket_pack_path).unwrap();
        assert!(!cipher_on_disk.starts_with(b"PACK"));
        assert!(!cipher_on_disk.windows(pack_bytes.len()).any(|w| w == pack_bytes.as_slice()));

        let mut env = read_and_verify_envelope_file(&tmp, repo, pack_id).unwrap();
        assert_eq!(env.encryption_mode, crypto::AUTHENTICATED_ENVELOPE_MODE);
        assert_eq!(env.provider_kind, provider::PROVIDER_KIND_LOCAL);
        verify_envelope_record(&env).unwrap();

        // Legacy authenticated envelopes may predate the provider_kind field;
        // serde's default keeps them readable as the supported local kind.
        let mut legacy_value = serde_json::to_value(&env).unwrap();
        legacy_value.as_object_mut().unwrap().remove("provider_kind");
        let legacy: KmsEnvelopeRecord = serde_json::from_value(legacy_value).unwrap();
        assert_eq!(legacy.provider_kind, provider::PROVIDER_KIND_LOCAL);
        verify_envelope_record(&legacy).unwrap();

        let mut changed_provider = env.clone();
        changed_provider.provider_kind = "external-kms-v1".to_owned();
        assert!(verify_envelope_record(&changed_provider).is_err());
        changed_provider.wrapped_key_json = Some("not-a-wrapped-dek".to_owned());
        assert!(verify_envelope_record(&changed_provider).is_err());
        env.storage_tier = "cold_archive".to_owned();
        env.envelope_mac = crypto::compute_authenticated_envelope_mac(&crypto::EnvelopeMacInputs {
            encryption_mode: &env.encryption_mode, repo, pack_id, key_id: &env.key_id, key_version: env.key_version,
            cipher_suite: &env.cipher_suite, pack_sha256: &env.pack_sha256, idx_sha256: &env.idx_sha256,
            ciphertext_sha256: env.ciphertext_sha256.as_deref().unwrap(), ciphertext_bytes: env.ciphertext_bytes.unwrap(),
            envelope_id: env.envelope_id.unwrap(), nonce_prefix: env.nonce_prefix.as_deref().unwrap(),
            wrapped_key_json: env.wrapped_key_json.as_deref().unwrap(),
        });
        write_envelope_file(&tmp, &env).unwrap();
        assert!(evict_cold_pack_local(&tmp, &tmp, repo, &pack).unwrap());
        let hydrated = hydrate_cold_pack_verified(&tmp, &tmp, "pando-default", repo, &pack).await.unwrap();
        assert!(hydrated.rehydrated_from_object_store && std::fs::read(dir.join(format!("{pack_id}.pack"))).unwrap() == pack_bytes);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
