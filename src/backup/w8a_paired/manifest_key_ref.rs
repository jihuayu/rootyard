//! Non-secret key/config identity for a W8-A paired archive; key bytes never enter it.
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::encryption_config::BlobEncryptionConfig;
use crate::blob_store::key_provider::{DATA_KEY_BYTES, WrapContext, WrappedKey};

use super::{W8aError, W8aResult};
pub const MANIFEST_SEAL_DOMAIN: &[u8] = b"rootyard-w8a-manifest-v1\0";
pub const KEY_CANARY_DOMAIN: &[u8] = b"rootyard-w8a-key-canary-v1\0";
pub const KEY_DIGEST_DOMAIN: &[u8] = b"rootyard-w8a-keyring-public-v1\0";
pub const W8A_FORMAT_VERSION: &str = "rootyard-w8a-pg-blob-v1";
pub const ENV_KMS_KEY_REF: &str = "ROOTYARD_BLOB_KMS_KEY_REF";
pub const ENV_PAIRED_RAFT_CLUSTER: &str = "ROOTYARD_PAIRED_RAFT_CLUSTER_JSON";
const KEYRING_MANIFEST: &str = "keyring.json";
const MAX_KEYRING_MANIFEST_BYTES: u64 = 16 * 1024;
const CANARY_NAMESPACE: &str = "w8a-key-canary";
fn mismatch(reason: impl Into<String>) -> W8aError {
    W8aError::KeyReferenceMismatch(reason.into())
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct W8aKeyReference {
    pub mode: String,
    pub active_key_id: Option<String>,
    pub known_key_ids: Vec<String>,
    pub key_ids_digest: Option<String>,
    pub kms_key_reference: Option<String>,
    pub canary_attempt_id: Option<Uuid>,
    pub canary_wrapped_key_json: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct W8aPairedSidecarManifest {
    pub w8a_backup_id: Uuid,
    pub format: u32,
    pub schema_head: i32,
    pub schema_contract_sha256: String,
    pub metadata_dump_sha256: String,
    pub inner_manifest_sha256: String,
    pub inner_complete_sha256: String,
    pub inner_backup_id: Uuid,
    pub inner_volume_id: Uuid,
    pub blob_repository_count: usize,
    pub blob_artifact_count: usize,
    pub blob_total_bytes: u64,
    pub blob_closure_digest: String,
    pub blob_backend_identity: String,
    pub blob_provider: String,
    pub source_cluster_incarnation: Uuid,
    pub source_storage_authority_id: Uuid,
    pub source_storage_authority_epoch: i64,
    pub key_reference: W8aKeyReference,
    pub single_node_w8a: bool,
    pub raft_cut_supported: bool,
    pub paired_restore_trusted: bool,
    pub manifest_seal_sha256: String,
}
impl W8aPairedSidecarManifest {
    /// Canonical seal: same object with the seal field blank, fixed struct order, domain tag.
    pub fn compute_manifest_seal(&self) -> W8aResult<String> {
        let mut canonical = self.clone();
        canonical.manifest_seal_sha256.clear();
        let bytes = serde_json::to_vec(&canonical)
            .map_err(|error| W8aError::MixedPointInTime(format!("sidecar serialization failed: {error}")))?;
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_SEAL_DOMAIN);
        hasher.update(bytes);
        Ok(hex::encode(hasher.finalize()))
    }
    pub fn seal(mut self) -> W8aResult<Self> {
        self.manifest_seal_sha256 = self.compute_manifest_seal()?;
        Ok(self)
    }
    pub fn verify_manifest_seal(&self) -> W8aResult<()> {
        if self.manifest_seal_sha256.is_empty() {
            return Err(W8aError::MixedPointInTime("sidecar manifest seal is missing".into()));
        }
        if self.manifest_seal_sha256 != self.compute_manifest_seal()? {
            return Err(W8aError::MixedPointInTime(
                "sidecar manifest seal does not cover the recorded archive identity".into(),
            ));
        }
        Ok(())
    }
}
pub fn capture_key_reference(w8a_backup_id: Uuid, blob_backend_identity: &str) -> W8aResult<W8aKeyReference> {
    let config = BlobEncryptionConfig::from_env()
        .map_err(|error| W8aError::KeyReferenceMismatch(format!("blob encryption configuration: {error}")))?;
    let keyring = std::env::var_os(crate::blob_store::encryption_config::ENV_BLOB_KEYRING_DIR);
    let kms = std::env::var(ENV_KMS_KEY_REF).ok();
    capture_key_reference_with(
        &config,
        keyring.as_deref().map(Path::new),
        kms.as_deref(),
        w8a_backup_id,
        blob_backend_identity,
    )
}
pub fn verify_key_reference(
    expected: &W8aKeyReference,
    w8a_backup_id: Uuid,
    blob_backend_identity: &str,
) -> W8aResult<()> {
    let config = BlobEncryptionConfig::from_env()
        .map_err(|error| W8aError::KeyReferenceMismatch(format!("blob encryption configuration: {error}")))?;
    let keyring = std::env::var_os(crate::blob_store::encryption_config::ENV_BLOB_KEYRING_DIR);
    let kms = std::env::var(ENV_KMS_KEY_REF).ok();
    verify_key_reference_with(
        &config,
        keyring.as_deref().map(Path::new),
        kms.as_deref(),
        expected,
        w8a_backup_id,
        blob_backend_identity,
    )
}
pub(super) fn capture_key_reference_with(
    config: &BlobEncryptionConfig,
    keyring_dir: Option<&Path>,
    kms_reference: Option<&str>,
    w8a_backup_id: Uuid,
    blob_backend_identity: &str,
) -> W8aResult<W8aKeyReference> {
    let mode = mode_name(config);
    if config.is_provider_managed() {
        return Ok(W8aKeyReference {
            mode,
            active_key_id: None,
            known_key_ids: Vec::new(),
            key_ids_digest: None,
            kms_key_reference: validated_kms_reference(kms_reference)?,
            canary_attempt_id: None,
            canary_wrapped_key_json: None,
        });
    }
    let provider = config
        .open_key_provider()
        .map_err(|error| W8aError::KeyReferenceMismatch(format!("opening the key provider: {error}")))?
        .ok_or_else(|| W8aError::KeyReferenceMismatch("local-envelope mode has no key provider".into()))?;
    let dir = keyring_dir.ok_or_else(|| {
        W8aError::KeyReferenceMismatch("ROOTYARD_BLOB_KEYRING_DIR is required for local-envelope".into())
    })?;
    let (active_key_id, known_key_ids, key_ids_digest) = keyring_identity(dir)?;
    if active_key_id != provider.current_key_id().as_str() {
        return Err(mismatch("keyring current key differs from provider"));
    }
    let probe = canary_probe(w8a_backup_id, blob_backend_identity);
    let attempt_id = derived_uuid(&probe, b"attempt");
    let context = WrapContext::new(
        derived_uuid(&probe, b"tenant"),
        derived_uuid(&probe, b"authority"),
        1,
        attempt_id,
        CANARY_NAMESPACE,
        &hex::encode(probe),
    )
    .map_err(|error| W8aError::KeyReferenceMismatch(format!("canary wrap context: {error}")))?;
    let wrapped = provider
        .wrap_data_key(&probe, &context)
        .map_err(|error| W8aError::KeyReferenceMismatch(format!("wrapping the canary key: {error}")))?;
    let canary_wrapped_key_json = wrapped
        .to_json()
        .map_err(|error| W8aError::KeyReferenceMismatch(format!("serializing the canary key: {error}")))?;
    Ok(W8aKeyReference {
        mode,
        active_key_id: Some(active_key_id),
        known_key_ids,
        key_ids_digest: Some(key_ids_digest),
        kms_key_reference: validated_kms_reference(kms_reference)?,
        canary_attempt_id: Some(attempt_id),
        canary_wrapped_key_json: Some(canary_wrapped_key_json),
    })
}
pub(super) fn verify_key_reference_with(
    config: &BlobEncryptionConfig,
    keyring_dir: Option<&Path>,
    current_kms: Option<&str>,
    expected: &W8aKeyReference,
    w8a_backup_id: Uuid,
    blob_backend_identity: &str,
) -> W8aResult<()> {
    let mode = mode_name(config);
    if mode != expected.mode {
        return Err(mismatch(format!("archive mode `{}` differs from the current mode `{mode}`", expected.mode)));
    }
    let probe = canary_probe(w8a_backup_id, blob_backend_identity);
    if config.is_provider_managed() {
        if expected.active_key_id.is_some()
            || !expected.known_key_ids.is_empty()
            || expected.key_ids_digest.is_some()
            || expected.canary_attempt_id.is_some()
            || expected.canary_wrapped_key_json.is_some()
        {
            return Err(mismatch("provider-managed archive carries local key identity"));
        }
        let current = validated_kms_reference(current_kms)?;
        if current != expected.kms_key_reference {
            return Err(mismatch("provider-managed KMS reference differs from the archive"));
        }
        return Ok(());
    }
    let provider = config
        .open_key_provider()
        .map_err(|error| W8aError::KeyReferenceMismatch(format!("opening the key provider: {error}")))?
        .ok_or_else(|| W8aError::KeyReferenceMismatch("local-envelope mode has no key provider".into()))?;
    let dir = keyring_dir.ok_or_else(|| {
        W8aError::KeyReferenceMismatch("ROOTYARD_BLOB_KEYRING_DIR is required for local-envelope".into())
    })?;
    let (active_key_id, known_key_ids, key_ids_digest) = keyring_identity(dir)?;
    if Some(active_key_id) != expected.active_key_id
        || known_key_ids != expected.known_key_ids
        || Some(key_ids_digest) != expected.key_ids_digest
    {
        return Err(mismatch("local keyring ids or public fingerprints differ from the archive"));
    }
    if expected.canary_wrapped_key_json.is_none() || expected.canary_attempt_id.is_none() {
        return Err(mismatch("local-envelope archive has no key canary"));
    }
    let attempt_id = expected.canary_attempt_id.unwrap_or_default();
    let context = WrapContext::new(
        derived_uuid(&probe, b"tenant"),
        derived_uuid(&probe, b"authority"),
        1,
        attempt_id,
        CANARY_NAMESPACE,
        &hex::encode(probe),
    )
    .map_err(|error| W8aError::KeyReferenceMismatch(format!("canary wrap context: {error}")))?;
    let wrapped = WrappedKey::from_json(expected.canary_wrapped_key_json.as_deref().unwrap_or_default().as_bytes())
        .map_err(|error| W8aError::KeyReferenceMismatch(format!("parsing the canary key: {error}")))?;
    let unwrapped = provider
        .unwrap_data_key(&wrapped, &context)
        .map_err(|error| W8aError::KeyReferenceMismatch(format!("unwrapping the canary key: {error}")))?;
    if unwrapped.expose_secret() != &probe {
        return Err(mismatch("canary key does not round-trip"));
    }
    Ok(())
}
fn mode_name(config: &BlobEncryptionConfig) -> String {
    if config.is_local_envelope() { "local-envelope".into() } else { "provider-managed".into() }
}
fn canary_probe(w8a_backup_id: Uuid, blob_backend_identity: &str) -> [u8; DATA_KEY_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_CANARY_DOMAIN);
    hasher.update(w8a_backup_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(blob_backend_identity.as_bytes());
    hasher.finalize().into()
}
fn derived_uuid(probe: &[u8; DATA_KEY_BYTES], label: &[u8]) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(probe);
    hasher.update([0u8]);
    hasher.update(label);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringManifest {
    schema: u32,
    current: String,
    keys: Vec<KeyringEntry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringEntry {
    key_id: String,
    sha256: String,
}
fn keyring_identity(dir: &Path) -> W8aResult<(String, Vec<String>, String)> {
    let path = dir.join(KEYRING_MANIFEST);
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| W8aError::KeyReferenceMismatch(format!("reading keyring manifest metadata: {error}")))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(mismatch("keyring manifest must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
            return Err(mismatch("keyring manifest must be private and single-link"));
        }
    }
    if metadata.len() > MAX_KEYRING_MANIFEST_BYTES {
        return Err(mismatch("keyring manifest is too large"));
    }
    let bytes = std::fs::read(&path)
        .map_err(|error| W8aError::KeyReferenceMismatch(format!("reading keyring manifest: {error}")))?;
    let manifest: KeyringManifest = serde_json::from_slice(&bytes)
        .map_err(|error| W8aError::KeyReferenceMismatch(format!("parsing keyring manifest: {error}")))?;
    if manifest.schema != 1 {
        return Err(mismatch("keyring manifest schema must be 1"));
    }
    let mut entries: Vec<(String, String)> =
        manifest.keys.into_iter().map(|entry| (entry.key_id, entry.sha256)).collect();
    entries.sort();
    for (id, fingerprint) in &entries {
        if id.is_empty()
            || id.len() > 64
            || fingerprint.len() != 64
            || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(mismatch("keyring key id or fingerprint is invalid"));
        }
    }
    let known_key_ids: Vec<String> = entries.iter().map(|(id, _)| id.clone()).collect();
    let mut hasher = Sha256::new();
    hasher.update(KEY_DIGEST_DOMAIN);
    for (id, fingerprint) in &entries {
        hasher.update(id.as_bytes());
        hasher.update([0u8]);
        hasher.update(fingerprint.as_bytes());
    }
    Ok((manifest.current, known_key_ids, hex::encode(hasher.finalize())))
}
fn validated_kms_reference(reference: Option<&str>) -> W8aResult<Option<String>> {
    let Some(reference) = reference else { return Ok(None) };
    if reference.is_empty() || reference.len() > 256 {
        return Err(mismatch("KMS reference is empty or too long"));
    }
    if !reference.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(mismatch("KMS reference must be a single printable non-secret token"));
    }
    let lowered = reference.to_ascii_lowercase();
    for forbidden in ["secret", "password", "credential", "token="] {
        if lowered.contains(forbidden) {
            return Err(mismatch("KMS reference appears to contain a secret"));
        }
    }
    Ok(Some(reference.to_owned()))
}
