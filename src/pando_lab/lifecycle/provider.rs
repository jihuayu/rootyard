use super::crypto::sha256_hex;
use super::data_key::PandoDataKey;
use super::wrapped_dek::PandoWrappedDek;
use anyhow::{Context, Result, bail, ensure};
use futures_util::future::BoxFuture;
use ring::rand::{SecureRandom, SystemRandom};
use rootyard::blob_store::key_provider::{
    DATA_KEY_BYTES, DataKey, KeyId, KeyProvider, KeyProviderCapabilities, KeyProviderError,
    LocalFileKeyProvider, WrapContext, WrappedKey,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const POLICY_FILE_NAME: &str = "kms_policy.json";
pub const KEYRING_FILE_NAME: &str = "keyring.json";
pub const PROVIDER_KIND_LOCAL: &str = "local-file-key-provider";
pub const PROVIDER_KIND_VAULT: &str = "vault-transit";

/// Pando-only provider boundary. Unlike the shared Blob `KeyProvider`, this
/// boundary is async so a network-backed provider (for example Vault Transit)
/// can be added in a later checkpoint without blocking an async runtime. The
/// local concrete provider remains available through the synchronous shared
/// `KeyProvider` trait as a compatibility path.
pub trait PandoKeyProvider: fmt::Debug + Send + Sync {
    fn current_key_id(&self) -> &KeyId;
    fn capabilities(&self) -> KeyProviderCapabilities;
    fn wrap_data_key<'a>(
        &'a self,
        data_key: &'a PandoDataKey,
        context: &'a WrapContext,
    ) -> BoxFuture<'a, std::result::Result<PandoWrappedDek, KeyProviderError>>;
    fn unwrap_data_key<'a>(
        &'a self,
        wrapped: &'a PandoWrappedDek,
        context: &'a WrapContext,
    ) -> BoxFuture<'a, std::result::Result<PandoDataKey, KeyProviderError>>;
    fn rewrap_data_key<'a>(
        &'a self,
        wrapped: &'a PandoWrappedDek,
        context: &'a WrapContext,
    ) -> BoxFuture<'a, std::result::Result<PandoWrappedDek, KeyProviderError>>;
}

impl<T: KeyProvider + ?Sized> PandoKeyProvider for T {
    fn current_key_id(&self) -> &KeyId {
        KeyProvider::current_key_id(self)
    }

    fn capabilities(&self) -> KeyProviderCapabilities {
        KeyProvider::capabilities(self)
    }

    fn wrap_data_key<'a>(
        &'a self,
        data_key: &'a PandoDataKey,
        context: &'a WrapContext,
    ) -> BoxFuture<'a, std::result::Result<PandoWrappedDek, KeyProviderError>> {
        Box::pin(async move {
            let wrapped = KeyProvider::wrap_data_key(self, data_key.expose_secret(), context)?;
            Ok(PandoWrappedDek::Local(wrapped))
        })
    }

    fn unwrap_data_key<'a>(
        &'a self,
        wrapped: &'a PandoWrappedDek,
        context: &'a WrapContext,
    ) -> BoxFuture<'a, std::result::Result<PandoDataKey, KeyProviderError>> {
        Box::pin(async move {
            let PandoWrappedDek::Local(wrapped) = wrapped else {
                return Err(KeyProviderError::InvalidWrappedKey(
                    "external wrapped DEK cannot be unwrapped by the local provider",
                ));
            };
            let data_key = KeyProvider::unwrap_data_key(self, wrapped, context)?;
            Ok(PandoDataKey::copy_from_slice(data_key.expose_secret()))
        })
    }

    fn rewrap_data_key<'a>(
        &'a self,
        wrapped: &'a PandoWrappedDek,
        context: &'a WrapContext,
    ) -> BoxFuture<'a, std::result::Result<PandoWrappedDek, KeyProviderError>> {
        Box::pin(async move {
            let PandoWrappedDek::Local(wrapped) = wrapped else {
                return Err(KeyProviderError::InvalidWrappedKey(
                    "external wrapped DEK cannot be rewrapped by the local provider",
                ));
            };
            let rewrapped = KeyProvider::rewrap_data_key(self, wrapped, context)?;
            Ok(PandoWrappedDek::Local(rewrapped))
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedKeyStatus {
    Active,
    Retained,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedKeyEntry {
    pub key_id: String,
    pub key_version: i32,
    pub sha256: String,
    pub status: ManagedKeyStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsKeyPolicy {
    pub schema: u32,
    pub provider_kind: String,
    pub provider_revoked: bool,
    pub retain_previous_generations: bool,
    pub min_readable_key_version: i32,
    pub active_key_id: String,
    pub active_key_version: i32,
    pub keys: Vec<ManagedKeyEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringManifestWire {
    schema: u32,
    current: String,
    keys: Vec<KeyringKeyWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringKeyWire {
    key_id: String,
    sha256: String,
}

pub fn resolve_kms_dir(root: &Path, repo: Uuid) -> PathBuf {
    if let Some(raw) = std::env::var_os("PANDO_KMS_KEYRING_DIR")
        && !raw.is_empty()
    {
        let configured = PathBuf::from(raw);
        if configured.join(KEYRING_FILE_NAME).is_file() || configured.join(POLICY_FILE_NAME).is_file()
        {
            return configured;
        }
        return configured.join(repo.to_string());
    }
    root.join("kms").join(repo.to_string())
}

fn ensure_private_dir(dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(std::fs::canonicalize(dir)?)
}

fn write_private_atomic(target: &Path, bytes: &[u8]) -> Result<()> {
    let parent = target.parent().context("missing parent for private KMS file")?;
    let tmp = parent.join(format!(".kms-tmp-{}", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    drop(file);
    std::fs::rename(&tmp, target)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn key_file_path(dir: &Path, key_id: &str) -> PathBuf {
    dir.join(format!("{key_id}.key"))
}

fn generate_random_kek() -> Result<Zeroizing<[u8; DATA_KEY_BYTES]>> {
    let mut bytes = Zeroizing::new([0u8; DATA_KEY_BYTES]);
    SystemRandom::new()
        .fill(&mut bytes[..])
        .map_err(|_| anyhow::anyhow!("system random generator unavailable for KEK"))?;
    Ok(bytes)
}

fn sync_keyring_manifest(dir: &Path, policy: &KmsKeyPolicy) -> Result<()> {
    let active_entry = policy
        .keys
        .iter()
        .find(|entry| entry.key_id == policy.active_key_id && entry.status == ManagedKeyStatus::Active);
    let keyring_path = dir.join(KEYRING_FILE_NAME);
    if active_entry.is_none() {
        if keyring_path.exists() {
            std::fs::remove_file(&keyring_path)?;
        }
        return Ok(());
    }
    let keys: Vec<KeyringKeyWire> = policy
        .keys
        .iter()
        .filter(|entry| match entry.status {
            ManagedKeyStatus::Active => true,
            ManagedKeyStatus::Retained => policy.retain_previous_generations,
            ManagedKeyStatus::Revoked => false,
        })
        .map(|entry| KeyringKeyWire {
            key_id: entry.key_id.clone(),
            sha256: entry.sha256.clone(),
        })
        .collect();
    let manifest = KeyringManifestWire {
        schema: 1,
        current: policy.active_key_id.clone(),
        keys,
    };
    write_private_atomic(&keyring_path, &serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

fn save_policy_and_keyring(dir: &Path, policy: &KmsKeyPolicy) -> Result<()> {
    let canonical = ensure_private_dir(dir)?;
    sync_keyring_manifest(&canonical, policy)?;
    write_private_atomic(
        &canonical.join(POLICY_FILE_NAME),
        &serde_json::to_vec_pretty(policy)?,
    )?;
    Ok(())
}

fn validate_key_id(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    ensure!(trimmed.len() >= 3, "invalid kms_key_id '{raw}'");
    KeyId::parse(trimmed).map_err(|err| anyhow::anyhow!("invalid KMS key id: {err}"))?;
    Ok(trimmed.to_owned())
}

fn create_key_entry(canonical: &Path, key_id: &str, key_version: i32) -> Result<ManagedKeyEntry> {
    let kek = generate_random_kek()?;
    let sha256 = sha256_hex(&kek[..]);
    write_private_atomic(&key_file_path(canonical, key_id), &kek[..])?;
    Ok(ManagedKeyEntry {
        key_id: key_id.to_owned(),
        key_version,
        sha256,
        status: ManagedKeyStatus::Active,
    })
}

fn init_default_policy(dir: &Path, default_key_id: &str) -> Result<KmsKeyPolicy> {
    let key_id = validate_key_id(default_key_id)?;
    let canonical = ensure_private_dir(dir)?;
    let entry = create_key_entry(&canonical, &key_id, 1)?;
    let policy = KmsKeyPolicy {
        schema: 1,
        provider_kind: PROVIDER_KIND_LOCAL.to_owned(),
        provider_revoked: false,
        retain_previous_generations: true,
        min_readable_key_version: 1,
        active_key_id: key_id,
        active_key_version: 1,
        keys: vec![entry],
    };
    save_policy_and_keyring(&canonical, &policy)?;
    Ok(policy)
}

pub fn load_policy(dir: &Path) -> Result<KmsKeyPolicy> {
    let path = dir.join(POLICY_FILE_NAME);
    ensure!(path.is_file(), "KMS policy manifest missing at {}", path.display());
    let policy: KmsKeyPolicy = serde_json::from_slice(&std::fs::read(&path)?)?;
    ensure!(policy.schema == 1, "unsupported KMS policy schema {}", policy.schema);
    Ok(policy)
}

fn policy_from_external_keyring(dir: &Path) -> Result<KmsKeyPolicy> {
    let canonical = std::fs::canonicalize(dir)?;
    let raw: KeyringManifestWire =
        serde_json::from_slice(&std::fs::read(canonical.join(KEYRING_FILE_NAME))?)?;
    ensure!(raw.schema == 1, "unsupported external keyring schema");
    let mut active_ver = 1i32;
    let keys = raw
        .keys
        .into_iter()
        .enumerate()
        .map(|(idx, item)| {
            let ver = (idx + 1) as i32;
            let status = if item.key_id == raw.current {
                active_ver = ver;
                ManagedKeyStatus::Active
            } else {
                ManagedKeyStatus::Retained
            };
            ManagedKeyEntry { key_id: item.key_id, key_version: ver, sha256: item.sha256, status }
        })
        .collect();
    Ok(KmsKeyPolicy {
        schema: 1,
        provider_kind: PROVIDER_KIND_LOCAL.to_owned(),
        provider_revoked: false,
        retain_previous_generations: true,
        min_readable_key_version: 1,
        active_key_id: raw.current,
        active_key_version: active_ver,
        keys,
    })
}

pub struct PandoKmsProvider {
    policy: KmsKeyPolicy,
    active_key_id: KeyId,
    inner: Option<LocalFileKeyProvider>,
}

impl fmt::Debug for PandoKmsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PandoKmsProvider")
            .field("active_key_id", &self.active_key_id)
            .field("provider_revoked", &self.policy.provider_revoked)
            .finish_non_exhaustive()
    }
}

impl PandoKmsProvider {
    pub fn open_or_init(kms_dir: &Path, default_key_id: &str) -> Result<Self> {
        if !kms_dir.join(POLICY_FILE_NAME).is_file() && !kms_dir.join(KEYRING_FILE_NAME).is_file() {
            init_default_policy(kms_dir, default_key_id)?;
        }
        Self::open_existing(kms_dir)
    }

    pub fn open_existing(kms_dir: &Path) -> Result<Self> {
        ensure!(kms_dir.is_dir(), "KMS keyring directory missing at {}", kms_dir.display());
        let canonical = std::fs::canonicalize(kms_dir)?;
        let policy = if canonical.join(POLICY_FILE_NAME).is_file() {
            load_policy(&canonical)?
        } else if canonical.join(KEYRING_FILE_NAME).is_file() {
            policy_from_external_keyring(&canonical)?
        } else {
            bail!("missing KMS keyring and policy in {}", canonical.display());
        };
        let active_key_id = KeyId::parse(&policy.active_key_id)
            .map_err(|err| anyhow::anyhow!("invalid active KMS key_id in policy: {err}"))?;
        let active_usable = policy
            .keys
            .iter()
            .any(|e| e.key_id == policy.active_key_id && e.status == ManagedKeyStatus::Active);
        let inner = if !policy.provider_revoked && active_usable && canonical.join(KEYRING_FILE_NAME).is_file() {
            Some(
                LocalFileKeyProvider::load(&canonical)
                    .map_err(|err| anyhow::anyhow!("failed loading LocalFileKeyProvider: {err}"))?,
            )
        } else {
            None
        };
        Ok(Self { policy, active_key_id, inner })
    }

    pub fn policy(&self) -> &KmsKeyPolicy {
        &self.policy
    }

    pub fn active_entry(&self) -> Result<&ManagedKeyEntry> {
        ensure!(!self.policy.provider_revoked, "KMS provider access is revoked");
        self.policy
            .keys
            .iter()
            .find(|e| e.key_id == self.policy.active_key_id && e.status == ManagedKeyStatus::Active)
            .context("active KMS key is missing or revoked")
    }

    fn check_readable_policy(
        &self,
        key_id: &str,
        expected_version: Option<i32>,
    ) -> std::result::Result<(), KeyProviderError> {
        if self.policy.provider_revoked {
            return Err(KeyProviderError::KeyRing("KMS provider access is revoked"));
        }
        let entry = match self.policy.keys.iter().find(|entry| entry.key_id == key_id) {
            Some(entry) => entry,
            None => match KeyId::parse(key_id) {
                Ok(parsed) => return Err(KeyProviderError::MissingKey(parsed)),
                Err(_) => return Err(KeyProviderError::KeyRing("unknown KMS key id")),
            },
        };
        if entry.status == ManagedKeyStatus::Revoked {
            return Err(KeyProviderError::KeyRing("KMS key is revoked"));
        }
        if entry.key_version < self.policy.min_readable_key_version
            || expected_version.is_some_and(|v| v < self.policy.min_readable_key_version)
        {
            return Err(KeyProviderError::KeyRing("KMS key generation below minimum readable version"));
        }
        if entry.status == ManagedKeyStatus::Retained && !self.policy.retain_previous_generations {
            return Err(KeyProviderError::KeyRing("retained KMS key generation disabled by policy"));
        }
        Ok(())
    }

    pub fn ensure_key_readable(&self, key_id: &str, key_version: i32) -> Result<()> {
        self.check_readable_policy(key_id, Some(key_version))
            .map_err(|err| anyhow::anyhow!("{err}"))
    }
}

impl KeyProvider for PandoKmsProvider {
    fn current_key_id(&self) -> &KeyId {
        &self.active_key_id
    }

    fn wrap_data_key(
        &self,
        data_key: &[u8; DATA_KEY_BYTES],
        context: &WrapContext,
    ) -> std::result::Result<WrappedKey, KeyProviderError> {
        if self.policy.provider_revoked {
            return Err(KeyProviderError::KeyRing("KMS provider access is revoked"));
        }
        match self.policy.keys.iter().find(|e| e.key_id == self.policy.active_key_id) {
            Some(entry) if entry.status == ManagedKeyStatus::Active => {}
            Some(_) => return Err(KeyProviderError::KeyRing("active KMS key is revoked")),
            None => return Err(KeyProviderError::MissingKey(self.active_key_id.clone())),
        }
        self.inner
            .as_ref()
            .ok_or_else(|| KeyProviderError::MissingKey(self.active_key_id.clone()))?
            .wrap_data_key(data_key, context)
    }

    fn unwrap_data_key(
        &self,
        wrapped: &WrappedKey,
        context: &WrapContext,
    ) -> std::result::Result<DataKey, KeyProviderError> {
        self.check_readable_policy(wrapped.key_id().as_str(), None)?;
        self.inner
            .as_ref()
            .ok_or_else(|| KeyProviderError::MissingKey(wrapped.key_id().clone()))?
            .unwrap_data_key(wrapped, context)
    }

    fn capabilities(&self) -> KeyProviderCapabilities {
        KeyProviderCapabilities {
            local_envelope: true,
            rewrap: true,
            retained_key_versions: self.policy.retain_previous_generations,
            provider_managed: false,
            plaintext_fallback: false,
        }
    }
}

pub fn prepare_rotation_target_key(
    kms_dir: &Path,
    new_key_id: &str,
    default_initial_key_id: &str,
) -> Result<(KmsKeyPolicy, i32)> {
    let target = validate_key_id(new_key_id)?;
    if !kms_dir.join(POLICY_FILE_NAME).is_file() {
        init_default_policy(kms_dir, default_initial_key_id)?;
    }
    let canonical = ensure_private_dir(kms_dir)?;
    let mut policy = load_policy(&canonical)?;
    ensure!(!policy.provider_revoked, "cannot rotate KMS key while provider access is revoked");

    if let Some(existing) = policy.keys.iter().find(|entry| entry.key_id == target) {
        ensure!(existing.status != ManagedKeyStatus::Revoked, "KMS key '{target}' is revoked");
        ensure!(
            policy.active_key_id == target && existing.status == ManagedKeyStatus::Active,
            "cannot reuse retained KMS key '{target}' as rotation target; rotation requires a distinct fresh key_id"
        );
        save_policy_and_keyring(&canonical, &policy)?;
        return Ok((policy.clone(), policy.active_key_version));
    }
    ensure!(
        !key_file_path(&canonical, &target).exists(),
        "key material already exists on disk for unregistered KMS key '{target}'"
    );

    let new_ver = policy.keys.iter().map(|e| e.key_version).max().unwrap_or(policy.active_key_version) + 1;
    for entry in &mut policy.keys {
        if entry.status == ManagedKeyStatus::Active {
            entry.status = ManagedKeyStatus::Retained;
        }
    }
    policy.keys.push(create_key_entry(&canonical, &target, new_ver)?);
    policy.active_key_id = target;
    policy.active_key_version = new_ver;
    save_policy_and_keyring(&canonical, &policy)?;
    Ok((policy, new_ver))
}

fn mutate_policy(
    kms_dir: &Path,
    f: impl FnOnce(&Path, &mut KmsKeyPolicy) -> Result<()>,
) -> Result<KmsKeyPolicy> {
    let canonical = ensure_private_dir(kms_dir)?;
    let mut policy = load_policy(&canonical)?;
    f(&canonical, &mut policy)?;
    save_policy_and_keyring(&canonical, &policy)?;
    Ok(policy)
}

pub fn revoke_key_in_dir(kms_dir: &Path, key_id: &str) -> Result<KmsKeyPolicy> {
    mutate_policy(kms_dir, |canonical, policy| {
        let trimmed = key_id.trim();
        let entry = policy
            .keys
            .iter_mut()
            .find(|entry| entry.key_id == trimmed)
            .with_context(|| format!("cannot revoke unknown KMS key '{trimmed}'"))?;
        entry.status = ManagedKeyStatus::Revoked;
        let key_path = key_file_path(canonical, trimmed);
        if key_path.is_file() {
            let zeros = Zeroizing::new([0u8; DATA_KEY_BYTES]);
            write_private_atomic(&key_path, &zeros[..])?;
            std::fs::remove_file(&key_path)?;
        }
        Ok(())
    })
}

pub fn set_provider_revoked_in_dir(kms_dir: &Path, revoked: bool) -> Result<KmsKeyPolicy> {
    mutate_policy(kms_dir, |_, policy| {
        policy.provider_revoked = revoked;
        Ok(())
    })
}

pub fn update_policy_in_dir(
    kms_dir: &Path,
    retain_previous: Option<bool>,
    min_readable_key_version: Option<i32>,
) -> Result<KmsKeyPolicy> {
    if let Some(min_ver) = min_readable_key_version {
        ensure!(min_ver >= 1, "min_readable_key_version must be >= 1");
    }
    mutate_policy(kms_dir, |_, policy| {
        if let Some(retain) = retain_previous {
            policy.retain_previous_generations = retain;
        }
        if let Some(min_ver) = min_readable_key_version {
            policy.min_readable_key_version = min_ver;
        }
        Ok(())
    })
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;
