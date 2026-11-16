use super::{KEYRING_FILE_NAME, KeyringKeyWire, KeyringManifestWire, KmsKeyPolicy, ManagedKeyStatus, POLICY_FILE_NAME};
use anyhow::{Context, Result};
use ring::rand::{SecureRandom, SystemRandom};
use rootyard::blob_store::key_provider::DATA_KEY_BYTES;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) fn ensure_private_dir(dir: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(std::fs::canonicalize(dir)?)
}

pub(super) fn write_private_atomic(target: &Path, bytes: &[u8]) -> Result<()> {
    let parent = target.parent().context("missing parent for private KMS file")?;
    let tmp = parent.join(format!(".kms-tmp-{}", Uuid::new_v4()));
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    drop(file);
    std::fs::rename(&tmp, target)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) fn key_file_path(dir: &Path, key_id: &str) -> PathBuf {
    dir.join(format!("{key_id}.key"))
}

pub(super) fn generate_random_kek() -> Result<Zeroizing<[u8; DATA_KEY_BYTES]>> {
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
        .map(|entry| KeyringKeyWire { key_id: entry.key_id.clone(), sha256: entry.sha256.clone() })
        .collect();
    let manifest = KeyringManifestWire { schema: 1, current: policy.active_key_id.clone(), keys };
    write_private_atomic(&keyring_path, &serde_json::to_vec_pretty(&manifest)?)?;
    Ok(())
}

pub(super) fn save_policy_and_keyring(dir: &Path, policy: &KmsKeyPolicy) -> Result<()> {
    let canonical = ensure_private_dir(dir)?;
    sync_keyring_manifest(&canonical, policy)?;
    write_private_atomic(&canonical.join(POLICY_FILE_NAME), &serde_json::to_vec_pretty(policy)?)?;
    Ok(())
}
