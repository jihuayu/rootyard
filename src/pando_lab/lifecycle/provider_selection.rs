use super::{
    provider::{KmsKeyPolicy, PROVIDER_KIND_LOCAL, PROVIDER_KIND_VAULT, PandoKeyProvider, PandoKmsProvider},
    rotation::KmsRotationCheckpoint,
    vault_provider::VaultTransitProvider,
};
use anyhow::{Context, Result, bail, ensure};
use std::path::Path;
use uuid::Uuid;

pub(crate) const PROVIDER_ENV: &str = "PANDO_KMS_PROVIDER";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PandoProviderSelection {
    Local,
    VaultTransit,
}

impl PandoProviderSelection {
    pub(crate) fn kind(self) -> &'static str {
        match self {
            Self::Local => PROVIDER_KIND_LOCAL,
            Self::VaultTransit => PROVIDER_KIND_VAULT,
        }
    }
}

pub(crate) struct PandoWriteProvider {
    provider: Box<dyn PandoKeyProvider>,
    key_version_hint: i32,
    local_policy: Option<KmsKeyPolicy>,
}

impl PandoWriteProvider {
    pub(crate) fn provider(&self) -> &dyn PandoKeyProvider {
        self.provider.as_ref()
    }

    pub(crate) fn key_version_hint(&self) -> i32 {
        self.key_version_hint
    }

    pub(crate) fn into_local_policy(self) -> Option<KmsKeyPolicy> {
        self.local_policy
    }
}

pub(crate) enum PandoReadProvider {
    Local(PandoKmsProvider),
    VaultTransit(VaultTransitProvider),
}

impl PandoReadProvider {
    pub(crate) fn as_key_provider(&self) -> &dyn PandoKeyProvider {
        match self {
            Self::Local(provider) => provider,
            Self::VaultTransit(provider) => provider,
        }
    }

    pub(crate) fn ensure_key_readable(&self, key_id: &str, key_version: i32) -> Result<()> {
        match self {
            Self::Local(provider) => provider.ensure_key_readable(key_id, key_version),
            Self::VaultTransit(_) => Ok(()),
        }
    }
}

pub(crate) fn selected_kind() -> Result<PandoProviderSelection> {
    match std::env::var(PROVIDER_ENV) {
        Ok(value) => selection_from_value(Some(&value)),
        Err(std::env::VarError::NotPresent) => Ok(PandoProviderSelection::Local),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{PROVIDER_ENV} is not valid UTF-8"),
    }
}

fn selection_from_value(value: Option<&str>) -> Result<PandoProviderSelection> {
    match value {
        None => Ok(PandoProviderSelection::Local),
        Some(value) if value == PROVIDER_KIND_LOCAL => Ok(PandoProviderSelection::Local),
        Some(value) if value == PROVIDER_KIND_VAULT => Ok(PandoProviderSelection::VaultTransit),
        Some("") => bail!("{PROVIDER_ENV} is empty"),
        Some(other) => bail!("unknown {PROVIDER_ENV} value '{other}'"),
    }
}

pub(crate) fn for_write(
    base_root: &Path,
    repo: Uuid,
    active_rotation: Option<&KmsRotationCheckpoint>,
) -> Result<PandoWriteProvider> {
    let kms_dir = super::provider::resolve_kms_dir(base_root, repo);
    match selected_kind()? {
        PandoProviderSelection::Local => {
            if let Some(cp) = active_rotation {
                ensure!(
                    cp.to_provider_kind == PROVIDER_KIND_LOCAL,
                    "active rotation requires the Vault Transit provider for new writes"
                );
            }
            let provider = PandoKmsProvider::open_or_init(&kms_dir, super::DEFAULT_KMS_KEY_ID)?;
            let key_version = provider.active_entry()?.key_version;
            let policy = Some(provider.policy().clone());
            Ok(PandoWriteProvider { provider: Box::new(provider), key_version_hint: key_version, local_policy: policy })
        }
        PandoProviderSelection::VaultTransit => {
            let mut provider = VaultTransitProvider::from_env().context("Pando Vault Transit provider unavailable")?;
            if let Some(cp) = active_rotation {
                ensure!(
                    cp.to_provider_kind == PROVIDER_KIND_VAULT,
                    "active Local rotation cannot use the Vault Transit write provider"
                );
                ensure!(cp.to_key_id == provider.key_name(), "active rotation targets a different Vault key");
                ensure!(
                    cp.external_rotate_issued,
                    "active Vault rotation target has not been issued; refusing new writes"
                );
                provider = provider.with_pinned_write_version(cp.expected_version())?;
            }
            Ok(PandoWriteProvider { provider: Box::new(provider), key_version_hint: 1, local_policy: None })
        }
    }
}

pub(crate) fn for_envelope(base_root: &Path, repo: Uuid, provider_kind: &str) -> Result<PandoReadProvider> {
    if provider_kind == PROVIDER_KIND_LOCAL {
        let kms_dir = super::provider::resolve_kms_dir(base_root, repo);
        return Ok(PandoReadProvider::Local(PandoKmsProvider::open_existing(&kms_dir)?));
    }
    if provider_kind == PROVIDER_KIND_VAULT {
        let provider = VaultTransitProvider::from_env().context("Pando Vault Transit provider unavailable")?;
        return Ok(PandoReadProvider::VaultTransit(provider));
    }
    bail!("unsupported Pando envelope provider_kind '{provider_kind}'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_defaults_local_and_fails_closed_on_unknown_or_empty_values() {
        assert_eq!(selection_from_value(None).unwrap(), PandoProviderSelection::Local);
        assert_eq!(selection_from_value(Some(PROVIDER_KIND_LOCAL)).unwrap(), PandoProviderSelection::Local);
        assert_eq!(selection_from_value(Some(PROVIDER_KIND_VAULT)).unwrap(), PandoProviderSelection::VaultTransit);
        assert!(selection_from_value(Some("")).is_err());
        assert!(selection_from_value(Some("vault")).is_err());
        assert!(selection_from_value(Some("local")).is_err());
        assert_eq!(PandoProviderSelection::Local.kind(), PROVIDER_KIND_LOCAL);
        assert_eq!(PandoProviderSelection::VaultTransit.kind(), PROVIDER_KIND_VAULT);
        assert!(for_envelope(Path::new("/nonexistent-pando-root"), uuid::Uuid::nil(), "unknown-provider").is_err());
    }
}
