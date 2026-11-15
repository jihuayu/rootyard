//! Explicit encryption-policy configuration for the standalone Blob profile.
//!
//! Standalone deployments select either provider-managed encryption or a local
//! [`KeyProvider`](super::key_provider::KeyProvider) envelope rooted at a
//! keyring directory. Vault is never a mandatory dependency for standalone
//! operation, and unsupported/plaintext/ambiguous configurations fail closed.

use std::{
    fmt,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use super::{
    BlobError,
    key_provider::{KeyProvider, LocalFileKeyProvider},
};

pub const ENV_BLOB_ENCRYPTION_MODE: &str = "ROOTYARD_BLOB_ENCRYPTION_MODE";
pub const ENV_BLOB_KEYRING_DIR: &str = "ROOTYARD_BLOB_KEYRING_DIR";

/// Explicit encryption mechanism for standalone Blob objects.
#[derive(Clone, PartialEq, Eq)]
pub enum BlobEncryptionMode {
    /// Object encryption is handled by the remote Blob provider (SSE / bucket
    /// policy); no local envelope wrapper is applied.
    ProviderManaged,
    /// Client-side chunked AES-256-GCM envelope wrapped by a replaceable
    /// [`KeyProvider`] loaded from `keyring_dir`.
    LocalEnvelope { keyring_dir: PathBuf },
}

impl BlobEncryptionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProviderManaged => "provider-managed",
            Self::LocalEnvelope { .. } => "local-envelope",
        }
    }

    pub fn is_local_envelope(&self) -> bool {
        matches!(self, Self::LocalEnvelope { .. })
    }

    pub fn is_provider_managed(&self) -> bool {
        matches!(self, Self::ProviderManaged)
    }

    pub fn keyring_dir(&self) -> Option<&Path> {
        match self {
            Self::ProviderManaged => None,
            Self::LocalEnvelope { keyring_dir } => Some(keyring_dir.as_path()),
        }
    }
}

impl fmt::Debug for BlobEncryptionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderManaged => f.write_str("ProviderManaged"),
            Self::LocalEnvelope { .. } => f.debug_struct("LocalEnvelope").field("keyring_dir", &"<redacted>").finish(),
        }
    }
}

/// Validated encryption policy attached to [`super::config::BlobProfile`].
#[derive(Clone, PartialEq, Eq)]
pub struct BlobEncryptionConfig {
    mode: BlobEncryptionMode,
    explicit: bool,
}

impl BlobEncryptionConfig {
    /// Construct an explicit provider-managed encryption configuration.
    pub fn provider_managed() -> Self {
        Self { mode: BlobEncryptionMode::ProviderManaged, explicit: true }
    }

    /// Construct an explicit local-envelope configuration backed by `keyring_dir`.
    pub fn local_envelope(keyring_dir: impl Into<PathBuf>) -> Result<Self, BlobError> {
        let dir = keyring_dir.into();
        validate_keyring_dir(&dir)?;
        Ok(Self { mode: BlobEncryptionMode::LocalEnvelope { keyring_dir: dir }, explicit: true })
    }

    /// Compatibility default used when `ROOTYARD_BLOB_ENCRYPTION_MODE` and
    /// `ROOTYARD_BLOB_KEYRING_DIR` are both absent during profile loading.
    pub(super) fn implicit_provider_managed() -> Self {
        Self { mode: BlobEncryptionMode::ProviderManaged, explicit: false }
    }

    /// Parse `ROOTYARD_BLOB_ENCRYPTION_MODE` and `ROOTYARD_BLOB_KEYRING_DIR` from
    /// the process environment, allowing both unset as implicit provider-managed
    /// while rejecting partial, Vault, plaintext or unrecognized settings.
    pub fn from_env() -> Result<Self, BlobError> {
        Self::parse_with(super::config::env_optional, false)
    }

    /// Parse encryption configuration while requiring `ROOTYARD_BLOB_ENCRYPTION_MODE`
    /// to be explicitly configured.
    pub fn from_env_strict() -> Result<Self, BlobError> {
        Self::parse_with(super::config::env_optional, true)
    }

    pub(crate) fn parse_with<F>(mut lookup: F, require_explicit: bool) -> Result<Self, BlobError>
    where
        F: FnMut(&str) -> Result<Option<String>, BlobError>,
    {
        let mode_raw = lookup(ENV_BLOB_ENCRYPTION_MODE)?;
        let keyring_raw = lookup(ENV_BLOB_KEYRING_DIR)?;

        match mode_raw.as_deref() {
            Some("provider-managed") => {
                if keyring_raw.is_some() {
                    return Err(BlobError::Config(
                        "ROOTYARD_BLOB_KEYRING_DIR must not be set when ROOTYARD_BLOB_ENCRYPTION_MODE=provider-managed"
                            .into(),
                    ));
                }
                Ok(Self::provider_managed())
            }
            Some("local-envelope") => {
                let Some(dir_raw) = keyring_raw else {
                    return Err(BlobError::Config(
                        "ROOTYARD_BLOB_KEYRING_DIR is required when ROOTYARD_BLOB_ENCRYPTION_MODE=local-envelope"
                            .into(),
                    ));
                };
                Self::local_envelope(PathBuf::from(dir_raw))
            }
            Some("vault") | Some("vault-transit") => Err(BlobError::Config(
                "vault encryption mode is neither required nor supported for standalone blob storage; \
                 set `provider-managed` or `local-envelope`"
                    .into(),
            )),
            Some(_) => Err(BlobError::Config(
                "invalid ROOTYARD_BLOB_ENCRYPTION_MODE; expected `provider-managed` or `local-envelope`".into(),
            )),
            None => {
                if keyring_raw.is_some() {
                    return Err(BlobError::Config(
                        "ROOTYARD_BLOB_KEYRING_DIR requires explicit ROOTYARD_BLOB_ENCRYPTION_MODE=local-envelope"
                            .into(),
                    ));
                }
                if require_explicit {
                    return Err(BlobError::Config(
                        "ROOTYARD_BLOB_ENCRYPTION_MODE must be explicitly set to `provider-managed` or `local-envelope`"
                            .into(),
                    ));
                }
                Ok(Self::implicit_provider_managed())
            }
        }
    }

    pub fn mode(&self) -> &BlobEncryptionMode {
        &self.mode
    }

    pub fn is_explicit(&self) -> bool {
        self.explicit
    }

    pub fn is_local_envelope(&self) -> bool {
        self.mode.is_local_envelope()
    }

    pub fn is_provider_managed(&self) -> bool {
        self.mode.is_provider_managed()
    }

    /// Require that this configuration came from an explicit policy choice.
    pub fn require_explicit(&self) -> Result<&BlobEncryptionMode, BlobError> {
        if !self.explicit {
            return Err(BlobError::Config("blob encryption mode was not explicitly configured".into()));
        }
        Ok(&self.mode)
    }

    /// Open the configured [`KeyProvider`] for `local-envelope` mode, or `None`
    /// for `provider-managed` mode. Fails closed on missing, symlinked or
    /// improperly permissioned keyrings.
    pub fn open_key_provider(&self) -> Result<Option<Arc<dyn KeyProvider>>, BlobError> {
        match &self.mode {
            BlobEncryptionMode::ProviderManaged => Ok(None),
            BlobEncryptionMode::LocalEnvelope { keyring_dir } => {
                let provider = LocalFileKeyProvider::load(keyring_dir)
                    .map_err(|error| BlobError::Config(format!("failed to load local envelope keyring: {error}")))?;
                Ok(Some(Arc::new(provider)))
            }
        }
    }
}

impl fmt::Debug for BlobEncryptionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobEncryptionConfig").field("mode", &self.mode).field("explicit", &self.explicit).finish()
    }
}

fn validate_keyring_dir(path: &Path) -> Result<(), BlobError> {
    if path.as_os_str().is_empty() {
        return Err(BlobError::Config("ROOTYARD_BLOB_KEYRING_DIR must not be empty".into()));
    }
    let Some(raw) = path.to_str() else {
        return Err(BlobError::Config("ROOTYARD_BLOB_KEYRING_DIR must be valid UTF-8".into()));
    };
    if raw.contains('\0') {
        return Err(BlobError::Config("ROOTYARD_BLOB_KEYRING_DIR contains an invalid NUL byte".into()));
    }
    if !path.is_absolute()
        || !path.components().all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(BlobError::Config("ROOTYARD_BLOB_KEYRING_DIR must be a clean absolute path".into()));
    }
    Ok(())
}
