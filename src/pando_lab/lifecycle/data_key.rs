use ring::rand::{SecureRandom, SystemRandom};
use rootyard::blob_store::key_provider::{DATA_KEY_BYTES, KeyProviderError};
use std::fmt;
use zeroize::Zeroizing;

/// Pando-owned DEK storage. The only copy of the plaintext key is a zeroizing
/// array, and this type deliberately does not implement `Clone`, `Serialize`,
/// `Deserialize` or a byte-revealing `Debug`.
pub struct PandoDataKey {
    bytes: Zeroizing<[u8; DATA_KEY_BYTES]>,
}

impl PandoDataKey {
    pub(super) fn generate() -> Result<Self, KeyProviderError> {
        let mut bytes = Zeroizing::new([0u8; DATA_KEY_BYTES]);
        SystemRandom::new()
            .fill(&mut bytes[..])
            .map_err(|_| KeyProviderError::RandomUnavailable)?;
        Ok(Self { bytes })
    }

    pub(super) fn from_bytes(bytes: [u8; DATA_KEY_BYTES]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub(super) fn expose_secret(&self) -> &[u8; DATA_KEY_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for PandoDataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PandoDataKey(<redacted>)")
    }
}
