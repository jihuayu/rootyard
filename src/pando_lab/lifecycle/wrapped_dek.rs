use super::valid_kms_key_id;
use rootyard::blob_store::key_provider::{KeyProviderError, WrappedKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

pub const PANDO_WRAPPED_DEK_VERSION: u32 = 1;
pub const PANDO_WRAPPED_DEK_JSON_MAX: usize = 16 * 1024;
pub const PANDO_OPAQUE_PAYLOAD_MAX: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PandoProviderKind {
    VaultTransit,
}

impl PandoProviderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultTransit => "vault-transit",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "vault-transit" => Some(Self::VaultTransit),
            _ => None,
        }
    }
}

/// Provider-neutral Pando wrapped DEK. The local variant preserves the exact
/// legacy `blob_store::key_provider::WrappedKey` JSON. The versioned variant
/// keeps a future provider's opaque ciphertext separate from the shared Blob
/// fixed-size wrapped-key representation; no external provider is wired yet.
pub enum PandoWrappedDek {
    Local(WrappedKey),
    Versioned {
        provider_kind: PandoProviderKind,
        key_id: String,
        key_version: i32,
        payload: Vec<u8>,
    },
}

impl fmt::Debug for PandoWrappedDek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(wrapped) => f.debug_tuple("Local").field(wrapped).finish(),
            Self::Versioned {
                provider_kind,
                key_id,
                key_version,
                payload,
            } => f
                .debug_struct("Versioned")
                .field("provider_kind", provider_kind)
                .field("key_id", &"<redacted>")
                .field("key_version", key_version)
                .field("payload_len", &payload.len())
                .finish(),
        }
    }
}

impl PandoWrappedDek {
    pub fn key_id(&self) -> &str {
        match self {
            Self::Local(wrapped) => wrapped.key_id().as_str(),
            Self::Versioned { key_id, .. } => key_id,
        }
    }

    pub fn provider_kind(&self) -> &'static str {
        match self {
            Self::Local(_) => super::provider::PROVIDER_KIND_LOCAL,
            Self::Versioned { provider_kind, .. } => provider_kind.as_str(),
        }
    }

    pub(super) fn from_json(bytes: &[u8]) -> Result<Self, KeyProviderError> {
        if bytes.is_empty() || bytes.len() > PANDO_WRAPPED_DEK_JSON_MAX {
            return Err(KeyProviderError::InvalidWrappedKey(
                "wrapped DEK JSON is empty or exceeds the size limit",
            ));
        }
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|_| KeyProviderError::InvalidWrappedKey("wrapped DEK is not valid JSON"))?;
        let is_versioned = value
            .as_object()
            .is_some_and(|object| object.contains_key("pando_wrapped_dek"));
        if is_versioned {
            let wire: VersionedEnvelopeWire = serde_json::from_value(value)
                .map_err(|_| KeyProviderError::InvalidWrappedKey("invalid versioned wrapped DEK schema"))?;
            let (provider_kind, key_id, key_version, payload) = wire.pando_wrapped_dek.validate()?;
            return Ok(Self::Versioned {
                provider_kind,
                key_id,
                key_version,
                payload,
            });
        }
        WrappedKey::from_json(bytes)
            .map(Self::Local)
            .map_err(|_| KeyProviderError::InvalidWrappedKey("invalid legacy local wrapped DEK"))
    }

    pub(super) fn to_json(&self) -> Result<String, KeyProviderError> {
        match self {
            Self::Local(wrapped) => wrapped.to_json(),
            Self::Versioned {
                provider_kind,
                key_id,
                key_version,
                payload,
            } => {
                validate_versioned_parts(*provider_kind, key_id, *key_version, payload)?;
                serde_json::to_string(&VersionedEnvelopeWire {
                    pando_wrapped_dek: VersionedBodyWire {
                        version: PANDO_WRAPPED_DEK_VERSION,
                        provider_kind: provider_kind.as_str().to_owned(),
                        key_id: key_id.clone(),
                        key_version: *key_version,
                        payload_hex: hex::encode(payload),
                    },
                })
                .map_err(|_| KeyProviderError::Serialization)
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionedEnvelopeWire {
    pando_wrapped_dek: VersionedBodyWire,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionedBodyWire {
    version: u32,
    provider_kind: String,
    key_id: String,
    key_version: i32,
    payload_hex: String,
}

impl VersionedBodyWire {
    fn validate(self) -> Result<(PandoProviderKind, String, i32, Vec<u8>), KeyProviderError> {
        if self.version != PANDO_WRAPPED_DEK_VERSION {
            return Err(KeyProviderError::InvalidWrappedKey(
                "unsupported Pando wrapped DEK version",
            ));
        }
        let provider_kind = PandoProviderKind::parse(&self.provider_kind)
            .ok_or(KeyProviderError::InvalidWrappedKey("unknown wrapped DEK provider kind"))?;
        if !valid_kms_key_id(&self.key_id) || self.key_id != self.key_id.trim() {
            return Err(KeyProviderError::InvalidWrappedKey("invalid wrapped DEK key id"));
        }
        if self.key_version < 1 {
            return Err(KeyProviderError::InvalidWrappedKey("invalid wrapped DEK key version"));
        }
        if self.payload_hex.is_empty()
            || self.payload_hex.len() > PANDO_OPAQUE_PAYLOAD_MAX * 2
            || !self.payload_hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(KeyProviderError::InvalidWrappedKey(
                "invalid opaque wrapped DEK payload",
            ));
        }
        let payload = hex::decode(&self.payload_hex)
            .map_err(|_| KeyProviderError::InvalidWrappedKey("invalid opaque wrapped DEK payload"))?;
        if payload.is_empty() || payload.len() > PANDO_OPAQUE_PAYLOAD_MAX {
            return Err(KeyProviderError::InvalidWrappedKey(
                "invalid opaque wrapped DEK payload length",
            ));
        }
        Ok((provider_kind, self.key_id, self.key_version, payload))
    }
}

fn validate_versioned_parts(
    provider_kind: PandoProviderKind,
    key_id: &str,
    key_version: i32,
    payload: &[u8],
) -> Result<(), KeyProviderError> {
    if provider_kind != PandoProviderKind::VaultTransit
        || !valid_kms_key_id(key_id)
        || key_id != key_id.trim()
        || key_version < 1
        || payload.is_empty()
        || payload.len() > PANDO_OPAQUE_PAYLOAD_MAX
    {
        return Err(KeyProviderError::InvalidWrappedKey(
            "invalid versioned wrapped DEK fields",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::crypto::{
        compute_authenticated_envelope_mac, pack_wrap_context, sha256_hex, EnvelopeMacInputs,
    };
    use super::super::provider::{PandoKmsProvider, PandoKeyProvider};
    use super::super::data_key::PandoDataKey;

    const LEGACY_LOCAL: &str = r#"{"version":1,"key_id":"kms-local-default-v1","nonce":"000102030405060708090a0b","wrapped_dek":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f","aad_digest":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}"#;
    const LEGACY_MAC: &str = "0a74c11486db282523915a5a6b52a414d469fed640811f90eb585fdbfd8b6aa2";
    const VERSIONED: &str = r#"{"pando_wrapped_dek":{"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"payload_hex":"aabbcc"}}"#;

    fn sample_mac(wrapped_key_json: &str) -> String {
        let pack_sha256 = "11".repeat(32);
        let idx_sha256 = "22".repeat(32);
        let ciphertext_sha256 = "33".repeat(32);
        compute_authenticated_envelope_mac(&EnvelopeMacInputs {
            encryption_mode: "authenticated-envelope-v1",
            repo: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            pack_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            key_id: "kms-local-default-v1",
            key_version: 1,
            cipher_suite: "AES-256-GCM-HMAC-SHA256",
            pack_sha256: &pack_sha256,
            idx_sha256: &idx_sha256,
            ciphertext_sha256: &ciphertext_sha256,
            ciphertext_bytes: 123,
            envelope_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
            nonce_prefix: "01020304",
            wrapped_key_json,
        })
    }

    #[test]
    fn legacy_local_golden_encoding_and_mac_inputs_are_stable() {
        let decoded = PandoWrappedDek::from_json(LEGACY_LOCAL.as_bytes()).unwrap();
        assert!(matches!(decoded, PandoWrappedDek::Local(_)));
        assert_eq!(decoded.to_json().unwrap(), LEGACY_LOCAL);
        assert_eq!(sample_mac(LEGACY_LOCAL), LEGACY_MAC);
    }

    #[test]
    fn versioned_schema_is_strict_and_provider_specific() {
        let decoded = PandoWrappedDek::from_json(VERSIONED.as_bytes()).unwrap();
        match &decoded {
            PandoWrappedDek::Versioned {
                provider_kind,
                key_id,
                key_version,
                payload,
            } => {
                assert_eq!(*provider_kind, PandoProviderKind::VaultTransit);
                assert_eq!(key_id.as_str(), "pando-vault-key");
                assert_eq!(*key_version, 3);
                assert_eq!(payload.as_slice(), [0xaa, 0xbb, 0xcc].as_slice());
            }
            PandoWrappedDek::Local(_) => panic!("versioned payload parsed as local"),
        }
        assert_eq!(decoded.to_json().unwrap(), VERSIONED);

        for bad in [
            r#"{"pando_wrapped_dek":{"version":2,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"payload_hex":"aabbcc"}}"#,
            r#"{"pando_wrapped_dek":{"version":1,"provider_kind":"unknown","key_id":"pando-vault-key","key_version":3,"payload_hex":"aabbcc"}}"#,
            r#"{"pando_wrapped_dek":{"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":0,"payload_hex":"aabbcc"}}"#,
            r#"{"pando_wrapped_dek":{"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"payload_hex":""}}"#,
            r#"{"pando_wrapped_dek":{"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"payload_hex":"zz"}}"#,
            r#"{"pando_wrapped_dek":{"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"payload_hex":"aabbcc"},"extra":true}"#,
            r#"{"pando_wrapped_dek":{"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"payload_hex":"aabbcc","extra":true}}"#,
        ] {
            assert!(PandoWrappedDek::from_json(bad.as_bytes()).is_err(), "accepted {bad}");
        }
        let oversized = format!(
            r#"{{"pando_wrapped_dek":{{"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"payload_hex":"{}"}}}}"#,
            "aa".repeat(PANDO_OPAQUE_PAYLOAD_MAX + 1)
        );
        assert!(PandoWrappedDek::from_json(oversized.as_bytes()).is_err());
        let legacy_extra = LEGACY_LOCAL.replace(r#"{"version":1,"#, r#"{"version":1,"extra":true,"#);
        assert!(PandoWrappedDek::from_json(legacy_extra.as_bytes()).is_err());

        let tampered_payload = VERSIONED.replace("aabbcc", "aabbcd");
        assert!(PandoWrappedDek::from_json(tampered_payload.as_bytes()).is_ok());
        assert_ne!(sample_mac(VERSIONED), sample_mac(&tampered_payload));
    }

    #[tokio::test]
    async fn local_adapter_roundtrips_legacy_and_rejects_versioned_payload_before_local_fallback() {
        let tmp = std::env::temp_dir().join(format!("pando-wrapped-dek-{}", uuid::Uuid::new_v4()));
        let provider = PandoKmsProvider::open_or_init(&tmp, "kms-local-default-v1").unwrap();
        let context = pack_wrap_context(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            &"44".repeat(32),
        ).unwrap();
        let data_key = PandoDataKey::generate().unwrap();
        let wrapped = provider.wrap_data_key(&data_key, &context).await.unwrap();
        let encoded = wrapped.to_json().unwrap();
        let decoded = PandoWrappedDek::from_json(encoded.as_bytes()).unwrap();
        assert_eq!(decoded.to_json().unwrap(), encoded);
        let opened = provider.unwrap_data_key(&decoded, &context).await.unwrap();
        assert_eq!(
            sha256_hex(opened.expose_secret()),
            sha256_hex(data_key.expose_secret())
        );

        let versioned = PandoWrappedDek::from_json(VERSIONED.as_bytes()).unwrap();
        assert!(provider.unwrap_data_key(&versioned, &context).await.is_err());
        assert!(provider.rewrap_data_key(&versioned, &context).await.is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
