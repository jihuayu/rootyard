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
    Versioned { provider_kind: PandoProviderKind, key_id: String, key_version: i32, payload: Vec<u8> },
}

impl fmt::Debug for PandoWrappedDek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(wrapped) => f.debug_tuple("Local").field(wrapped).finish(),
            Self::Versioned { provider_kind, key_id, key_version, payload } => f
                .debug_struct("Versioned")
                .field("provider_kind", provider_kind)
                .field("key_id", &"<redacted>")
                .field("key_version", key_version)
                .field("payload_len", &payload.len())
                .finish(),
        }
    }
}

pub(super) fn parse_vault_ciphertext_version(payload: &[u8]) -> Option<i32> {
    if payload.is_empty() || payload.len() > PANDO_OPAQUE_PAYLOAD_MAX {
        return None;
    }
    let text = std::str::from_utf8(payload).ok()?;
    let rest = text.strip_prefix("vault:v")?;
    let (version, ciphertext) = rest.split_once(':')?;
    if ciphertext.is_empty()
        || !ciphertext.bytes().all(|byte| byte.is_ascii_graphic())
        || !version.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let version = version.parse::<i32>().ok()?;
    (version >= 1).then_some(version)
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
            Self::Versioned { provider_kind, .. } => (*provider_kind).as_str(),
        }
    }

    pub fn key_version(&self) -> Option<i32> {
        match self {
            Self::Local(_) => None,
            Self::Versioned { key_version, .. } => Some(*key_version),
        }
    }

    pub(super) fn validate_binding(
        &self,
        outer_provider_kind: &str,
        outer_key_id: &str,
        outer_key_version: i32,
    ) -> Result<(), KeyProviderError> {
        match self {
            Self::Local(wrapped) => {
                if outer_provider_kind != super::provider::PROVIDER_KIND_LOCAL
                    || outer_key_id != wrapped.key_id().as_str()
                {
                    return Err(KeyProviderError::InvalidWrappedKey(
                        "local wrapped DEK does not match outer envelope identity",
                    ));
                }
            }
            Self::Versioned { provider_kind, key_id, key_version, payload } => {
                if *provider_kind != PandoProviderKind::VaultTransit
                    || outer_provider_kind != (*provider_kind).as_str()
                    || outer_key_id != key_id.as_str()
                    || outer_key_version != *key_version
                    || parse_vault_ciphertext_version(payload) != Some(*key_version)
                {
                    return Err(KeyProviderError::InvalidWrappedKey(
                        "versioned wrapped DEK does not match outer envelope identity",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn from_json(bytes: &[u8]) -> Result<Self, KeyProviderError> {
        if bytes.is_empty() || bytes.len() > PANDO_WRAPPED_DEK_JSON_MAX {
            return Err(KeyProviderError::InvalidWrappedKey("wrapped DEK JSON is empty or exceeds the size limit"));
        }
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|_| KeyProviderError::InvalidWrappedKey("wrapped DEK is not valid JSON"))?;
        let is_versioned = value.as_object().is_some_and(|object| object.contains_key("pando_wrapped_dek"));
        if is_versioned {
            let wire: VersionedEnvelopeWire = serde_json::from_slice(bytes)
                .map_err(|_| KeyProviderError::InvalidWrappedKey("invalid versioned wrapped DEK schema"))?;
            let (provider_kind, key_id, key_version, payload) = wire.pando_wrapped_dek.validate()?;
            return Ok(Self::Versioned { provider_kind, key_id, key_version, payload });
        }
        WrappedKey::from_json(bytes)
            .map(Self::Local)
            .map_err(|_| KeyProviderError::InvalidWrappedKey("invalid legacy local wrapped DEK"))
    }

    pub(super) fn to_json(&self) -> Result<String, KeyProviderError> {
        match self {
            Self::Local(wrapped) => wrapped.to_json(),
            Self::Versioned { provider_kind, key_id, key_version, payload } => {
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
            return Err(KeyProviderError::InvalidWrappedKey("unsupported Pando wrapped DEK version"));
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
            return Err(KeyProviderError::InvalidWrappedKey("invalid opaque wrapped DEK payload"));
        }
        let payload = hex::decode(&self.payload_hex)
            .map_err(|_| KeyProviderError::InvalidWrappedKey("invalid opaque wrapped DEK payload"))?;
        if payload.is_empty() || payload.len() > PANDO_OPAQUE_PAYLOAD_MAX {
            return Err(KeyProviderError::InvalidWrappedKey("invalid opaque wrapped DEK payload length"));
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
        return Err(KeyProviderError::InvalidWrappedKey("invalid versioned wrapped DEK fields"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::crypto::{EnvelopeMacInputs, compute_authenticated_envelope_mac, pack_wrap_context, sha256_hex};
    use super::super::data_key::PandoDataKey;
    use super::super::provider::{PandoKeyProvider, PandoKmsProvider};
    use super::*;

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
    fn provider_binding_checks_outer_identity_and_vault_ciphertext_version() {
        let versioned = PandoWrappedDek::Versioned {
            provider_kind: PandoProviderKind::VaultTransit,
            key_id: "pando-vault-key".to_owned(),
            key_version: 3,
            payload: b"vault:v3:abcdef".to_vec(),
        };
        assert!(versioned.validate_binding("vault-transit", "pando-vault-key", 3).is_ok());
        assert!(versioned.validate_binding("local-file-key-provider", "pando-vault-key", 3).is_err());
        assert!(versioned.validate_binding("vault-transit", "other-key", 3).is_err());
        assert!(versioned.validate_binding("vault-transit", "pando-vault-key", 2).is_err());
        let wrong_ciphertext_version = PandoWrappedDek::Versioned {
            provider_kind: PandoProviderKind::VaultTransit,
            key_id: "pando-vault-key".to_owned(),
            key_version: 3,
            payload: b"vault:v2:abcdef".to_vec(),
        };
        assert!(wrong_ciphertext_version.validate_binding("vault-transit", "pando-vault-key", 3).is_err());

        let local = PandoWrappedDek::from_json(LEGACY_LOCAL.as_bytes()).unwrap();
        assert!(local.validate_binding("local-file-key-provider", "kms-local-default-v1", 1).is_ok());
        assert!(local.validate_binding("vault-transit", "kms-local-default-v1", 1).is_err());
        assert!(local.validate_binding("local-file-key-provider", "other-key", 1).is_err());
    }

    #[test]
    fn authenticated_envelope_write_binds_provider_identity() {
        use super::super::Pack;
        use super::super::crypto::{AUTHENTICATED_ENVELOPE_MODE, SealedPackArtifact};
        use super::super::envelopes::build_authenticated_envelope_record;

        let repo = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let pack = Pack {
            id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            pack_sha256: "11".repeat(32),
            idx_sha256: "22".repeat(32),
        };
        let wrapped = PandoWrappedDek::Versioned {
            provider_kind: PandoProviderKind::VaultTransit,
            key_id: "pando-vault-key".to_owned(),
            key_version: 3,
            payload: b"vault:v3:abcdef".to_vec(),
        }
        .to_json()
        .unwrap();
        let sealed = SealedPackArtifact {
            ciphertext: Vec::new(),
            ciphertext_sha256: "33".repeat(32),
            ciphertext_bytes: 0,
            plaintext_sha256: pack.pack_sha256.clone(),
            plaintext_bytes: 0,
            envelope_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap(),
            nonce_prefix_hex: "01020304".to_owned(),
            wrapped_key_json: wrapped,
            key_id: "pando-vault-key".to_owned(),
            key_version: 3,
            provider_kind: "vault-transit".to_owned(),
            cipher_suite: "AES-256-GCM-HMAC-SHA256".to_owned(),
            encryption_mode: AUTHENTICATED_ENVELOPE_MODE.to_owned(),
        };
        let env = build_authenticated_envelope_record(repo, &pack, &sealed, "hot").unwrap();
        assert_eq!(env.provider_kind, "vault-transit");
        assert_eq!(env.key_version, 3);

        let mut mismatched = sealed.clone();
        mismatched.key_version = 2;
        assert!(build_authenticated_envelope_record(repo, &pack, &mismatched, "hot").is_err());
        let mut mismatched_kind = sealed.clone();
        mismatched_kind.provider_kind = "local-file-key-provider".to_owned();
        assert!(build_authenticated_envelope_record(repo, &pack, &mismatched_kind, "hot").is_err());
    }

    #[test]
    fn authenticated_envelope_verification_binds_outer_provider_identity() {
        use super::super::envelopes::verify_envelope_record;
        use super::super::{ENVELOPE_SCHEMA, KmsEnvelopeRecord};

        let wrapped = PandoWrappedDek::Versioned {
            provider_kind: PandoProviderKind::VaultTransit,
            key_id: "pando-vault-key".to_owned(),
            key_version: 3,
            payload: b"vault:v3:abcdef".to_vec(),
        }
        .to_json()
        .unwrap();
        let mut env = KmsEnvelopeRecord {
            schema: ENVELOPE_SCHEMA.to_owned(),
            repo: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            pack_id: uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            key_id: "pando-vault-key".to_owned(),
            key_version: 3,
            cipher_suite: "AES-256-GCM-HMAC-SHA256".to_owned(),
            pack_sha256: "11".repeat(32),
            idx_sha256: "22".repeat(32),
            plaintext_sha256: "11".repeat(32),
            envelope_mac: String::new(),
            storage_tier: "hot".to_owned(),
            encryption_mode: "authenticated-envelope-v1".to_owned(),
            envelope_id: Some(uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap()),
            nonce_prefix: Some("01020304".to_owned()),
            wrapped_key_json: Some(wrapped.clone()),
            ciphertext_sha256: Some("33".repeat(32)),
            ciphertext_bytes: Some(123),
            provider_kind: "vault-transit".to_owned(),
        };
        env.envelope_mac = compute_authenticated_envelope_mac(&EnvelopeMacInputs {
            encryption_mode: &env.encryption_mode,
            repo: env.repo,
            pack_id: env.pack_id,
            key_id: &env.key_id,
            key_version: env.key_version,
            cipher_suite: &env.cipher_suite,
            pack_sha256: &env.pack_sha256,
            idx_sha256: &env.idx_sha256,
            ciphertext_sha256: env.ciphertext_sha256.as_deref().unwrap(),
            ciphertext_bytes: env.ciphertext_bytes.unwrap(),
            envelope_id: env.envelope_id.unwrap(),
            nonce_prefix: env.nonce_prefix.as_deref().unwrap(),
            wrapped_key_json: &wrapped,
        });
        verify_envelope_record(&env).unwrap();

        let mut wrong_version = env.clone();
        wrong_version.key_version = 2;
        wrong_version.envelope_mac = compute_authenticated_envelope_mac(&EnvelopeMacInputs {
            encryption_mode: &wrong_version.encryption_mode,
            repo: wrong_version.repo,
            pack_id: wrong_version.pack_id,
            key_id: &wrong_version.key_id,
            key_version: wrong_version.key_version,
            cipher_suite: &wrong_version.cipher_suite,
            pack_sha256: &wrong_version.pack_sha256,
            idx_sha256: &wrong_version.idx_sha256,
            ciphertext_sha256: wrong_version.ciphertext_sha256.as_deref().unwrap(),
            ciphertext_bytes: wrong_version.ciphertext_bytes.unwrap(),
            envelope_id: wrong_version.envelope_id.unwrap(),
            nonce_prefix: wrong_version.nonce_prefix.as_deref().unwrap(),
            wrapped_key_json: &wrapped,
        });
        assert!(verify_envelope_record(&wrong_version).is_err());

        let mut wrong_kind = env.clone();
        wrong_kind.provider_kind = "local-file-key-provider".to_owned();
        wrong_kind.envelope_mac = compute_authenticated_envelope_mac(&EnvelopeMacInputs {
            encryption_mode: &wrong_kind.encryption_mode,
            repo: wrong_kind.repo,
            pack_id: wrong_kind.pack_id,
            key_id: &wrong_kind.key_id,
            key_version: wrong_kind.key_version,
            cipher_suite: &wrong_kind.cipher_suite,
            pack_sha256: &wrong_kind.pack_sha256,
            idx_sha256: &wrong_kind.idx_sha256,
            ciphertext_sha256: wrong_kind.ciphertext_sha256.as_deref().unwrap(),
            ciphertext_bytes: wrong_kind.ciphertext_bytes.unwrap(),
            envelope_id: wrong_kind.envelope_id.unwrap(),
            nonce_prefix: wrong_kind.nonce_prefix.as_deref().unwrap(),
            wrapped_key_json: &wrapped,
        });
        assert!(verify_envelope_record(&wrong_kind).is_err());
    }

    #[test]
    fn versioned_schema_is_strict_and_provider_specific() {
        let decoded = PandoWrappedDek::from_json(VERSIONED.as_bytes()).unwrap();
        match &decoded {
            PandoWrappedDek::Versioned { provider_kind, key_id, key_version, payload } => {
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
            r#"{"pando_wrapped_dek":null}"#,
            r#"{"pando_wrapped_dek":"not-an-object"}"#,
            r#"{"pando_wrapped_dek":{"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"payload_hex":"aabbcc"},"pando_wrapped_dek":{"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"payload_hex":"aabbcc"}}"#,
            r#"{"pando_wrapped_dek":{"version":1,"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"payload_hex":"aabbcc"}}"#,
            r#"{"pando_wrapped_dek":{"version":1,"provider_kind":"vault-transit","provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"payload_hex":"aabbcc"}}"#,
            r#"{"pando_wrapped_dek":{"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_id":"pando-vault-key","key_version":3,"payload_hex":"aabbcc"}}"#,
            r#"{"pando_wrapped_dek":{"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"key_version":3,"payload_hex":"aabbcc"}}"#,
            r#"{"pando_wrapped_dek":{"version":1,"provider_kind":"vault-transit","key_id":"pando-vault-key","key_version":3,"payload_hex":"aabbcc","payload_hex":"aabbcc"}}"#,
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
        let context =
            pack_wrap_context(uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), uuid::Uuid::new_v4(), &"44".repeat(32))
                .unwrap();
        let data_key = PandoDataKey::generate().unwrap();
        let wrapped = provider.wrap_data_key(&data_key, &context).await.unwrap();
        let encoded = wrapped.to_json().unwrap();
        let decoded = PandoWrappedDek::from_json(encoded.as_bytes()).unwrap();
        assert_eq!(decoded.to_json().unwrap(), encoded);
        let opened = provider.unwrap_data_key(&decoded, &context).await.unwrap();
        assert_eq!(sha256_hex(opened.expose_secret()), sha256_hex(data_key.expose_secret()));

        let versioned = PandoWrappedDek::from_json(VERSIONED.as_bytes()).unwrap();
        assert!(provider.unwrap_data_key(&versioned, &context).await.is_err());
        assert!(provider.rewrap_data_key(&versioned, &context).await.is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
