use super::super::data_key::PandoDataKey;
use super::super::provider::{PandoKeyProvider, PandoKmsProvider};
use super::super::wrapped_dek::PandoWrappedDek;
use super::*;
use rootyard::blob_store::key_provider::{KeyId, KeyProviderCapabilities, KeyProviderError};

#[derive(Debug)]
struct PlaintextFallbackProvider(KeyId);

impl KeyProvider for PlaintextFallbackProvider {
    fn current_key_id(&self) -> &KeyId {
        &self.0
    }

    fn wrap_data_key(
        &self,
        _data_key: &[u8; DATA_KEY_BYTES],
        _context: &WrapContext,
    ) -> std::result::Result<WrappedKey, KeyProviderError> {
        Err(KeyProviderError::KeyRing("dummy"))
    }

    fn unwrap_data_key(
        &self,
        _wrapped: &WrappedKey,
        _context: &WrapContext,
    ) -> std::result::Result<DataKey, KeyProviderError> {
        Err(KeyProviderError::KeyRing("dummy"))
    }

    fn capabilities(&self) -> KeyProviderCapabilities {
        KeyProviderCapabilities {
            local_envelope: true,
            rewrap: false,
            retained_key_versions: false,
            provider_managed: false,
            plaintext_fallback: true,
        }
    }
}

#[derive(Debug)]
struct VersionedProvider {
    key_id: KeyId,
}

impl PandoKeyProvider for VersionedProvider {
    fn current_key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn capabilities(&self) -> KeyProviderCapabilities {
        KeyProviderCapabilities {
            local_envelope: false,
            rewrap: true,
            retained_key_versions: true,
            provider_managed: true,
            plaintext_fallback: false,
        }
    }

    fn wrap_data_key<'a>(
        &'a self,
        _data_key: &'a PandoDataKey,
        _context: &'a WrapContext,
    ) -> futures_util::future::BoxFuture<'a, std::result::Result<PandoWrappedDek, KeyProviderError>> {
        Box::pin(async move {
            Ok(PandoWrappedDek::Versioned {
                provider_kind: super::super::wrapped_dek::PandoProviderKind::VaultTransit,
                key_id: "pando-vault-key".to_owned(),
                key_version: 7,
                payload: b"vault:v7:abcdef".to_vec(),
            })
        })
    }

    fn unwrap_data_key<'a>(
        &'a self,
        _wrapped: &'a PandoWrappedDek,
        _context: &'a WrapContext,
    ) -> futures_util::future::BoxFuture<'a, std::result::Result<PandoDataKey, KeyProviderError>> {
        Box::pin(async { Err(KeyProviderError::KeyRing("test provider cannot unwrap")) })
    }

    fn rewrap_data_key<'a>(
        &'a self,
        _wrapped: &'a PandoWrappedDek,
        _context: &'a WrapContext,
    ) -> futures_util::future::BoxFuture<'a, std::result::Result<PandoWrappedDek, KeyProviderError>> {
        Box::pin(async { Err(KeyProviderError::KeyRing("test provider cannot rewrap")) })
    }
}

fn sample_pack_payload() -> (Uuid, Uuid, Vec<u8>, String) {
    let mut plain = b"PACK\x00\x00\x00\x02\x00\x00\x00\x01".to_vec();
    plain.extend_from_slice(b"ROOTYARD_SECRET_BLOB_CONTENT_ISSUE_21:");
    plain.resize(SEALED_CHUNK_BYTES + 1234, 0x5Au8);
    let idx_sha = sha256_hex(b"sample-pack-index");
    (Uuid::new_v4(), Uuid::new_v4(), plain, idx_sha)
}

#[tokio::test]
async fn versioned_provider_key_version_overrides_the_caller_hint() {
    let provider = VersionedProvider { key_id: KeyId::parse("pando-vault-key").unwrap() };
    let (repo, pack_id, plain, idx_sha) = sample_pack_payload();
    let sealed =
        seal_pack_bytes(&provider, repo, pack_id, &idx_sha, "AES-256-GCM-HMAC-SHA256", 1, &plain).await.unwrap();
    assert_eq!(sealed.provider_kind, "vault-transit");
    assert_eq!(sealed.key_id, "pando-vault-key");
    assert_eq!(sealed.key_version, 7);
}

#[tokio::test]
async fn sealed_packs_encrypt_with_random_dek_nonce_and_roundtrip_both_ciphers() {
    let tmp = std::env::temp_dir().join(format!("pando-crypto-ok-{}", Uuid::new_v4()));
    let prov = PandoKmsProvider::open_or_init(&tmp, "kms-local-default-v1").unwrap();
    let (repo, pack_id, plain, idx_sha) = sample_pack_payload();

    for suite in ["AES-256-GCM-HMAC-SHA256", "CHACHA20-POLY1305-SHA256"] {
        let s1 = seal_pack_bytes(&prov, repo, pack_id, &idx_sha, suite, 1, &plain).await.unwrap();
        let s2 = seal_pack_bytes(&prov, repo, pack_id, &idx_sha, suite, 1, &plain).await.unwrap();
        assert_ne!(s1.envelope_id, s2.envelope_id);
        assert_ne!(s1.nonce_prefix_hex, s2.nonce_prefix_hex);
        assert_ne!(s1.ciphertext, s2.ciphertext);
        assert!(!s1.ciphertext.starts_with(b"PACK"));
        assert!(!s1.ciphertext.windows(37).any(|w| w == b"ROOTYARD_SECRET_BLOB_CONTENT_ISSUE_21"));

        let opened = open_sealed_pack_bytes(
            &prov,
            &OpenSealedRequest {
                repo,
                pack_id,
                expected_plaintext_sha256: &s1.plaintext_sha256,
                expected_idx_sha256: &idx_sha,
                expected_cipher_suite: suite,
                expected_envelope_id: Some(s1.envelope_id),
                expected_nonce_prefix: Some(&s1.nonce_prefix_hex),
                wrapped_key_json: &s1.wrapped_key_json,
            },
            &s1.ciphertext,
        )
        .await
        .unwrap();
        assert_eq!(opened, plain);
        assert_eq!(sha256_hex(&opened), sha256_hex(&plain));
    }

    let empty_sealed =
        seal_pack_bytes(&prov, repo, pack_id, &idx_sha, "CHACHA20-POLY1305-SHA256", 1, b"").await.unwrap();
    let empty_open = open_sealed_pack_bytes(
        &prov,
        &OpenSealedRequest {
            repo,
            pack_id,
            expected_plaintext_sha256: &empty_sealed.plaintext_sha256,
            expected_idx_sha256: &idx_sha,
            expected_cipher_suite: "CHACHA20-POLY1305-SHA256",
            expected_envelope_id: Some(empty_sealed.envelope_id),
            expected_nonce_prefix: Some(&empty_sealed.nonce_prefix_hex),
            wrapped_key_json: &empty_sealed.wrapped_key_json,
        },
        &empty_sealed.ciphertext,
    )
    .await
    .unwrap();
    assert!(empty_open.is_empty());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn tampered_ciphertext_wrong_key_wrong_context_and_fallback_provider_fail_closed() {
    let tmp = std::env::temp_dir().join(format!("pando-crypto-fail-{}", Uuid::new_v4()));
    let prov = PandoKmsProvider::open_or_init(&tmp.join("kms-a"), "kms-local-default-v1").unwrap();
    let wrong_prov = PandoKmsProvider::open_or_init(&tmp.join("kms-b"), "kms-local-default-v1").unwrap();
    let (repo, pack_id, plain, idx_sha) = sample_pack_payload();
    let suite = "AES-256-GCM-HMAC-SHA256";
    let sealed = seal_pack_bytes(&prov, repo, pack_id, &idx_sha, suite, 1, &plain).await.unwrap();

    let dummy = PlaintextFallbackProvider(KeyId::parse("kms-dummy-v1").unwrap());
    assert!(seal_pack_bytes(&dummy, repo, pack_id, &idx_sha, suite, 1, &plain).await.is_err());

    let base_req = OpenSealedRequest {
        repo,
        pack_id,
        expected_plaintext_sha256: &sealed.plaintext_sha256,
        expected_idx_sha256: &idx_sha,
        expected_cipher_suite: suite,
        expected_envelope_id: Some(sealed.envelope_id),
        expected_nonce_prefix: Some(&sealed.nonce_prefix_hex),
        wrapped_key_json: &sealed.wrapped_key_json,
    };

    assert!(open_sealed_pack_bytes(&dummy, &base_req, &sealed.ciphertext).await.is_err());
    assert!(open_sealed_pack_bytes(&wrong_prov, &base_req, &sealed.ciphertext).await.is_err());

    let mut flipped = sealed.ciphertext.clone();
    let mid = flipped.len() - 32;
    flipped[mid] ^= 0x01;
    assert!(open_sealed_pack_bytes(&prov, &base_req, &flipped).await.is_err());

    let mut truncated = sealed.ciphertext.clone();
    truncated.pop();
    assert!(open_sealed_pack_bytes(&prov, &base_req, &truncated).await.is_err());

    let mut trailing = sealed.ciphertext.clone();
    trailing.push(0x99);
    assert!(open_sealed_pack_bytes(&prov, &base_req, &trailing).await.is_err());

    let wrong_repo = OpenSealedRequest { repo: Uuid::new_v4(), ..base_req };
    assert!(open_sealed_pack_bytes(&prov, &wrong_repo, &sealed.ciphertext).await.is_err());

    let bad_idx = sha256_hex(b"wrong-idx");
    let wrong_idx = OpenSealedRequest { expected_idx_sha256: &bad_idx, ..base_req };
    assert!(open_sealed_pack_bytes(&prov, &wrong_idx, &sealed.ciphertext).await.is_err());

    let wrong_suite = OpenSealedRequest { expected_cipher_suite: "CHACHA20-POLY1305-SHA256", ..base_req };
    assert!(open_sealed_pack_bytes(&prov, &wrong_suite, &sealed.ciphertext).await.is_err());

    let mut wrapped_val: serde_json::Value = serde_json::from_str(&sealed.wrapped_key_json).unwrap();
    wrapped_val["ciphertext_b64"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==");
    let bad_wrapped_json = wrapped_val.to_string();
    let bad_wrapped_req = OpenSealedRequest { wrapped_key_json: &bad_wrapped_json, ..base_req };
    assert!(open_sealed_pack_bytes(&prov, &bad_wrapped_req, &sealed.ciphertext).await.is_err());

    let _ = std::fs::remove_dir_all(&tmp);
}
