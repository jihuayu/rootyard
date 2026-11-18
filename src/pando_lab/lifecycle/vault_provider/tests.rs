use super::*;

#[test]
fn config_requires_strict_origin_tls_and_components() {
    let timeout = Some(Duration::from_secs(3));
    assert!(
        VaultTransitConfig::from_values(
            "https://vault.example.com",
            "token-value".to_owned(),
            "transit",
            "pando-vault-key",
            timeout,
        )
        .is_ok()
    );
    assert!(
        VaultTransitConfig::from_values(
            "http://127.0.0.1:8200",
            "token-value".to_owned(),
            "transit",
            "pando-vault-key",
            timeout,
        )
        .is_ok()
    );
    for base in [
        "http://vault.example.com",
        "https://vault.example.com/v1/transit",
        "https://vault.example.com/?x=1",
        "https://vault.example.com/#fragment",
        "https://user:pass@vault.example.com",
    ] {
        assert!(
            VaultTransitConfig::from_values(base, "token-value".to_owned(), "transit", "pando-vault-key", timeout)
                .is_err(),
            "accepted {base}"
        );
    }
    for (mount, key) in [("", "pando-vault-key"), ("transit", ""), ("bad/mount", "pando-vault-key")] {
        assert!(
            VaultTransitConfig::from_values(
                "https://vault.example.com",
                "token-value".to_owned(),
                mount,
                key,
                timeout,
            )
            .is_err()
        );
    }
    for key_name in ["a", "ab", " pando-vault-key", "pando-vault-key "] {
        assert!(
            VaultTransitConfig::from_values(
                "https://vault.example.com",
                "token-value".to_owned(),
                "transit",
                key_name,
                timeout,
            )
            .is_err(),
            "accepted key name {key_name:?}"
        );
    }
    assert!(
        VaultTransitConfig::from_values(
            "https://vault.example.com",
            "token-value".to_owned(),
            "transit",
            "abc",
            timeout,
        )
        .is_ok()
    );
    let config = VaultTransitConfig::from_values(
        "https://vault.example.com",
        "super-secret-token".to_owned(),
        "transit",
        "pando-vault-key",
        timeout,
    )
    .unwrap();
    assert!(!format!("{config:?}").contains("super-secret-token"));
}

#[test]
fn key_metadata_requires_derived_aes256_and_positive_latest_version() {
    let valid = br#"{"data":{"type":"aes256-gcm96","derived":true,"latest_version":3}}"#;
    assert_eq!(parse_key_metadata(valid).unwrap(), (3, 0));
    for invalid in [
        br#"{"data":{"type":"aes256-gcm96","derived":false,"latest_version":3}}"#.as_slice(),
        br#"{"data":{"type":"rsa-2048","derived":true,"latest_version":3}}"#.as_slice(),
        br#"{"data":{"type":"aes256-gcm96","derived":true}}"#.as_slice(),
        br#"{"data":{"type":"aes256-gcm96","derived":true,"latest_version":0}}"#.as_slice(),
        br#"{"data":{"type":"aes256-gcm96","derived":true,"latest_version":3,"min_encryption_version":4}}"#.as_slice(),
    ] {
        assert!(parse_key_metadata(invalid).is_err());
    }
}

#[test]
fn ciphertext_version_parser_rejects_mismatch_and_malformed_values() {
    assert_eq!(parse_vault_ciphertext_version(b"vault:v3:abcdef"), Some(3));
    for value in [b"".as_slice(), b"vault:v0:abc", b"vault:vx:abc", b"vault:v2:", b"other:v2:abc"] {
        assert_eq!(parse_vault_ciphertext_version(value), None);
    }
    assert!(ensure_ciphertext("vault:v2:abcdef", 3).is_err());
    assert!(ensure_ciphertext("vault:v3:abcdef", 3).is_ok());
}
