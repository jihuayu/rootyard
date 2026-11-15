use super::super::crypto::{
    OpenSealedRequest, open_sealed_pack_bytes, rewrap_pack_dek, seal_pack_bytes, sha256_hex,
};
use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn kms_rotation_retention_policy_revocation_and_rewrap_lifecycle() {
    let tmp = std::env::temp_dir().join(format!("pando-kms-prov-{}", Uuid::new_v4()));
    let kms_dir = tmp.join("kms-repo");
    let prov_v1 = PandoKmsProvider::open_or_init(&kms_dir, "kms-local-default-v1").unwrap();
    let dir_mode = std::fs::metadata(&kms_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
    let key_mode = std::fs::metadata(kms_dir.join("kms-local-default-v1.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(key_mode, 0o600);

    let (repo, pack1, pack2) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let idx_sha = sha256_hex(b"idx-v1");
    let plain1 = b"PACK\x00\x00\x00\x02pack-one-secret-data".to_vec();
    let plain2 = b"PACK\x00\x00\x00\x02pack-two-secret-data".to_vec();

    let sealed1 = seal_pack_bytes(
        &prov_v1,
        repo,
        pack1,
        &idx_sha,
        "AES-256-GCM-HMAC-SHA256",
        1,
        &plain1,
    )
    .unwrap();

    let (_pol2, ver2) =
        prepare_rotation_target_key(&kms_dir, "kms-rot-v2", "kms-local-default-v1").unwrap();
    assert_eq!(ver2, 2);
    let prov_v2 = PandoKmsProvider::open_existing(&kms_dir).unwrap();
    let sealed2 = seal_pack_bytes(
        &prov_v2,
        repo,
        pack2,
        &idx_sha,
        "CHACHA20-POLY1305-SHA256",
        ver2,
        &plain2,
    )
    .unwrap();

    let opened1_via_retained = open_sealed_pack_bytes(
        &prov_v2,
        &OpenSealedRequest {
            repo,
            pack_id: pack1,
            expected_plaintext_sha256: &sealed1.plaintext_sha256,
            expected_idx_sha256: &idx_sha,
            expected_cipher_suite: "AES-256-GCM-HMAC-SHA256",
            expected_envelope_id: Some(sealed1.envelope_id),
            expected_nonce_prefix: Some(&sealed1.nonce_prefix_hex),
            wrapped_key_json: &sealed1.wrapped_key_json,
        },
        &sealed1.ciphertext,
    )
    .unwrap();
    assert_eq!(opened1_via_retained, plain1);

    let (rewrapped_key_id, rewrapped_json) = rewrap_pack_dek(
        &prov_v2,
        repo,
        pack1,
        sealed1.envelope_id,
        &sealed1.plaintext_sha256,
        &sealed1.wrapped_key_json,
    )
    .unwrap();
    assert_eq!(rewrapped_key_id, "kms-rot-v2");

    update_policy_in_dir(&kms_dir, Some(false), None).unwrap();
    let prov_no_retain = PandoKmsProvider::open_existing(&kms_dir).unwrap();
    assert!(prov_no_retain.ensure_key_readable("kms-local-default-v1", 1).is_err());
    assert!(open_sealed_pack_bytes(
        &prov_no_retain,
        &OpenSealedRequest {
            repo,
            pack_id: pack1,
            expected_plaintext_sha256: &sealed1.plaintext_sha256,
            expected_idx_sha256: &idx_sha,
            expected_cipher_suite: "AES-256-GCM-HMAC-SHA256",
            expected_envelope_id: Some(sealed1.envelope_id),
            expected_nonce_prefix: Some(&sealed1.nonce_prefix_hex),
            wrapped_key_json: &sealed1.wrapped_key_json,
        },
        &sealed1.ciphertext,
    )
    .is_err());
    let opened1_rewrapped = open_sealed_pack_bytes(
        &prov_no_retain,
        &OpenSealedRequest {
            repo,
            pack_id: pack1,
            expected_plaintext_sha256: &sealed1.plaintext_sha256,
            expected_idx_sha256: &idx_sha,
            expected_cipher_suite: "AES-256-GCM-HMAC-SHA256",
            expected_envelope_id: Some(sealed1.envelope_id),
            expected_nonce_prefix: Some(&sealed1.nonce_prefix_hex),
            wrapped_key_json: &rewrapped_json,
        },
        &sealed1.ciphertext,
    )
    .unwrap();
    assert_eq!(opened1_rewrapped, plain1);

    update_policy_in_dir(&kms_dir, Some(true), Some(2)).unwrap();
    let prov_min_v2 = PandoKmsProvider::open_existing(&kms_dir).unwrap();
    assert!(prov_min_v2.ensure_key_readable("kms-local-default-v1", 1).is_err());
    assert!(prov_min_v2.ensure_key_readable("kms-rot-v2", 2).is_ok());

    revoke_key_in_dir(&kms_dir, "kms-local-default-v1").unwrap();
    assert!(!kms_dir.join("kms-local-default-v1.key").exists());
    let prov_rev_v1 = PandoKmsProvider::open_existing(&kms_dir).unwrap();
    assert!(prov_rev_v1.ensure_key_readable("kms-local-default-v1", 1).is_err());
    assert!(prov_rev_v1.ensure_key_readable("kms-rot-v2", 2).is_ok());

    set_provider_revoked_in_dir(&kms_dir, true).unwrap();
    let prov_revoked = PandoKmsProvider::open_existing(&kms_dir).unwrap();
    assert!(prov_revoked.active_entry().is_err());
    assert!(seal_pack_bytes(
        &prov_revoked,
        repo,
        pack2,
        &idx_sha,
        "CHACHA20-POLY1305-SHA256",
        2,
        &plain2,
    )
    .is_err());
    assert!(open_sealed_pack_bytes(
        &prov_revoked,
        &OpenSealedRequest {
            repo,
            pack_id: pack2,
            expected_plaintext_sha256: &sealed2.plaintext_sha256,
            expected_idx_sha256: &idx_sha,
            expected_cipher_suite: "CHACHA20-POLY1305-SHA256",
            expected_envelope_id: Some(sealed2.envelope_id),
            expected_nonce_prefix: Some(&sealed2.nonce_prefix_hex),
            wrapped_key_json: &sealed2.wrapped_key_json,
        },
        &sealed2.ciphertext,
    )
    .is_err());

    set_provider_revoked_in_dir(&kms_dir, false).unwrap();
    let prov_restored = PandoKmsProvider::open_existing(&kms_dir).unwrap();
    let opened2 = open_sealed_pack_bytes(
        &prov_restored,
        &OpenSealedRequest {
            repo,
            pack_id: pack2,
            expected_plaintext_sha256: &sealed2.plaintext_sha256,
            expected_idx_sha256: &idx_sha,
            expected_cipher_suite: "CHACHA20-POLY1305-SHA256",
            expected_envelope_id: Some(sealed2.envelope_id),
            expected_nonce_prefix: Some(&sealed2.nonce_prefix_hex),
            wrapped_key_json: &sealed2.wrapped_key_json,
        },
        &sealed2.ciphertext,
    )
    .unwrap();
    assert_eq!(opened2, plain2);

    std::fs::remove_file(kms_dir.join(POLICY_FILE_NAME)).unwrap();
    let external = PandoKmsProvider::open_existing(&kms_dir).unwrap();
    assert_eq!(external.policy().active_key_id, "kms-rot-v2");
    let _ = std::fs::remove_dir_all(&tmp);
}
