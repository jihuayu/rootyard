use rootyard::storage::encrypted_objects::{VaultTransit, decrypt_file, encrypt_file, rotate_envelope};
use std::{fs::File, io::{Read, Write}, path::PathBuf, time::Duration};
use tokio::time::Instant;

fn deadline() -> Instant { Instant::now() + Duration::from_secs(120) }

#[tokio::test]
async fn vault_pack_encryption_rotation() {
    if std::env::var_os("ROOTYARD_KMS_VAULT_URL").is_none() { return; }
    let provider = VaultTransit::from_env().unwrap();
    let root = PathBuf::from(std::env::var("ROOTYARD_KMS_TEST_ROOT").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    let source = root.join("pack.plain");
    let ciphertext = root.join("pack.cipher");
    let envelopes = root.join("envelopes");
    let phase = std::env::var("ROOTYARD_KMS_TEST_PHASE").unwrap();
    if phase == "publish" {
        let mut file = File::create(&source).unwrap();
        let block = vec![0x4c; 64 * 1024];
        for _ in 0..192 { file.write_all(&block).unwrap(); }
        file.write_all(b"pack-end-marker").unwrap();
        file.sync_all().unwrap();
        let first = encrypt_file(&provider, &source, &ciphertext, &envelopes, deadline()).await.unwrap();
        assert_eq!(first.generation, 1);
        let missing_parent = root.join("missing-parent").join("envelopes");
        let retry_cipher = root.join("retry.cipher");
        assert!(encrypt_file(&provider, &source, &retry_cipher, &missing_parent, deadline()).await.is_err());
        assert!(!retry_cipher.exists());
        std::fs::create_dir(root.join("missing-parent")).unwrap();
        encrypt_file(&provider, &source, &retry_cipher, &missing_parent, deadline()).await.unwrap();
        decrypt_file(&provider, &retry_cipher, &missing_parent, None, &root.join("retry.out"), deadline()).await.unwrap();
        assert_eq!(std::fs::read(root.join("retry.out")).unwrap(), std::fs::read(&source).unwrap());
        let mut raw = Vec::new();
        File::open(&ciphertext).unwrap().take(4096).read_to_end(&mut raw).unwrap();
        assert!(!raw.windows(32).any(|w| w == [0x4c; 32]));
        let out = root.join("first.out");
        decrypt_file(&provider, &ciphertext, &envelopes, None, &out, deadline()).await.unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), std::fs::read(&source).unwrap());
        provider.rotate_master(deadline()).await.unwrap();
        let second = rotate_envelope(&provider, &envelopes, deadline()).await.unwrap();
        assert!(second.generation > 1 && second.wrapped_key != first.wrapped_key);
        decrypt_file(&provider, &ciphertext, &envelopes, Some(1), &root.join("old.out"), deadline()).await.unwrap();
        decrypt_file(&provider, &ciphertext, &envelopes, None, &root.join("new.out"), deadline()).await.unwrap();
        assert_eq!(std::fs::read(root.join("old.out")).unwrap(), std::fs::read(root.join("new.out")).unwrap());
        let mut tampered = std::fs::read(&ciphertext).unwrap();
        tampered[20] ^= 0x80;
        std::fs::write(root.join("tampered.cipher"), tampered).unwrap();
        assert!(decrypt_file(&provider, &root.join("tampered.cipher"), &envelopes, None, &root.join("bad.out"), deadline()).await.is_err());
        assert!(!root.join("bad.out").exists());
    } else if phase == "recover" {
        decrypt_file(&provider, &ciphertext, &envelopes, Some(1), &root.join("restart-old.out"), deadline()).await.unwrap();
        decrypt_file(&provider, &ciphertext, &envelopes, None, &root.join("restart-new.out"), deadline()).await.unwrap();
        assert_eq!(std::fs::read(root.join("restart-old.out")).unwrap(), std::fs::read(root.join("restart-new.out")).unwrap());
    } else if phase == "revoked" {
        assert!(decrypt_file(&provider, &ciphertext, &envelopes, Some(1), &root.join("revoked-old.out"), deadline()).await.is_err());
        assert!(!root.join("revoked-old.out").exists());
        decrypt_file(&provider, &ciphertext, &envelopes, None, &root.join("current.out"), deadline()).await.unwrap();
    } else { panic!("unknown KMS test phase"); }
}
