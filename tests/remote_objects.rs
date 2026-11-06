use rootyard::storage::remote_objects::{ObjectKey, RemoteObjectStore};
use sha2::{Digest, Sha256};
use std::{fs::File, io::Write, path::PathBuf, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

fn deadline() -> Instant { Instant::now() + Duration::from_secs(90) }

#[tokio::test]
async fn local_streaming_and_digest_gate() {
    let root = tempfile::tempdir().unwrap();
    let store = RemoteObjectStore::Local(root.path().join("objects"));
    let source = root.path().join("source");
    std::fs::write(&source, b"immutable bytes").unwrap();
    let digest = hex::encode(Sha256::digest(b"immutable bytes"));
    let key = ObjectKey::new(Uuid::new_v4(), "workspace", &digest).unwrap();
    store.put_file(&key, &source, 15, deadline()).await.unwrap();
    assert_eq!(store.get_range(&key, 2, 5, deadline()).await.unwrap(), b"mutab");
    let dest = root.path().join("dest");
    store.get_to_file(&key, &dest, 15, deadline()).await.unwrap();
    assert_eq!(std::fs::read(dest).unwrap(), b"immutable bytes");
    let bad = ObjectKey::new(key.tenant_id, "workspace", &"0".repeat(64)).unwrap();
    assert!(store.put_file(&bad, &source, 15, deadline()).await.is_err());
    assert!(store.head(&bad, deadline()).await.unwrap().is_none());
    store.delete(&key, deadline()).await.unwrap();
    assert!(store.head(&key, deadline()).await.unwrap().is_none());
}

#[tokio::test]
async fn s3_streaming_cycle() {
    if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_none() { return; }
    let store = RemoteObjectStore::from_env(PathBuf::from("unused")).unwrap();
    let fixture = PathBuf::from(std::env::var("ROOTYARD_S3_TEST_FIXTURE").unwrap());
    let phase = std::env::var("ROOTYARD_S3_TEST_PHASE").unwrap();
    if phase == "recover" {
        let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&fixture).unwrap()).unwrap();
        let tenant: Uuid = saved["tenant"].as_str().unwrap().parse().unwrap();
        let key = ObjectKey::new(tenant, "pack", saved["digest"].as_str().unwrap()).unwrap();
        let size = saved["size"].as_u64().unwrap();
        let dest = fixture.with_extension("recovered");
        store.get_to_file(&key, &dest, size, deadline()).await.unwrap();
        assert_eq!(std::fs::metadata(&dest).unwrap().len(), size);
        assert!(store.get_to_file(&key, &fixture.with_extension("truncated"), size - 1, deadline()).await.is_err());
        assert!(!fixture.with_extension("truncated").exists());
        store.delete(&key, deadline()).await.unwrap();
        assert!(store.head(&key, deadline()).await.unwrap().is_none());
        return;
    }
    assert_eq!(phase, "publish");
    let source = fixture.with_extension("source");
    let mut file = File::create(&source).unwrap();
    let mut hasher = Sha256::new();
    let block = vec![0x5a; 64 * 1024];
    for _ in 0..320 { file.write_all(&block).unwrap(); hasher.update(&block); }
    file.write_all(b"tail").unwrap(); hasher.update(b"tail");
    file.sync_all().unwrap();
    let size = 320 * block.len() as u64 + 4;
    let key = ObjectKey::new(Uuid::new_v4(), "pack", &hex::encode(hasher.finalize())).unwrap();
    let wrong = ObjectKey::new(key.tenant_id, "pack", &"f".repeat(64)).unwrap();
    assert!(store.put_file(&wrong, &source, size, deadline()).await.is_err());
    assert!(store.head(&wrong, deadline()).await.unwrap().is_none());
    store.put_file(&key, &source, size, deadline()).await.unwrap();
    assert_eq!(store.head(&key, deadline()).await.unwrap().unwrap().size, size);
    assert_eq!(store.get_range(&key, 8 * 1024 * 1024 - 2, 4, deadline()).await.unwrap(), [0x5a; 4]);
    std::fs::write(&fixture, serde_json::to_vec(&serde_json::json!({"tenant":key.tenant_id,"digest":key.sha256,"size":size})).unwrap()).unwrap();
}
