use rootyard::{db, pando_gateway::pack_store::PackStore};
use rand::RngCore;
use std::{path::{Path, PathBuf}, process::Command, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

fn run(git: &Path, args: &[&str], cwd: &Path) {
    let status = Command::new(git).args(args).current_dir(cwd).status().unwrap();
    assert!(status.success(), "Git fixture command failed: {args:?}");
}
fn deadline() -> Instant { Instant::now() + Duration::from_secs(300) }

#[tokio::test]
async fn remote_encrypted_pack_publish_and_restart_recovery() {
    if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_none() ||
        std::env::var_os("ROOTYARD_KMS_VAULT_URL").is_none() ||
        std::env::var_os("ROOTYARD_PANDO_TEST_ROOT").is_none() { return; }
    let pool = db::pool(&std::env::var("ROOTYARD_TEST_DATABASE_URL").unwrap()).unwrap();
    db::migrate(&pool).await.unwrap();
    let root = PathBuf::from(std::env::var("ROOTYARD_PANDO_TEST_ROOT").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    let git = PathBuf::from(std::env::var("ROOTYARD_GIT_PATH").unwrap_or_else(|_| "/usr/bin/git".into()));
    let phase = std::env::var("ROOTYARD_PANDO_TEST_PHASE").unwrap();
    let store = PackStore::from_env(root.join(format!("work-{phase}")), git.clone()).unwrap();
    if phase == "publish" {
        let owner = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let user = format!("pando{}", &owner.simple().to_string()[..12]);
        let client = pool.get().await.unwrap();
        client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&owner,&user]).await.unwrap();
        client.execute("INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,'packtest','ready')",
            &[&repo,&owner]).await.unwrap();
        let bare = root.join("source.git");
        let work = root.join("source-work");
        std::fs::create_dir(&bare).unwrap();
        std::fs::create_dir(&work).unwrap();
        run(&git, &["init", "--bare", "--object-format=sha1", "."], &bare);
        run(&git, &["init", "--object-format=sha1", "."], &work);
        let mut payload = vec![0u8; 10 * 1024 * 1024 + 17];
        rand::rng().fill_bytes(&mut payload);
        std::fs::write(work.join("payload.bin"), payload).unwrap();
        run(&git, &["add", "payload.bin"], &work);
        run(&git, &["-c", "user.name=Pack Test", "-c", "user.email=pack@test.invalid", "commit", "-m", "pack"], &work);
        run(&git, &["push", bare.to_str().unwrap(), "HEAD:refs/heads/main"], &work);
        run(&git, &["repack", "-ad"], &bare);
        let packs = bare.join("objects/pack");
        let pack = std::fs::read_dir(&packs).unwrap().map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "pack")).unwrap();
        assert!(std::fs::metadata(&pack).unwrap().len() > 8 * 1024 * 1024);
        let manifest = store.publish(&pool, repo, owner, 1, "sha1", &pack,
            &pack.with_extension("idx"), deadline()).await.unwrap();
        assert_ne!(manifest.pack.plaintext_sha256, manifest.pack.ciphertext_sha256);
        assert!(manifest.pack.ciphertext_bytes > manifest.pack.plaintext_bytes);
        let ready: i64 = client.query_one("SELECT count(*) FROM pando_pack_manifests WHERE id=$1", &[&manifest.id])
            .await.unwrap().get(0);
        assert_eq!(ready, 1);
        assert!(store.publish(&pool, repo, owner, 999, "sha1", &pack,
            &pack.with_extension("idx"), deadline()).await.is_err());
        let still_ready: i64 = client.query_one("SELECT count(*) FROM pando_pack_manifests WHERE repository_id=$1", &[&repo])
            .await.unwrap().get(0);
        assert_eq!(still_ready, 1);
        std::fs::write(root.join("identity.json"), serde_json::to_vec(&serde_json::json!({
            "repository_id":repo,"pack_id":manifest.id,"plaintext_sha256":manifest.pack.plaintext_sha256,
            "pack_bytes":manifest.pack.plaintext_bytes
        })).unwrap()).unwrap();
    } else if phase == "recover" {
        // Deliberately remove all local source and publication cache state.
        let _ = std::fs::remove_dir_all(root.join("source.git"));
        let _ = std::fs::remove_dir_all(root.join("source-work"));
        let _ = std::fs::remove_dir_all(root.join("work-publish"));
        let ids: serde_json::Value = serde_json::from_slice(&std::fs::read(root.join("identity.json")).unwrap()).unwrap();
        let repo: Uuid = ids["repository_id"].as_str().unwrap().parse().unwrap();
        let pack_id: Uuid = ids["pack_id"].as_str().unwrap().parse().unwrap();
        let destination = root.join("recovered");
        let manifest = store.recover(&pool, repo, pack_id, &destination, deadline()).await.unwrap();
        assert_eq!(manifest.pack.plaintext_sha256, ids["plaintext_sha256"].as_str().unwrap());
        assert_eq!(manifest.pack.plaintext_bytes, ids["pack_bytes"].as_u64().unwrap());
        assert_eq!(std::fs::metadata(destination.join(format!("pack-{pack_id}.pack"))).unwrap().len(), manifest.pack.plaintext_bytes);
        assert_eq!(std::fs::metadata(destination.join(format!("pack-{pack_id}.idx"))).unwrap().len(), manifest.index.plaintext_bytes);
    } else { panic!("unknown Pando test phase"); }
}
