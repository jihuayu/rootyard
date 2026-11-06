use axum::http::{HeaderMap, HeaderValue, header};
use rand::RngCore;
use rootyard::{
    AppState, auth,
    config::Config,
    db, dispatch, metrics,
    pando_gateway::{backup, pack_store::PackStore, prepare, publish, snapshot},
    storage::{
        self,
        remote_objects::{ObjectKey, RemoteObjectStore},
    },
};
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Barrier, Semaphore};
use tokio::time::Instant;
use uuid::Uuid;

fn run(git: &Path, args: &[&str], cwd: &Path) {
    let status = Command::new(git).args(args).current_dir(cwd).status().unwrap();
    assert!(status.success(), "Git fixture command failed: {args:?}");
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(300)
}

async fn concurrent_views(state: Arc<AppState>, repository: db::Repository) {
    let gate = Arc::new(Barrier::new(9));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let state = state.clone();
        let repository = repository.clone();
        let gate = gate.clone();
        tasks.spawn(async move {
            let lease = storage::read_leases::shared(&state.pool, repository.id, deadline()).await.unwrap();
            gate.wait().await;
            let _local = state.storage.read_snapshot_lock(repository.id).await;
            let view = Box::pin(snapshot::materialize(&state, &repository, &lease, deadline())).await.unwrap();
            assert!(view.path().join("objects/pack").is_dir());
        });
    }
    gate.wait().await;
    tokio::time::timeout(Duration::from_secs(5), async {
        state.pool.get().await.unwrap().query_one("SELECT 1", &[]).await.unwrap();
    })
    .await
    .expect("eight snapshot leases starved authorization query");
    let completed = tokio::time::timeout(Duration::from_secs(90), async {
        while let Some(task) = tasks.join_next().await {
            task.unwrap();
        }
    })
    .await;
    if completed.is_err() {
        tasks.abort_all();
        panic!("eight Pando snapshots deadlocked the pool");
    }
}

#[tokio::test]
async fn remote_encrypted_pack_publish_and_restart_recovery() {
    if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_none()
        || std::env::var_os("ROOTYARD_KMS_VAULT_URL").is_none()
        || std::env::var_os("ROOTYARD_PANDO_TEST_ROOT").is_none()
    {
        return;
    }
    let pool = db::pool(&std::env::var("ROOTYARD_TEST_DATABASE_URL").unwrap()).unwrap();
    db::migrate(&pool).await.unwrap();
    let root = PathBuf::from(std::env::var("ROOTYARD_PANDO_TEST_ROOT").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    let git = PathBuf::from(std::env::var("ROOTYARD_GIT_PATH").unwrap_or_else(|_| "/usr/bin/git".into()));
    let format = std::env::var("ROOTYARD_PANDO_TEST_OBJECT_FORMAT").unwrap_or_else(|_| "sha1".into());
    assert!(matches!(format.as_str(), "sha1" | "sha256"));
    let format_arg = format!("--object-format={format}");
    let phase = std::env::var("ROOTYARD_PANDO_TEST_PHASE").unwrap();
    let store = PackStore::from_env(root.join(format!("work-{phase}")), git.clone()).unwrap();
    if phase == "publish" {
        let owner = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let user = format!("pando{}", &owner.simple().to_string()[..12]);
        let client = pool.get().await.unwrap();
        client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&owner, &user]).await.unwrap();
        client
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state,object_format) VALUES($1,$2,'packtest','ready',$3)",
                &[&repo, &owner, &format],
            )
            .await
            .unwrap();
        let bare = root.join("source.git");
        let work = root.join("source-work");
        std::fs::create_dir(&bare).unwrap();
        std::fs::create_dir(&work).unwrap();
        run(&git, &["init", "--bare", &format_arg, "."], &bare);
        run(&git, &["init", &format_arg, "."], &work);
        let mut payload = vec![0u8; 10 * 1024 * 1024 + 17];
        rand::rng().fill_bytes(&mut payload);
        std::fs::write(work.join("payload.bin"), payload).unwrap();
        run(&git, &["add", "payload.bin"], &work);
        run(&git, &["-c", "user.name=Pack Test", "-c", "user.email=pack@test.invalid", "commit", "-m", "pack"], &work);
        run(&git, &["push", bare.to_str().unwrap(), "HEAD:refs/heads/main"], &work);
        run(&git, &["repack", "-ad"], &bare);
        let packs = bare.join("objects/pack");
        let pack = std::fs::read_dir(&packs)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "pack"))
            .unwrap();
        assert!(std::fs::metadata(&pack).unwrap().len() > 8 * 1024 * 1024);
        let manifest =
            Box::pin(store.publish(&pool, repo, owner, 1, &format, &pack, &pack.with_extension("idx"), deadline()))
                .await
                .unwrap();
        let commit = Command::new(&git).args(["rev-parse", "HEAD"]).current_dir(&work).output().unwrap();
        assert!(commit.status.success());
        let oid = String::from_utf8(commit.stdout).unwrap().trim().to_owned();
        client.execute("UPDATE repositories SET storage_backend='pando' WHERE id=$1", &[&repo]).await.unwrap();
        client.execute("INSERT INTO pando_repository_states(repository_id,tenant_id,storage_generation,ref_generation,object_format,state,pack_ids) \
            VALUES($1,$2,1,1,$3,'serving',$4)", &[&repo,&owner,&format,&vec![manifest.id]]).await.unwrap();
        client
            .execute(
                "INSERT INTO pando_refs(repository_id,ref_name,oid,updated_generation) \
            VALUES($1,'refs/heads/main',$2,1)",
                &[&repo, &oid],
            )
            .await
            .unwrap();
        assert_ne!(manifest.pack.plaintext_sha256, manifest.pack.ciphertext_sha256);
        assert!(manifest.pack.ciphertext_bytes > manifest.pack.plaintext_bytes);
        let ready: i64 = client
            .query_one("SELECT count(*) FROM pando_pack_manifests WHERE id=$1", &[&manifest.id])
            .await
            .unwrap()
            .get(0);
        assert_eq!(ready, 1);
        assert!(
            Box::pin(store.publish(&pool, repo, owner, 999, &format, &pack, &pack.with_extension("idx"), deadline()))
                .await
                .is_err()
        );
        let still_ready: i64 = client
            .query_one("SELECT count(*) FROM pando_pack_manifests WHERE repository_id=$1", &[&repo])
            .await
            .unwrap()
            .get(0);
        assert_eq!(still_ready, 1);
        std::fs::write(
            root.join("identity.json"),
            serde_json::to_vec(&serde_json::json!({
                "repository_id":repo,"pack_id":manifest.id,"plaintext_sha256":manifest.pack.plaintext_sha256,
                "pack_bytes":manifest.pack.plaintext_bytes,"commit_oid":oid,"tenant_id":owner,
                "object_format":format,"owner_slug":user
            }))
            .unwrap(),
        )
        .unwrap();
    } else if phase == "recover" {
        // Deliberately remove all local source and publication cache state.
        let _ = std::fs::remove_dir_all(root.join("source.git"));
        let _ = std::fs::remove_dir_all(root.join("source-work"));
        let _ = std::fs::remove_dir_all(root.join("work-publish"));
        let ids: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("identity.json")).unwrap()).unwrap();
        let repo: Uuid = ids["repository_id"].as_str().unwrap().parse().unwrap();
        let pack_id: Uuid = ids["pack_id"].as_str().unwrap().parse().unwrap();
        let destination = root.join("recovered");
        let manifest = Box::pin(store.recover(&pool, repo, pack_id, &destination, deadline())).await.unwrap();
        eprintln!("pando fixture: remote pack recovered");
        assert_eq!(manifest.pack.plaintext_sha256, ids["plaintext_sha256"].as_str().unwrap());
        assert_eq!(manifest.pack.plaintext_bytes, ids["pack_bytes"].as_u64().unwrap());
        assert_eq!(
            std::fs::metadata(destination.join(format!("pack-{pack_id}.pack"))).unwrap().len(),
            manifest.pack.plaintext_bytes
        );
        assert_eq!(
            std::fs::metadata(destination.join(format!("pack-{pack_id}.idx"))).unwrap().len(),
            manifest.index.plaintext_bytes
        );
        let config = Config {
            database_url: std::env::var("ROOTYARD_TEST_DATABASE_URL").unwrap(),
            data_dir: root.join("server-data"),
            bind: "127.0.0.1:0".parse().unwrap(),
            git: git.clone(),
            max_request_bytes: 128 * 1024 * 1024,
            max_output_bytes: 128 * 1024 * 1024,
            max_concurrent_git: 2,
            git_timeout: Duration::from_secs(120),
            git_memory_bytes: 1024 * 1024 * 1024,
            max_repo_bytes: 1024 * 1024 * 1024,
            max_pending_deliveries: 10000,
            outbox_worker: false,
            metrics_bind: None,
        };
        let state = Arc::new(AppState {
            mirror_primary: None,
            dispatch: dispatch::Signals::default(),
            storage: storage::Storage::open(&config).unwrap(),
            config,
            pool: pool.clone(),
            hooks: None,
            transfer_metrics: Arc::new(metrics::TransferCounters::default()),
            git_slots: Arc::new(Semaphore::new(2)),
        });
        let lease = storage::read_leases::shared(&state.pool, repo, deadline()).await.unwrap();
        let _local = state.storage.read_snapshot_lock(repo).await;
        let repository = db::Repository {
            id: repo,
            name: "packtest".into(),
            owner: ids["owner_slug"].as_str().unwrap().into(),
            state: "ready".into(),
            clone_path: "/git/fixture/packtest.git".into(),
            storage_backend: "pando".into(),
            storage_generation: 1,
            object_format: format.clone(),
        };
        let snapshot = Box::pin(snapshot::materialize(&state, &repository, &lease, deadline())).await.unwrap();
        eprintln!("pando fixture: authoritative snapshot materialized");
        let actual = Command::new(&git)
            .arg("--git-dir")
            .arg(snapshot.path())
            .args(["rev-parse", "refs/heads/main"])
            .output()
            .unwrap();
        assert!(actual.status.success());
        assert_eq!(String::from_utf8(actual.stdout).unwrap().trim(), ids["commit_oid"].as_str().unwrap());
        let remote = RemoteObjectStore::from_env(root.join("unused-local")).unwrap();
        let mut client = pool.get().await.unwrap();
        let weak = client.transaction().await.unwrap();
        assert!(
            Box::pin(backup::export_closure(&*weak, &remote, repo, &root.join("must-not-publish"), deadline()))
                .await
                .is_err()
        );
        weak.rollback().await.unwrap();
        let tx = client.transaction().await.unwrap();
        tx.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ").await.unwrap();
        let backup_dir = root.join(format!("backup-{}", Uuid::new_v4()));
        eprintln!("pando fixture: exporting encrypted backup closure");
        let backup_manifest =
            Box::pin(backup::export_closure(&*tx, &remote, repo, &backup_dir, deadline())).await.unwrap();
        eprintln!("pando fixture: backup closure exported");
        assert_eq!(backup_manifest.packs.len(), 1);
        assert_eq!(backup_manifest.refs["refs/heads/main"], ids["commit_oid"].as_str().unwrap());
        for artifact in [&manifest.pack, &manifest.index] {
            for (namespace, digest) in
                [("pando-cipher", &artifact.ciphertext_sha256), ("pando-envelope", &artifact.envelope_sha256)]
            {
                let key = ObjectKey::new(manifest.tenant_id, namespace, digest).unwrap();
                remote.delete(&key, deadline()).await.unwrap();
                assert!(remote.head(&key, deadline()).await.unwrap().is_none());
            }
        }
        eprintln!("pando fixture: remote test objects deleted");
        Box::pin(backup::import_closure(&*tx, &remote, repo, &backup_dir, deadline())).await.unwrap();
        eprintln!("pando fixture: backup closure imported");
        tx.commit().await.unwrap();
        let second = root.join("backup-restored");
        Box::pin(store.recover(&pool, repo, pack_id, &second, deadline())).await.unwrap();
        assert_eq!(
            std::fs::metadata(second.join(format!("pack-{pack_id}.pack"))).unwrap().len(),
            manifest.pack.plaintext_bytes
        );
        let client_work = root.join(format!("push-client-{}", Uuid::new_v4()));
        run(
            &git,
            ["clone", "--branch", "main", snapshot.path().to_str().unwrap(), client_work.to_str().unwrap()].as_slice(),
            &root,
        );
        std::fs::write(client_work.join("after.txt"), b"commit after Pando materialization\n").unwrap();
        run(&git, &["add", "after.txt"], &client_work);
        run(
            &git,
            &["-c", "user.name=Pack Test", "-c", "user.email=pack@test.invalid", "commit", "-m", "post-cutover-style"],
            &client_work,
        );
        run(&git, &["push", "origin", "HEAD:refs/heads/main"], &client_work);
        let prepared = Box::pin(prepare::stage(&state, &repository, manifest.tenant_id, &snapshot, &lease, deadline()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prepared.changes().len(), 1);
        assert_eq!(prepared.changes()[0].old_oid, ids["commit_oid"].as_str().unwrap());
        assert_ne!(prepared.changes()[0].new_oid, prepared.changes()[0].old_oid);
        let staged_pack = prepared.pack().expect("new ref target requires a pack");
        assert_eq!(staged_pack.object_format, format);
        // The newly staged pack must contain the entire reachable closure,
        // not merely the loose objects introduced by the latest receive.
        let staged_dir = root.join(format!("staged-pack-{}", Uuid::new_v4()));
        let bare_view = root.join(format!("staged-view-{}", Uuid::new_v4()));
        std::fs::create_dir(&bare_view).unwrap();
        run(&git, &["init", "--bare", &format_arg, "."], &bare_view);
        Box::pin(store.recover(&pool, repo, staged_pack.id, &staged_dir, deadline())).await.unwrap();
        let view_packs = bare_view.join("objects/pack");
        std::fs::copy(
            staged_dir.join(format!("pack-{}.pack", staged_pack.id)),
            view_packs.join(format!("pack-{}.pack", staged_pack.id)),
        )
        .unwrap();
        std::fs::copy(
            staged_dir.join(format!("pack-{}.idx", staged_pack.id)),
            view_packs.join(format!("pack-{}.idx", staged_pack.id)),
        )
        .unwrap();
        run(&git, &["update-ref", "refs/heads/main", &prepared.changes()[0].new_oid], &bare_view);
        run(&git, &["fsck", "--full", "--strict"], &bare_view);
        run(&git, &["update-ref", "refs/heads/main", ids["commit_oid"].as_str().unwrap()], snapshot.path());
        run(&git, &["update-ref", "refs/heads/copy", ids["commit_oid"].as_str().unwrap()], snapshot.path());
        let copied = Box::pin(prepare::stage(&state, &repository, manifest.tenant_id, &snapshot, &lease, deadline()))
            .await
            .unwrap()
            .unwrap();
        assert!(copied.pack().is_none(), "refs-only branch copy republished an unchanged pack");
        assert_eq!(copied.changes().len(), 1);
        assert_eq!(copied.changes()[0].ref_name, "refs/heads/copy");
        run(&git, &["update-ref", "-d", "refs/heads/copy"], snapshot.path());
        run(&git, &["update-ref", "-d", "refs/heads/main"], snapshot.path());
        let deleting = Box::pin(prepare::stage(&state, &repository, manifest.tenant_id, &snapshot, &lease, deadline()))
            .await
            .unwrap()
            .unwrap();
        assert!(deleting.pack().is_none());
        assert_eq!(deleting.changes().len(), 1);
        assert!(deleting.changes()[0].new_oid.bytes().all(|byte| byte == b'0'));
        run(&git, &["update-ref", "refs/heads/main", &prepared.changes()[0].new_oid], snapshot.path());
        drop(_local);
        let issued = db::issue_token(&pool, &repository.owner, false, false).await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", issued["token"].as_str().unwrap())).unwrap(),
        );
        let actor = auth::authenticate(&pool, &headers).await.unwrap();
        let ref_guard = storage::ref_publication::acquire(&pool, repo, 1, &["refs/heads/main".to_string()], deadline())
            .await
            .unwrap();
        let committed = Box::pin(publish::publish(
            &state,
            &repository,
            &actor,
            manifest.tenant_id,
            &snapshot,
            &prepared,
            prepared.changes(),
            &ref_guard,
            deadline(),
        ))
        .await
        .unwrap();
        assert_eq!(committed, 2);
        let row = pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT s.ref_generation,s.operation_sequence,
            s.pack_ids,r.oid FROM pando_repository_states s JOIN pando_refs r
            ON r.repository_id=s.repository_id WHERE s.repository_id=$1 AND r.ref_name='refs/heads/main'",
                &[&repo],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i64>(0), 2);
        assert_eq!(row.get::<_, i64>(1), 1);
        assert_eq!(row.get::<_, Vec<Uuid>>(2), vec![pack_id, staged_pack.id]);
        assert_eq!(row.get::<_, String>(3), prepared.changes()[0].new_oid);
        assert_eq!(
            pool.get()
                .await
                .unwrap()
                .query_one(
                    "SELECT count(*) FROM outbox_events
            WHERE repository_id=$1 AND ref_name='refs/heads/main'",
                    &[&repo]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            1
        );
        assert!(
            Box::pin(publish::publish(
                &state,
                &repository,
                &actor,
                manifest.tenant_id,
                &snapshot,
                &prepared,
                prepared.changes(),
                &ref_guard,
                deadline()
            ))
            .await
            .is_err()
        );
        drop(ref_guard);
        drop(snapshot);
        drop(lease);
        concurrent_views(state, repository).await;
    } else {
        panic!("unknown Pando test phase");
    }
}
