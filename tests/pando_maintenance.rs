//! Real PostgreSQL + Garage/Vault acceptance for automatic Pando maintenance.
//!
//! The test compacts a serving Pando pack set without pruning any object,
//! proves a packed object that no ref names survives, exercises automatic
//! threshold scheduling, cache hydration/eviction, duplicate wakeups and the
//! explicit refusal of remote object deletion.
use rootyard::{
    AppState,
    config::Config,
    db, dispatch, metrics,
    pando_gateway::{
        backup,
        pack_store::{PackManifest, PackStore},
        retention, snapshot, transition,
    },
    storage::{
        self, read_leases,
        remote_objects::{ObjectKey, RemoteObjectStore},
    },
    storage_lifecycle::{jobs, models::Policy, scheduler, worker},
};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;
use tokio::time::Instant;
use uuid::Uuid;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(300)
}

fn run(git: &Path, args: &[&str], cwd: &Path) {
    let status = Command::new(git).args(args).current_dir(cwd).status().unwrap();
    assert!(status.success(), "Git fixture command failed: {args:?}");
}

fn output(git: &Path, args: &[&str], cwd: &Path) -> Vec<u8> {
    let out = Command::new(git).args(args).current_dir(cwd).output().unwrap();
    assert!(out.status.success(), "Git fixture command failed: {args:?}");
    out.stdout
}

fn config(root: &Path, git: &Path) -> Config {
    Config {
        database_url: std::env::var("ROOTYARD_TEST_DATABASE_URL").unwrap(),
        data_dir: root.join("server-data"),
        bind: "127.0.0.1:0".parse().unwrap(),
        git: git.to_owned(),
        max_request_bytes: 128 * 1024 * 1024,
        max_output_bytes: 128 * 1024 * 1024,
        max_concurrent_git: 2,
        git_timeout: Duration::from_secs(120),
        git_memory_bytes: 1024 * 1024 * 1024,
        max_repo_bytes: 1024 * 1024 * 1024,
        max_pending_deliveries: 10000,
        outbox_worker: false,
        metrics_bind: None,
    }
}

async fn fixture(pool: &deadpool_postgres::Pool) -> (Uuid, Uuid, String) {
    let owner = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let slug = format!("p{}", &owner.simple().to_string()[..12]);
    let client = pool.get().await.unwrap();
    client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&owner, &slug]).await.unwrap();
    client
        .execute(
            "INSERT INTO repositories(id,owner_id,name,state,object_format,storage_generation) \
             VALUES($1,$2,'pando-maint','ready','sha1',1)",
            &[&repo, &owner],
        )
        .await
        .unwrap();
    (repo, owner, slug)
}

fn seed_bare(git: &Path, bare: &Path, work: &Path) -> String {
    std::fs::create_dir_all(bare).unwrap();
    run(git, &["init", "--bare", "--object-format=sha1", "."], bare);
    std::fs::create_dir_all(work).unwrap();
    run(git, &["init", "--object-format=sha1", "."], work);
    std::fs::write(work.join("README.md"), b"retained Pando root\n").unwrap();
    run(git, &["add", "README.md"], work);
    run(git, &["-c", "user.name=Pando", "-c", "user.email=pando@test.invalid", "commit", "-m", "root"], work);
    run(git, &["push", bare.to_str().unwrap(), "HEAD:refs/heads/main"], work);
    run(git, &["symbolic-ref", "HEAD", "refs/heads/main"], bare);
    String::from_utf8(output(git, &["rev-parse", "HEAD"], work)).unwrap().trim().to_owned()
}

fn hash_object(git: &Path, bare: &Path, payload: &[u8]) -> String {
    let mut child = Command::new(git)
        .args(["--git-dir", bare.to_str().unwrap(), "hash-object", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(payload).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn pack_one(git: &Path, bare: &Path, oid: &str) -> PathBuf {
    let prefix = bare.join(format!("orphan-{}", Uuid::new_v4()));
    let mut child = Command::new(git)
        .args(["--git-dir", bare.to_str().unwrap(), "pack-objects", "-q"])
        .arg(&prefix)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.as_mut().unwrap(), "{oid}").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let hash = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    let pack = PathBuf::from(format!("{}-{hash}.pack", prefix.display()));
    assert!(pack.is_file() && pack.with_extension("idx").is_file());
    pack
}

fn repository(id: Uuid, owner: &str, backend: &str) -> db::Repository {
    db::Repository {
        id,
        name: "pando-maint".into(),
        owner: owner.into(),
        state: "ready".into(),
        clone_path: format!("/git/{owner}/pando-maint.git"),
        storage_backend: backend.into(),
        storage_generation: 1,
        object_format: "sha1".into(),
    }
}

async fn drain(state: &Arc<AppState>, policy: &Policy) {
    for _ in 0..32 {
        match worker::run_once(state, policy, Uuid::new_v4()).await.unwrap() {
            Some(_) => {}
            None => return,
        }
    }
    panic!("maintenance worker did not reach an empty queue");
}

#[tokio::test]
async fn automatic_pando_compaction_preserves_all_packed_objects() {
    if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_none()
        || std::env::var_os("ROOTYARD_KMS_VAULT_URL").is_none()
        || std::env::var_os("ROOTYARD_PANDO_TEST_ROOT").is_none()
        || std::env::var_os("ROOTYARD_TEST_DATABASE_URL").is_none()
    {
        eprintln!("pando maintenance fixture skipped: remote object/Vault/DB environment absent");
        return;
    }
    let root = PathBuf::from(std::env::var("ROOTYARD_PANDO_TEST_ROOT").unwrap())
        .join(format!("maintenance-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let git = PathBuf::from(std::env::var("ROOTYARD_GIT_PATH").unwrap_or_else(|_| "/usr/bin/git".into()));
    let config = config(&root, &git);
    let pool = db::pool(&config.database_url).unwrap();
    db::migrate(&pool).await.unwrap();
    // This is a role-private disposable database; retire any interrupted job
    // from an earlier failed run before exercising the global claim path.
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE storage_maintenance_jobs SET state='failed',lease_owner=NULL,lease_until=NULL, \
         completed_at=clock_timestamp(),updated_at=clock_timestamp(), \
         last_error='retired by pando maintenance fixture' \
         WHERE state IN ('queued','running')",
            &[],
        )
        .await
        .unwrap();
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
    let (repo, owner, slug) = fixture(&pool).await;
    let bare = state.storage.repo_path(repo);
    let work = root.join("work");
    let root_oid = seed_bare(&git, &bare, &work);
    run(&git, &["config", "rootyard.repositoryId", &repo.to_string()], &bare);
    let gitfs = repository(repo, &slug, "gitfs");
    let report = transition::cutover(&state, &gitfs, deadline()).await.unwrap();
    assert_eq!(report.packs, 1);

    // Add a real packed object that no ref names. SQL retention roots cannot be
    // represented by Pando's ref-only snapshot; compaction must preserve it
    // from the existing pack set regardless of reachability.
    let orphan = hash_object(&git, &bare, b"retained only by durable SQL pin\n");
    let orphan_pack = pack_one(&git, &bare, &orphan);
    let store = PackStore::from_env(state.storage.root.join("pando-pack-work"), git.clone()).unwrap();
    let extra = Box::pin(store.publish(
        &pool,
        repo,
        owner,
        1,
        "sha1",
        &orphan_pack,
        &orphan_pack.with_extension("idx"),
        deadline(),
    ))
    .await
    .unwrap();
    let client = pool.get().await.unwrap();
    client
        .execute(
            "UPDATE pando_repository_states SET pack_ids=array_append(pack_ids,$2) WHERE repository_id=$1",
            &[&repo, &extra.id],
        )
        .await
        .unwrap();
    let before_packs: i32 = client
        .query_one("SELECT cardinality(pack_ids) FROM pando_repository_states WHERE repository_id=$1", &[&repo])
        .await
        .unwrap()
        .get(0);
    assert_eq!(before_packs, 2);
    let before_manifests: i64 = client
        .query_one("SELECT count(*) FROM pando_pack_manifests WHERE repository_id=$1", &[&repo])
        .await
        .unwrap()
        .get(0);

    // A paired backup taken before compaction must keep its own byte-identical
    // copy of every pack, independent of later remote GC.
    let remote = RemoteObjectStore::from_env(root.join("pando-pack-work")).unwrap();
    let backup_dir = root.join("pre-compaction-backup");
    let mut backup_client = pool.get().await.unwrap();
    let backup_tx = backup_client.transaction().await.unwrap();
    backup_tx.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ").await.unwrap();
    let exported = Box::pin(backup::export_closure(&*backup_tx, &remote, repo, &backup_dir, deadline())).await.unwrap();
    assert!(exported.packs.len() >= 2, "backup must capture the whole serving closure");
    let backed_up_old_cipher =
        backup_dir.join(ObjectKey::new(owner, "pando-cipher", &extra.pack.ciphertext_sha256).unwrap().volume_path());
    assert!(backed_up_old_cipher.is_file(), "backup did not copy the old pack ciphertext");
    backup_tx.commit().await.unwrap();

    let policy = Policy {
        enabled: true,
        poll: Duration::from_secs(1),
        lease_seconds: 5,
        loose_threshold: 1,
        pack_threshold: 2,
        stage_age_seconds: 1,
        cache_max_age_seconds: 60,
        tombstone_grace_seconds: 1,
        scan_period_seconds: 1,
        quiescence_seconds: 1,
        max_attempts: 3,
    };
    let scheduled = scheduler::schedule_once(&state, &policy).await.unwrap();
    assert!(scheduled >= 2, "automatic Pando threshold did not schedule work: {scheduled}");
    assert!(
        !jobs::enqueue(&pool, repo, owner, 1, "pando_repack").await.unwrap(),
        "duplicate Pando wakeup bypassed the active-kind unique index"
    );
    let active_repack: i64 = client
        .query_one(
            "SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id=$1 AND kind='pando_repack' AND state IN ('queued','running')",
            &[&repo],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(active_repack, 1);
    drain(&state, &policy).await;

    let pando = client
        .query_one(
            "SELECT r.storage_backend,r.storage_generation,s.ref_generation,s.pack_ids,s.head_ref \
             FROM repositories r JOIN pando_repository_states s ON s.repository_id=r.id WHERE r.id=$1",
            &[&repo],
        )
        .await
        .unwrap();
    let after_packs: Vec<Uuid> = pando.get("pack_ids");
    assert_eq!(after_packs.len(), 1, "compaction must commit one complete pack closure");
    assert!(!after_packs.contains(&extra.id), "old pack ids must be replaced only after object-set proof");
    assert_eq!(pando.get::<_, i64>("ref_generation"), 1);
    let refs: String = client
        .query_one("SELECT oid FROM pando_refs WHERE repository_id=$1 AND ref_name='refs/heads/main'", &[&repo])
        .await
        .unwrap()
        .get(0);
    assert_eq!(refs, root_oid);
    let after_manifests: i64 = client
        .query_one("SELECT count(*) FROM pando_pack_manifests WHERE repository_id=$1", &[&repo])
        .await
        .unwrap()
        .get(0);
    assert_eq!(after_manifests, before_manifests + 1, "old manifests and remote bytes must be retained");
    let repack_result: serde_json::Value = client
        .query_one(
            "SELECT result FROM storage_maintenance_jobs WHERE repository_id=$1 AND kind='pando_repack' AND state='succeeded' ORDER BY completed_at DESC LIMIT 1",
            &[&repo],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(repack_result["new_packs"].as_i64(), Some(1));
    assert_eq!(repack_result["old_pack_manifests_retained"].as_bool(), Some(true));

    // A fresh serving snapshot must still resolve both the ref root and the
    // unreachable packed object. This is the decisive non-pruning oracle.
    let lease = read_leases::shared(&pool, repo, deadline()).await.unwrap();
    let view =
        Box::pin(snapshot::materialize(&state, &repository(repo, &slug, "pando"), &lease, deadline())).await.unwrap();
    let status = Command::new(&git)
        .args(["--git-dir", view.path().to_str().unwrap(), "cat-file", "-e", &orphan])
        .status()
        .unwrap();
    assert!(status.success(), "compaction dropped an object retained outside refs");
    let status = Command::new(&git)
        .args(["--git-dir", view.path().to_str().unwrap(), "cat-file", "-e", &root_oid])
        .status()
        .unwrap();
    assert!(status.success());
    drop(view);
    drop(lease);

    // Hydration may have raced ahead of compaction on the first pass. One
    // scheduler interval must repair the new closure automatically.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    scheduler::schedule_once(&state, &policy).await.unwrap();
    drain(&state, &policy).await;
    let cache_dir = PackStore::cache_dir(&state.storage.root, repo);
    let new_pack = after_packs[0];
    let cached_pack = cache_dir.join(format!("pack-{new_pack}.pack"));
    let cached_index = cache_dir.join(format!("pack-{new_pack}.idx"));
    assert!(cached_pack.is_file() && cached_index.is_file(), "automatic hydration missed compacted pack");

    // Same-length cache corruption must never become a serving snapshot. The
    // cache is not authority; a manifest-digest mismatch falls back to exact
    // remote recovery and repairs both files.
    let good_pack = std::fs::read(&cached_pack).unwrap();
    let good_index = std::fs::read(&cached_index).unwrap();
    for path in [&cached_pack, &cached_index] {
        let mut corrupt = std::fs::read(path).unwrap();
        let offset = corrupt.len() / 2;
        corrupt[offset] ^= 0xff;
        std::fs::write(path, &corrupt).unwrap();
        let lease = read_leases::shared(&pool, repo, deadline()).await.unwrap();
        let view = Box::pin(snapshot::materialize(&state, &repository(repo, &slug, "pando"), &lease, deadline()))
            .await
            .unwrap();
        assert!(
            Command::new(&git)
                .args(["--git-dir", view.path().to_str().unwrap(), "cat-file", "-e", &orphan])
                .status()
                .unwrap()
                .success()
        );
        drop(view);
        drop(lease);
    }
    assert_eq!(std::fs::read(&cached_pack).unwrap(), good_pack, "corrupt cache pack was not rebuilt");
    assert_eq!(std::fs::read(&cached_index).unwrap(), good_index, "corrupt cache index was not rebuilt");

    // Age both cache files, then let the automatic retention probe evict them.
    for path in [&cached_pack, &cached_index] {
        let status = Command::new("touch").args(["-d", "2 hours ago"]).arg(path).status().unwrap();
        assert!(status.success());
    }
    tokio::time::sleep(Duration::from_millis(1100)).await;
    scheduler::schedule_once(&state, &policy).await.unwrap();
    drain(&state, &policy).await;
    assert!(!cached_pack.exists() && !cached_index.exists(), "automatic cache eviction did not remove an expired pair");
    assert_eq!(
        client
            .query_one("SELECT count(*) FROM pando_pack_manifests WHERE repository_id=$1", &[&repo])
            .await
            .unwrap()
            .get::<_, i64>(0),
        after_manifests,
        "cache eviction touched remote manifests"
    );

    // A missing cache is repairable automatically and never changes authority.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    scheduler::schedule_once(&state, &policy).await.unwrap();
    drain(&state, &policy).await;
    assert!(cached_pack.is_file() && cached_index.is_file(), "automatic rehydration did not restore the cache pair");

    // The global backup/migration advisory barrier precedes any Pando pack
    // publication. A held exclusive barrier leaves the durable job retryable.
    let before_barrier: Vec<Uuid> = client
        .query_one("SELECT pack_ids FROM pando_repository_states WHERE repository_id=$1", &[&repo])
        .await
        .unwrap()
        .get(0);
    client
        .execute(
            "INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,repository_generation)              VALUES($1,$2,$3,'pando_repack',1)",
            &[&Uuid::new_v4(), &repo, &owner],
        )
        .await
        .unwrap();
    let mut blocker = pool.get().await.unwrap();
    let tx = blocker.transaction().await.unwrap();
    tx.execute("SELECT pg_advisory_xact_lock(738390103)", &[]).await.unwrap();
    let blocked = worker::run_once(&state, &policy, Uuid::new_v4()).await.unwrap().unwrap();
    assert_eq!(blocked.state, "queued", "backup barrier did not leave the Pando job retryable");
    assert_eq!(
        client
            .query_one("SELECT pack_ids FROM pando_repository_states WHERE repository_id=$1", &[&repo])
            .await
            .unwrap()
            .get::<_, Vec<Uuid>>(0),
        before_barrier,
        "Pando pack authority changed while the backup barrier was held"
    );
    tx.rollback().await.unwrap();
    drop(blocker);
    tokio::time::sleep(Duration::from_millis(2200)).await;
    drain(&state, &policy).await;
    assert!(
        client
            .query_one(
                "SELECT count(*) FROM storage_maintenance_jobs WHERE repository_id=$1 AND kind='pando_repack' AND state IN ('queued','running')",
                &[&repo],
            )
            .await
            .unwrap()
            .get::<_, i64>(0)
            == 0
    );

    // Old unreferenced packs stay recoverable until a destructive stage is
    // explicitly enabled and has retired them after proof.
    for old in [after_packs[0], extra.id] {
        let destination = root.join(format!("recovery-{old}"));
        Box::pin(store.recover(&pool, repo, old, &destination, deadline())).await.unwrap();
        assert!(destination.join(format!("pack-{old}.pack")).is_file());
    }

    // A stale DB deleter must not be able to finalize the old claim once the
    // same content address has been resurrected onto a fresh generation path.
    let old_manifest: PackManifest = {
        let value: serde_json::Value = client
            .query_one(
                "SELECT manifest FROM pando_pack_manifests WHERE repository_id=$1 AND NOT (id = ANY($2::uuid[])) ORDER BY created_at LIMIT 1",
                &[&repo, &after_packs],
            )
            .await
            .unwrap()
            .get(0);
        serde_json::from_value(value).unwrap()
    };
    let old_row = client
        .query_one(
            "SELECT authority_id,object_generation,remote_path,claim_generation FROM pando_remote_artifacts              WHERE tenant_id=$1 AND namespace='pando-cipher' AND sha256=$2",
            &[&owner, &old_manifest.pack.ciphertext_sha256],
        )
        .await
        .unwrap();
    let old_authority: Uuid = old_row.get(0);
    let old_generation: i64 = old_row.get(1);
    let old_path: String = old_row.get(2);
    let old_claim: i64 = old_row.get(3);
    let (cipher_slot, _envelope_slot) = {
        let mut reserve_client = pool.get().await.unwrap();
        let reserve_tx = reserve_client.transaction().await.unwrap();
        let pair = retention::reserve_pair(
            &*reserve_tx,
            owner,
            &old_manifest.pack.ciphertext_sha256,
            &old_manifest.pack.envelope_sha256,
        )
        .await
        .unwrap();
        reserve_tx.commit().await.unwrap();
        pair
    };
    let new_scoped = cipher_slot.key().path();
    assert_ne!(new_scoped, old_path, "resurrection reused the stale deletable path");
    assert!(!new_scoped.contains(&format!("/g{old_generation}/")));
    let stale = client
        .execute(
            "UPDATE pando_remote_artifacts SET state='deleted'              WHERE authority_id=$1 AND tenant_id=$2 AND namespace='pando-cipher' AND sha256=$3                AND state='deleting' AND claimed_by=$4 AND claim_generation=$5 AND remote_path=$6",
            &[&old_authority, &owner, &old_manifest.pack.ciphertext_sha256, &Uuid::new_v4(), &old_claim, &old_path],
        )
        .await
        .unwrap();
    assert_eq!(stale, 0, "stale claim finalized after resurrection");
    assert_eq!(
        client
            .query_one(
                "SELECT count(*) FROM pando_remote_artifacts WHERE authority_id=$1 AND tenant_id=$2                  AND namespace='pando-cipher' AND sha256=$3 AND state='reserved' AND remote_path=$4",
                &[&old_authority, &owner, &old_manifest.pack.ciphertext_sha256, &new_scoped],
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );

    // Destructive deletion is a separate, proof-gated stage. Without the
    // explicit operator enable it must succeed as a measured dry run and must
    // not remove any bytes.
    client
        .execute(
            "INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,repository_generation)              VALUES($1,$2,$3,'pando_tombstone_delete',1)",
            &[&Uuid::new_v4(), &repo, &owner],
        )
        .await
        .unwrap();
    worker::run_once(&state, &policy, Uuid::new_v4()).await.unwrap();
    let refused = client
        .query_one(
            "SELECT state,result FROM storage_maintenance_jobs WHERE repository_id=$1 AND kind='pando_tombstone_delete' ORDER BY created_at DESC LIMIT 1",
            &[&repo],
        )
        .await
        .unwrap();
    assert_eq!(refused.get::<_, String>(0), "succeeded");
    let result: serde_json::Value = refused.get(1);
    assert_eq!(result["remote_deleted"].as_bool(), Some(false));
    assert_eq!(result["dry_run"].as_bool(), Some(true));

    // An unregistered legacy tenant-only object is permanently protected.
    let legacy_bytes = b"legacy tenant-only pando ciphertext";
    let legacy_sha = hex::encode(Sha256::digest(legacy_bytes));
    let legacy_file = root.join("legacy.bin");
    std::fs::write(&legacy_file, legacy_bytes).unwrap();
    let legacy_key = ObjectKey::new(owner, "pando-cipher", &legacy_sha).unwrap();
    remote.put_file(&legacy_key, &legacy_file, legacy_bytes.len() as u64, deadline()).await.unwrap();

    // Collect the still-retired index artifacts that are eligible and verify
    // their current generation paths exist before the destructive run.
    let retired = client
        .query(
            "SELECT a.authority_id,a.object_generation,a.namespace,a.sha256,a.remote_path              FROM pando_remote_artifacts a              JOIN pando_manifest_artifacts l ON l.authority_id=a.authority_id AND l.tenant_id=a.tenant_id                AND l.namespace=a.namespace AND l.sha256=a.sha256 
             WHERE l.repository_id=$1 AND a.state='retired' ORDER BY a.namespace,a.sha256",
            &[&repo],
        )
        .await
        .unwrap();
    assert!(!retired.is_empty(), "mark stage retired no unreferenced artifact");
    let mut retired_keys = Vec::new();
    for row in &retired {
        let authority: Uuid = row.get(0);
        let generation: i64 = row.get(1);
        let namespace: String = row.get(2);
        let sha: String = row.get(3);
        let path: String = row.get(4);
        let key = ObjectKey::scoped(owner, authority, generation, &namespace, &sha).unwrap();
        assert_eq!(key.path(), path);
        assert!(remote.head(&key, deadline()).await.unwrap().is_some());
        retired_keys.push(key);
    }
    unsafe { std::env::set_var("ROOTYARD_PANDO_REMOTE_DELETE", "true") };
    tokio::time::sleep(Duration::from_millis(1200)).await;
    client
        .execute(
            "INSERT INTO storage_maintenance_jobs(id,repository_id,tenant_id,kind,repository_generation)              VALUES($1,$2,$3,'pando_tombstone_delete',1)",
            &[&Uuid::new_v4(), &repo, &owner],
        )
        .await
        .unwrap();
    worker::run_once(&state, &policy, Uuid::new_v4()).await.unwrap();
    let deleted = client
        .query_one(
            "SELECT result FROM storage_maintenance_jobs WHERE repository_id=$1 AND kind='pando_tombstone_delete'              ORDER BY created_at DESC LIMIT 1",
            &[&repo],
        )
        .await
        .unwrap();
    let deleted: serde_json::Value = deleted.get(0);
    assert_eq!(deleted["remote_deleted"].as_bool(), Some(true));
    assert!(deleted["deleted"].as_u64().unwrap() >= 1, "no eligible ciphertext was removed: {deleted}");
    for key in &retired_keys {
        assert!(remote.head(key, deadline()).await.unwrap().is_none(), "eligible ciphertext survived deletion");
    }
    // Serving pack bytes and the unregistered legacy object must survive.
    let serving_sha: String = client
        .query_one(
            "SELECT manifest->'pack'->>'ciphertext_sha256' FROM pando_pack_manifests WHERE repository_id=$1 AND id=$2",
            &[&repo, &after_packs[0]],
        )
        .await
        .unwrap()
        .get(0);
    let serving = retention::resolve_artifact(&**client, owner, "pando-cipher", &serving_sha).await.unwrap();
    if serving.registered {
        assert!(remote.head(&serving.key, deadline()).await.unwrap().is_some());
    }
    assert!(remote.head(&legacy_key, deadline()).await.unwrap().is_some(), "legacy object was deleted");
    assert!(backed_up_old_cipher.is_file(), "paired backup bytes changed during remote GC");
    unsafe { std::env::remove_var("ROOTYARD_PANDO_REMOTE_DELETE") };
    eprintln!("pando maintenance fixture: compaction/cache/backup/delete/resurrection acceptance complete");
}
