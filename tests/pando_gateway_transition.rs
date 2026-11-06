//! Two-phase Pando cutover/rollback and durable transition-fence tests.
//!
//! The full round-trip needs PostgreSQL, the remote object store and Vault
//! Transit, exactly like the production Pando pack tests. The fence-admission
//! test only needs PostgreSQL. Both skip when their environment is absent.
use axum::http::StatusCode;
use rootyard::{
    AppState,
    config::Config,
    db, dispatch, journal, metrics,
    pando_gateway::transition,
    storage::{self, read_leases, ref_publication},
};
use std::{path::Path, process::Command, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tokio::time::Instant;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(300)
}

fn run(git: &Path, args: &[&str], cwd: &Path) {
    let status = Command::new(git).args(args).current_dir(cwd).status().unwrap();
    assert!(status.success(), "Git fixture command failed: {args:?}");
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

async fn fixture(pool: &deadpool_postgres::Pool, name: &str) -> (uuid::Uuid, uuid::Uuid, String) {
    let owner = uuid::Uuid::new_v4();
    let repo = uuid::Uuid::new_v4();
    let slug = format!("t{}", &owner.simple().to_string()[..12]);
    let client = pool.get().await.unwrap();
    client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&owner, &slug]).await.unwrap();
    client
        .execute("INSERT INTO namespaces(id,slug,kind,user_id) VALUES($1,$2,'user',$1)", &[&owner, &slug])
        .await
        .unwrap();
    client
        .execute("INSERT INTO repositories(id,owner_id,name,state) VALUES($1,$2,$3,'ready')", &[&repo, &owner, &name])
        .await
        .unwrap();
    (repo, owner, slug)
}

async fn seed_bare(git: &Path, bare: &Path, work: &Path, format_arg: &str) -> String {
    std::fs::create_dir_all(bare).unwrap();
    run(git, &["init", "--bare", format_arg, "."], bare);
    std::fs::create_dir_all(work).unwrap();
    run(git, &["init", format_arg, "."], work);
    std::fs::write(work.join("README.md"), b"pando cutover fixture\n").unwrap();
    run(git, &["add", "README.md"], work);
    run(git, &["-c", "user.name=Cutover", "-c", "user.email=cutover@test.invalid", "commit", "-m", "initial"], work);
    run(git, &["push", bare.to_str().unwrap(), "HEAD:refs/heads/main"], work);
    run(git, &["symbolic-ref", "HEAD", "refs/heads/main"], bare);
    let output = Command::new(git).args(["rev-parse", "HEAD"]).current_dir(work).output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn repository(id: uuid::Uuid, owner: &str, backend: &str) -> db::Repository {
    db::Repository {
        id,
        name: "transition".into(),
        owner: owner.into(),
        state: "ready".into(),
        clone_path: format!("/git/{owner}/transition.git"),
        storage_backend: backend.into(),
        storage_generation: 1,
        object_format: "sha1".into(),
    }
}

#[tokio::test]
async fn draining_fence_rejects_concurrent_write_admission() {
    let Ok(url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else { return };
    let pool = db::pool(&url).unwrap();
    db::migrate(&pool).await.unwrap();
    let (repo, _owner, _slug) = fixture(&pool, "fence").await;
    let client = pool.get().await.unwrap();
    let transition_id = uuid::Uuid::new_v4();
    client
        .execute(
            "UPDATE repositories SET transition_state='draining',transition_id=$2, \
            transition_started_at=clock_timestamp(),backend_transition_epoch=1 WHERE id=$1",
            &[&repo, &transition_id],
        )
        .await
        .unwrap();
    // A write admitted during the draining fence is rejected before it can
    // acquire a native ref guard or touch pack state.
    assert!(transition::admit_write(&pool, repo, "gitfs").await.is_err());
    let refs = ["refs/heads/main".to_string()];
    assert!(ref_publication::acquire(&pool, repo, 1, &refs, deadline()).await.is_err());
    // A generation-only change is not enough to bypass the fence.
    client.execute("UPDATE repositories SET storage_generation=2 WHERE id=$1", &[&repo]).await.unwrap();
    assert!(transition::admit_write(&pool, repo, "gitfs").await.is_err());
    client
        .execute(
            "UPDATE repositories SET transition_state='stable',transition_id=NULL, \
            transition_started_at=NULL,storage_generation=1 WHERE id=$1",
            &[&repo],
        )
        .await
        .unwrap();
    transition::admit_write(&pool, repo, "gitfs").await.unwrap();
    let _lease = read_leases::shared(&pool, repo, deadline()).await.unwrap();
}

#[tokio::test]
async fn cutover_rollback_round_trip_and_durable_failure() {
    if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_none()
        || std::env::var_os("ROOTYARD_KMS_VAULT_URL").is_none()
        || std::env::var_os("ROOTYARD_PANDO_TEST_ROOT").is_none()
        || std::env::var_os("ROOTYARD_TEST_DATABASE_URL").is_none()
    {
        return;
    }
    let root = std::path::PathBuf::from(std::env::var("ROOTYARD_PANDO_TEST_ROOT").unwrap())
        .join(format!("transition-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let git = std::path::PathBuf::from(std::env::var("ROOTYARD_GIT_PATH").unwrap_or_else(|_| "/usr/bin/git".into()));
    let config = config(&root, &git);
    let pool = db::pool(&config.database_url).unwrap();
    db::migrate(&pool).await.unwrap();
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
    let (repo, _owner, slug) = fixture(&pool, "transition").await;
    let bare = state.storage.repo_path(repo);
    let work = root.join("work");
    let oid = seed_bare(&git, &bare, &work, "--object-format=sha1").await;
    run(&git, &["config", "rootyard.repositoryId", &repo.to_string()], &bare);
    let client = pool.get().await.unwrap();
    client.execute("UPDATE repositories SET object_format='sha1' WHERE id=$1", &[&repo]).await.unwrap();

    let token = uuid::Uuid::new_v4();
    client
        .execute(
            "INSERT INTO tokens(id,user_id,digest,read_only) VALUES($1,$2,$3,false)",
            &[&token, &_owner, &vec![0u8; 32]],
        )
        .await
        .unwrap();
    let actor = _owner;
    client
        .execute(
            "INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,storage_generation,evidence,outcome)             VALUES($1,$2,$3,$4,$5,5,1,'{}','recorded')",
            &[&uuid::Uuid::new_v4(), &repo, &actor, &token, &slug],
        )
        .await
        .unwrap();
    let gitfs = repository(repo, &slug, "gitfs");
    let report = transition::cutover(&state, &gitfs, deadline()).await.unwrap();
    let pando_sequence: i64 = client
        .query_one("SELECT operation_sequence FROM pando_repository_states WHERE repository_id=$1", &[&repo])
        .await
        .unwrap()
        .get(0);
    assert_eq!(pando_sequence, 5, "cutover must carry the durable operation high-water mark");
    assert!(journal::sequence(&state.storage.root, repo).unwrap() >= 5, "local journal must not lag shared sequences");
    assert_eq!(report.direction, "gitfs_to_pando");
    assert_eq!(report.transition_epoch, 1);
    assert_eq!(report.refs, 1);
    assert_eq!(report.packs, 1);
    let row = client
        .query_one(
            "SELECT storage_backend,transition_state,backend_transition_epoch,transition_id \
            FROM repositories WHERE id=$1",
            &[&repo],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "pando");
    assert_eq!(row.get::<_, String>(1), "stable");
    assert_eq!(row.get::<_, i64>(2), 1);
    assert_eq!(row.get::<_, Option<uuid::Uuid>>(3), None);
    let pando = client
        .query_one(
            "SELECT s.state,s.head_ref,s.pack_ids,r.oid FROM pando_repository_states s \
            JOIN pando_refs r ON r.repository_id=s.repository_id \
            WHERE s.repository_id=$1 AND r.ref_name='refs/heads/main'",
            &[&repo],
        )
        .await
        .unwrap();
    assert_eq!(pando.get::<_, String>(0), "serving");
    assert_eq!(pando.get::<_, String>(1), "refs/heads/main");
    assert_eq!(pando.get::<_, Vec<uuid::Uuid>>(2).len(), 1);
    assert_eq!(pando.get::<_, String>(3), oid);
    // The fence keeps rejecting writes while the draining state is durable.
    client
        .execute(
            "UPDATE repositories SET transition_state='draining',transition_id=$2, \
            transition_started_at=clock_timestamp() WHERE id=$1",
            &[&repo, &uuid::Uuid::new_v4()],
        )
        .await
        .unwrap();
    assert!(transition::admit_write(&pool, repo, "pando").await.is_err());
    client
        .execute(
            "UPDATE repositories SET transition_state='stable',transition_id=NULL,transition_started_at=NULL WHERE id=$1",
            &[&repo],
        )
        .await
        .unwrap();

    // A Pando-era operation advances the shared namespace without touching the
    // local journal counter; rollback must reseed it before restoring GitFS.
    client
        .execute(
            "INSERT INTO git_operations(id,repository_id,actor_id,token_id,actor_name,sequence,storage_generation,evidence,outcome)             VALUES($1,$2,$3,$4,$5,6,1,'{}','recorded')",
            &[&uuid::Uuid::new_v4(), &repo, &actor, &token, &slug],
        )
        .await
        .unwrap();

    // A stale advertised HEAD is a parity failure: the durable fence records it
    // and leaves GitFS authority unchanged.
    client
        .execute("UPDATE pando_repository_states SET head_ref='refs/heads/missing' WHERE repository_id=$1", &[&repo])
        .await
        .unwrap();
    let pando = repository(repo, &slug, "pando");
    assert!(transition::rollback(&state, &pando, deadline()).await.is_err());
    let failed = client
        .query_one("SELECT transition_state,transition_error FROM repositories WHERE id=$1", &[&repo])
        .await
        .unwrap();
    assert_eq!(failed.get::<_, String>(0), "failed");
    assert!(failed.get::<_, Option<String>>(1).is_some());

    // The failed fence is durable but retryable after repairing the snapshot.
    client
        .execute("UPDATE pando_repository_states SET head_ref='refs/heads/main' WHERE repository_id=$1", &[&repo])
        .await
        .unwrap();
    let report = transition::rollback(&state, &pando, deadline()).await.unwrap();
    assert_eq!(report.direction, "pando_to_gitfs");
    assert_eq!(report.transition_epoch, 2);
    assert_eq!(report.refs, 1);
    let row = client
        .query_one(
            "SELECT storage_backend,transition_state,backend_transition_epoch \
            FROM repositories WHERE id=$1",
            &[&repo],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "gitfs");
    assert_eq!(row.get::<_, String>(1), "stable");
    assert_eq!(row.get::<_, i64>(2), 2);
    assert!(
        journal::sequence(&state.storage.root, repo).unwrap() >= 6,
        "rollback must carry the shared Pando operation sequences back to GitFS"
    );
    let pando = client
        .query_one("SELECT state,head_ref FROM pando_repository_states WHERE repository_id=$1", &[&repo])
        .await
        .unwrap();
    assert_eq!(pando.get::<_, String>(0), "rollback");
    run(&git, &["fsck", "--full", "--strict"], &bare);
    let observed = Command::new(&git)
        .args(["--git-dir", bare.to_str().unwrap(), "for-each-ref", "--format=%(refname) %(objectname)"])
        .output()
        .unwrap();
    assert!(observed.status.success());
    assert_eq!(String::from_utf8(observed.stdout).unwrap().trim(), format!("refs/heads/main {oid}"));
    let head = Command::new(&git).args(["--git-dir", bare.to_str().unwrap(), "symbolic-ref", "HEAD"]).output().unwrap();
    assert_eq!(String::from_utf8(head.stdout).unwrap().trim(), "refs/heads/main");
}

#[tokio::test]
async fn gitfs_write_admission_rejects_backend_switch_and_transition_fence() {
    let Ok(url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else { return };
    let pool = db::pool(&url).unwrap();
    db::migrate(&pool).await.unwrap();
    let (repo, owner, _slug) = fixture(&pool, "gitfs-admission").await;
    let config = Config {
        database_url: url,
        data_dir: std::env::temp_dir().join(format!("rootyard-gitfs-admission-{}", uuid::Uuid::new_v4())),
        bind: "127.0.0.1:0".parse().unwrap(),
        git: std::path::PathBuf::from("/usr/bin/git"),
        max_request_bytes: 1024,
        max_output_bytes: 1024,
        max_concurrent_git: 1,
        git_timeout: Duration::from_secs(5),
        git_memory_bytes: 1024 * 1024,
        max_repo_bytes: 1024 * 1024,
        max_pending_deliveries: 10,
        outbox_worker: false,
        metrics_bind: None,
    };
    let state = AppState {
        mirror_primary: None,
        dispatch: dispatch::Signals::default(),
        storage: storage::Storage::open(&config).unwrap(),
        config,
        pool: pool.clone(),
        hooks: None,
        transfer_metrics: Arc::new(metrics::TransferCounters::default()),
        git_slots: Arc::new(Semaphore::new(1)),
    };
    let repo = repository(repo, &_slug, "gitfs");
    rootyard::reliability::ensure_gitfs_current(&state, &repo).await.unwrap();
    pool.get()
        .await
        .unwrap()
        .execute("UPDATE repositories SET storage_backend='pando' WHERE id=$1", &[&repo.id])
        .await
        .unwrap();
    assert_eq!(rootyard::reliability::ensure_gitfs_current(&state, &repo).await.unwrap_err().0, StatusCode::CONFLICT);
    pool.get()
        .await
        .unwrap()
        .execute("UPDATE repositories SET storage_backend='gitfs',transition_state='draining' WHERE id=$1", &[&repo.id])
        .await
        .unwrap();
    assert_eq!(rootyard::reliability::ensure_gitfs_current(&state, &repo).await.unwrap_err().0, StatusCode::CONFLICT);
    let _ = owner;
}
