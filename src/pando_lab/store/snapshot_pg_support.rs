//! Source-only PostgreSQL barrier cases for retained read snapshots.
//!
//! Every case is `#[ignore]`d and was not executed in this checkpoint. The
//! fixtures fail closed before creating a directory or database row when an
//! external object-store/KMS/endpoint override is present. The connection URL
//! sets a repeatable-read session default so each barrier proves the actual
//! transaction is still read committed.

use super::super::{Config, Control, Pack, Snapshot, repack, store};
use anyhow::{Result, bail, ensure};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

static TEST_LOCK: Mutex<()> = Mutex::new(());
static BARRIER: Mutex<Option<PathBuf>> = Mutex::new(None);
static FAULT: Mutex<Option<String>> = Mutex::new(None);

pub(crate) fn set_barrier(dir: Option<PathBuf>) {
    *BARRIER.lock().expect("snapshot retention barrier lock") = dir;
}

pub(crate) fn set_fault(point: Option<&str>) {
    *FAULT.lock().expect("snapshot retention fault lock") = point.map(str::to_owned);
}

async fn wait_release(dir: &Path, point: &str) -> Result<()> {
    let started = std::time::Instant::now();
    while !dir.join(format!("{point}.release")).exists() {
        ensure!(
            started.elapsed().as_secs() < 30,
            "snapshot retention test barrier timeout"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}

/// Test seam that records the actual transaction isolation at a production
/// lock/selection boundary rather than asserting a test-only imitation.
pub(crate) async fn barrier_tx(
    point: &str,
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<()> {
    let dir = { BARRIER.lock().expect("snapshot retention barrier lock").clone() };
    let Some(dir) = dir else {
        return Ok(());
    };
    std::fs::create_dir_all(&dir)?;
    let isolation: String = transaction
        .query_one("SHOW transaction_isolation", &[])
        .await?
        .get(0);
    std::fs::write(dir.join(format!("{point}.isolation")), isolation)?;
    std::fs::write(dir.join(format!("{point}.ready")), b"")?;
    wait_release(&dir, point).await
}

pub(crate) fn fault(point: &str) -> Result<()> {
    let fault = { FAULT.lock().expect("snapshot retention fault lock").clone() };
    if fault.as_deref() == Some(point) {
        bail!("snapshot retention test fault before commit");
    }
    Ok(())
}

pub(crate) async fn wait_ready(dir: &Path, point: &str) {
    let marker = dir.join(format!("{point}.ready"));
    for _ in 0..3000 {
        if marker.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("snapshot retention test barrier point '{point}' was not reached");
}

pub(crate) fn assert_read_committed(dir: &Path, point: &str) {
    let isolation = std::fs::read_to_string(dir.join(format!("{point}.isolation")))
        .expect("the production barrier must record actual transaction isolation");
    assert_eq!(
        isolation.trim(),
        "read committed",
        "actual transaction isolation at {point}"
    );
}

/// Poll PostgreSQL lock state to a finite deadline. This observes the real
/// waiter instead of guessing with a fixed sleep.
pub(crate) async fn wait_for_lock_wait(
    admin: &Client,
    first: &str,
    second: &str,
    label: &str,
    attempts: usize,
) {
    let first = format!("%{first}%");
    let second = format!("%{second}%");
    for _ in 0..attempts {
        let count: i64 = admin
            .query_one(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE datname=current_database() AND state='active' \
                 AND wait_event_type='Lock' AND query ILIKE $1 AND query ILIKE $2",
                &[&first, &second],
            )
            .await
            .unwrap()
            .get(0);
        if count > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("did not observe PostgreSQL lock wait for {label}");
}

fn database_with_repeatable_read_default(database: &str) -> String {
    if database.contains("://") {
        let separator = if database.contains('?') { '&' } else { '?' };
        format!(
            "{database}{separator}options=-c%20default_transaction_isolation%3Drepeatable%20read"
        )
    } else {
        format!("{database} options='-c default_transaction_isolation=repeatable read'")
    }
}

fn external_override_present() -> bool {
    [
        "PANDO_OBJECT_STORE_ROOT",
        "PANDO_KMS_KEYRING_DIR",
        "PANDO_KMS_PROVIDER",
        "ROOTYARD_OBJECT_STORE_ENDPOINT",
    ]
    .into_iter()
    .any(|key| std::env::var_os(key).is_some())
}

pub(super) fn config_for(label: &str) -> Option<(Config, PathBuf)> {
    if external_override_present() {
        panic!(
            "snapshot retention PG fixture refuses external object-store/KMS/endpoint overrides"
        );
    }
    let database = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok()?;
    if database.trim().is_empty() {
        return None;
    }
    let database = database_with_repeatable_read_default(&database);
    let root = std::env::temp_dir().join(format!("pando-snapshot-pg-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(root.join("objects")).ok()?;
    std::fs::create_dir_all(root.join("sessions")).ok()?;
    Some((
        Config {
            database,
            root: root.clone(),
            git: PathBuf::from("/usr/bin/git"),
        },
        root,
    ))
}

pub(super) async fn connect(config: &Config) -> Client {
    let (client, connection) = tokio_postgres::connect(&config.database, NoTls)
        .await
        .expect("ROOTYARD_TEST_DATABASE_URL must accept PostgreSQL connections");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute("SET default_transaction_isolation='repeatable read'")
        .await
        .expect("fixture session default isolation");
    client
}

pub(super) async fn cleanup(client: &Client, repo: Uuid) {
    for sql in [
        "DELETE FROM pando_lab.changes WHERE repo=$1",
        "DELETE FROM pando_lab.snapshots WHERE repo=$1",
        "DELETE FROM pando_lab.pinned_roots WHERE repo=$1",
        "DELETE FROM pando_lab.refs WHERE repo=$1",
        "DELETE FROM pando_lab.objects WHERE repo=$1",
        "DELETE FROM pando_lab.manifests WHERE repo=$1",
        "DELETE FROM pando_lab.repacks WHERE repo=$1",
        "DELETE FROM pando_lab.object_store_manifests WHERE repo=$1",
        "DELETE FROM pando_lab.kms_envelopes WHERE repo=$1",
        "DELETE FROM pando_lab.kms_key_policies WHERE repo=$1",
        "DELETE FROM pando_lab.lifecycle_policies WHERE repo=$1",
        "DELETE FROM pando_lab.kms_keys WHERE repo=$1",
        "DELETE FROM pando_lab.kms_rotations WHERE repo=$1",
        "DELETE FROM pando_lab.operations WHERE repo=$1",
        "DELETE FROM pando_lab.repositories WHERE id=$1",
    ] {
        let _ = client.execute(sql, &[&repo]).await;
    }
}

pub(super) async fn insert_repo(client: &Client, repo: Uuid) {
    client
        .execute(
            "INSERT INTO pando_lab.repositories(id,storage_backend) VALUES($1,'pando')",
            &[&repo],
        )
        .await
        .unwrap();
}

async fn init_work(config: &Config, work: &Path) {
    std::fs::create_dir_all(work).unwrap();
    config
        .git(work, &["init", "--initial-branch=main", "."], b"")
        .await
        .unwrap();
    config
        .git(work, &["config", "user.name", "T"], b"")
        .await
        .unwrap();
    config
        .git(work, &["config", "user.email", "t@e.c"], b"")
        .await
        .unwrap();
}

async fn commit_file(
    config: &Config,
    work: &Path,
    name: &str,
    text: &str,
    message: &str,
) -> String {
    std::fs::write(work.join(name), text).unwrap();
    config.git(work, &["add", name], b"").await.unwrap();
    config
        .git(work, &["commit", "-m", message], b"")
        .await
        .unwrap();
    String::from_utf8(
        config
            .git(work, &["rev-parse", "HEAD"], b"")
            .await
            .unwrap(),
    )
    .unwrap()
    .trim()
    .to_owned()
}

async fn publish(
    config: &Config,
    admin: &Client,
    repo: Uuid,
    work: &Path,
    roots: &[String],
) -> Pack {
    let (pack, oids) = store::publish_pack(config, repo, Uuid::new_v4(), work, roots)
        .await
        .unwrap()
        .expect("incremental pack");
    admin
        .execute(
            "INSERT INTO pando_lab.manifests(repo,pack_id,pack_sha256,idx_sha256) VALUES($1,$2,$3,$4)",
            &[&repo, &pack.id, &pack.pack_sha256, &pack.idx_sha256],
        )
        .await
        .unwrap();
    for oid in &oids {
        admin
            .execute(
                "INSERT INTO pando_lab.objects(repo,oid,pack_id) VALUES($1,$2,$3)",
                &[&repo, oid, &pack.id],
            )
            .await
            .unwrap();
    }
    pack
}

async fn set_ref(admin: &Client, repo: Uuid, name: &str, oid: &str) {
    admin
        .execute(
            "INSERT INTO pando_lab.refs(repo,name,oid) VALUES($1,$2,$3) \
             ON CONFLICT(repo,name) DO UPDATE SET oid=EXCLUDED.oid",
            &[&repo, &name, &oid],
        )
        .await
        .unwrap();
}

pub(super) async fn seed_single_pack(
    config: &Config,
    admin: &Client,
    repo: Uuid,
) -> (Pack, String) {
    let work = config.root.join("work");
    init_work(config, &work).await;
    let commit = commit_file(config, &work, "a.txt", "one\n", "c1").await;
    let pack = publish(config, admin, repo, &work, &[commit.clone()]).await;
    set_ref(admin, repo, "refs/heads/main", &commit).await;
    (pack, commit)
}

pub(super) async fn seed_two_packs(
    config: &Config,
    admin: &Client,
    repo: Uuid,
) -> (Pack, Pack) {
    let work = config.root.join("work");
    init_work(config, &work).await;
    let first = commit_file(config, &work, "a.txt", "one\n", "c1").await;
    let live = publish(config, admin, repo, &work, &[first.clone()]).await;
    set_ref(admin, repo, "refs/heads/main", &first).await;
    config
        .git(&work, &["checkout", "-b", "expired", &first], b"")
        .await
        .unwrap();
    let second = commit_file(config, &work, "b.txt", "two\n", "c2").await;
    let expired = publish(config, admin, repo, &work, &[second]).await;
    (live, expired)
}

pub(super) async fn insert_old_metadata(admin: &Client, repo: Uuid, pack: &Pack) {
    admin
        .execute(
            "INSERT INTO pando_lab.object_store_manifests(\
             repo,pack_id,bucket,pack_key,idx_key,manifest_key,pack_sha256,idx_sha256,\
             pack_bytes,idx_bytes,object_count,chunk_size,chunk_count,manifest_json) \
             VALUES($1,$2,'fixture',$3,$4,$5,$6,$7,1,1,1,1,1,'{}'::jsonb)",
            &[
                &repo,
                &pack.id,
                &format!("packs/{}.pack", pack.id),
                &format!("packs/{}.idx", pack.id),
                &format!("manifests/{}.json", pack.id),
                &pack.pack_sha256,
                &pack.idx_sha256,
            ],
        )
        .await
        .unwrap();
}

pub(super) async fn insert_snapshot(
    admin: &Client,
    repo: Uuid,
    principal: &str,
    packs: &[Pack],
    expires_interval: &str,
) -> Uuid {
    let id = Uuid::new_v4();
    let refs = BTreeMap::<String, String>::new();
    admin
        .execute(
            "INSERT INTO pando_lab.snapshots(\
             id,repo,principal,generation,storage_generation,refs,packs,expires_at) \
             VALUES($1,$2,$3,0,1,$4,$5,clock_timestamp()+$6::interval)",
            &[
                &id,
                &repo,
                &principal,
                &serde_json::to_value(&refs).unwrap(),
                &serde_json::to_value(packs).unwrap(),
                &expires_interval,
            ],
        )
        .await
        .unwrap();
    id
}

pub(super) async fn retained_snapshot(
    admin: &Client,
    token: Uuid,
    repo: Uuid,
    principal: &str,
) -> Snapshot {
    let row = admin
        .query_one(
            "SELECT generation,storage_generation,refs,packs FROM pando_lab.snapshots \
             WHERE id=$1 AND repo=$2 AND principal=$3 AND expires_at>clock_timestamp()",
            &[&token, &repo, &principal],
        )
        .await
        .expect("retained snapshot must be live and bound to its principal");
    Snapshot {
        repo,
        generation: row.get(0),
        storage_generation: row.get(1),
        refs: serde_json::from_value(row.get(2)).unwrap(),
        packs: serde_json::from_value(row.get(3)).unwrap(),
    }
}

pub(super) async fn assert_token_ttl(admin: &Client, token: Uuid) {
    let live_default: bool = admin
        .query_one(
            "SELECT expires_at > clock_timestamp()+interval '4 minutes' \
             AND expires_at < clock_timestamp()+interval '6 minutes' \
             FROM pando_lab.snapshots WHERE id=$1",
            &[&token],
        )
        .await
        .unwrap()
        .get(0);
    assert!(live_default, "the schema's five-minute token lifetime must remain");
}

pub(super) async fn materialize_and_read(
    config: &Config,
    snapshot: &Snapshot,
    base: &Path,
    path: &str,
) -> String {
    let repo = store::materialize(config, snapshot, base, &Control::default())
        .await
        .unwrap();
    let refspec = format!("refs/heads/main:{path}");
    String::from_utf8(
        config
            .git(&repo, &["show", &refspec], b"")
            .await
            .unwrap(),
    )
    .unwrap()
}

pub(super) async fn metadata_count(admin: &Client, repo: Uuid, pack: Uuid) -> i64 {
    admin
        .query_one(
            "SELECT count(*) FROM pando_lab.object_store_manifests WHERE repo=$1 AND pack_id=$2",
            &[&repo, &pack],
        )
        .await
        .unwrap()
        .get(0)
}

pub(super) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub(super) struct HookGuard;

impl HookGuard {
    pub(super) fn new() -> Self {
        set_barrier(None);
        set_fault(None);
        Self
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        set_barrier(None);
        set_fault(None);
    }
}

pub(super) fn options() -> repack::RepackOptions {
    repack::RepackOptions {
        prune_superseded: true,
        pin_oids: Vec::new(),
        sync_object_store: false,
    }
}
