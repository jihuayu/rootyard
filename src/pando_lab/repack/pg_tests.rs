//! Source-only PostgreSQL cases for the repack producer transaction boundary.
//!
//! Every case is `#[ignore]`d and was not executed in this checkpoint. They use
//! an owned repository row and disposable root with the normal
//! `experimental/pando/schema.sql` installed in `ROOTYARD_TEST_DATABASE_URL`.
//! Explicit `--ignored` invocation fails closed when that dedicated selector is
//! missing or empty; there is no silent success path.

use super::super::{Config, Pack, lifecycle, store};
use super::{RepackOptions, repack_repo};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

static TEST_LOCK: Mutex<()> = Mutex::new(());

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct HookGuard;

impl HookGuard {
    fn new() -> Self {
        super::test_support::set_barrier(None);
        super::test_support::set_fault(None);
        Self
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        super::test_support::set_barrier(None);
        super::test_support::set_fault(None);
    }
}

fn set_barrier(dir: PathBuf) {
    super::test_support::set_barrier(Some(dir));
}

fn set_fault(point: &str) {
    super::test_support::set_fault(Some(point));
}

/// Fail closed before any fixture side effect. This inspects only presence,
/// never values, and never mutates process-global environment.
///
/// Direct fixture-escaping overrides in the real source are:
/// - `object_store::store_root` -> `PANDO_OBJECT_STORE_ROOT`
/// - `lifecycle::provider::resolve_kms_dir` -> `PANDO_KMS_KEYRING_DIR`
/// - `provider_selection` -> `PANDO_KMS_PROVIDER`
/// - `object_store::remote_enabled` -> `ROOTYARD_OBJECT_STORE_ENDPOINT`
///
/// Vault URL/token/mount/key variables are unreachable while
/// `PANDO_KMS_PROVIDER` is absent or Local, and any presence of that selector
/// is rejected below. `PANDO_OBJECT_STORE_BUCKET` changes only a key prefix
/// under the owned temporary root, not the fixture root itself.
fn preflight_fixture_isolation() {
    for name in
        ["PANDO_OBJECT_STORE_ROOT", "PANDO_KMS_KEYRING_DIR", "PANDO_KMS_PROVIDER", "ROOTYARD_OBJECT_STORE_ENDPOINT"]
    {
        assert!(
            std::env::var_os(name).is_none(),
            "repack PG fixture isolation preflight failed: external {name} is set; remove it so the owned temporary fixture cannot escape"
        );
    }
}

fn config_for(label: &str) -> (Config, PathBuf) {
    let database = match std::env::var("ROOTYARD_TEST_DATABASE_URL") {
        Ok(database) if !database.trim().is_empty() => database,
        _ => panic!("ROOTYARD_TEST_DATABASE_URL must be set and non-empty for ignored repack PostgreSQL cases"),
    };
    let root = std::env::temp_dir().join(format!("pando-repack-pg-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(root.join("objects")).expect("create owned repack PG fixture objects directory");
    std::fs::create_dir_all(root.join("sessions")).expect("create owned repack PG fixture sessions directory");
    (Config { database, root: root.clone(), git: PathBuf::from("/usr/bin/git") }, root)
}

async fn connect(config: &Config) -> Client {
    let (client, connection) = tokio_postgres::connect(&config.database, NoTls)
        .await
        .expect("ROOTYARD_TEST_DATABASE_URL must accept PostgreSQL connections");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

async fn cleanup(client: &Client, repo: Uuid) {
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

async fn table_count(client: &Client, table: &str, repo: Uuid) -> i64 {
    client.query_one(&format!("SELECT count(*) FROM pando_lab.{table} WHERE repo=$1"), &[&repo]).await.unwrap().get(0)
}

async fn insert_repo(client: &Client, repo: Uuid) {
    client
        .execute("INSERT INTO pando_lab.repositories(id,storage_backend) VALUES($1,'pando')", &[&repo])
        .await
        .unwrap();
}

fn commit_file(config: &Config, work: &Path, name: &str, text: &str, message: &str) -> String {
    std::fs::write(work.join(name), text).unwrap();
    super::run_sync_git(&config.git, work, &["add", name], b"").unwrap();
    super::run_sync_git(&config.git, work, &["commit", "-m", message], b"").unwrap();
    String::from_utf8(super::run_sync_git(&config.git, work, &["rev-parse", "HEAD"], b"").unwrap())
        .unwrap()
        .trim()
        .to_owned()
}

async fn publish(config: &Config, admin: &Client, repo: Uuid, work: &Path, roots: &[String]) -> Pack {
    let (pack, oids) =
        store::publish_pack(config, repo, Uuid::new_v4(), work, roots).await.unwrap().expect("incremental pack");
    admin
        .execute(
            "INSERT INTO pando_lab.manifests(repo,pack_id,pack_sha256,idx_sha256) VALUES($1,$2,$3,$4)",
            &[&repo, &pack.id, &pack.pack_sha256, &pack.idx_sha256],
        )
        .await
        .unwrap();
    for oid in &oids {
        admin
            .execute("INSERT INTO pando_lab.objects(repo,oid,pack_id) VALUES($1,$2,$3)", &[&repo, oid, &pack.id])
            .await
            .unwrap();
    }
    pack
}

async fn set_ref(admin: &Client, repo: Uuid, name: &str, oid: &str) {
    admin
        .execute(
            "INSERT INTO pando_lab.refs(repo,name,oid) VALUES($1,$2,$3) ON CONFLICT(repo,name) DO UPDATE SET oid=EXCLUDED.oid",
            &[&repo, &name, &oid],
        )
        .await
        .unwrap();
}

/// Three real packs: main c1, main c2, and a side commit reachable only from a
/// pinned root. Repack must compact all three while preserving the pin.
async fn seed_repo(config: &Config, admin: &Client, repo: Uuid) -> Vec<Pack> {
    let work = config.root.join("work");
    std::fs::create_dir_all(&work).unwrap();
    super::run_sync_git(&config.git, &work, &["init", "--initial-branch=main", "."], b"").unwrap();
    super::run_sync_git(&config.git, &work, &["config", "user.name", "T"], b"").unwrap();
    super::run_sync_git(&config.git, &work, &["config", "user.email", "t@e.c"], b"").unwrap();

    let c1 = commit_file(config, &work, "a.txt", "one\n", "c1");
    let p1 = publish(config, admin, repo, &work, &[c1.clone()]).await;
    set_ref(admin, repo, "refs/heads/main", &c1).await;

    let c2 = commit_file(config, &work, "b.txt", "two\n", "c2");
    let p2 = publish(config, admin, repo, &work, &[c2.clone()]).await;
    set_ref(admin, repo, "refs/heads/main", &c2).await;

    super::run_sync_git(&config.git, &work, &["checkout", "-b", "pin", &c1], b"").unwrap();
    let pin = commit_file(config, &work, "pin.txt", "pin\n", "pin");
    let p3 = publish(config, admin, repo, &work, &[pin.clone()]).await;
    admin
        .execute("INSERT INTO pando_lab.pinned_roots(repo,name,oid) VALUES($1,'ci-pin',$2)", &[&repo, &pin])
        .await
        .unwrap();

    vec![p1, p2, p3]
}

async fn insert_local_checkpoint(admin: &Client, repo: Uuid) -> Uuid {
    let checkpoint = lifecycle::rotation::KmsRotationCheckpoint {
        rotation_id: Uuid::new_v4(),
        repo,
        from_key_id: lifecycle::DEFAULT_KMS_KEY_ID.to_owned(),
        from_key_version: 1,
        to_key_id: lifecycle::DEFAULT_KMS_KEY_ID.to_owned(),
        to_key_version: 1,
        state: "IN_PROGRESS".to_owned(),
        revoke_previous: false,
        target_pack_ids: Vec::new(),
        completed_pack_ids: Vec::new(),
        failed_pack_id: None,
        from_provider_kind: lifecycle::provider::PROVIDER_KIND_LOCAL.to_owned(),
        to_provider_kind: lifecycle::provider::PROVIDER_KIND_LOCAL.to_owned(),
        expected_to_version: 0,
        external_rotate_issued: false,
        reconcile_stage: lifecycle::rotation::KmsReconcileStage::NotIssued,
        target_contract: String::new(),
        write_epoch: 0,
    };
    admin
        .execute(
            "INSERT INTO pando_lab.kms_rotations(id,repo,from_key_id,from_key_version,to_key_id,to_key_version,state,checkpoint_json) \
             VALUES($1,$2,$3,$4,$5,$6,'IN_PROGRESS',$7)",
            &[
                &checkpoint.rotation_id,
                &repo,
                &checkpoint.from_key_id,
                &checkpoint.from_key_version,
                &checkpoint.to_key_id,
                &checkpoint.to_key_version,
                &serde_json::to_value(&checkpoint).unwrap(),
            ],
        )
        .await
        .unwrap();
    checkpoint.rotation_id
}

async fn wait_ready(dir: &Path, point: &str) {
    let marker = dir.join(format!("{point}.ready"));
    for _ in 0..3000 {
        if marker.exists() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("repack test barrier point '{point}' was not reached");
}

fn default_options(sync_object_store: bool) -> RepackOptions {
    RepackOptions { prune_superseded: true, pin_oids: Vec::new(), sync_object_store }
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_repack_default_local_publishes_one_authority_and_retains_pinned_data() {
    let _lock = test_lock();
    let _hooks = HookGuard::new();
    preflight_fixture_isolation();
    let (config, root) = config_for("default-local");
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    insert_repo(&admin, repo).await;
    let packs = seed_repo(&config, &admin, repo).await;

    let report = repack_repo(&config, repo, &default_options(true)).await.unwrap();
    let compacted = report.compacted_pack_id.expect("compacted pack");

    assert!(report.object_store_synced);
    assert_eq!(report.packs_before, packs.len());
    assert_eq!(report.packs_after, 1);
    assert_eq!(table_count(&admin, "manifests", repo).await, 1);
    assert_eq!(table_count(&admin, "objects", repo).await, report.objects_after as i64);
    assert_eq!(table_count(&admin, "repacks", repo).await, 1);
    assert_eq!(table_count(&admin, "object_store_manifests", repo).await, 1);
    assert_eq!(table_count(&admin, "kms_envelopes", repo).await, 1);

    let row = admin
        .query_one(
            "SELECT m.pack_sha256,m.idx_sha256,e.provider_kind,e.key_id,e.key_version \
             FROM pando_lab.manifests m JOIN pando_lab.kms_envelopes e USING(repo,pack_id) \
             WHERE m.repo=$1 AND m.pack_id=$2",
            &[&repo, &compacted],
        )
        .await
        .unwrap();
    assert_eq!(Some(row.get::<_, String>(0)), report.compacted_pack_sha256);
    assert_eq!(Some(row.get::<_, String>(1)), report.compacted_idx_sha256);
    assert_eq!(row.get::<_, String>(2), lifecycle::provider::PROVIDER_KIND_LOCAL);
    assert_eq!(row.get::<_, String>(3), lifecycle::DEFAULT_KMS_KEY_ID);
    assert_eq!(row.get::<_, i32>(4), 1);

    let mirror = lifecycle::envelope_file_path(&config.root, repo, compacted);
    assert!(mirror.is_file(), "the committed receipt must refresh the envelope mirror after commit");
    assert!(config.root.join("objects").join(repo.to_string()).join(format!("{compacted}.pack")).is_file());
    assert!(config.root.join("manifests").join(repo.to_string()).join(format!("{compacted}.json")).is_file());

    let pin: String = admin
        .query_one("SELECT oid FROM pando_lab.pinned_roots WHERE repo=$1 AND name='ci-pin'", &[&repo])
        .await
        .unwrap()
        .get(0);
    let owner: Uuid = admin
        .query_one("SELECT pack_id FROM pando_lab.objects WHERE repo=$1 AND oid=$2", &[&repo, &pin])
        .await
        .unwrap()
        .get(0);
    assert_eq!(owner, compacted, "pinned-root data must survive compaction");

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_repack_generation_race_fails_cleanly_without_authority() {
    let _lock = test_lock();
    let _hooks = HookGuard::new();
    preflight_fixture_isolation();
    let (config, root) = config_for("generation-race");
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    insert_repo(&admin, repo).await;
    let packs = seed_repo(&config, &admin, repo).await;

    let barrier = root.join("barrier");
    set_barrier(barrier.clone());
    let config2 = config.clone();
    let handle = tokio::spawn(async move { repack_repo(&config2, repo, &default_options(true)).await });
    wait_ready(&barrier, "after-prepare").await;

    admin.execute("UPDATE pando_lab.repositories SET generation=generation+1 WHERE id=$1", &[&repo]).await.unwrap();
    std::fs::write(barrier.join("after-prepare.release"), b"").unwrap();

    let error = handle.await.unwrap().unwrap_err();
    assert!(format!("{error:#}").contains("concurrent repository state change during repack"));
    assert_eq!(table_count(&admin, "repacks", repo).await, 0);
    assert_eq!(table_count(&admin, "object_store_manifests", repo).await, 0);
    assert_eq!(table_count(&admin, "kms_envelopes", repo).await, 0);
    assert_eq!(table_count(&admin, "manifests", repo).await, packs.len() as i64);
    assert_eq!(
        std::fs::read_dir(config.root.join("objects").join(repo.to_string())).unwrap().count(),
        packs.len() * 2,
        "the rejected compacted local pack/idx must not masquerade as authority"
    );

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_repack_forced_final_failure_rolls_back_authority_and_mirror() {
    let _lock = test_lock();
    let _hooks = HookGuard::new();
    preflight_fixture_isolation();
    let (config, root) = config_for("forced-rollback");
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    insert_repo(&admin, repo).await;
    let packs = seed_repo(&config, &admin, repo).await;

    set_fault("after-publication");
    let error = repack_repo(&config, repo, &default_options(true)).await.unwrap_err();
    assert!(format!("{error:#}").contains("test fault injection"));

    assert_eq!(table_count(&admin, "repacks", repo).await, 0);
    assert_eq!(table_count(&admin, "object_store_manifests", repo).await, 0);
    assert_eq!(table_count(&admin, "kms_envelopes", repo).await, 0);
    assert_eq!(table_count(&admin, "manifests", repo).await, packs.len() as i64);
    for pack in &packs {
        assert!(
            config.root.join("objects").join(repo.to_string()).join(format!("{}.pack", pack.id)).is_file(),
            "a rolled-back final transaction must not remove the previous committed local pack set"
        );
    }
    let mirror_dir = config.root.join("object_store").join("envelopes").join(repo.to_string());
    assert!(
        !mirror_dir.exists() || std::fs::read_dir(&mirror_dir).unwrap().next().is_none(),
        "a rolled-back prepared receipt must never refresh the envelope mirror"
    );

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_repack_rotation_barrier_keeps_exact_target_and_shared_gate() {
    let _lock = test_lock();
    let _hooks = HookGuard::new();
    preflight_fixture_isolation();
    let (config, root) = config_for("rotation-barrier");
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    insert_repo(&admin, repo).await;
    seed_repo(&config, &admin, repo).await;
    insert_local_checkpoint(&admin, repo).await;

    let barrier = root.join("barrier");
    set_barrier(barrier.clone());
    let config2 = config.clone();
    let handle = tokio::spawn(async move { repack_repo(&config2, repo, &default_options(true)).await });
    wait_ready(&barrier, "after-prepare").await;

    // Rotation takes runner then the exclusive publication gate. The repack
    // shared gate must make this fail instead of passing between selection and
    // its final authority commit.
    let rotation = lifecycle::rotation::rotate_kms_key_with_options(
        &config,
        repo,
        &lifecycle::rotation::KmsRotateOptions {
            resume: false,
            fail_after_packs: None,
            revoke_previous: false,
            target_key_id: Some("kms-local-rotated-v2".to_owned()),
            target_version: Some(2),
        },
    )
    .await;
    assert!(rotation.is_err(), "exclusive rotation must not pass a held shared publication gate");

    std::fs::write(barrier.join("after-prepare.release"), b"").unwrap();
    let report = handle.await.unwrap().unwrap();
    let compacted = report.compacted_pack_id.expect("compacted pack");
    assert!(report.object_store_synced);

    let row = admin
        .query_one(
            "SELECT provider_kind,key_id,key_version FROM pando_lab.kms_envelopes WHERE repo=$1 AND pack_id=$2",
            &[&repo, &compacted],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), lifecycle::provider::PROVIDER_KIND_LOCAL);
    assert_eq!(row.get::<_, String>(1), lifecycle::DEFAULT_KMS_KEY_ID);
    assert_eq!(row.get::<_, i32>(2), 1);
    let states: Vec<String> = admin
        .query("SELECT state FROM pando_lab.kms_rotations WHERE repo=$1", &[&repo])
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(states, vec!["IN_PROGRESS".to_owned()]);

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
#[ignore = "requires ROOTYARD_TEST_DATABASE_URL and the pando_lab schema"]
async fn pg_repack_no_sync_local_legacy_and_active_target_narrow_reject() {
    let _lock = test_lock();
    let _hooks = HookGuard::new();
    preflight_fixture_isolation();
    let (config, root) = config_for("no-sync");
    let admin = connect(&config).await;
    let repo = Uuid::new_v4();
    insert_repo(&admin, repo).await;
    seed_repo(&config, &admin, repo).await;

    let report = repack_repo(&config, repo, &default_options(false)).await.unwrap();
    assert!(!report.object_store_synced);
    assert_eq!(table_count(&admin, "repacks", repo).await, 1);
    assert_eq!(table_count(&admin, "manifests", repo).await, 1);
    assert_eq!(table_count(&admin, "object_store_manifests", repo).await, 0);
    assert_eq!(table_count(&admin, "kms_envelopes", repo).await, 0);

    insert_local_checkpoint(&admin, repo).await;
    let error = repack_repo(&config, repo, &default_options(false)).await.unwrap_err();
    assert!(format!("{error:#}").contains("sync_object_store=false"));
    assert_eq!(table_count(&admin, "repacks", repo).await, 1);
    assert_eq!(table_count(&admin, "manifests", repo).await, 1);
    assert_eq!(table_count(&admin, "object_store_manifests", repo).await, 0);
    assert_eq!(table_count(&admin, "kms_envelopes", repo).await, 0);

    cleanup(&admin, repo).await;
    let _ = std::fs::remove_dir_all(root);
}
