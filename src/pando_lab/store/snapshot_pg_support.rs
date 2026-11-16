//! Source-only PostgreSQL barrier cases for retained read snapshots.
//!
//! Every case is `#[ignore]`d and was not executed in this checkpoint. The
//! fixtures fail closed before creating a directory or database row when an
//! external object-store/KMS/endpoint override is present. The connection URL
//! sets a repeatable-read session default so each barrier proves the actual
//! transaction is still read committed.

use super::super::{Config, Control, Pack, Snapshot, repack};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

fn database_with_repeatable_read_default(database: &str) -> String {
    if database.contains("://") {
        let separator = if database.contains('?') { '&' } else { '?' };
        format!("{database}{separator}options=-c%20default_transaction_isolation%3Drepeatable%5C%20read")
    } else {
        format!("{database} options='-c default_transaction_isolation=repeatable\\\\ read'")
    }
}

fn external_override_present() -> bool {
    ["PANDO_OBJECT_STORE_ROOT", "PANDO_KMS_KEYRING_DIR", "PANDO_KMS_PROVIDER", "ROOTYARD_OBJECT_STORE_ENDPOINT"]
        .into_iter()
        .any(|key| std::env::var_os(key).is_some())
}

pub(super) fn config_for(label: &str) -> (Config, PathBuf) {
    if external_override_present() {
        panic!("snapshot retention PG fixture refuses external object-store/KMS/endpoint overrides");
    }
    let database = std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .unwrap_or_else(|_| panic!("snapshot retention PG cases require a nonempty ROOTYARD_TEST_DATABASE_URL"));
    let database = database.trim().to_owned();
    if database.is_empty() {
        panic!("snapshot retention PG cases require a nonempty ROOTYARD_TEST_DATABASE_URL");
    }
    if database.parse::<tokio_postgres::Config>().is_err() {
        panic!("snapshot retention PG cases require a valid ROOTYARD_TEST_DATABASE_URL");
    }
    let database = database_with_repeatable_read_default(&database);
    let root = std::env::temp_dir().join(format!("pando-snapshot-pg-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(root.join("objects")).expect("snapshot retention fixture root");
    std::fs::create_dir_all(root.join("sessions")).expect("snapshot retention fixture sessions");
    (Config { database, root: root.clone(), git: PathBuf::from("/usr/bin/git") }, root)
}

pub(super) fn actor_config(config: &Config, appname: &str) -> Config {
    let mut actor = config.clone();
    actor.database = if actor.database.contains("://") {
        let separator = if actor.database.contains('?') { '&' } else { '?' };
        format!("{}{separator}application_name={appname}", actor.database)
    } else {
        format!("{} application_name='{appname}'", actor.database)
    };
    actor
}

pub(super) async fn connect_named(config: &Config, appname: &str) -> Client {
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
        .execute("SELECT set_config('application_name',$1,false)", &[&appname])
        .await
        .expect("fixture session application_name");
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
        .execute("INSERT INTO pando_lab.repositories(id,storage_backend) VALUES($1,'pando')", &[&repo])
        .await
        .unwrap();
}

async fn init_work(config: &Config, work: &Path) {
    std::fs::create_dir_all(work).unwrap();
    config.git(work, &["init", "--initial-branch=main", "."], b"").await.unwrap();
    config.git(work, &["config", "user.name", "T"], b"").await.unwrap();
    config.git(work, &["config", "user.email", "t@e.c"], b"").await.unwrap();
}

async fn commit_file(config: &Config, work: &Path, name: &str, text: &str, message: &str) -> String {
    std::fs::write(work.join(name), text).unwrap();
    config.git(work, &["add", name], b"").await.unwrap();
    config.git(work, &["commit", "-m", message], b"").await.unwrap();
    String::from_utf8(config.git(work, &["rev-parse", "HEAD"], b"").await.unwrap()).unwrap().trim().to_owned()
}

async fn publish(config: &Config, admin: &Client, repo: Uuid, work: &Path, roots: &[String]) -> Pack {
    let (pack, oids) =
        super::publish_pack(config, repo, Uuid::new_v4(), work, roots).await.unwrap().expect("incremental pack");
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
            "INSERT INTO pando_lab.refs(repo,name,oid) VALUES($1,$2,$3) \
             ON CONFLICT(repo,name) DO UPDATE SET oid=EXCLUDED.oid",
            &[&repo, &name, &oid],
        )
        .await
        .unwrap();
}

pub(super) async fn seed_single_pack(config: &Config, admin: &Client, repo: Uuid) -> (Pack, String) {
    let work = config.root.join("work");
    init_work(config, &work).await;
    let commit = commit_file(config, &work, "a.txt", "one\n", "c1").await;
    let pack = publish(config, admin, repo, &work, &[commit.clone()]).await;
    set_ref(admin, repo, "refs/heads/main", &commit).await;
    (pack, commit)
}

pub(super) async fn seed_two_packs(config: &Config, admin: &Client, repo: Uuid) -> (Pack, Pack) {
    let work = config.root.join("work");
    init_work(config, &work).await;
    let first = commit_file(config, &work, "a.txt", "one\n", "c1").await;
    let live = publish(config, admin, repo, &work, &[first.clone()]).await;
    set_ref(admin, repo, "refs/heads/main", &first).await;
    config.git(&work, &["checkout", "-b", "expired", &first], b"").await.unwrap();
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

pub(super) async fn retained_snapshot(admin: &Client, token: Uuid, repo: Uuid, principal: &str) -> Snapshot {
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

pub(super) async fn materialize_and_read(config: &Config, snapshot: &Snapshot, base: &Path, path: &str) -> String {
    let repo = super::materialize(config, snapshot, base, &Control::default()).await.unwrap();
    let refspec = format!("refs/heads/main:{path}");
    String::from_utf8(config.git(&repo, &["show", &refspec], b"").await.unwrap()).unwrap()
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

pub(super) fn options() -> repack::RepackOptions {
    repack::RepackOptions { prune_superseded: true, pin_oids: Vec::new(), sync_object_store: false }
}
