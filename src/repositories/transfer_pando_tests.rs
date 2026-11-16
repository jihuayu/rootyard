//! Real migrated-schema PG17 + mock-S3 interleaving tests for transfer copy,
//! Pando delete/rekey fencing, and legacy shared-key rollback safety (#85).
use super::{
    purge_exec::delete_pando_artifact_fenced,
    transfer_lease::load_record_with_lock,
    transfer_model::CopiedRemoteObject,
    transfer_pando::{PandoTransferCopy, copy_pando_objects_with_store},
    transfer_phases::phase_rekey_db_with_pool,
    transfer_remote::cleanup_rollback_objects_with_stores,
    transfer_remote_tests::{MockRemoteS3, start_s3},
};
use crate::{
    db,
    pando_gateway::retention,
    storage::remote_objects::{ObjectKey, RemoteObjectStore},
};
use deadpool_postgres::{Client, Pool};
use reqwest::Url;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::Path,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::time::Instant;
use uuid::Uuid;

async fn setup_migrated_pool() -> Option<(Pool, Uuid)> {
    let base = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok()?;
    let admin = db::pool(&base).unwrap();
    let schema = format!("xfer_pando_full_{}", Uuid::new_v4().simple());
    admin.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA \"{schema}\"")).await.unwrap();
    let mut url = Url::parse(&base).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = db::pool(url.as_str()).unwrap();
    db::migrate(&pool).await.unwrap();
    let auth_id: Uuid = pool
        .get()
        .await
        .unwrap()
        .query_one("SELECT authority_id FROM pando_storage_authorities WHERE singleton", &[])
        .await
        .unwrap()
        .get(0);
    Some((pool, auth_id))
}

async fn seed_user(pool: &Pool, id: Uuid, prefix: &str) {
    let name = format!("{prefix}{}", &id.simple().to_string()[..8]);
    pool.get().await.unwrap().execute("INSERT INTO users(id, username) VALUES($1, $2)", &[&id, &name]).await.unwrap();
}

async fn seed_transfer_row(
    c: &Client,
    xfer_id: Uuid,
    repo_id: Uuid,
    from_owner: Uuid,
    to_owner: Uuid,
    repo_name: &str,
    lease_owner: &str,
) {
    c.execute(
        "INSERT INTO repository_transfers \
         (id, repository_id, from_owner_id, to_owner_id, from_name, to_name, initiated_by, \
          expected_version, state, lease_owner, lease_until, lease_epoch) \
         VALUES($1,$2,$3,$4,$5,$5,$3,1,'copying_remote',$6,clock_timestamp()+interval '60 seconds',1)",
        &[&xfer_id, &repo_id, &from_owner, &to_owner, &repo_name, &lease_owner],
    )
    .await
    .unwrap();
}

async fn seed_linked_repo_manifest(
    c: &Client,
    store: &RemoteObjectStore,
    dir: &Path,
    auth_id: Uuid,
    owner: Uuid,
    repo_name: &str,
    payload: &[u8],
    deadline: Instant,
) -> (Uuid, Uuid, String, ObjectKey) {
    let sha = hex::encode(Sha256::digest(payload));
    let bin_path = dir.join(format!("{repo_name}.bin"));
    tokio::fs::write(&bin_path, payload).await.unwrap();
    let src_key = ObjectKey::scoped(owner, auth_id, 1, retention::NAMESPACE_CIPHER, &sha).unwrap();
    store.put_file(&src_key, &bin_path, payload.len() as u64, deadline).await.unwrap();

    let (repo_id, manifest_id) = (Uuid::new_v4(), Uuid::new_v4());
    c.execute(
        "INSERT INTO repositories(id, owner_id, name, state) VALUES($1,$2,$3,'ready')",
        &[&repo_id, &owner, &repo_name],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO pando_remote_artifacts \
         (authority_id, tenant_id, namespace, sha256, size, object_generation, remote_path, state) \
         VALUES($1,$2,$3,$4,$5,1,$6,'active')",
        &[&auth_id, &owner, &retention::NAMESPACE_CIPHER, &sha, &(payload.len() as i64), &src_key.path()],
    )
    .await
    .unwrap();
    let m_json = json!({"tenant_id": owner.to_string(), "pack_cipher": {"sha256": sha, "size": payload.len()}});
    c.execute(
        "INSERT INTO pando_pack_manifests \
         (id, repository_id, tenant_id, storage_generation, object_format, manifest) \
         VALUES($1,$2,$3,1,'sha1',$4)",
        &[&manifest_id, &repo_id, &owner, &m_json],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO pando_manifest_artifacts \
         (manifest_id, repository_id, authority_id, tenant_id, namespace, sha256, artifact_role) \
         VALUES($1,$2,$3,$4,$5,$6,'pack-cipher')",
        &[&manifest_id, &repo_id, &auth_id, &owner, &retention::NAMESPACE_CIPHER, &sha],
    )
    .await
    .unwrap();
    (repo_id, manifest_id, sha, src_key)
}

async fn run_phase_rekey(
    pool: &Pool,
    xfer_id: Uuid,
    copied: &[CopiedRemoteObject],
    deadline: Instant,
) -> anyhow::Result<()> {
    let mut c = pool.get().await?;
    c.execute(
        "UPDATE repository_transfers SET copied_objects = $2, state = 'rekeying_db' WHERE id = $1",
        &[&xfer_id, &serde_json::to_value(copied)?],
    )
    .await?;
    let tx = c.transaction().await?;
    let rec = load_record_with_lock(&tx, xfer_id, false).await?;
    tx.commit().await?;
    phase_rekey_db_with_pool(pool, &rec, deadline).await
}

#[tokio::test]
async fn transfer_copy_and_rekey_fence_deleting_pando_artifacts_fail_closed() {
    let Some((pool, auth_id)) = setup_migrated_pool().await else {
        return;
    };
    let mock = Arc::new(MockRemoteS3::new());
    let (store, server) = start_s3(mock.clone()).await;
    let dir = std::env::temp_dir().join(format!("ry-xfer-pando-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();

    let (from_owner, to_owner) = (Uuid::new_v4(), Uuid::new_v4());
    seed_user(&pool, from_owner, "ufrom").await;
    seed_user(&pool, to_owner, "uto").await;
    let c = pool.get().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);

    // Scenario A: Deleting g=1 on `to_owner` must NEVER be resurrected by copy; copy mints g>1 and rekey commits it cleanly.
    let bytes_a = b"pando-transfer-a-bytes";
    let (repo_a, manifest_a, sha_a, src_a) =
        seed_linked_repo_manifest(&c, store.as_ref(), &dir, auth_id, from_owner, "repo-a", bytes_a, deadline).await;
    let dst_stale_a = ObjectKey::scoped(to_owner, auth_id, 1, retention::NAMESPACE_CIPHER, &sha_a).unwrap();
    store.put_file(&dst_stale_a, &dir.join("repo-a.bin"), bytes_a.len() as u64, deadline).await.unwrap();
    c.execute(
        "INSERT INTO pando_remote_artifacts \
         (authority_id, tenant_id, namespace, sha256, size, object_generation, remote_path, state) \
         VALUES($1,$2,$3,$4,$5,1,$6,'active')",
        &[&auth_id, &to_owner, &retention::NAMESPACE_CIPHER, &sha_a, &(bytes_a.len() as i64), &dst_stale_a.path()],
    )
    .await
    .unwrap();

    mock.gate_first_delete.store(true, Ordering::SeqCst);
    let del_entered = mock.first_delete_entered.notified();
    let (pool_d1, store_d1, sha_a_d) = (pool.clone(), Arc::clone(&store), sha_a.clone());
    let deleter_a = tokio::spawn(async move {
        delete_pando_artifact_fenced(
            &pool_d1,
            store_d1.as_ref(),
            auth_id,
            to_owner,
            retention::NAMESPACE_CIPHER,
            &sha_a_d,
            Some(1),
            deadline,
        )
        .await
    });
    del_entered.await;

    let xfer_a = Uuid::new_v4();
    seed_transfer_row(&c, xfer_a, repo_a, from_owner, to_owner, "repo-a", "w1").await;
    let (mut copied_a, mut seen_a) = (Vec::new(), BTreeSet::new());
    copy_pando_objects_with_store(
        &pool,
        store.as_ref(),
        &PandoTransferCopy {
            transfer_lease: Some((xfer_a, "w1", 1)),
            repo_id: repo_a,
            from_owner,
            to_owner,
            stage_dir: &dir,
            deadline,
        },
        &mut copied_a,
        &mut seen_a,
    )
    .await
    .unwrap();
    assert_eq!(copied_a.len(), 1);
    assert_ne!(copied_a[0].to_key, dst_stale_a.path(), "copy must bump generation past deleting g1");

    mock.release_first_delete.notify_one();
    assert!(deleter_a.await.unwrap().unwrap());
    assert!(store.head(&dst_stale_a, deadline).await.unwrap().is_none(), "stale g1 deleted");
    run_phase_rekey(&pool, xfer_a, &copied_a, deadline).await.unwrap();

    let owner_a: Uuid = c.query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&repo_a]).await.unwrap().get(0);
    assert_eq!(owner_a, to_owner);
    let link_a: Uuid = c
        .query_one("SELECT tenant_id FROM pando_manifest_artifacts WHERE manifest_id=$1", &[&manifest_a])
        .await
        .unwrap()
        .get(0);
    assert_eq!(link_a, to_owner);
    let art_row = c
        .query_one(
            "SELECT state, object_generation, remote_path FROM pando_remote_artifacts WHERE authority_id=$1 AND tenant_id=$2 AND sha256=$3",
            &[&auth_id, &to_owner, &sha_a],
        )
        .await
        .unwrap();
    assert_eq!(art_row.get::<_, &str>(0), "active");
    assert!(art_row.get::<_, i64>(1) > 1);
    let new_key_a = ObjectKey::scoped(to_owner, auth_id, art_row.get(1), retention::NAMESPACE_CIPHER, &sha_a).unwrap();
    assert_eq!(art_row.get::<_, &str>(2), new_key_a.path());
    assert!(store.head(&new_key_a, deadline).await.unwrap().is_some(), "rekeyed artifact survives stale delete");
    let fences_left: i64 = c
        .query_one("SELECT count(*) FROM pando_publication_fences WHERE manifest_id=$1", &[&manifest_a])
        .await
        .unwrap()
        .get(0);
    assert_eq!(fences_left, 0, "transfer fences cleared upon atomic rekey");

    // Scenario B: Concurrent delete commits `deleting` AFTER copy and BEFORE phase_rekey_db -> rekey MUST fail closed!
    let (repo_b, manifest_b, sha_b, src_b) = seed_linked_repo_manifest(
        &c,
        store.as_ref(),
        &dir,
        auth_id,
        from_owner,
        "repo-b",
        b"pando-transfer-b-bytes",
        deadline,
    )
    .await;
    let xfer_b = Uuid::new_v4();
    seed_transfer_row(&c, xfer_b, repo_b, from_owner, to_owner, "repo-b", "w1").await;
    let (mut copied_b, mut seen_b) = (Vec::new(), BTreeSet::new());
    copy_pando_objects_with_store(
        &pool,
        store.as_ref(),
        &PandoTransferCopy {
            transfer_lease: Some((xfer_b, "w1", 1)),
            repo_id: repo_b,
            from_owner,
            to_owner,
            stage_dir: &dir,
            deadline,
        },
        &mut copied_b,
        &mut seen_b,
    )
    .await
    .unwrap();

    c.execute(
        "UPDATE pando_publication_fences SET lease_until = clock_timestamp() - interval '5 seconds' WHERE manifest_id=$1",
        &[&manifest_b],
    )
    .await
    .unwrap();
    mock.gate_first_delete.store(true, Ordering::SeqCst);
    let del_entered_b = mock.first_delete_entered.notified();
    let (pool_d2, store_d2, sha_b_d) = (pool.clone(), Arc::clone(&store), sha_b.clone());
    let deleter_b = tokio::spawn(async move {
        delete_pando_artifact_fenced(
            &pool_d2,
            store_d2.as_ref(),
            auth_id,
            to_owner,
            retention::NAMESPACE_CIPHER,
            &sha_b_d,
            None,
            deadline,
        )
        .await
    });
    del_entered_b.await;

    assert!(run_phase_rekey(&pool, xfer_b, &copied_b, deadline).await.is_err(), "rekey must reject deleting artifact");
    let owner_b: Uuid = c.query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&repo_b]).await.unwrap().get(0);
    assert_eq!(owner_b, from_owner, "failed rekey must preserve from_owner");
    let link_b: Uuid = c
        .query_one("SELECT tenant_id FROM pando_manifest_artifacts WHERE manifest_id=$1", &[&manifest_b])
        .await
        .unwrap()
        .get(0);
    assert_eq!(link_b, from_owner);
    mock.release_first_delete.notify_one();
    assert!(deleter_b.await.unwrap().unwrap());
    assert!(store.head(&src_a, deadline).await.unwrap().is_some());
    assert!(store.head(&src_b, deadline).await.unwrap().is_some());

    server.abort();
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn legacy_unlinked_rollback_preserves_shared_key_across_concurrent_second_transfer() {
    let Some((pool, _)) = setup_migrated_pool().await else {
        return;
    };
    let mock = Arc::new(MockRemoteS3::new());
    let (store, server) = start_s3(mock.clone()).await;
    let dir = std::env::temp_dir().join(format!("ry-xfer-legacy-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();

    let (from_1, from_2, to_owner) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    seed_user(&pool, from_1, "u1").await;
    seed_user(&pool, from_2, "u2").await;
    seed_user(&pool, to_owner, "ut").await;
    let c = pool.get().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);

    let legacy_bytes = b"shared-legacy-v1-pack";
    let sha = hex::encode(Sha256::digest(legacy_bytes));
    let payload_path = dir.join("legacy.bin");
    tokio::fs::write(&payload_path, legacy_bytes).await.unwrap();
    let src_1 = ObjectKey::new(from_1, retention::NAMESPACE_CIPHER, &sha).unwrap();
    let src_2 = ObjectKey::new(from_2, retention::NAMESPACE_CIPHER, &sha).unwrap();
    let dst_legacy = ObjectKey::new(to_owner, retention::NAMESPACE_CIPHER, &sha).unwrap();
    store.put_file(&src_1, &payload_path, legacy_bytes.len() as u64, deadline).await.unwrap();
    store.put_file(&src_2, &payload_path, legacy_bytes.len() as u64, deadline).await.unwrap();

    let (repo_1, repo_2, xfer_1, xfer_2) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    c.execute(
        "INSERT INTO repositories(id, owner_id, name, state) VALUES($1,$2,'leg-1','ready'),($3,$4,'leg-2','ready')",
        &[&repo_1, &from_1, &repo_2, &from_2],
    )
    .await
    .unwrap();
    for (rid, oid) in [(repo_1, from_1), (repo_2, from_2)] {
        let mj = json!({"tenant_id": oid.to_string(), "pack_cipher": {"sha256": sha, "size": legacy_bytes.len()}});
        c.execute(
            "INSERT INTO pando_pack_manifests \
             (id, repository_id, tenant_id, storage_generation, object_format, manifest) \
             VALUES($1,$2,$3,1,'sha1',$4)",
            &[&Uuid::new_v4(), &rid, &oid, &mj],
        )
        .await
        .unwrap();
    }
    seed_transfer_row(&c, xfer_1, repo_1, from_1, to_owner, "leg-1", "w1").await;
    seed_transfer_row(&c, xfer_2, repo_2, from_2, to_owner, "leg-2", "w2").await;

    let (mut copied_1, mut seen_1) = (Vec::new(), BTreeSet::new());
    let (mut copied_2, mut seen_2) = (Vec::new(), BTreeSet::new());
    copy_pando_objects_with_store(
        &pool,
        store.as_ref(),
        &PandoTransferCopy {
            transfer_lease: Some((xfer_1, "w1", 1)),
            repo_id: repo_1,
            from_owner: from_1,
            to_owner,
            stage_dir: &dir,
            deadline,
        },
        &mut copied_1,
        &mut seen_1,
    )
    .await
    .unwrap();
    copy_pando_objects_with_store(
        &pool,
        store.as_ref(),
        &PandoTransferCopy {
            transfer_lease: Some((xfer_2, "w2", 1)),
            repo_id: repo_2,
            from_owner: from_2,
            to_owner,
            stage_dir: &dir,
            deadline,
        },
        &mut copied_2,
        &mut seen_2,
    )
    .await
    .unwrap();

    // Transfer 1 rolls back BEFORE Transfer 2 commits rekey; un-fenced legacy destination key MUST stay intact!
    c.execute(
        "UPDATE repository_transfers SET state = 'rolling_back', copied_objects = $2 WHERE id = $1",
        &[&xfer_1, &serde_json::to_value(&copied_1).unwrap()],
    )
    .await
    .unwrap();
    cleanup_rollback_objects_with_stores(
        &pool,
        xfer_1,
        "w1",
        1,
        repo_1,
        to_owner,
        &copied_1,
        Some(store.as_ref()),
        store.as_ref(),
        Some(store.as_ref()),
        deadline,
    )
    .await
    .unwrap();

    run_phase_rekey(&pool, xfer_2, &copied_2, deadline).await.unwrap();
    let owner_2: Uuid = c.query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&repo_2]).await.unwrap().get(0);
    assert_eq!(owner_2, to_owner);
    assert!(
        store.head(&dst_legacy, deadline).await.unwrap().is_some(),
        "un-fenced legacy key preserved across second transfer"
    );
    assert!(store.head(&src_1, deadline).await.unwrap().is_some());

    server.abort();
    let _ = tokio::fs::remove_dir_all(&dir).await;
}
