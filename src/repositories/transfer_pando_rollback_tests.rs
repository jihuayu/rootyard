//! Rollback fence-cleanup, uncleaned fail-closed, and incremental
//! crash-recovery tests for authority-scoped Pando transfers (#85).
use super::{
    transfer_exec::parse_tenant_key,
    transfer_lease::load_record_with_lock,
    transfer_pando::{PandoTransferCopy, copy_pando_objects_with_store},
    transfer_pando_tests::{seed_linked_repo_manifest, seed_transfer_row, seed_user, setup_migrated_pool},
    transfer_remote::cleanup_rollback_objects_with_stores,
    transfer_remote_tests::{MockRemoteS3, start_s3},
};
use crate::{pando_gateway::retention, storage::remote_objects::ObjectKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::time::Instant;
use uuid::Uuid;

#[tokio::test]
async fn scoped_pando_copy_pre_rekey_rollback_cleans_own_fences_rows_and_bytes() {
    let Some((pool, auth_id)) = setup_migrated_pool().await else {
        return;
    };
    let mock = Arc::new(MockRemoteS3::new());
    let (store, server) = start_s3(mock.clone()).await;
    let dir = std::env::temp_dir().join(format!("ry-pando-rb-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();

    let (from_owner, to_owner) = (Uuid::new_v4(), Uuid::new_v4());
    seed_user(&pool, from_owner, "rbfrom").await;
    seed_user(&pool, to_owner, "rbto").await;
    let c = pool.get().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);

    // 1. Unshared scoped copy -> rollback must clear own fences, delete target S3 bytes & mark row deleted.
    let (repo_a, m_a, sha_a, src_a) =
        seed_linked_repo_manifest(&c, store.as_ref(), &dir, auth_id, from_owner, "rb-a", b"rb-pack-a", deadline).await;
    let xfer_a = Uuid::new_v4();
    seed_transfer_row(&c, xfer_a, repo_a, from_owner, to_owner, "rb-a", "w1").await;
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
    let dst_a = parse_tenant_key(to_owner, &copied_a[0].to_key).unwrap();
    assert!(store.head(&dst_a, deadline).await.unwrap().is_some());

    // Simulate failed remote delete once: rollback MUST fail closed instead of masking uncleaned active artifact.
    c.execute("UPDATE repository_transfers SET state = 'rolling_back' WHERE id = $1", &[&xfer_a]).await.unwrap();
    mock.fail_deletes_500.store(true, Ordering::SeqCst);
    assert!(
        cleanup_rollback_objects_with_stores(
            &pool,
            xfer_a,
            "w1",
            1,
            repo_a,
            to_owner,
            &copied_a,
            None,
            store.as_ref(),
            Some(store.as_ref()),
            deadline,
        )
        .await
        .is_err()
    );
    mock.fail_deletes_500.store(false, Ordering::SeqCst);

    // Succeed cleanly once remote S3 delete recovers; transfer's own fence cleared & S3/PG cleaned.
    cleanup_rollback_objects_with_stores(
        &pool,
        xfer_a,
        "w1",
        1,
        repo_a,
        to_owner,
        &copied_a,
        None,
        store.as_ref(),
        Some(store.as_ref()),
        deadline,
    )
    .await
    .unwrap();
    assert_eq!(
        c.query_one("SELECT count(*) FROM pando_publication_fences WHERE manifest_id = $1", &[&m_a])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        c.query_one(
            "SELECT state FROM pando_remote_artifacts WHERE authority_id=$1 AND tenant_id=$2 AND namespace=$3 AND sha256=$4",
            &[&auth_id, &to_owner, &retention::NAMESPACE_CIPHER, &sha_a],
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "deleted"
    );
    assert!(store.head(&dst_a, deadline).await.unwrap().is_none(), "rolled back target S3 bytes removed");
    assert!(store.head(&src_a, deadline).await.unwrap().is_some(), "source S3 bytes preserved");

    // 2. Concurrent other-repo pending fence on `to_owner` for the same SHA MUST be preserved by rollback.
    let (repo_s, m_s, sha_s, _) =
        seed_linked_repo_manifest(&c, store.as_ref(), &dir, auth_id, from_owner, "rb-s", b"rb-shared-s", deadline)
            .await;
    let xfer_s = Uuid::new_v4();
    seed_transfer_row(&c, xfer_s, repo_s, from_owner, to_owner, "rb-s", "w1").await;
    let (mut copied_s, mut seen_s) = (Vec::new(), BTreeSet::new());
    copy_pando_objects_with_store(
        &pool,
        store.as_ref(),
        &PandoTransferCopy {
            transfer_lease: Some((xfer_s, "w1", 1)),
            repo_id: repo_s,
            from_owner,
            to_owner,
            stage_dir: &dir,
            deadline,
        },
        &mut copied_s,
        &mut seen_s,
    )
    .await
    .unwrap();
    let dst_s = parse_tenant_key(to_owner, &copied_s[0].to_key).unwrap();
    let other_manifest = Uuid::new_v4();
    c.execute(
        "INSERT INTO pando_publication_fences(manifest_id, authority_id, tenant_id, namespace, sha256, lease_until) \
         VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '120 seconds')",
        &[&other_manifest, &auth_id, &to_owner, &retention::NAMESPACE_CIPHER, &sha_s],
    )
    .await
    .unwrap();
    c.execute("UPDATE repository_transfers SET state = 'rolling_back' WHERE id = $1", &[&xfer_s]).await.unwrap();
    cleanup_rollback_objects_with_stores(
        &pool,
        xfer_s,
        "w1",
        1,
        repo_s,
        to_owner,
        &copied_s,
        None,
        store.as_ref(),
        Some(store.as_ref()),
        deadline,
    )
    .await
    .unwrap();
    assert_eq!(
        c.query_one("SELECT count(*) FROM pando_publication_fences WHERE manifest_id = $1", &[&m_s])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        c.query_one("SELECT count(*) FROM pando_publication_fences WHERE manifest_id = $1", &[&other_manifest])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1,
        "unrelated publisher fence must survive transfer rollback"
    );
    assert_eq!(
        c.query_one(
            "SELECT state FROM pando_remote_artifacts WHERE authority_id=$1 AND tenant_id=$2 AND namespace=$3 AND sha256=$4",
            &[&auth_id, &to_owner, &retention::NAMESPACE_CIPHER, &sha_s],
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "active"
    );
    assert!(store.head(&dst_s, deadline).await.unwrap().is_some());

    server.abort();
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn incremental_copied_objects_persist_recovers_after_second_object_failure() {
    let Some((pool, auth_id)) = setup_migrated_pool().await else {
        return;
    };
    let mock = Arc::new(MockRemoteS3::new());
    let (store, server) = start_s3(mock.clone()).await;
    let dir = std::env::temp_dir().join(format!("ry-pando-inc-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();

    let (from_owner, to_owner) = (Uuid::new_v4(), Uuid::new_v4());
    seed_user(&pool, from_owner, "incfrom").await;
    seed_user(&pool, to_owner, "incto").await;
    let c = pool.get().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);

    let (bytes_1, bytes_2) = (b"pando-cipher-first-obj", b"pando-envelope-second-obj");
    let (sha_1, sha_2) = (hex::encode(Sha256::digest(bytes_1)), hex::encode(Sha256::digest(bytes_2)));
    let (p1, p2) = (dir.join("c1.bin"), dir.join("e2.bin"));
    tokio::fs::write(&p1, bytes_1).await.unwrap();
    tokio::fs::write(&p2, bytes_2).await.unwrap();
    let src_1 = ObjectKey::scoped(from_owner, auth_id, 1, retention::NAMESPACE_CIPHER, &sha_1).unwrap();
    let src_2 = ObjectKey::scoped(from_owner, auth_id, 1, retention::NAMESPACE_ENVELOPE, &sha_2).unwrap();
    store.put_file(&src_1, &p1, bytes_1.len() as u64, deadline).await.unwrap();
    store.put_file(&src_2, &p2, bytes_2.len() as u64, deadline).await.unwrap();

    let (repo_id, manifest_id, xfer_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    c.execute(
        "INSERT INTO repositories(id, owner_id, name, state) VALUES($1,$2,'inc-repo','ready')",
        &[&repo_id, &from_owner],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO pando_remote_artifacts(authority_id, tenant_id, namespace, sha256, size, object_generation, remote_path, state) \
         VALUES($1,$2,$3,$4,$5,1,$6,'active'), ($1,$2,$7,$8,$9,1,$10,'active')",
        &[
            &auth_id, &from_owner, &retention::NAMESPACE_CIPHER, &sha_1, &(bytes_1.len() as i64), &src_1.path(),
            &retention::NAMESPACE_ENVELOPE, &sha_2, &(bytes_2.len() as i64), &src_2.path(),
        ],
    )
    .await
    .unwrap();
    let mj = json!({"tenant_id": from_owner.to_string()});
    c.execute(
        "INSERT INTO pando_pack_manifests(id, repository_id, tenant_id, storage_generation, object_format, manifest) \
         VALUES($1,$2,$3,1,'sha1',$4)",
        &[&manifest_id, &repo_id, &from_owner, &mj],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO pando_manifest_artifacts(manifest_id, repository_id, authority_id, tenant_id, namespace, sha256, artifact_role) \
         VALUES($1,$2,$3,$4,$5,$6,'pack-cipher'), ($1,$2,$3,$4,$7,$8,'pack-envelope')",
        &[&manifest_id, &repo_id, &auth_id, &from_owner, &retention::NAMESPACE_CIPHER, &sha_1, &retention::NAMESPACE_ENVELOPE, &sha_2],
    )
    .await
    .unwrap();
    seed_transfer_row(&c, xfer_id, repo_id, from_owner, to_owner, "inc-repo", "w1").await;

    // Allow 1st artifact copy + read-back verification (`GET` #0 & #1), fail 2nd artifact's `GET` (#2).
    mock.gets.store(0, Ordering::SeqCst);
    mock.fail_gets_after.store(2, Ordering::SeqCst);
    let (mut copied, mut seen) = (Vec::new(), BTreeSet::new());
    let copy_err = copy_pando_objects_with_store(
        &pool,
        store.as_ref(),
        &PandoTransferCopy {
            transfer_lease: Some((xfer_id, "w1", 1)),
            repo_id,
            from_owner,
            to_owner,
            stage_dir: &dir,
            deadline,
        },
        &mut copied,
        &mut seen,
    )
    .await;
    assert!(copy_err.is_err(), "second artifact GET failure must abort copy");

    // Reload ONLY the durable DB record (simulating crash/restart recovery): 1st (`active`) & 2nd (`reserved`) were persisted!
    mock.fail_gets_after.store(usize::MAX, Ordering::SeqCst);
    c.execute("UPDATE repository_transfers SET state = 'rolling_back' WHERE id = $1", &[&xfer_id]).await.unwrap();
    let mut c_rec = pool.get().await.unwrap();
    let tx_rec = c_rec.transaction().await.unwrap();
    let rec = load_record_with_lock(&tx_rec, xfer_id, false).await.unwrap();
    tx_rec.commit().await.unwrap();
    assert_eq!(rec.copied_objects.len(), 2, "durable record captured activated 1st and reserved 2nd artifacts");
    let dst_1 = parse_tenant_key(to_owner, &rec.copied_objects[0].to_key).unwrap();
    assert!(store.head(&dst_1, deadline).await.unwrap().is_some());

    cleanup_rollback_objects_with_stores(
        &pool,
        xfer_id,
        "w1",
        1,
        repo_id,
        to_owner,
        &rec.copied_objects,
        None,
        store.as_ref(),
        Some(store.as_ref()),
        deadline,
    )
    .await
    .unwrap();
    for (ns, sha) in [(retention::NAMESPACE_CIPHER, &sha_1), (retention::NAMESPACE_ENVELOPE, &sha_2)] {
        assert_eq!(
            c.query_one(
                "SELECT state FROM pando_remote_artifacts WHERE authority_id=$1 AND tenant_id=$2 AND namespace=$3 AND sha256=$4",
                &[&auth_id, &to_owner, &ns, sha],
            )
            .await
            .unwrap()
            .get::<_, String>(0),
            "deleted"
        );
    }
    assert!(store.head(&dst_1, deadline).await.unwrap().is_none(), "activated 1st artifact bytes cleaned by recovery");
    assert_eq!(
        c.query_one("SELECT count(*) FROM pando_publication_fences WHERE manifest_id = $1", &[&manifest_id])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(store.head(&src_1, deadline).await.unwrap().is_some());
    assert!(store.head(&src_2, deadline).await.unwrap().is_some());

    server.abort();
    let _ = tokio::fs::remove_dir_all(&dir).await;
}
