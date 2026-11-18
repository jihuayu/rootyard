//! Rollback fence-cleanup, uncleaned fail-closed, and incremental
//! crash-recovery tests for authority-scoped Pando transfers (#85).
use super::{
    transfer_exec::parse_tenant_key,
    transfer_lease::load_record_with_lock,
    transfer_model::CopiedRemoteObject,
    transfer_pando::{PandoTransferCopy, copy_pando_objects_with_store},
    transfer_pando_tests::{seed_linked_repo_manifest, seed_transfer_row, seed_user, setup_migrated_pool},
    transfer_remote::cleanup_rollback_objects_with_stores,
    transfer_remote_tests::{MockRemoteS3, start_s3},
};
use crate::{
    pando_gateway::retention,
    storage::remote_objects::{ObjectKey, RemoteObjectStore},
};
use deadpool_postgres::{Client, Pool};
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

struct CopiedTransferFixture {
    repo_id: Uuid,
    manifest_id: Uuid,
    sha: String,
    src: ObjectKey,
    dst: ObjectKey,
    xfer_id: Uuid,
    copied: Vec<CopiedRemoteObject>,
}

struct RbCtx<'a> {
    pool: &'a Pool,
    c: &'a Client,
    store: &'a RemoteObjectStore,
    dir: &'a Path,
    auth_id: Uuid,
    deadline: Instant,
}

async fn setup_copied_transfer(
    ctx: &RbCtx<'_>,
    from_owner: Uuid,
    to_owner: Uuid,
    repo_name: &str,
    payload: &[u8],
) -> CopiedTransferFixture {
    let (repo_id, manifest_id, sha, src) =
        seed_linked_repo_manifest(ctx.c, ctx.store, ctx.dir, ctx.auth_id, from_owner, repo_name, payload, ctx.deadline)
            .await;
    let xfer_id = Uuid::new_v4();
    seed_transfer_row(ctx.c, xfer_id, repo_id, from_owner, to_owner, repo_name, "w1").await;
    let (mut copied, mut seen) = (Vec::new(), BTreeSet::new());
    copy_pando_objects_with_store(
        ctx.pool,
        ctx.store,
        &PandoTransferCopy {
            transfer_lease: Some((xfer_id, "w1", 1)),
            repo_id,
            from_owner,
            to_owner,
            stage_dir: ctx.dir,
            deadline: ctx.deadline,
        },
        &mut copied,
        &mut seen,
    )
    .await
    .unwrap();
    let dst = parse_tenant_key(to_owner, &copied[0].to_key).unwrap();
    assert!(ctx.store.head(&dst, ctx.deadline).await.unwrap().is_some());
    CopiedTransferFixture { repo_id, manifest_id, sha, src, dst, xfer_id, copied }
}

async fn run_rollback(ctx: &RbCtx<'_>, fx: &CopiedTransferFixture, to_owner: Uuid) -> anyhow::Result<()> {
    cleanup_rollback_objects_with_stores(
        ctx.pool,
        fx.xfer_id,
        "w1",
        1,
        fx.repo_id,
        to_owner,
        &fx.copied,
        None,
        ctx.store,
        Some(ctx.store),
        ctx.deadline,
    )
    .await
}

async fn artifact_state_and_active_lease(
    ctx: &RbCtx<'_>,
    to_owner: Uuid,
    sha: &str,
) -> (String, bool, Option<Uuid>, Option<String>) {
    let row = ctx
        .c
        .query_one(
            "SELECT state, (lease_until IS NOT NULL AND lease_until > clock_timestamp()), claimed_by, last_error \
             FROM pando_remote_artifacts WHERE authority_id=$1 AND tenant_id=$2 AND namespace=$3 AND sha256=$4",
            &[&ctx.auth_id, &to_owner, &retention::NAMESPACE_CIPHER, &sha],
        )
        .await
        .unwrap();
    (row.get(0), row.get(1), row.get(2), row.get(3))
}

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
    let ctx = RbCtx { pool: &pool, c: &c, store: store.as_ref(), dir: &dir, auth_id, deadline };

    // 1. Clean DELETE 204 pre-rekey rollback deletes own fences, target row & S3 bytes (`rolled_back`), keeping src.
    let fx_a = setup_copied_transfer(&ctx, from_owner, to_owner, "rb-a", b"rb-pack-a").await;
    c.execute("UPDATE repository_transfers SET state = 'rolling_back' WHERE id = $1", &[&fx_a.xfer_id]).await.unwrap();
    run_rollback(&ctx, &fx_a, to_owner).await.unwrap();
    c.execute("UPDATE repository_transfers SET state = 'rolled_back' WHERE id = $1", &[&fx_a.xfer_id]).await.unwrap();
    assert_eq!(
        c.query_one("SELECT count(*) FROM pando_publication_fences WHERE manifest_id = $1", &[&fx_a.manifest_id])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(artifact_state_and_active_lease(&ctx, to_owner, &fx_a.sha).await.0, "deleted");
    assert_eq!(
        c.query_one("SELECT state FROM repository_transfers WHERE id = $1", &[&fx_a.xfer_id])
            .await
            .unwrap()
            .get::<_, String>(0),
        "rolled_back"
    );
    assert!(store.head(&fx_a.dst, deadline).await.unwrap().is_none(), "rolled back target S3 bytes removed");
    assert!(store.head(&fx_a.src, deadline).await.unwrap().is_some(), "source S3 bytes preserved");

    // 2. Concurrent other-repo pending fence on `to_owner` for the same SHA MUST be preserved by rollback.
    let fx_s = setup_copied_transfer(&ctx, from_owner, to_owner, "rb-s", b"rb-shared-s").await;
    let other_manifest = Uuid::new_v4();
    c.execute(
        "INSERT INTO pando_publication_fences(manifest_id, authority_id, tenant_id, namespace, sha256, lease_until) \
         VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '120 seconds')",
        &[&other_manifest, &auth_id, &to_owner, &retention::NAMESPACE_CIPHER, &fx_s.sha],
    )
    .await
    .unwrap();
    c.execute("UPDATE repository_transfers SET state = 'rolling_back' WHERE id = $1", &[&fx_s.xfer_id]).await.unwrap();
    run_rollback(&ctx, &fx_s, to_owner).await.unwrap();
    assert_eq!(
        c.query_one("SELECT count(*) FROM pando_publication_fences WHERE manifest_id = $1", &[&fx_s.manifest_id])
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
    assert_eq!(artifact_state_and_active_lease(&ctx, to_owner, &fx_s.sha).await.0, "active");
    assert!(store.head(&fx_s.dst, deadline).await.unwrap().is_some());

    server.abort();
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn scoped_pando_copy_delete_500_quarantines_and_fails_closed_until_lease_expiry() {
    let Some((pool, auth_id)) = setup_migrated_pool().await else {
        return;
    };
    let mock = Arc::new(MockRemoteS3::new());
    let (store, server) = start_s3(mock.clone()).await;
    let dir = std::env::temp_dir().join(format!("ry-pando-q-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();

    let (from_owner, to_owner) = (Uuid::new_v4(), Uuid::new_v4());
    seed_user(&pool, from_owner, "qfrom").await;
    seed_user(&pool, to_owner, "qto").await;
    let c = pool.get().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let ctx = RbCtx { pool: &pool, c: &c, store: store.as_ref(), dir: &dir, auth_id, deadline };

    let fx = setup_copied_transfer(&ctx, from_owner, to_owner, "rb-q", b"rb-pack-q").await;
    c.execute("UPDATE repository_transfers SET state = 'rolling_back' WHERE id = $1", &[&fx.xfer_id]).await.unwrap();

    // 1. DELETE 500 cleans own fence, quarantines target artifact in `'deleting'` with active 120s lease, keeps `rolling_back`.
    mock.fail_deletes_500.store(true, Ordering::SeqCst);
    assert!(run_rollback(&ctx, &fx, to_owner).await.is_err());
    assert_eq!(
        c.query_one("SELECT count(*) FROM pando_publication_fences WHERE manifest_id = $1", &[&fx.manifest_id])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let (st, lease_active, claimed_by, last_err) = artifact_state_and_active_lease(&ctx, to_owner, &fx.sha).await;
    assert_eq!(st, "deleting");
    assert!(lease_active, "failed remote delete must retain active 120s quarantine lease");
    assert!(claimed_by.is_some());
    assert!(last_err.is_some());
    assert_eq!(
        c.query_one("SELECT state FROM repository_transfers WHERE id = $1", &[&fx.xfer_id])
            .await
            .unwrap()
            .get::<_, String>(0),
        "rolling_back"
    );

    // 2. Immediate retry within active 120s lease MUST continue to fail closed even after S3 recovers.
    mock.fail_deletes_500.store(false, Ordering::SeqCst);
    assert!(
        run_rollback(&ctx, &fx, to_owner).await.is_err(),
        "retry during active 120s deleting lease must fail closed"
    );
    let (st2, lease_active2, _, _) = artifact_state_and_active_lease(&ctx, to_owner, &fx.sha).await;
    assert_eq!(st2, "deleting");
    assert!(lease_active2);
    assert_eq!(
        c.query_one("SELECT state FROM repository_transfers WHERE id = $1", &[&fx.xfer_id])
            .await
            .unwrap()
            .get::<_, String>(0),
        "rolling_back"
    );
    assert!(store.head(&fx.dst, deadline).await.unwrap().is_some(), "active lease blocks premature delete");

    // 3. Only once the 120s lease has expired can rollback reclaim `'deleting'`, delete S3 bytes, and finalize `'rolled_back'`.
    c.execute(
        "UPDATE pando_remote_artifacts SET lease_until = clock_timestamp() - interval '1 second' \
         WHERE authority_id=$1 AND tenant_id=$2 AND namespace=$3 AND sha256=$4",
        &[&auth_id, &to_owner, &retention::NAMESPACE_CIPHER, &fx.sha],
    )
    .await
    .unwrap();
    run_rollback(&ctx, &fx, to_owner).await.unwrap();
    c.execute("UPDATE repository_transfers SET state = 'rolled_back' WHERE id = $1", &[&fx.xfer_id]).await.unwrap();
    let (st3, lease_active3, claimed_by3, last_err3) = artifact_state_and_active_lease(&ctx, to_owner, &fx.sha).await;
    assert_eq!(st3, "deleted");
    assert!(!lease_active3);
    assert!(claimed_by3.is_none());
    assert!(last_err3.is_none());
    assert!(store.head(&fx.dst, deadline).await.unwrap().is_none());
    assert!(store.head(&fx.src, deadline).await.unwrap().is_some());
    assert_eq!(
        c.query_one("SELECT state FROM repository_transfers WHERE id = $1", &[&fx.xfer_id])
            .await
            .unwrap()
            .get::<_, String>(0),
        "rolled_back"
    );

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

    // Allow 1st artifact transfer (src GET #0, LegacyS3Store verify GET #1, put_file readback GET #2); fail 2nd GET (#3).
    mock.gets.store(0, Ordering::SeqCst);
    mock.fail_gets_after.store(3, Ordering::SeqCst);
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
    for (ns, sha, expected_state) in
        [(retention::NAMESPACE_CIPHER, &sha_1, "active"), (retention::NAMESPACE_ENVELOPE, &sha_2, "reserved")]
    {
        assert_eq!(
            c.query_one(
                "SELECT state FROM pando_remote_artifacts WHERE authority_id=$1 AND tenant_id=$2 AND namespace=$3 AND sha256=$4",
                &[&auth_id, &to_owner, &ns, sha],
            )
            .await
            .unwrap()
            .get::<_, String>(0),
            expected_state
        );
    }
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
