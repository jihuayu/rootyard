//! Crash/cancel lifecycle drills for the W8-A paired restore guard, marker and fence.
use std::path::{Path, PathBuf};

use anyhow::{Result, bail, ensure};
use deadpool_postgres::Pool;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use rootyard::backup::w8a_paired::{W8aCreateReceipt, W8aError, W8aPairedSidecarManifest, check, restore};
use rootyard::events::{self, OperationRecord, RefEventInput};

use crate::s3::{EnvGuard, LoopbackS3};
use crate::seed;

const ADVISORY_KEY: i64 = 738_390_103;

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn startup_guard(target: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(target.file_name().unwrap_or_default());
    name.push(".rootyard-restoring");
    target.parent().unwrap_or_else(|| Path::new(".")).join(name)
}

fn has_partial_staging(root: &Path) -> Result<bool> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".rootyard-restore-") && name.ends_with(".partial") {
                return Ok(true);
            }
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(false)
}

async fn has_restore_in_progress(url: &str) -> Result<bool> {
    let pool = seed::pool_for(url)?;
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_db_role_setting s, unnest(s.setconfig) AS setting \
             WHERE s.setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database()) \
             AND s.setrole=0 AND setting LIKE 'rootyard.restore_in_progress=%')",
            &[],
        )
        .await?;
    Ok(row.get(0))
}

async fn fresh_database(admin: &str) -> Result<(String, String)> {
    let name = format!("w8a_{}", Uuid::new_v4().simple());
    seed::create_database(admin, &name).await?;
    let url = seed::with_database(admin, &name);
    Ok((name, url))
}

fn tampered_epoch_archive(archive: &Path, target: &Path) -> Result<PathBuf> {
    seed::copy_tree(archive, target)?;
    let path = target.join("w8a-paired.json");
    let mut sidecar: W8aPairedSidecarManifest = serde_json::from_slice(&std::fs::read(&path)?)?;
    sidecar.source_storage_authority_epoch += 1;
    let bytes = serde_json::to_vec(&sidecar.seal()?)?;
    std::fs::write(&path, &bytes)?;
    std::fs::write(target.join("W8A_COMPLETE"), sha256(&bytes))?;
    Ok(target.to_path_buf())
}

async fn assert_runtime_startup_refused_with_other_data_dir(
    env: &mut EnvGuard,
    url: &str,
    other_data_dir: &Path,
) -> Result<()> {
    ensure!(
        rootyard::backup::ensure_not_restoring(other_data_dir).is_ok(),
        "separate data_dir unexpectedly had a local guard"
    );
    let pool = seed::pool_for(url)?;
    env.set_opt("ROOTYARD_SCHEMA_MODE", None);
    ensure!(
        rootyard::db::prepare_runtime_schema(&pool).await.is_err(),
        "auto prepare_runtime_schema succeeded against fenced/restoring DB"
    );
    env.set_opt("ROOTYARD_SCHEMA_MODE", Some("external"));
    ensure!(
        rootyard::db::prepare_runtime_schema(&pool).await.is_err(),
        "external prepare_runtime_schema succeeded against fenced/restoring DB"
    );
    env.set_opt("ROOTYARD_SCHEMA_MODE", None);
    Ok(())
}

/// A cleanly restored database must start in both schema modes and must keep
/// `pg_refstore` as the single ref authority while legacy `gitfs` projection
/// stays a plain, rebuildable consumer effect.
pub async fn verify_post_restore_startup_and_projection(
    env: &mut EnvGuard,
    pool: &Pool,
    owner_id: Uuid,
    token_id: Uuid,
    actor_name: &str,
    head_oid: &str,
) -> Result<()> {
    env.set_opt("ROOTYARD_SCHEMA_MODE", None);
    ensure!(
        rootyard::db::prepare_runtime_schema(pool).await.is_ok(),
        "auto prepare_runtime_schema refused the cleanly restored database"
    );
    env.set_opt("ROOTYARD_SCHEMA_MODE", Some("external"));
    ensure!(
        rootyard::db::prepare_runtime_schema(pool).await.is_ok(),
        "external prepare_runtime_schema refused the cleanly restored database"
    );
    env.set_opt("ROOTYARD_SCHEMA_MODE", None);
    let client = pool.get().await?;
    let audit: i64 = client.query_one("SELECT count(*) FROM audit_events", &[]).await?.get(0);
    ensure!(audit == 1, "restored pg_refstore event was not audited exactly once: {audit}");
    let applied: i64 = client
        .query_one("SELECT count(*) FROM event_deliveries WHERE state='delivered' AND effect='applied'", &[])
        .await?
        .get(0);
    ensure!(applied == 2, "restored pg_refstore event was not applied by both workers: {applied}");
    let projection: i64 = client.query_one("SELECT count(*) FROM repository_ref_projection", &[]).await?.get(0);
    ensure!(projection == 0, "pg_refstore outbox event wrote a competing ref projection: {projection}");
    let gitfs_repo = Uuid::new_v4();
    client
        .execute(
            "INSERT INTO repositories(id, owner_id, name, state) VALUES ($1, $2, 'w8a-gitfs-proj', 'ready')",
            &[&gitfs_repo, &owner_id],
        )
        .await?;
    drop(client);
    let operation = OperationRecord {
        id: Uuid::new_v4(),
        repository_id: gitfs_repo,
        actor_id: owner_id,
        token_id,
        service_principal_id: None,
        actor_name: actor_name.to_owned(),
        sequence: 1,
        storage_generation: 1,
        outcome: "recorded".into(),
        evidence: json!({"kind": "w8a_paired_seed"}),
        admission: None,
    };
    let change = RefEventInput {
        transaction_sequence: 1,
        ref_name: "refs/heads/main".into(),
        old_oid: "0".repeat(40),
        new_oid: head_oid.to_owned(),
    };
    events::publish(pool, &operation, &[change]).await?;
    let lease_owner = Uuid::new_v4();
    for consumer in ["audit-log", "ref-index"] {
        while events::worker_once(pool, consumer, lease_owner, 10).await? > 0 {}
    }
    ensure!(events::pending_count(pool).await? == 0, "outbox did not drain after the legacy projection probe");
    let client = pool.get().await?;
    let audit: i64 = client.query_one("SELECT count(*) FROM audit_events", &[]).await?.get(0);
    ensure!(audit == 2, "legacy gitfs outbox event was not audited: {audit}");
    let ref_name = "refs/heads/main";
    let row = client
        .query_one(
            "SELECT oid, source_kind FROM repository_ref_projection WHERE repository_id=$1 AND ref_name=$2",
            &[&gitfs_repo, &ref_name],
        )
        .await?;
    let projected = (row.get::<_, Option<String>>(0), row.get::<_, String>(1));
    ensure!(
        projected == (Some(head_oid.to_owned()), "push_receipt".to_owned()),
        "legacy gitfs ref projection was not applied with push_receipt semantics: {projected:?}"
    );
    Ok(())
}

pub async fn run_lifecycle_guard_drills(
    env: &mut EnvGuard,
    admin: &str,
    temp: &Path,
    git: &Path,
    server: &LoopbackS3,
    archive: &Path,
    created: &W8aCreateReceipt,
) -> Result<()> {
    let tampered = tampered_epoch_archive(archive, &temp.join("tampered-epoch"))?;
    check(&tampered)?;
    let (database, url) = fresh_database(admin).await?;
    env.update(crate::TEST_URL, &url);
    let config = crate::config(url.clone(), temp, "drill-a", git);
    let compute = temp.join("drill-a-compute");
    let refused = restore(&config, &tampered, &compute, true).await;
    ensure!(
        matches!(refused, Err(W8aError::MixedPointInTime(_))),
        "tampered source epoch was not refused as mixed point in time: {refused:?}"
    );
    ensure!(has_restore_in_progress(&url).await?, "database restore marker did not persist");
    ensure!(startup_guard(&config.data_dir).exists(), "startup guard did not persist");
    ensure!(
        rootyard::backup::ensure_not_restoring(&config.data_dir).is_err(),
        "local startup guard is not observed by the pre-start check"
    );
    ensure!(!config.data_dir.exists(), "failed restore published its target");
    ensure!(!compute.exists(), "failed restore kept the compute directory");
    ensure!(!has_partial_staging(temp)?, "failed restore kept a partial staging directory");
    assert_runtime_startup_refused_with_other_data_dir(env, &url, &temp.join("other-serve-a")).await?;
    let _ = seed::drop_database(admin, &database).await;

    let (database, url) = fresh_database(admin).await?;
    env.update(crate::TEST_URL, &url);
    let config = crate::config(url.clone(), temp, "drill-b", git);
    let compute = temp.join("drill-b-compute");
    server.clear();
    server.arm_corrupt_get_at(created.blob_artifact_count + 1);
    let refused = restore(&config, archive, &compute, true).await;
    ensure!(
        matches!(&refused, Err(W8aError::MissingOrCorruptBlobArtifact(_) | W8aError::GitFsckFailed { .. })),
        "corrupt re-export was not refused after the fence: {refused:?}"
    );
    ensure!(has_restore_in_progress(&url).await?, "corrupt restore cleared its database marker");
    ensure!(startup_guard(&config.data_dir).exists(), "corrupt restore cleared its startup guard");
    ensure!(!config.data_dir.exists() && !compute.exists(), "corrupt restore published or kept local state");
    ensure!(!has_partial_staging(temp)?, "corrupt restore kept a partial staging directory");
    assert_runtime_startup_refused_with_other_data_dir(env, &url, &temp.join("other-serve-b")).await?;
    server.clear_intercepts();
    let _ = seed::drop_database(admin, &database).await;

    let (database, url) = fresh_database(admin).await?;
    env.update(crate::TEST_URL, &url);
    let config = crate::config(url.clone(), temp, "drill-c", git);
    let compute = temp.join("drill-c-compute");
    server.clear();
    let paused = server.arm_pause_get_at(created.blob_artifact_count + 1);
    let mut restoring = Box::pin(restore(&config, archive, &compute, true));
    tokio::select! {
        _ = paused.entered.notified() => {}
        result = &mut restoring => bail!("restore finished before the guarded fsck re-export: {result:?}"),
    }
    let pool = seed::pool_for(&url)?;
    let probe = pool.get().await?;
    let lock_free: bool = probe.query_one("SELECT pg_try_advisory_lock($1)", &[&ADVISORY_KEY]).await?.get(0);
    if lock_free {
        probe.query_one("SELECT pg_advisory_unlock($1)", &[&ADVISORY_KEY]).await?;
    }
    ensure!(!lock_free, "restore released the lifecycle barrier while fsck was suspended");
    let shared_free: bool = probe.query_one("SELECT pg_try_advisory_lock_shared($1)", &[&ADVISORY_KEY]).await?.get(0);
    if shared_free {
        probe.query_one("SELECT pg_advisory_unlock_shared($1)", &[&ADVISORY_KEY]).await?;
    }
    ensure!(!shared_free, "restore released the shared lifecycle barrier while fsck was suspended");
    ensure!(
        rootyard::backup::ensure_not_restoring(&config.data_dir).is_err(),
        "local startup guard missing while fsck suspended"
    );
    ensure!(!config.data_dir.exists(), "target published while fsck suspended");
    ensure!(has_restore_in_progress(&url).await?, "DB marker missing while fsck suspended");
    let fenced: bool = probe
        .query_one("SELECT remote_delete_fenced FROM public.pando_storage_authorities WHERE singleton=true", &[])
        .await?
        .get(0);
    ensure!(fenced, "fresh-incarnation fence did not run before the guarded fsck");
    drop(probe);
    drop(pool);
    assert_runtime_startup_refused_with_other_data_dir(env, &url, &temp.join("other-serve-c-live")).await?;
    drop(restoring);
    paused.release.notify_one();
    server.clear_intercepts();
    tokio::task::yield_now().await;
    ensure!(has_restore_in_progress(&url).await?, "cancelled restore cleared its database marker");
    ensure!(startup_guard(&config.data_dir).exists(), "cancelled restore cleared its startup guard");
    ensure!(!config.data_dir.exists() && !compute.exists(), "cancelled restore published or kept local state");
    ensure!(!has_partial_staging(temp)?, "cancelled restore kept a partial staging directory");
    assert_runtime_startup_refused_with_other_data_dir(env, &url, &temp.join("other-serve-c-cancelled")).await?;
    let _ = seed::drop_database(admin, &database).await;
    Ok(())
}
