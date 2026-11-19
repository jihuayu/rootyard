//! Crash/cancel lifecycle drills for the W8-A paired restore guard, marker and fence.
use std::path::{Path, PathBuf};

use anyhow::{Result, bail, ensure};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use rootyard::backup::w8a_paired::{W8aCreateReceipt, W8aError, W8aPairedSidecarManifest, check, restore};

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
    drop(restoring);
    paused.release.notify_one();
    server.clear_intercepts();
    tokio::task::yield_now().await;
    ensure!(has_restore_in_progress(&url).await?, "cancelled restore cleared its database marker");
    ensure!(startup_guard(&config.data_dir).exists(), "cancelled restore cleared its startup guard");
    ensure!(!config.data_dir.exists() && !compute.exists(), "cancelled restore published or kept local state");
    ensure!(!has_partial_staging(temp)?, "cancelled restore kept a partial staging directory");
    let _ = seed::drop_database(admin, &database).await;
    Ok(())
}
