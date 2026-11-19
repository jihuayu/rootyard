//! Clean-room `schema 151` / `format 30` restore + new-incarnation installation & boot
//! onto fresh PostgreSQL 17, isolated `BlobStore`, and fresh 3-voter mTLS Raft clusters (#153).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio_postgres::Client;
use uuid::Uuid;

use crate::blob_store::opendal::BlobStore;
use crate::config::Config;

use super::admission_guard::IncarnationAdmissionGuard;
use super::format30_boot_raft::{boot_active_and_peer_mtls_raft_incarnation, boot_record};
use super::format30_paired::{FORMAT30_SUBDIR, Format30PairedManifest, verify_format30_paired_archive};
use super::format30_realm_rehome::{
    RestoredRepoCapture, capture_restored_repositories_for_rebind, rebind_restored_repositories_in_new_realm,
};
use super::mtls_raft::MtlsLiveRaftBackend;
use super::pg_cutpoint::{pg_err, sync_restored_pg_projection_cursors};
use super::pg_freeze_settings::{
    set_pg_database_freeze_marker, set_pg_database_read_only, terminate_and_await_other_pg_sessions,
};
use super::pg_restore_admission::verify_pg_restored_cursors;
use super::production_runtime::PairedProductionRuntimeGuard;
use super::quorum_wal::DurableRaftBackend;
use super::types::{NewIncarnationAuthority, PairedBackupError, RestoreOutcome};

/// Complete result of the staged restore + new-incarnation installation before publication.
type RestoredIncarnation = (Client, NewIncarnationAuthority, usize);

/// Restore the complete `schema 151` / `format 30` archive (`pg_restore` + `BlobStore` rebuild) into
/// a brand-new PG 17 database + target `BlobStore`, and **install + boot** the new incarnation
/// (`new_cluster_incarnation` + restored `authz_floor` + `deleter_epoch` floor + revoked pre-restore
/// tokens/decisions) onto both the restored `schema 151` PG DB and fresh 3-voter mTLS Raft clusters.
pub async fn restore_and_boot_format30_new_incarnation(
    archive_dir: &Path,
    work_dir: &Path,
    dst_config: &Config,
    target_store: &BlobStore,
    booted_active_raft: &mut MtlsLiveRaftBackend,
    booted_peer_rafts: &mut BTreeMap<i64, MtlsLiveRaftBackend>,
) -> Result<(RestoreOutcome, IncarnationAdmissionGuard), PairedBackupError> {
    restore_and_boot_format30_inner(
        archive_dir,
        work_dir,
        dst_config,
        target_store,
        booted_active_raft,
        booted_peer_rafts,
        || {},
    )
    .await
}

/// Fault-injection entry point: `before_thaw` runs inside the fallible restore block after the
/// restored PostgreSQL cursors verify and immediately before the frozen boot record is thawed across
/// every Raft group, so a live test can partition the quorum while the volume is still unpublished.
#[doc(hidden)]
pub async fn restore_and_boot_format30_with_pre_thaw_hook(
    archive_dir: &Path,
    work_dir: &Path,
    dst_config: &Config,
    target_store: &BlobStore,
    booted_active_raft: &mut MtlsLiveRaftBackend,
    booted_peer_rafts: &mut BTreeMap<i64, MtlsLiveRaftBackend>,
    before_thaw: impl FnOnce(),
) -> Result<(RestoreOutcome, IncarnationAdmissionGuard), PairedBackupError> {
    restore_and_boot_format30_inner(
        archive_dir,
        work_dir,
        dst_config,
        target_store,
        booted_active_raft,
        booted_peer_rafts,
        before_thaw,
    )
    .await
}

async fn restore_and_boot_format30_inner(
    archive_dir: &Path,
    work_dir: &Path,
    dst_config: &Config,
    target_store: &BlobStore,
    booted_active_raft: &mut MtlsLiveRaftBackend,
    booted_peer_rafts: &mut BTreeMap<i64, MtlsLiveRaftBackend>,
    before_thaw: impl FnOnce(),
) -> Result<(RestoreOutcome, IncarnationAdmissionGuard), PairedBackupError> {
    let backend_hex = target_store.backend_identity().as_hex().to_owned();
    let manifest = verify_format30_paired_archive(archive_dir, Some(&backend_hex))?;
    let fmt30_dir = archive_dir.join(FORMAT30_SUBDIR);

    let expected_peer_ids: BTreeSet<i64> = manifest.raft_cutpoint.peer_groups.iter().map(|p| p.group_id).collect();
    let provided_peer_ids: BTreeSet<i64> = booted_peer_rafts.keys().copied().collect();
    if expected_peer_ids != provided_peer_ids {
        return Err(PairedBackupError::IncompleteCut(
            "restore target peer Raft group set does not match archived peer_groups",
        ));
    }

    // Refuse to restore into a dirty/previous incarnation: every configured target voter must be a
    // brand-new empty `raft-node` replica that never hosted this backup's cluster or authority.
    let forbidden_incarnations = BTreeSet::from([
        manifest.pg_cutpoint.source_cluster_incarnation,
        manifest.pg_cutpoint.source_storage_authority_id,
    ]);
    booted_active_raft.verify_pristine_new_incarnation_target(
        &manifest.raft_cutpoint.group_membership_digest,
        &forbidden_incarnations,
    )?;
    for (&gid, peer) in booted_peer_rafts.iter() {
        let proof =
            manifest.raft_cutpoint.peer_groups.iter().find(|p| p.group_id == gid).ok_or_else(|| {
                PairedBackupError::CutpointSkew(format!("booted peer Raft group {gid} has no cutpoint"))
            })?;
        peer.verify_pristine_new_incarnation_target(&proof.group_membership_digest, &forbidden_incarnations)?;
    }

    // Refuse an already-published target BEFORE writing the crash-persistent guard or touching
    // PostgreSQL: publishing a restored volume over a live one is never recoverable.
    if std::fs::symlink_metadata(&dst_config.data_dir).is_ok() {
        return Err(PairedBackupError::FreezeNotHeld(
            "restore target data_dir already exists; refusing to publish a restored volume over it",
        ));
    }
    crate::backup::ensure_not_restoring(&dst_config.data_dir)
        .map_err(|_| PairedBackupError::FreezeNotHeld("incomplete restore guard blocks target data_dir"))?;

    // PostgreSQL is fenced *before* the target volume is touched. Only the durable freeze marker is
    // armed here: `crate::backup::restore` rejects a pre-existing `rootyard.restore_in_progress`
    // and requires zero sibling sessions, then sets that marker itself inside its `BackupMutex`.
    let marker = format!("restore-boot:{}", manifest.backup_id);
    let parsed: tokio_postgres::Config = dst_config.database_url.parse().map_err(pg_err)?;
    let pre_client =
        crate::db::connect_config(parsed.clone()).await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    set_pg_database_freeze_marker(&pre_client, Some(&marker)).await?;
    terminate_and_await_other_pg_sessions(&pre_client, Duration::from_secs(5)).await?;
    drop(pre_client);
    // Let the terminations settle so `restore` observes `sessions == 0` when it connects.
    tokio::time::sleep(Duration::from_millis(120)).await;

    // Never publish `dst_config.data_dir` before the paired freeze marker and every restored
    // rebind have committed: the volume is restored into a private staging directory and
    // published by exactly one atomic rename once all PostgreSQL + Raft work has committed.
    let stage_root = staging_root(&dst_config.data_dir)?;
    let staged_data = stage_root.join("data");
    let mut staged_config = dst_config.clone();
    staged_config.data_dir = staged_data.clone();
    let guard_path = restore_guard_path(&dst_config.data_dir)?;
    create_private_dir(&stage_root)?;
    write_restore_guard(&guard_path, manifest.backup_id)?;
    let restored: Result<RestoredIncarnation, PairedBackupError> = async {
        crate::backup::restore(
            &staged_config,
            &fmt30_dir,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
        )
        .await
        .map_err(|e| PairedBackupError::Postgres(format!("format 30 backup::restore failed: {e:#}")))?;

        let mut dst_client =
            crate::db::connect_config(parsed.clone()).await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
        dst_client.batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE").await.map_err(pg_err)?;
        set_pg_database_freeze_marker(&dst_client, Some(&marker)).await?;
        set_restore_in_progress(&dst_client, Some(manifest.backup_id)).await?;
        set_pg_database_read_only(&dst_client, true).await?;
        terminate_and_await_other_pg_sessions(&dst_client, Duration::from_secs(5)).await?;

        let captured_repos = capture_restored_repositories_for_rebind(&dst_client, &fmt30_dir, &manifest).await?;
        let inc = install_new_incarnation_on_restored_schema151(&mut dst_client, &manifest, &captured_repos).await?;
        let rebound_packs =
            rebind_restored_repositories_in_new_realm(&mut dst_client, dst_config, target_store, &inc, &captured_repos)
                .await?;
        let boot_freeze = boot_record(&manifest, &inc, true, Uuid::new_v4(), None)?;
        let git_verified_refs = boot_active_and_peer_mtls_raft_incarnation(
            (&fmt30_dir, work_dir),
            &manifest,
            &inc,
            &boot_freeze,
            &rebound_packs,
            booted_active_raft,
            booted_peer_rafts,
        )?;

        let (active_snap, _) = booted_active_raft.durable_state()?;
        let mut peer_snaps = BTreeMap::new();
        for (&gid, pr) in booted_peer_rafts.iter() {
            peer_snaps.insert(gid, pr.durable_state()?.0);
        }
        sync_restored_pg_projection_cursors(
            &mut dst_client,
            manifest.raft_cutpoint.group_id,
            &active_snap,
            &peer_snaps,
        )
        .await?;
        verify_pg_restored_cursors(&dst_client, manifest.raft_cutpoint.group_id, &active_snap, &peer_snaps).await?;
        before_thaw();
        // Thaw every Raft group *inside* the fallible block: a lost quorum here leaves PostgreSQL
        // frozen, the admission guard on disk and `dst_config.data_dir` unpublished.
        let boot_thaw =
            boot_record(&manifest, &inc, false, boot_freeze.barrier_id, Some(manifest.paired_cut_digest.clone()))?;
        for pr in booted_peer_rafts.values() {
            pr.write_freeze_record(&boot_thaw)?;
        }
        booted_active_raft.write_freeze_record(&boot_thaw)?;
        clear_restored_pg_freeze(&dst_client).await?;
        Ok((dst_client, inc, git_verified_refs))
    }
    .await;
    let (dst_client, inc, git_verified_refs) = match restored {
        Ok(restored) => restored,
        Err(err) => {
            // Nothing was published: discard only the private staging copy. The target guard stays
            // on disk and the PG freeze/read-only fences stay armed, so startup cannot admit it.
            let _ = std::fs::remove_dir_all(&stage_root);
            return Err(err);
        }
    };

    // Everything that can still fail has committed: publish the staged volume with one atomic
    // no-replace rename that can never clobber a live or previously restored incarnation.
    if let Err(err) = publish_staged_dir_noreplace(&staged_data, &dst_config.data_dir) {
        let _ = set_pg_database_freeze_marker(&dst_client, Some(&marker)).await;
        let _ = set_pg_database_read_only(&dst_client, true).await;
        let _ = std::fs::remove_dir_all(&stage_root);
        return Err(err);
    }
    let _ = std::fs::remove_dir_all(&stage_root);
    sync_parent_dir(&dst_config.data_dir)?;
    // The crash-persistent admission guard is removed last: only a fully thawed, published
    // incarnation may become visible to service startup.
    std::fs::remove_file(&guard_path)?;

    let guard = IncarnationAdmissionGuard { live: inc.clone() };
    super::startup_wiring::set_installed_production_runtime_guard(Some(
        PairedProductionRuntimeGuard::from_live_authority(guard.clone(), false),
    ));
    let outcome = RestoreOutcome {
        backup_id: manifest.backup_id,
        restored_repos: manifest.pg_cutpoint.repositories.len(),
        restored_blobs: manifest.blob_closure.total_artifacts,
        reused_blobs: 0,
        git_verified_refs,
        incarnation: inc,
    };
    Ok((outcome, guard))
}

/// Clear every restored PostgreSQL fence after the Raft thaw has committed. The volume is still
/// unpublished and the admission guard is still on disk, so no service can observe this window.
async fn clear_restored_pg_freeze(client: &Client) -> Result<(), PairedBackupError> {
    client
        .execute(
            "UPDATE public.pando_storage_authorities \
             SET remote_delete_fenced = false, remote_delete_fence_reason = NULL WHERE singleton = true",
            &[],
        )
        .await
        .map_err(pg_err)?;
    set_pg_database_read_only(client, false).await?;
    set_pg_database_freeze_marker(client, None).await?;
    set_restore_in_progress(client, None).await?;
    terminate_and_await_other_pg_sessions(client, Duration::from_secs(5)).await?;
    client
        .batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE; RESET default_transaction_read_only")
        .await
        .map_err(pg_err)
}

/// Publish the staged volume with one atomic no-replace directory rename: an existing target is a
/// typed refusal, so a restore can never clobber a live or previously restored incarnation.
pub(super) fn publish_staged_dir_noreplace(staged: &Path, dst: &Path) -> Result<(), PairedBackupError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let src_c = std::ffi::CString::new(staged.as_os_str().as_bytes())
            .map_err(|_| PairedBackupError::InvalidArgument("staged path contains interior NUL"))?;
        let dst_c = std::ffi::CString::new(dst.as_os_str().as_bytes())
            .map_err(|_| PairedBackupError::InvalidArgument("destination path contains interior NUL"))?;
        let rc = unsafe {
            libc::renameat2(libc::AT_FDCWD, src_c.as_ptr(), libc::AT_FDCWD, dst_c.as_ptr(), libc::RENAME_NOREPLACE)
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::EEXIST | libc::ENOTEMPTY))
                || err.kind() == std::io::ErrorKind::AlreadyExists
            {
                return Err(PairedBackupError::FreezeNotHeld(
                    "restore target data_dir already exists; no-replace publish refused",
                ));
            }
            return Err(PairedBackupError::Io(err));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        if std::fs::symlink_metadata(dst).is_ok() {
            return Err(PairedBackupError::FreezeNotHeld(
                "restore target data_dir already exists; no-replace publish refused",
            ));
        }
        std::fs::rename(staged, dst)?;
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent_dir(target: &Path) -> Result<(), PairedBackupError> {
    let parent = target.parent().ok_or(PairedBackupError::FreezeNotHeld("restore target has no parent volume"))?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_target: &Path) -> Result<(), PairedBackupError> {
    Ok(())
}

/// `.<name>.rootyard-restoring` sibling of the final volume, byte-identical to the guard path
/// used by `crate::backup` so startup admission sees the same crash-persistent marker.
fn restore_guard_path(target: &Path) -> Result<PathBuf, PairedBackupError> {
    let path = if target.is_absolute() { target.to_owned() } else { std::env::current_dir()?.join(target) };
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().ok_or(PairedBackupError::FreezeNotHeld("restore target has no volume name"))?);
    name.push(".rootyard-restoring");
    Ok(path.parent().ok_or(PairedBackupError::FreezeNotHeld("restore target has no parent volume"))?.join(name))
}

/// Private staging root next to — never inside — the final volume.
fn staging_root(target: &Path) -> Result<PathBuf, PairedBackupError> {
    let guard = restore_guard_path(target)?;
    let parent = guard.parent().ok_or(PairedBackupError::FreezeNotHeld("restore target has no parent volume"))?;
    Ok(parent.join(format!(".paired-fmt30-stage-{}", Uuid::new_v4())))
}

fn create_private_dir(path: &Path) -> Result<(), PairedBackupError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;
    Ok(())
}

fn write_restore_guard(path: &Path, backup_id: Uuid) -> Result<(), PairedBackupError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    std::io::Write::write_all(&mut file, format!("{backup_id}\n").as_bytes())?;
    file.sync_data()?;
    Ok(())
}

/// PostgreSQL-visible companion marker of the volume guard: readers refuse a database whose
/// `rootyard.restore_in_progress` setting is present, even across a `raft-node` restart.
async fn set_restore_in_progress(client: &Client, backup_id: Option<Uuid>) -> Result<(), PairedBackupError> {
    let database: String = client.query_one("SELECT current_database()", &[]).await.map_err(pg_err)?.get(0);
    let quoted = format!("\"{}\"", database.replace('"', "\"\""));
    let statement = match backup_id {
        Some(id) => format!("ALTER DATABASE {quoted} SET rootyard.restore_in_progress = '{id}'"),
        None => format!("ALTER DATABASE {quoted} RESET rootyard.restore_in_progress"),
    };
    client.batch_execute(&statement).await.map_err(pg_err)
}

/// Install the rotated new incarnation into the restored `schema 151` database: cluster identity,
/// floors, revoked pre-restore authority and `rehome_restored_repositories_realm` for every restored
/// gate/protocol/serving realm row.
async fn install_new_incarnation_on_restored_schema151(
    client: &mut Client,
    manifest: &Format30PairedManifest,
    captured_repos: &[RestoredRepoCapture],
) -> Result<NewIncarnationAuthority, PairedBackupError> {
    let install = super::format30_incarnation::install_new_incarnation_on_restored_schema151;
    install(client, manifest, captured_repos).await
}
