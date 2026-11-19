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
    rehome_restored_repositories_realm,
};
use super::mtls_raft::{DurableRaftFreezeRecord, MtlsLiveRaftBackend};
use super::pg_cutpoint::{pg_err, sync_restored_pg_projection_cursors};
use super::pg_freeze_settings::{
    set_pg_database_freeze_marker, set_pg_database_read_only, terminate_and_await_other_pg_sessions,
};
use super::pg_restore_admission::verify_pg_restored_cursors;
use super::production_runtime::PairedProductionRuntimeGuard;
use super::quorum_wal::DurableRaftBackend;
use super::types::{NewIncarnationAuthority, PairedBackupError, RestoreOutcome};

/// Complete result of the staged restore + new-incarnation installation before publication.
type RestoredIncarnation = (Client, NewIncarnationAuthority, DurableRaftFreezeRecord, usize);

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
        Ok((dst_client, inc, boot_freeze, git_verified_refs))
    }
    .await;
    let (dst_client, inc, boot_freeze, git_verified_refs) = match restored {
        Ok(restored) => restored,
        Err(err) => {
            // Nothing was published: discard only the private staging copy. The target guard stays
            // on disk and the PG freeze/read-only fences stay armed, so startup cannot admit it.
            let _ = std::fs::remove_dir_all(&stage_root);
            return Err(err);
        }
    };

    // Everything that can still fail has committed: publish the staged volume with one rename.
    if dst_config.data_dir.exists() {
        return Err(PairedBackupError::FreezeNotHeld(
            "restore target data_dir already exists; refusing to publish a restored volume over it",
        ));
    }
    std::fs::rename(&staged_data, &dst_config.data_dir)?;
    let _ = std::fs::remove_dir_all(&stage_root);

    let boot_thaw =
        boot_record(&manifest, &inc, false, boot_freeze.barrier_id, Some(manifest.paired_cut_digest.clone()))?;
    for pr in booted_peer_rafts.values() {
        pr.write_freeze_record(&boot_thaw)?;
    }
    booted_active_raft.write_freeze_record(&boot_thaw)?;
    dst_client
        .execute(
            "UPDATE public.pando_storage_authorities \
             SET remote_delete_fenced = false, remote_delete_fence_reason = NULL WHERE singleton = true",
            &[],
        )
        .await
        .map_err(pg_err)?;
    set_pg_database_read_only(&dst_client, false).await?;
    set_pg_database_freeze_marker(&dst_client, None).await?;
    set_restore_in_progress(&dst_client, None).await?;
    terminate_and_await_other_pg_sessions(&dst_client, Duration::from_secs(5)).await?;
    dst_client
        .batch_execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE; RESET default_transaction_read_only")
        .await
        .map_err(pg_err)?;
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

async fn install_new_incarnation_on_restored_schema151(
    client: &mut Client,
    manifest: &Format30PairedManifest,
    captured_repos: &[RestoredRepoCapture],
) -> Result<NewIncarnationAuthority, PairedBackupError> {
    let gate_auth_e = manifest.pg_cutpoint.repositories.iter().map(|r| r.authority_epoch).max().unwrap_or(1).max(1);
    let active_grp_e = manifest.pg_cutpoint.repositories.iter().map(|r| r.group_epoch).max().unwrap_or(1).max(1);
    let max_floor = manifest
        .raft_cutpoint
        .close_receipts
        .iter()
        .map(|r| r.authz_floor)
        .max()
        .unwrap_or(1)
        .max(manifest.pg_cutpoint.max_decision_scope_version);
    let new_authz_floor = max_floor.saturating_add(10);
    let requested_deleter_epoch = manifest.freeze.fenced_deleter_epoch.saturating_add(1);
    let deleter_floor_i64 = i64::try_from(requested_deleter_epoch).unwrap_or(i64::MAX);

    let new_cluster_inc = Uuid::new_v4();
    let new_storage_auth = Uuid::new_v4();
    let new_storage_gen = manifest.pg_cutpoint.source_storage_generation.saturating_add(2);
    let new_history_inc = Uuid::new_v4();
    let new_auth_epoch = gate_auth_e.saturating_add(1);
    let max_peer_grp_e = manifest.raft_cutpoint.group_epochs.values().copied().max().unwrap_or(1);
    let new_grp_epoch = active_grp_e.max(max_peer_grp_e).saturating_add(1);

    let tx = client.transaction().await.map_err(pg_err)?;
    tx.batch_execute("SET LOCAL session_replication_role = replica").await.map_err(pg_err)?;
    tx.execute(
        "UPDATE public.cluster_authority SET incarnation = $1, rotated_at = clock_timestamp() WHERE singleton = true",
        &[&new_cluster_inc],
    )
    .await
    .map_err(pg_err)?;
    let srow = tx
        .query_one(
            "UPDATE public.pando_storage_authorities \
             SET authority_id = $1, generation = GREATEST(generation + 1, $2), \
                 restore_generation = GREATEST(restore_generation + 1, $3), \
                 authority_epoch = $4, remote_delete_fenced = true, \
                 remote_delete_fence_reason = 'restore-boot-in-progress', rotated_at = clock_timestamp() \
             WHERE singleton = true \
             RETURNING generation, authority_epoch, restore_generation",
            &[&new_storage_auth, &new_storage_gen, &deleter_floor_i64, &new_auth_epoch],
        )
        .await
        .map_err(pg_err)?;
    let (actual_storage_gen, actual_auth_e): (i64, i64) = (srow.get(0), srow.get(1));
    let new_deleter_epoch = u64::try_from(srow.get::<_, i64>(2)).unwrap_or(requested_deleter_epoch);

    tx.execute("UPDATE public.tokens SET revoked = true WHERE NOT revoked", &[]).await.map_err(pg_err)?;
    tx.execute(
        "UPDATE public.ref_store_publication_decisions \
         SET state = 'CANCELLED', closed_code = 'restored_new_incarnation', \
             cancelled_at = clock_timestamp(), cancel_change_id = $1 \
         WHERE state = 'OPEN'",
        &[&Uuid::new_v4()],
    )
    .await
    .map_err(pg_err)?;

    tx.execute(
        "INSERT INTO public.ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
         VALUES('authority', $1, $2, 'CLOSING', $3) \
         ON CONFLICT (scope_kind, scope_id) DO UPDATE \
         SET state = 'CLOSING', \
             version = GREATEST(public.ref_store_decision_scopes.version, EXCLUDED.version), \
             change_id = COALESCE(public.ref_store_decision_scopes.change_id, EXCLUDED.change_id)",
        &[&manifest.pg_cutpoint.source_storage_authority_id, &new_authz_floor, &Uuid::new_v4()],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "INSERT INTO public.ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
         VALUES('authority', $1, $2, 'OPEN', NULL) \
         ON CONFLICT (scope_kind, scope_id) DO UPDATE \
         SET version = GREATEST(public.ref_store_decision_scopes.version, EXCLUDED.version)",
        &[&new_storage_auth, &new_authz_floor],
    )
    .await
    .map_err(pg_err)?;
    tx.execute(
        "UPDATE public.ref_store_decision_scopes SET version = GREATEST(version, $1) WHERE state = 'OPEN'",
        &[&new_authz_floor],
    )
    .await
    .map_err(pg_err)?;
    for repo in &manifest.pg_cutpoint.repositories {
        for kind in ["repo_access", "repo_lifecycle"] {
            tx.execute(
                "INSERT INTO public.ref_store_decision_scopes(scope_kind, scope_id, version, state, change_id) \
                 VALUES($1, $2, $3, 'OPEN', NULL) \
                 ON CONFLICT (scope_kind, scope_id) DO UPDATE \
                 SET version = GREATEST(public.ref_store_decision_scopes.version, EXCLUDED.version)",
                &[&kind, &repo.repository_id, &new_authz_floor],
            )
            .await
            .map_err(pg_err)?;
        }
    }
    rehome_restored_repositories_realm(&tx, captured_repos, new_history_inc, actual_auth_e, new_grp_epoch).await?;
    tx.batch_execute(
        "SET LOCAL session_replication_role = DEFAULT; \
         DELETE FROM public.ref_store_core_serving_reads; \
         DELETE FROM public.ref_cas_projection_jobs; \
         DELETE FROM public.ref_cas_projected_refs; \
         DELETE FROM public.ref_cas_projected_events; \
         DELETE FROM public.ref_cas_projected_operations;",
    )
    .await
    .map_err(pg_err)?;
    tx.commit().await.map_err(pg_err)?;

    let mut fenced_inc = BTreeSet::from([
        manifest.pg_cutpoint.source_cluster_incarnation,
        manifest.pg_cutpoint.source_storage_authority_id,
    ]);
    for repo in &manifest.pg_cutpoint.repositories {
        fenced_inc.insert(repo.history_incarnation);
    }
    for peer in &manifest.raft_cutpoint.peer_groups {
        for gate in &peer.snapshot.body.gates {
            fenced_inc.insert(gate.history_incarnation);
        }
    }
    let fenced_decisions: BTreeSet<Uuid> =
        manifest.raft_cutpoint.snapshot.body.decisions.iter().map(|d| d.decision_id).collect();
    Ok(NewIncarnationAuthority {
        new_cluster_incarnation: new_cluster_inc,
        new_storage_authority_id: new_storage_auth,
        new_storage_generation: actual_storage_gen,
        new_history_incarnation: new_history_inc,
        new_authority_epoch: actual_auth_e,
        new_group_epoch: new_grp_epoch,
        new_authz_floor,
        new_deleter_epoch,
        fenced_prior_incarnations: fenced_inc,
        fenced_pre_backup_decision_ids: fenced_decisions,
    })
}
