//! Verified isolated restore and capability fencing.
use super::*;

mod verify;
use self::verify::verify;

pub(in crate::backup) struct W8aRestorePlan<'a> {
    pub sidecar: &'a w8a_paired::W8aPairedSidecarManifest,
    pub compute_dir: &'a Path,
}

struct StagingDirGuard {
    path: PathBuf,
    published: bool,
}

impl StagingDirGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, published: false }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn publish_to(&mut self, target: &Path) -> Result<()> {
        publish(&self.path, target)?;
        self.published = true;
        Ok(())
    }
}

impl Drop for StagingDirGuard {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Archives before format20 never recorded a storage backend. For those the
/// restored database's own `storage_backend` is the only authority: it must be
/// a legacy native backend (`gitfs` or `pando`, which own a bare repository;
/// never `pg_refstore`, which has none), and only the comparison copy drops the
/// new field so the repository compares exactly with the fields the archive
/// had. Current formats must record the backend (a current archive decoded
/// without it has `None` here) and match it exactly.
/// Everything else (identity, generation, state, reason, incident, unknown
/// operations, refs and HEAD) is compared unchanged for every format.
pub(super) fn restore_metadata_repositories(
    archived: &[Repository],
    mut restored: Vec<Repository>,
    has_backend: bool,
) -> Result<()> {
    for repo in &mut restored {
        if !has_backend {
            ensure!(
                matches!(repo.backend.as_deref(), Some("gitfs" | "pando")),
                "historical archive restored a repository on a non-native backend"
            );
            repo.backend = None;
        }
        if let Some(old) = archived.iter().find(|old| old.id == repo.id) {
            repo.refs.clone_from(&old.refs);
            repo.head.clone_from(&old.head);
        }
    }
    ensure!(restored == archived, "restored metadata mismatch");
    Ok(())
}

pub fn check(source: &Path) -> Result<()> {
    let source = absolute(source, true)?;
    let manifest = verify(&source)?;
    println!(
        "{}",
        serde_json::json!({"backup_id":manifest.backup_id,"checksums_verified":true,"authenticity_verified":false})
    );
    Ok(())
}

pub async fn restore(
    config: &Config,
    source: &Path,
    allow_legacy_schema007: bool,
    allow_legacy_schema130: bool,
    allow_legacy_schema131: bool,
    allow_legacy_schema132: bool,
    allow_legacy_schema133: bool,
    allow_legacy_schema134: bool,
    allow_legacy_schema135: bool,
    allow_legacy_schema136: bool,
    allow_legacy_schema137: bool,
    allow_legacy_schema138: bool,
    allow_legacy_schema139: bool,
    allow_legacy_schema140: bool,
    allow_legacy_schema141: bool,
    allow_legacy_schema142: bool,
    allow_legacy_schema143: bool,
) -> Result<()> {
    restore_inner(
        config,
        source,
        None,
        allow_legacy_schema007,
        allow_legacy_schema130,
        allow_legacy_schema131,
        allow_legacy_schema132,
        allow_legacy_schema133,
        allow_legacy_schema134,
        allow_legacy_schema135,
        allow_legacy_schema136,
        allow_legacy_schema137,
        allow_legacy_schema138,
        allow_legacy_schema139,
        allow_legacy_schema140,
        allow_legacy_schema141,
        allow_legacy_schema142,
        allow_legacy_schema143,
    )
    .await
    .map(|_| ())
}

pub(in crate::backup) async fn restore_w8a_paired(
    config: &Config,
    source: &Path,
    plan: W8aRestorePlan<'_>,
) -> Result<(authority::W8aFenceReceipt, Vec<w8a_paired::W8aRepoFsckReceipt>)> {
    let outcome = restore_inner(
        config,
        source,
        Some(plan),
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
    .await?;
    outcome.context("W8-A paired restore completed without fence receipt")
}

async fn restore_inner(
    config: &Config,
    source: &Path,
    w8a_plan: Option<W8aRestorePlan<'_>>,
    allow_legacy_schema007: bool,
    allow_legacy_schema130: bool,
    allow_legacy_schema131: bool,
    allow_legacy_schema132: bool,
    allow_legacy_schema133: bool,
    allow_legacy_schema134: bool,
    allow_legacy_schema135: bool,
    allow_legacy_schema136: bool,
    allow_legacy_schema137: bool,
    allow_legacy_schema138: bool,
    allow_legacy_schema139: bool,
    allow_legacy_schema140: bool,
    allow_legacy_schema141: bool,
    allow_legacy_schema142: bool,
    allow_legacy_schema143: bool,
) -> Result<Option<(authority::W8aFenceReceipt, Vec<w8a_paired::W8aRepoFsckReceipt>)>> {
    let started = Instant::now();
    let source = absolute(source, true)?;
    let target = absolute(&config.data_dir, false)?;
    disjoint(&source, &target)?;
    let manifest = verify(&source)?;
    ensure!(
        u8::from(allow_legacy_schema007)
            + u8::from(allow_legacy_schema130)
            + u8::from(allow_legacy_schema131)
            + u8::from(allow_legacy_schema132)
            + u8::from(allow_legacy_schema133)
            + u8::from(allow_legacy_schema134)
            + u8::from(allow_legacy_schema135)
            + u8::from(allow_legacy_schema136)
            + u8::from(allow_legacy_schema137)
            + u8::from(allow_legacy_schema138)
            + u8::from(allow_legacy_schema139)
            + u8::from(allow_legacy_schema140)
            + u8::from(allow_legacy_schema141)
            + u8::from(allow_legacy_schema142)
            + u8::from(allow_legacy_schema143)
            <= 1,
        "choose one explicit legacy schema upgrade"
    );
    ensure!(!allow_legacy_schema007 || manifest.format == 4, "legacy opt-in requires format4/schema007");
    ensure!(!allow_legacy_schema130 || manifest.format == 6, "legacy opt-in requires format6/schema130");
    ensure!(!allow_legacy_schema131 || manifest.format == 7, "legacy opt-in requires format7/schema131");
    ensure!(!allow_legacy_schema132 || manifest.format == 8, "legacy opt-in requires format8/schema132");
    ensure!(!allow_legacy_schema133 || manifest.format == 9, "legacy opt-in requires format9/schema133");
    ensure!(!allow_legacy_schema134 || manifest.format == 10, "legacy opt-in requires format10/schema134");
    ensure!(!allow_legacy_schema135 || manifest.format == 11, "legacy opt-in requires format11/schema135");
    ensure!(!allow_legacy_schema136 || manifest.format == 12, "legacy opt-in requires format12/schema136");
    ensure!(!allow_legacy_schema137 || manifest.format == 13, "legacy opt-in requires format13/schema137");
    ensure!(!allow_legacy_schema138 || manifest.format == 14, "legacy opt-in requires format14/schema138");
    ensure!(!allow_legacy_schema139 || manifest.format == 15, "legacy opt-in requires format15/schema139");
    ensure!(!allow_legacy_schema140 || manifest.format == 16, "legacy opt-in requires format16/schema140");
    ensure!(!allow_legacy_schema141 || manifest.format == 17, "legacy opt-in requires format17/schema141");
    ensure!(!allow_legacy_schema142 || manifest.format == 18, "legacy opt-in requires format18/schema142");
    ensure!(!allow_legacy_schema143 || manifest.format == 19, "legacy opt-in requires format19/schema143");
    ensure!(
        (allow_legacy_schema007 && manifest.format == 4)
            || (allow_legacy_schema130 && manifest.format == 6)
            || (allow_legacy_schema131 && manifest.format == 7)
            || (allow_legacy_schema132 && manifest.format == 8)
            || (allow_legacy_schema133 && manifest.format == 9)
            || (allow_legacy_schema134 && manifest.format == 10)
            || (allow_legacy_schema135 && manifest.format == 11)
            || (allow_legacy_schema136 && manifest.format == 12)
            || (allow_legacy_schema137 && manifest.format == 13)
            || (allow_legacy_schema138 && manifest.format == 14)
            || (allow_legacy_schema139 && manifest.format == 15)
            || (allow_legacy_schema140 && manifest.format == 16)
            || (allow_legacy_schema141 && manifest.format == 17)
            || (allow_legacy_schema142 && manifest.format == 18)
            || (allow_legacy_schema143 && manifest.format == 19)
            || manifest.binary_sha256 == hash(&std::env::current_exe()?)?,
        "restore requires the exact backup binary; upgrade separately"
    );
    // The schema140 opt-in may only consume a genuine frozen format16 archive.
    if allow_legacy_schema140 {
        ensure!(
            manifest.format == 16
                && manifest.schema_versions == schema_versions(16)?
                && manifest.schema_contract_sha256 == schema_contract_digest(16)?,
            "legacy opt-in requires the exact format16/schema140 catalog"
        );
    }
    // The schema141 opt-in may only consume a genuine frozen format17 archive;
    // a mixed or incorrect opt-in was already refused above.
    if allow_legacy_schema141 {
        ensure!(
            manifest.format == 17
                && manifest.schema_versions == schema_versions(17)?
                && manifest.schema_contract_sha256 == schema_contract_digest(17)?,
            "legacy opt-in requires the exact format17/schema141 catalog"
        );
    }
    // The schema142 opt-in may only consume a genuine frozen format18 archive;
    // verify() and this frozen-catalog comparison refuse a relabelled one.
    if allow_legacy_schema142 {
        ensure!(
            manifest.format == 18
                && manifest.schema_versions == schema_versions(18)?
                && manifest.schema_contract_sha256 == schema_contract_digest(18)?,
            "legacy opt-in requires the exact format18/schema142 catalog"
        );
    }
    // The schema143 opt-in may only consume a genuine frozen format19 archive;
    // verify() and this frozen-catalog comparison refuse a relabelled one.
    if allow_legacy_schema143 {
        ensure!(
            manifest.format == 19
                && manifest.schema_versions == schema_versions(19)?
                && manifest.schema_contract_sha256 == schema_contract_digest(19)?,
            "legacy opt-in requires the exact format19/schema143 catalog"
        );
    }
    let mut client = pg(config).await?;
    // Real lifecycle barrier shared with serve-blob, held until publication.
    let mutex = BackupMutex::acquire(&client).await?;
    ensure_database_available(&client).await?;
    database_scope(&client, true).await?;
    let object_count: i64 = client.query_one("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'", &[]).await?.get(0);
    ensure!(object_count == 0, "restore requires a fresh empty dedicated database");
    let sessions: i64 = client
        .query_one(
            "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()",
            &[],
        )
        .await?
        .get(0);
    ensure!(sessions == 0, "restore database must have no other connections");
    let version: String = client.query_one("SHOW server_version", &[]).await?.get(0);
    ensure!(version.starts_with("17."), "restore requires PostgreSQL 17");
    let guard = restore_guard_path(&target)?;
    write_private(&guard, format!("{}\n", manifest.backup_id).as_bytes())?;
    File::open(target.parent().unwrap())?.sync_all()?;
    lifetime::restore_marker(&client, Some(manifest.backup_id)).await?;
    let staging_path = target.parent().unwrap().join(format!(".rootyard-restore-{}.partial", Uuid::new_v4()));
    ensure!(!staging_path.exists(), "restore staging collision");
    let mut staging = StagingDirGuard::new(staging_path);
    let entries = manifest
        .files
        .iter()
        .filter_map(|(n, e)| n.strip_prefix("volume/").map(|n| (n.to_owned(), e.clone())))
        .collect();
    copy_volume(&source.join("volume"), staging.path(), &entries)?;
    let _volume = volume_lock(staging.path())?;
    ensure!(volume_identity(staging.path())? == manifest.volume_id, "restored volume identity mismatch");
    let mut repos = manifest.repositories.clone();
    git_inventory(config, staging.path(), &mut repos, true).await?;
    ensure!(repos == manifest.repositories, "restored native refs/HEAD differ from manifest");
    // An archive is executable SQL; --trust-backup is a required operator choice.
    let mut restore = pg_command(config, "pg_restore")?;
    restore
        .args([
            "--no-password",
            "--dbname",
            "",
            "--single-transaction",
            "--clean",
            "--if-exists",
            "--exit-on-error",
            "--no-owner",
            "--no-privileges",
        ])
        .arg(source.join("metadata.dump"));
    checked(&mut restore).await?;
    ensure!(schema(&client, manifest.format).await? == manifest.schema_versions, "restored schema mismatch");
    // The catalog projection ends with SET search_path=pg_catalog; restore public first.
    client.batch_execute("SET search_path=public").await?;
    // Formats 6 through 19 are frozen at schema 130 through 143 and always need
    // their explicit legacy opt-in, so only a re-checked frozen catalog may be
    // upgraded here (schema144 adds roots, decisions, verdict/quota ledgers and
    // the separate per-repository protocol state).
    if matches!(manifest.format, 6..=19) {
        let mut upgraded = client;
        crate::db::migrate_client(&mut upgraded).await?;
        ensure!(
            schema(&upgraded, super::catalog::FORMAT).await? == crate::db::SCHEMA_VERSIONS,
            "restored legacy schema did not upgrade to the current catalog"
        );
        client = upgraded;
        client.batch_execute("SET search_path=public").await?;
    }
    let restored_foreign_volumes: i64 = client
        .query_one("SELECT count(*) FROM public.recovery_resolutions WHERE volume_id<>$1", &[&manifest.volume_id])
        .await?
        .get(0);
    ensure!(restored_foreign_volumes == 0, "restored resolutions belong to another volume");
    if manifest.format >= 6 {
        ensure!(
            lfs_inventory::metadata(&client).await? == manifest.lfs_objects,
            "restored LFS metadata differs from backup closure"
        );
    }
    // Only a genuine format4 archive at its verified schema007 predates the
    // schema138 RefStore registry; every other archive has rows to count.
    let has_ref_store_registry = manifest.format != 4;
    let metadata_repos = repositories(&client, has_ref_store_registry).await?;
    let has_backend = manifest.format >= 20;
    restore_metadata_repositories(&manifest.repositories, metadata_repos, has_backend)?;
    // A backup can predate cancellation; never resurrect a previously issued
    // checkout bearer (plan and native pins stay evidence, not permission).
    if manifest.format >= 5 {
        client
            .execute("UPDATE public.ci_checkout_jobs SET revoked=true WHERE plan IS NOT NULL AND NOT revoked", &[])
            .await?;
        let unsafe_grants: bool = client
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM public.ci_checkout_jobs WHERE plan IS NOT NULL AND NOT revoked)",
                &[],
            )
            .await?
            .get(0);
        ensure!(!unsafe_grants, "restored checkout credentials were not invalidated");
    }
    if manifest.format >= 6 && manifest.format != FORMAT_PAIRED {
        authority::fence(&client).await?;
        // Rotate the storage authority exactly once for the whole restored
        // database before importing any repository closure. Per-repository
        // rotation would invalidate paths imported for earlier repositories.
        crate::pando_gateway::retention::reset_authority(&mut client).await?;
        // Restored pando_refs/HEAD rows are only complete once the encrypted
        // pack closure is back in remote object storage. Import before the
        // volume is published so a failure leaves the isolated restore intact.
        let pando: Vec<Uuid> = client
            .query(
                "SELECT r.id FROM public.repositories r JOIN public.pando_repository_states s \
            ON s.repository_id=r.id WHERE r.storage_backend='pando' ORDER BY r.id",
                &[],
            )
            .await?
            .iter()
            .map(|row| row.get(0))
            .collect();
        if !pando.is_empty() {
            let remote =
                crate::storage::remote_objects::RemoteObjectStore::from_env(config.data_dir.join("pando-pack-work"))?;
            let until = tokio::time::Instant::now() + std::time::Duration::from_secs(3600);
            for repo in pando {
                let closure = source.join("pando").join(repo.to_string());
                ensure!(closure.is_dir(), "backup is missing a Pando pack closure");
                let tx = client
                    .build_transaction()
                    .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
                    .start()
                    .await?;
                tx.batch_execute("SET LOCAL search_path=public").await?;
                crate::pando_gateway::backup::import_closure(&tx, &remote, repo, &closure, until).await?;
                tx.commit().await?;
            }
        }
    }
    if manifest.format == FORMAT_PAIRED {
        let closure = manifest.blob_closure.as_ref().context("paired archive carries no Blob closure")?;
        ensure!(
            manifest.repositories.iter().all(|r| r.backend.as_deref() == Some("pg_refstore")),
            "mixed legacy/Blob restore is unsupported"
        );
        ensure!(
            Some(
                ledger::carry(&client, tokio::time::Instant::from_std(started + std::time::Duration::from_secs(3600)))
                    .await?
            ) == manifest.refstore,
            "restored RefStore rows differ from the archive cut"
        );
        if let Some(plan) = &w8a_plan {
            w8a_paired::verify_restored_source_snapshot(&client, plan.sidecar).await.map_err(anyhow::Error::new)?;
        }
        authority::fence(&client).await?;
        crate::pando_gateway::retention::reset_authority(&mut client).await?;
        let profile = crate::blob_store::config::BlobProfile::from_env()?;
        let store = crate::blob_store::opendal::BlobStore::open(profile)?;
        let transfer = crate::blob_store::archive::ArchiveTransfer::new(store);
        ensure!(
            transfer.backend_identity_hex() == closure.backend_identity && transfer.provider() == closure.provider,
            "restore target Blob backend identity differs from the archive"
        );
        // The caller's one absolute restore deadline bounds every read and rebuild.
        let until = tokio::time::Instant::from_std(started + std::time::Duration::from_secs(3600));
        blob_closure::import(&client, &transfer, &manifest.blob_artifacts, &source, until, &mutex).await?;
    }
    let w8a_outcome = if let Some(plan) = w8a_plan {
        ensure!(manifest.format == FORMAT_PAIRED, "W8-A paired restore requires format30");
        let outcome = w8a_paired::finish_guarded_restore(
            config,
            &mut client,
            &mutex,
            plan.sidecar,
            &manifest.blob_artifacts,
            plan.compute_dir,
        )
        .await
        .map_err(anyhow::Error::new)?;
        Some(outcome)
    } else {
        None
    };
    ensure!(!target.exists(), "destination appeared during restore");
    // Keep the exclusive lifecycle barrier until the target is published.
    mutex.ensure_held(&client).await?;
    staging.publish_to(&target)?;
    File::open(target.parent().unwrap())?.sync_all()?;
    fs::remove_file(&guard)?;
    File::open(target.parent().unwrap())?.sync_all()?;
    lifetime::restore_marker(&client, None).await?;
    mutex.release(&client).await?;
    drop(client);
    if w8a_outcome.is_none() {
        println!(
            "{}",
            serde_json::json!({"backup_id":manifest.backup_id,"restored":true,"started_service":false,"blob_artifacts":manifest.blob_artifacts.len(),"elapsed_seconds":started.elapsed().as_secs_f64(),"unknown_operations":manifest.repositories.iter().map(|r|r.unknown_operations).sum::<i64>()})
        );
    }
    Ok(w8a_outcome)
}
