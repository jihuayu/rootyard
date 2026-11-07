//! Verified isolated restore and capability fencing.
use super::*;

pub(super) fn verify(source: &Path) -> Result<Manifest> {
    let manifest_meta = fs::symlink_metadata(source.join("manifest.json"))?;
    ensure!(
        manifest_meta.is_file() && manifest_meta.nlink() == 1 && manifest_meta.len() <= MAX_MANIFEST,
        "invalid manifest"
    );
    let complete = fs::symlink_metadata(source.join("COMPLETE"))?;
    ensure!(complete.is_file() && complete.len() == 64 && complete.nlink() == 1, "invalid completion marker");
    let mut expected = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source.join("COMPLETE"))?
        .take(65)
        .read_to_string(&mut expected)?;
    ensure!(expected.len() == 64 && hash(&source.join("manifest.json"))? == expected, "incomplete or damaged manifest");
    let manifest: Manifest = serde_json::from_slice(&fs::read(source.join("manifest.json"))?)?;
    ensure!(
        matches!(manifest.format, 4..=10)
            && manifest.schema_versions == schema_versions(manifest.format)?
            && manifest.schema_contract_sha256 == schema_contract_digest(manifest.format)?,
        "unsupported backup format"
    );
    ensure!(volume_identity(&source.join("volume"))? == manifest.volume_id, "backup volume identity mismatch");
    if manifest.format >= 6 {
        lfs_inventory::verify(&source.join("volume"), &manifest.lfs_objects)?;
    }
    let mut actual = inventory(&source.join("volume"))?
        .into_iter()
        .map(|(n, e)| (format!("volume/{n}"), e))
        .collect::<BTreeMap<_, _>>();
    let pando_root = source.join("pando");
    let has_pando = match fs::symlink_metadata(&pando_root) {
        Ok(meta) => {
            ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "invalid Pando closure directory");
            for (name, entry) in inventory(&pando_root)? {
                actual.insert(format!("pando/{name}"), entry);
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    let dump = source.join("metadata.dump");
    let metadata = fs::symlink_metadata(&dump)?;
    ensure!(metadata.is_file() && metadata.nlink() == 1, "invalid dump file");
    actual.insert(
        "metadata.dump".into(),
        Entry {
            kind: "file".into(),
            mode: metadata.mode() & 0o7777,
            bytes: metadata.len(),
            sha256: Some(hash(&dump)?),
            target: None,
        },
    );
    ensure!(actual == manifest.files, "backup inventory or checksum mismatch");
    ensure!(
        manifest.journal_record_files
            == actual.keys().filter(|p| p.starts_with("volume/journal/") && p.ends_with("/operation.json")).count(),
        "journal inventory mismatch"
    );
    let mut names = fs::read_dir(source)?.map(|e| e.map(|v| v.file_name())).collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    let mut allowed = ["COMPLETE", "manifest.json", "metadata.dump", "volume"].map(std::ffi::OsString::from).to_vec();
    if has_pando {
        allowed.push("pando".into());
    }
    allowed.sort();
    ensure!(names == allowed, "unexpected backup files");
    Ok(manifest)
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
) -> Result<()> {
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
            <= 1,
        "choose one explicit legacy schema upgrade"
    );
    ensure!(!allow_legacy_schema007 || manifest.format == 4, "legacy opt-in requires format4/schema007");
    ensure!(!allow_legacy_schema130 || manifest.format == 6, "legacy opt-in requires format6/schema130");
    ensure!(!allow_legacy_schema131 || manifest.format == 7, "legacy opt-in requires format7/schema131");
    ensure!(!allow_legacy_schema132 || manifest.format == 8, "legacy opt-in requires format8/schema132");
    ensure!(!allow_legacy_schema133 || manifest.format == 9, "legacy opt-in requires format9/schema133");
    ensure!(
        (allow_legacy_schema007 && manifest.format == 4)
            || (allow_legacy_schema130 && manifest.format == 6)
            || (allow_legacy_schema131 && manifest.format == 7)
            || (allow_legacy_schema132 && manifest.format == 8)
            || (allow_legacy_schema133 && manifest.format == 9)
            || manifest.binary_sha256 == hash(&std::env::current_exe()?)?,
        "restore requires the exact backup binary; upgrade separately"
    );
    let mut client = pg(config).await?;
    client.query_one("SELECT pg_advisory_lock(738390103)", &[]).await?;
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
    let staging = target.parent().unwrap().join(format!(".rootyard-restore-{}.partial", Uuid::new_v4()));
    let entries = manifest
        .files
        .iter()
        .filter_map(|(n, e)| n.strip_prefix("volume/").map(|n| (n.to_owned(), e.clone())))
        .collect();
    copy_volume(&source.join("volume"), &staging, &entries)?;
    let _volume = volume_lock(&staging)?;
    ensure!(volume_identity(&staging)? == manifest.volume_id, "restored volume identity mismatch");
    let mut repos = manifest.repositories.clone();
    git_inventory(config, &staging, &mut repos, true).await?;
    ensure!(repos == manifest.repositories, "restored native refs/HEAD differ from manifest");
    // An archive is executable SQL. --trust-backup is a required operator choice,
    // not an assertion that hashes authenticate it. Destination stays isolated.
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
    // The catalog projection ends with SET search_path=pg_catalog. Restore the
    // target's public application schema before applying the reviewed upgrade.
    client.batch_execute("SET search_path=public").await?;
    // Formats 6/7/8/9 are frozen at schema 130/131/132/133. Preserve them for
    // old archives and apply the reviewed Rust migration path only after the
    // exact frozen catalog and version list have been verified from the restored
    // dump. A format8 or format9 archive always needs its explicit legacy opt-in,
    // so no restored database can serve the current schema without the reviewed
    // later migrations (including schema134 identity constraints).
    if matches!(manifest.format, 6..=9) {
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
    let mut metadata_repos = repositories(&client).await?;
    for repo in &mut metadata_repos {
        if let Some(old) = manifest.repositories.iter().find(|old| old.id == repo.id) {
            repo.refs.clone_from(&old.refs);
            repo.head.clone_from(&old.head);
        }
    }
    ensure!(metadata_repos == manifest.repositories, "restored metadata mismatch");
    // A backup can predate cancellation. Never resurrect any previously issued
    // checkout bearer after restoring old authority; plan and native pins remain
    // evidence, not permission to mint a credential for the same job again.
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
    if manifest.format >= 6 {
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
    ensure!(!target.exists(), "destination appeared during restore");
    publish(&staging, &target)?;
    File::open(target.parent().unwrap())?.sync_all()?;
    fs::remove_file(&guard)?;
    File::open(target.parent().unwrap())?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"backup_id":manifest.backup_id,"restored":true,"started_service":false,"elapsed_seconds":started.elapsed().as_secs_f64(),"unknown_operations":manifest.repositories.iter().map(|r|r.unknown_operations).sum::<i64>()})
    );
    Ok(())
}
