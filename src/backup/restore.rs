//! Verified isolated restore and capability fencing.
use super::*;

pub(super) fn verify(source: &Path) -> Result<Manifest> {
    let manifest_meta = fs::symlink_metadata(source.join("manifest.json"))?;
    ensure!(
        manifest_meta.is_file()
            && manifest_meta.nlink() == 1
            && manifest_meta.len() <= MAX_MANIFEST,
        "invalid manifest"
    );
    let complete = fs::symlink_metadata(source.join("COMPLETE"))?;
    ensure!(
        complete.is_file() && complete.len() == 64 && complete.nlink() == 1,
        "invalid completion marker"
    );
    let mut expected = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source.join("COMPLETE"))?
        .take(65)
        .read_to_string(&mut expected)?;
    ensure!(
        expected.len() == 64 && hash(&source.join("manifest.json"))? == expected,
        "incomplete or damaged manifest"
    );
    let manifest: Manifest = serde_json::from_slice(&fs::read(source.join("manifest.json"))?)?;
    ensure!(
        matches!(manifest.format, 4..=6)
            && manifest.schema_versions == schema_versions(manifest.format)?
            && manifest.schema_contract_sha256 == schema_contract_digest(manifest.format)?,
        "unsupported backup format"
    );
    ensure!(
        volume_identity(&source.join("volume"))? == manifest.volume_id,
        "backup volume identity mismatch"
    );
    if manifest.format >= 6 {
        lfs_inventory::verify(&source.join("volume"), &manifest.lfs_objects)?;
    }
    let mut actual = inventory(&source.join("volume"))?
        .into_iter()
        .map(|(n, e)| (format!("volume/{n}"), e))
        .collect::<BTreeMap<_, _>>();
    let dump = source.join("metadata.dump");
    let metadata = fs::symlink_metadata(&dump)?;
    ensure!(
        metadata.is_file() && metadata.nlink() == 1,
        "invalid dump file"
    );
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
    ensure!(
        actual == manifest.files,
        "backup inventory or checksum mismatch"
    );
    ensure!(
        manifest.journal_record_files
            == actual
                .keys()
                .filter(|p| p.starts_with("volume/journal/") && p.ends_with("/operation.json"))
                .count(),
        "journal inventory mismatch"
    );
    let mut names = fs::read_dir(source)?
        .map(|e| e.map(|v| v.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    ensure!(
        names
            == ["COMPLETE", "manifest.json", "metadata.dump", "volume"]
                .map(std::ffi::OsString::from),
        "unexpected backup files"
    );
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

pub async fn restore(config: &Config, source: &Path, allow_legacy_schema007: bool) -> Result<()> {
    let started = Instant::now();
    let source = absolute(source, true)?;
    let target = absolute(&config.data_dir, false)?;
    disjoint(&source, &target)?;
    let manifest = verify(&source)?;
    ensure!(
        !allow_legacy_schema007 || manifest.format == 4,
        "legacy opt-in requires format4/schema007"
    );
    ensure!(
        (allow_legacy_schema007 && manifest.format == 4)
            || manifest.binary_sha256 == hash(&std::env::current_exe()?)?,
        "restore requires the exact backup binary; upgrade separately"
    );
    let client = pg(config).await?;
    client
        .query_one("SELECT pg_advisory_lock(738390103)", &[])
        .await?;
    database_scope(&client, true).await?;
    let object_count: i64 = client.query_one("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'", &[]).await?.get(0);
    ensure!(
        object_count == 0,
        "restore requires a fresh empty dedicated database"
    );
    let sessions: i64 = client.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()", &[]).await?.get(0);
    ensure!(
        sessions == 0,
        "restore database must have no other connections"
    );
    let version: String = client.query_one("SHOW server_version", &[]).await?.get(0);
    ensure!(version.starts_with("17."), "restore requires PostgreSQL 17");
    let guard = restore_guard_path(&target)?;
    write_private(&guard, format!("{}\n", manifest.backup_id).as_bytes())?;
    File::open(target.parent().unwrap())?.sync_all()?;
    let staging = target
        .parent()
        .unwrap()
        .join(format!(".rootyard-restore-{}.partial", Uuid::new_v4()));
    let entries = manifest
        .files
        .iter()
        .filter_map(|(n, e)| n.strip_prefix("volume/").map(|n| (n.to_owned(), e.clone())))
        .collect();
    copy_volume(&source.join("volume"), &staging, &entries)?;
    let _volume = volume_lock(&staging)?;
    ensure!(
        volume_identity(&staging)? == manifest.volume_id,
        "restored volume identity mismatch"
    );
    let mut repos = manifest.repositories.clone();
    git_inventory(config, &staging, &mut repos, true).await?;
    ensure!(
        repos == manifest.repositories,
        "restored native refs/HEAD differ from manifest"
    );
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
    ensure!(
        schema(&client, manifest.format).await? == manifest.schema_versions,
        "restored schema mismatch"
    );
    let restored_foreign_volumes: i64 = client
        .query_one(
            "SELECT count(*) FROM public.recovery_resolutions WHERE volume_id<>$1",
            &[&manifest.volume_id],
        )
        .await?
        .get(0);
    ensure!(
        restored_foreign_volumes == 0,
        "restored resolutions belong to another volume"
    );
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
    ensure!(
        metadata_repos == manifest.repositories,
        "restored metadata mismatch"
    );
    // A backup can predate cancellation. Never resurrect any previously issued
    // checkout bearer after restoring old authority; plan and native pins remain
    // evidence, not permission to mint a credential for the same job again.
    if manifest.format >= 5 {
        client.execute("UPDATE public.ci_checkout_jobs SET revoked=true WHERE plan IS NOT NULL AND NOT revoked", &[]).await?;
        let unsafe_grants: bool = client.query_one("SELECT EXISTS (SELECT 1 FROM public.ci_checkout_jobs WHERE plan IS NOT NULL AND NOT revoked)", &[]).await?.get(0);
        ensure!(
            !unsafe_grants,
            "restored checkout credentials were not invalidated"
        );
    }
    if manifest.format >= 6 {
        authority::fence(&client).await?;
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
