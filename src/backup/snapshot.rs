//! Offline snapshot barriers and paired backup publication.
use super::*;

/// Operator must already have stopped serving; this command never stops services.
pub async fn create(config: &Config, destination: &Path) -> Result<()> {
    let started = Instant::now();
    let root = absolute(&config.data_dir, true)?;
    let destination = absolute(destination, false)?;
    disjoint(&root, &destination)?;
    ensure_not_restoring(&root)?;
    let _volume = volume_lock(&root)?;
    let volume_id = volume_identity(&root)?;
    let mut client = pg(config).await?;
    // Acquire this BEFORE beginning REPEATABLE READ: SELECT would otherwise fix
    // the snapshot before waiting for old transactions/migrations to commit.
    client.query_one("SELECT pg_advisory_lock(738390103)", &[]).await?;
    let tx = client.build_transaction().isolation_level(tokio_postgres::IsolationLevel::RepeatableRead).start().await?;
    let list = catalog::relations(FORMAT, true)?
        .iter()
        .map(|t| format!("public.\"{}\"", t.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(",");
    tx.batch_execute(&format!("LOCK TABLE {list} IN SHARE MODE")).await?;
    // No snapshot-taking SELECT occurs before all DML/DDL table locks are held.
    let versions = schema(&tx, FORMAT).await?;
    tx.batch_execute("SET LOCAL search_path=public").await?;
    // A durable cutover/rollback fence means the backend authority is in
    // motion. Never capture a paired backup from a repository under transition.
    let transitioning: i64 =
        tx.query_one("SELECT count(*) FROM public.repositories WHERE transition_state <> 'stable'", &[]).await?.get(0);
    ensure!(transitioning == 0, "backup requires a stable storage transition fence");
    let snapshot: String = tx.query_one("SELECT pg_export_snapshot()", &[]).await?.get(0);
    let boundary = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let postgres_version: String = tx.query_one("SHOW server_version", &[]).await?.get(0);
    ensure!(postgres_version.starts_with("17."), "this format is verified only with PostgreSQL 17");
    let mut repos = repositories(&tx).await?;
    let foreign_volumes: i64 = tx
        .query_one("SELECT count(*) FROM public.recovery_resolutions WHERE volume_id<>$1", &[&volume_id])
        .await?
        .get(0);
    ensure!(foreign_volumes == 0, "resolution history belongs to another volume");
    let lfs_objects = lfs_inventory::metadata(&tx).await?;
    lfs_inventory::hydrate(config, &lfs_objects).await?;
    let source_inventory = inventory(&root)?;
    git_inventory(config, &root, &mut repos, false).await?;
    let id = Uuid::new_v4();
    let staging = destination.parent().unwrap().join(format!(".rootyard-backup-{id}.partial"));
    private_dir(&staging)?;
    let mut dump = pg_command(config, "pg_dump")?;
    dump.args([
        "--no-password",
        "--lock-wait-timeout=5s",
        "--format=custom",
        "--schema=public",
        "--no-owner",
        "--no-privileges",
        "--snapshot",
        &snapshot,
        "--file",
    ])
    .arg(staging.join("metadata.dump"));
    checked(&mut dump).await?;
    fs::set_permissions(staging.join("metadata.dump"), fs::Permissions::from_mode(0o600))?;
    File::open(staging.join("metadata.dump"))?.sync_all()?;
    copy_volume(&root, &staging.join("volume"), &source_inventory)?;
    // Pando authority lives in remote encrypted packs, not the volume. Export
    // the exact committed closure under the same repeatable-read transaction so
    // the archive carries both pando_refs/HEAD and every encrypted artifact.
    let pando_root = staging.join("pando");
    private_dir(&pando_root)?;
    let pando_repos: Vec<Uuid> = tx
        .query("SELECT id FROM public.repositories WHERE storage_backend='pando' ORDER BY id", &[])
        .await?
        .iter()
        .map(|row| row.get(0))
        .collect();
    if !pando_repos.is_empty() {
        let remote = crate::storage::remote_objects::RemoteObjectStore::from_env(root.join("pando-pack-work"))?;
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(3600);
        for repo in pando_repos {
            crate::pando_gateway::backup::export_closure(&tx, &remote, repo, &pando_root.join(repo.to_string()), until)
                .await?;
        }
    }
    ensure!(inventory(&root)? == source_inventory, "volume changed during barrier");
    // Prove the exporting session still owns its transaction before publishing.
    tx.query_one("SELECT 1", &[]).await?;
    let mut files = BTreeMap::new();
    files.insert(
        "metadata.dump".into(),
        Entry {
            kind: "file".into(),
            mode: 0o600,
            bytes: fs::metadata(staging.join("metadata.dump"))?.len(),
            sha256: Some(hash(&staging.join("metadata.dump"))?),
            target: None,
        },
    );
    for (name, entry) in source_inventory {
        files.insert(format!("volume/{name}"), entry);
    }
    for (name, entry) in inventory(&pando_root)? {
        files.insert(format!("pando/{name}"), entry);
    }
    let manifest = Manifest {
        format: FORMAT,
        backup_id: id,
        volume_id,
        schema_contract_sha256: schema_contract_digest(FORMAT)?,
        boundary_unix_seconds: boundary,
        rootyard_version: env!("CARGO_PKG_VERSION").into(),
        binary_sha256: hash(&std::env::current_exe()?)?,
        postgres_version,
        pg_dump_version: String::from_utf8(checked(command("pg_dump").arg("--version")).await?)?.trim().into(),
        git_version: String::from_utf8(checked(command(&config.git).arg("--version")).await?)?.trim().into(),
        schema_versions: versions,
        consistency: "offline-volume-flock+postgres-share-locks+exported-snapshot".into(),
        journal_record_files: files
            .keys()
            .filter(|p| p.starts_with("volume/journal/") && p.ends_with("/operation.json"))
            .count(),
        repositories: repos,
        lfs_objects,
        files,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    ensure!(manifest_bytes.len() as u64 <= MAX_MANIFEST, "manifest exceeds format bound");
    write_private(&staging.join("manifest.json"), &manifest_bytes)?;
    File::open(&staging)?.sync_all()?;
    tx.commit().await?;
    write_private(&staging.join("COMPLETE"), hash(&staging.join("manifest.json"))?.as_bytes())?;
    File::open(&staging)?.sync_all()?;
    // Drop connection releases session migration lock; never modify source data.
    drop(client);
    ensure!(!destination.exists(), "destination appeared during backup");
    publish(&staging, &destination)?;
    File::open(destination.parent().unwrap())?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"backup_id":id,"complete":true,"elapsed_seconds":started.elapsed().as_secs_f64(),"boundary_unix_seconds":boundary,"unknown_operations":manifest.repositories.iter().map(|r|r.unknown_operations).sum::<i64>()})
    );
    Ok(())
}
