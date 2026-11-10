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
    ensure_database_available(&client).await?;
    // Real lifecycle barrier shared with serve-blob: an exclusive session lock
    // that every serving process holds shared for its whole lifetime. It is
    // taken BEFORE the exported snapshot and held until publication finished,
    // because SELECT would otherwise fix the snapshot before waiting for old
    // transactions/migrations to commit.
    let mutex = BackupMutex::acquire(&client).await?;
    let tx = client.build_transaction().isolation_level(tokio_postgres::IsolationLevel::RepeatableRead).start().await?;
    let list = catalog::relations(FORMAT, true)?
        .iter()
        .map(|t| format!("public.\"{}\"", t.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(",");
    tx.batch_execute(&format!("LOCK TABLE {list} IN SHARE MODE")).await?;
    // No snapshot-taking SELECT occurs before all DML/DDL table locks are held.
    // The archive version is selected by the actual source, never by a flag:
    // any `pg_refstore` serving repository forces the paired Blob closure
    // version. A Blob-served source can therefore never produce a metadata-only
    // archive that would be mistaken for an independent byte backup.
    let served = ledger::serving_repositories(&tx).await?;
    let format = if served > 0 { FORMAT_PAIRED } else { FORMAT };
    let versions = schema(&tx, format).await?;
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
    // A source database always carries the schema138 RefStore registry.
    let mut repos = repositories(&tx, true).await?;
    if format == FORMAT_PAIRED {
        ensure!(
            repos.iter().all(|r| r.backend.as_deref() == Some("pg_refstore")),
            "paired Blob archives currently require only pg_refstore repositories"
        );
    }
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
    // Prove the exporting session still owns its lifecycle barrier and its
    // exported snapshot transaction before publishing.
    mutex.ensure_held(&tx).await?;
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
    // Exact v1 Blob closure of every `pg_refstore` repository. Bytes are the
    // only thing that makes this an independent backup: the manifest records
    // their checksums and the source physical backend identity.
    // The caller's one absolute deadline bounds the source validation, the
    // export, the inventory reads and the RefStore carry; never restarted.
    let until = tokio::time::Instant::from_std(started + std::time::Duration::from_secs(3600));
    let (blob_closure, blob_artifacts) = if format == FORMAT_PAIRED {
        // Fail closed before a single byte is exported: every registration a
        // live membership, retained snapshot/root (active or released) or
        // serving read still declares must have its exact pack/idx pair, hold
        // binding and recomputed digest, or the archive is refused. This runs
        // on the exported-snapshot transaction above, not on a second snapshot.
        ledger_validation::validate_source(&tx, until).await.context("source artifact ledger cannot be archived")?;
        // Missing scope or an unsupported backend is an explicit refusal, never
        // a silently byte-less archive.
        let profile = crate::blob_store::config::BlobProfile::from_env()
            .map_err(|_| anyhow::anyhow!("paired backup requires a supported OpenDAL Blob profile"))?;
        let store = crate::blob_store::opendal::BlobStore::open(profile)
            .map_err(|_| anyhow::anyhow!("paired backup could not open the Blob backend"))?;
        // The export witness reads exact locators only; it is minted with the
        // real volume/backup identities already fixed above.
        let read = ArchiveRead::seal(volume_id, id)?;
        let transfer = crate::blob_store::archive::ArchiveTransfer::for_export(&read, store);
        let artifacts = ledger::inventory(&tx, transfer.backend_identity_hex(), transfer.provider(), until)
            .await
            .context("exact Blob closure cannot be captured from this source")?;
        let (closure, blob_files) =
            blob_closure::export(&read, &transfer, &artifacts, &staging, until, &mutex, &tx).await?;
        for (name, entry) in blob_files {
            ensure!(files.insert(name, entry).is_none(), "archive member path collision");
        }
        (Some(closure), artifacts)
    } else {
        ensure!(served == 0, "served pg_refstore source cannot produce a metadata archive");
        (None, Vec::new())
    };
    // Durable RefStore rows the paired closure depends on; the restore compares
    // them with the restored database before rebuilding any byte.
    let refstore = if format == FORMAT_PAIRED { Some(ledger::carry(&tx, until).await?) } else { None };
    let paired = blob_closure.is_some();
    let manifest = Manifest {
        format,
        backup_id: id,
        volume_id,
        schema_contract_sha256: schema_contract_digest(format)?,
        boundary_unix_seconds: boundary,
        rootyard_version: env!("CARGO_PKG_VERSION").into(),
        binary_sha256: hash(&std::env::current_exe()?)?,
        postgres_version,
        pg_dump_version: String::from_utf8(checked(command("pg_dump").arg("--version")).await?)?.trim().into(),
        git_version: String::from_utf8(checked(command(&config.git).arg("--version")).await?)?.trim().into(),
        schema_versions: versions,
        consistency: if paired {
            "offline-volume-flock+postgres-advisory-lock+share-locks+exported-snapshot+verified-blob-closure+validated-source-artifact-ledger"
        } else {
            "offline-volume-flock+postgres-advisory-lock+share-locks+exported-snapshot"
        }
        .into(),
        journal_record_files: files
            .keys()
            .filter(|p| p.starts_with("volume/journal/") && p.ends_with("/operation.json"))
            .count(),
        repositories: repos,
        lfs_objects,
        blob_closure,
        blob_artifacts,
        refstore,
        files,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    ensure!(manifest_bytes.len() as u64 <= MAX_MANIFEST, "manifest exceeds format bound");
    write_private(&staging.join("manifest.json"), &manifest_bytes)?;
    File::open(&staging)?.sync_all()?;
    tx.commit().await?;
    write_private(&staging.join("COMPLETE"), hash(&staging.join("manifest.json"))?.as_bytes())?;
    File::open(&staging)?.sync_all()?;
    // Keep the source fenced until the completed archive is durably published.
    ensure!(!destination.exists(), "destination appeared during backup");
    publish(&staging, &destination)?;
    File::open(destination.parent().unwrap())?.sync_all()?;
    mutex.release(&client).await?;
    drop(client);
    println!(
        "{}",
        serde_json::json!({"backup_id":id,"format":format,"complete":true,"elapsed_seconds":started.elapsed().as_secs_f64(),"boundary_unix_seconds":boundary,"unknown_operations":manifest.repositories.iter().map(|r|r.unknown_operations).sum::<i64>(),"blob_artifacts":manifest.blob_closure.as_ref().map_or(0,|c|c.artifacts),"blob_bytes":manifest.blob_closure.as_ref().map_or(0,|c|c.bytes)})
    );
    Ok(())
}
