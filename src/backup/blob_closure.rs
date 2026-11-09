//! Exact OpenDAL Blob byte closure of the `pg_refstore` serving repositories.
//!
//! Export runs inside the offline barrier (volume flock + PostgreSQL exclusive
//! session advisory lock + REPEATABLE READ/exported snapshot + SHARE table
//! locks). All source rows — the registered artifacts, their immutable A3
//! holds (the only place the original attempt locator lives), the consume
//! receipts and the publication authority — are read from that one snapshot.
//! Every object is verified against the live backend identity, exported into
//! the archive with its exact bytes, and re-verified afterwards so the archive
//! holds the bytes that were live for the cut.
//!
//! Restore is same-coordinate: the archive carries the original locators and
//! the restored PostgreSQL snapshot keeps its registered-artifact rows, holds,
//! receipts and ACKs verbatim. For every member:
//!
//! * an exact readable copy at the original locator is reused;
//! * a confirmed absent object is rebuilt at that exact locator through the
//!   sealed writer, gated by a per-artifact [`OfflineRestorePermit`];
//! * a present-but-different or unreadable object is refused. Nothing is
//!   overwritten, deleted or re-pointed, and no ledger row is rewritten.
//!
//! A source that still has a pending/unknown write operation, or any
//! non-`committed`/`rejected` terminal, is refused *before* export: its closure
//! may be about to change and cannot be captured as a closed cut.
use super::*;
use crate::blob_store::{
    BlobLocator,
    archive::{ArchiveTransfer, Rebuild},
};
use ledger::Artifact;

/// Export every closure artifact into the private staging directory.
pub(super) async fn export(
    read: &ArchiveRead,
    transfer: &ArchiveTransfer,
    artifacts: &[Artifact],
    destination: &Path,
    deadline: Instant,
    mutex: &BackupMutex,
    client: &(impl GenericClient + Sync),
) -> Result<(BlobClosure, BTreeMap<String, Entry>)> {
    let backend = transfer.backend_identity_hex().to_owned();
    let provider = transfer.provider().to_owned();
    ensure!(
        artifacts.iter().all(|a| a.backend_identity == backend && a.provider == provider),
        "Blob closure backend differs"
    );
    private_dir(&destination.join("blob"))?;
    let mut directories = std::collections::BTreeSet::new();
    for artifact in artifacts {
        ensure!(transfer.live(deadline), "Blob export deadline reached");
        let locator = artifact.locator()?;
        transfer
            .verify_for_export(read, &locator, deadline)
            .await
            .context("source Blob artifact failed verified read-back")?;
        let path = destination.join(artifact.archive_path());
        let repository = destination.join("blob").join(artifact.repository_id.to_string());
        let pack = repository.join(artifact.pack_id.to_string());
        for directory in [repository, pack] {
            if directories.insert(directory.clone()) {
                private_dir(&directory)?;
            }
        }
        ensure!(
            fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "archive member collision"
        );
        let length = transfer
            .export(read, &locator, &artifact.sha256, artifact.length, &path, deadline)
            .await
            .context("exact Blob artifact could not be exported from the source backend")?;
        ensure!(length == artifact.length, "exported Blob artifact length differs");
        File::open(&path)?.sync_all()?;
    }
    mutex.ensure_held(client).await?;
    // Re-read the source after export: the archive holds bytes that were live
    // for the cut, not a copy of an object replaced in between.
    for artifact in artifacts {
        transfer
            .verify_for_export(read, &artifact.locator()?, deadline)
            .await
            .context("source Blob artifact changed during export")?;
    }
    let closure = ledger::closure_of(artifacts, &backend, &provider);
    Ok((closure, entries(destination, artifacts)?))
}

/// Exact file accounting for every archived member. The archive manifest is
/// built from this, and restore re-derives it to prove the bytes it imports.
fn entries(root: &Path, artifacts: &[Artifact]) -> Result<BTreeMap<String, Entry>> {
    let files: BTreeMap<_, _> =
        inventory(&root.join("blob"))?.into_iter().map(|(name, entry)| (format!("blob/{name}"), entry)).collect();
    ensure!(files.len() < MAX_ENTRIES, "archive file count exceeds bound");
    let actual_files = files.values().filter(|entry| entry.kind == "file").count();
    ensure!(actual_files == artifacts.len(), "archive contains extra or missing Blob files");
    for artifact in artifacts {
        let local = root.join(artifact.archive_path());
        let meta = fs::symlink_metadata(&local)?;
        ensure!(meta.is_file() && meta.nlink() == 1 && meta.len() == artifact.length, "archive Blob member differs");
        let entry = files.get(&artifact.archive_path()).context("missing archive Blob member")?;
        ensure!(
            entry.kind == "file"
                && entry.bytes == artifact.length
                && entry.sha256.as_deref() == Some(artifact.sha256.as_str()),
            "archive Blob member digest differs"
        );
    }
    Ok(files)
}

/// Restore every archived member at its original locator and prove the result.
///
/// Runs only after the archive was fully verified, the isolated target passed
/// its empty/fresh checks, the restored catch-up migrations finished and the
/// exclusive lifecycle barrier is held. Each member is rebuilt (or its exact
/// existing copy reused) through a permit bound to that one locator and the
/// archive backend, then the restored ledger is re-derived and compared with
/// the manifest. No ledger row is written.
pub(super) async fn import(
    client: &(impl GenericClient + Sync),
    transfer: &ArchiveTransfer,
    artifacts: &[Artifact],
    archive_root: &Path,
    deadline: Instant,
    mutex: &BackupMutex,
) -> Result<()> {
    let backend = transfer.backend_identity_hex().to_owned();
    let provider = transfer.provider().to_owned();
    // The archive itself must carry every member before the first upload.
    let files = entries(archive_root, artifacts)?;
    // Restored PostgreSQL must describe exactly the same closure; a difference
    // means the archive and the restored snapshot are not one paired cut.
    let restored = ledger::inventory(client, &backend, &provider)
        .await
        .context("restored Blob ledger cannot be verified before import")?;
    ensure!(restored == artifacts, "restored Blob ledger differs from the archive manifest");
    let (mut rebuilt, mut reused) = (0usize, 0usize);
    for artifact in artifacts {
        ensure!(transfer.live(deadline), "Blob restore deadline reached");
        let locator: BlobLocator = artifact.locator()?;
        let permit = OfflineRestorePermit::issue(locator.clone(), &backend)?;
        let outcome = transfer
            .rebuild(&permit, &locator, &archive_root.join(artifact.archive_path()), &artifact.sha256, deadline)
            .await
            .context("archive Blob member could not be verified or rebuilt")?;
        match outcome {
            Rebuild::AlreadyExact => reused += 1,
            Rebuild::Rebuilt => rebuilt += 1,
        }
        mutex.ensure_held(client).await?;
    }
    // Re-derive the ledger from the restored database and prove it still equals
    // the manifest exactly (nothing re-pointed, nothing lost).
    let after = ledger::inventory(client, &backend, &provider).await?;
    ensure!(after == artifacts, "restored Blob ledger changed during import");
    ensure!(files.len() == rebuilt + reused, "archive member accounting mismatch");
    Ok(())
}
