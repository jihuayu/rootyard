//! CI sidecar staging and atomic publication of a verified sidecar
//! bundle into the target repository directory.
use super::sidecar_capture::{bundle_intents, manifest_ci_roots, read_sidecar_directory, validate_bundle_stage};
use super::{MAX_SIDECAR_BYTES, SidecarBundle, safe_directory, sync_directory};
use crate::{
    AppState, Error, journal,
    sharding::{
        models::conflict,
        replication::{self, RefManifest},
    },
};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path as FsPath, PathBuf},
};
use uuid::Uuid;

pub(crate) fn progress_path(state: &AppState, operation_id: Uuid) -> Result<PathBuf, Error> {
    Ok(replication::staging_root(state)?.join(format!("{operation_id}.sidecar.json")))
}

pub(crate) fn staged_path(state: &AppState, operation_id: Uuid) -> Result<PathBuf, Error> {
    Ok(replication::staging_root(state)?.join(format!("{operation_id}.sidecar")))
}

pub(super) fn receipt_path(state: &AppState, operation_id: Uuid) -> Result<PathBuf, Error> {
    Ok(replication::staging_root(state)?.join(format!("{operation_id}.sidecar.published.json")))
}

/// Persist the captured sidecar image before its transfer so a restart can
/// prove the exact measured operation sequence it is resuming.
pub(crate) fn write_progress(state: &AppState, bundle: &SidecarBundle) -> Result<(), Error> {
    let bytes = serde_json::to_vec(bundle).map_err(Error::internal)?;
    if bytes.len() > MAX_SIDECAR_BYTES {
        return Err(conflict("CI sidecar progress exceeds limit"));
    }
    journal::atomic(&progress_path(state, bundle.operation_id)?, &bytes, true).map_err(Error::internal)
}

/// Validate and durably stage a transferred bundle. The live `ci-pins`
/// directory is not touched here: only a committed cutover may publish.
pub(crate) fn stage_incoming(
    state: &AppState,
    bundle: &SidecarBundle,
    repo_id: Uuid,
    operation_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    manifest: &RefManifest,
) -> Result<(), Error> {
    validate_bundle_stage(
        bundle,
        repo_id,
        operation_id,
        owner_id,
        object_format,
        bundle.source_generation,
        manifest,
        &bundle.refs_sha256,
        bundle.journal_sequence,
    )?;
    let root = replication::staging_root(state)?;
    let temporary = root.join(format!(".{operation_id}.sidecar.tmp-{}", Uuid::new_v4()));
    if safe_directory(&temporary)? {
        fs::remove_dir_all(&temporary).map_err(Error::internal)?;
    }
    fs::create_dir(&temporary).map_err(Error::internal)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700)).map_err(Error::internal)?;
    let result = (|| {
        for file in &bundle.files {
            let path = temporary.join(&file.name);
            if path.parent() != Some(temporary.as_path()) {
                return Err(conflict("transferred CI sidecar path escapes its directory"));
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&path)
                .map_err(Error::internal)?;
            output.write_all(file.content.as_bytes()).map_err(Error::internal)?;
            output.sync_all().map_err(Error::internal)?;
        }
        let manifest_path = temporary.join("bundle.json");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&manifest_path)
            .map_err(Error::internal)?;
        output.write_all(&serde_json::to_vec(bundle).map_err(Error::internal)?).map_err(Error::internal)?;
        output.sync_all().map_err(Error::internal)?;
        sync_directory(&temporary)?;
        Ok::<_, Error>(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    let final_path = staged_path(state, operation_id)?;
    if safe_directory(&final_path)? {
        fs::remove_dir_all(&final_path).map_err(Error::internal)?;
    }
    fs::rename(&temporary, &final_path).map_err(Error::internal)?;
    sync_directory(&root)?;
    write_progress(state, bundle)?;
    Ok(())
}

/// New-generation files written by the new primary after cutover. They are
/// legitimate and must survive finalization; they are only accepted when their
/// retained root is in the current manifest and their receipt matches.
pub(super) fn scan_live_new_generation(
    directory: &FsPath,
    repo_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    target_generation: i64,
    source_generation: i64,
    manifest: &RefManifest,
) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    let scanned = read_sidecar_directory(directory, repo_id, owner_id, object_format, None)?;
    let roots = manifest_ci_roots(manifest)?;
    let mut values = BTreeMap::new();
    for (job, (intent, content)) in &scanned.intents {
        if intent.storage_generation <= source_generation {
            // Historical retention evidence is carried verbatim by the
            // bundle and must not be reclassified as a fresh target pin.
            continue;
        }
        if intent.storage_generation != target_generation {
            return Err(conflict("live CI sidecar has an unexpected storage generation"));
        }
        let Some(oid) = roots.get(&intent.retention_ref) else {
            return Err(conflict("live CI intent has no retained root"));
        };
        if oid != &intent.target_oid {
            return Err(conflict("live CI intent differs from its retained root"));
        }
        values.insert(format!("{job}.json"), content.clone());
        if let Some(receipt) = scanned.receipts.get(job) {
            values.insert(format!("{job}.pinned.json"), receipt.clone());
        }
    }
    for job in scanned.receipts.keys() {
        if !scanned.intents.contains_key(job) {
            return Err(conflict("live CI receipt has no intent"));
        }
    }
    Ok(values)
}

pub(super) fn desired_files(
    bundle: &SidecarBundle,
    repo_id: Uuid,
    owner_id: Uuid,
    object_format: &str,
    live: &BTreeMap<String, Vec<u8>>,
    manifest: &RefManifest,
) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    let (intents, receipts) =
        bundle_intents(bundle, repo_id, bundle.operation_id, owner_id, object_format, bundle.source_generation)?;
    let roots = manifest_ci_roots(manifest)?;
    let mut desired: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (job, intent) in intents {
        let Some(oid) = roots.get(&intent.retention_ref) else {
            if receipts.contains(&job) {
                return Err(conflict("CI pinned receipt has no retained root"));
            }
            continue;
        };
        if oid != &intent.target_oid {
            return Err(conflict("CI intent differs from the target retained root"));
        }
        let bytes = serde_json::to_vec(&intent).map_err(Error::internal)?;
        if let Some(existing) = desired.insert(format!("{job}.json"), bytes.clone())
            && existing != bytes
        {
            return Err(conflict("conflicting CI intent images during finalization"));
        }
        if receipts.contains(&job) {
            desired.insert(format!("{job}.pinned.json"), bytes);
        }
    }
    for (name, content) in live {
        if let Some(existing) = desired.insert(name.clone(), content.clone())
            && existing != *content
        {
            return Err(conflict("new-primary CI pin conflicts with transferred evidence"));
        }
    }
    for name in &bundle.retained_refs {
        if !manifest.refs.contains_key(name) {
            return Err(conflict("target lost a retained backup or snapshot root"));
        }
    }
    Ok(desired)
}

fn directory_image(path: &FsPath) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    let mut values = BTreeMap::new();
    for entry in fs::read_dir(path).map_err(Error::internal)? {
        let entry = entry.map_err(Error::internal)?;
        let name = entry.file_name().into_string().map_err(|_| conflict("non UTF-8 CI sidecar filename"))?;
        if name.starts_with(".tmp-") {
            continue;
        }
        let kind = entry.file_type().map_err(Error::internal)?;
        if !kind.is_file() || kind.is_symlink() {
            return Err(conflict("unsafe entry in live CI sidecar directory"));
        }
        values.insert(name, journal::read(&entry.path()).map_err(Error::internal)?);
    }
    Ok(values)
}

fn rename_exchange(left: &FsPath, right: &FsPath) -> std::io::Result<()> {
    let left = CString::new(left.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
    let right = CString::new(right.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
    // RENAME_EXCHANGE is 2 on Linux; the syscall atomically swaps both names.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            left.as_ptr(),
            libc::AT_FDCWD,
            right.as_ptr(),
            2 as libc::c_uint,
        )
    };
    if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
}

pub(super) fn publish_directory(
    root: &FsPath,
    repo_id: Uuid,
    desired: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Error> {
    let base = root.join("ci-pins");
    if !safe_directory(&base)? {
        journal::mkdir(&base).map_err(Error::internal)?;
    }
    if let Ok(meta) = fs::symlink_metadata(&base)
        && (meta.file_type().is_symlink() || meta.uid() != unsafe { libc::geteuid() })
    {
        return Err(conflict("unsafe live CI sidecar root"));
    }
    let temporary = base.join(format!(".{repo_id}.stage-{}", Uuid::new_v4()));
    fs::create_dir(&temporary).map_err(Error::internal)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700)).map_err(Error::internal)?;
    let result = (|| {
        for (name, content) in desired {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(temporary.join(name))
                .map_err(Error::internal)?;
            file.write_all(content).map_err(Error::internal)?;
            file.sync_all().map_err(Error::internal)?;
        }
        sync_directory(&temporary)?;
        Ok::<_, Error>(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    let destination = base.join(repo_id.to_string());
    if !safe_directory(&destination)? {
        fs::rename(&temporary, &destination).map_err(Error::internal)?;
        sync_directory(&base)?;
        return Ok(());
    }
    let desired_image: BTreeMap<String, Vec<u8>> =
        desired.iter().map(|(name, value)| (name.clone(), value.clone())).collect();
    if directory_image(&destination)? == desired_image {
        let _ = fs::remove_dir_all(&temporary);
        return Ok(());
    }
    match rename_exchange(&temporary, &destination) {
        Ok(()) => {
            sync_directory(&base)?;
            let _ = fs::remove_dir_all(&temporary);
            Ok(())
        }
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) || error.raw_os_error() == Some(libc::ENOSYS) => {
            let retired = base.join(format!(".{repo_id}.retired-{}", Uuid::new_v4()));
            fs::rename(&destination, &retired).map_err(Error::internal)?;
            if let Err(second) = fs::rename(&temporary, &destination) {
                let _ = fs::rename(&retired, &destination);
                return Err(Error::internal(second));
            }
            sync_directory(&base)?;
            let _ = fs::remove_dir_all(&retired);
            Ok(())
        }
        Err(error) => Err(Error::internal(error)),
    }
}
