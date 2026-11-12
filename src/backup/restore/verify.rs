//! Archive verification shared by `backup-verify` and isolated restore.
//!
//! The checks stay in the parent `restore` module's scope so the public
//! `check`/`restore` entrypoints remain defined in `src/backup/restore.rs`.
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
        matches!(manifest.format, 4..=22)
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
    let has_blob = match fs::symlink_metadata(source.join("blob")) {
        Ok(meta) => {
            ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "invalid Blob closure directory");
            for (name, entry) in inventory(&source.join("blob"))? {
                actual.insert(format!("blob/{name}"), entry);
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
    if has_blob {
        allowed.push("blob".into());
    }
    // The archive version and its members must agree exactly: a paired archive
    // carries locators, a closure summary and a blob/ tree; a format21 archive
    // carries none of them and is never presented as an independent backup.
    match manifest.format {
        FORMAT_PAIRED => {
            let closure = manifest.blob_closure.as_ref().context("paired archive carries no Blob closure")?;
            ensure!(has_blob, "paired archive is missing its Blob byte closure");
            ensure!(
                closure.artifacts == manifest.blob_artifacts.len(),
                "Blob closure count differs from its artifact locators"
            );
            ensure!(
                closure.bytes == manifest.blob_artifacts.iter().map(|a| a.length).sum::<u64>(),
                "Blob closure byte total differs from its artifact locators"
            );
            ensure!(
                closure.digest
                    == ledger::closure_of(&manifest.blob_artifacts, &closure.backend_identity, &closure.provider)
                        .digest,
                "Blob closure digest differs from its artifact locators"
            );
            for artifact in &manifest.blob_artifacts {
                ensure!(matches!(artifact.role.as_str(), "pack" | "idx"), "unsupported archived artifact role");
                let entry =
                    manifest.files.get(&artifact.archive_path()).context("paired archive is missing an artifact")?;
                ensure!(
                    entry.bytes == artifact.length && entry.sha256.as_deref() == Some(artifact.sha256.as_str()),
                    "archived Blob member differs from its locator"
                );
                ensure!(!artifact.attempt_id.is_nil(), "Blob locator has no attempt id");
            }
            ensure!(manifest.refstore.is_some(), "paired archive carries no RefStore carry map");
            ensure!(
                actual.iter().filter(|(name, entry)| name.starts_with("blob/") && entry.kind == "file").count()
                    == manifest.blob_artifacts.len(),
                "Blob closure member inventory differs from its artifact locators"
            );
        }
        FORMAT => ensure!(
            manifest.blob_closure.is_none()
                && manifest.blob_artifacts.is_empty()
                && manifest.refstore.is_none()
                && !has_blob,
            "metadata archive must not carry Blob bytes or locators"
        ),
        _ => ensure!(
            manifest.blob_closure.is_none()
                && manifest.blob_artifacts.is_empty()
                && manifest.refstore.is_none()
                && !has_blob,
            "historical archive must not carry paired Blob members"
        ),
    }
    allowed.sort();
    ensure!(names == allowed, "unexpected backup files");
    Ok(manifest)
}
