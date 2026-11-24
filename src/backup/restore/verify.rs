//! Archive verification shared by `backup-verify` and isolated restore.
//!
//! The checks stay in the parent `restore` module's scope so the public
//! `check`/`restore` entrypoints remain defined in `src/backup/restore.rs`.
use super::*;

pub(crate) struct VerifiedArchiveIdentity {
    pub(crate) format: u32,
    pub(crate) backup_id: Uuid,
    pub(crate) schema_head: i32,
    pub(crate) schema_contract_sha256: String,
    pub(crate) repository_count: usize,
}

/// The two outer paired protocols were introduced with format 30. Their
/// version-one envelopes keep their existing paths and seal domains.
pub(crate) fn paired_envelope_schema_head(format: u32) -> Option<i32> {
    match format {
        30 | FORMAT_PAIRED => schema_versions(format).ok()?.last().copied(),
        _ => None,
    }
}

/// Verify the actual inner archive and return the identity covered by its
/// manifest and COMPLETE marker without re-parsing an unchecked manifest.
pub(crate) fn verify_archive_identity(source: &Path) -> Result<VerifiedArchiveIdentity> {
    let manifest = verify(&absolute(source, true)?)?;
    Ok(VerifiedArchiveIdentity {
        format: manifest.format,
        backup_id: manifest.backup_id,
        schema_head: manifest.schema_versions.last().copied().context("inner archive has no schema version")?,
        schema_contract_sha256: manifest.schema_contract_sha256,
        repository_count: manifest.repositories.len(),
    })
}

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
        matches!(manifest.format, 4..=32)
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
        format if catalog::is_paired(format) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn sha256(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<()> {
        fs::write(path, data)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    fn write_archive(root: &Path, format: u32, malformed_closure: bool) -> Result<()> {
        fs::create_dir_all(root)?;
        let volume = root.join("volume");
        fs::create_dir(&volume)?;
        fs::set_permissions(&volume, fs::Permissions::from_mode(0o700))?;
        let volume_id = Uuid::from_u128(0x11);
        write_file(&volume.join(".volume-id"), volume_id.to_string().as_bytes(), 0o600)?;

        let repository_id = Uuid::from_u128(0x21);
        let pack_id = Uuid::from_u128(0x22);
        let data = b"canonical packed bytes";
        let blob = root.join("blob");
        let repository_blob = blob.join(repository_id.to_string());
        let pack_blob = repository_blob.join(pack_id.to_string());
        fs::create_dir_all(&pack_blob)?;
        for directory in [&blob, &repository_blob, &pack_blob] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        }
        let artifact_path = pack_blob.join("pack.pack");
        write_file(&artifact_path, data, 0o600)?;

        let artifact = ledger::Artifact {
            repository_id,
            registration_id: Uuid::from_u128(0x23),
            pack_id,
            role: "pack".into(),
            slot: 0,
            hold_id: Uuid::from_u128(0x24),
            acquire_request_id: Uuid::from_u128(0x25),
            consume_request_id: Uuid::from_u128(0x26),
            provider: "s3".into(),
            backend_identity: "a".repeat(64),
            sha256: sha256(data),
            length: data.len() as u64,
            tenant_id: Uuid::from_u128(0x27),
            authority_id: Uuid::from_u128(0x28),
            generation: 1,
            attempt_id: Uuid::from_u128(0x29),
            namespace: "format28".into(),
            artifact_set_digest: None,
            declared_by: Vec::new(),
        };
        let mut closure = ledger::closure_of(std::slice::from_ref(&artifact), &artifact.backend_identity, "s3");
        if malformed_closure {
            closure.artifacts += 1;
        }

        let metadata = b"real pg dump bytes";
        write_file(&root.join("metadata.dump"), metadata, 0o600)?;
        let mut files = BTreeMap::new();
        for (name, entry) in inventory(&volume)? {
            files.insert(format!("volume/{name}"), entry);
        }
        for (name, entry) in inventory(&blob)? {
            files.insert(format!("blob/{name}"), entry);
        }
        files.insert(
            "metadata.dump".into(),
            Entry {
                kind: "file".into(),
                mode: 0o600,
                bytes: metadata.len() as u64,
                sha256: Some(sha256(metadata)),
                target: None,
            },
        );

        let manifest = Manifest {
            format,
            backup_id: Uuid::from_u128(0x31),
            volume_id,
            schema_contract_sha256: schema_contract_digest(format)?,
            boundary_unix_seconds: 0,
            rootyard_version: "test".into(),
            binary_sha256: "b".repeat(64),
            postgres_version: "17".into(),
            pg_dump_version: "17".into(),
            git_version: "2.47.3".into(),
            schema_versions: schema_versions(format)?,
            consistency: "complete".into(),
            journal_record_files: 0,
            repositories: vec![Repository {
                id: repository_id,
                generation: 1,
                incident_revision: 0,
                state: "ready".into(),
                recovery_reason: None,
                backend: Some("pg_refstore".into()),
                unknown_operations: 0,
                refs: None,
                head: None,
            }],
            lfs_objects: Vec::new(),
            blob_closure: Some(closure),
            blob_artifacts: vec![artifact],
            refstore: Some(BTreeMap::new()),
            files,
        };
        let bytes = serde_json::to_vec(&manifest)?;
        write_file(&root.join("manifest.json"), &bytes, 0o600)?;
        write_file(&root.join("COMPLETE"), sha256(&bytes).as_bytes(), 0o600)?;
        Ok(())
    }

    #[test]
    fn frozen_and_current_paired_layouts_verify() -> Result<()> {
        for format in [28, 30, 32] {
            let temp = tempfile::tempdir()?;
            write_archive(temp.path(), format, false)?;
            let manifest = verify(temp.path())?;
            assert_eq!(manifest.format, format);
            assert_eq!(manifest.blob_artifacts.len(), 1);
            assert!(manifest.blob_closure.is_some());
            assert!(manifest.refstore.is_some());
        }
        Ok(())
    }

    #[test]
    fn metadata_formats_and_malformed_paired_layouts_stay_rejected() -> Result<()> {
        for format in [27, 29, 31] {
            let temp = tempfile::tempdir()?;
            write_archive(temp.path(), format, false)?;
            let error = verify(temp.path()).unwrap_err().to_string();
            assert!(error.contains("must not carry"), "format {format}: {error}");
        }
        for format in [28, 30, 32] {
            let temp = tempfile::tempdir()?;
            write_archive(temp.path(), format, true)?;
            let error = verify(temp.path()).unwrap_err().to_string();
            assert!(error.contains("Blob closure count"), "format {format}: {error}");
        }
        Ok(())
    }
}
