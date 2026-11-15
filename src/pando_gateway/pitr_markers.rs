//! Local non-PostgreSQL filesystem markers and crash-safe epoch claim intents
//! stored under `data_dir` for Pando PITR authority fencing (#77).
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const DEPLOYMENT_ID_FILE: &str = ".pando-deployment-id";
const VOLUME_ID_FILE: &str = ".volume-id";
const CLAIM_VERSION: u32 = 1;
const MAX_CLAIM_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorityClaimFile {
    pub(super) version: u32,
    pub(super) authority_id: Uuid,
    pub(super) target_epoch: i64,
    pub(super) deployment_id: Uuid,
    pub(super) volume_id: Uuid,
    pub(super) proof_nonce: Uuid,
    pub(super) backend_identity: String,
}

pub fn read_volume_id(data_dir: &Path) -> Result<Uuid> {
    read_uuid_marker(&data_dir.join(VOLUME_ID_FILE), "volume identity")
}

pub fn read_deployment_id_if_present(data_dir: &Path) -> Result<Option<Uuid>> {
    let path = data_dir.join(DEPLOYMENT_ID_FILE);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => read_uuid_marker(&path, "Pando deployment identity").map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn ensure_deployment_id(data_dir: &Path) -> Result<Uuid> {
    if let Some(existing) = read_deployment_id_if_present(data_dir)? {
        return Ok(existing);
    }
    let id = Uuid::new_v4();
    let target = data_dir.join(DEPLOYMENT_ID_FILE);
    let tmp = data_dir.join(format!("{DEPLOYMENT_ID_FILE}.{}.tmp", Uuid::new_v4()));
    let mut file =
        OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
    let write_res = file.write_all(id.to_string().as_bytes()).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = write_res {
        let _ = std::fs::remove_file(&tmp);
        return Err(error.into());
    }
    if let Err(error) = std::fs::rename(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error.into());
    }
    File::open(data_dir)?.sync_all()?;
    Ok(id)
}

fn read_uuid_marker(path: &Path, label: &str) -> Result<Uuid> {
    let meta = std::fs::symlink_metadata(path).with_context(|| format!("{label} missing"))?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1 && meta.len() == 36,
        "invalid {label} marker"
    );
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let mut text = String::new();
    (&mut file).take(64).read_to_string(&mut text)?;
    text.parse().with_context(|| format!("invalid {label} UUID"))
}

fn claim_file_path(data_dir: &Path, authority_id: Uuid) -> PathBuf {
    data_dir.join(format!(".pando-authority-claim-{authority_id}.json"))
}

pub(super) fn new_claim_file(
    authority_id: Uuid,
    target_epoch: i64,
    deployment_id: Uuid,
    volume_id: Uuid,
    backend_identity: String,
) -> AuthorityClaimFile {
    AuthorityClaimFile {
        version: CLAIM_VERSION,
        authority_id,
        target_epoch,
        deployment_id,
        volume_id,
        proof_nonce: Uuid::new_v4(),
        backend_identity,
    }
}

pub(super) fn read_claim_file(data_dir: &Path, authority_id: Uuid) -> Result<Option<AuthorityClaimFile>> {
    let path = claim_file_path(data_dir, authority_id);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1 && meta.len() <= MAX_CLAIM_BYTES as u64,
        "corrupt Pando authority claim file"
    );
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path)?;
    let mut bytes = Vec::new();
    (&mut file).take(MAX_CLAIM_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_CLAIM_BYTES, "Pando authority claim file exceeds limit");
    let claim: AuthorityClaimFile = serde_json::from_slice(&bytes).context("parse Pando authority claim file")?;
    ensure!(claim.version == CLAIM_VERSION && claim.authority_id == authority_id, "mismatched authority claim file");
    Ok(Some(claim))
}

pub(super) fn write_claim_file(data_dir: &Path, claim: &AuthorityClaimFile) -> Result<()> {
    let target = claim_file_path(data_dir, claim.authority_id);
    let tmp = data_dir.join(format!(".pando-authority-claim-{}.{}.tmp", claim.authority_id, Uuid::new_v4()));
    let payload = serde_json::to_vec(claim)?;
    let mut file =
        OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
    let res = file.write_all(&payload).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(error.into());
    }
    if let Err(error) = std::fs::rename(&tmp, &target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error.into());
    }
    File::open(data_dir)?.sync_all()?;
    Ok(())
}

pub fn clear_claim_file_best_effort(data_dir: &Path, authority_id: Uuid) {
    let _ = std::fs::remove_file(claim_file_path(data_dir, authority_id));
}
