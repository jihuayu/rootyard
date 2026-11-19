//! Stock-Git `fsck --full --strict` of the restored Blob bytes, before publication.
//! Every member is re-exported from the target backend (never trusted from the archive),
//! named by its Git pack trailer, and checked in a per-repository directory that is always removed.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

use serde::Serialize;
use uuid::Uuid;

use crate::blob_store::archive::ArchiveTransfer;
use crate::blob_store::config::BlobProfile;
use crate::blob_store::opendal::BlobStore;
use crate::config::Config;

use super::manifest_key_ref::W8aPairedSidecarManifest;
use super::{W8aError, W8aResult};

const EXPORT_SECONDS: u64 = 600;
#[derive(Debug, Clone, Serialize)]
pub struct W8aRepoFsckReceipt {
    pub repository_id: Uuid,
    pub object_format: String,
    pub head_ref: String,
    pub head_oid: String,
    pub refs: usize,
    pub pack_artifacts: usize,
}
struct RepoFsckDirGuard {
    path: PathBuf,
}
impl Drop for RepoFsckDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
pub(super) async fn run_guarded_fsck(
    config: &Config,
    client: &tokio_postgres::Client,
    mutex: &super::super::BackupMutex,
    sidecar: &W8aPairedSidecarManifest,
    artifacts: &[super::super::ledger::Artifact],
    compute: &Path,
) -> W8aResult<Vec<W8aRepoFsckReceipt>> {
    mutex.ensure_held(client).await.map_err(|error| W8aError::RestoreFailed(format!("{error:#}")))?;
    let store = BlobStore::open(
        BlobProfile::from_env().map_err(|error| W8aError::RestoreFailed(format!("opening Blob backend: {error}")))?,
    )
    .map_err(|error| W8aError::RestoreFailed(format!("opening Blob backend: {error}")))?;
    if store.backend_identity().as_hex() != sidecar.blob_backend_identity {
        return Err(W8aError::MissingOrCorruptBlobArtifact(
            "target Blob backend identity differs from the archive".into(),
        ));
    }
    let read = super::super::ArchiveRead::seal(sidecar.inner_volume_id, sidecar.inner_backup_id)
        .map_err(|error| W8aError::RestoreFailed(error.to_string()))?;
    let transfer = ArchiveTransfer::for_export(&read, store);
    let repos = client
        .query(
            "SELECT r.id, r.object_format, g.head_ref FROM public.repositories r JOIN public.ref_store_core_gates g ON g.repository_id=r.id JOIN public.ref_store_serving_repositories s ON s.repository_id=r.id WHERE r.storage_backend='pg_refstore' AND s.state='ready' ORDER BY r.id",
            &[],
        )
        .await
        .map_err(|error| W8aError::RestoreFailed(format!("listing restored repositories: {error}")))?;
    if repos.is_empty() {
        return Err(W8aError::RestoreFailed("restored database has no serving repositories".into()));
    }
    let refs = client
        .query(
            "SELECT repository_id, ref_name, oid FROM public.ref_store_core_refs ORDER BY repository_id, ref_name",
            &[],
        )
        .await
        .map_err(|error| W8aError::RestoreFailed(format!("listing restored refs: {error}")))?;
    let mut refs_by_repo: BTreeMap<Uuid, Vec<(String, String)>> = BTreeMap::new();
    for row in refs {
        refs_by_repo.entry(row.get(0)).or_default().push((row.get(1), row.get(2)));
    }
    let deadline = Instant::now() + Duration::from_secs(EXPORT_SECONDS);
    let mut receipts = Vec::new();
    for row in repos {
        let repository_id: Uuid = row.get(0);
        let object_format: String = row.get(1);
        let head_ref: String = row.get(2);
        if !matches!(object_format.as_str(), "sha1" | "sha256") {
            return Err(W8aError::RestoreFailed(format!(
                "repository {repository_id} has an unsupported object format"
            )));
        }
        let members: Vec<_> = artifacts.iter().filter(|artifact| artifact.repository_id == repository_id).collect();
        if members.is_empty() {
            return Err(W8aError::MissingOrCorruptBlobArtifact(format!("repository {repository_id} has no Blob pack")));
        }
        let repo_refs = refs_by_repo
            .get(&repository_id)
            .ok_or_else(|| W8aError::RestoreFailed(format!("repository {repository_id} has no restored refs")))?;
        let head_oid =
            repo_refs.iter().find(|(name, _)| name == &head_ref).map(|(_, oid)| oid.clone()).ok_or_else(|| {
                W8aError::RestoreFailed(format!("repository {repository_id} is missing its head ref"))
            })?;
        let directory = compute.join(format!(".w8a-fsck-{}", repository_id.simple()));
        super::super::private_dir(&directory)
            .map_err(|error| W8aError::RestoreFailed(format!("creating fsck directory: {error:#}")))?;
        let _guard = RepoFsckDirGuard { path: directory.clone() };
        mutex.ensure_held(client).await.map_err(|error| W8aError::RestoreFailed(format!("{error:#}")))?;
        let receipt = fsck_one(
            config,
            &directory,
            repository_id,
            &object_format,
            &head_ref,
            &head_oid,
            repo_refs,
            &members,
            &transfer,
            &read,
            deadline,
        )
        .await?;
        mutex.ensure_held(client).await.map_err(|error| W8aError::RestoreFailed(format!("{error:#}")))?;
        receipts.push(receipt);
    }
    mutex.ensure_held(client).await.map_err(|error| W8aError::RestoreFailed(format!("{error:#}")))?;
    Ok(receipts)
}
async fn fsck_one(
    config: &Config,
    directory: &Path,
    repository_id: Uuid,
    object_format: &str,
    head_ref: &str,
    head_oid: &str,
    refs: &[(String, String)],
    members: &[&super::super::ledger::Artifact],
    transfer: &ArchiveTransfer,
    read: &super::super::ArchiveRead,
    deadline: Instant,
) -> W8aResult<W8aRepoFsckReceipt> {
    let format_flag = format!("--object-format={object_format}");
    let output = git_at(config, directory, &["init", "--bare", "--quiet", format_flag.as_str()]).await?;
    if !output.status.success() {
        return Err(W8aError::RestoreFailed(format!("git init failed: {}", output_tail(&output))));
    }
    let staged = directory.join("w8a-members");
    super::super::private_dir(&staged)
        .map_err(|error| W8aError::RestoreFailed(format!("creating fsck staging: {error:#}")))?;
    let pack_dir = directory.join("objects").join("pack");
    let hash_len = if object_format == "sha256" { 32 } else { 20 };
    let mut names: BTreeMap<Uuid, String> = BTreeMap::new();
    let mut order = Vec::with_capacity(members.len());
    for member in members {
        let path = staged.join(format!("{}.{}", member.pack_id.simple(), member.role));
        let locator = member.locator().map_err(map_archive_error)?;
        transfer.export(read, &locator, &member.sha256, member.length, &path, deadline).await.map_err(|error| {
            W8aError::MissingOrCorruptBlobArtifact(format!("re-exporting restored Blob artifact: {error}"))
        })?;
        order.push((member.pack_id, member.role.clone(), path));
    }
    for (pack_id, role, path) in &order {
        if role != "pack" {
            continue;
        }
        let read_error =
            |error: std::io::Error| W8aError::MissingOrCorruptBlobArtifact(format!("reading exported pack: {error}"));
        let mut file = std::fs::File::open(path).map_err(read_error)?;
        let length = file.metadata().map_err(read_error)?.len();
        if length < hash_len as u64 {
            return Err(W8aError::MissingOrCorruptBlobArtifact("exported pack is truncated".into()));
        }
        file.seek(SeekFrom::End(-(hash_len as i64))).map_err(read_error)?;
        let mut trailer = vec![0u8; hash_len];
        file.read_exact(&mut trailer).map_err(read_error)?;
        let name = hex::encode(trailer);
        std::fs::rename(path, pack_dir.join(format!("pack-{name}.pack")))
            .map_err(|error| W8aError::RestoreFailed(format!("installing pack: {error}")))?;
        names.insert(*pack_id, name);
    }
    for (pack_id, role, path) in &order {
        if role != "idx" {
            continue;
        }
        let name = names
            .get(pack_id)
            .ok_or_else(|| W8aError::MissingOrCorruptBlobArtifact("idx artifact has no paired pack".into()))?;
        std::fs::rename(path, pack_dir.join(format!("pack-{name}.idx")))
            .map_err(|error| W8aError::RestoreFailed(format!("installing idx: {error}")))?;
    }
    for (name, oid) in refs {
        let output = git_at(config, directory, &["update-ref", name, oid]).await?;
        if !output.status.success() {
            return Err(W8aError::RestoreFailed(format!("git update-ref {name}: {}", output_tail(&output))));
        }
    }
    let head_out = git_at(config, directory, &["symbolic-ref", "HEAD", head_ref]).await?;
    if !head_out.status.success() {
        return Err(W8aError::RestoreFailed(format!("git symbolic-ref HEAD {head_ref}: {}", output_tail(&head_out))));
    }
    let output = git_at(config, directory, &["fsck", "--full", "--strict"]).await?;
    if !output.status.success() {
        return Err(W8aError::GitFsckFailed { repository_id, detail: output_tail(&output) });
    }
    Ok(W8aRepoFsckReceipt {
        repository_id,
        object_format: object_format.to_owned(),
        head_ref: head_ref.to_owned(),
        head_oid: head_oid.to_owned(),
        refs: refs.len(),
        pack_artifacts: members.len(),
    })
}
async fn git_at(config: &Config, directory: &Path, args: &[&str]) -> W8aResult<Output> {
    let mut full = vec![OsString::from("--git-dir"), directory.as_os_str().to_owned()];
    full.extend(args.iter().map(OsString::from));
    git_output(config, full).await
}
async fn git_output(config: &Config, args: Vec<OsString>) -> W8aResult<Output> {
    let mut command = super::super::command(&config.git);
    command.args(args).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    command.output().await.map_err(|error| W8aError::RestoreFailed(format!("running Git: {error}")))
}
fn output_tail(output: &Output) -> String {
    let mut combined = output.stdout.clone();
    combined.extend_from_slice(&output.stderr);
    String::from_utf8_lossy(&combined[combined.len().saturating_sub(1024)..]).into_owned()
}
fn map_archive_error(error: anyhow::Error) -> W8aError {
    W8aError::MissingOrCorruptBlobArtifact(format!("{error:#}").chars().take(512).collect())
}
