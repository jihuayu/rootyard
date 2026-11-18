//! Single-node W8-A paired backup creation.
//!
//! Preflight proves the source is one stable, PG RefStore serving incarnation
//! with no raft projection rows, captures non-secret source identities, then
//! drops the read-only connection and delegates the frozen format30 archive to
//! the shared offline backup. Only after that inner archive verifies does this
//! module add the W8-A sidecar and complete marker; publication is atomic.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::Output;
use std::time::Instant;

use anyhow::Context;
use serde::Serialize;
use uuid::Uuid;

use crate::blob_store::archive::ArchiveTransfer;
use crate::config::Config;
use crate::storage_lifecycle::models::Policy;

use super::manifest_key_ref::{
    ENV_PAIRED_RAFT_CLUSTER, W8aKeyReference, W8aPairedSidecarManifest, capture_key_reference,
};
use super::{W8aError, W8aResult, ensure_destructive_gc_disabled};

const SIDECAR: &str = "w8a-paired.json";
const COMPLETE: &str = "W8A_COMPLETE";

#[derive(Debug, Clone, Serialize)]
pub struct W8aCreateReceipt {
    pub w8a_backup_id: Uuid,
    pub destination: String,
    pub format: u32,
    pub schema_head: i32,
    pub inner_backup_id: Uuid,
    pub inner_volume_id: Uuid,
    pub metadata_dump_sha256: String,
    pub blob_repository_count: usize,
    pub blob_artifact_count: usize,
    pub blob_total_bytes: u64,
    pub blob_closure_digest: String,
    pub source_cluster_incarnation: Uuid,
    pub source_storage_authority_id: Uuid,
    pub source_storage_authority_epoch: i64,
    pub key_reference: W8aKeyReference,
    pub sidecar: W8aPairedSidecarManifest,
}

#[derive(Debug, Clone, Copy)]
struct SourceIdentity {
    cluster_incarnation: Uuid,
    storage_authority_id: Uuid,
    storage_authority_epoch: i64,
}

pub async fn create(config: &Config, destination: &Path) -> W8aResult<W8aCreateReceipt> {
    let w8a_backup_id = Uuid::new_v4();
    if std::env::var_os(ENV_PAIRED_RAFT_CLUSTER).is_some() {
        return Err(W8aError::RaftCutForbiddenInSingleNodeW8a(format!(
            "{ENV_PAIRED_RAFT_CLUSTER} must be unset for a single-node W8-A backup"
        )));
    }
    if destination.join("paired-manifest.json").exists() {
        return Err(W8aError::RaftCutForbiddenInSingleNodeW8a(
            "destination already describes a paired raft cut".into(),
        ));
    }
    let target = super::super::absolute(destination, false)
        .map_err(|error| W8aError::BackupFailed(format!("destination: {error:#}")))?;
    let policy = Policy::from_env().map_err(|error| W8aError::BackupFailed(format!("policy: {error:#}")))?;
    ensure_destructive_gc_disabled(&policy)?;
    let source = read_source(config).await?;
    let staging = target
        .parent()
        .context("destination has no parent")
        .map_err(backup_error)?
        .join(format!(".rootyard-w8a-{}.partial", w8a_backup_id.simple()));
    if staging.exists() {
        return Err(W8aError::BackupFailed("staging directory already exists".into()));
    }
    super::super::private_dir(&staging).map_err(backup_error)?;
    let result = build(config, &staging, &target, w8a_backup_id, source).await;
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result
}

async fn build(
    config: &Config,
    staging: &Path,
    target: &Path,
    w8a_backup_id: Uuid,
    source: SourceIdentity,
) -> W8aResult<W8aCreateReceipt> {
    let inner = staging.join("format30");
    super::super::create(config, &inner)
        .await
        .map_err(|error| W8aError::BackupFailed(format!("inner format30 backup: {error:#}")))?;
    super::super::check(&inner)
        .map_err(|error| W8aError::BackupFailed(format!("inner format30 archive: {error:#}")))?;
    let raw = std::fs::read(inner.join("manifest.json"))
        .map_err(|error| W8aError::BackupFailed(format!("reading inner manifest: {error}")))?;
    let manifest: super::super::Manifest = serde_json::from_slice(&raw)
        .map_err(|error| W8aError::BackupFailed(format!("parsing inner manifest: {error}")))?;
    let schema_head = manifest
        .schema_versions
        .last()
        .copied()
        .ok_or_else(|| W8aError::BackupFailed("inner archive has no schema version".into()))?;
    if manifest.format != super::super::FORMAT_PAIRED {
        return Err(W8aError::BackupFailed(format!(
            "inner archive format {} is not the paired format {}",
            manifest.format,
            super::super::FORMAT_PAIRED
        )));
    }
    if schema_head != crate::db::SCHEMA_VERSIONS.last().copied().unwrap_or(0) {
        return Err(W8aError::BackupFailed(format!(
            "inner archive schema head {schema_head} is not {}",
            crate::db::SCHEMA_VERSIONS.last().copied().unwrap_or(0)
        )));
    }
    let closure = manifest
        .blob_closure
        .as_ref()
        .ok_or_else(|| W8aError::MissingOrCorruptBlobArtifact("inner archive has no Blob closure".into()))?;
    let mut per_repository: BTreeMap<Uuid, usize> = BTreeMap::new();
    for artifact in &manifest.blob_artifacts {
        *per_repository.entry(artifact.repository_id).or_insert(0) += 1;
    }
    if closure.artifacts == 0
        || closure.repositories == 0
        || manifest.blob_artifacts.len() != closure.artifacts
        || per_repository.len() != closure.repositories
        || per_repository.values().any(|count| count % 2 != 0)
    {
        return Err(W8aError::MissingOrCorruptBlobArtifact(
            "inner Blob closure counts do not describe paired pack/idx artifacts for every repository".into(),
        ));
    }
    if closure.backend_identity.is_empty() || closure.digest.len() != 64 {
        return Err(W8aError::MissingOrCorruptBlobArtifact(
            "inner Blob closure lacks a backend identity or digest".into(),
        ));
    }
    let metadata_dump_sha256 =
        super::super::hash(&inner.join("metadata.dump")).map_err(|error| W8aError::BackupFailed(error.to_string()))?;
    let inner_manifest_sha256 =
        super::super::hash(&inner.join("manifest.json")).map_err(|error| W8aError::BackupFailed(error.to_string()))?;
    let inner_complete_sha256 =
        super::super::hash(&inner.join("COMPLETE")).map_err(|error| W8aError::BackupFailed(error.to_string()))?;
    let key_reference = capture_key_reference(w8a_backup_id, &closure.backend_identity)?;
    let sidecar = W8aPairedSidecarManifest {
        w8a_backup_id,
        format: manifest.format,
        schema_head,
        schema_contract_sha256: manifest.schema_contract_sha256.clone(),
        metadata_dump_sha256,
        inner_manifest_sha256,
        inner_complete_sha256,
        inner_backup_id: manifest.backup_id,
        inner_volume_id: manifest.volume_id,
        blob_repository_count: closure.repositories,
        blob_artifact_count: closure.artifacts,
        blob_total_bytes: closure.bytes,
        blob_closure_digest: closure.digest.clone(),
        blob_backend_identity: closure.backend_identity.clone(),
        blob_provider: closure.provider.clone(),
        source_cluster_incarnation: source.cluster_incarnation,
        source_storage_authority_id: source.storage_authority_id,
        source_storage_authority_epoch: source.storage_authority_epoch,
        key_reference: key_reference.clone(),
        single_node_w8a: true,
        raft_cut_supported: false,
        paired_restore_trusted: false,
        manifest_seal_sha256: String::new(),
    }
    .seal()?;
    let sidecar_path = staging.join(SIDECAR);
    let sidecar_bytes = serde_json::to_vec(&sidecar)
        .map_err(|error| W8aError::BackupFailed(format!("serializing the sidecar: {error}")))?;
    super::super::write_private(&sidecar_path, &sidecar_bytes).map_err(backup_error)?;
    let sidecar_sha256 = super::super::hash(&sidecar_path).map_err(backup_error)?;
    super::super::write_private(&staging.join(COMPLETE), sidecar_sha256.as_bytes()).map_err(backup_error)?;
    super::super::publish(staging, target).map_err(backup_error)?;
    Ok(W8aCreateReceipt {
        w8a_backup_id,
        destination: target.display().to_string(),
        format: manifest.format,
        schema_head,
        inner_backup_id: manifest.backup_id,
        inner_volume_id: manifest.volume_id,
        metadata_dump_sha256: sidecar.metadata_dump_sha256.clone(),
        blob_repository_count: closure.repositories,
        blob_artifact_count: closure.artifacts,
        blob_total_bytes: closure.bytes,
        blob_closure_digest: closure.digest.clone(),
        source_cluster_incarnation: source.cluster_incarnation,
        source_storage_authority_id: source.storage_authority_id,
        source_storage_authority_epoch: source.storage_authority_epoch,
        key_reference,
        sidecar,
    })
}

async fn read_source(config: &Config) -> W8aResult<SourceIdentity> {
    let client = super::super::pg(config).await.map_err(backup_error)?;
    let row = client
        .query_one(
            "SELECT
                 (SELECT count(*) FROM public.repositories),
                 (SELECT count(*) FROM public.repositories WHERE storage_backend='pg_refstore'),
                 (SELECT count(*) FROM public.ref_cas_projection_cursors),
                 (SELECT count(*) FROM public.ref_cas_projected_operations),
                 ca.incarnation, p.authority_id, p.authority_epoch
             FROM public.cluster_authority ca, public.pando_storage_authorities p
             WHERE ca.singleton=true AND p.singleton=true",
            &[],
        )
        .await
        .map_err(|error| W8aError::BackupFailed(format!("source preflight: {error}")))?;
    let total: i64 = row.get(0);
    let served: i64 = row.get(1);
    let raft_cursors: i64 = row.get(2);
    let raft_operations: i64 = row.get(3);
    ensure_clean_source(total, served, raft_cursors, raft_operations)?;
    let source = SourceIdentity {
        cluster_incarnation: row.get(4),
        storage_authority_id: row.get(5),
        storage_authority_epoch: row.get(6),
    };
    drop(client);
    Ok(source)
}

fn ensure_clean_source(total: i64, served: i64, raft_cursors: i64, raft_operations: i64) -> W8aResult<()> {
    if raft_cursors != 0 || raft_operations != 0 {
        return Err(W8aError::RaftCutForbiddenInSingleNodeW8a(format!(
            "raft projection rows exist ({raft_cursors} cursors, {raft_operations} operations)"
        )));
    }
    if total == 0 || total != served {
        return Err(W8aError::UnsupportedRepositoryBackend(format!(
            "{total} repositories, {served} with committed PG RefStore serving"
        )));
    }
    Ok(())
}

fn backup_error(error: anyhow::Error) -> W8aError {
    W8aError::BackupFailed(format!("{error:#}"))
}

#[cfg(test)]
mod tests {
    use super::ensure_clean_source;

    #[test]
    fn preflight_refuses_mixed_backends_and_raft_rows() {
        assert!(ensure_clean_source(1, 1, 0, 0).is_ok());
        assert!(ensure_clean_source(0, 0, 0, 0).is_err());
        assert!(ensure_clean_source(2, 1, 0, 0).is_err());
        assert!(ensure_clean_source(1, 1, 1, 0).is_err());
        assert!(ensure_clean_source(1, 1, 0, 1).is_err());
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct W8aRepoFsckReceipt {
    pub repository_id: Uuid,
    pub object_format: String,
    pub head_ref: String,
    pub head_oid: String,
    pub refs: usize,
    pub pack_artifacts: usize,
}

pub(super) async fn fsck_one(
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
    let init = vec![
        OsString::from("init"),
        OsString::from("--bare"),
        OsString::from("--quiet"),
        OsString::from(format!("--object-format={object_format}")),
        directory.as_os_str().to_owned(),
    ];
    git_output(config, init).await?;
    let pack_dir = directory.join("objects/pack");
    std::fs::create_dir_all(&pack_dir).map_err(|error| W8aError::RestoreFailed(error.to_string()))?;
    let mut temporary: BTreeMap<Uuid, BTreeMap<String, std::path::PathBuf>> = BTreeMap::new();
    for artifact in members {
        let target = pack_dir.join(format!("w8a-tmp-{}-{}", artifact.pack_id, artifact.role));
        transfer
            .export(
                read,
                &artifact.locator().map_err(map_archive_error)?,
                &artifact.sha256,
                artifact.length,
                &target,
                deadline,
            )
            .await
            .map_err(|error| W8aError::MissingOrCorruptBlobArtifact(format!("exporting {}: {error}", artifact.role)))?;
        temporary.entry(artifact.pack_id).or_default().insert(artifact.role.clone(), target);
    }
    let checksum_len = if object_format == "sha1" { 20 } else { 32 };
    for (pack_id, mut roles) in temporary {
        let pack = roles
            .remove("pack")
            .ok_or_else(|| W8aError::MissingOrCorruptBlobArtifact(format!("pack {pack_id} has no pack member")))?;
        let bytes = std::fs::read(&pack)
            .map_err(|error| W8aError::MissingOrCorruptBlobArtifact(format!("reading pack {pack_id}: {error}")))?;
        if bytes.len() < checksum_len {
            return Err(W8aError::MissingOrCorruptBlobArtifact(format!("pack {pack_id} is truncated")));
        }
        let name = format!("pack-{}", hex::encode(&bytes[bytes.len() - checksum_len..]));
        std::fs::rename(&pack, pack_dir.join(format!("{name}.pack")))
            .map_err(|error| W8aError::RestoreFailed(format!("naming pack {pack_id}: {error}")))?;
        let idx = roles
            .remove("idx")
            .ok_or_else(|| W8aError::MissingOrCorruptBlobArtifact(format!("pack {pack_id} has no idx member")))?;
        std::fs::rename(&idx, pack_dir.join(format!("{name}.idx")))
            .map_err(|error| W8aError::RestoreFailed(format!("naming idx {pack_id}: {error}")))?;
    }
    for (name, oid) in refs {
        git_at(config, directory, &["update-ref", name, oid]).await?;
    }
    git_at(config, directory, &["symbolic-ref", "HEAD", head_ref]).await?;
    let fsck = git_at(config, directory, &["fsck", "--full", "--strict"]).await?;
    if !fsck.status.success() {
        return Err(W8aError::GitFsckFailed { repository_id, detail: output_tail(&fsck) });
    }
    Ok(W8aRepoFsckReceipt {
        repository_id,
        object_format: object_format.into(),
        head_ref: head_ref.into(),
        head_oid: head_oid.into(),
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
