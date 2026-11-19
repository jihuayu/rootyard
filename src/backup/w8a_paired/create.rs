//! Single-node W8-A paired backup creation.
//!
//! Preflight proves the source is one stable, PG RefStore serving incarnation
//! with no raft projection rows and captures the non-secret source authority
//! identity inside the shared `RepeatableRead` + `SHARE`-locked
//! `pg_export_snapshot()` transaction (never on a separate pre-snapshot
//! connection). Only after that inner format30 archive verifies does this
//! module add the W8-A sidecar and complete marker; publication is atomic.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Serialize;
use uuid::Uuid;

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

struct StagingW8aGuard {
    path: PathBuf,
    published: bool,
}

impl StagingW8aGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, published: false }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn publish_to(&mut self, destination: &Path) -> W8aResult<()> {
        super::super::publish(&self.path, destination).map_err(backup_error)?;
        self.published = true;
        Ok(())
    }
}

impl Drop for StagingW8aGuard {
    fn drop(&mut self) {
        if !self.published {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
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
    let staging_path = target
        .parent()
        .context("destination has no parent")
        .map_err(backup_error)?
        .join(format!(".rootyard-w8a-{}.partial", w8a_backup_id.simple()));
    if staging_path.exists() {
        return Err(W8aError::BackupFailed("staging directory already exists".into()));
    }
    super::super::private_dir(&staging_path).map_err(backup_error)?;
    let mut staging = StagingW8aGuard::new(staging_path);
    build(config, &mut staging, &target, w8a_backup_id).await
}

async fn build(
    config: &Config,
    staging: &mut StagingW8aGuard,
    target: &Path,
    w8a_backup_id: Uuid,
) -> W8aResult<W8aCreateReceipt> {
    let inner = staging.path().join("format30");
    let source = super::super::snapshot::create_with_source_check(config, &inner, |src| {
        ensure_clean_source(src.total_repositories, src.served_repositories, src.raft_cursors, src.raft_operations)
            .map_err(anyhow::Error::new)
    })
    .await
    .map_err(|error| match error.downcast::<W8aError>() {
        Ok(typed) => typed,
        Err(other) => W8aError::BackupFailed(format!("inner format30 backup: {other:#}")),
    })?;
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
    let sidecar_path = staging.path().join(SIDECAR);
    let sidecar_bytes = serde_json::to_vec(&sidecar)
        .map_err(|error| W8aError::BackupFailed(format!("serializing the sidecar: {error}")))?;
    super::super::write_private(&sidecar_path, &sidecar_bytes).map_err(backup_error)?;
    let sidecar_sha256 = super::super::hash(&sidecar_path).map_err(backup_error)?;
    super::super::write_private(&staging.path().join(COMPLETE), sidecar_sha256.as_bytes()).map_err(backup_error)?;
    staging.publish_to(target)?;
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
