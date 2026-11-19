//! W8-A paired archive verification and fresh-incarnation restore.
//!
//! Verification is read-only. Restore delegates PostgreSQL + Blob rebuild to the
//! shared format30 path, proves no raft projection rows, applies the W8-A
//! fresh-incarnation fence, and runs stock Git fsck on bytes re-exported from
//! the target Blob backend.
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::Serialize;
use uuid::Uuid;

use crate::config::Config;
use crate::storage_lifecycle::models::Policy;

use super::fsck::W8aRepoFsckReceipt;
use super::manifest_key_ref::{ENV_PAIRED_RAFT_CLUSTER, W8aPairedSidecarManifest, verify_key_reference};
use super::{W8aError, W8aFenceReceipt, W8aResult, ensure_destructive_gc_disabled};
const SIDECAR: &str = "w8a-paired.json";
const COMPLETE: &str = "W8A_COMPLETE";
const INNER: &str = "format30";
const MAX_SIDECAR_BYTES: u64 = 64 * 1024;
#[derive(Debug, Clone, Serialize)]
pub struct W8aRestoreReceipt {
    pub w8a_backup_id: Uuid,
    pub source: String,
    pub destination: String,
    pub trusted_backup: bool,
    pub destination_trusted: bool,
    pub format: u32,
    pub schema_head: i32,
    pub new_cluster_incarnation: Uuid,
    pub new_storage_authority_id: Uuid,
    pub new_storage_restore_generation: i64,
    pub new_storage_authority_epoch: i64,
    pub remote_delete_fenced: bool,
    pub destructive_gc_enabled: bool,
    pub revoked_tokens: i64,
    pub revoked_sessions: i64,
    pub cancelled_ci_runs: i64,
    pub revoked_ci_checkouts: i64,
    pub expired_workspaces: i64,
    pub cancelled_decisions: i64,
    pub advanced_decision_scopes: i64,
    pub released_pins: i64,
    pub aborted_pull_merges: i64,
    pub reset_deliveries: i64,
    pub repositories_fscked: Vec<W8aRepoFsckReceipt>,
}

struct Checked {
    root: PathBuf,
    sidecar: W8aPairedSidecarManifest,
}
pub fn check(source: &Path) -> W8aResult<W8aPairedSidecarManifest> {
    Ok(inspect(source)?.sidecar)
}
pub async fn restore(
    config: &Config,
    source: &Path,
    compute_dir: &Path,
    trust_backup: bool,
) -> W8aResult<W8aRestoreReceipt> {
    if !trust_backup {
        return Err(W8aError::RestoreFailed("paired restore requires explicit --trust-backup".into()));
    }
    if std::env::var_os(ENV_PAIRED_RAFT_CLUSTER).is_some() {
        return Err(W8aError::RaftCutForbiddenInSingleNodeW8a(format!(
            "{ENV_PAIRED_RAFT_CLUSTER} must be unset for single-node W8-A restore"
        )));
    }
    let policy = Policy::from_env().map_err(|error| W8aError::RestoreFailed(format!("policy: {error:#}")))?;
    ensure_destructive_gc_disabled(&policy)?;
    let checked = inspect(source)?;
    verify_key_reference(
        &checked.sidecar.key_reference,
        checked.sidecar.w8a_backup_id,
        &checked.sidecar.blob_backend_identity,
    )?;
    let compute = prepare_compute(compute_dir, &checked.root, &config.data_dir)?;
    let plan = super::super::restore::W8aRestorePlan { sidecar: &checked.sidecar, compute_dir: compute.path() };
    let (fence, repos) = super::super::restore::restore_w8a_paired(config, &checked.root.join(INNER), plan)
        .await
        .map_err(|error| match error.downcast::<W8aError>() {
            Ok(typed) => typed,
            Err(other) => classify_restore_error(&format!("{other:#}")),
        })?;
    Ok(W8aRestoreReceipt {
        w8a_backup_id: checked.sidecar.w8a_backup_id,
        source: checked.root.display().to_string(),
        destination: config.data_dir.display().to_string(),
        trusted_backup: true,
        destination_trusted: true,
        format: checked.sidecar.format,
        schema_head: checked.sidecar.schema_head,
        new_cluster_incarnation: fence.new_cluster_incarnation,
        new_storage_authority_id: fence.new_storage_authority_id,
        new_storage_restore_generation: fence.new_storage_restore_generation,
        new_storage_authority_epoch: fence.new_storage_authority_epoch,
        remote_delete_fenced: fence.remote_delete_fenced,
        destructive_gc_enabled: false,
        revoked_tokens: fence.revoked_tokens,
        revoked_sessions: fence.revoked_sessions,
        cancelled_ci_runs: fence.cancelled_ci_runs,
        revoked_ci_checkouts: fence.revoked_ci_checkouts,
        expired_workspaces: fence.expired_workspaces,
        cancelled_decisions: fence.cancelled_decisions,
        advanced_decision_scopes: fence.advanced_decision_scopes,
        released_pins: fence.released_pins,
        aborted_pull_merges: fence.aborted_pull_merges,
        reset_deliveries: fence.reset_deliveries,
        repositories_fscked: repos,
    })
}
fn inspect(source: &Path) -> W8aResult<Checked> {
    let root = super::super::absolute(source, true)
        .map_err(|error| W8aError::RestoreFailed(format!("archive path: {error:#}")))?;
    if root.join("paired-manifest.json").exists() {
        return Err(W8aError::RaftCutForbiddenInSingleNodeW8a(
            "paired-manifest.json describes a multi-node raft cut, not a single-node W8-A backup".into(),
        ));
    }
    let mut names = std::fs::read_dir(&root)
        .map_err(|error| W8aError::RestoreFailed(format!("reading archive: {error}")))?
        .map(|entry| entry.map(|value| value.file_name()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| W8aError::RestoreFailed(format!("reading archive: {error}")))?;
    names.sort();
    let allowed: Vec<OsString> = [COMPLETE, INNER, SIDECAR].into_iter().map(OsString::from).collect();
    if names != allowed {
        return Err(W8aError::MixedPointInTime(
            "paired archive must contain exactly W8A_COMPLETE, format30 and w8a-paired.json".into(),
        ));
    }
    let complete_path = root.join(COMPLETE);
    if regular_file(&complete_path, "W8A_COMPLETE", false)?.len() != 64 {
        return Err(W8aError::MixedPointInTime("W8A_COMPLETE must be exactly 64 bytes".into()));
    }
    let recorded_complete = std::fs::read_to_string(&complete_path)
        .map_err(|error| W8aError::MixedPointInTime(format!("reading W8A_COMPLETE: {error}")))?;
    if !is_lower_hex_64(&recorded_complete) {
        return Err(W8aError::MixedPointInTime("W8A_COMPLETE is not a lowercase SHA-256".into()));
    }
    let sidecar_path = root.join(SIDECAR);
    let sidecar_meta = regular_file(&sidecar_path, SIDECAR, false)?;
    if sidecar_meta.len() == 0 || sidecar_meta.len() > MAX_SIDECAR_BYTES {
        return Err(W8aError::MixedPointInTime("w8a-paired.json size is out of range".into()));
    }
    let sidecar: W8aPairedSidecarManifest = serde_json::from_slice(
        &std::fs::read(&sidecar_path)
            .map_err(|error| W8aError::MixedPointInTime(format!("reading sidecar: {error}")))?,
    )
    .map_err(|error| W8aError::MixedPointInTime(format!("parsing w8a-paired.json: {error}")))?;
    sidecar.verify_manifest_seal()?;
    if recorded_complete != super::super::hash(&sidecar_path).map_err(map_archive_error)? {
        return Err(W8aError::MixedPointInTime("W8A_COMPLETE does not cover w8a-paired.json".into()));
    }
    if sidecar.w8a_backup_id.is_nil()
        || sidecar.source_cluster_incarnation.is_nil()
        || sidecar.source_storage_authority_id.is_nil()
        || sidecar.format != super::super::FORMAT_PAIRED
        || sidecar.schema_head != crate::db::SCHEMA_VERSIONS.last().copied().unwrap_or(0)
        || sidecar.blob_backend_identity.is_empty()
        || sidecar.blob_provider.is_empty()
        || !sidecar.single_node_w8a
        || sidecar.raft_cut_supported
        || sidecar.source_storage_authority_epoch < 1
    {
        return Err(W8aError::MixedPointInTime("sidecar topology or format identity is invalid".into()));
    }
    let inner = root.join(INNER);
    let inner_meta = std::fs::symlink_metadata(&inner)
        .map_err(|error| W8aError::MixedPointInTime(format!("reading format30: {error}")))?;
    if !inner_meta.is_dir() || inner_meta.file_type().is_symlink() {
        return Err(W8aError::MixedPointInTime("format30 is not a real directory".into()));
    }
    let manifest: super::super::Manifest = serde_json::from_slice(
        &std::fs::read(inner.join("manifest.json"))
            .map_err(|error| W8aError::MixedPointInTime(format!("reading inner manifest: {error}")))?,
    )
    .map_err(|error| W8aError::MixedPointInTime(format!("parsing inner manifest: {error}")))?;
    let schema_head = manifest
        .schema_versions
        .last()
        .copied()
        .ok_or_else(|| W8aError::MixedPointInTime("inner manifest has no schema version".into()))?;
    if manifest.format != sidecar.format
        || schema_head != sidecar.schema_head
        || manifest.backup_id != sidecar.inner_backup_id
        || manifest.volume_id != sidecar.inner_volume_id
        || manifest.schema_contract_sha256 != sidecar.schema_contract_sha256
    {
        return Err(W8aError::MixedPointInTime("sidecar and inner manifest identities differ".into()));
    }
    if super::super::schema_contract_digest(sidecar.format).map_err(map_archive_error)?
        != sidecar.schema_contract_sha256
    {
        return Err(W8aError::MixedPointInTime("sidecar schema contract digest is not the frozen catalog".into()));
    }
    let closure = manifest
        .blob_closure
        .as_ref()
        .ok_or_else(|| W8aError::MissingOrCorruptBlobArtifact("inner archive has no Blob closure".into()))?;
    let recomputed = super::super::ledger::closure_of(
        &manifest.blob_artifacts,
        &sidecar.blob_backend_identity,
        &sidecar.blob_provider,
    );
    if recomputed.repositories != sidecar.blob_repository_count
        || recomputed.artifacts != sidecar.blob_artifact_count
        || recomputed.bytes != sidecar.blob_total_bytes
        || recomputed.digest != sidecar.blob_closure_digest
        || closure.backend_identity != sidecar.blob_backend_identity
        || closure.provider != sidecar.blob_provider
        || closure.artifacts != sidecar.blob_artifact_count
        || closure.bytes != sidecar.blob_total_bytes
    {
        return Err(W8aError::MissingOrCorruptBlobArtifact(
            "inner Blob closure summary differs from the sidecar".into(),
        ));
    }
    if super::super::hash(&inner.join("metadata.dump")).map_err(map_archive_error)? != sidecar.metadata_dump_sha256
        || super::super::hash(&inner.join("manifest.json")).map_err(map_archive_error)? != sidecar.inner_manifest_sha256
        || super::super::hash(&inner.join("COMPLETE")).map_err(map_archive_error)? != sidecar.inner_complete_sha256
    {
        return Err(W8aError::MixedPointInTime(
            "metadata.dump, inner manifest or inner COMPLETE was swapped after the sidecar was sealed".into(),
        ));
    }
    for artifact in &manifest.blob_artifacts {
        let path = inner.join(artifact.archive_path());
        let metadata = regular_file(&path, "archived Blob member", false)
            .map_err(|error| W8aError::MissingOrCorruptBlobArtifact(format!("Blob member: {error}")))?;
        if metadata.len() != artifact.length
            || super::super::hash(&path).map_err(|error| {
                W8aError::MissingOrCorruptBlobArtifact(format!("hashing archived Blob member: {error:#}"))
            })? != artifact.sha256
        {
            return Err(W8aError::MissingOrCorruptBlobArtifact(format!(
                "archived Blob member {} differs from its locator",
                artifact.archive_path()
            )));
        }
    }
    super::super::check(&inner).map_err(|error| classify_inner_error(&format!("{error:#}")))?;
    Ok(Checked { root, sidecar })
}
fn regular_file(path: &Path, label: &str, blob: bool) -> W8aResult<std::fs::Metadata> {
    let invalid = |message: String| {
        if blob { W8aError::MissingOrCorruptBlobArtifact(message) } else { W8aError::MixedPointInTime(message) }
    };
    let meta = std::fs::symlink_metadata(path).map_err(|error| invalid(format!("{label}: {error}")))?;
    #[cfg(unix)]
    let multi_link = {
        use std::os::unix::fs::MetadataExt;
        meta.nlink() != 1
    };
    #[cfg(not(unix))]
    let multi_link = false;
    if !meta.is_file() || meta.file_type().is_symlink() || multi_link {
        return Err(invalid(format!("{label} must be a single-link regular file")));
    }
    Ok(meta)
}
fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn classify_restore_error(error: &str) -> W8aError {
    let lowered = error.to_ascii_lowercase();
    if lowered.contains("refstore rows differ") {
        W8aError::MixedPointInTime(error.chars().take(512).collect())
    } else if ["blob", "rebuild", "backend identity"].iter().any(|needle| lowered.contains(needle)) {
        W8aError::MissingOrCorruptBlobArtifact(error.chars().take(512).collect())
    } else {
        W8aError::RestoreFailed(error.chars().take(512).collect())
    }
}
fn classify_inner_error(error: &str) -> W8aError {
    match classify_restore_error(error) {
        W8aError::MissingOrCorruptBlobArtifact(reason) => W8aError::MissingOrCorruptBlobArtifact(reason),
        W8aError::MixedPointInTime(reason) => W8aError::MixedPointInTime(reason),
        _ => W8aError::MixedPointInTime(error.chars().take(512).collect()),
    }
}
fn map_archive_error(error: anyhow::Error) -> W8aError {
    classify_inner_error(&format!("{error:#}"))
}
struct ComputeDirGuard {
    path: PathBuf,
}

impl ComputeDirGuard {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ComputeDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn prepare_compute(compute_dir: &Path, source: &Path, target: &Path) -> W8aResult<ComputeDirGuard> {
    let exists = std::fs::symlink_metadata(compute_dir).is_ok();
    let compute = super::super::absolute(compute_dir, exists)
        .map_err(|error| W8aError::RestoreFailed(format!("compute directory: {error:#}")))?;
    let target = super::super::absolute(target, std::fs::symlink_metadata(target).is_ok())
        .map_err(|error| W8aError::RestoreFailed(format!("restore target: {error:#}")))?;
    for (label, other) in [("archive", source), ("restore target", target.as_path())] {
        super::super::disjoint(&compute, other)
            .map_err(|error| W8aError::RestoreFailed(format!("compute directory overlaps the {label}: {error:#}")))?;
    }
    if exists {
        let empty = std::fs::read_dir(&compute)
            .map_err(|error| W8aError::RestoreFailed(format!("reading compute directory: {error}")))?
            .next()
            .is_none();
        if !empty {
            return Err(W8aError::RestoreFailed("compute directory must be empty".into()));
        }
    } else {
        super::super::private_dir(&compute)
            .map_err(|error| W8aError::RestoreFailed(format!("creating compute directory: {error:#}")))?;
    }
    Ok(ComputeDirGuard { path: compute })
}

pub(in crate::backup) async fn verify_restored_source_snapshot(
    client: &tokio_postgres::Client,
    sidecar: &W8aPairedSidecarManifest,
) -> W8aResult<()> {
    let row = client
        .query_one(
            "SELECT (SELECT count(*) FROM public.ref_cas_projection_cursors) + (SELECT count(*) FROM public.ref_cas_projected_operations), ca.incarnation, p.authority_id, p.authority_epoch FROM public.cluster_authority ca, public.pando_storage_authorities p WHERE ca.singleton=true AND p.singleton=true",
            &[],
        )
        .await
        .map_err(|error| W8aError::RestoreFailed(format!("restored source authority: {error}")))?;
    let raft: i64 = row.get(0);
    if raft != 0 {
        return Err(W8aError::RaftCutForbiddenInSingleNodeW8a(format!(
            "restored database contains {raft} raft projection rows"
        )));
    }
    let incarnation: Uuid = row.get(1);
    let authority_id: Uuid = row.get(2);
    let epoch: i64 = row.get(3);
    if incarnation != sidecar.source_cluster_incarnation
        || authority_id != sidecar.source_storage_authority_id
        || epoch != sidecar.source_storage_authority_epoch
    {
        return Err(W8aError::MixedPointInTime(
            "restored database source authority differs from the captured paired source".into(),
        ));
    }
    Ok(())
}

pub(in crate::backup) async fn finish_guarded_restore(
    config: &Config,
    client: &mut tokio_postgres::Client,
    mutex: &super::super::BackupMutex,
    sidecar: &W8aPairedSidecarManifest,
    artifacts: &[super::super::ledger::Artifact],
    compute: &Path,
) -> W8aResult<(W8aFenceReceipt, Vec<W8aRepoFsckReceipt>)> {
    let raft: i64 = client
        .query_one(
            "SELECT (SELECT count(*) FROM public.ref_cas_projection_cursors) + (SELECT count(*) FROM public.ref_cas_projected_operations)",
            &[],
        )
        .await
        .map_err(|error| W8aError::RestoreFailed(format!("raft projection check: {error}")))?
        .get(0);
    if raft != 0 {
        return Err(W8aError::RaftCutForbiddenInSingleNodeW8a(format!(
            "restored database contains {raft} raft projection rows"
        )));
    }
    mutex.ensure_held(client).await.map_err(|error| W8aError::RestoreFailed(format!("{error:#}")))?;
    let fence = super::super::authority::fence_w8a_fresh_incarnation(
        client,
        sidecar.source_cluster_incarnation,
        sidecar.source_storage_authority_epoch,
    )
    .await
    .map_err(|error| W8aError::RestoreFailed(format!("restored_incarnation fence: {error:#}")))?;
    let repos = super::fsck::run_guarded_fsck(config, client, mutex, sidecar, artifacts, compute).await?;
    mutex.ensure_held(client).await.map_err(|error| W8aError::RestoreFailed(format!("{error:#}")))?;
    Ok((fence, repos))
}
