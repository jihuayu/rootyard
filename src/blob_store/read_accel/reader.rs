//! Read-replica materializer with fail-closed fallback to authoritative pack-only Git.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use tokio::fs;
use uuid::Uuid;

use super::{
    super::{
        BlobError, BlobLocator,
        disposable_view::{DisposableViewRoot, TempViewLease},
        envelope::EnvelopeMetadata,
        key_provider::KeyProvider,
        opendal::BlobStore,
    },
    ReadAccelError,
    builder::{AuthoritativePackSource, AuthoritativeRef, PackRetentionGuard, PackRetentionRegistry},
    download_object_file,
    manifest::{
        PackDigestEntry, ReadAccelArtifact, ReadAccelArtifactKind, ReadAccelConfig, ReadAccelFallbackReason,
        ReadAccelManifest, ReadAccelObjectFormat,
    },
    populate_bare_view_from_authoritative_packs, run_git, run_git_with_stderr, sort_pack_sources,
    validate_ref_name_and_oid, verify_file_digest_and_len,
};

/// Pointer to a candidate read-acceleration manifest object in `BlobStore`.
#[derive(Debug, Clone)]
pub struct ManifestFetchRef {
    pub locator: BlobLocator,
    pub envelope: Option<EnvelopeMetadata>,
}

/// Request to materialize a disposable read-only Git view backed by authoritative packs
/// and optional non-authoritative read-acceleration sidecars.
#[derive(Clone)]
pub struct MaterializeViewRequest {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub object_format: ReadAccelObjectFormat,
    pub expected_membership_generation: u64,
    pub authoritative_packs: Vec<AuthoritativePackSource>,
    pub refs: Vec<AuthoritativeRef>,
    pub manifest_ref: Option<ManifestFetchRef>,
    pub config: ReadAccelConfig,
    pub retention_registry: Option<PackRetentionRegistry>,
    pub key_provider: Option<Arc<dyn KeyProvider>>,
}

/// Outcome of sidecar application on a materialized Git view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadAccelSidecarStatus {
    Disabled,
    Applied,
    FallbackToAuthoritativePackOnly(ReadAccelFallbackReason),
}

/// Per-view Blob IO and materialization metrics separating pack costs from sidecar costs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReadAccelMaterializeMetrics {
    pub pack_get_attempts: u64,
    pub pack_get_bytes: u64,
    pub sidecar_get_attempts: u64,
    pub sidecar_get_bytes: u64,
    pub sidecars_applied: usize,
    pub quarantined_sidecar_paths: Vec<String>,
    pub materialize_duration_ms: u64,
}

/// Live materialized bare Git view owned by a bounded `TempViewLease`.
pub struct MaterializedAccelView {
    lease: TempViewLease,
    _retention_guard: Option<PackRetentionGuard>,
    pub status: ReadAccelSidecarStatus,
    pub metrics: ReadAccelMaterializeMetrics,
    repo_path: PathBuf,
}

impl MaterializedAccelView {
    pub fn repo_path(&self) -> Result<&Path, ReadAccelError> {
        self.lease.ensure_live()?;
        Ok(&self.repo_path)
    }

    pub fn status(&self) -> &ReadAccelSidecarStatus {
        &self.status
    }

    pub fn metrics(&self) -> &ReadAccelMaterializeMetrics {
        &self.metrics
    }

    pub fn reap(self) {
        self.lease.reap();
    }
}

/// Materialize authoritative packs into a fresh disposable Git view and optionally apply
/// validated read-acceleration sidecars, failing closed to pack-only Git on any anomaly.
pub async fn materialize_git_view_with_read_accel(
    store: &BlobStore,
    view_root: &DisposableViewRoot,
    request: &MaterializeViewRequest,
    deadline: Instant,
) -> Result<MaterializedAccelView, ReadAccelError> {
    let started = Instant::now();
    request.config.validate()?;
    if request.tenant_id.is_nil() || request.repo_id.is_nil() || request.history_id.is_nil() {
        return Err(ReadAccelError::InvalidInput("tenant_id, repo_id and history_id must be non-nil".into()));
    }
    if request.expected_membership_generation == 0 {
        return Err(ReadAccelError::InvalidInput("expected_membership_generation must be positive".into()));
    }
    for reference in &request.refs {
        validate_ref_name_and_oid(&reference.name, &reference.oid, request.object_format)?;
    }

    let paired =
        sort_pack_sources(request.tenant_id, request.repo_id, request.object_format, &request.authoritative_packs)?;
    let expected_packs: Vec<_> = paired.iter().map(|(_, entry)| entry.clone()).collect();
    let total_pack_bytes = expected_packs
        .iter()
        .fold(0u64, |acc, item| acc.saturating_add(item.pack_length).saturating_add(item.idx_length));
    let reserved_bytes = total_pack_bytes.saturating_mul(2).max(16 * 1024 * 1024);

    let lease = view_root.create_view("read-accel-rd", request.tenant_id, request.repo_id, reserved_bytes, None)?;
    let (pack_get_attempts, pack_get_bytes) = populate_bare_view_from_authoritative_packs(
        store,
        &lease,
        request.object_format,
        &paired,
        &request.refs,
        request.key_provider.as_ref(),
        deadline,
    )
    .await?;
    let repo_path = lease.repo_path()?.to_path_buf();
    let mut metrics =
        ReadAccelMaterializeMetrics { pack_get_attempts, pack_get_bytes, ..ReadAccelMaterializeMetrics::default() };

    if !request.config.enabled {
        return Ok(static_view(lease, repo_path, &mut metrics, ReadAccelSidecarStatus::Disabled, started));
    }

    match try_hydrate_sidecars(store, &lease, request, &expected_packs, &mut metrics, deadline).await {
        Ok(retention_guard) => {
            metrics.materialize_duration_ms = started.elapsed().as_millis() as u64;
            Ok(MaterializedAccelView {
                lease,
                _retention_guard: retention_guard,
                status: ReadAccelSidecarStatus::Applied,
                metrics,
                repo_path,
            })
        }
        Err(SidecarStageOutcome::Fatal(err)) => Err(err),
        Err(SidecarStageOutcome::Fallback(reason)) => {
            metrics.sidecars_applied = 0;
            metrics.quarantined_sidecar_paths = scrub_sidecars_in_repo(&repo_path).await?;
            let status = ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(reason);
            Ok(static_view(lease, repo_path, &mut metrics, status, started))
        }
    }
}

async fn try_hydrate_sidecars(
    store: &BlobStore,
    lease: &TempViewLease,
    request: &MaterializeViewRequest,
    expected_packs: &[PackDigestEntry],
    metrics: &mut ReadAccelMaterializeMetrics,
    deadline: Instant,
) -> Result<Option<PackRetentionGuard>, SidecarStageOutcome> {
    let staging_dir = lease.dir_path().map_err(ReadAccelError::from)?;
    let manifest = fetch_and_bind_manifest(store, request, expected_packs, staging_dir, metrics, deadline)
        .await
        .map_err(SidecarStageOutcome::Fallback)?;
    let selected = select_artifacts(&manifest, &request.config);
    if selected.is_empty() {
        return Err(SidecarStageOutcome::Fallback(ReadAccelFallbackReason::ManifestInvalid(
            "no configured sidecars present in manifest".into(),
        )));
    }
    let retention_guard = match &request.retention_registry {
        Some(reg) => Some(reg.pin_manifest(&manifest).map_err(ReadAccelError::from)?),
        None => None,
    };
    apply_and_verify_sidecars(store, lease, request, &selected, metrics, deadline).await?;
    Ok(retention_guard)
}

/// Validate on-disk sidecars inside an existing cached bare repo against an optional manifest
/// and stock `git` verification, quarantining and scrubbing bad sidecar files fail-closed.
pub async fn verify_and_recover_view_sidecars(
    repo_path: &Path,
    expected_manifest: Option<&ReadAccelManifest>,
    deadline: Instant,
) -> Result<(ReadAccelSidecarStatus, Vec<String>), ReadAccelError> {
    let reason = match expected_manifest {
        None => Some(ReadAccelFallbackReason::NoManifestConfigured),
        Some(manifest) => verify_cached_manifest_files(repo_path, manifest, deadline).await.err(),
    };
    if let Some(fallback) = reason {
        let removed = scrub_sidecars_in_repo(repo_path).await?;
        return Ok((ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(fallback), removed));
    }
    Ok((ReadAccelSidecarStatus::Applied, Vec::new()))
}

/// Remove all read-acceleration sidecar files from a bare repo, preserving authoritative packs/idx.
pub async fn scrub_sidecars_in_repo(repo_path: &Path) -> Result<Vec<String>, ReadAccelError> {
    let mut removed = Vec::new();
    let pack_dir = repo_path.join("objects/pack");
    if let Ok(mut entries) = fs::read_dir(&pack_dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name_os = entry.file_name();
            let Some(name) = name_os.to_str() else { continue };
            if name == "multi-pack-index" || (name.starts_with("multi-pack-index-") && name.ends_with(".bitmap")) {
                remove_regular_sidecar(&entry.path(), format!("objects/pack/{name}"), &mut removed).await?;
            }
        }
    }
    remove_regular_sidecar(
        &repo_path.join("objects/info/commit-graph"),
        "objects/info/commit-graph".to_owned(),
        &mut removed,
    )
    .await?;
    let graph_dir = repo_path.join("objects/info/commit-graphs");
    if let Ok(meta) = fs::symlink_metadata(&graph_dir).await {
        if meta.file_type().is_symlink() {
            return Err(ReadAccelError::SidecarIntegrityFailed("refusing to follow symlink commit-graphs dir"));
        }
        if meta.is_dir() {
            fs::remove_dir_all(&graph_dir).await.map_err(|e| ReadAccelError::Io(e.to_string()))?;
            removed.push("objects/info/commit-graphs".to_owned());
        }
    }
    removed.sort();
    Ok(removed)
}

enum SidecarStageOutcome {
    Fallback(ReadAccelFallbackReason),
    Fatal(ReadAccelError),
}

impl From<ReadAccelError> for SidecarStageOutcome {
    fn from(value: ReadAccelError) -> Self {
        Self::Fatal(value)
    }
}

async fn fetch_and_bind_manifest(
    store: &BlobStore,
    request: &MaterializeViewRequest,
    expected_packs: &[PackDigestEntry],
    staging_dir: &Path,
    metrics: &mut ReadAccelMaterializeMetrics,
    deadline: Instant,
) -> Result<ReadAccelManifest, ReadAccelFallbackReason> {
    let manifest_ref = request.manifest_ref.as_ref().ok_or(ReadAccelFallbackReason::NoManifestConfigured)?;
    let manifest_dst = staging_dir.join("manifest-download.json");
    metrics.sidecar_get_attempts = metrics.sidecar_get_attempts.saturating_add(1);
    download_object_file(
        store,
        &manifest_ref.locator,
        manifest_ref.envelope.as_ref(),
        request.key_provider.as_ref(),
        &manifest_dst,
        deadline,
    )
    .await
    .map_err(|err| ReadAccelFallbackReason::ManifestFetchFailed(err.to_string()))?;
    metrics.sidecar_get_bytes = metrics.sidecar_get_bytes.saturating_add(manifest_ref.locator.length());

    let bytes =
        fs::read(&manifest_dst).await.map_err(|err| ReadAccelFallbackReason::ManifestInvalid(err.to_string()))?;
    let manifest = ReadAccelManifest::from_json_bytes(&bytes)
        .map_err(|err| ReadAccelFallbackReason::ManifestInvalid(err.to_string()))?;
    manifest.matches_binding(
        request.tenant_id,
        request.repo_id,
        request.history_id,
        request.object_format,
        request.expected_membership_generation,
        expected_packs,
    )?;
    Ok(manifest)
}

#[derive(Default)]
struct PlacedSidecars<'a> {
    has_midx: bool,
    bitmap_rel: Option<&'a str>,
    has_graph: bool,
}

impl<'a> PlacedSidecars<'a> {
    fn record(&mut self, artifact: &'a ReadAccelArtifact) {
        match artifact.kind {
            ReadAccelArtifactKind::Midx => self.has_midx = true,
            ReadAccelArtifactKind::Bitmap => self.bitmap_rel = Some(artifact.relative_path.as_str()),
            ReadAccelArtifactKind::CommitGraph => self.has_graph = true,
        }
    }

    async fn verify(self, repo_path: &Path, deadline: Instant) -> Result<(), ReadAccelFallbackReason> {
        if self.has_midx
            && let Err(err) = run_git(repo_path, &["multi-pack-index", "verify"], None, deadline).await
        {
            return Err(git_verify_err("multi-pack-index", err));
        }
        if let Some(rel) = self.bitmap_rel {
            let header =
                fs::read(repo_path.join(rel)).await.map_err(|e| ReadAccelFallbackReason::SidecarArtifactCorrupt {
                    kind: ReadAccelArtifactKind::Bitmap,
                    detail: e.to_string(),
                })?;
            if header.len() < 32 || &header[..4] != b"BITM" {
                return Err(ReadAccelFallbackReason::SidecarArtifactCorrupt {
                    kind: ReadAccelArtifactKind::Bitmap,
                    detail: "invalid bitmap header magic or length".into(),
                });
            }
            let (_, stderr) =
                run_git_with_stderr(repo_path, &["rev-list", "--count", "--use-bitmap-index", "--all"], None, deadline)
                    .await
                    .map_err(|err| git_verify_err("rev-list", err))?;
            if stderr.contains("corrupt") || stderr.contains("failed to load bitmap") {
                return Err(ReadAccelFallbackReason::GitSidecarVerificationFailed {
                    command: "rev-list",
                    detail: stderr,
                });
            }
        }
        if self.has_graph
            && let Err(err) = run_git(repo_path, &["commit-graph", "verify"], None, deadline).await
        {
            return Err(git_verify_err("commit-graph", err));
        }
        Ok(())
    }
}

async fn apply_and_verify_sidecars(
    store: &BlobStore,
    lease: &TempViewLease,
    request: &MaterializeViewRequest,
    selected: &[&ReadAccelArtifact],
    metrics: &mut ReadAccelMaterializeMetrics,
    deadline: Instant,
) -> Result<(), SidecarStageOutcome> {
    let repo_path = lease.repo_path().map_err(ReadAccelError::from)?;
    let staging_dir = lease.dir_path().map_err(ReadAccelError::from)?;
    let mut placed = PlacedSidecars::default();
    for &artifact in selected {
        let loc = artifact
            .locator
            .to_locator()
            .map_err(|e| SidecarStageOutcome::Fallback(ReadAccelFallbackReason::ManifestInvalid(e.to_string())))?;
        let stage_path = staging_dir.join(format!("sidecar-{:?}.tmp", artifact.kind));
        metrics.sidecar_get_attempts = metrics.sidecar_get_attempts.saturating_add(1);
        download_object_file(
            store,
            &loc,
            artifact.envelope.as_ref(),
            request.key_provider.as_ref(),
            &stage_path,
            deadline,
        )
        .await
        .map_err(|err| SidecarStageOutcome::Fallback(classify_download_failure(artifact.kind, err)))?;
        metrics.sidecar_get_bytes = metrics.sidecar_get_bytes.saturating_add(loc.length());
        if let Err(err) =
            verify_file_digest_and_len(&stage_path, &artifact.plaintext_sha256, artifact.plaintext_length).await
        {
            let _ = fs::remove_file(&stage_path).await;
            return Err(SidecarStageOutcome::Fallback(ReadAccelFallbackReason::SidecarArtifactCorrupt {
                kind: artifact.kind,
                detail: err.to_string(),
            }));
        }
        let target_path =
            lease.resolve_repo_relative_path(Path::new(&artifact.relative_path)).map_err(ReadAccelError::from)?;
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| ReadAccelError::Io(e.to_string()))?;
        }
        fs::rename(&stage_path, &target_path).await.map_err(|e| ReadAccelError::Io(e.to_string()))?;
        metrics.sidecars_applied = metrics.sidecars_applied.saturating_add(1);
        placed.record(artifact);
    }
    placed.verify(repo_path, deadline).await.map_err(SidecarStageOutcome::Fallback)
}

async fn verify_cached_manifest_files(
    repo_path: &Path,
    manifest: &ReadAccelManifest,
    deadline: Instant,
) -> Result<(), ReadAccelFallbackReason> {
    manifest.validate().map_err(|e| ReadAccelFallbackReason::ManifestInvalid(e.to_string()))?;
    let mut placed = PlacedSidecars::default();
    for artifact in &manifest.artifacts {
        verify_file_digest_and_len(
            &repo_path.join(&artifact.relative_path),
            &artifact.plaintext_sha256,
            artifact.plaintext_length,
        )
        .await
        .map_err(|err| ReadAccelFallbackReason::SidecarArtifactCorrupt {
            kind: artifact.kind,
            detail: err.to_string(),
        })?;
        placed.record(artifact);
    }
    placed.verify(repo_path, deadline).await
}

async fn remove_regular_sidecar(path: &Path, rel: String, removed: &mut Vec<String>) -> Result<(), ReadAccelError> {
    let Ok(meta) = fs::symlink_metadata(path).await else { return Ok(()) };
    if meta.file_type().is_symlink() {
        return Err(ReadAccelError::SidecarIntegrityFailed("refusing to follow symlink sidecar"));
    }
    if meta.is_file() {
        fs::remove_file(path).await.map_err(|e| ReadAccelError::Io(e.to_string()))?;
        removed.push(rel);
    }
    Ok(())
}

fn select_artifacts<'a>(manifest: &'a ReadAccelManifest, cfg: &ReadAccelConfig) -> Vec<&'a ReadAccelArtifact> {
    [
        (cfg.include_midx, ReadAccelArtifactKind::Midx),
        (cfg.include_midx && cfg.include_bitmap, ReadAccelArtifactKind::Bitmap),
        (cfg.include_commit_graph, ReadAccelArtifactKind::CommitGraph),
    ]
    .into_iter()
    .filter_map(|(enabled, kind)| enabled.then(|| manifest.artifact(kind)).flatten())
    .collect()
}

fn classify_download_failure(kind: ReadAccelArtifactKind, err: ReadAccelError) -> ReadAccelFallbackReason {
    match &err {
        ReadAccelError::Blob(BlobError::NotFound) => ReadAccelFallbackReason::SidecarArtifactMissing(kind),
        _ => ReadAccelFallbackReason::SidecarArtifactCorrupt { kind, detail: err.to_string() },
    }
}

fn git_verify_err(default_cmd: &'static str, err: ReadAccelError) -> ReadAccelFallbackReason {
    match err {
        ReadAccelError::GitCommandFailed { command, detail } => {
            ReadAccelFallbackReason::GitSidecarVerificationFailed { command, detail }
        }
        other => {
            ReadAccelFallbackReason::GitSidecarVerificationFailed { command: default_cmd, detail: other.to_string() }
        }
    }
}

fn static_view(
    lease: TempViewLease,
    repo_path: PathBuf,
    metrics: &mut ReadAccelMaterializeMetrics,
    status: ReadAccelSidecarStatus,
    started: Instant,
) -> MaterializedAccelView {
    metrics.materialize_duration_ms = started.elapsed().as_millis() as u64;
    MaterializedAccelView { lease, _retention_guard: None, status, metrics: metrics.clone(), repo_path }
}
