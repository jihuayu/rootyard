//! Private support module for the Issue #165 read-acceleration integration test.
//!
//! The top-level `#[tokio::test]` wrapper in `tests/blob_read_accel.rs` keeps the
//! public test name and calls the implementation here, keeping both files below
//! the repository's strict 500-line module budget.

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result, ensure};
use rootyard::blob_store::BlobLocator;
use rootyard::blob_store::read_accel::{
    ReadAccelArtifactKind, ReadAccelFallbackReason, ReadAccelManifest, ReadAccelMaterializeMetrics,
    ReadAccelObjectFormat, ReadAccelSidecarStatus, verify_and_recover_view_sidecars,
};

use super::{LoopbackS3, SampleRepoPacks, assert_git_parity, test_ctx};

pub(super) async fn fault_injection_drift_missing_corrupt_and_local_cache_recovery() -> Result<()> {
    use ReadAccelFallbackReason::{
        MembershipGenerationDrift, PackSetDigestDrift, SidecarArtifactCorrupt, SidecarArtifactMissing,
    };
    use ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly as Fallback;
    let s3 = LoopbackS3::shared();
    let ctx = test_ctx().context("phase: test context")?;
    let sample = SampleRepoPacks::seed(ReadAccelObjectFormat::Sha1, true).context("phase: seed sample")?;
    let baseline = sample.open(&ctx, 1, None, false).await.context("phase: baseline open")?;
    let bundle = sample.build(&ctx, 1, 1, &sample.packs, None).await.context("phase: baseline build")?;

    // 1. Membership drift & pack-set drift fail closed before sidecar GETs.
    let drift_view = sample.open(&ctx, 2, Some(&bundle), true).await.context("phase: membership drift open")?;
    ensure!(matches!(drift_view.status(), Fallback(MembershipGenerationDrift { expected: 2, manifest: 1 })));
    ensure!(drift_view.metrics().sidecar_get_attempts == 1);
    assert_git_parity(
        baseline.repo_path().context("phase: membership drift parity")?,
        drift_view.repo_path().context("phase: membership drift parity")?,
        &sample,
    )
    .context("phase: membership drift parity")?;
    let subset_view = sample
        .open_with_packs(&ctx, 1, &sample.packs[..1], &[], (Some(&bundle), true), None)
        .await
        .context("phase: pack subset open")?;
    ensure!(matches!(subset_view.status(), Fallback(PackSetDigestDrift)));

    // 2. Local cache tamper scrubs sidecars cleanly; cleared-cache rebuild restores Applied view.
    let cached_view = sample.open(&ctx, 1, Some(&bundle), true).await.context("phase: cached open")?;
    ensure!(
        *cached_view.status() == ReadAccelSidecarStatus::Applied,
        "phase: cached open expected applied, got {} kind={} stage={} detail_class={}",
        finite_status_label(cached_view.status()),
        cached_fallback_kind_label(cached_view.status()),
        cached_fallback_stage_label(
            cached_view.status(),
            cached_view.metrics(),
            &bundle.manifest,
            &bundle.manifest_locator,
            true,
        ),
        cached_fallback_detail_class(cached_view.status())
    );
    let bm_path = cached_view
        .repo_path()
        .context("phase: cached bitmap path")?
        .join(&bundle.manifest.artifact(ReadAccelArtifactKind::Bitmap).unwrap().relative_path);
    let bm_meta = std::fs::metadata(&bm_path).context("phase: cached bitmap stat")?;
    ensure!(bm_meta.is_file(), "phase: cached bitmap stat expected regular file");
    ensure!(bm_meta.len() > 8, "phase: cached bitmap stat too small for byte-8 tamper");
    std::fs::set_permissions(&bm_path, Permissions::from_mode(0o644)).context("phase: cached bitmap chmod")?;
    let mut raw = std::fs::read(&bm_path).context("phase: cached bitmap read")?;
    ensure!(raw.len() > 8, "phase: cached bitmap tamper too small for byte-8 tamper");
    raw[8] ^= 0xff;
    std::fs::write(&bm_path, raw).context("phase: cached bitmap tamper write")?;
    let recovered_path = cached_view.repo_path().context("phase: cached bitmap recover")?;
    let (status, removed) = verify_and_recover_view_sidecars(recovered_path, Some(&bundle.manifest), ctx.dl)
        .await
        .context("phase: cached bitmap recover")?;
    ensure!(
        matches!(status, Fallback(SidecarArtifactCorrupt { kind: ReadAccelArtifactKind::Bitmap, .. }))
            && removed.len() == 3
            && !recovered_path.join("objects/pack/multi-pack-index").exists()
    );
    assert_git_parity(baseline.repo_path().context("phase: cached recovered parity")?, recovered_path, &sample)
        .context("phase: cached recovered parity")?;
    cached_view.reap();
    let rebuilt = sample.open(&ctx, 1, Some(&bundle), true).await.context("phase: reaped rebuild open")?;
    ensure!(*rebuilt.status() == ReadAccelSidecarStatus::Applied);
    rebuilt.reap();

    // 3. Bit-flipped MIDX, truncated CommitGraph, and deleted Bitmap Blob all quarantine & fall back cleanly.
    let bundle2 =
        sample.build(&ctx, 1, 2, &sample.packs, None).await.context("phase: remote-fault build commit-graph+bitmap")?;
    for (kind, target_bundle, op, want_missing, require_midx_quarantine) in [
        (ReadAccelArtifactKind::Midx, &bundle, None, false, false),
        (ReadAccelArtifactKind::CommitGraph, &bundle2, Some(12), false, true),
        (ReadAccelArtifactKind::Bitmap, &bundle2, Some(0), true, true),
    ] {
        let (mutate_phase, open_phase, quarantine_phase, parity_phase) = match kind {
            ReadAccelArtifactKind::Midx => (
                "phase: remote-fault midx mutate",
                "phase: remote-fault midx open",
                "phase: remote-fault midx quarantine",
                "phase: remote-fault midx parity",
            ),
            ReadAccelArtifactKind::CommitGraph => (
                "phase: remote-fault commit-graph mutate",
                "phase: remote-fault commit-graph open",
                "phase: remote-fault commit-graph quarantine",
                "phase: remote-fault commit-graph parity",
            ),
            ReadAccelArtifactKind::Bitmap => (
                "phase: remote-fault bitmap mutate",
                "phase: remote-fault bitmap open",
                "phase: remote-fault bitmap quarantine",
                "phase: remote-fault bitmap parity",
            ),
        };
        s3.mutate_object(
            &target_bundle.manifest.artifact(kind).unwrap().locator.to_locator().context(mutate_phase)?,
            op,
        );
        let view = sample.open(&ctx, 1, Some(target_bundle), true).await.context(open_phase)?;
        ensure!(
            match (view.status(), want_missing) {
                (Fallback(SidecarArtifactMissing(k)), true) => *k == kind,
                (Fallback(SidecarArtifactCorrupt { kind: k, .. }), false) => *k == kind,
                _ => false,
            },
            "{}: unexpected fallback status: {}",
            open_phase,
            finite_status_label(view.status())
        );
        if require_midx_quarantine {
            ensure!(
                view.metrics().quarantined_sidecar_paths.iter().any(|p| p == "objects/pack/multi-pack-index"),
                "{}: midx quarantine marker missing",
                quarantine_phase
            );
            ensure!(
                !view.repo_path().context(quarantine_phase)?.join("objects/pack/multi-pack-index").exists(),
                "{}: midx quarantine path still present",
                quarantine_phase
            );
        }
        assert_git_parity(
            baseline.repo_path().context(parity_phase)?,
            view.repo_path().context(parity_phase)?,
            &sample,
        )
        .context(parity_phase)?;
    }
    Ok(())
}

fn finite_status_label(status: &ReadAccelSidecarStatus) -> &'static str {
    match status {
        ReadAccelSidecarStatus::Disabled => "disabled",
        ReadAccelSidecarStatus::Applied => "applied",
        ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(reason) => match reason {
            ReadAccelFallbackReason::NoManifestConfigured => "fallback/no-manifest",
            ReadAccelFallbackReason::ManifestFetchFailed(_) => "fallback/manifest-fetch-failed",
            ReadAccelFallbackReason::ManifestInvalid(_) => "fallback/manifest-invalid",
            ReadAccelFallbackReason::TenantRepoHistoryMismatch => "fallback/tenant-repo-history-mismatch",
            ReadAccelFallbackReason::ObjectFormatMismatch => "fallback/object-format-mismatch",
            ReadAccelFallbackReason::MembershipGenerationDrift { .. } => "fallback/membership-generation-drift",
            ReadAccelFallbackReason::PackSetDigestDrift => "fallback/pack-set-digest-drift",
            ReadAccelFallbackReason::SidecarArtifactMissing(_) => "fallback/sidecar-artifact-missing",
            ReadAccelFallbackReason::SidecarArtifactCorrupt { .. } => "fallback/sidecar-artifact-corrupt",
            ReadAccelFallbackReason::GitSidecarVerificationFailed { .. } => "fallback/git-sidecar-verification-failed",
        },
    }
}

fn cached_corrupt_kind(status: &ReadAccelSidecarStatus) -> Option<ReadAccelArtifactKind> {
    if let ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(ReadAccelFallbackReason::SidecarArtifactCorrupt {
        kind,
        ..
    }) = status
    {
        Some(*kind)
    } else {
        None
    }
}

fn cached_artifact_kind_label(kind: ReadAccelArtifactKind) -> &'static str {
    match kind {
        ReadAccelArtifactKind::Midx => "midx",
        ReadAccelArtifactKind::Bitmap => "bitmap",
        ReadAccelArtifactKind::CommitGraph => "commit-graph",
    }
}

fn cached_fallback_kind_label(status: &ReadAccelSidecarStatus) -> &'static str {
    if let ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(reason) = status {
        match reason {
            ReadAccelFallbackReason::SidecarArtifactCorrupt { kind, .. } => return cached_artifact_kind_label(*kind),
            ReadAccelFallbackReason::SidecarArtifactMissing(kind) => return cached_artifact_kind_label(*kind),
            _ => {}
        }
    }
    "none"
}

fn cached_fallback_detail_class(status: &ReadAccelSidecarStatus) -> &'static str {
    if let ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(ReadAccelFallbackReason::SidecarArtifactCorrupt {
        detail,
        ..
    }) = status
    {
        match detail.as_str() {
            "blob operation deadline exceeded" => "blob-deadline",
            "read-acceleration operation deadline exceeded" => "read-accel-deadline",
            "blob digest mismatch" => "blob-digest",
            "read-acceleration sidecar integrity failed: local sidecar SHA-256 or length mismatch" => {
                "local-digest-or-length"
            }
            "invalid bitmap header magic or length" => "bitmap-header",
            "blob provider error: blob readback task failed" => "readback-task",
            "blob provider error: blob destination directory failed" => "destination-directory",
            "blob provider error: blob staging file creation failed" => "staging-create",
            "blob provider error: blob staging write failed" => "staging-write",
            "blob provider error: blob staging fsync failed" => "staging-fsync",
            "blob provider error: blob destination rename failed" => "destination-rename",
            "blob provider error: blob destination fsync failed" => "destination-fsync",
            "blob resource limits conflict with the initialized process-wide context" => "resource-context-conflict",
            "blob locator already exists" => "blob-already-exists",
            _ => "unknown",
        }
    } else {
        "none"
    }
}

fn cached_fallback_stage_label(
    status: &ReadAccelSidecarStatus,
    metrics: &ReadAccelMaterializeMetrics,
    manifest: &ReadAccelManifest,
    manifest_locator: &BlobLocator,
    enabled_default_config: bool,
) -> &'static str {
    let Some(kind) = cached_corrupt_kind(status) else {
        return "inconsistent-metrics";
    };
    if !enabled_default_config || manifest.artifacts.len() != 3 {
        return "inconsistent-metrics";
    }
    let mut counts = [0usize; 3];
    for artifact in &manifest.artifacts {
        let index = match artifact.kind {
            ReadAccelArtifactKind::Midx => 0,
            ReadAccelArtifactKind::Bitmap => 1,
            ReadAccelArtifactKind::CommitGraph => 2,
        };
        counts[index] += 1;
    }
    if counts != [1, 1, 1] {
        return "inconsistent-metrics";
    }
    let (Some(midx), Some(bitmap), Some(commit_graph)) = (
        manifest.artifact(ReadAccelArtifactKind::Midx),
        manifest.artifact(ReadAccelArtifactKind::Bitmap),
        manifest.artifact(ReadAccelArtifactKind::CommitGraph),
    ) else {
        return "inconsistent-metrics";
    };
    let artifacts = [midx, bitmap, commit_graph];
    let mut prefix = [0u64; 3];
    let mut complete = [0u64; 3];
    let mut offset = manifest_locator.length();
    for (index, artifact) in artifacts.iter().enumerate() {
        prefix[index] = offset;
        let Some(next) = offset.checked_add(artifact.locator.length) else {
            return "inconsistent-metrics";
        };
        offset = next;
        complete[index] = offset;
    }
    let attempts = metrics.sidecar_get_attempts;
    let bytes = metrics.sidecar_get_bytes;
    let index = match kind {
        ReadAccelArtifactKind::Midx => 0,
        ReadAccelArtifactKind::Bitmap => 1,
        ReadAccelArtifactKind::CommitGraph => 2,
    };
    if kind == ReadAccelArtifactKind::Bitmap && attempts == 4 && bytes == complete[2] {
        return "bitmap-post-placement-header";
    }
    if attempts == index as u64 + 2 && bytes == prefix[index] {
        return "download";
    }
    if attempts == index as u64 + 2 && bytes == complete[index] {
        return "downloaded-local-integrity";
    }
    "inconsistent-metrics"
}
