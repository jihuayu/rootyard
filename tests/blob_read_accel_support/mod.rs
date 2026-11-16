//! Private support module for the Issue #165 read-acceleration integration test.
//!
//! The top-level `#[tokio::test]` wrapper in `tests/blob_read_accel.rs` keeps the
//! public test name and calls the implementation here, keeping both files below
//! the repository's strict 500-line module budget.

use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result, ensure};
use rootyard::blob_store::disposable_view::DisposableViewError;
use rootyard::blob_store::{BlobError, BlobLocator};
use rootyard::blob_store::read_accel::{
    ReadAccelArtifactKind, ReadAccelFallbackReason, ReadAccelManifest, ReadAccelMaterializeMetrics,
    ReadAccelObjectFormat, ReadAccelSidecarStatus, verify_and_recover_view_sidecars,
};

use super::{LoopbackS3, SampleRepoPacks, assert_git_parity, test_ctx};

pub(super) async fn fault_injection_drift_missing_corrupt_and_local_cache_recovery() -> Result<()> {
    detail_classifier::assert_detail_classifier_contract();
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
macro_rules! finite_enum {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum $name { $($variant),+ }
        impl $name {
            fn label(self) -> &'static str { match self { $(Self::$variant => $label),+ } }
        }
    };
}
finite_enum!(FormatState {
    NotStarted => "not_started", Sha1 => "sha1", Sha256 => "sha256",
});
finite_enum!(Phase {
    DefaultPolicy => "default_policy", Context => "context", Seed => "seed", DisabledOpen => "disabled_open",
    DisabledStatus => "disabled_status", Build => "build", ArtifactInventory => "artifact_inventory",
    EnabledOpen => "enabled_open", EnabledRepoPath => "enabled_repo_path", EnabledStatus => "enabled_status",
    MidxVerify => "midx_verify", CommitGraphVerify => "commit_graph_verify", BitmapCount => "bitmap_count",
    DisabledRepoPath => "disabled_repo_path", ParityRevList => "parity_rev_list", ParityCount => "parity_count",
    ParityMergeBase => "parity_merge_base", ParityAncestry => "parity_ancestry",
    ParityObjectInventory => "parity_object_inventory",
});
finite_enum!(ErrorClass {
    None => "none", Assertion => "assertion", Manifest => "manifest", DisabledByDefault => "disabled-by-default",
    InvalidInput => "invalid-input", Blob => "blob", Envelope => "envelope", Closure => "closure",
    DisposableView => "disposable-view", GitCommandFailed => "git-command-failed",
    SidecarIntegrityFailed => "sidecar-integrity-failed", DeadlineExceeded => "deadline-exceeded", Io => "io",
    InvalidUtf8 => "invalid-utf8", Unknown => "unknown",
});
finite_enum!(BlobClass {
    None => "none", Config => "config", UnsupportedService => "unsupported-service", NotFound => "not-found",
    AlreadyExists => "already-exists", LengthMismatch => "length-mismatch", DigestMismatch => "digest-mismatch",
    RangeExceedsLimit => "range-exceeds-limit", RangeUnsupported => "range-unsupported",
    DeadlineExceeded => "deadline-exceeded", StagingBudgetExceeded => "staging-budget-exceeded",
    CapacityConflict => "capacity-conflict", DeleteDisabled => "delete-disabled", ForeignBackend => "foreign-backend",
    Provider => "provider", Remote => "remote",
});
finite_enum!(ViewClass {
    None => "none", InvalidConfig => "invalid-config", InvalidArgument => "invalid-argument",
    UnsafePath => "unsafe-path", CapacityExceeded => "capacity-exceeded", Expired => "expired", Io => "io",
});
finite_enum!(GitCommandClass {
    None => "none", Init => "init", MultiPackIndex => "multi-pack-index", CommitGraph => "commit-graph",
    RevList => "rev-list", MergeBase => "merge-base", CatFile => "cat-file", VerifyPack => "verify-pack",
    UpdateRef => "update-ref", Git => "git", Unknown => "unknown",
});
finite_enum!(IoKindClass {
    None => "none", NotFound => "not-found", PermissionDenied => "permission-denied", TimedOut => "timed-out",
    WouldBlock => "would-block", BrokenPipe => "broken-pipe", ConnectionReset => "connection-reset",
    InvalidData => "invalid-data", InvalidInput => "invalid-input", UnexpectedEof => "unexpected-eof",
    Other => "other",
});
finite_enum!(StatusClass {
    NotCaptured => "not-captured", Disabled => "disabled", Applied => "applied",
    FallbackNoManifest => "fallback/no-manifest", FallbackManifestFetchFailed => "fallback/manifest-fetch-failed",
    FallbackManifestInvalid => "fallback/manifest-invalid",
    FallbackTenantRepoHistoryMismatch => "fallback/tenant-repo-history-mismatch",
    FallbackObjectFormatMismatch => "fallback/object-format-mismatch",
    FallbackMembershipGenerationDrift => "fallback/membership-generation-drift",
    FallbackPackSetDigestDrift => "fallback/pack-set-digest-drift",
    FallbackSidecarArtifactMissing => "fallback/sidecar-artifact-missing",
    FallbackSidecarArtifactCorrupt => "fallback/sidecar-artifact-corrupt",
    FallbackGitSidecarVerificationFailed => "fallback/git-sidecar-verification-failed",
});
finite_enum!(KindClass {
    NotCaptured => "not-captured", None => "none", Midx => "midx", Bitmap => "bitmap",
    CommitGraph => "commit-graph",
});
finite_enum!(StageClass {
    NotCaptured => "not-captured", Applied => "applied", Disabled => "disabled", Download => "download",
    DownloadedLocalIntegrity => "downloaded-local-integrity",
    BitmapPostPlacementHeader => "bitmap-post-placement-header", InconsistentMetrics => "inconsistent-metrics",
});
impl FormatState {
    fn from_format(format: ReadAccelObjectFormat) -> Self {
        match format { ReadAccelObjectFormat::Sha1 => Self::Sha1, ReadAccelObjectFormat::Sha256 => Self::Sha256 }
    }
}
impl BlobClass {
    fn from_error(err: &BlobError) -> Self {
        match err {
            BlobError::Config(_) => Self::Config, BlobError::UnsupportedService(_) => Self::UnsupportedService,
            BlobError::NotFound => Self::NotFound, BlobError::AlreadyExists => Self::AlreadyExists,
            BlobError::LengthMismatch { .. } => Self::LengthMismatch,
            BlobError::DigestMismatch { .. } => Self::DigestMismatch,
            BlobError::RangeExceedsLimit { .. } => Self::RangeExceedsLimit,
            BlobError::RangeUnsupported { .. } => Self::RangeUnsupported,
            BlobError::DeadlineExceeded => Self::DeadlineExceeded,
            BlobError::StagingBudgetExceeded { .. } => Self::StagingBudgetExceeded,
            BlobError::CapacityConflict => Self::CapacityConflict, BlobError::DeleteDisabled => Self::DeleteDisabled,
            BlobError::ForeignBackend => Self::ForeignBackend, BlobError::Provider(_) => Self::Provider,
            BlobError::Remote(_) => Self::Remote,
        }
    }
}
impl ViewClass {
    fn from_error(err: &DisposableViewError) -> Self {
        match err {
            DisposableViewError::InvalidConfig(_) => Self::InvalidConfig,
            DisposableViewError::InvalidArgument(_) => Self::InvalidArgument,
            DisposableViewError::UnsafePath(_) => Self::UnsafePath,
            DisposableViewError::CapacityExceeded(_) => Self::CapacityExceeded,
            DisposableViewError::Expired => Self::Expired, DisposableViewError::Io(_) => Self::Io,
        }
    }
}
impl GitCommandClass {
    fn from_command(command: &'static str) -> Self {
        match command {
            "init" => Self::Init, "verify-pack" => Self::VerifyPack, "update-ref" => Self::UpdateRef,
            "multi-pack-index" => Self::MultiPackIndex, "commit-graph" => Self::CommitGraph,
            "rev-list" => Self::RevList, "git" => Self::Git, _ => Self::Unknown,
        }
    }
    fn from_args(args: &[&str]) -> Self {
        match args.first().copied() {
            Some("init") => Self::Init, Some("multi-pack-index") => Self::MultiPackIndex,
            Some("commit-graph") => Self::CommitGraph, Some("rev-list") => Self::RevList,
            Some("merge-base") => Self::MergeBase, Some("cat-file") => Self::CatFile,
            Some("verify-pack") => Self::VerifyPack, Some("update-ref") => Self::UpdateRef,
            _ => Self::Unknown,
        }
    }
}
impl IoKindClass {
    fn from_kind(kind: std::io::ErrorKind) -> Self {
        match kind {
            std::io::ErrorKind::NotFound => Self::NotFound,
            std::io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            std::io::ErrorKind::TimedOut => Self::TimedOut,
            std::io::ErrorKind::WouldBlock => Self::WouldBlock,
            std::io::ErrorKind::BrokenPipe => Self::BrokenPipe,
            std::io::ErrorKind::ConnectionReset => Self::ConnectionReset,
            std::io::ErrorKind::InvalidData => Self::InvalidData,
            std::io::ErrorKind::InvalidInput => Self::InvalidInput,
            std::io::ErrorKind::UnexpectedEof => Self::UnexpectedEof, _ => Self::Other,
        }
    }
}
impl StatusClass {
    fn from_status(status: &ReadAccelSidecarStatus) -> Self {
        match finite_status_label(status) {
            "disabled" => Self::Disabled, "applied" => Self::Applied,
            "fallback/no-manifest" => Self::FallbackNoManifest,
            "fallback/manifest-fetch-failed" => Self::FallbackManifestFetchFailed,
            "fallback/manifest-invalid" => Self::FallbackManifestInvalid,
            "fallback/tenant-repo-history-mismatch" => Self::FallbackTenantRepoHistoryMismatch,
            "fallback/object-format-mismatch" => Self::FallbackObjectFormatMismatch,
            "fallback/membership-generation-drift" => Self::FallbackMembershipGenerationDrift,
            "fallback/pack-set-digest-drift" => Self::FallbackPackSetDigestDrift,
            "fallback/sidecar-artifact-missing" => Self::FallbackSidecarArtifactMissing,
            "fallback/sidecar-artifact-corrupt" => Self::FallbackSidecarArtifactCorrupt,
            "fallback/git-sidecar-verification-failed" => Self::FallbackGitSidecarVerificationFailed,
            _ => Self::NotCaptured,
        }
    }
}
impl KindClass {
    fn from_label(label: &'static str) -> Self {
        match label {
            "none" => Self::None, "midx" => Self::Midx, "bitmap" => Self::Bitmap,
            "commit-graph" => Self::CommitGraph, _ => Self::NotCaptured,
        }
    }
}
impl StageClass {
    fn from_label(label: &'static str) -> Self {
        match label {
            "download" => Self::Download, "downloaded-local-integrity" => Self::DownloadedLocalIntegrity,
            "bitmap-post-placement-header" => Self::BitmapPostPlacementHeader,
            "inconsistent-metrics" => Self::InconsistentMetrics, _ => Self::NotCaptured,
        }
    }
}
mod detail_classifier;
mod parity;
mod retention;
pub(super) use detail_classifier::{DetailClass, cached_fallback_detail_class};
pub(super) use parity::sha1_and_sha256_parity_and_default_disabled_behavior;
pub(super) use retention::retention_pin_protects_packs_until_release_and_compaction_rebuild;
