//! Private retention-case diagnostics for Issue #165.
//!
//! The original retention body is preserved in order. A caller-owned finite
//! format/phase context records only fixed enums, audited static labels, and
//! bounded numeric values at each fallible operation or assertion. No raw
//! error chain, Git argv/stderr, path, metadata, or provider payload is kept.

use std::{fmt, path::Path, process::Output};

use anyhow::Result;
use rootyard::blob_store::{
    BlobError, BlobLocator,
    disposable_view::DisposableViewError,
    read_accel::{
        PackRetentionRegistry, ReadAccelError, ReadAccelManifest, ReadAccelMaterializeMetrics, ReadAccelObjectFormat,
        ReadAccelSidecarStatus,
    },
};

use super::{
    BlobClass, DetailClass, ErrorClass, FormatState, IoKindClass, KindClass, StageClass, StatusClass, ViewClass,
    cached_fallback_detail_class, cached_fallback_kind_label, cached_fallback_stage_label,
};
use crate::{SampleRepoPacks, git_cmd, test_ctx};

macro_rules! finite_enum {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum $name { $($variant),+ }
        impl $name {
            fn label(self) -> &'static str {
                match self { $(Self::$variant => $label),+ }
            }
        }
    };
}

finite_enum!(Phase {
    Context => "context", Seed => "seed", SeedPackCount => "seed_pack_count",
    Gen1Build => "gen1_build", Gen1Open => "gen1_open", Gen1PinAssert => "gen1_pin_assert",
    BaselineOpen => "baseline_open", Gen1Reap => "gen1_reap", ReleasedPinAssert => "released_pin_assert",
    CompactRepack => "compact_repack", CompactedCollectUpload => "compacted_collect_upload",
    CompactedPackCount => "compacted_pack_count", Gen2Build => "gen2_build", Gen2Open => "gen2_open",
    Gen2AppliedAssert => "gen2_applied_assert", Gen2RepoPath => "gen2_repo_path",
    Gen2MidxVerify => "gen2_midx_verify", BaselineRepoPath => "baseline_repo_path",
    Gen2ParityRepoPath => "gen2_parity_repo_path", ParityRevList => "parity_rev_list",
    ParityCount => "parity_count", ParityMergeBase => "parity_merge_base", ParityAncestry => "parity_ancestry",
    ParityObjectInventory => "parity_object_inventory",
});
finite_enum!(Side { None => "none", Baseline => "baseline", Rebuilt => "rebuilt" });
finite_enum!(GitOp {
    None => "none", Repack => "repack", MidxVerify => "multi-pack-index", RevList => "rev-list",
    MergeBase => "merge-base", MergeBaseAncestor => "merge-base-ancestor", CatFile => "cat-file",
});

macro_rules! try_anyhow {
    ($diag:expr, $phase:expr, $expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err(err) => return Err(fail_anyhow($diag, $phase, &err).into()),
        }
    };
}
macro_rules! try_read_accel {
    ($diag:expr, $phase:expr, $expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err(err) => return Err(fail_read_accel($diag, $phase, &err).into()),
        }
    };
}

#[derive(Clone, Copy, Debug)]
struct ViewProjection {
    status: StatusClass,
    kind: KindClass,
    stage: StageClass,
    detail: DetailClass,
    sidecars_applied: u64,
    sidecar_get_attempts: u64,
    sidecar_get_bytes: u64,
    quarantined: u64,
    artifacts: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct Diag {
    format: FormatState,
    phase: Phase,
    error: ErrorClass,
    blob: BlobClass,
    view: ViewClass,
    side: Side,
    git_op: GitOp,
    exit_code: Option<i32>,
    signal: Option<i32>,
    io_kind: IoKindClass,
    raw_os_error: Option<i32>,
    projection: Option<ViewProjection>,
    pack_count: Option<u64>,
    compacted_pack_count: Option<u64>,
    first_pack_pinned: Option<bool>,
    first_idx_pinned: Option<bool>,
    pinned_locator_count: Option<u64>,
}

impl Diag {
    fn initial() -> Self {
        Self {
            format: FormatState::NotStarted,
            phase: Phase::Context,
            error: ErrorClass::None,
            blob: BlobClass::None,
            view: ViewClass::None,
            side: Side::None,
            git_op: GitOp::None,
            exit_code: None,
            signal: None,
            io_kind: IoKindClass::None,
            raw_os_error: None,
            projection: None,
            pack_count: None,
            compacted_pack_count: None,
            first_pack_pinned: None,
            first_idx_pinned: None,
            pinned_locator_count: None,
        }
    }

    fn set_format(&mut self, format: FormatState) {
        self.format = format;
    }

    fn begin_phase(&mut self, phase: Phase) {
        let format = self.format;
        *self = Self { format, phase, ..Self::initial() };
    }
}

struct SafeDiagError {
    diag: Box<Diag>,
}

impl fmt::Debug for SafeDiagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for SafeDiagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = &*self.diag;
        write!(
            f,
            "read-accel retention diagnostic: format={} phase={} error={} blob={} disposable_view={} side={} git_command={} exit_code={:?} signal={:?} io_kind={} raw_os_error={:?}",
            d.format.label(),
            d.phase.label(),
            d.error.label(),
            d.blob.label(),
            d.view.label(),
            d.side.label(),
            d.git_op.label(),
            d.exit_code,
            d.signal,
            d.io_kind.label(),
            d.raw_os_error
        )?;
        if let Some(view) = d.projection {
            write!(
                f,
                " view_status={} view_kind={} view_stage={} view_detail={} sidecars_applied={} sidecar_get_attempts={} sidecar_get_bytes={} quarantined={} manifest_artifacts={:?}",
                view.status.label(),
                view.kind.label(),
                view.stage.label(),
                view.detail.label(),
                view.sidecars_applied,
                view.sidecar_get_attempts,
                view.sidecar_get_bytes,
                view.quarantined,
                view.artifacts
            )?;
        }
        write!(
            f,
            " pack_count={:?} compacted_pack_count={:?} first_pack_pinned={:?} first_idx_pinned={:?} pinned_locator_count={:?}",
            d.pack_count, d.compacted_pack_count, d.first_pack_pinned, d.first_idx_pinned, d.pinned_locator_count
        )?;
        Ok(())
    }
}

impl std::error::Error for SafeDiagError {}

pub(super) async fn retention_pin_protects_packs_until_release_and_compaction_rebuild() -> Result<()> {
    super::detail_classifier::assert_detail_label_adapter_contract();

    let mut diag = Diag::initial();
    let ctx = try_anyhow!(&mut diag, Phase::Context, test_ctx());
    diag.set_format(FormatState::Sha1);

    let sample = try_anyhow!(&mut diag, Phase::Seed, SampleRepoPacks::seed(ReadAccelObjectFormat::Sha1, true));

    diag.begin_phase(Phase::SeedPackCount);
    diag.pack_count = Some(sample.packs.len() as u64);
    if sample.packs.len() < 2 {
        return Err(fail_assert(&mut diag, Phase::SeedPackCount).into());
    }

    let registry = PackRetentionRegistry::new();
    let gen1 =
        try_anyhow!(&mut diag, Phase::Gen1Build, sample.build(&ctx, 1, 1, &sample.packs, Some(registry.clone())).await);

    let active_view = try_anyhow!(
        &mut diag,
        Phase::Gen1Open,
        sample.open_with_packs(&ctx, 1, &sample.packs, &sample.refs, (Some(&gen1), true), Some(registry.clone())).await
    );

    diag.begin_phase(Phase::Gen1PinAssert);
    let first_pack_pinned = registry.is_pack_pinned(&sample.packs[0].pack_locator);
    let first_idx_pinned = registry.is_pack_pinned(&sample.packs[0].idx_locator);
    diag.first_pack_pinned = Some(first_pack_pinned);
    diag.first_idx_pinned = Some(first_idx_pinned);
    diag.pinned_locator_count = Some(registry.pinned_locator_count() as u64);
    diag.projection =
        Some(project_view(active_view.status(), active_view.metrics(), &gen1.manifest, &gen1.manifest_locator));
    if !(first_pack_pinned && first_idx_pinned) {
        return Err(fail_assert(&mut diag, Phase::Gen1PinAssert).into());
    }

    let baseline = try_anyhow!(&mut diag, Phase::BaselineOpen, sample.open(&ctx, 1, None, false).await);

    diag.begin_phase(Phase::Gen1Reap);
    active_view.reap();

    diag.begin_phase(Phase::ReleasedPinAssert);
    let first_pack_pinned = registry.is_pack_pinned(&sample.packs[0].pack_locator);
    let first_idx_pinned = registry.is_pack_pinned(&sample.packs[0].idx_locator);
    let pinned_locator_count = registry.pinned_locator_count();
    diag.first_pack_pinned = Some(first_pack_pinned);
    diag.first_idx_pinned = Some(first_idx_pinned);
    diag.pinned_locator_count = Some(pinned_locator_count as u64);
    if !(!first_pack_pinned && pinned_locator_count == 0) {
        return Err(fail_assert(&mut diag, Phase::ReleasedPinAssert).into());
    }

    diag.begin_phase(Phase::CompactRepack);
    if let Err(err) =
        git_ok_diag(&mut diag, sample.work_dir.path(), &["repack", "-ad", "--no-write-bitmap-index"], GitOp::Repack)
    {
        return Err(err.into());
    }

    let compacted_packs = try_anyhow!(&mut diag, Phase::CompactedCollectUpload, sample.collect_and_upload_packs());

    diag.begin_phase(Phase::CompactedPackCount);
    diag.compacted_pack_count = Some(compacted_packs.len() as u64);
    if compacted_packs.len() != 1 {
        return Err(fail_assert(&mut diag, Phase::CompactedPackCount).into());
    }

    let gen2 =
        try_anyhow!(&mut diag, Phase::Gen2Build, sample.build(&ctx, 2, 2, &compacted_packs, Some(registry)).await);

    let gen2_view = try_anyhow!(
        &mut diag,
        Phase::Gen2Open,
        sample.open_with_packs(&ctx, 2, &compacted_packs, &sample.refs, (Some(&gen2), true), None).await
    );

    diag.begin_phase(Phase::Gen2AppliedAssert);
    diag.projection =
        Some(project_view(gen2_view.status(), gen2_view.metrics(), &gen2.manifest, &gen2.manifest_locator));
    if !(*gen2_view.status() == ReadAccelSidecarStatus::Applied) {
        return Err(fail_assert(&mut diag, Phase::Gen2AppliedAssert).into());
    }

    let gen2_path = try_read_accel!(&mut diag, Phase::Gen2RepoPath, gen2_view.repo_path());

    diag.begin_phase(Phase::Gen2MidxVerify);
    if let Err(err) = git_ok_diag(&mut diag, gen2_path, &["multi-pack-index", "verify"], GitOp::MidxVerify) {
        return Err(err.into());
    }

    let baseline_path = try_read_accel!(&mut diag, Phase::BaselineRepoPath, baseline.repo_path());

    let gen2_parity_path = try_read_accel!(&mut diag, Phase::Gen2ParityRepoPath, gen2_view.repo_path());

    if let Err(err) = assert_git_parity_diagnosed(&mut diag, baseline_path, gen2_parity_path, &sample) {
        return Err(err.into());
    }
    Ok(())
}

fn assert_git_parity_diagnosed(
    diag: &mut Diag,
    baseline: &Path,
    rebuilt: &Path,
    sample: &SampleRepoPacks,
) -> std::result::Result<(), SafeDiagError> {
    let main_tip = sample.refs[0].oid.as_str();
    let feature_tip = sample.refs[1].oid.as_str();
    for (args, phase, op) in [
        (&["rev-list", "--all"][..], Phase::ParityRevList, GitOp::RevList),
        (&["rev-list", "--count", "--all"][..], Phase::ParityCount, GitOp::RevList),
        (&["merge-base", main_tip, feature_tip][..], Phase::ParityMergeBase, GitOp::MergeBase),
    ] {
        diag.begin_phase(phase);
        diag.git_op = op;
        diag.side = Side::Baseline;
        let expected = git_ok_diag(diag, baseline, args, op)?;
        diag.side = Side::Rebuilt;
        let candidate = git_ok_diag(diag, rebuilt, args, op)?;
        if expected != candidate {
            diag.side = Side::None;
            return Err(fail_assert(diag, phase));
        }
    }

    let base_commit = sample.base_commit.as_str();
    for (anc, tip, want) in [(base_commit, main_tip, 0), (feature_tip, main_tip, 1)] {
        diag.begin_phase(Phase::ParityAncestry);
        diag.git_op = GitOp::MergeBaseAncestor;
        diag.side = Side::Baseline;
        let expected =
            git_cmd_diag(diag, baseline, &["merge-base", "--is-ancestor", anc, tip], GitOp::MergeBaseAncestor)?;
        if expected.status.code() != Some(want) {
            diag.error = ErrorClass::Assertion;
            diag.exit_code = expected.status.code();
            diag.signal = status_signal(&expected.status);
            return Err(SafeDiagError { diag: Box::new(*diag) });
        }
        diag.side = Side::Rebuilt;
        let candidate =
            git_cmd_diag(diag, rebuilt, &["merge-base", "--is-ancestor", anc, tip], GitOp::MergeBaseAncestor)?;
        if candidate.status.code() != Some(want) {
            diag.error = ErrorClass::Assertion;
            diag.exit_code = candidate.status.code();
            diag.signal = status_signal(&candidate.status);
            return Err(SafeDiagError { diag: Box::new(*diag) });
        }
    }

    diag.begin_phase(Phase::ParityObjectInventory);
    diag.git_op = GitOp::CatFile;
    diag.side = Side::Baseline;
    let expected = git_object_inventory_diag(diag, baseline)?;
    diag.side = Side::Rebuilt;
    let candidate = git_object_inventory_diag(diag, rebuilt)?;
    if expected != candidate {
        diag.side = Side::None;
        return Err(fail_assert(diag, Phase::ParityObjectInventory));
    }
    Ok(())
}

fn git_object_inventory_diag(diag: &mut Diag, repo: &Path) -> std::result::Result<Vec<String>, SafeDiagError> {
    let text = git_ok_diag(diag, repo, &["cat-file", "--batch-check", "--batch-all-objects"], GitOp::CatFile)?;
    let mut objects: Vec<_> = text.lines().map(str::to_owned).collect();
    objects.sort();
    Ok(objects)
}

fn git_cmd_diag(diag: &mut Diag, repo: &Path, args: &[&str], op: GitOp) -> std::result::Result<Output, SafeDiagError> {
    match git_cmd(repo, args) {
        Ok(output) => Ok(output),
        Err(err) => {
            classify_anyhow(&err, diag);
            diag.git_op = op;
            Err(SafeDiagError { diag: Box::new(*diag) })
        }
    }
}

fn git_ok_diag(diag: &mut Diag, repo: &Path, args: &[&str], op: GitOp) -> std::result::Result<String, SafeDiagError> {
    let output = git_cmd_diag(diag, repo, args, op)?;
    if !output.status.success() {
        diag.error = ErrorClass::GitCommandFailed;
        diag.git_op = op;
        diag.exit_code = output.status.code();
        diag.signal = status_signal(&output.status);
        return Err(SafeDiagError { diag: Box::new(*diag) });
    }
    match String::from_utf8(output.stdout) {
        Ok(text) => Ok(text.trim().to_owned()),
        Err(_) => {
            diag.error = ErrorClass::InvalidUtf8;
            diag.git_op = op;
            Err(SafeDiagError { diag: Box::new(*diag) })
        }
    }
}

fn project_view(
    status: &ReadAccelSidecarStatus,
    metrics: &ReadAccelMaterializeMetrics,
    manifest: &ReadAccelManifest,
    manifest_locator: &BlobLocator,
) -> ViewProjection {
    let stage = match status {
        ReadAccelSidecarStatus::Applied => StageClass::Applied,
        ReadAccelSidecarStatus::Disabled => StageClass::Disabled,
        ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(_) => {
            StageClass::from_label(cached_fallback_stage_label(status, metrics, manifest, manifest_locator, true))
        }
    };
    ViewProjection {
        status: StatusClass::from_status(status),
        kind: KindClass::from_label(cached_fallback_kind_label(status)),
        stage,
        detail: DetailClass::from_label(cached_fallback_detail_class(status)),
        sidecars_applied: metrics.sidecars_applied as u64,
        sidecar_get_attempts: metrics.sidecar_get_attempts,
        sidecar_get_bytes: metrics.sidecar_get_bytes,
        quarantined: metrics.quarantined_sidecar_paths.len() as u64,
        artifacts: Some(manifest.artifacts.len() as u64),
    }
}

fn classify_anyhow(err: &anyhow::Error, diag: &mut Diag) {
    if let Some(err) = err.downcast_ref::<ReadAccelError>() {
        classify_read_accel(err, diag);
    } else if let Some(err) = err.downcast_ref::<BlobError>() {
        diag.error = ErrorClass::Blob;
        diag.blob = BlobClass::from_error(err);
    } else if let Some(err) = err.downcast_ref::<DisposableViewError>() {
        diag.error = ErrorClass::DisposableView;
        diag.view = ViewClass::from_error(err);
    } else if let Some(err) = err.downcast_ref::<std::io::Error>() {
        diag.error = ErrorClass::Io;
        diag.io_kind = IoKindClass::from_kind(err.kind());
        diag.raw_os_error = err.raw_os_error();
    } else if err.downcast_ref::<std::string::FromUtf8Error>().is_some()
        || err.downcast_ref::<std::str::Utf8Error>().is_some()
    {
        diag.error = ErrorClass::InvalidUtf8;
    } else {
        diag.error = ErrorClass::Unknown;
    }
}

fn classify_read_accel(err: &ReadAccelError, diag: &mut Diag) {
    match err {
        ReadAccelError::Manifest(_) => diag.error = ErrorClass::Manifest,
        ReadAccelError::DisabledByDefault => diag.error = ErrorClass::DisabledByDefault,
        ReadAccelError::InvalidInput(_) => diag.error = ErrorClass::InvalidInput,
        ReadAccelError::Blob(err) => {
            diag.error = ErrorClass::Blob;
            diag.blob = BlobClass::from_error(err);
        }
        ReadAccelError::Envelope(_) => diag.error = ErrorClass::Envelope,
        ReadAccelError::Closure(_) => diag.error = ErrorClass::Closure,
        ReadAccelError::DisposableView(err) => {
            diag.error = ErrorClass::DisposableView;
            diag.view = ViewClass::from_error(err);
        }
        ReadAccelError::GitCommandFailed { command, .. } => {
            diag.error = ErrorClass::GitCommandFailed;
            diag.git_op = match *command {
                "multi-pack-index" => GitOp::MidxVerify,
                "rev-list" => GitOp::RevList,
                _ => GitOp::None,
            };
        }
        ReadAccelError::SidecarIntegrityFailed(_) => diag.error = ErrorClass::SidecarIntegrityFailed,
        ReadAccelError::DeadlineExceeded => diag.error = ErrorClass::DeadlineExceeded,
        ReadAccelError::Io(_) => diag.error = ErrorClass::Io,
    }
}

fn fail_anyhow(diag: &mut Diag, phase: Phase, err: &anyhow::Error) -> SafeDiagError {
    diag.begin_phase(phase);
    classify_anyhow(err, diag);
    SafeDiagError { diag: Box::new(*diag) }
}

fn fail_read_accel(diag: &mut Diag, phase: Phase, err: &ReadAccelError) -> SafeDiagError {
    diag.begin_phase(phase);
    classify_read_accel(err, diag);
    SafeDiagError { diag: Box::new(*diag) }
}

fn fail_assert(diag: &mut Diag, phase: Phase) -> SafeDiagError {
    diag.phase = phase;
    diag.error = ErrorClass::Assertion;
    SafeDiagError { diag: Box::new(*diag) }
}

#[cfg(unix)]
fn status_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn status_signal(_: &std::process::ExitStatus) -> Option<i32> {
    None
}
