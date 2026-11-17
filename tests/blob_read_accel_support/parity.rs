//! Finite, privacy-safe diagnostics for the SHA1/SHA256 parity and default-disabled case.
//!
//! The caller owns a finite format and phase marker. Every fallible required step records a
//! fixed phase before the operation. Errors are reduced immediately to fixed enums, booleans
//! and bounded numeric fields; the original error, its Display/Debug text, Git argv/stderr,
//! paths and metadata are never retained or printed. Existing finite sidecar classifiers from
//! this support module are reused for status/kind/stage/detail labels.

use std::{fmt, path::Path, process::Output};

use anyhow::Result;
use rootyard::blob_store::{
    BlobError, BlobLocator,
    disposable_view::DisposableViewError,
    read_accel::{
        ENABLE_BY_DEFAULT, ReadAccelConfig, ReadAccelError, ReadAccelManifest, ReadAccelMaterializeMetrics,
        ReadAccelObjectFormat, ReadAccelSidecarStatus,
    },
};

use super::{
    BlobClass, DetailClass, ErrorClass, FormatState, GitCommandClass, IoKindClass, KindClass, Phase, StageClass,
    StatusClass, ViewClass, cached_fallback_detail_class, cached_fallback_kind_label, cached_fallback_stage_label,
};
use crate::{SampleRepoPacks, git_cmd, test_ctx};

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
    git_command: GitCommandClass,
    exit_code: Option<i32>,
    signal: Option<i32>,
    io_kind: IoKindClass,
    raw_os_error: Option<i32>,
    projection: Option<ViewProjection>,
    artifact_count: Option<u64>,
}

impl Diag {
    fn new() -> Self {
        Self {
            format: FormatState::NotStarted,
            phase: Phase::DefaultPolicy,
            error: ErrorClass::None,
            blob: BlobClass::None,
            view: ViewClass::None,
            git_command: GitCommandClass::None,
            exit_code: None,
            signal: None,
            io_kind: IoKindClass::None,
            raw_os_error: None,
            projection: None,
            artifact_count: None,
        }
    }

    fn set_format(&mut self, format: FormatState) {
        self.format = format;
    }

    fn set_phase(&mut self, phase: Phase) {
        self.phase = phase;
    }
}

struct SafeDiagError {
    diag: Diag,
}

impl fmt::Debug for SafeDiagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for SafeDiagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = &self.diag;
        write!(
            f,
            "read-accel parity diagnostic: format={} phase={} error={}",
            d.format.label(),
            d.phase.label(),
            d.error.label()
        )?;
        if d.blob != BlobClass::None {
            write!(f, " blob={}", d.blob.label())?;
        }
        if d.view != ViewClass::None {
            write!(f, " disposable_view={}", d.view.label())?;
        }
        if d.git_command != GitCommandClass::None {
            write!(f, " git_command={}", d.git_command.label())?;
        }
        if let Some(code) = d.exit_code {
            write!(f, " exit_code={code}")?;
        }
        if let Some(signal) = d.signal {
            write!(f, " signal={signal}")?;
        }
        if d.io_kind != IoKindClass::None {
            write!(f, " io_kind={}", d.io_kind.label())?;
        }
        if let Some(errno) = d.raw_os_error {
            write!(f, " raw_os_error={errno}")?;
        }
        if let Some(view) = d.projection {
            write!(
                f,
                " view_status={} view_kind={} view_stage={} view_detail={} sidecars_applied={} sidecar_get_attempts={} sidecar_get_bytes={} quarantined={}",
                view.status.label(),
                view.kind.label(),
                view.stage.label(),
                view.detail.label(),
                view.sidecars_applied,
                view.sidecar_get_attempts,
                view.sidecar_get_bytes,
                view.quarantined
            )?;
            if let Some(artifacts) = view.artifacts {
                write!(f, " manifest_artifacts={artifacts}")?;
            }
        }
        if d.projection.is_none()
            && let Some(artifacts) = d.artifact_count
        {
            write!(f, " manifest_artifacts={artifacts}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SafeDiagError {}

pub(super) async fn sha1_and_sha256_parity_and_default_disabled_behavior() -> Result<()> {
    let mut diag = Diag::new();
    diag.set_phase(Phase::DefaultPolicy);
    if !(!ENABLE_BY_DEFAULT && !ReadAccelConfig::default().enabled) {
        return Err(fail_assert(&mut diag, Phase::DefaultPolicy).into());
    }
    diag.set_phase(Phase::Context);
    let ctx = match test_ctx() {
        Ok(ctx) => ctx,
        Err(err) => return Err(fail_anyhow(&mut diag, Phase::Context, &err).into()),
    };
    for format in [ReadAccelObjectFormat::Sha1, ReadAccelObjectFormat::Sha256] {
        diag = Diag::new();
        diag.set_format(FormatState::from_format(format));
        diag.set_phase(Phase::Seed);
        let sample = match SampleRepoPacks::seed(format, false) {
            Ok(sample) => sample,
            Err(err) => return Err(fail_anyhow(&mut diag, Phase::Seed, &err).into()),
        };
        diag.set_phase(Phase::DisabledOpen);
        let disabled_view = match sample.open(&ctx, 1, None, false).await {
            Ok(view) => view,
            Err(err) => return Err(fail_anyhow(&mut diag, Phase::DisabledOpen, &err).into()),
        };
        diag.set_phase(Phase::DisabledStatus);
        if !(*disabled_view.status() == ReadAccelSidecarStatus::Disabled
            && disabled_view.metrics().sidecar_get_attempts == 0)
        {
            diag.projection = Some(project_view_simple(disabled_view.status(), disabled_view.metrics()));
            return Err(fail_assert(&mut diag, Phase::DisabledStatus).into());
        }
        diag.set_phase(Phase::Build);
        let bundle = match sample.build(&ctx, 1, 1, &sample.packs, None).await {
            Ok(bundle) => bundle,
            Err(err) => return Err(fail_anyhow(&mut diag, Phase::Build, &err).into()),
        };
        diag.set_phase(Phase::ArtifactInventory);
        diag.artifact_count = Some(bundle.manifest.artifacts.len() as u64);
        if bundle.manifest.artifacts.len() != 3 {
            return Err(fail_assert(&mut diag, Phase::ArtifactInventory).into());
        }
        diag.set_phase(Phase::EnabledOpen);
        let enabled_view = match sample.open(&ctx, 1, Some(&bundle), true).await {
            Ok(view) => view,
            Err(err) => return Err(fail_anyhow(&mut diag, Phase::EnabledOpen, &err).into()),
        };
        diag.set_phase(Phase::EnabledStatus);
        diag.projection = Some(project_view_full(
            enabled_view.status(),
            enabled_view.metrics(),
            &bundle.manifest,
            &bundle.manifest_locator,
        ));
        if !(*enabled_view.status() == ReadAccelSidecarStatus::Applied && enabled_view.metrics().sidecars_applied == 3)
        {
            return Err(fail_assert(&mut diag, Phase::EnabledStatus).into());
        }
        diag.set_phase(Phase::EnabledRepoPath);
        let enabled_path = match enabled_view.repo_path() {
            Ok(path) => path,
            Err(err) => return Err(fail_read_accel(&mut diag, Phase::EnabledRepoPath, &err).into()),
        };
        diag.set_phase(Phase::MidxVerify);
        if let Err(err) =
            git_ok_diag(&mut diag, enabled_path, &["multi-pack-index", "verify"], GitCommandClass::MultiPackIndex)
        {
            return Err(err.into());
        }
        diag.set_phase(Phase::CommitGraphVerify);
        if let Err(err) =
            git_ok_diag(&mut diag, enabled_path, &["commit-graph", "verify"], GitCommandClass::CommitGraph)
        {
            return Err(err.into());
        }
        diag.set_phase(Phase::BitmapCount);
        let enabled_count = match git_ok_diag(
            &mut diag,
            enabled_path,
            &["rev-list", "--count", "--use-bitmap-index", "--all"],
            GitCommandClass::RevList,
        ) {
            Ok(count) => count,
            Err(err) => return Err(err.into()),
        };
        diag.set_phase(Phase::DisabledRepoPath);
        let disabled_path = match disabled_view.repo_path() {
            Ok(path) => path,
            Err(err) => return Err(fail_read_accel(&mut diag, Phase::DisabledRepoPath, &err).into()),
        };
        diag.set_phase(Phase::BitmapCount);
        let disabled_count =
            match git_ok_diag(&mut diag, disabled_path, &["rev-list", "--count", "--all"], GitCommandClass::RevList) {
                Ok(count) => count,
                Err(err) => return Err(err.into()),
            };
        if enabled_count != disabled_count {
            return Err(fail_assert(&mut diag, Phase::BitmapCount).into());
        }
        diag.set_phase(Phase::DisabledRepoPath);
        let parity_disabled_path = match disabled_view.repo_path() {
            Ok(path) => path,
            Err(err) => return Err(fail_read_accel(&mut diag, Phase::DisabledRepoPath, &err).into()),
        };
        if let Err(err) = assert_git_parity_diagnosed(&mut diag, parity_disabled_path, enabled_path, &sample) {
            return Err(err.into());
        }
    }
    Ok(())
}

fn assert_git_parity_diagnosed(
    diag: &mut Diag,
    expected_repo: &Path,
    candidate_repo: &Path,
    sample: &SampleRepoPacks,
) -> std::result::Result<(), SafeDiagError> {
    let main_tip = sample.refs[0].oid.as_str();
    let feature_tip = sample.refs[1].oid.as_str();
    for (args, phase) in [
        (&["rev-list", "--all"][..], Phase::ParityRevList),
        (&["rev-list", "--count", "--all"][..], Phase::ParityCount),
        (&["merge-base", main_tip, feature_tip][..], Phase::ParityMergeBase),
    ] {
        diag.set_phase(phase);
        let expected = git_ok_diag(diag, expected_repo, args, GitCommandClass::from_args(args))?;
        let candidate = git_ok_diag(diag, candidate_repo, args, GitCommandClass::from_args(args))?;
        if expected != candidate {
            return Err(fail_assert(diag, phase));
        }
    }
    let base_commit = sample.base_commit.as_str();
    for (anc, tip, want) in [(base_commit, main_tip, 0), (feature_tip, main_tip, 1)] {
        diag.set_phase(Phase::ParityAncestry);
        let expected =
            git_cmd_diag(diag, expected_repo, &["merge-base", "--is-ancestor", anc, tip], GitCommandClass::MergeBase)?;
        if expected.status.code() != Some(want) {
            diag.error = ErrorClass::Assertion;
            diag.git_command = GitCommandClass::MergeBase;
            diag.exit_code = expected.status.code();
            diag.signal = status_signal(&expected.status);
            return Err(SafeDiagError { diag: *diag });
        }
        let candidate =
            git_cmd_diag(diag, candidate_repo, &["merge-base", "--is-ancestor", anc, tip], GitCommandClass::MergeBase)?;
        if candidate.status.code() != Some(want) {
            diag.error = ErrorClass::Assertion;
            diag.git_command = GitCommandClass::MergeBase;
            diag.exit_code = candidate.status.code();
            diag.signal = status_signal(&candidate.status);
            return Err(SafeDiagError { diag: *diag });
        }
    }
    diag.set_phase(Phase::ParityObjectInventory);
    let expected = git_object_inventory_diag(diag, expected_repo)?;
    let candidate = git_object_inventory_diag(diag, candidate_repo)?;
    if expected != candidate {
        return Err(fail_assert(diag, Phase::ParityObjectInventory));
    }
    Ok(())
}

fn git_object_inventory_diag(diag: &mut Diag, repo: &Path) -> std::result::Result<Vec<String>, SafeDiagError> {
    let text =
        git_ok_diag(diag, repo, &["cat-file", "--batch-check", "--batch-all-objects"], GitCommandClass::CatFile)?;
    let mut objects: Vec<_> = text.lines().map(str::to_owned).collect();
    objects.sort();
    Ok(objects)
}

fn git_cmd_diag(
    diag: &mut Diag,
    repo: &Path,
    args: &[&str],
    command: GitCommandClass,
) -> std::result::Result<Output, SafeDiagError> {
    match git_cmd(repo, args) {
        Ok(output) => Ok(output),
        Err(err) => {
            classify_anyhow(&err, diag);
            diag.git_command = command;
            Err(SafeDiagError { diag: *diag })
        }
    }
}

fn git_ok_diag(
    diag: &mut Diag,
    repo: &Path,
    args: &[&str],
    command: GitCommandClass,
) -> std::result::Result<String, SafeDiagError> {
    let output = git_cmd_diag(diag, repo, args, command)?;
    if !output.status.success() {
        diag.error = ErrorClass::GitCommandFailed;
        diag.git_command = command;
        diag.exit_code = output.status.code();
        diag.signal = status_signal(&output.status);
        return Err(SafeDiagError { diag: *diag });
    }
    match String::from_utf8(output.stdout) {
        Ok(text) => Ok(text.trim().to_owned()),
        Err(_) => {
            diag.error = ErrorClass::InvalidUtf8;
            diag.git_command = command;
            Err(SafeDiagError { diag: *diag })
        }
    }
}

fn project_view_simple(status: &ReadAccelSidecarStatus, metrics: &ReadAccelMaterializeMetrics) -> ViewProjection {
    ViewProjection {
        status: StatusClass::from_status(status),
        kind: KindClass::from_label(cached_fallback_kind_label(status)),
        stage: match status {
            ReadAccelSidecarStatus::Applied => StageClass::Applied,
            ReadAccelSidecarStatus::Disabled => StageClass::Disabled,
            ReadAccelSidecarStatus::FallbackToAuthoritativePackOnly(_) => StageClass::InconsistentMetrics,
        },
        detail: DetailClass::from_label(cached_fallback_detail_class(status)),
        sidecars_applied: metrics.sidecars_applied as u64,
        sidecar_get_attempts: metrics.sidecar_get_attempts,
        sidecar_get_bytes: metrics.sidecar_get_bytes,
        quarantined: metrics.quarantined_sidecar_paths.len() as u64,
        artifacts: None,
    }
}

fn project_view_full(
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
            diag.git_command = GitCommandClass::from_command(command);
        }
        ReadAccelError::SidecarIntegrityFailed(_) => diag.error = ErrorClass::SidecarIntegrityFailed,
        ReadAccelError::DeadlineExceeded => diag.error = ErrorClass::DeadlineExceeded,
        ReadAccelError::Io(_) => diag.error = ErrorClass::Io,
    }
}

fn fail_anyhow(diag: &mut Diag, phase: Phase, err: &anyhow::Error) -> SafeDiagError {
    diag.set_phase(phase);
    classify_anyhow(err, diag);
    SafeDiagError { diag: *diag }
}

fn fail_read_accel(diag: &mut Diag, phase: Phase, err: &ReadAccelError) -> SafeDiagError {
    diag.set_phase(phase);
    classify_read_accel(err, diag);
    SafeDiagError { diag: *diag }
}

fn fail_assert(diag: &mut Diag, phase: Phase) -> SafeDiagError {
    diag.set_phase(phase);
    diag.error = ErrorClass::Assertion;
    SafeDiagError { diag: *diag }
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
