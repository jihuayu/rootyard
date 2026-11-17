//! Test-only bounded diagnostic support for the Issue #182 empty/history integration case.
//!
//! This module contains no `#[test]` functions and no production imports beyond the typed
//! `CloneKitError` classification.  It is shared by `tests/ci_clonekit.rs` and the pure
//! contract test; the case body macro is expanded only by the former.

use std::{cell::Cell, io::Write, rc::Rc};

use rootyard::ci_checkouts::clonekit::CloneKitError;

/// Closed target phases for the empty/history case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    Setup,
    EmptyBuildOrStatus,
    ActiveBuild,
    CorruptBuild,
    CorruptPublicationPreservesLatest,
    HistoryGrant,
    HistoryCheckout,
    HistoryStrategy,
}

impl Phase {
    pub(crate) const fn is_assert_phase(self) -> bool {
        matches!(self, Self::EmptyBuildOrStatus | Self::CorruptPublicationPreservesLatest | Self::HistoryStrategy)
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Setup => "SETUP",
            Self::EmptyBuildOrStatus => "EMPTY_BUILD_OR_STATUS",
            Self::ActiveBuild => "ACTIVE_BUILD",
            Self::CorruptBuild => "CORRUPT_BUILD",
            Self::CorruptPublicationPreservesLatest => "CORRUPT_PUBLICATION_PRESERVES_LATEST",
            Self::HistoryGrant => "HISTORY_GRANT",
            Self::HistoryCheckout => "HISTORY_CHECKOUT",
            Self::HistoryStrategy => "HISTORY_STRATEGY",
        }
    }
}

/// Closed diagnostic classes: exact typed `CloneKitError` variants plus the three non-error classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    Assert,
    Panic,
    Other,
    InvalidConfig,
    InvalidInput,
    Unauthorized,
    GrantExpired,
    GrantRevoked,
    CrossTenantDenied,
    MissingKit,
    EmptyRepository,
    StaleGeneration,
    HistoryChanged,
    CorruptArtifact,
    ForeignBackend,
    IncompleteClosure,
    DependencyCheckFailed,
    PinProtectionActive,
    TransferCancelled,
    GitFailed,
    BlobFailed,
    DatabaseFailed,
}

impl Class {
    fn from_ck(err: &CloneKitError) -> Self {
        match err {
            CloneKitError::InvalidConfig(_) => Self::InvalidConfig,
            CloneKitError::InvalidInput(_) => Self::InvalidInput,
            CloneKitError::Unauthorized(_) => Self::Unauthorized,
            CloneKitError::GrantExpired => Self::GrantExpired,
            CloneKitError::GrantRevoked(_) => Self::GrantRevoked,
            CloneKitError::CrossTenantDenied => Self::CrossTenantDenied,
            CloneKitError::MissingKit => Self::MissingKit,
            CloneKitError::EmptyRepository => Self::EmptyRepository,
            CloneKitError::StaleGeneration { .. } => Self::StaleGeneration,
            CloneKitError::HistoryChanged { .. } => Self::HistoryChanged,
            CloneKitError::CorruptArtifact(_) => Self::CorruptArtifact,
            CloneKitError::ForeignBackend => Self::ForeignBackend,
            CloneKitError::IncompleteClosure(_) => Self::IncompleteClosure,
            CloneKitError::DependencyCheckFailed(_) => Self::DependencyCheckFailed,
            CloneKitError::PinProtectionActive(_) => Self::PinProtectionActive,
            CloneKitError::TransferCancelled => Self::TransferCancelled,
            CloneKitError::GitFailed(_) => Self::GitFailed,
            CloneKitError::BlobFailed(_) => Self::BlobFailed,
            CloneKitError::DatabaseFailed(_) => Self::DatabaseFailed,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Assert => "ASSERT",
            Self::Panic => "PANIC",
            Self::Other => "OTHER",
            Self::InvalidConfig => "INVALID_CONFIG",
            Self::InvalidInput => "INVALID_INPUT",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::GrantExpired => "GRANT_EXPIRED",
            Self::GrantRevoked => "GRANT_REVOKED",
            Self::CrossTenantDenied => "CROSS_TENANT_DENIED",
            Self::MissingKit => "MISSING_KIT",
            Self::EmptyRepository => "EMPTY_REPOSITORY",
            Self::StaleGeneration => "STALE_GENERATION",
            Self::HistoryChanged => "HISTORY_CHANGED",
            Self::CorruptArtifact => "CORRUPT_ARTIFACT",
            Self::ForeignBackend => "FOREIGN_BACKEND",
            Self::IncompleteClosure => "INCOMPLETE_CLOSURE",
            Self::DependencyCheckFailed => "DEPENDENCY_CHECK_FAILED",
            Self::PinProtectionActive => "PIN_PROTECTION_ACTIVE",
            Self::TransferCancelled => "TRANSFER_CANCELLED",
            Self::GitFailed => "GIT_FAILED",
            Self::BlobFailed => "BLOB_FAILED",
            Self::DatabaseFailed => "DATABASE_FAILED",
        }
    }
}

/// Exactly one finite diagnostic frame: closed phase/class and a source line.  No payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub(crate) phase: Phase,
    pub(crate) class: Class,
    pub(crate) file: &'static str,
    pub(crate) line: u32,
}

/// Local armed recorder.  It emits at most one fixed frame and only on a failed/panicking end.
pub(crate) struct Recorder {
    armed: bool,
    phase: Phase,
    file: &'static str,
    line: u32,
    first: Option<Frame>,
    panicking_override: Option<bool>,
    observer: Option<Rc<Cell<Option<Frame>>>>,
}

impl Recorder {
    pub(crate) fn new(file: &'static str, line: u32) -> Self {
        Self { armed: true, phase: Phase::Setup, file, line, first: None, panicking_override: None, observer: None }
    }

    #[allow(dead_code)] // used only by the separate pure contract test
    pub(crate) fn test_with(panicking: bool, observer: Rc<Cell<Option<Frame>>>) -> Self {
        Self {
            armed: true,
            phase: Phase::Setup,
            file: file!(),
            line: line!(),
            first: None,
            panicking_override: Some(panicking),
            observer: Some(observer),
        }
    }

    pub(crate) fn mark(&mut self, phase: Phase, file: &'static str, line: u32) {
        self.phase = phase;
        self.file = file;
        self.line = line;
    }

    fn record(&mut self, phase: Phase, class: Class, file: &'static str, line: u32) {
        if self.first.is_none() {
            self.first = Some(Frame { phase, class, file, line });
        }
    }

    /// Mark the phase, then evaluate one operation.  A panic therefore sees the marked phase;
    /// a returned error is classified at this operation's own source checkpoint.
    pub(crate) fn eager_anyhow<T>(
        &mut self,
        phase: Phase,
        file: &'static str,
        line: u32,
        operation: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        self.mark(phase, file, line);
        let result = operation();
        if let Err(err) = &result {
            let class = err.downcast_ref::<CloneKitError>().map(Class::from_ck).unwrap_or(Class::Other);
            self.record(phase, class, file, line);
        }
        result
    }

    /// CloneKitError-returning form of [`Self::eager_anyhow`].
    pub(crate) fn eager_ck<T>(
        &mut self,
        phase: Phase,
        file: &'static str,
        line: u32,
        operation: impl FnOnce() -> Result<T, CloneKitError>,
    ) -> Result<T, CloneKitError> {
        self.mark(phase, file, line);
        let result = operation();
        if let Err(err) = &result {
            self.record(phase, Class::from_ck(err), file, line);
        }
        result
    }

    /// Observe the final original `anyhow::Error` without changing it.  Typed CloneKit errors keep
    /// their exact class; an untyped error in an assert phase is `ASSERT`, otherwise `OTHER`.
    pub(crate) fn observe_final(&mut self, err: &anyhow::Error) {
        let class = err
            .downcast_ref::<CloneKitError>()
            .map(Class::from_ck)
            .unwrap_or_else(|| if self.phase.is_assert_phase() { Class::Assert } else { Class::Other });
        self.record(self.phase, class, self.file, self.line);
    }

    #[allow(dead_code)] // used only by the separate pure contract test
    pub(crate) fn recorded(&self) -> Option<Frame> {
        self.first
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    pub(crate) fn finish(&mut self, panicking: bool) -> Option<Frame> {
        if !self.armed {
            return None;
        }
        self.armed = false;
        if let Some(frame) = self.first {
            return Some(frame);
        }
        let class = if panicking {
            Class::Panic
        } else if self.phase.is_assert_phase() {
            Class::Assert
        } else {
            Class::Other
        };
        Some(Frame { phase: self.phase, class, file: self.file, line: self.line })
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        let panicking = self.panicking_override.unwrap_or_else(std::thread::panicking);
        let Some(frame) = self.finish(panicking) else { return };
        if let Some(observer) = &self.observer {
            observer.set(Some(frame));
        } else {
            // Best-effort, bounded stderr write.  A diagnostic I/O failure must not replace the
            // test's original error or panic.
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(
                stderr,
                "ISSUE182_EMPTY_HISTORY phase={} class={} source={}:{}",
                frame.phase.as_str(),
                frame.class.as_str(),
                frame.file,
                frame.line
            );
        }
    }
}

/// The exact empty/history case body, moved out of `tests/ci_clonekit.rs` to keep that source
/// below its strict line contract.  The test wrapper retains the original name, attribute,
/// inventory, fixtures, order, oracles, and `&&` short-circuit.  The inner async body returns
/// the original `anyhow::Error` unchanged; only the outer boundary observes it.
#[allow(unused_macros)] // exported for ci_clonekit; intentionally inert in the pure contract target
#[macro_export]
macro_rules! empty_history_case_body {
    () => {{
        let mut diag = crate::ck_diag::Recorder::new(file!(), line!());
        diag.mark(crate::ck_diag::Phase::Setup, file!(), line!());
        let result: anyhow::Result<()> = async {
            let td = TempDir::new()?;
            let ids = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
            let vr = diag.eager_anyhow(crate::ck_diag::Phase::Setup, file!(), line!(), || private_vr(&td))?;
            let store = diag.eager_ck(crate::ck_diag::Phase::Setup, file!(), line!(), || {
                CloneKitPublicationStore::open(&td.path().join("cat"))
            })?;
            let empty = diag.eager_anyhow(crate::ck_diag::Phase::EmptyBuildOrStatus, file!(), line!(), || {
                init_repo(td.path(), "empty.git", Sha1)
            })?;
            diag.mark(crate::ck_diag::Phase::EmptyBuildOrStatus, file!(), line!());
            anyhow::ensure!(
                build_kit(ids, Sha1, 1, &empty, &td, None, None)?.manifest.status == CloneKitStatus::EmptyRepository
            );

            diag.mark(crate::ck_diag::Phase::ActiveBuild, file!(), line!());
            let repo = diag.eager_anyhow(crate::ck_diag::Phase::ActiveBuild, file!(), line!(), || {
                init_repo(td.path(), "active", Sha1)
            })?;
            let c1 = diag.eager_anyhow(crate::ck_diag::Phase::ActiveBuild, file!(), line!(), || {
                add_commit(&repo, "a.txt", b"v1", "c1")
            })?;
            diag.eager_anyhow(crate::ck_diag::Phase::ActiveBuild, file!(), line!(), || {
                build_kit(ids, Sha1, 1, &repo, &td, Some(&store), None)
            })?;
            let b2 = diag.eager_anyhow(crate::ck_diag::Phase::CorruptBuild, file!(), line!(), || {
                build_kit(ids, Sha1, 2, &repo, &td, None, Some(BuildFailurePoint::CorruptStagedPack))
            })?;
            diag.mark(crate::ck_diag::Phase::CorruptPublicationPreservesLatest, file!(), line!());
            anyhow::ensure!(
                publish_clonekit_versioned(&store, &b2, &git_binary(), None, None).is_err()
                    && store.load_latest(ids.1)?.expect("latest").kit_generation == 1
            );

            let (g_h2, c_h2) = diag.eager_anyhow(crate::ck_diag::Phase::HistoryGrant, file!(), line!(), || {
                make_grant((ids.0, ids.1, Uuid::new_v4()), Sha1, &c1, None, 1_750_000_000)
            })?;
            let (co, mem): (Co<'_>, Arc<dyn CloneKitAuthorityOracle>) =
                (Co { store: Some(&store), ..Co::new(&vr) }, Arc::new(InMemoryAuthorityOracle::new()));
            diag.mark(crate::ck_diag::Phase::HistoryCheckout, file!(), line!());
            let res = co.run(&g_h2, &c_h2, &mem, pol(true, true), repo.to_str().expect("utf8"), None).await?;
            diag.mark(crate::ck_diag::Phase::HistoryStrategy, file!(), line!());
            anyhow::ensure!(
                res.telemetry.strategy
                    == CheckoutStrategy::StockGitFallback { reason: FallbackReason::KitHistoryMismatch }
            );
            Ok::<(), anyhow::Error>(())
        }
        .await;
        match &result {
            Ok(()) => diag.disarm(),
            Err(err) => diag.observe_final(err),
        }
        result
    }};
}
