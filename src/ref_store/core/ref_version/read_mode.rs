//! Explicit read modes (`StrongSnapshot`, `VERSION_CLOSURE`, `VERSION_SET`),
//! session lower-bound enforcement and observable §4 errors.
use super::closure::{CausalClosureError, CausalVersionLookup, VerifiedDependencyClosure, verify_dependency_closure};
use super::contract::{RefVersionRealm, VersionId};
use super::limits::MAX_COMMIT_SET_REFS;
use crate::ref_store::contract::RequestDigest;

/// Explicit read mode (§4). Never silently downgrades `StrongSnapshot` into a fast mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadModeKind {
    StrongSnapshot,
    VersionClosure,
    VersionSet,
}

/// Repository consumers listed in `docs/ref-version-pack-contract.md` §4.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadConsumer {
    SmartHttpFetch,
    SingleRefBrowse,
    CrossRefCompare,
    PrMergeDecision,
    CiCheckoutPin,
    BackupRestore,
    DurableComputeCache,
    SessionReadYourWrites,
}

impl ReadConsumer {
    /// Whether this consumer requires repository-wide common time (`StrongSnapshot`)
    /// and must never implicitly run under `VERSION_SET`.
    pub const fn requires_strong_common_time(self) -> bool {
        matches!(self, Self::SmartHttpFetch | Self::PrMergeDecision | Self::BackupRestore)
    }
}

/// Complete §4 observable read errors (never emits partial refs or unverified bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalReadError {
    VersionNotFound,
    VersionRetired,
    Deleted,
    DependencyMissing,
    DependencyCorrupt,
    DependencyRealmMismatch,
    DependencyCycleIntegrity,
    ClosureTooLarge,
    BehindSession,
    NotCommonTime,
    AuthorityUnavailable,
    UnknownOperation,
}

impl CausalReadError {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VersionNotFound => "version_not_found",
            Self::VersionRetired => "version_retired",
            Self::Deleted => "deleted",
            Self::DependencyMissing => "dependency_missing",
            Self::DependencyCorrupt => "dependency_corrupt",
            Self::DependencyRealmMismatch => "dependency_realm_mismatch",
            Self::DependencyCycleIntegrity => "dependency_cycle_integrity",
            Self::ClosureTooLarge => "closure_too_large",
            Self::BehindSession => "behind_session",
            Self::NotCommonTime => "not_common_time",
            Self::AuthorityUnavailable => "authority_unavailable",
            Self::UnknownOperation => "unknown_operation",
        }
    }

    pub const fn from_closure_error(error: CausalClosureError) -> Self {
        match error {
            CausalClosureError::VersionNotFound => Self::VersionNotFound,
            CausalClosureError::VersionRetired => Self::VersionRetired,
            CausalClosureError::TombstoneVersion => Self::Deleted,
            CausalClosureError::DependencyMissing => Self::DependencyMissing,
            CausalClosureError::DependencyCorrupt => Self::DependencyCorrupt,
            CausalClosureError::DependencyRealmMismatch => Self::DependencyRealmMismatch,
            CausalClosureError::DependencyCycleIntegrity => Self::DependencyCycleIntegrity,
            CausalClosureError::ClosureTooLarge => Self::ClosureTooLarge,
        }
    }
}

/// Authority-verified strong snapshot fallback metadata (§1.2 / §4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrongSnapshotState {
    pub authority_seq: i64,
    pub snapshot_digest: RequestDigest,
}

/// Explicit read selector and session/fallback options (§4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadTarget {
    StrongSnapshot,
    VersionClosure { version_id: VersionId },
    VersionSet { version_ids: Vec<VersionId> },
}

impl ReadTarget {
    pub const fn mode(&self) -> ReadModeKind {
        match self {
            Self::StrongSnapshot => ReadModeKind::StrongSnapshot,
            Self::VersionClosure { .. } => ReadModeKind::VersionClosure,
            Self::VersionSet { .. } => ReadModeKind::VersionSet,
        }
    }
}

/// Verified read request options. `fallback = StrongSnapshot` never triggers silently.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalReadOptions {
    pub consumer: ReadConsumer,
    pub target: ReadTarget,
    pub session_lower_bound: Option<i64>,
    pub historical_pinned: bool,
    pub allow_strong_fallback: bool,
}

/// Explicitly labeled read verification receipt (`§4`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalReadReceipt {
    pub effective_mode: ReadModeKind,
    pub common_time: bool,
    pub fallback_used: bool,
    pub authority_seq: i64,
    pub verified_closures: Vec<VerifiedDependencyClosure>,
    pub snapshot_digest: Option<RequestDigest>,
}

/// Evaluate read authorization, causal closure verification, session-bound
/// freshness and explicit fallback labeling (`§4`).
pub fn verify_causal_read(
    lookup: Option<&dyn CausalVersionLookup>,
    realm: &RefVersionRealm,
    options: &CausalReadOptions,
    strong_snapshot: Option<StrongSnapshotState>,
) -> Result<CausalReadReceipt, CausalReadError> {
    if options.consumer.requires_strong_common_time() && options.target.mode() != ReadModeKind::StrongSnapshot {
        return Err(CausalReadError::NotCommonTime);
    }
    let Some(lookup) = lookup else {
        return Err(CausalReadError::AuthorityUnavailable);
    };
    let attempt = evaluate_target(lookup, realm, options, strong_snapshot);
    match attempt {
        Ok(receipt) => Ok(receipt),
        Err(error) if can_fallback(options, error) => {
            let Some(snapshot) = strong_snapshot else {
                return Err(error);
            };
            check_session_bound(snapshot.authority_seq, options)?;
            Ok(CausalReadReceipt {
                effective_mode: ReadModeKind::StrongSnapshot,
                common_time: true,
                fallback_used: true,
                authority_seq: snapshot.authority_seq,
                verified_closures: Vec::new(),
                snapshot_digest: Some(snapshot.snapshot_digest),
            })
        }
        Err(error) => Err(error),
    }
}

fn evaluate_target(
    lookup: &dyn CausalVersionLookup,
    realm: &RefVersionRealm,
    options: &CausalReadOptions,
    strong_snapshot: Option<StrongSnapshotState>,
) -> Result<CausalReadReceipt, CausalReadError> {
    match &options.target {
        ReadTarget::StrongSnapshot => {
            let snapshot = strong_snapshot.ok_or(CausalReadError::AuthorityUnavailable)?;
            check_session_bound(snapshot.authority_seq, options)?;
            Ok(CausalReadReceipt {
                effective_mode: ReadModeKind::StrongSnapshot,
                common_time: true,
                fallback_used: false,
                authority_seq: snapshot.authority_seq,
                verified_closures: Vec::new(),
                snapshot_digest: Some(snapshot.snapshot_digest),
            })
        }
        ReadTarget::VersionClosure { version_id } => {
            let closure =
                verify_dependency_closure(lookup, realm, version_id).map_err(CausalReadError::from_closure_error)?;
            let seq = closure.root().authority_seq();
            check_session_bound(seq, options)?;
            Ok(CausalReadReceipt {
                effective_mode: ReadModeKind::VersionClosure,
                common_time: false,
                fallback_used: false,
                authority_seq: seq,
                verified_closures: vec![closure],
                snapshot_digest: None,
            })
        }
        ReadTarget::VersionSet { version_ids } => {
            if version_ids.is_empty() || version_ids.len() > MAX_COMMIT_SET_REFS {
                return Err(CausalReadError::ClosureTooLarge);
            }
            let mut verified = Vec::with_capacity(version_ids.len());
            let mut max_seq = 0_i64;
            for version_id in version_ids {
                let closure = verify_dependency_closure(lookup, realm, version_id)
                    .map_err(CausalReadError::from_closure_error)?;
                let seq = closure.root().authority_seq();
                max_seq = max_seq.max(seq);
                verified.push(closure);
            }
            check_session_bound(max_seq, options)?;
            Ok(CausalReadReceipt {
                effective_mode: ReadModeKind::VersionSet,
                common_time: false,
                fallback_used: false,
                authority_seq: max_seq,
                verified_closures: verified,
                snapshot_digest: None,
            })
        }
    }
}

fn check_session_bound(observed_seq: i64, options: &CausalReadOptions) -> Result<(), CausalReadError> {
    if !options.historical_pinned
        && let Some(bound) = options.session_lower_bound
        && observed_seq < bound
    {
        return Err(CausalReadError::BehindSession);
    }
    Ok(())
}

fn can_fallback(options: &CausalReadOptions, error: CausalReadError) -> bool {
    if !options.allow_strong_fallback || options.target.mode() == ReadModeKind::StrongSnapshot {
        return false;
    }
    matches!(
        error,
        CausalReadError::VersionNotFound
            | CausalReadError::VersionRetired
            | CausalReadError::Deleted
            | CausalReadError::BehindSession
            | CausalReadError::NotCommonTime
    )
}
