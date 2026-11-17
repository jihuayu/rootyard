//! Strict tenant, request authorization, ref-visibility, and read-isolation boundary (Issue #184).
//!
//! Enforces live per-request authorization (revocation, auth epoch, tenant/repo/history
//! realm binding), hidden-ref advertisement filtering, anti-oracle `have` checks, and
//! default `StrongSnapshot` read isolation (`docs/ref-version-pack-contract.md` §4).
use super::super::contract::{RefVersionRealm, VersionId};
use super::super::read_mode::{ReadConsumer, ReadModeKind, StrongSnapshotState};
use super::super::record::RefHead;
use super::model::{CoverHierarchyIndex, CoverHierarchyRecord, CoverMembershipDigest};
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::types::{GitOid, RefName};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use uuid::Uuid;

/// Per-request ref visibility rule preventing hidden-ref leaks in ads and fetch plans.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefVisibilityPolicy {
    AllAuthorized,
    AllowOnly(BTreeSet<RefName>),
    DenyList(BTreeSet<RefName>),
}

impl RefVisibilityPolicy {
    pub fn is_ref_visible(&self, name: &RefName) -> bool {
        match self {
            Self::AllAuthorized => true,
            Self::AllowOnly(allowed) => allowed.contains(name),
            Self::DenyList(denied) => !denied.contains(name),
        }
    }
}

/// Live per-request authorization context bound to tenant, repo, history, and actor epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub history_incarnation: Uuid,
    pub actor_id: Uuid,
    pub token_id: Uuid,
    pub auth_epoch: u64,
    pub min_valid_auth_epoch: u64,
    pub revoked: bool,
    pub visibility: RefVisibilityPolicy,
    pub allow_historical_pins: bool,
    pub allow_non_common_time_set: bool,
}

impl AuthorizationContext {
    /// Build a live default authorization context bound cleanly to `realm` at epoch 1.
    pub fn for_realm(realm: &RefVersionRealm, actor_id: Uuid, token_id: Uuid) -> Self {
        Self {
            tenant_id: realm.tenant_id(),
            repository_id: realm.repository_id(),
            history_incarnation: realm.history_incarnation(),
            actor_id,
            token_id,
            auth_epoch: 1,
            min_valid_auth_epoch: 1,
            revoked: false,
            visibility: RefVisibilityPolicy::AllAuthorized,
            allow_historical_pins: true,
            allow_non_common_time_set: false,
        }
    }

    /// Fail closed on nil IDs, revocation, stale auth epoch, or tenant/repo/history mismatch.
    pub fn validate(&self, realm: &RefVersionRealm) -> Result<(), FetchPlanError> {
        if self.tenant_id.is_nil()
            || self.repository_id.is_nil()
            || self.history_incarnation.is_nil()
            || self.actor_id.is_nil()
            || self.token_id.is_nil()
        {
            return Err(FetchPlanError::AuthDenied("nil authorization identifier"));
        }
        if self.revoked || self.auth_epoch < self.min_valid_auth_epoch || self.auth_epoch == 0 {
            return Err(FetchPlanError::AuthRevoked);
        }
        if self.tenant_id != realm.tenant_id() {
            return Err(FetchPlanError::TenantMismatch);
        }
        if self.repository_id != realm.repository_id() || self.history_incarnation != realm.history_incarnation() {
            return Err(FetchPlanError::RealmMismatch);
        }
        Ok(())
    }

    pub fn can_see_ref(&self, name: &RefName) -> bool {
        self.visibility.is_ref_visible(name)
    }
}

/// Authorized ref advertisement item (never includes tombstones or hidden refs).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdvertisedRef {
    pub ref_name: RefName,
    pub target_oid: GitOid,
    pub version_id: VersionId,
    pub ref_generation: u64,
}

/// Filter repository heads through live authorization and ref-visibility rules.
pub fn advertise_authorized_refs(
    auth: &AuthorizationContext,
    realm: &RefVersionRealm,
    heads: &[RefHead],
) -> Result<Vec<AdvertisedRef>, FetchPlanError> {
    auth.validate(realm)?;
    let mut advertised = Vec::new();
    for head in heads {
        if head.realm() != realm {
            return Err(FetchPlanError::RealmMismatch);
        }
        let Some(oid) = head.target() else { continue };
        if !auth.can_see_ref(head.ref_name()) {
            continue;
        }
        advertised.push(AdvertisedRef {
            ref_name: head.ref_name().clone(),
            target_oid: oid,
            version_id: head.version_id(),
            ref_generation: head.ref_generation(),
        });
    }
    advertised.sort_by(|a, b| a.ref_name.cmp(&b.ref_name));
    Ok(advertised)
}

/// Explicit read-isolation mode. Default is strictly [`ReadIsolationMode::StrongSnapshot`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ReadIsolationMode {
    #[default]
    StrongSnapshot,
    VersionClosure {
        version_id: VersionId,
        session_lower_bound: Option<i64>,
        historical_pinned: bool,
    },
    VersionSet {
        version_ids: Vec<VersionId>,
        session_lower_bound: Option<i64>,
        historical_pinned: bool,
    },
}

impl ReadIsolationMode {
    pub const fn mode_kind(&self) -> ReadModeKind {
        match self {
            Self::StrongSnapshot => ReadModeKind::StrongSnapshot,
            Self::VersionClosure { .. } => ReadModeKind::VersionClosure,
            Self::VersionSet { .. } => ReadModeKind::VersionSet,
        }
    }

    pub const fn is_common_time(&self) -> bool {
        matches!(self, Self::StrongSnapshot)
    }

    pub const fn is_historical_pinned(&self) -> bool {
        match self {
            Self::StrongSnapshot => false,
            Self::VersionClosure { historical_pinned, .. } | Self::VersionSet { historical_pinned, .. } => {
                *historical_pinned
            }
        }
    }

    pub const fn session_lower_bound(&self) -> Option<i64> {
        match self {
            Self::StrongSnapshot => None,
            Self::VersionClosure { session_lower_bound, .. } | Self::VersionSet { session_lower_bound, .. } => {
                *session_lower_bound
            }
        }
    }
}

/// Consistent repository snapshot point captured by the authority for `StrongSnapshot` reads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrongSnapshotCut {
    pub authority_seq: i64,
    pub snapshot_digest: RequestDigest,
    pub membership_digest: CoverMembershipDigest,
    pub heads: BTreeMap<RefName, RefHead>,
}

/// Explicitly labeled fallback to full verified strong-snapshot materialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrongSnapshotFallback {
    pub state: StrongSnapshotState,
    pub authorized_heads: Vec<AdvertisedRef>,
    pub snapshot_membership_digest: CoverMembershipDigest,
}

/// Typed reason why fast cover planning deferred to strong-snapshot fallback.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    MissingBaseCover,
    TamperedCoverDigest,
    RetentionLost,
    MembershipDrifted,
    ClosureBoundsExceeded,
    SharedCoverExposesHiddenObjects,
}

/// Typed fail-closed error returned by the fetch planner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FetchPlanError {
    AuthDenied(&'static str),
    AuthRevoked,
    TenantMismatch,
    RealmMismatch,
    HiddenRefDenied,
    UnauthorizedObjectScope,
    NonCommonTimeDenied,
    StrongCutRequired,
    TargetDeleted,
    VersionNotFound,
    VersionRetired,
    BehindSession,
    DependencyClosureFailed,
    MissingBaseCover,
    TamperedCoverDigest,
    RetentionLost,
    MembershipDrifted,
    ClosureBoundsExceeded,
    NoWantsRequested,
    InvalidPlanInput(&'static str),
}

impl fmt::Display for FetchPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthDenied(msg) => write!(f, "authorization denied: {msg}"),
            Self::AuthRevoked => f.write_str("authorization token or grant revoked"),
            Self::TenantMismatch => f.write_str("tenant mismatch"),
            Self::RealmMismatch => f.write_str("repository or history realm mismatch"),
            Self::HiddenRefDenied => f.write_str("requested or probed ref is hidden or unauthorized"),
            Self::UnauthorizedObjectScope => f.write_str("cover exposes unauthorized objects"),
            Self::NonCommonTimeDenied => f.write_str("consumer requires strong common-time snapshot"),
            Self::StrongCutRequired => f.write_str("strong snapshot cut is required for default mode"),
            Self::TargetDeleted => f.write_str("target ref is deleted tombstone"),
            Self::VersionNotFound => f.write_str("target ref version not found"),
            Self::VersionRetired => f.write_str("target ref version retired"),
            Self::BehindSession => f.write_str("version is behind session lower bound"),
            Self::DependencyClosureFailed => f.write_str("causal version dependency closure failed"),
            Self::MissingBaseCover => f.write_str("required pack or thin delta base cover missing"),
            Self::TamperedCoverDigest => f.write_str("cover record digest verification failed"),
            Self::RetentionLost => f.write_str("required cover pack lost retention eligibility"),
            Self::MembershipDrifted => f.write_str("cover index membership digest drifted from snapshot cut"),
            Self::ClosureBoundsExceeded => f.write_str("selected fetch cover closure exceeds bounds"),
            Self::NoWantsRequested => f.write_str("fetch plan requires at least one want"),
            Self::InvalidPlanInput(msg) => write!(f, "invalid fetch plan input: {msg}"),
        }
    }
}

impl std::error::Error for FetchPlanError {}

/// Validate read-isolation mode compatibility against consumer and actor capabilities.
pub(super) fn validate_isolation_policy(
    consumer: ReadConsumer,
    auth: &AuthorizationContext,
    isolation: &ReadIsolationMode,
    strong_cut: Option<&StrongSnapshotCut>,
) -> Result<(), FetchPlanError> {
    if consumer.requires_strong_common_time() && !matches!(isolation, ReadIsolationMode::StrongSnapshot) {
        return Err(FetchPlanError::NonCommonTimeDenied);
    }
    match isolation {
        ReadIsolationMode::StrongSnapshot => {
            if strong_cut.is_none() {
                return Err(FetchPlanError::StrongCutRequired);
            }
        }
        ReadIsolationMode::VersionClosure { historical_pinned, .. } => {
            if *historical_pinned && !auth.allow_historical_pins {
                return Err(FetchPlanError::AuthDenied("historical pin reads not permitted"));
            }
        }
        ReadIsolationMode::VersionSet { version_ids, historical_pinned, .. } => {
            if version_ids.is_empty() {
                return Err(FetchPlanError::InvalidPlanInput("version_set requires at least one version"));
            }
            if !auth.allow_non_common_time_set {
                return Err(FetchPlanError::NonCommonTimeDenied);
            }
            if *historical_pinned && !auth.allow_historical_pins {
                return Err(FetchPlanError::AuthDenied("historical pin reads not permitted"));
            }
        }
    }
    Ok(())
}

/// Build the exact set of commits reachable from visible authorized tips so hidden-ref
/// probing and shared-pack cross-ref leakage fail closed.
pub(super) fn collect_authorized_commit_scope(
    auth: &AuthorizationContext,
    realm: &RefVersionRealm,
    visible_tips: &[GitOid],
    strong_cut: Option<&StrongSnapshotCut>,
    cover_index: &CoverHierarchyIndex,
) -> Result<BTreeSet<GitOid>, FetchPlanError> {
    let mut parent_map: BTreeMap<GitOid, Vec<GitOid>> = BTreeMap::new();
    for cover in cover_index.all_covers() {
        if cover.realm() != realm {
            return Err(FetchPlanError::RealmMismatch);
        }
        for link in cover.covered_commits() {
            parent_map.entry(link.commit_oid).or_insert_with(|| link.parent_oids.clone());
        }
    }
    let mut queue = VecDeque::new();
    let mut authorized = BTreeSet::new();
    for tip in visible_tips {
        if authorized.insert(*tip) {
            queue.push_back(*tip);
        }
    }
    if let Some(cut) = strong_cut {
        for (name, head) in &cut.heads {
            if auth.can_see_ref(name)
                && let Some(oid) = head.target()
                && authorized.insert(oid)
            {
                queue.push_back(oid);
            }
        }
    }
    while let Some(commit) = queue.pop_front() {
        if let Some(parents) = parent_map.get(&commit) {
            for parent in parents {
                if authorized.insert(*parent) {
                    queue.push_back(*parent);
                }
            }
        }
    }
    Ok(authorized)
}

pub(super) fn cover_exposes_unauthorized_commits(
    cover: &CoverHierarchyRecord,
    auth: &AuthorizationContext,
    authorized_commits: &BTreeSet<GitOid>,
) -> bool {
    if matches!(auth.visibility, RefVisibilityPolicy::AllAuthorized) {
        return false;
    }
    cover.covered_commits().iter().any(|link| !authorized_commits.contains(&link.commit_oid))
}

pub(super) fn map_closure_err(err: super::super::closure::CausalClosureError) -> FetchPlanError {
    use super::super::closure::CausalClosureError;
    match err {
        CausalClosureError::VersionNotFound => FetchPlanError::VersionNotFound,
        CausalClosureError::VersionRetired => FetchPlanError::VersionRetired,
        CausalClosureError::TombstoneVersion => FetchPlanError::TargetDeleted,
        CausalClosureError::DependencyRealmMismatch => FetchPlanError::RealmMismatch,
        CausalClosureError::ClosureTooLarge => FetchPlanError::ClosureBoundsExceeded,
        CausalClosureError::DependencyMissing
        | CausalClosureError::DependencyCorrupt
        | CausalClosureError::DependencyCycleIntegrity => FetchPlanError::DependencyClosureFailed,
    }
}
