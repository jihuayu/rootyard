//! Causal `have/want` + `ref_version` + tiered compaction cover fetch planner (Issue #184).
//!
//! Selects reusable immutable pack covers across empty clone, small incremental fetch,
//! deep lag, criss-cross/multi-merge, multi-ref, historical pin reads, and
//! non-fast-forward updates while preserving strict authorization and strong-snapshot
//! defaults. Fails closed or falls back explicitly to [`StrongSnapshotFallback`].
use super::super::closure::{CausalVersionLookup, verify_dependency_closure};
use super::super::contract::{RefVersionRealm, VersionId};
use super::super::digest::{CanonicalWriter, push_oid, validate_realm};
use super::super::limits::{count_u32, positive_u64};
use super::super::read_mode::ReadConsumer;
use super::auth::{
    AuthorizationContext, FallbackReason, FetchPlanError, MAX_PLANNER_INDEXED_COVERS, MAX_PLANNER_INDEXED_LINKS,
    ReadIsolationMode, StrongSnapshotCut, StrongSnapshotFallback, collect_authorized_commit_scope, map_closure_err,
    validate_isolation_policy, validate_strong_cut,
};
use super::model::{CoverCommitLink, CoverHierarchyIndex, CoverTier, oid_bytes};
use super::planner_select::{CoverSelectionCtx, SelectionResult, fallback_or_err, select_covers};
use super::retention_class::RetentionClassificationIndex;
use crate::ref_store::core::types::{GitOid, RefName, RefTarget};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use uuid::Uuid;

const FETCH_PLAN_DOMAIN: &[u8] = b"ry-pack-cover-fetch-plan-v1";
pub const DEFAULT_COMPACTED_THRESHOLD: usize = 3;

/// Requested ref or pinned historical version target for fetch planning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WantTarget {
    Ref { ref_name: RefName },
    PinnedVersion { ref_name: RefName, version_id: VersionId },
}

impl WantTarget {
    pub fn ref_name(&self) -> &RefName {
        match self {
            Self::Ref { ref_name } | Self::PinnedVersion { ref_name, .. } => ref_name,
        }
    }
}

/// Client-claimed existing commit/version state (never trusted for authorization).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HaveSpec {
    pub have_oids: Vec<GitOid>,
    pub have_version_ids: Vec<VersionId>,
}

/// Complete input to [`plan_fetch_covers`].
#[derive(Clone, Debug)]
pub struct FetchPlanRequest {
    pub consumer: ReadConsumer,
    pub realm: RefVersionRealm,
    pub auth: AuthorizationContext,
    pub isolation: ReadIsolationMode,
    pub strong_cut: Option<StrongSnapshotCut>,
    pub wants: Vec<WantTarget>,
    pub haves: HaveSpec,
    pub allow_strong_fallback: bool,
    pub prefer_compacted_above_delta_count: usize,
}

impl FetchPlanRequest {
    /// Build a fetch plan request with safe fallback and default compacted threshold enabled.
    pub fn new(
        consumer: ReadConsumer,
        realm: RefVersionRealm,
        auth: AuthorizationContext,
        isolation: ReadIsolationMode,
    ) -> Self {
        Self {
            consumer,
            realm,
            auth,
            isolation,
            strong_cut: None,
            wants: Vec::new(),
            haves: HaveSpec::default(),
            allow_strong_fallback: true,
            prefer_compacted_above_delta_count: DEFAULT_COMPACTED_THRESHOLD,
        }
    }
}

/// Canonical SHA-256 digest binding every field of a [`FetchPlan`].
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FetchPlanDigest([u8; 32]);

impl FetchPlanDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for FetchPlanDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FetchPlanDigest({})", hex::encode(self.0))
    }
}

/// One selected immutable pack cover in topological dependency order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedCoverEntry {
    pub cover_id: Uuid,
    pub pack_id: Uuid,
    pub tier: CoverTier,
    pub verified_bytes: u64,
    pub is_thin_pack: bool,
    pub delta_base_cover_ids: Vec<Uuid>,
}

/// Reproducible, verifiable fetch plan produced by [`plan_fetch_covers`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FetchPlan {
    pub realm: RefVersionRealm,
    pub isolation: ReadIsolationMode,
    pub common_time: bool,
    pub authority_seq: i64,
    pub wants: Vec<WantTarget>,
    pub resolved_want_commits: Vec<GitOid>,
    pub verified_have_commits: Vec<GitOid>,
    pub needed_commits: Vec<GitOid>,
    pub selected_covers: Vec<PlannedCoverEntry>,
    pub external_client_base_covers: Vec<Uuid>,
    pub total_selected_bytes: u64,
    pub metadata_reads: u64,
    pub plan_digest: FetchPlanDigest,
}

/// Outcome of fetch cover planning: either a verified plan or an explicit strong fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FetchPlanOutcome {
    Planned(Box<FetchPlan>),
    FallbackToStrongSnapshot { reason: FallbackReason, snapshot: StrongSnapshotFallback },
}

/// Compute a causal fetch pack plan from `have/want`, `ref_version`, compaction covers,
/// and live retention/authorization state.
pub fn plan_fetch_covers(
    req: &FetchPlanRequest,
    version_lookup: &dyn CausalVersionLookup,
    cover_index: &CoverHierarchyIndex,
    retention_index: &RetentionClassificationIndex,
) -> Result<FetchPlanOutcome, FetchPlanError> {
    if req.wants.is_empty() {
        return Err(FetchPlanError::NoWantsRequested);
    }
    req.auth.validate(&req.realm)?;
    if cover_index.realm() != &req.realm {
        return Err(FetchPlanError::RealmMismatch);
    }
    validate_isolation_policy(req.consumer, &req.auth, &req.isolation, req.strong_cut.as_ref())?;
    let mut metadata_reads = 0_u64;

    if let Some(cut) = &req.strong_cut {
        match validate_strong_cut(cut, &req.realm, cover_index.membership_digest()) {
            Ok(()) => {}
            Err(FetchPlanError::MembershipDrifted) => {
                return fallback_or_err(req, FallbackReason::MembershipDrifted, FetchPlanError::MembershipDrifted);
            }
            Err(err) => return Err(err),
        }
    }

    let (want_commits, authority_seq) = resolve_wants(req, version_lookup, &mut metadata_reads)?;
    let (commit_links, commit_to_covers, digest_ok) = match index_commits_and_covers(cover_index, &mut metadata_reads) {
        Ok(indexed) => indexed,
        Err(FetchPlanError::ClosureBoundsExceeded) => {
            return fallback_or_err(req, FallbackReason::ClosureBoundsExceeded, FetchPlanError::ClosureBoundsExceeded);
        }
        Err(err) => return Err(err),
    };
    let authorized_commits = match collect_authorized_commit_scope(
        &req.auth,
        &req.realm,
        &want_commits,
        req.strong_cut.as_ref(),
        cover_index,
    ) {
        Ok(scope) => scope,
        Err(FetchPlanError::ClosureBoundsExceeded) => {
            return fallback_or_err(req, FallbackReason::ClosureBoundsExceeded, FetchPlanError::ClosureBoundsExceeded);
        }
        Err(err) => return Err(err),
    };

    let verified_have_commits =
        resolve_verified_haves(req, version_lookup, &authorized_commits, &commit_to_covers, &mut metadata_reads)?;
    let have_ancestors = collect_ancestors(&verified_have_commits, &commit_links);
    let mut needed_commits = Vec::new();
    let needed_set = match collect_missing_commits(&want_commits, &have_ancestors, &commit_links, &commit_to_covers) {
        Ok(set) => set,
        Err(err) => {
            return fallback_or_err(req, FallbackReason::MissingBaseCover, err);
        }
    };
    needed_commits.extend(needed_set.iter().copied());
    needed_commits.sort_by_key(|oid| oid_bytes(*oid));

    let selection = if needed_set.is_empty() {
        SelectionResult::default()
    } else {
        let ctx = CoverSelectionCtx {
            req,
            cover_index,
            retention_index,
            authorized_commits: &authorized_commits,
            have_ancestors: &have_ancestors,
            needed_set: &needed_set,
            digest_ok: &digest_ok,
            threshold: req.prefer_compacted_above_delta_count.max(1),
        };
        match select_covers(&ctx) {
            Ok(res) => res,
            Err((reason, err)) => return fallback_or_err(req, reason, err),
        }
    };

    let total_selected_bytes = selection.selected.iter().fold(0_u64, |acc, c| acc.saturating_add(c.verified_bytes));
    let mut plan = FetchPlan {
        realm: req.realm,
        isolation: req.isolation.clone(),
        common_time: req.isolation.is_common_time(),
        authority_seq,
        wants: req.wants.clone(),
        resolved_want_commits: want_commits,
        verified_have_commits,
        needed_commits,
        selected_covers: selection.selected,
        external_client_base_covers: selection.external_client_bases,
        total_selected_bytes,
        metadata_reads,
        plan_digest: FetchPlanDigest([0_u8; 32]),
    };
    plan.plan_digest =
        compute_fetch_plan_digest(&plan).map_err(|_| FetchPlanError::InvalidPlanInput("plan encoding"))?;
    Ok(FetchPlanOutcome::Planned(Box::new(plan)))
}

/// Deterministic SHA-256 digest over every canonical field of a [`FetchPlan`].
pub(super) fn compute_fetch_plan_digest(
    plan: &FetchPlan,
) -> Result<FetchPlanDigest, super::super::contract::RefVersionCodecError> {
    let nums = validate_realm(&plan.realm)?;
    let mut w = CanonicalWriter::new();
    w.push_len_prefixed(FETCH_PLAN_DOMAIN)?;
    w.push_len_prefixed(plan.realm.tenant_id().as_bytes())?;
    w.push_len_prefixed(plan.realm.repository_id().as_bytes())?;
    w.push_len_prefixed(plan.realm.history_incarnation().as_bytes())?;
    w.push_u8(plan.realm.authority_kind().tag());
    w.push_u64(nums.authority_epoch);
    w.push_u64(nums.group_id);
    w.push_u64(nums.group_epoch);
    w.push_u8(match plan.realm.object_format() {
        crate::ref_store::core::types::GitObjectFormat::Sha1 => 1,
        crate::ref_store::core::types::GitObjectFormat::Sha256 => 2,
    });
    w.push_u8(u8::from(plan.common_time));
    w.push_u64(positive_u64(plan.authority_seq, "authority_seq")?);
    w.push_u32(count_u32(plan.wants.len(), "wants")?);
    for want in &plan.wants {
        w.push_len_prefixed(want.ref_name().as_str().as_bytes())?;
        if let WantTarget::PinnedVersion { version_id, .. } = want {
            w.push_u8(1);
            w.push_len_prefixed(version_id.as_bytes())?;
        } else {
            w.push_u8(0);
        }
    }
    w.push_u32(count_u32(plan.resolved_want_commits.len(), "want_commits")?);
    for oid in &plan.resolved_want_commits {
        push_oid(&mut w, *oid)?;
    }
    w.push_u32(count_u32(plan.verified_have_commits.len(), "have_commits")?);
    for oid in &plan.verified_have_commits {
        push_oid(&mut w, *oid)?;
    }
    w.push_u32(count_u32(plan.selected_covers.len(), "selected_covers")?);
    for entry in &plan.selected_covers {
        w.push_len_prefixed(entry.cover_id.as_bytes())?;
        w.push_len_prefixed(entry.pack_id.as_bytes())?;
        w.push_u8(entry.tier.tag());
        w.push_u64(entry.verified_bytes);
        w.push_u8(u8::from(entry.is_thin_pack));
    }
    w.push_u32(count_u32(plan.external_client_base_covers.len(), "external_bases")?);
    for id in &plan.external_client_base_covers {
        w.push_len_prefixed(id.as_bytes())?;
    }
    w.push_u64(plan.total_selected_bytes);
    Ok(FetchPlanDigest(w.finish()))
}

fn resolve_wants(
    req: &FetchPlanRequest,
    version_lookup: &dyn CausalVersionLookup,
    metadata_reads: &mut u64,
) -> Result<(Vec<GitOid>, i64), FetchPlanError> {
    let mut want_commits = Vec::with_capacity(req.wants.len());
    let mut max_seq = 0_i64;
    for want in &req.wants {
        if !req.auth.can_see_ref(want.ref_name()) {
            return Err(FetchPlanError::HiddenRefDenied);
        }
        let (version_id, expected_ref, expected_oid) = match want {
            WantTarget::Ref { ref_name } => {
                let cut = req.strong_cut.as_ref().ok_or(FetchPlanError::StrongCutRequired)?;
                let head = cut.heads.get(ref_name).ok_or(FetchPlanError::VersionNotFound)?;
                if head.realm() != &req.realm {
                    return Err(FetchPlanError::RealmMismatch);
                }
                if head.ref_name() != ref_name {
                    return Err(FetchPlanError::InvalidPlanInput("snapshot head key does not match RefHead ref_name"));
                }
                let oid = head.target().ok_or(FetchPlanError::TargetDeleted)?;
                (head.version_id(), ref_name, Some(oid))
            }
            WantTarget::PinnedVersion { ref_name, version_id } => {
                if !req.auth.allow_historical_pins && req.isolation.is_historical_pinned() {
                    return Err(FetchPlanError::AuthDenied("historical pin reads not permitted"));
                }
                (*version_id, ref_name, None)
            }
        };
        let closure = verify_dependency_closure(version_lookup, &req.realm, &version_id).map_err(map_closure_err)?;
        *metadata_reads = metadata_reads.saturating_add(1 + closure.dependencies().len() as u64);
        if closure.root().ref_name() != expected_ref {
            return Err(FetchPlanError::InvalidPlanInput("version ref_name mismatch"));
        }
        if let Some(cut) = &req.strong_cut
            && closure.root().authority_seq() > cut.authority_seq
        {
            return Err(FetchPlanError::InvalidPlanInput("resolved version exceeds snapshot cut authority_seq"));
        }
        if let Some(exp) = expected_oid
            && closure.root().target() != &RefTarget::Oid(exp)
        {
            return Err(FetchPlanError::InvalidPlanInput("snapshot head target mismatches version record"));
        }
        let seq = closure.root().authority_seq();
        if !req.isolation.is_historical_pinned()
            && let Some(bound) = req.isolation.session_lower_bound()
            && seq < bound
        {
            return Err(FetchPlanError::BehindSession);
        }
        max_seq = max_seq.max(seq);
        let oid = match closure.root().target() {
            RefTarget::Oid(oid) => *oid,
            RefTarget::Delete => return Err(FetchPlanError::TargetDeleted),
        };
        if !want_commits.contains(&oid) {
            want_commits.push(oid);
        }
    }
    let effective_seq = match &req.strong_cut {
        Some(cut) if matches!(req.isolation, ReadIsolationMode::StrongSnapshot) => cut.authority_seq,
        _ => max_seq,
    };
    Ok((want_commits, effective_seq))
}

fn index_commits_and_covers(
    cover_index: &CoverHierarchyIndex,
    metadata_reads: &mut u64,
) -> Result<(HashMap<GitOid, CoverCommitLink>, HashMap<GitOid, Vec<Uuid>>, BTreeMap<Uuid, bool>), FetchPlanError> {
    if cover_index.cover_count() > MAX_PLANNER_INDEXED_COVERS {
        return Err(FetchPlanError::ClosureBoundsExceeded);
    }
    let mut links = HashMap::new();
    let mut commit_to_covers: HashMap<GitOid, Vec<Uuid>> = HashMap::new();
    let mut digest_ok = BTreeMap::new();
    let mut link_count = 0_usize;
    for cover in cover_index.all_covers() {
        link_count = link_count.saturating_add(cover.covered_commits().len());
        if link_count > MAX_PLANNER_INDEXED_LINKS {
            return Err(FetchPlanError::ClosureBoundsExceeded);
        }
        *metadata_reads = metadata_reads.saturating_add(1);
        let valid = cover.verify_digest().is_ok();
        digest_ok.insert(cover.cover_id(), valid);
        for link in cover.covered_commits() {
            links.entry(link.commit_oid).or_insert_with(|| link.clone());
            commit_to_covers.entry(link.commit_oid).or_default().push(cover.cover_id());
        }
    }
    Ok((links, commit_to_covers, digest_ok))
}

fn resolve_verified_haves(
    req: &FetchPlanRequest,
    version_lookup: &dyn CausalVersionLookup,
    authorized_commits: &HashSet<GitOid>,
    commit_to_covers: &HashMap<GitOid, Vec<Uuid>>,
    metadata_reads: &mut u64,
) -> Result<Vec<GitOid>, FetchPlanError> {
    let mut verified = HashSet::new();
    for oid in &req.haves.have_oids {
        if authorized_commits.contains(oid) {
            verified.insert(*oid);
        } else if commit_to_covers.contains_key(oid) {
            return Err(FetchPlanError::HiddenRefDenied);
        }
    }
    for vid in &req.haves.have_version_ids {
        *metadata_reads = metadata_reads.saturating_add(1);
        if let super::super::closure::VersionLookupEntry::Active(node) = version_lookup.lookup_version(vid) {
            if node.record.realm() != &req.realm {
                return Err(FetchPlanError::RealmMismatch);
            }
            if let RefTarget::Oid(oid) = node.record.target() {
                if authorized_commits.contains(oid) {
                    verified.insert(*oid);
                } else if commit_to_covers.contains_key(oid) {
                    return Err(FetchPlanError::HiddenRefDenied);
                }
            }
        }
    }
    let mut out: Vec<GitOid> = verified.into_iter().collect();
    out.sort_by_key(|oid| oid_bytes(*oid));
    Ok(out)
}

pub(super) fn collect_ancestors(roots: &[GitOid], commit_links: &HashMap<GitOid, CoverCommitLink>) -> HashSet<GitOid> {
    let mut visited = HashSet::new();
    let mut queue: VecDeque<GitOid> = VecDeque::new();
    for root in roots {
        if visited.insert(*root) {
            queue.push_back(*root);
        }
    }
    while let Some(oid) = queue.pop_front() {
        if let Some(link) = commit_links.get(&oid) {
            for parent in &link.parent_oids {
                if visited.insert(*parent) {
                    queue.push_back(*parent);
                }
            }
        }
    }
    visited
}

fn collect_missing_commits(
    wants: &[GitOid],
    have_ancestors: &HashSet<GitOid>,
    commit_links: &HashMap<GitOid, CoverCommitLink>,
    commit_to_covers: &HashMap<GitOid, Vec<Uuid>>,
) -> Result<HashSet<GitOid>, FetchPlanError> {
    let mut needed = HashSet::new();
    let mut queue = VecDeque::new();
    for want in wants {
        if !have_ancestors.contains(want) && needed.insert(*want) {
            queue.push_back(*want);
        }
    }
    while let Some(oid) = queue.pop_front() {
        if !commit_to_covers.contains_key(&oid) {
            return Err(FetchPlanError::MissingBaseCover);
        }
        let Some(link) = commit_links.get(&oid) else {
            return Err(FetchPlanError::MissingBaseCover);
        };
        for parent in &link.parent_oids {
            if !have_ancestors.contains(parent) && needed.insert(*parent) {
                queue.push_back(*parent);
            }
        }
    }
    Ok(needed)
}
