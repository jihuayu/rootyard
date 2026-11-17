//! Independent fail-closed closure proof verifier for fetch pack plans (Issue #184).
//!
//! Independently re-validates authorization, hidden-ref boundaries, ref-version
//! dependency closures, 3-state retention eligibility, Git commit DAG completeness,
//! thin-pack external delta bases, and closure bounds without trusting planner
//! heuristics. Produces the unforgeable [`VerifiedFetchPlanProof`].
use super::super::closure::{CausalVersionLookup, verify_dependency_closure};
use super::super::contract::RefVersionRealm;
use super::super::digest::CanonicalWriter;
use super::super::limits::{
    MAX_CLOSURE_ARTIFACTS, MAX_CLOSURE_PACKS, MAX_CLOSURE_VERIFIED_BYTES, count_u32, positive_u64,
};
use super::super::read_mode::ReadConsumer;
use super::auth::{
    AuthorizationContext, FetchPlanError, StrongSnapshotCut, collect_authorized_commit_scope,
    cover_exposes_unauthorized_commits, map_closure_err, validate_isolation_policy,
};
use super::model::{CoverCommitLink, CoverHierarchyIndex, CoverHierarchyRecord};
use super::planner::{FetchPlan, FetchPlanDigest, WantTarget, collect_ancestors, compute_fetch_plan_digest};
use super::retention_class::{CoverHoldKind, RetentionClassificationIndex};
use crate::ref_store::core::types::{GitOid, RefTarget};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use uuid::Uuid;

const PLAN_PROOF_DOMAIN: &[u8] = b"ry-pack-cover-plan-proof-v1";

/// Unforgeable closure proof minted ONLY by [`verify_fetch_plan_closure`].
///
/// Private fields, neither `Clone` nor `Deserialize`, ensuring no caller or cache
/// metadata can fabricate verification.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedFetchPlanProof {
    proof_digest: [u8; 32],
    plan_digest: FetchPlanDigest,
    realm: RefVersionRealm,
    authority_seq: i64,
    common_time: bool,
    selected_cover_ids: Vec<Uuid>,
    selected_pack_ids: Vec<Uuid>,
    external_client_base_covers: Vec<Uuid>,
    total_verified_bytes: u64,
}

impl VerifiedFetchPlanProof {
    pub const fn proof_digest(&self) -> &[u8; 32] {
        &self.proof_digest
    }
    pub const fn plan_digest(&self) -> FetchPlanDigest {
        self.plan_digest
    }
    pub const fn realm(&self) -> &RefVersionRealm {
        &self.realm
    }
    pub const fn authority_seq(&self) -> i64 {
        self.authority_seq
    }
    pub const fn common_time(&self) -> bool {
        self.common_time
    }
    pub fn selected_cover_ids(&self) -> &[Uuid] {
        &self.selected_cover_ids
    }
    pub fn selected_pack_ids(&self) -> &[Uuid] {
        &self.selected_pack_ids
    }
    pub fn external_client_base_covers(&self) -> &[Uuid] {
        &self.external_client_base_covers
    }
    pub const fn total_verified_bytes(&self) -> u64 {
        self.total_verified_bytes
    }

    pub fn binds(&self, plan: &FetchPlan) -> bool {
        let Ok(recomputed) = compute_fetch_plan_digest(plan) else {
            return false;
        };
        if recomputed != self.plan_digest || plan.plan_digest != self.plan_digest {
            return false;
        }
        let cover_ids: Vec<Uuid> = plan.selected_covers.iter().map(|c| c.cover_id).collect();
        let pack_ids: Vec<Uuid> = plan.selected_covers.iter().map(|c| c.pack_id).collect();
        self.realm == plan.realm
            && self.authority_seq == plan.authority_seq
            && self.common_time == plan.common_time
            && self.selected_cover_ids == cover_ids
            && self.selected_pack_ids == pack_ids
            && self.external_client_base_covers == plan.external_client_base_covers
            && self.total_verified_bytes == plan.total_selected_bytes
    }
}

/// Typed verification failure raised when a fetch plan cannot be proved closed or safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanVerifyError {
    PlanDigestMismatch,
    Plan(FetchPlanError),
    SelectedCoverMissing,
    SelectedPackMetadataMismatch,
    ThinBaseOrderingViolation,
    CommitDagGap,
    TotalBytesMismatch,
}

impl fmt::Display for PlanVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanDigestMismatch => f.write_str("fetch plan digest mismatch"),
            Self::Plan(err) => write!(f, "fetch plan verification failed: {err}"),
            Self::SelectedCoverMissing => f.write_str("selected cover record missing from index"),
            Self::SelectedPackMetadataMismatch => {
                f.write_str("selected cover metadata disagrees with authoritative record")
            }
            Self::ThinBaseOrderingViolation => f.write_str("thin pack precedes or lacks verified delta base cover"),
            Self::CommitDagGap => f.write_str("selected covers leave a Git commit ancestry gap"),
            Self::TotalBytesMismatch => f.write_str("selected plan total bytes mismatch"),
        }
    }
}

impl std::error::Error for PlanVerifyError {}

impl From<FetchPlanError> for PlanVerifyError {
    fn from(value: FetchPlanError) -> Self {
        Self::Plan(value)
    }
}

/// Independently verify every causal, authorization, retention, and Git-closure
/// invariant of `plan` and mint an unforgeable [`VerifiedFetchPlanProof`].
pub fn verify_fetch_plan_closure(
    plan: &FetchPlan,
    consumer: ReadConsumer,
    auth: &AuthorizationContext,
    strong_cut: Option<&StrongSnapshotCut>,
    version_lookup: &dyn CausalVersionLookup,
    cover_index: &CoverHierarchyIndex,
    retention_index: &RetentionClassificationIndex,
) -> Result<VerifiedFetchPlanProof, PlanVerifyError> {
    let expected_digest = compute_fetch_plan_digest(plan).map_err(|_| PlanVerifyError::PlanDigestMismatch)?;
    if expected_digest != plan.plan_digest {
        return Err(PlanVerifyError::PlanDigestMismatch);
    }
    auth.validate(&plan.realm)?;
    if cover_index.realm() != &plan.realm {
        return Err(FetchPlanError::RealmMismatch.into());
    }
    validate_isolation_policy(consumer, auth, &plan.isolation, strong_cut)?;
    if plan.common_time != plan.isolation.is_common_time() {
        return Err(FetchPlanError::NonCommonTimeDenied.into());
    }
    if plan.wants.is_empty() {
        return Err(FetchPlanError::NoWantsRequested.into());
    }
    if let Some(cut) = strong_cut
        && cut.membership_digest != cover_index.membership_digest()
    {
        return Err(FetchPlanError::MembershipDrifted.into());
    }

    let expected_want_commits = verify_wants_and_cut(plan, strong_cut, auth, version_lookup)?;
    if expected_want_commits != plan.resolved_want_commits {
        return Err(PlanVerifyError::SelectedPackMetadataMismatch);
    }

    let authorized_commits =
        collect_authorized_commit_scope(auth, &plan.realm, &expected_want_commits, strong_cut, cover_index)?;

    let mut all_links = HashMap::new();
    for rec in cover_index.all_covers() {
        for link in rec.covered_commits() {
            all_links.entry(link.commit_oid).or_insert_with(|| link.clone());
        }
    }
    for oid in &plan.verified_have_commits {
        if !authorized_commits.contains(oid) {
            return Err(FetchPlanError::HiddenRefDenied.into());
        }
    }
    let have_ancestors = collect_ancestors(&plan.verified_have_commits, &all_links);

    let selected_records =
        verify_selected_covers(plan, auth, &authorized_commits, &have_ancestors, cover_index, retention_index)?;

    verify_commit_dag_closure(&expected_want_commits, &have_ancestors, &selected_records)?;

    let proof_digest = compute_proof_digest(plan)?;
    let selected_cover_ids = plan.selected_covers.iter().map(|c| c.cover_id).collect();
    let selected_pack_ids = plan.selected_covers.iter().map(|c| c.pack_id).collect();

    Ok(VerifiedFetchPlanProof {
        proof_digest,
        plan_digest: plan.plan_digest,
        realm: plan.realm,
        authority_seq: plan.authority_seq,
        common_time: plan.common_time,
        selected_cover_ids,
        selected_pack_ids,
        external_client_base_covers: plan.external_client_base_covers.clone(),
        total_verified_bytes: plan.total_selected_bytes,
    })
}

fn verify_wants_and_cut(
    plan: &FetchPlan,
    strong_cut: Option<&StrongSnapshotCut>,
    auth: &AuthorizationContext,
    version_lookup: &dyn CausalVersionLookup,
) -> Result<Vec<GitOid>, PlanVerifyError> {
    let mut want_commits = Vec::with_capacity(plan.wants.len());
    for want in &plan.wants {
        if !auth.can_see_ref(want.ref_name()) {
            return Err(FetchPlanError::HiddenRefDenied.into());
        }
        let version_id = match want {
            WantTarget::Ref { ref_name } => {
                let cut = strong_cut.ok_or(FetchPlanError::StrongCutRequired)?;
                let head = cut.heads.get(ref_name).ok_or(FetchPlanError::VersionNotFound)?;
                if head.is_tombstone() {
                    return Err(FetchPlanError::TargetDeleted.into());
                }
                head.version_id()
            }
            WantTarget::PinnedVersion { ref_name, version_id } => {
                let closure =
                    verify_dependency_closure(version_lookup, &plan.realm, version_id).map_err(map_closure_err)?;
                if closure.root().ref_name() != ref_name {
                    return Err(FetchPlanError::InvalidPlanInput("pinned ref mismatch").into());
                }
                *version_id
            }
        };
        let closure = verify_dependency_closure(version_lookup, &plan.realm, &version_id).map_err(map_closure_err)?;
        let oid = match closure.root().target() {
            RefTarget::Oid(oid) => *oid,
            RefTarget::Delete => return Err(FetchPlanError::TargetDeleted.into()),
        };
        if !want_commits.contains(&oid) {
            want_commits.push(oid);
        }
    }
    Ok(want_commits)
}

fn verify_selected_covers<'a>(
    plan: &FetchPlan,
    auth: &AuthorizationContext,
    authorized_commits: &HashSet<GitOid>,
    have_ancestors: &HashSet<GitOid>,
    cover_index: &'a CoverHierarchyIndex,
    retention_index: &RetentionClassificationIndex,
) -> Result<Vec<&'a CoverHierarchyRecord>, PlanVerifyError> {
    if plan.selected_covers.len() > MAX_CLOSURE_PACKS {
        return Err(FetchPlanError::ClosureBoundsExceeded.into());
    }
    let mut records = Vec::with_capacity(plan.selected_covers.len());
    let mut seen_earlier = BTreeSet::new();
    let mut total_artifacts = 0_usize;
    let mut total_bytes = 0_u64;
    let client_bases: BTreeSet<Uuid> = plan.external_client_base_covers.iter().copied().collect();

    for entry in &plan.selected_covers {
        let rec = cover_index.get(&entry.cover_id).ok_or(PlanVerifyError::SelectedCoverMissing)?;
        if rec.verify_digest().is_err() {
            return Err(FetchPlanError::TamperedCoverDigest.into());
        }
        if rec.realm() != &plan.realm {
            return Err(FetchPlanError::RealmMismatch.into());
        }
        if rec.pack().entry().pack_id() != entry.pack_id
            || rec.tier() != entry.tier
            || rec.pack().verified_bytes() != entry.verified_bytes
            || rec.artifacts().is_thin_pack != entry.is_thin_pack
            || rec.artifacts().delta_base_cover_ids != entry.delta_base_cover_ids
        {
            return Err(PlanVerifyError::SelectedPackMetadataMismatch);
        }
        if cover_exposes_unauthorized_commits(rec, auth, authorized_commits) {
            return Err(FetchPlanError::UnauthorizedObjectScope.into());
        }
        let cls = retention_index.classify_cover(rec);
        if !cls.physically_present || !cls.plannable_for_fetch {
            return Err(FetchPlanError::RetentionLost.into());
        }
        if !plan.isolation.is_historical_pinned()
            && (cover_index.is_retired_from_active(&rec.cover_id()) || cls.historical_read_only)
        {
            return Err(FetchPlanError::RetentionLost.into());
        }

        for base_id in &rec.artifacts().delta_base_cover_ids {
            if seen_earlier.contains(base_id) {
                continue;
            }
            if client_bases.contains(base_id) {
                let base_rec = cover_index.get(base_id).ok_or(PlanVerifyError::SelectedCoverMissing)?;
                if base_rec.verify_digest().is_err() {
                    return Err(FetchPlanError::TamperedCoverDigest.into());
                }
                if cover_exposes_unauthorized_commits(base_rec, auth, authorized_commits) {
                    return Err(FetchPlanError::UnauthorizedObjectScope.into());
                }
                let base_cls = retention_index.classify_cover(base_rec);
                if !base_cls.physically_present
                    || base_cls.active_protectors.contains(&CoverHoldKind::QuarantineHold)
                    || !base_rec.covered_commits().iter().all(|c| have_ancestors.contains(&c.commit_oid))
                {
                    return Err(PlanVerifyError::ThinBaseOrderingViolation);
                }
                continue;
            }
            return Err(PlanVerifyError::ThinBaseOrderingViolation);
        }

        if !seen_earlier.insert(rec.cover_id()) {
            return Err(PlanVerifyError::SelectedPackMetadataMismatch);
        }
        let count = usize::try_from(rec.pack().artifact_count()).unwrap_or(usize::MAX);
        total_artifacts = total_artifacts.saturating_add(count);
        total_bytes = total_bytes.saturating_add(rec.pack().verified_bytes());
        records.push(rec);
    }
    if total_artifacts > MAX_CLOSURE_ARTIFACTS || total_bytes > MAX_CLOSURE_VERIFIED_BYTES {
        return Err(FetchPlanError::ClosureBoundsExceeded.into());
    }
    if total_bytes != plan.total_selected_bytes {
        return Err(PlanVerifyError::TotalBytesMismatch);
    }
    Ok(records)
}

fn verify_commit_dag_closure(
    want_commits: &[GitOid],
    have_ancestors: &HashSet<GitOid>,
    selected_records: &[&CoverHierarchyRecord],
) -> Result<(), PlanVerifyError> {
    let mut selected_links: HashMap<GitOid, &CoverCommitLink> = HashMap::new();
    for rec in selected_records {
        for link in rec.covered_commits() {
            selected_links.insert(link.commit_oid, link);
        }
    }
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    for oid in want_commits {
        if !have_ancestors.contains(oid) && visited.insert(*oid) {
            queue.push_back(*oid);
        }
    }
    while let Some(oid) = queue.pop_front() {
        let Some(link) = selected_links.get(&oid) else {
            return Err(PlanVerifyError::CommitDagGap);
        };
        for parent in &link.parent_oids {
            if !have_ancestors.contains(parent) && visited.insert(*parent) {
                queue.push_back(*parent);
            }
        }
    }
    Ok(())
}

fn compute_proof_digest(plan: &FetchPlan) -> Result<[u8; 32], PlanVerifyError> {
    let mut w = CanonicalWriter::new();
    w.push_len_prefixed(PLAN_PROOF_DOMAIN).map_err(|_| PlanVerifyError::PlanDigestMismatch)?;
    w.push_len_prefixed(plan.plan_digest.as_bytes()).map_err(|_| PlanVerifyError::PlanDigestMismatch)?;
    w.push_u64(positive_u64(plan.authority_seq, "authority_seq").map_err(|_| PlanVerifyError::PlanDigestMismatch)?);
    w.push_u32(
        count_u32(plan.selected_covers.len(), "selected_covers").map_err(|_| PlanVerifyError::PlanDigestMismatch)?,
    );
    for entry in &plan.selected_covers {
        w.push_len_prefixed(entry.cover_id.as_bytes()).map_err(|_| PlanVerifyError::PlanDigestMismatch)?;
    }
    Ok(w.finish())
}
