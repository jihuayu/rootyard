//! Greedy weighted set-cover selection, thin-base closure expansion, and strong fallback (Issue #184).
use super::super::closure::{CausalVersionLookup, VersionLookupEntry};
use super::super::limits::{MAX_CLOSURE_ARTIFACTS, MAX_CLOSURE_PACKS, MAX_CLOSURE_VERIFIED_BYTES};
use super::super::read_mode::StrongSnapshotState;
use super::auth::{
    FallbackReason, FetchPlanError, MAX_PLANNER_SCORING_STEPS, StrongSnapshotFallback, advertise_authorized_refs,
    cover_exposes_unauthorized_commits,
};
use super::model::{CoverCommitLink, CoverHierarchyIndex, CoverHierarchyRecord, oid_bytes};
use super::planner::{FetchPlanOutcome, FetchPlanRequest, PlannedCoverEntry};
use super::retention_class::{CoverHoldKind, RetentionClassificationIndex};
use crate::ref_store::core::types::{GitOid, RefTarget};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use uuid::Uuid;

const SMALL_FETCH_PACK_OVERHEAD_BYTES: u64 = 2048;
const LARGE_FETCH_PACK_OVERHEAD_BYTES: u64 = 16384;

#[derive(Default)]
pub(super) struct SelectionResult {
    pub(super) selected: Vec<PlannedCoverEntry>,
    pub(super) external_client_bases: Vec<Uuid>,
}

pub(super) struct CoverSelectionCtx<'a> {
    pub(super) req: &'a FetchPlanRequest,
    pub(super) cover_index: &'a CoverHierarchyIndex,
    pub(super) retention_index: &'a RetentionClassificationIndex,
    pub(super) authorized_commits: &'a HashSet<GitOid>,
    pub(super) have_ancestors: &'a HashSet<GitOid>,
    pub(super) needed_set: &'a HashSet<GitOid>,
    pub(super) digest_ok: &'a BTreeMap<Uuid, bool>,
    pub(super) threshold: usize,
}

#[derive(Default)]
struct RejectionObservations {
    saw_tamper: bool,
    saw_retention_loss: bool,
    saw_hidden_leak: bool,
    saw_missing_base: bool,
}

impl RejectionObservations {
    fn into_error(self) -> (FallbackReason, FetchPlanError) {
        if self.saw_tamper {
            (FallbackReason::TamperedCoverDigest, FetchPlanError::TamperedCoverDigest)
        } else if self.saw_retention_loss {
            (FallbackReason::RetentionLost, FetchPlanError::RetentionLost)
        } else if self.saw_hidden_leak {
            (FallbackReason::SharedCoverExposesHiddenObjects, FetchPlanError::UnauthorizedObjectScope)
        } else {
            (FallbackReason::MissingBaseCover, FetchPlanError::MissingBaseCover)
        }
    }
}

struct CandidateCover<'a> {
    record: &'a CoverHierarchyRecord,
    covered_needed: HashSet<GitOid>,
    required_bases: Vec<Uuid>,
    client_satisfied_bases: Vec<Uuid>,
}

#[derive(Clone, Copy)]
enum Strategy {
    CostAware { pack_overhead_bytes: u64 },
    MinPackCount,
}

pub(super) fn fallback_or_err(
    req: &FetchPlanRequest,
    reason: FallbackReason,
    err: FetchPlanError,
) -> Result<FetchPlanOutcome, FetchPlanError> {
    if !req.allow_strong_fallback {
        return Err(err);
    }
    let Some(cut) = &req.strong_cut else {
        return Err(err);
    };
    let heads: Vec<_> = cut.heads.values().cloned().collect();
    let authorized_heads = advertise_authorized_refs(&req.auth, &req.realm, &heads)?;
    Ok(FetchPlanOutcome::FallbackToStrongSnapshot {
        reason,
        snapshot: StrongSnapshotFallback {
            state: StrongSnapshotState { authority_seq: cut.authority_seq, snapshot_digest: cut.snapshot_digest },
            authorized_heads,
            snapshot_membership_digest: cut.membership_digest,
        },
    })
}

pub(super) fn select_covers(ctx: &CoverSelectionCtx<'_>) -> Result<SelectionResult, (FallbackReason, FetchPlanError)> {
    let mut obs = RejectionObservations::default();
    let mut candidates = Vec::new();
    let is_historical = ctx.req.isolation.is_historical_pinned();
    let mut work_steps = 0_usize;

    for cover in ctx.cover_index.all_covers() {
        step_budget(&mut work_steps, 1 + cover.covered_commits().len())?;
        let covered_needed: HashSet<GitOid> =
            cover.covered_commits().iter().map(|c| c.commit_oid).filter(|oid| ctx.needed_set.contains(oid)).collect();
        if covered_needed.is_empty() {
            continue;
        }
        if !ctx.digest_ok.get(&cover.cover_id()).copied().unwrap_or(false) {
            obs.saw_tamper = true;
            continue;
        }
        if cover_exposes_unauthorized_commits(cover, &ctx.req.auth, ctx.authorized_commits) {
            obs.saw_hidden_leak = true;
            continue;
        }
        let cls = ctx.retention_index.classify_cover(cover);
        if !cls.physically_present || !cls.plannable_for_fetch {
            obs.saw_retention_loss = true;
            continue;
        }
        if !is_historical && (ctx.cover_index.is_retired_from_active(&cover.cover_id()) || cls.historical_read_only) {
            continue;
        }
        let mut state = DeltaExpandState {
            visiting: BTreeSet::from([cover.cover_id()]),
            expanded: BTreeSet::new(),
            required_bases: Vec::new(),
            client_bases: Vec::new(),
            obs: &mut obs,
        };
        if !expand_delta_bases(ctx, cover, &mut state, &mut work_steps)? {
            continue;
        }
        candidates.push(CandidateCover {
            record: cover,
            covered_needed,
            required_bases: state.required_bases,
            client_satisfied_bases: state.client_bases,
        });
    }

    let overhead = if ctx.needed_set.len() > ctx.threshold {
        LARGE_FETCH_PACK_OVERHEAD_BYTES
    } else {
        SMALL_FETCH_PACK_OVERHEAD_BYTES
    };
    let mut picked =
        run_greedy(&candidates, ctx, Strategy::CostAware { pack_overhead_bytes: overhead }, &mut work_steps)?
            .ok_or_else(|| obs.into_error())?;

    if picked.selected.len() > MAX_CLOSURE_PACKS {
        let compact = run_greedy(&candidates, ctx, Strategy::MinPackCount, &mut work_steps)?
            .ok_or((FallbackReason::ClosureBoundsExceeded, FetchPlanError::ClosureBoundsExceeded))?;
        picked = compact;
    }

    enforce_bounds(&picked.selected, ctx.cover_index)?;
    Ok(picked)
}

struct DeltaExpandState<'a> {
    visiting: BTreeSet<Uuid>,
    expanded: BTreeSet<Uuid>,
    required_bases: Vec<Uuid>,
    client_bases: Vec<Uuid>,
    obs: &'a mut RejectionObservations,
}

fn step_budget(work_steps: &mut usize, cost: usize) -> Result<(), (FallbackReason, FetchPlanError)> {
    *work_steps = work_steps.saturating_add(cost);
    if *work_steps > MAX_PLANNER_SCORING_STEPS {
        return Err((FallbackReason::ClosureBoundsExceeded, FetchPlanError::ClosureBoundsExceeded));
    }
    Ok(())
}

fn expand_delta_bases(
    ctx: &CoverSelectionCtx<'_>,
    cover: &CoverHierarchyRecord,
    state: &mut DeltaExpandState<'_>,
    work_steps: &mut usize,
) -> Result<bool, (FallbackReason, FetchPlanError)> {
    for base_id in &cover.artifacts().delta_base_cover_ids {
        step_budget(work_steps, 1)?;
        if state.visiting.contains(base_id) {
            return Ok(false);
        }
        if state.expanded.contains(base_id) {
            continue;
        }
        let Some(base) = ctx.cover_index.get(base_id) else {
            state.obs.saw_missing_base = true;
            return Ok(false);
        };
        if !ctx.digest_ok.get(base_id).copied().unwrap_or(false) {
            state.obs.saw_tamper = true;
            return Ok(false);
        }
        step_budget(work_steps, base.covered_commits().len())?;
        if cover_exposes_unauthorized_commits(base, &ctx.req.auth, ctx.authorized_commits) {
            state.obs.saw_hidden_leak = true;
            return Ok(false);
        }
        let base_cls = ctx.retention_index.classify_cover(base);
        let base_quarantined = base_cls.active_protectors.contains(&CoverHoldKind::QuarantineHold);
        let client_has_all = !base_quarantined
            && base_cls.physically_present
            && base.covered_commits().iter().all(|c| ctx.have_ancestors.contains(&c.commit_oid));
        if client_has_all {
            if !state.client_bases.contains(base_id) {
                state.client_bases.push(*base_id);
            }
        } else if base_cls.physically_present
            && base_cls.plannable_for_fetch
            && (ctx.req.isolation.is_historical_pinned()
                || (!ctx.cover_index.is_retired_from_active(base_id) && !base_cls.historical_read_only))
        {
            if !state.required_bases.contains(base_id) {
                state.required_bases.push(*base_id);
            }
            state.visiting.insert(*base_id);
            let ok = expand_delta_bases(ctx, base, state, work_steps)?;
            state.visiting.remove(base_id);
            if !ok {
                return Ok(false);
            }
        } else {
            state.obs.saw_retention_loss = true;
            return Ok(false);
        }
        state.expanded.insert(*base_id);
    }
    Ok(true)
}

fn run_greedy(
    candidates: &[CandidateCover<'_>],
    ctx: &CoverSelectionCtx<'_>,
    strategy: Strategy,
    work_steps: &mut usize,
) -> Result<Option<SelectionResult>, (FallbackReason, FetchPlanError)> {
    let mut uncovered = ctx.needed_set.clone();
    let mut chosen_ids: BTreeSet<Uuid> = BTreeSet::new();
    let mut client_bases: BTreeSet<Uuid> = BTreeSet::new();

    while !uncovered.is_empty() {
        let mut best_idx: Option<usize> = None;
        let mut best_key: (u128, u64, u8, Uuid) = (u128::MAX, u64::MAX, u8::MAX, Uuid::nil());

        for (idx, cand) in candidates.iter().enumerate() {
            step_budget(work_steps, 1)?;
            if chosen_ids.contains(&cand.record.cover_id()) {
                continue;
            }
            step_budget(work_steps, cand.covered_needed.len())?;
            let gain = cand.covered_needed.iter().filter(|oid| uncovered.contains(oid)).count() as u64;
            if gain == 0 {
                continue;
            }
            let eff_bytes = effective_bytes(cand, &chosen_ids, ctx.cover_index);
            let score_key = match strategy {
                Strategy::CostAware { pack_overhead_bytes } => {
                    let total_cost = u128::from(eff_bytes.saturating_add(pack_overhead_bytes));
                    let scaled_per_commit = total_cost.saturating_mul(1000) / u128::from(gain);
                    (scaled_per_commit, eff_bytes, cand.record.tier().rank(), cand.record.cover_id())
                }
                Strategy::MinPackCount => {
                    let inv_gain = u128::from(u64::MAX - gain);
                    (inv_gain, eff_bytes, u8::MAX - cand.record.tier().rank(), cand.record.cover_id())
                }
            };
            if best_idx.is_none() || score_key < best_key {
                best_idx = Some(idx);
                best_key = score_key;
            }
        }

        let Some(idx) = best_idx else {
            return Ok(None);
        };
        let chosen = &candidates[idx];
        chosen_ids.insert(chosen.record.cover_id());
        for base_id in &chosen.required_bases {
            if chosen_ids.insert(*base_id)
                && let Some(base_rec) = ctx.cover_index.get(base_id)
            {
                for link in base_rec.covered_commits() {
                    uncovered.remove(&link.commit_oid);
                }
            }
        }
        for base_id in &chosen.client_satisfied_bases {
            client_bases.insert(*base_id);
        }
        for oid in &chosen.covered_needed {
            uncovered.remove(oid);
        }
    }

    let Some(ordered) = topo_order_covers(&chosen_ids, ctx.cover_index) else {
        return Ok(None);
    };
    let selected = ordered
        .into_iter()
        .map(|rec| PlannedCoverEntry {
            cover_id: rec.cover_id(),
            pack_id: rec.pack().entry().pack_id(),
            tier: rec.tier(),
            verified_bytes: rec.pack().verified_bytes(),
            is_thin_pack: rec.artifacts().is_thin_pack,
            delta_base_cover_ids: rec.artifacts().delta_base_cover_ids.clone(),
        })
        .collect();

    Ok(Some(SelectionResult { selected, external_client_bases: client_bases.into_iter().collect() }))
}

fn effective_bytes(cand: &CandidateCover<'_>, chosen_ids: &BTreeSet<Uuid>, cover_index: &CoverHierarchyIndex) -> u64 {
    let mut total = cand.record.pack().verified_bytes();
    for base_id in &cand.required_bases {
        if !chosen_ids.contains(base_id)
            && let Some(base) = cover_index.get(base_id)
        {
            total = total.saturating_add(base.pack().verified_bytes());
        }
    }
    total
}

fn topo_order_covers<'a>(
    chosen_ids: &BTreeSet<Uuid>,
    cover_index: &'a CoverHierarchyIndex,
) -> Option<Vec<&'a CoverHierarchyRecord>> {
    let mut visited = BTreeSet::new();
    let mut result = Vec::with_capacity(chosen_ids.len());
    let mut records: Vec<&CoverHierarchyRecord> = chosen_ids.iter().filter_map(|id| cover_index.get(id)).collect();
    records.sort_by_key(|r| (r.min_authority_seq(), r.tier().rank(), r.cover_id()));

    fn visit<'a>(
        rec: &'a CoverHierarchyRecord,
        chosen_ids: &BTreeSet<Uuid>,
        cover_index: &'a CoverHierarchyIndex,
        visited: &mut BTreeSet<Uuid>,
        result: &mut Vec<&'a CoverHierarchyRecord>,
    ) {
        if !visited.insert(rec.cover_id()) {
            return;
        }
        for base_id in &rec.artifacts().delta_base_cover_ids {
            if chosen_ids.contains(base_id)
                && let Some(base_rec) = cover_index.get(base_id)
            {
                visit(base_rec, chosen_ids, cover_index, visited, result);
            }
        }
        result.push(rec);
    }

    for rec in records {
        visit(rec, chosen_ids, cover_index, &mut visited, &mut result);
    }
    Some(result)
}

fn enforce_bounds(
    selected: &[PlannedCoverEntry],
    cover_index: &CoverHierarchyIndex,
) -> Result<(), (FallbackReason, FetchPlanError)> {
    if selected.len() > MAX_CLOSURE_PACKS {
        return Err((FallbackReason::ClosureBoundsExceeded, FetchPlanError::ClosureBoundsExceeded));
    }
    let mut total_artifacts = 0_usize;
    let mut total_bytes = 0_u64;
    for entry in selected {
        let Some(rec) = cover_index.get(&entry.cover_id) else {
            return Err((FallbackReason::MissingBaseCover, FetchPlanError::MissingBaseCover));
        };
        let count = usize::try_from(rec.pack().artifact_count()).unwrap_or(usize::MAX);
        total_artifacts = total_artifacts.saturating_add(count);
        total_bytes = total_bytes.saturating_add(rec.pack().verified_bytes());
    }
    if total_artifacts > MAX_CLOSURE_ARTIFACTS || total_bytes > MAX_CLOSURE_VERIFIED_BYTES {
        return Err((FallbackReason::ClosureBoundsExceeded, FetchPlanError::ClosureBoundsExceeded));
    }
    Ok(())
}

pub(super) fn resolve_verified_haves(
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
        if let VersionLookupEntry::Active(node) = version_lookup.lookup_version(vid) {
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

pub(super) fn collect_missing_commits(
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
