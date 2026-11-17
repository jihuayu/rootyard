//! Unit contract tests for causal pack-cover model, compaction fencing, retention,
//! fetch planning, authorization boundaries, and independent closure verification.
use super::super::commit_set::{CommitSetHead, CommitSetInput, CommitSetVersionEntry, compute_commit_set_id};
use super::super::contract::{
    AuthorityKind, BaseRequestSelector, OperationDigestInput, RefVersionIntent, RefVersionKind, RefVersionRealm,
    VersionId,
};
use super::super::digest::{derive_candidate_version_id, operation_digest};
use super::super::pack_set::{PackSetEntry, VerifiedClosurePack, compute_pack_set_digest};
use super::super::record::{VersionRecord, VersionRecordInput};
use super::auth::{AuthorizationContext, RefVisibilityPolicy};
use super::model::{
    CompactionPublishOutcome, CoverArtifactPair, CoverCommitLink, CoverHierarchyIndex, CoverHierarchyRecord,
    CoverHierarchyRecordInput, CoverMembershipDigest, CoverModelError, CoverTier, compute_cover_membership_digest,
};
use super::retention_class::{
    CoverRetentionHold, NonAuthoritativeHint, PHYSICAL_GC_OWNER, PackRetentionState, PhysicalBlobStatus,
    RetentionClassificationIndex,
};
use crate::blob_store::BlobLocator;
use crate::ref_store::contract::{IssuerLane, RequestDigest};
use crate::ref_store::core::contract::CommitMode;
use crate::ref_store::core::types::{GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget};
use uuid::Uuid;

pub(super) fn uid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

pub(super) fn realm(fmt: GitObjectFormat) -> RefVersionRealm {
    RefVersionRealm::new(uid(10), uid(20), uid(30), AuthorityKind::Pg, 1, 0, 1, fmt)
}

pub(super) fn oid(fmt: GitObjectFormat, byte: u8) -> GitOid {
    match fmt {
        GitObjectFormat::Sha1 => GitOid::Sha1([byte; 20]),
        GitObjectFormat::Sha256 => GitOid::Sha256([byte; 32]),
    }
}

fn sha256_hex(seed: u8) -> String {
    hex::encode([seed; 32])
}

fn pack_stem(fmt: GitObjectFormat, seed: u8) -> String {
    match fmt {
        GitObjectFormat::Sha1 => format!("pack-{}", hex::encode([seed; 20])),
        GitObjectFormat::Sha256 => format!("pack-{}", hex::encode([seed; 32])),
    }
}

pub(super) fn make_pack(
    r: &RefVersionRealm,
    seed: u8,
    pack_len: u64,
    idx_len: u64,
    is_thin_pack: bool,
    delta_bases: Vec<Uuid>,
) -> (VerifiedClosurePack, CoverArtifactPair) {
    let pack_id = uid(1000 + u128::from(seed));
    let reg_id = uid(2000 + u128::from(seed));
    let entry = PackSetEntry::new(pack_id, reg_id, RequestDigest::of("art", &[&[seed]])).unwrap();
    let vpack = VerifiedClosurePack::new(
        entry,
        r.tenant_id(),
        r.repository_id(),
        "s3",
        sha256_hex(0xab),
        pack_len + idx_len,
        2,
    )
    .unwrap();
    let pack_loc = BlobLocator::new(
        r.tenant_id(),
        r.repository_id(),
        1,
        uid(3000 + u128::from(seed)),
        "packs",
        &sha256_hex(seed),
        pack_len,
    )
    .unwrap();
    let idx_loc = BlobLocator::new(
        r.tenant_id(),
        r.repository_id(),
        1,
        uid(4000 + u128::from(seed)),
        "packs",
        &sha256_hex(seed.wrapping_add(1)),
        idx_len,
    )
    .unwrap();
    let artifacts = CoverArtifactPair {
        pack_stem: pack_stem(r.object_format(), seed),
        pack_locator: pack_loc,
        idx_locator: idx_loc,
        is_thin_pack,
        delta_base_cover_ids: delta_bases,
    };
    (vpack, artifacts)
}

pub(super) fn mint_version(
    r: &RefVersionRealm,
    ref_str: &str,
    seq: i64,
    base: Option<&VersionRecord>,
    target_oid: GitOid,
    pack: VerifiedClosurePack,
    deps: Vec<VersionId>,
) -> (VersionRecord, VerifiedClosurePack) {
    let ref_name = RefName::new(ref_str).unwrap();
    let pre = match base {
        None => RefPrecondition::Absent,
        Some(b) => match b.target() {
            RefTarget::Oid(o) => RefPrecondition::Present(*o),
            RefTarget::Delete => RefPrecondition::Absent,
        },
    };
    let sel = match base {
        None => BaseRequestSelector::ExplicitAbsent,
        Some(b) => BaseRequestSelector::Present(b.version_id()),
    };
    let op_id = uid(5000 + seq as u128);
    let intent = RefVersionIntent::new(ref_name.clone(), RefVersionKind::Publish, pre, sel, RefTarget::Oid(target_oid));
    let op = OperationDigestInput::new(
        *r,
        uid(1),
        uid(2),
        IssuerLane::new("main").unwrap(),
        seq,
        op_id,
        seq,
        RequestDigest::of("gate", &[&seq.to_be_bytes()]),
        CommitMode::Atomic,
        HeadUpdate::Keep,
        vec![intent],
        RequestDigest::of("mem", &[&seq.to_be_bytes()]),
        vec![],
    );
    let od = operation_digest(&op).unwrap();
    let vid = derive_candidate_version_id(&op, od, &ref_name, base.map(VersionRecord::ref_generation)).unwrap();
    let pack_set_digest = compute_pack_set_digest(&[*pack.entry()]).unwrap();
    let cs_id = compute_commit_set_id(&CommitSetInput::new(
        *r,
        seq,
        op_id,
        od,
        vec![CommitSetVersionEntry::new(ref_name.clone(), vid, RefVersionKind::Publish, RefTarget::Oid(target_oid))],
        CommitSetHead::Absent,
    ))
    .unwrap();
    let rec = VersionRecord::seal(VersionRecordInput {
        version_id: vid,
        realm: *r,
        ref_name,
        ref_generation: base.map_or(1, |b| b.ref_generation() + 1),
        operation_id: op_id,
        operation_digest: od,
        authority_seq: seq,
        kind: RefVersionKind::Publish,
        target: RefTarget::Oid(target_oid),
        base_version_id: base.map(VersionRecord::version_id),
        object_deps: deps,
        pack_set_digest,
        commit_set_id: cs_id,
    })
    .unwrap();
    (rec, pack)
}

pub(super) fn seal_test_cover(
    r: &RefVersionRealm,
    meta: (u128, u64, (i64, i64), CoverMembershipDigest),
    tier: CoverTier,
    (pack, artifacts): (VerifiedClosurePack, CoverArtifactPair),
    covered_versions: Vec<VersionId>,
    covered_commits: Vec<CoverCommitLink>,
    input_cover_ids: Vec<Uuid>,
) -> CoverHierarchyRecord {
    CoverHierarchyRecord::seal(CoverHierarchyRecordInput {
        cover_id: uid(meta.0),
        realm: *r,
        tier,
        pack,
        artifacts,
        covered_versions,
        min_authority_seq: meta.2.0,
        max_authority_seq: meta.2.1,
        covered_commits,
        input_cover_ids,
        membership_generation: meta.1,
        membership_digest: meta.3,
        compaction_epoch: 1,
        worker_id: uid(701),
        operation_id: uid(meta.0 + 700),
    })
    .unwrap()
}

fn link(commit_oid: GitOid, parent: Option<GitOid>, v: &VersionRecord, authority_seq: i64) -> CoverCommitLink {
    CoverCommitLink { commit_oid, parent_oids: parent.into_iter().collect(), version_id: v.version_id(), authority_seq }
}

pub(super) fn default_auth(r: &RefVersionRealm) -> AuthorizationContext {
    AuthorizationContext {
        tenant_id: r.tenant_id(),
        repository_id: r.repository_id(),
        history_incarnation: r.history_incarnation(),
        actor_id: uid(90),
        token_id: uid(91),
        auth_epoch: 5,
        min_valid_auth_epoch: 5,
        revoked: false,
        visibility: RefVisibilityPolicy::AllAuthorized,
        allow_historical_pins: true,
        allow_non_common_time_set: false,
    }
}

#[test]
fn cover_record_digest_and_compaction_fencing_work_for_sha1_and_sha256() {
    for fmt in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let r = realm(fmt);
        let mem0 = compute_cover_membership_digest(&r, 1, &[]).unwrap();
        let mut index = CoverHierarchyIndex::new(r, mem0).unwrap();

        let (p1, a1) = make_pack(&r, 1, 1000, 200, false, vec![]);
        let (v1, p1_copy) = mint_version(&r, "refs/heads/main", 1, None, oid(fmt, 1), p1, vec![]);
        let (p2, a2) = make_pack(&r, 2, 1200, 220, false, vec![]);
        let (v2, p2_copy) = mint_version(&r, "refs/heads/main", 2, Some(&v1), oid(fmt, 2), p2, vec![v1.version_id()]);

        let mem1 = compute_cover_membership_digest(&r, 2, &[*p1_copy.entry()]).unwrap();
        let l1 = link(oid(fmt, 1), None, &v1, 1);
        let c1 = seal_test_cover(
            &r,
            (101, 2, (1, 1), mem1),
            CoverTier::Delta,
            (p1_copy.clone(), a1),
            vec![v1.version_id()],
            vec![l1.clone()],
            vec![],
        );
        c1.verify_digest().unwrap();
        index.register_leaf_cover(c1.clone(), mem1).unwrap();

        let mem2 = compute_cover_membership_digest(&r, 3, &[*p1_copy.entry(), *p2_copy.entry()]).unwrap();
        let l2 = link(oid(fmt, 2), Some(oid(fmt, 1)), &v2, 2);
        let c2 = seal_test_cover(
            &r,
            (102, 3, (2, 2), mem2),
            CoverTier::Delta,
            (p2_copy.clone(), a2),
            vec![v2.version_id()],
            vec![l2.clone()],
            vec![],
        );
        index.register_leaf_cover(c2.clone(), mem2).unwrap();

        // Compacted cover dropping v2 must fail closed.
        let (p3, a3) = make_pack(&r, 3, 1800, 300, false, vec![]);
        let mem3 = compute_cover_membership_digest(&r, 4, &[*p3.entry()]).unwrap();
        let in_ids = vec![c1.cover_id(), c2.cover_id()];
        let bad_drop = seal_test_cover(
            &r,
            (103, 4, (1, 2), mem3),
            CoverTier::Compacted,
            (p3.clone(), a3.clone()),
            vec![v1.version_id()],
            vec![l1.clone()],
            in_ids.clone(),
        );
        assert_eq!(index.publish_compacted_cover(bad_drop, 1, mem2, mem3), Err(CoverModelError::InputCoverageDrop));

        let full_comp = seal_test_cover(
            &r,
            (104, 4, (1, 2), mem3),
            CoverTier::Compacted,
            (p3, a3),
            vec![v1.version_id(), v2.version_id()],
            vec![l1, l2],
            in_ids,
        );
        // Stale membership digest rejected (simulating concurrent push drift).
        assert_eq!(
            index.publish_compacted_cover(full_comp.clone(), 1, mem1, mem3),
            Err(CoverModelError::MembershipConflict)
        );
        assert_eq!(
            index.publish_compacted_cover(full_comp.clone(), 1, mem2, mem3),
            Ok(CompactionPublishOutcome::Committed)
        );
        // Exact retry is idempotent; stale epoch is rejected; early retirement with active holds blocked.
        assert_eq!(
            index.publish_compacted_cover(full_comp, 1, mem2, mem3),
            Ok(CompactionPublishOutcome::IdempotentReplay)
        );
        assert_eq!(
            index.mark_retired_from_active(c1.cover_id(), uid(104), false),
            Err(CoverModelError::ActiveHoldPreventsRetirement)
        );
        assert_eq!(index.mark_retired_from_active(c1.cover_id(), uid(104), true), Ok(()));
    }
}

#[test]
fn three_state_retention_rejects_ttl_cache_and_async_projection_deletes() {
    let r = realm(GitObjectFormat::Sha256);
    let (p1, _) = make_pack(&r, 10, 500, 100, false, vec![]);
    let (v1, p1_copy) = mint_version(&r, "refs/heads/main", 1, None, oid(GitObjectFormat::Sha256, 10), p1, vec![]);
    let cover_id = uid(990);
    let pack_id = p1_copy.entry().pack_id();

    let mut ret = RetentionClassificationIndex::new();
    ret.add_non_authoritative_hint(NonAuthoritativeHint::TtlExpired { age_seconds: 999_999 });
    ret.add_non_authoritative_hint(NonAuthoritativeHint::CacheEvicted { cache_key: "redis:k".into() });
    ret.add_non_authoritative_hint(NonAuthoritativeHint::AsyncProjectionMissingOrStale { projection_lag: 42 });

    // Without complete non-zero authoritative snapshot & explicit retirement, cover fails closed.
    let c_missing_auth = ret.classify_pack(pack_id, cover_id, &[v1.version_id()]);
    assert_eq!(c_missing_auth.state, Some(PackRetentionState::PhysicallyPresent));
    assert!(!c_missing_auth.gc_eligible && !c_missing_auth.plannable_for_fetch);
    ret.set_authority_snapshot(0, false, [cover_id]);
    assert!(!ret.classify_pack(pack_id, cover_id, &[v1.version_id()]).gc_eligible);
    ret.set_authority_snapshot(1, true, []);
    assert!(!ret.classify_pack(pack_id, cover_id, &[v1.version_id()]).gc_eligible);

    // Complete authoritative snapshot + explicit retirement + no protectors -> gc_eligible, owned by #122/#151/#153.
    ret.set_authority_snapshot(1, true, [cover_id]);
    let c0 = ret.classify_pack(pack_id, cover_id, &[v1.version_id()]);
    assert_eq!(c0.state, Some(PackRetentionState::GcEligible));
    assert!(c0.physically_present && !c0.plannable_for_fetch && c0.gc_eligible);
    assert_eq!(c0.physical_gc_owner, PHYSICAL_GC_OWNER);
    assert_eq!(c0.ignored_non_authoritative_hints.len(), 3);

    // Pending/unknown operation keeps staged pack PhysicallyPresent (non-plannable, non-GC).
    ret.add_hold(CoverRetentionHold::PendingOrUnknownOperation {
        operation_id: uid(991),
        target_versions: vec![],
        staged_pack_ids: vec![pack_id],
        protected_cover_ids: vec![],
        age_seconds: 100_000_000,
        resolved: false,
    });
    let c_pending = ret.classify_pack(pack_id, cover_id, &[v1.version_id()]);
    assert_eq!(c_pending.state, Some(PackRetentionState::PhysicallyPresent));
    assert!(c_pending.physically_present && !c_pending.plannable_for_fetch && !c_pending.gc_eligible);

    // Historical cover / CI / backup holds make pack PlannableForFetch (historical_read_only) and non-GC.
    ret.clear_holds();
    ret.add_hold(CoverRetentionHold::CiCloneKitPin {
        job_id: uid(992),
        version_ids: vec![v1.version_id()],
        cover_ids: vec![cover_id],
        revoked: false,
    });
    let c_ci = ret.classify_pack(pack_id, cover_id, &[v1.version_id()]);
    assert_eq!(c_ci.state, Some(PackRetentionState::PlannableForFetch));
    assert!(c_ci.physically_present && c_ci.plannable_for_fetch && !c_ci.gc_eligible && c_ci.historical_read_only);

    // Quarantine overrides everything else -> non-plannable, non-GC.
    ret.add_hold(CoverRetentionHold::QuarantineHold {
        incident_id: uid(993),
        pack_ids: vec![pack_id],
        cover_ids: vec![],
        cleared: false,
    });
    let c_q = ret.classify_pack(pack_id, cover_id, &[v1.version_id()]);
    assert_eq!(c_q.state, Some(PackRetentionState::PhysicallyPresent));
    assert!(!c_q.plannable_for_fetch && !c_q.gc_eligible);

    // Physical GC deletion removes physical presence.
    ret.set_physical_status(pack_id, PhysicalBlobStatus::PhysicallyDeletedByGc { gc_issue: "#122" });
    let c_del = ret.classify_pack(pack_id, cover_id, &[v1.version_id()]);
    assert_eq!(c_del.state, None);
    assert!(!c_del.physically_present && !c_del.plannable_for_fetch && !c_del.gc_eligible);
}

#[test]
fn thin_pack_uncached_retired_or_historical_delta_base_falls_back_cleanly() {
    use super::super::closure::{CausalVersionNode, VersionGraph};
    use super::super::read_mode::ReadConsumer;
    use super::super::record::RefHead;
    use super::auth::{FallbackReason, FetchPlanError, ReadIsolationMode, StrongSnapshotCut};
    use super::planner::{DEFAULT_COMPACTED_THRESHOLD, FetchPlanOutcome, FetchPlanRequest, HaveSpec, WantTarget};

    let r = realm(GitObjectFormat::Sha1);
    let mem0 = compute_cover_membership_digest(&r, 1, &[]).unwrap();
    let mut index = CoverHierarchyIndex::new(r, mem0).unwrap();
    let mut graph = VersionGraph::new();

    let (p1, a1) = make_pack(&r, 31, 40_000, 1000, false, vec![]);
    let (v1, p1_c) = mint_version(&r, "refs/heads/main", 1, None, oid(GitObjectFormat::Sha1, 31), p1, vec![]);
    graph.insert_active(CausalVersionNode { record: v1.clone(), own_packs: vec![p1_c.clone()] });

    let (p2, a2) = make_pack(&r, 32, 2_000, 200, true, vec![uid(1101)]);
    let (v2, p2_c) =
        mint_version(&r, "refs/heads/main", 2, Some(&v1), oid(GitObjectFormat::Sha1, 32), p2, vec![v1.version_id()]);
    graph.insert_active(CausalVersionNode { record: v2.clone(), own_packs: vec![p2_c.clone()] });

    let mem1 = compute_cover_membership_digest(&r, 2, &[*p1_c.entry(), *p2_c.entry()]).unwrap();
    let l1 = link(oid(GitObjectFormat::Sha1, 31), None, &v1, 1);
    let l2 = link(oid(GitObjectFormat::Sha1, 32), Some(oid(GitObjectFormat::Sha1, 31)), &v2, 2);
    let c1 = seal_test_cover(
        &r,
        (1101, 2, (1, 1), mem1),
        CoverTier::Delta,
        (p1_c, a1),
        vec![v1.version_id()],
        vec![l1.clone()],
        vec![],
    );
    let c2 = seal_test_cover(
        &r,
        (1102, 2, (2, 2), mem1),
        CoverTier::Delta,
        (p2_c.clone(), a2),
        vec![v2.version_id()],
        vec![l2],
        vec![],
    );
    index.register_leaf_cover(c1, mem1).unwrap();
    index.register_leaf_cover(c2, mem1).unwrap();

    let main_ref = RefName::new("refs/heads/main").unwrap();
    let heads = std::collections::BTreeMap::from([(main_ref.clone(), RefHead::from_committed(&v2).unwrap())]);
    let mut hist_ret = RetentionClassificationIndex::new();
    hist_ret.add_hold(CoverRetentionHold::ActiveRefHead {
        ref_name: main_ref.clone(),
        version_id: v2.version_id(),
        cover_ids: vec![uid(1102)],
    });
    hist_ret.add_hold(CoverRetentionHold::HistoricalCoverHold {
        hold_id: uid(1103),
        cover_ids: vec![uid(1101)],
        version_ids: vec![],
        active_readers: 1,
        released: false,
    });
    let mut req = FetchPlanRequest {
        consumer: ReadConsumer::SmartHttpFetch,
        realm: r,
        auth: default_auth(&r),
        isolation: ReadIsolationMode::StrongSnapshot,
        strong_cut: Some(StrongSnapshotCut {
            authority_seq: 2,
            snapshot_digest: RequestDigest::of("hist", &[b"cut"]),
            membership_digest: index.membership_digest(),
            heads: heads.clone(),
        }),
        wants: vec![WantTarget::Ref { ref_name: main_ref.clone() }],
        haves: HaveSpec::default(),
        allow_strong_fallback: true,
        prefer_compacted_above_delta_count: DEFAULT_COMPACTED_THRESHOLD,
    };
    let assert_ret_lost = |req: &mut FetchPlanRequest, ret_idx: &RetentionClassificationIndex| {
        req.allow_strong_fallback = true;
        assert!(matches!(
            super::planner::plan_fetch_covers(req, &graph, &index, ret_idx).unwrap(),
            FetchPlanOutcome::FallbackToStrongSnapshot { reason: FallbackReason::RetentionLost, .. }
        ));
        req.allow_strong_fallback = false;
        assert_eq!(super::planner::plan_fetch_covers(req, &graph, &index, ret_idx), Err(FetchPlanError::RetentionLost));
    };
    assert_ret_lost(&mut req, &hist_ret);

    let (p_sup, a_sup) = make_pack(&r, 33, 39_000, 1000, false, vec![]);
    let mem2 = compute_cover_membership_digest(&r, 3, &[*p_sup.entry(), *p2_c.entry()]).unwrap();
    let sup = seal_test_cover(
        &r,
        (1104, 3, (1, 1), mem2),
        CoverTier::Compacted,
        (p_sup, a_sup),
        vec![v1.version_id()],
        vec![l1],
        vec![uid(1101)],
    );
    index.publish_compacted_cover(sup, 1, mem1, mem2).unwrap();
    index.mark_retired_from_active(uid(1101), uid(1104), true).unwrap();

    let mut active_ret = RetentionClassificationIndex::new();
    active_ret.add_hold(CoverRetentionHold::ActiveRefHead {
        ref_name: main_ref,
        version_id: v2.version_id(),
        cover_ids: vec![uid(1102), uid(1104), uid(1101)],
    });
    req.strong_cut = Some(StrongSnapshotCut {
        authority_seq: 2,
        snapshot_digest: RequestDigest::of("ret", &[b"cut"]),
        membership_digest: index.membership_digest(),
        heads,
    });
    assert_ret_lost(&mut req, &active_ret);
}
