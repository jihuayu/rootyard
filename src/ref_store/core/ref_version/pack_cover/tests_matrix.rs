//! Matrix tests for causal planner selection, authorization boundaries, fallback, and tamper refusal.
use super::super::closure::{CausalVersionNode, VersionGraph};
use super::super::contract::{AuthorityKind, RefVersionRealm};
use super::super::pack_set::VerifiedClosurePack;
use super::super::read_mode::ReadConsumer;
use super::super::record::{RefHead, VersionRecord};
use super::auth::{
    FallbackReason, FetchPlanError, ReadIsolationMode, RefVisibilityPolicy, StrongSnapshotCut,
    advertise_authorized_refs,
};
use super::model::{
    CoverCommitLink, CoverHierarchyIndex, CoverHierarchyRecord, CoverHierarchyRecordInput, CoverModelError, CoverTier,
    compute_cover_membership_digest,
};
use super::planner::{
    DEFAULT_COMPACTED_THRESHOLD, FetchPlanOutcome, FetchPlanRequest, HaveSpec, WantTarget, plan_fetch_covers,
};
use super::retention_class::{CoverRetentionHold, PackRetentionState, RetentionClassificationIndex};
use super::tests::{default_auth, make_pack, mint_version, oid, realm, seal_test_cover, uid};
use super::verifier::{PlanVerifyError, verify_fetch_plan_closure};
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::types::{GitObjectFormat, GitOid, RefName};
use std::collections::BTreeMap;

#[test]
fn planner_verifier_auth_isolation_and_fallback_matrix() {
    let r = realm(GitObjectFormat::Sha1);
    let mem0 = compute_cover_membership_digest(&r, 1, &[]).unwrap();
    let mut index = CoverHierarchyIndex::new(r, mem0).unwrap();
    let mut graph = VersionGraph::new();
    let mut ret = RetentionClassificationIndex::new();

    let (p1, a1) = make_pack(&r, 11, 50_000, 1000, false, vec![]);
    let (v1, p1_c) = mint_version(&r, "refs/heads/main", 1, None, oid(GitObjectFormat::Sha1, 1), p1, vec![]);
    graph.insert_active(CausalVersionNode { record: v1.clone(), own_packs: vec![p1_c.clone()] });

    let (p2, a2) = make_pack(&r, 12, 2_000, 200, true, vec![uid(111)]);
    let (v2, p2_c) =
        mint_version(&r, "refs/heads/main", 2, Some(&v1), oid(GitObjectFormat::Sha1, 2), p2, vec![v1.version_id()]);
    graph.insert_active(CausalVersionNode { record: v2.clone(), own_packs: vec![p2_c.clone()] });

    let (p_sec, a_sec) = make_pack(&r, 13, 3_000, 200, false, vec![]);
    let (v_sec, p_sec_c) = mint_version(&r, "refs/hidden/sec", 3, None, oid(GitObjectFormat::Sha1, 99), p_sec, vec![]);
    graph.insert_active(CausalVersionNode { record: v_sec.clone(), own_packs: vec![p_sec_c.clone()] });

    let mem1 = compute_cover_membership_digest(&r, 2, &[*p1_c.entry(), *p2_c.entry(), *p_sec_c.entry()]).unwrap();
    let l1 = CoverCommitLink {
        commit_oid: oid(GitObjectFormat::Sha1, 1),
        parent_oids: vec![],
        version_id: v1.version_id(),
        authority_seq: 1,
    };
    let l2 = CoverCommitLink {
        commit_oid: oid(GitObjectFormat::Sha1, 2),
        parent_oids: vec![oid(GitObjectFormat::Sha1, 1)],
        version_id: v2.version_id(),
        authority_seq: 2,
    };
    let l3 = CoverCommitLink {
        commit_oid: oid(GitObjectFormat::Sha1, 99),
        parent_oids: vec![],
        version_id: v_sec.version_id(),
        authority_seq: 3,
    };
    let c1 = seal_test_cover(
        &r,
        (111, 2, (1, 1), mem1),
        CoverTier::Delta,
        (p1_c.clone(), a1),
        vec![v1.version_id()],
        vec![l1],
        vec![],
    );
    let c2 = seal_test_cover(
        &r,
        (112, 2, (2, 2), mem1),
        CoverTier::Delta,
        (p2_c, a2),
        vec![v2.version_id()],
        vec![l2],
        vec![],
    );
    let c_sec = seal_test_cover(
        &r,
        (113, 2, (3, 3), mem1),
        CoverTier::Delta,
        (p_sec_c, a_sec),
        vec![v_sec.version_id()],
        vec![l3],
        vec![],
    );
    index.register_leaf_cover(c1.clone(), mem1).unwrap();
    index.register_leaf_cover(c2, mem1).unwrap();
    index.register_leaf_cover(c_sec, mem1).unwrap();

    ret.add_hold(CoverRetentionHold::ActiveRefHead {
        ref_name: RefName::new("refs/heads/main").unwrap(),
        version_id: v2.version_id(),
        cover_ids: vec![uid(111), uid(112)],
    });
    ret.add_hold(CoverRetentionHold::ActiveRefHead {
        ref_name: RefName::new("refs/hidden/sec").unwrap(),
        version_id: v_sec.version_id(),
        cover_ids: vec![uid(113)],
    });

    let mut heads = BTreeMap::new();
    heads.insert(RefName::new("refs/heads/main").unwrap(), RefHead::from_committed(&v2).unwrap());
    heads.insert(RefName::new("refs/hidden/sec").unwrap(), RefHead::from_committed(&v_sec).unwrap());
    let cut = StrongSnapshotCut {
        authority_seq: 3,
        snapshot_digest: RequestDigest::of("snap", &[b"cut"]),
        membership_digest: index.membership_digest(),
        heads: heads.clone(),
    };

    let mut restricted_auth = default_auth(&r);
    restricted_auth.visibility =
        RefVisibilityPolicy::AllowOnly([RefName::new("refs/heads/main").unwrap()].into_iter().collect());

    let ads = advertise_authorized_refs(&restricted_auth, &r, &heads.values().cloned().collect::<Vec<_>>()).unwrap();
    assert_eq!(ads.len(), 1);
    assert_eq!(ads[0].ref_name.as_str(), "refs/heads/main");

    let probe_req = FetchPlanRequest {
        consumer: ReadConsumer::SmartHttpFetch,
        realm: r,
        auth: restricted_auth.clone(),
        isolation: ReadIsolationMode::default(),
        strong_cut: Some(cut.clone()),
        wants: vec![WantTarget::Ref { ref_name: RefName::new("refs/heads/main").unwrap() }],
        haves: HaveSpec { have_oids: vec![oid(GitObjectFormat::Sha1, 99)], have_version_ids: vec![] },
        allow_strong_fallback: false,
        prefer_compacted_above_delta_count: DEFAULT_COMPACTED_THRESHOLD,
    };
    assert_eq!(plan_fetch_covers(&probe_req, &graph, &index, &ret), Err(FetchPlanError::HiddenRefDenied));

    let inc_req = FetchPlanRequest {
        consumer: ReadConsumer::SmartHttpFetch,
        realm: r,
        auth: restricted_auth.clone(),
        isolation: ReadIsolationMode::StrongSnapshot,
        strong_cut: Some(cut.clone()),
        wants: vec![WantTarget::Ref { ref_name: RefName::new("refs/heads/main").unwrap() }],
        haves: HaveSpec { have_oids: vec![oid(GitObjectFormat::Sha1, 1)], have_version_ids: vec![] },
        allow_strong_fallback: true,
        prefer_compacted_above_delta_count: DEFAULT_COMPACTED_THRESHOLD,
    };
    let FetchPlanOutcome::Planned(plan) = plan_fetch_covers(&inc_req, &graph, &index, &ret).unwrap() else {
        panic!("expected planned incremental outcome");
    };
    assert_eq!(plan.selected_covers.len(), 1);
    assert_eq!(plan.selected_covers[0].cover_id, uid(112));
    assert_eq!(plan.external_client_base_covers, vec![uid(111)]);
    let proof = verify_fetch_plan_closure(
        &plan,
        ReadConsumer::SmartHttpFetch,
        &restricted_auth,
        Some(&cut),
        &graph,
        &index,
        &ret,
    )
    .unwrap();
    assert!(proof.binds(&plan));

    let mut clone_req = inc_req.clone();
    clone_req.haves = HaveSpec::default();
    let FetchPlanOutcome::Planned(clone_plan) = plan_fetch_covers(&clone_req, &graph, &index, &ret).unwrap() else {
        panic!("expected planned clone outcome");
    };
    assert_eq!(clone_plan.selected_covers.iter().map(|c| c.cover_id).collect::<Vec<_>>(), vec![uid(111), uid(112)]);

    ret.add_hold(CoverRetentionHold::QuarantineHold {
        incident_id: uid(995),
        pack_ids: vec![p1_c.entry().pack_id()],
        cover_ids: vec![],
        cleared: false,
    });
    let fallback = plan_fetch_covers(&clone_req, &graph, &index, &ret).unwrap();
    assert!(matches!(
        fallback,
        FetchPlanOutcome::FallbackToStrongSnapshot { reason: FallbackReason::RetentionLost, .. }
    ));

    let mut non_common_req = inc_req.clone();
    non_common_req.isolation = ReadIsolationMode::VersionSet {
        version_ids: vec![v2.version_id()],
        session_lower_bound: None,
        historical_pinned: false,
    };
    assert_eq!(plan_fetch_covers(&non_common_req, &graph, &index, &ret), Err(FetchPlanError::NonCommonTimeDenied));

    // Verifier enforces session_lower_bound (BehindSession), and both planner & verifier bind PinnedVersion.
    let main_ref = RefName::new("refs/heads/main").unwrap();
    let vc_req = FetchPlanRequest {
        consumer: ReadConsumer::SingleRefBrowse,
        realm: r,
        auth: restricted_auth.clone(),
        isolation: ReadIsolationMode::VersionClosure {
            version_id: v2.version_id(),
            session_lower_bound: Some(2),
            historical_pinned: false,
        },
        strong_cut: None,
        wants: vec![WantTarget::PinnedVersion { ref_name: main_ref.clone(), version_id: v2.version_id() }],
        haves: HaveSpec { have_oids: vec![oid(GitObjectFormat::Sha1, 1)], have_version_ids: vec![] },
        allow_strong_fallback: false,
        prefer_compacted_above_delta_count: DEFAULT_COMPACTED_THRESHOLD,
    };
    let FetchPlanOutcome::Planned(vc_plan) = plan_fetch_covers(&vc_req, &graph, &index, &ret).unwrap() else {
        panic!("expected planned VersionClosure outcome");
    };
    let mut behind_req = vc_req.clone();
    behind_req.isolation = ReadIsolationMode::VersionClosure {
        version_id: v2.version_id(),
        session_lower_bound: Some(3),
        historical_pinned: false,
    };
    assert_eq!(plan_fetch_covers(&behind_req, &graph, &index, &ret), Err(FetchPlanError::BehindSession));
    let mut forged_behind_plan = (*vc_plan).clone();
    forged_behind_plan.isolation = behind_req.isolation.clone();
    forged_behind_plan.plan_digest = super::planner::compute_fetch_plan_digest(&forged_behind_plan).unwrap();
    assert_eq!(
        verify_fetch_plan_closure(
            &forged_behind_plan,
            ReadConsumer::SingleRefBrowse,
            &restricted_auth,
            None,
            &graph,
            &index,
            &ret,
        ),
        Err(PlanVerifyError::Plan(FetchPlanError::BehindSession))
    );

    let mut pin_strong_req = inc_req.clone();
    pin_strong_req.auth.allow_historical_pins = false;
    pin_strong_req.allow_strong_fallback = false;
    pin_strong_req.wants = vec![WantTarget::PinnedVersion { ref_name: main_ref.clone(), version_id: v1.version_id() }];
    assert!(matches!(
        plan_fetch_covers(&pin_strong_req, &graph, &index, &ret),
        Err(FetchPlanError::InvalidPlanInput(_))
    ));
    let mut pin_vc_mismatch = vc_req.clone();
    pin_vc_mismatch.wants = vec![WantTarget::PinnedVersion { ref_name: main_ref.clone(), version_id: v1.version_id() }];
    assert!(matches!(
        plan_fetch_covers(&pin_vc_mismatch, &graph, &index, &ret),
        Err(FetchPlanError::InvalidPlanInput(_))
    ));
    let mut forged_pin_plan = (*vc_plan).clone();
    forged_pin_plan.wants = vec![WantTarget::PinnedVersion { ref_name: main_ref, version_id: v1.version_id() }];
    forged_pin_plan.plan_digest = super::planner::compute_fetch_plan_digest(&forged_pin_plan).unwrap();
    assert!(matches!(
        verify_fetch_plan_closure(
            &forged_pin_plan,
            ReadConsumer::SingleRefBrowse,
            &restricted_auth,
            None,
            &graph,
            &index,
            &ret
        ),
        Err(PlanVerifyError::Plan(FetchPlanError::InvalidPlanInput(_)))
    ));

    let mut tampered = c1_for_tamper_test(&r, &p1_c, &v1);
    tampered.tamper_record_digest_for_test();
    assert_eq!(tampered.verify_digest(), Err(CoverModelError::RecordDigestMismatch));

    let mismatched_ver = CoverHierarchyRecord::seal(CoverHierarchyRecordInput {
        cover_id: uid(198),
        realm: r,
        tier: CoverTier::Delta,
        pack: p1_c.clone(),
        artifacts: make_pack(&r, 98, p1_c.verified_bytes() - 200, 200, false, vec![]).1,
        covered_versions: vec![v1.version_id()],
        min_authority_seq: 1,
        max_authority_seq: 1,
        covered_commits: vec![CoverCommitLink {
            commit_oid: oid(GitObjectFormat::Sha1, 1),
            parent_oids: vec![],
            version_id: v2.version_id(),
            authority_seq: 1,
        }],
        input_cover_ids: vec![],
        membership_generation: 2,
        membership_digest: compute_cover_membership_digest(&r, 2, &[*p1_c.entry()]).unwrap(),
        compaction_epoch: 1,
        worker_id: uid(798),
        operation_id: uid(898),
    });
    assert!(matches!(mismatched_ver, Err(CoverModelError::InvalidShape(_))));

    // Reset holds for forged-cut negative tests (both planner and verifier must reject).
    let mut active_ret = RetentionClassificationIndex::new();
    active_ret.add_hold(CoverRetentionHold::ActiveRefHead {
        ref_name: RefName::new("refs/heads/main").unwrap(),
        version_id: v2.version_id(),
        cover_ids: vec![uid(111), uid(112)],
    });
    assert_eq!(active_ret.classify_cover(&c1).state, Some(PackRetentionState::PlannableForFetch));

    let FetchPlanOutcome::Planned(valid_plan) = plan_fetch_covers(&inc_req, &graph, &index, &active_ret).unwrap()
    else {
        panic!("expected valid plan");
    };

    let mut forged_heads = heads.clone();
    forged_heads.insert(RefName::new("refs/heads/main").unwrap(), RefHead::from_committed(&v_sec).unwrap());
    let forged_cut = StrongSnapshotCut { heads: forged_heads, ..cut.clone() };
    let mut forged_req = inc_req.clone();
    forged_req.strong_cut = Some(forged_cut.clone());
    assert!(matches!(
        plan_fetch_covers(&forged_req, &graph, &index, &active_ret),
        Err(FetchPlanError::InvalidPlanInput(_))
    ));
    assert!(matches!(
        verify_fetch_plan_closure(
            &valid_plan,
            ReadConsumer::SmartHttpFetch,
            &restricted_auth,
            Some(&forged_cut),
            &graph,
            &index,
            &active_ret
        ),
        Err(PlanVerifyError::Plan(FetchPlanError::InvalidPlanInput(_)))
    ));

    let mut wrong_realm_heads = heads.clone();
    let other_r = RefVersionRealm::new(uid(91), uid(92), uid(93), AuthorityKind::Pg, 1, 0, 1, GitObjectFormat::Sha1);
    let (p_other, _) = make_pack(&other_r, 11, 50_000, 1000, false, vec![]);
    let (v_other, _) =
        mint_version(&other_r, "refs/heads/main", 1, None, oid(GitObjectFormat::Sha1, 1), p_other, vec![]);
    wrong_realm_heads.insert(RefName::new("refs/heads/main").unwrap(), RefHead::from_committed(&v_other).unwrap());
    let wrong_realm_cut = StrongSnapshotCut { heads: wrong_realm_heads, ..cut.clone() };
    let mut wrong_realm_req = inc_req.clone();
    wrong_realm_req.strong_cut = Some(wrong_realm_cut.clone());
    assert_eq!(plan_fetch_covers(&wrong_realm_req, &graph, &index, &active_ret), Err(FetchPlanError::RealmMismatch));
    assert_eq!(
        verify_fetch_plan_closure(
            &valid_plan,
            ReadConsumer::SmartHttpFetch,
            &restricted_auth,
            Some(&wrong_realm_cut),
            &graph,
            &index,
            &active_ret
        ),
        Err(PlanVerifyError::Plan(FetchPlanError::RealmMismatch))
    );

    let stale_seq_cut = StrongSnapshotCut { authority_seq: 1, ..cut.clone() };
    let mut stale_seq_req = inc_req.clone();
    stale_seq_req.strong_cut = Some(stale_seq_cut.clone());
    assert!(matches!(
        plan_fetch_covers(&stale_seq_req, &graph, &index, &active_ret),
        Err(FetchPlanError::InvalidPlanInput(_))
    ));
    assert!(matches!(
        verify_fetch_plan_closure(
            &valid_plan,
            ReadConsumer::SmartHttpFetch,
            &restricted_auth,
            Some(&stale_seq_cut),
            &graph,
            &index,
            &active_ret
        ),
        Err(PlanVerifyError::SelectedPackMetadataMismatch)
            | Err(PlanVerifyError::Plan(FetchPlanError::InvalidPlanInput(_)))
    ));
}

#[test]
fn planner_rejects_aggregate_scoring_work_budget_exhaustion() {
    let r = realm(GitObjectFormat::Sha1);
    let tip_oid = oid(GitObjectFormat::Sha1, 1);
    let (p_base, _) = make_pack(&r, 255, 1024, 100, false, vec![]);
    let (v1, p1_c) = mint_version(&r, "refs/heads/main", 1, None, tip_oid, p_base, vec![]);
    let mut graph = VersionGraph::new();
    graph.insert_active(CausalVersionNode { record: v1.clone(), own_packs: vec![p1_c.clone()] });

    let mut links = Vec::with_capacity(250);
    let mk_oid = |idx: usize| -> GitOid {
        if idx == 249 {
            return tip_oid;
        }
        let mut raw = [0_u8; 20];
        raw[..8].copy_from_slice(&(idx as u64 + 1).to_be_bytes());
        raw[19] = 2;
        GitOid::parse(GitObjectFormat::Sha1, &hex::encode(raw)).unwrap()
    };
    for i in 0..250_usize {
        let parent_oids = if i > 0 { vec![mk_oid(i - 1)] } else { vec![] };
        links.push(CoverCommitLink {
            commit_oid: mk_oid(i),
            parent_oids,
            version_id: v1.version_id(),
            authority_seq: 1,
        });
    }
    let mut entries = Vec::new();
    let mut mem = compute_cover_membership_digest(&r, 1, &[]).unwrap();
    let mut index = CoverHierarchyIndex::new(r, mem).unwrap();
    let mut ret = RetentionClassificationIndex::new();
    let mut hold_ids = Vec::new();
    for (k, link) in links.iter().enumerate() {
        let (pk, art) = make_pack(&r, (k % 250) as u8, 2000 + k as u64, 100, false, vec![]);
        entries.push(*pk.entry());
        mem = compute_cover_membership_digest(&r, index.membership_generation() + 1, &entries).unwrap();
        let meta = (10_000 + k as u128, index.membership_generation() + 1, (1, 1), mem);
        let cov =
            seal_test_cover(&r, meta, CoverTier::Delta, (pk, art), vec![v1.version_id()], vec![link.clone()], vec![]);
        hold_ids.push(cov.cover_id());
        index.register_leaf_cover(cov, mem).unwrap();
    }
    ret.add_hold(CoverRetentionHold::ActiveRefHead {
        ref_name: RefName::new("refs/heads/main").unwrap(),
        version_id: v1.version_id(),
        cover_ids: hold_ids,
    });
    let mut heads = BTreeMap::new();
    heads.insert(RefName::new("refs/heads/main").unwrap(), RefHead::from_committed(&v1).unwrap());
    let cut = StrongSnapshotCut {
        authority_seq: 1,
        snapshot_digest: RequestDigest::of("budget", &[b"cut"]),
        membership_digest: index.membership_digest(),
        heads,
    };
    let req = FetchPlanRequest {
        consumer: ReadConsumer::SmartHttpFetch,
        realm: r,
        auth: default_auth(&r),
        isolation: ReadIsolationMode::StrongSnapshot,
        strong_cut: Some(cut),
        wants: vec![WantTarget::Ref { ref_name: RefName::new("refs/heads/main").unwrap() }],
        haves: HaveSpec::default(),
        allow_strong_fallback: false,
        prefer_compacted_above_delta_count: DEFAULT_COMPACTED_THRESHOLD,
    };
    assert_eq!(plan_fetch_covers(&req, &graph, &index, &ret), Err(FetchPlanError::ClosureBoundsExceeded));
}

fn c1_for_tamper_test(r: &RefVersionRealm, p: &VerifiedClosurePack, v: &VersionRecord) -> CoverHierarchyRecord {
    let (_, a) = make_pack(r, 99, p.verified_bytes() - 200, 200, false, vec![]);
    let mem = compute_cover_membership_digest(r, 2, &[*p.entry()]).unwrap();
    let l = CoverCommitLink {
        commit_oid: oid(r.object_format(), 1),
        parent_oids: vec![],
        version_id: v.version_id(),
        authority_seq: 1,
    };
    seal_test_cover(r, (199, 2, (1, 1), mem), CoverTier::Delta, (p.clone(), a), vec![v.version_id()], vec![l], vec![])
}
