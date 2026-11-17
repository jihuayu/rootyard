//! Matrix tests for causal planner selection, authorization boundaries, fallback, and tamper refusal.
use super::super::closure::{CausalVersionNode, VersionGraph};
use super::super::contract::RefVersionRealm;
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
use super::retention_class::{CoverRetentionHold, RetentionClassificationIndex};
use super::tests::{default_auth, make_pack, mint_version, oid, realm, uid};
use super::verifier::verify_fetch_plan_closure;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::types::{GitObjectFormat, RefName};
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
    let c1 = CoverHierarchyRecord::seal(CoverHierarchyRecordInput {
        cover_id: uid(111),
        realm: r,
        tier: CoverTier::Delta,
        pack: p1_c.clone(),
        artifacts: a1,
        covered_versions: vec![v1.version_id()],
        min_authority_seq: 1,
        max_authority_seq: 1,
        covered_commits: vec![CoverCommitLink {
            commit_oid: oid(GitObjectFormat::Sha1, 1),
            parent_oids: vec![],
            version_id: v1.version_id(),
            authority_seq: 1,
        }],
        input_cover_ids: vec![],
        membership_generation: 2,
        membership_digest: mem1,
        compaction_epoch: 1,
        worker_id: uid(701),
        operation_id: uid(811),
    })
    .unwrap();
    let c2 = CoverHierarchyRecord::seal(CoverHierarchyRecordInput {
        cover_id: uid(112),
        realm: r,
        tier: CoverTier::Delta,
        pack: p2_c.clone(),
        artifacts: a2,
        covered_versions: vec![v2.version_id()],
        min_authority_seq: 2,
        max_authority_seq: 2,
        covered_commits: vec![CoverCommitLink {
            commit_oid: oid(GitObjectFormat::Sha1, 2),
            parent_oids: vec![oid(GitObjectFormat::Sha1, 1)],
            version_id: v2.version_id(),
            authority_seq: 2,
        }],
        input_cover_ids: vec![],
        membership_generation: 2,
        membership_digest: mem1,
        compaction_epoch: 1,
        worker_id: uid(701),
        operation_id: uid(812),
    })
    .unwrap();
    let c_sec = CoverHierarchyRecord::seal(CoverHierarchyRecordInput {
        cover_id: uid(113),
        realm: r,
        tier: CoverTier::Delta,
        pack: p_sec_c.clone(),
        artifacts: a_sec,
        covered_versions: vec![v_sec.version_id()],
        min_authority_seq: 3,
        max_authority_seq: 3,
        covered_commits: vec![CoverCommitLink {
            commit_oid: oid(GitObjectFormat::Sha1, 99),
            parent_oids: vec![],
            version_id: v_sec.version_id(),
            authority_seq: 3,
        }],
        input_cover_ids: vec![],
        membership_generation: 2,
        membership_digest: mem1,
        compaction_epoch: 1,
        worker_id: uid(701),
        operation_id: uid(813),
    })
    .unwrap();
    index.register_leaf_cover(c1, mem1).unwrap();
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

    let mut non_common_req = inc_req;
    non_common_req.isolation = ReadIsolationMode::VersionSet {
        version_ids: vec![v2.version_id()],
        session_lower_bound: None,
        historical_pinned: false,
    };
    assert_eq!(plan_fetch_covers(&non_common_req, &graph, &index, &ret), Err(FetchPlanError::NonCommonTimeDenied));

    let mut tampered = c1_for_tamper_test(&r, &p1_c, &v1);
    tampered.tamper_record_digest_for_test();
    assert_eq!(tampered.verify_digest(), Err(CoverModelError::RecordDigestMismatch));
}

fn c1_for_tamper_test(r: &RefVersionRealm, p: &VerifiedClosurePack, v: &VersionRecord) -> CoverHierarchyRecord {
    let (_, a) = make_pack(r, 99, p.verified_bytes() - 200, 200, false, vec![]);
    let mem = compute_cover_membership_digest(r, 2, &[*p.entry()]).unwrap();
    CoverHierarchyRecord::seal(CoverHierarchyRecordInput {
        cover_id: uid(199),
        realm: *r,
        tier: CoverTier::Delta,
        pack: p.clone(),
        artifacts: a,
        covered_versions: vec![v.version_id()],
        min_authority_seq: 1,
        max_authority_seq: 1,
        covered_commits: vec![CoverCommitLink {
            commit_oid: oid(r.object_format(), 1),
            parent_oids: vec![],
            version_id: v.version_id(),
            authority_seq: 1,
        }],
        input_cover_ids: vec![],
        membership_generation: 2,
        membership_digest: mem,
        compaction_epoch: 1,
        worker_id: uid(799),
        operation_id: uid(899),
    })
    .unwrap()
}
