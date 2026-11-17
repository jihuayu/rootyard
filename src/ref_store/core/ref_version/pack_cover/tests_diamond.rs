//! Regression tests for diamond delta-base DAG memoization and bounded expansion work (Issue #184).
use super::super::closure::{CausalVersionNode, VersionGraph};
use super::super::contract::RefVersionRealm;
use super::super::pack_set::{PackSetEntry, VerifiedClosurePack};
use super::super::read_mode::ReadConsumer;
use super::super::record::RefHead;
use super::auth::{FetchPlanError, ReadIsolationMode, RefVisibilityPolicy, StrongSnapshotCut};
use super::model::{
    CoverArtifactPair, CoverCommitLink, CoverHierarchyIndex, CoverTier, compute_cover_membership_digest,
};
use super::planner::{FetchPlanOutcome, FetchPlanRequest, WantTarget, plan_fetch_covers};
use super::retention_class::{CoverRetentionHold, RetentionClassificationIndex};
use super::tests::{default_auth, make_pack, mint_version, oid, realm, seal_test_cover, uid};
use super::verifier::verify_fetch_plan_closure;
use crate::blob_store::BlobLocator;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::types::{GitObjectFormat, GitOid, RefName};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

fn uniq_pack(r: &RefVersionRealm, id: u128, bases: Vec<Uuid>) -> (VerifiedClosurePack, CoverArtifactPair) {
    let entry = PackSetEntry::new(
        uid(1_000_000 + id),
        uid(2_000_000 + id),
        RequestDigest::of("uniq-art", &[&id.to_be_bytes()]),
    )
    .unwrap();
    let vpack =
        VerifiedClosurePack::new(entry, r.tenant_id(), r.repository_id(), "s3", hex::encode([0xab; 32]), 1300, 2)
            .unwrap();
    let mut sha = [0_u8; 32];
    sha[..16].copy_from_slice(&id.to_be_bytes());
    let sha_p = hex::encode(sha);
    sha[31] ^= 1;
    let sha_i = hex::encode(sha);
    let pack_loc =
        BlobLocator::new(r.tenant_id(), r.repository_id(), 1, uid(3_000_000 + id), "packs", &sha_p, 1200).unwrap();
    let idx_loc =
        BlobLocator::new(r.tenant_id(), r.repository_id(), 1, uid(4_000_000 + id), "packs", &sha_i, 100).unwrap();
    let mut stem_raw = [0_u8; 20];
    stem_raw[..16].copy_from_slice(&id.to_be_bytes());
    let artifacts = CoverArtifactPair {
        pack_stem: format!("pack-{}", hex::encode(stem_raw)),
        pack_locator: pack_loc,
        idx_locator: idx_loc,
        is_thin_pack: !bases.is_empty(),
        delta_base_cover_ids: bases,
    };
    (vpack, artifacts)
}

#[test]
fn planner_expands_diamond_delta_dag_linearly_and_bounds_delta_work() {
    let r = realm(GitObjectFormat::Sha1);
    let main_ref = RefName::new("refs/heads/main").unwrap();
    let tip = oid(GitObjectFormat::Sha1, 1);
    let (p0, _) = make_pack(&r, 250, 1024, 100, false, vec![]);
    let (v1, p0_c) = mint_version(&r, "refs/heads/main", 1, None, tip, p0, vec![]);
    let mut graph = VersionGraph::new();
    graph.insert_active(CausalVersionNode { record: v1.clone(), own_packs: vec![p0_c] });

    let dummy = |id: u128| {
        let mut raw = [0_u8; 20];
        raw[..16].copy_from_slice(&id.to_be_bytes());
        GitOid::parse(GitObjectFormat::Sha1, &hex::encode(raw)).unwrap()
    };
    let add_many = |idx: &mut CoverHierarchyIndex,
                    ents: &mut Vec<_>,
                    id: u128,
                    commits: Vec<GitOid>,
                    bases: Vec<Uuid>,
                    holds: &mut Vec<Uuid>| {
        let (pk, art) = uniq_pack(&r, id, bases);
        ents.push(*pk.entry());
        let g = idx.membership_generation() + 1;
        let m = compute_cover_membership_digest(&r, g, ents).unwrap();
        let links = commits
            .into_iter()
            .map(|commit_oid| CoverCommitLink {
                commit_oid,
                parent_oids: vec![],
                version_id: v1.version_id(),
                authority_seq: 1,
            })
            .collect();
        let cov =
            seal_test_cover(&r, (id, g, (1, 1), m), CoverTier::Delta, (pk, art), vec![v1.version_id()], links, vec![]);
        holds.push(cov.cover_id());
        idx.register_leaf_cover(cov, m).unwrap();
    };
    let add = |idx: &mut CoverHierarchyIndex,
               ents: &mut Vec<_>,
               id: u128,
               commit: GitOid,
               bases: Vec<Uuid>,
               holds: &mut Vec<Uuid>| {
        add_many(idx, ents, id, vec![commit], bases, holds);
    };
    let run_req = |idx: &CoverHierarchyIndex, holds: Vec<Uuid>| {
        let mut ret = RetentionClassificationIndex::new();
        ret.add_hold(CoverRetentionHold::ActiveRefHead {
            ref_name: main_ref.clone(),
            version_id: v1.version_id(),
            cover_ids: holds,
        });
        let cut = StrongSnapshotCut {
            authority_seq: 1,
            snapshot_digest: RequestDigest::of("dag", &[b"cut"]),
            membership_digest: idx.membership_digest(),
            heads: BTreeMap::from([(main_ref.clone(), RefHead::from_committed(&v1).unwrap())]),
        };
        let mut req =
            FetchPlanRequest::new(ReadConsumer::SmartHttpFetch, r, default_auth(&r), ReadIsolationMode::StrongSnapshot);
        req.strong_cut = Some(cut.clone());
        req.wants = vec![WantTarget::Ref { ref_name: main_ref.clone() }];
        req.allow_strong_fallback = false;
        (plan_fetch_covers(&req, &graph, idx, &ret), cut, ret, req)
    };

    // 1. Valid 3-layer 3-wide diamond (14 covers <= 16 pack bound) succeeds and verifies.
    let mem0 = compute_cover_membership_digest(&r, 1, &[]).unwrap();
    let (mut idx, mut ents, mut holds) = (CoverHierarchyIndex::new(r, mem0).unwrap(), Vec::new(), Vec::new());
    add(&mut idx, &mut ents, 20_000, dummy(20_000), vec![], &mut holds);
    let mut prev = vec![uid(20_000)];
    for layer in 0..3_u128 {
        let mut mid = Vec::new();
        for k in 0..3_u128 {
            let id = 20_010 + layer * 10 + k;
            add(&mut idx, &mut ents, id, dummy(id), prev.clone(), &mut holds);
            mid.push(uid(id));
        }
        let j = 20_050 + layer;
        add(&mut idx, &mut ents, j, dummy(j), mid, &mut holds);
        prev = vec![uid(j)];
    }
    add(&mut idx, &mut ents, 20_099, tip, prev, &mut holds);
    let (res, cut, ret, req) = run_req(&idx, holds);
    let FetchPlanOutcome::Planned(plan) = res.unwrap() else {
        panic!("expected diamond plan");
    };
    assert_eq!(plan.selected_covers.len(), 14);
    assert!(verify_fetch_plan_closure(&plan, req.consumer, &req.auth, Some(&cut), &graph, &idx, &ret).is_ok());

    // 2. 28-layer binary diamond (2^28 naive paths) finishes linearly via memoization and fails closed.
    let (mut d_idx, mut d_ents, mut d_holds) = (CoverHierarchyIndex::new(r, mem0).unwrap(), Vec::new(), Vec::new());
    add(&mut d_idx, &mut d_ents, 30_000, dummy(30_000), vec![], &mut d_holds);
    let mut prev2 = vec![uid(30_000)];
    for layer in 0..28_u128 {
        let (a, b, j) = (31_000 + layer * 3, 31_001 + layer * 3, 31_002 + layer * 3);
        add(&mut d_idx, &mut d_ents, a, dummy(a), prev2.clone(), &mut d_holds);
        add(&mut d_idx, &mut d_ents, b, dummy(b), prev2, &mut d_holds);
        add(&mut d_idx, &mut d_ents, j, dummy(j), vec![uid(a), uid(b)], &mut d_holds);
        prev2 = vec![uid(j)];
    }
    add(&mut d_idx, &mut d_ents, 39_999, tip, prev2, &mut d_holds);
    let t0 = Instant::now();
    assert_eq!(run_req(&d_idx, d_holds).0, Err(FetchPlanError::ClosureBoundsExceeded));
    assert!(t0.elapsed() < Duration::from_secs(2));

    // 3. Delta fanout within MAX_DELTA_BASES (8 bases x 512 commits, 20 leaves -> 28 covers << 4096) exhausts work_steps in expand_delta_bases.
    let (mut b_idx, mut b_ents, mut b_holds) = (CoverHierarchyIndex::new(r, mem0).unwrap(), Vec::new(), Vec::new());
    let mut bases = Vec::with_capacity(8);
    for b in 0..8_u128 {
        let commits: Vec<_> = (0..512_u128).map(|i| dummy(100_000 + b * 1000 + i)).collect();
        add_many(&mut b_idx, &mut b_ents, 40_000 + b, commits, vec![], &mut b_holds);
        bases.push(uid(40_000 + b));
    }
    for k in 0..20_u128 {
        add(&mut b_idx, &mut b_ents, 41_000 + k, tip, bases.clone(), &mut b_holds);
    }
    assert_eq!(run_req(&b_idx, b_holds).0, Err(FetchPlanError::ClosureBoundsExceeded));
}

#[test]
fn planner_bounds_work_steps_on_shared_unauthorized_delta_base() {
    let r = realm(GitObjectFormat::Sha1);
    let main_ref = RefName::new("refs/heads/main").unwrap();
    let pub_ref = RefName::new("refs/heads/pub").unwrap();
    let tip = oid(GitObjectFormat::Sha1, 1);
    let hidden_oid = oid(GitObjectFormat::Sha1, 0xff);
    let dummy = |i: u128| {
        let mut raw = [0_u8; 20];
        raw[..16].copy_from_slice(&i.to_be_bytes());
        GitOid::parse(GitObjectFormat::Sha1, &hex::encode(raw)).unwrap()
    };
    let (p0, _) = make_pack(&r, 250, 1024, 100, false, vec![]);
    let (v1, p0_c) = mint_version(&r, "refs/heads/main", 4, None, tip, p0, vec![]);
    let (p1, _) = make_pack(&r, 251, 1024, 100, false, vec![]);
    let (v_pub, p1_c) = mint_version(&r, "refs/heads/pub", 2, None, dummy(2_046), p1, vec![]);
    let (p2, _) = make_pack(&r, 252, 1024, 100, false, vec![]);
    let (v_sec, p2_c) = mint_version(&r, "refs/hidden/secret", 3, None, hidden_oid, p2, vec![]);
    let mut graph = VersionGraph::new();
    for (record, pk) in [(&v1, p0_c), (&v_pub, p1_c), (&v_sec, p2_c)] {
        graph.insert_active(CausalVersionNode { record: record.clone(), own_packs: vec![pk] });
    }

    let mem0 = compute_cover_membership_digest(&r, 1, &[]).unwrap();
    let (mut idx, mut ents, mut holds) = (CoverHierarchyIndex::new(r, mem0).unwrap(), Vec::new(), Vec::new());
    let mut unauth_links: Vec<_> = (0..2_047_u128)
        .map(|i| CoverCommitLink {
            commit_oid: dummy(i),
            parent_oids: if i > 0 { vec![dummy(i - 1)] } else { vec![] },
            version_id: v_pub.version_id(),
            authority_seq: 2,
        })
        .collect();
    unauth_links.push(CoverCommitLink {
        commit_oid: hidden_oid,
        parent_oids: vec![],
        version_id: v_sec.version_id(),
        authority_seq: 3,
    });
    let (ub_pk, ub_art) = uniq_pack(&r, 50_000, vec![]);
    ents.push(*ub_pk.entry());
    let g1 = idx.membership_generation() + 1;
    let m1 = compute_cover_membership_digest(&r, g1, &ents).unwrap();
    let ub = seal_test_cover(
        &r,
        (50_000, g1, (2, 3), m1),
        CoverTier::Delta,
        (ub_pk, ub_art),
        vec![v_pub.version_id(), v_sec.version_id()],
        unauth_links,
        vec![],
    );
    holds.push(ub.cover_id());
    idx.register_leaf_cover(ub, m1).unwrap();

    for k in 0..35_u128 {
        let (rk_pk, rk_art) = uniq_pack(&r, 51_000 + k, vec![uid(50_000)]);
        ents.push(*rk_pk.entry());
        let g = idx.membership_generation() + 1;
        let m = compute_cover_membership_digest(&r, g, &ents).unwrap();
        let lk =
            CoverCommitLink { commit_oid: tip, parent_oids: vec![], version_id: v1.version_id(), authority_seq: 4 };
        let cov = seal_test_cover(
            &r,
            (51_000 + k, g, (4, 4), m),
            CoverTier::Delta,
            (rk_pk, rk_art),
            vec![v1.version_id()],
            vec![lk],
            vec![],
        );
        holds.push(cov.cover_id());
        idx.register_leaf_cover(cov, m).unwrap();
        if k == 0 {
            // Single root within budget fails closed as UnauthorizedObjectScope, not Bypass.
            let mut ret1 = RetentionClassificationIndex::new();
            ret1.add_hold(CoverRetentionHold::ActiveRefHead {
                ref_name: main_ref.clone(),
                version_id: v1.version_id(),
                cover_ids: holds.clone(),
            });
            let mut auth = default_auth(&r);
            auth.visibility = RefVisibilityPolicy::AllowOnly([main_ref.clone(), pub_ref.clone()].into_iter().collect());
            let heads = BTreeMap::from([
                (main_ref.clone(), RefHead::from_committed(&v1).unwrap()),
                (pub_ref.clone(), RefHead::from_committed(&v_pub).unwrap()),
            ]);
            let mut req1 =
                FetchPlanRequest::new(ReadConsumer::SmartHttpFetch, r, auth, ReadIsolationMode::StrongSnapshot);
            req1.strong_cut = Some(StrongSnapshotCut {
                authority_seq: 4,
                snapshot_digest: RequestDigest::of("u1", &[b"c"]),
                membership_digest: idx.membership_digest(),
                heads,
            });
            req1.wants = vec![WantTarget::Ref { ref_name: main_ref.clone() }];
            req1.allow_strong_fallback = false;
            assert_eq!(plan_fetch_covers(&req1, &graph, &idx, &ret1), Err(FetchPlanError::UnauthorizedObjectScope));
        }
    }

    let mut ret = RetentionClassificationIndex::new();
    ret.add_hold(CoverRetentionHold::ActiveRefHead {
        ref_name: main_ref.clone(),
        version_id: v1.version_id(),
        cover_ids: holds,
    });
    let mut auth = default_auth(&r);
    auth.visibility = RefVisibilityPolicy::AllowOnly([main_ref.clone(), pub_ref.clone()].into_iter().collect());
    let heads = BTreeMap::from([
        (main_ref.clone(), RefHead::from_committed(&v1).unwrap()),
        (pub_ref, RefHead::from_committed(&v_pub).unwrap()),
    ]);
    let mut req = FetchPlanRequest::new(ReadConsumer::SmartHttpFetch, r, auth, ReadIsolationMode::StrongSnapshot);
    req.strong_cut = Some(StrongSnapshotCut {
        authority_seq: 4,
        snapshot_digest: RequestDigest::of("u35", &[b"c"]),
        membership_digest: idx.membership_digest(),
        heads,
    });
    req.wants = vec![WantTarget::Ref { ref_name: main_ref }];
    req.allow_strong_fallback = false;
    assert_eq!(plan_fetch_covers(&req, &graph, &idx, &ret), Err(FetchPlanError::ClosureBoundsExceeded));
}
