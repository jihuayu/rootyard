//! Bounded transitive closure and digest-stability §8 contract tests.

use super::fixtures::{MintSpec, closure_pack, default_realm, mint_node, mint_publish, oid, uid};
use rootyard::ref_store::ref_version::{
    CausalClosureError, CausalVersionLookup, MAX_CLOSURE_PACKS, MAX_CLOSURE_VERIFIED_BYTES, MAX_OBJECT_DEP_DEPTH,
    MAX_OBJECT_DEPS_PER_VERSION, RefVersionKind, VersionGraph, VersionId, VersionLookupEntry, VersionRecord,
    VersionRecordInput, compute_pack_set_digest, select_verifier_dependencies, verify_dependency_closure,
};
use rootyard::ref_store::{RefName, RefPrecondition, RefTarget};

#[test]
fn depth_fanout_edges_packs_bytes_bounds_are_exact_and_fail_closed() {
    let realm = default_realm();
    let backend = "d".repeat(64);

    // 1. Exact depth = 16 succeeds; depth = 17 fails ClosureTooLarge.
    let mut chain_nodes = Vec::new();
    let mut prev_vid: Option<VersionId> = None;
    for depth_from_leaf in 0..=17_usize {
        let node = mint_publish(
            &realm,
            &format!("refs/heads/chain-{depth_from_leaf}"),
            oid((depth_from_leaf + 1) as u8),
            i64::try_from(depth_from_leaf + 1).unwrap(),
            prev_vid.into_iter().collect(),
            vec![],
            500 + u64::try_from(depth_from_leaf).unwrap(),
        );
        prev_vid = Some(node.record.version_id());
        chain_nodes.push(node);
    }
    let vid_16 = chain_nodes[16].record.version_id();
    let vid_17 = chain_nodes[17].record.version_id();
    let mut depth_graph = VersionGraph::new();
    for node in chain_nodes {
        depth_graph.insert_active(node);
    }
    let c16 = verify_dependency_closure(&depth_graph, &realm, &vid_16).unwrap();
    assert_eq!(c16.max_depth(), MAX_OBJECT_DEP_DEPTH);
    assert_eq!(verify_dependency_closure(&depth_graph, &realm, &vid_17), Err(CausalClosureError::ClosureTooLarge));

    // 2. Direct fanout 8 & total transitive deps 64 succeed; +1 exceeds bounds cleanly.
    let mut graph64 = VersionGraph::new();
    let mut level1_vids = Vec::new();
    let mut extra_leaf_vid = None;
    let mut seed = 600_u64;
    for i in 0..8_usize {
        let mut level2_vids = Vec::new();
        for j in 0..7_usize {
            let leaf = mint_publish(&realm, &format!("refs/heads/l2-{i}-{j}"), oid(0x41), 1, vec![], vec![], seed);
            seed += 1;
            if i == 0 && j == 0 {
                let extra = mint_publish(&realm, "refs/heads/l3-extra", oid(0x42), 1, vec![], vec![], seed);
                seed += 1;
                extra_leaf_vid = Some(extra.record.version_id());
                graph64.insert_active(extra);
            }
            level2_vids.push(leaf.record.version_id());
            graph64.insert_active(leaf);
        }
        let mid = mint_publish(&realm, &format!("refs/heads/l1-{i}"), oid(0x43), 2, level2_vids, vec![], seed);
        seed += 1;
        level1_vids.push(mid.record.version_id());
        graph64.insert_active(mid);
    }
    let root64 = mint_publish(&realm, "refs/heads/root64", oid(0x44), 3, level1_vids.clone(), vec![], seed);
    seed += 1;
    let root64_vid = root64.record.version_id();
    graph64.insert_active(root64);
    assert_eq!(verify_dependency_closure(&graph64, &realm, &root64_vid).unwrap().dependencies().len(), 64);

    let overflow_mid =
        mint_publish(&realm, "refs/heads/l1-extra", oid(0x45), 2, vec![extra_leaf_vid.unwrap()], vec![], seed);
    let overflow_mid_vid = overflow_mid.record.version_id();
    graph64.insert_active(overflow_mid);
    let mut nine = level1_vids.clone();
    nine.push(overflow_mid_vid);
    assert_eq!(nine.len(), MAX_OBJECT_DEPS_PER_VERSION + 1);
    assert_eq!(select_verifier_dependencies(&[], &nine), Err(CausalClosureError::ClosureTooLarge));
    let root_rec = match graph64.lookup_version(&root64_vid) {
        VersionLookupEntry::Active(n) => n.record,
        _ => unreachable!(),
    };
    assert!(
        VersionRecord::seal(VersionRecordInput {
            version_id: overflow_mid_vid,
            realm,
            ref_name: RefName::new("refs/heads/too-wide").unwrap(),
            ref_generation: 1,
            operation_id: uid(910),
            operation_digest: root_rec.operation_digest(),
            authority_seq: 4,
            kind: RefVersionKind::Publish,
            target: RefTarget::Oid(oid(0x46)),
            base_version_id: None,
            object_deps: nine,
            pack_set_digest: compute_pack_set_digest(&[]).unwrap(),
            commit_set_id: root_rec.commit_set_id(),
        })
        .is_err()
    );

    let l1_0_vid = level1_vids[0];
    let l1_0_deps = match graph64.lookup_version(&l1_0_vid) {
        VersionLookupEntry::Active(n) => n.record.object_deps().to_vec(),
        _ => unreachable!(),
    };
    let updated_l2 =
        mint_publish(&realm, "refs/heads/l2-0-0", oid(0x41), 2, vec![extra_leaf_vid.unwrap()], vec![], seed + 1);
    let updated_l2_vid = updated_l2.record.version_id();
    let updated_l1_deps: Vec<_> =
        l1_0_deps.iter().enumerate().map(|(idx, id)| if idx == 0 { updated_l2_vid } else { *id }).collect();
    let updated_l1 = mint_publish(&realm, "refs/heads/l1-0", oid(0x43), 3, updated_l1_deps, vec![], seed + 2);
    let mut deps65_root = level1_vids;
    deps65_root[0] = updated_l1.record.version_id();
    let root65 = mint_publish(&realm, "refs/heads/root65", oid(0x44), 4, deps65_root, vec![], seed + 3);
    let root65_vid = root65.record.version_id();
    graph64.insert_active(updated_l2);
    graph64.insert_active(updated_l1);
    graph64.insert_active(root65);
    assert_eq!(verify_dependency_closure(&graph64, &realm, &root65_vid), Err(CausalClosureError::ClosureTooLarge));

    // 3. Closure packs (16 ok, 17 fail) and verified bytes boundary + BASE non-recursion.
    let packs_16: Vec<_> = (1..=u64::try_from(MAX_CLOSURE_PACKS).unwrap())
        .map(|s| closure_pack(realm.tenant_id(), 800 + s, "s3", &backend, 512))
        .collect();
    let node16 = mint_publish(&realm, "refs/heads/p16", oid(0x51), 1, vec![], packs_16, 901);
    let p16_vid = node16.record.version_id();
    let node17 = mint_publish(
        &realm,
        "refs/heads/p17",
        oid(0x52),
        2,
        vec![p16_vid],
        vec![closure_pack(realm.tenant_id(), 899, "s3", &backend, 512)],
        902,
    );
    let p17_vid = node17.record.version_id();
    let mut pgraph = VersionGraph::new();
    pgraph.insert_active(node16);
    pgraph.insert_active(node17);
    let c_packs = verify_dependency_closure(&pgraph, &realm, &p16_vid).unwrap();
    assert_eq!(c_packs.packs().len(), MAX_CLOSURE_PACKS);
    assert_eq!(c_packs.total_artifacts(), MAX_CLOSURE_PACKS * 2);
    assert_eq!(verify_dependency_closure(&pgraph, &realm, &p17_vid), Err(CausalClosureError::ClosureTooLarge));

    let half = MAX_CLOSURE_VERIFIED_BYTES / 2;
    let rem = MAX_CLOSURE_VERIFIED_BYTES - half;
    let byte_dep = mint_publish(
        &realm,
        "refs/heads/b1",
        oid(0x61),
        1,
        vec![],
        vec![closure_pack(realm.tenant_id(), 950, "s3", &backend, half)],
        903,
    );
    let byte_dep_vid = byte_dep.record.version_id();
    let retired_base = mint_publish(&realm, "refs/heads/b2", oid(0x60), 1, vec![], vec![], 903);
    let byte_ok = mint_node(MintSpec {
        realm: &realm,
        ref_name: "refs/heads/b2",
        kind: RefVersionKind::Publish,
        precondition: RefPrecondition::Present(oid(0x60)),
        base_record: Some(&retired_base.record),
        target: RefTarget::Oid(oid(0x62)),
        authority_seq: 2,
        object_deps: vec![byte_dep_vid],
        own_packs: vec![closure_pack(realm.tenant_id(), 951, "s3", &backend, rem)],
        op_seed: 904,
    });
    let byte_ok_vid = byte_ok.record.version_id();
    let byte_over = mint_node(MintSpec {
        realm: &realm,
        ref_name: "refs/heads/b3",
        kind: RefVersionKind::Publish,
        precondition: RefPrecondition::Absent,
        base_record: Some(&byte_dep.record),
        target: RefTarget::Oid(oid(0x63)),
        authority_seq: 2,
        object_deps: vec![byte_dep_vid],
        own_packs: vec![closure_pack(realm.tenant_id(), 952, "s3", &backend, rem + 1)],
        op_seed: 905,
    });
    let byte_over_vid = byte_over.record.version_id();
    let mut bgraph = VersionGraph::new();
    bgraph.mark_retired(retired_base.record.version_id());
    bgraph.insert_active(byte_dep);
    bgraph.insert_active(byte_ok);
    bgraph.insert_active(byte_over);
    assert_eq!(
        verify_dependency_closure(&bgraph, &realm, &byte_ok_vid).unwrap().total_verified_bytes(),
        MAX_CLOSURE_VERIFIED_BYTES
    );
    assert_eq!(verify_dependency_closure(&bgraph, &realm, &byte_over_vid), Err(CausalClosureError::ClosureTooLarge));
}

#[test]
fn closed_closure_is_ordered_and_digest_stable() {
    let realm = default_realm();
    let backend = "e".repeat(64);
    let shared_pack = closure_pack(realm.tenant_id(), 1001, "s3", &backend, 1024);
    let leaf = mint_publish(&realm, "refs/heads/leaf", oid(0x01), 1, vec![], vec![shared_pack.clone()], 1001);
    let leaf_vid = leaf.record.version_id();
    let left = mint_publish(
        &realm,
        "refs/heads/left",
        oid(0x02),
        2,
        vec![leaf_vid],
        vec![closure_pack(realm.tenant_id(), 1002, "s3", &backend, 2048)],
        1002,
    );
    let right = mint_publish(&realm, "refs/heads/right", oid(0x03), 3, vec![leaf_vid], vec![shared_pack], 1003);
    let left_vid = left.record.version_id();
    let right_vid = right.record.version_id();
    let top_a = mint_publish(&realm, "refs/heads/top", oid(0x04), 4, vec![left_vid, right_vid], vec![], 1004);
    let top_b = mint_publish(&realm, "refs/heads/top", oid(0x04), 4, vec![right_vid, left_vid], vec![], 1004);
    assert_eq!(top_a.record.record_digest(), top_b.record.record_digest());

    let top_vid = top_a.record.version_id();
    let mut g = VersionGraph::new();
    g.insert_active(leaf);
    g.insert_active(left);
    g.insert_active(right);
    g.insert_active(top_a);
    let c1 = verify_dependency_closure(&g, &realm, &top_vid).unwrap();
    g.insert_active(top_b);
    let c2 = verify_dependency_closure(&g, &realm, &top_vid).unwrap();
    assert_eq!(c1, c2);
    assert_eq!(c1.dependencies().len(), 3);
    assert_eq!(c1.packs().len(), 2);
    assert_eq!(c1.total_verified_bytes(), 1024 + 2048);
    assert_eq!(c1.closure_digest(), c2.closure_digest());
}
