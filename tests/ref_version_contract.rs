//! Pure verifiable contract suite for `rootyard::ref_store::ref_version` (§8).

#[path = "ref_version_contract_support/closure_bounds_cases.rs"]
mod closure_bounds_cases;
#[path = "ref_version_contract_support/digest_terminal_cases.rs"]
mod digest_terminal_cases;
#[path = "ref_version_contract_support/extra_cases.rs"]
mod extra_cases;
#[path = "ref_version_contract_support/fixtures.rs"]
mod fixtures;

use fixtures::{MintSpec, default_realm, mint_node, mint_publish, oid, op_input, planned_pack, uid};
use rootyard::ref_store::ref_version::{
    AuthorityKind, BaseCoherenceError, BaseRequestSelector, CausalClosureError, CausalRejectCode, CausalVersionNode,
    CommitSetHead, CommitSetInput, CommitSetVersionEntry, RefHead, RefVersionCodecError, RefVersionIntent,
    RefVersionKind, RefVersionRealm, VersionGraph, VersionRecord, VersionRecordInput, compute_commit_set_id,
    compute_pack_set_digest, derive_candidate_version_id, operation_digest, select_verifier_dependencies,
    verify_base_coherence, verify_dependency_closure,
};
use rootyard::ref_store::{GitObjectFormat, RefName, RefPrecondition, RefTarget};
use std::collections::BTreeSet;

fn intent(
    name: &str,
    kind: RefVersionKind,
    pre: RefPrecondition,
    base: BaseRequestSelector,
    target: RefTarget,
) -> RefVersionIntent {
    RefVersionIntent::new(RefName::new(name).unwrap(), kind, pre, base, target)
}

#[test]
fn version_id_binds_tenant_repo_history_authority_ref_operation() {
    let base_realm = default_realm();
    let main = RefName::new("refs/heads/main").unwrap();
    let topic = RefName::new("refs/heads/topic").unwrap();
    let base_intent = vec![intent(
        "refs/heads/main",
        RefVersionKind::Publish,
        RefPrecondition::Absent,
        BaseRequestSelector::ExplicitAbsent,
        RefTarget::Oid(oid(0x11)),
    )];
    let base_op = op_input(base_realm, 1, base_intent.clone(), vec![planned_pack(1, 512)]);
    let base_od = operation_digest(&base_op).unwrap();
    let base_vid = derive_candidate_version_id(&base_op, base_od, &main, None).unwrap();

    let mut distinct = BTreeSet::new();
    distinct.insert(base_vid);

    let alt_realms = [
        RefVersionRealm::new(uid(9), uid(2), uid(3), AuthorityKind::Pg, 1, 0, 1, GitObjectFormat::Sha1),
        RefVersionRealm::new(uid(1), uid(9), uid(3), AuthorityKind::Pg, 1, 0, 1, GitObjectFormat::Sha1),
        RefVersionRealm::new(uid(1), uid(2), uid(9), AuthorityKind::Pg, 1, 0, 1, GitObjectFormat::Sha1),
        RefVersionRealm::new(uid(1), uid(2), uid(3), AuthorityKind::Raft, 1, 0, 1, GitObjectFormat::Sha1),
        RefVersionRealm::new(uid(1), uid(2), uid(3), AuthorityKind::Pg, 2, 0, 1, GitObjectFormat::Sha1),
        RefVersionRealm::new(uid(1), uid(2), uid(3), AuthorityKind::Raft, 1, 7, 1, GitObjectFormat::Sha1),
        RefVersionRealm::new(uid(1), uid(2), uid(3), AuthorityKind::Pg, 1, 0, 2, GitObjectFormat::Sha1),
    ];
    for realm in alt_realms {
        let op = op_input(realm, 1, base_intent.clone(), vec![planned_pack(1, 512)]);
        let od = operation_digest(&op).unwrap();
        assert!(distinct.insert(derive_candidate_version_id(&op, od, &main, None).unwrap()));
    }

    let two_refs = op_input(
        base_realm,
        1,
        vec![
            base_intent[0].clone(),
            intent(
                "refs/heads/topic",
                RefVersionKind::Publish,
                RefPrecondition::Absent,
                BaseRequestSelector::ExplicitAbsent,
                RefTarget::Oid(oid(0x22)),
            ),
        ],
        vec![],
    );
    let two_od = operation_digest(&two_refs).unwrap();
    assert!(distinct.insert(derive_candidate_version_id(&two_refs, two_od, &topic, None).unwrap()));

    let op2 = op_input(base_realm, 2, base_intent, vec![planned_pack(1, 512)]);
    let od2 = operation_digest(&op2).unwrap();
    assert!(distinct.insert(derive_candidate_version_id(&op2, od2, &main, None).unwrap()));

    let gen2_op = op_input(
        base_realm,
        1,
        vec![intent(
            "refs/heads/main",
            RefVersionKind::Publish,
            RefPrecondition::Absent,
            BaseRequestSelector::Present(base_vid),
            RefTarget::Oid(oid(0x11)),
        )],
        vec![],
    );
    let gen2_od = operation_digest(&gen2_op).unwrap();
    assert!(distinct.insert(derive_candidate_version_id(&gen2_op, gen2_od, &main, Some(1)).unwrap()));
}

#[test]
fn same_oid_new_generation_is_not_aba() {
    let realm = default_realm();
    let v1 = mint_publish(&realm, "refs/heads/main", oid(0x11), 1, vec![], vec![], 1);
    let h1 = RefHead::from_committed(&v1.record).unwrap();
    let del = mint_node(MintSpec {
        realm: &realm,
        ref_name: "refs/heads/main",
        kind: RefVersionKind::Delete,
        precondition: RefPrecondition::Present(oid(0x11)),
        base_record: Some(&v1.record),
        target: RefTarget::Delete,
        authority_seq: 2,
        object_deps: vec![],
        own_packs: vec![],
        op_seed: 2,
    });
    let h2 = RefHead::from_committed(&del.record).unwrap();
    assert!(h2.is_tombstone());
    assert_eq!(h2.ref_generation(), 2);

    let recreate_intent = intent(
        "refs/heads/main",
        RefVersionKind::Publish,
        RefPrecondition::Absent,
        BaseRequestSelector::Present(del.record.version_id()),
        RefTarget::Oid(oid(0x11)),
    );
    assert_eq!(verify_base_coherence(&realm, &recreate_intent, Some(&h2)), Ok(3));
    let v3 = mint_node(MintSpec {
        realm: &realm,
        ref_name: "refs/heads/main",
        kind: RefVersionKind::Publish,
        precondition: RefPrecondition::Absent,
        base_record: Some(&del.record),
        target: RefTarget::Oid(oid(0x11)),
        authority_seq: 3,
        object_deps: vec![],
        own_packs: vec![],
        op_seed: 3,
    });
    let h3 = RefHead::from_committed(&v3.record).unwrap();
    assert_ne!(h1.version_id(), h3.version_id());
    assert_eq!(v1.record.target(), v3.record.target());

    let stale_req = intent(
        "refs/heads/main",
        RefVersionKind::Publish,
        RefPrecondition::Present(oid(0x11)),
        BaseRequestSelector::Present(v1.record.version_id()),
        RefTarget::Oid(oid(0x22)),
    );
    assert_eq!(
        verify_base_coherence(&realm, &stale_req, Some(&h3)),
        Err(BaseCoherenceError::Rejected(CausalRejectCode::BaseVersionMismatch))
    );
}

#[test]
fn tombstone_generation_survives_delete() {
    let realm = default_realm();
    let v1 = mint_publish(&realm, "refs/heads/feat", oid(0x55), 1, vec![], vec![], 10);
    let del = mint_node(MintSpec {
        realm: &realm,
        ref_name: "refs/heads/feat",
        kind: RefVersionKind::Delete,
        precondition: RefPrecondition::Present(oid(0x55)),
        base_record: Some(&v1.record),
        target: RefTarget::Delete,
        authority_seq: 2,
        object_deps: vec![],
        own_packs: vec![],
        op_seed: 11,
    });
    let tomb_head = RefHead::from_committed(&del.record).unwrap();
    assert_eq!(tomb_head.target(), None);
    assert_eq!(tomb_head.ref_generation(), 2);

    let bad_absent = intent(
        "refs/heads/feat",
        RefVersionKind::Publish,
        RefPrecondition::Absent,
        BaseRequestSelector::ExplicitAbsent,
        RefTarget::Oid(oid(0x66)),
    );
    assert_eq!(
        verify_base_coherence(&realm, &bad_absent, Some(&tomb_head)),
        Err(BaseCoherenceError::Rejected(CausalRejectCode::BaseVersionMismatch))
    );
    let bad_old = intent(
        "refs/heads/feat",
        RefVersionKind::Publish,
        RefPrecondition::Present(oid(0x55)),
        BaseRequestSelector::Present(tomb_head.version_id()),
        RefTarget::Oid(oid(0x66)),
    );
    assert_eq!(
        verify_base_coherence(&realm, &bad_old, Some(&tomb_head)),
        Err(BaseCoherenceError::Rejected(CausalRejectCode::OldOidMismatch))
    );
}

#[test]
fn client_supplied_dependency_is_not_authority() {
    let realm = default_realm();
    let forged = mint_publish(&realm, "refs/heads/forged", oid(0x01), 1, vec![], vec![], 20).record.version_id();
    let real_dep = mint_publish(&realm, "refs/heads/real", oid(0x02), 2, vec![], vec![], 21);
    let real_vid = real_dep.record.version_id();
    let authoritative_deps = select_verifier_dependencies(&[forged], &[real_vid]).unwrap();
    assert_eq!(authoritative_deps, vec![real_vid]);

    let child = mint_publish(&realm, "refs/heads/child", oid(0x03), 3, authoritative_deps, vec![], 22);
    let child_vid = child.record.version_id();
    let mut graph = VersionGraph::new();
    graph.insert_active(real_dep);
    graph.insert_active(child);
    let verified = verify_dependency_closure(&graph, &realm, &child_vid).unwrap();
    assert_eq!(verified.dependencies().len(), 1);
    assert_eq!(verified.dependencies()[0].version_id(), real_vid);
}

#[test]
fn base_must_be_exact_current_head() {
    let realm = default_realm();
    let legacy = intent(
        "refs/heads/main",
        RefVersionKind::Publish,
        RefPrecondition::Absent,
        BaseRequestSelector::LegacyNotSupplied,
        RefTarget::Oid(oid(0x11)),
    );
    assert_eq!(verify_base_coherence(&realm, &legacy, None), Err(BaseCoherenceError::LegacyUnsupported));

    let v1 = mint_publish(&realm, "refs/heads/main", oid(0x11), 1, vec![], vec![], 30);
    let h1 = RefHead::from_committed(&v1.record).unwrap();
    let v2 = mint_node(MintSpec {
        realm: &realm,
        ref_name: "refs/heads/main",
        kind: RefVersionKind::Publish,
        precondition: RefPrecondition::Present(oid(0x11)),
        base_record: Some(&v1.record),
        target: RefTarget::Oid(oid(0x22)),
        authority_seq: 2,
        object_deps: vec![],
        own_packs: vec![],
        op_seed: 31,
    });
    let h2 = RefHead::from_committed(&v2.record).unwrap();

    let wrong_base = intent(
        "refs/heads/main",
        RefVersionKind::Publish,
        RefPrecondition::Present(oid(0x22)),
        BaseRequestSelector::Present(h1.version_id()),
        RefTarget::Oid(oid(0x33)),
    );
    assert_eq!(
        verify_base_coherence(&realm, &wrong_base, Some(&h2)),
        Err(BaseCoherenceError::Rejected(CausalRejectCode::BaseVersionMismatch))
    );

    let wrong_oid = intent(
        "refs/heads/main",
        RefVersionKind::Publish,
        RefPrecondition::Present(oid(0x11)),
        BaseRequestSelector::Present(h2.version_id()),
        RefTarget::Oid(oid(0x33)),
    );
    assert_eq!(
        verify_base_coherence(&realm, &wrong_oid, Some(&h2)),
        Err(BaseCoherenceError::Rejected(CausalRejectCode::OldOidMismatch))
    );

    let bad_repack = intent(
        "refs/heads/main",
        RefVersionKind::Repack,
        RefPrecondition::Present(oid(0x22)),
        BaseRequestSelector::Present(h2.version_id()),
        RefTarget::Oid(oid(0x33)),
    );
    assert_eq!(
        verify_base_coherence(&realm, &bad_repack, Some(&h2)),
        Err(BaseCoherenceError::Rejected(CausalRejectCode::OldOidMismatch))
    );
    let ok_repack = intent(
        "refs/heads/main",
        RefVersionKind::Repack,
        RefPrecondition::Present(oid(0x22)),
        BaseRequestSelector::Present(h2.version_id()),
        RefTarget::Oid(oid(0x22)),
    );
    assert_eq!(verify_base_coherence(&realm, &ok_repack, Some(&h2)), Ok(3));
}

#[test]
fn dependency_cycle_self_same_commit_set_and_cross_realm_are_refused() {
    let realm = default_realm();
    let a = mint_publish(&realm, "refs/heads/a", oid(0x11), 5, vec![], vec![], 40);
    let vid_a = a.record.version_id();

    assert_eq!(
        VersionRecord::seal(VersionRecordInput {
            version_id: vid_a,
            realm,
            ref_name: a.record.ref_name().clone(),
            ref_generation: 1,
            operation_id: a.record.operation_id(),
            operation_digest: a.record.operation_digest(),
            authority_seq: 5,
            kind: RefVersionKind::Publish,
            target: RefTarget::Oid(oid(0x11)),
            base_version_id: None,
            object_deps: vec![vid_a],
            pack_set_digest: a.record.pack_set_digest(),
            commit_set_id: a.record.commit_set_id(),
        }),
        Err(RefVersionCodecError::SelfDependency)
    );

    let sibling_same_seq = mint_publish(&realm, "refs/heads/b", oid(0x12), 5, vec![vid_a], vec![], 41);
    let same_seq_vid = sibling_same_seq.record.version_id();
    let mut graph = VersionGraph::new();
    graph.insert_active(a);
    graph.insert_active(sibling_same_seq);
    assert_eq!(
        verify_dependency_closure(&graph, &realm, &same_seq_vid),
        Err(CausalClosureError::DependencyCycleIntegrity)
    );

    let cyc1 = RefName::new("refs/heads/cyc1").unwrap();
    let op_x = op_input(
        realm,
        42,
        vec![intent(
            "refs/heads/cyc1",
            RefVersionKind::Publish,
            RefPrecondition::Absent,
            BaseRequestSelector::ExplicitAbsent,
            RefTarget::Oid(oid(0x21)),
        )],
        vec![],
    );
    let od_x = operation_digest(&op_x).unwrap();
    let vid_x = derive_candidate_version_id(&op_x, od_x, &cyc1, None).unwrap();
    let y_seed = mint_publish(&realm, "refs/heads/cyc2", oid(0x22), 9, vec![vid_x], vec![], 43);
    let vid_y = y_seed.record.version_id();
    let cs_x = compute_commit_set_id(&CommitSetInput::new(
        realm,
        10,
        op_x.operation_id(),
        od_x,
        vec![CommitSetVersionEntry::new(cyc1.clone(), vid_x, RefVersionKind::Publish, RefTarget::Oid(oid(0x21)))],
        CommitSetHead::Absent,
    ))
    .unwrap();
    let rec_x = VersionRecord::seal(VersionRecordInput {
        version_id: vid_x,
        realm,
        ref_name: cyc1,
        ref_generation: 1,
        operation_id: op_x.operation_id(),
        operation_digest: od_x,
        authority_seq: 10,
        kind: RefVersionKind::Publish,
        target: RefTarget::Oid(oid(0x21)),
        base_version_id: None,
        object_deps: vec![vid_y],
        pack_set_digest: compute_pack_set_digest(&[]).unwrap(),
        commit_set_id: cs_x,
    })
    .unwrap();
    graph.insert_active(y_seed);
    graph.insert_active(CausalVersionNode { record: rec_x, own_packs: vec![] });
    assert_eq!(verify_dependency_closure(&graph, &realm, &vid_x), Err(CausalClosureError::DependencyCycleIntegrity));

    let other_realm = RefVersionRealm::new(uid(1), uid(2), uid(99), AuthorityKind::Pg, 1, 0, 1, GitObjectFormat::Sha1);
    let foreign = mint_publish(&other_realm, "refs/heads/other", oid(0x31), 1, vec![], vec![], 44);
    let foreign_vid = foreign.record.version_id();
    let bad_link = mint_publish(&realm, "refs/heads/local", oid(0x32), 11, vec![foreign_vid], vec![], 45);
    let bad_link_vid = bad_link.record.version_id();
    graph.insert_active(foreign);
    graph.insert_active(bad_link);
    assert_eq!(
        verify_dependency_closure(&graph, &realm, &bad_link_vid),
        Err(CausalClosureError::DependencyRealmMismatch)
    );
}
