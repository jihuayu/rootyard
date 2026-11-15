//! CommitSet, RecordDigest, PackSetDigest, OperationDigest and Terminal §8 contract tests.

use super::fixtures::{MintSpec, default_realm, mint_node, mint_publish, oid, op_input, planned_pack, uid};
use rootyard::ref_store::ref_version::{
    BaseRequestSelector, CausalClosureError, CausalRejectCode, CommitSetHead, CommitSetInput, CommitSetVersionEntry,
    PackSetEntry, RefVersionCodecError, RefVersionIntent, RefVersionKind, VersionGraph, VersionLookupEntry,
    VersionRecord, VersionRecordInput, VersionResultEntry, VersionResultOutcome, VersionTerminalInput,
    VersionTerminalKind, compute_commit_set_id, compute_pack_set_digest, derive_candidate_version_id, encode_terminal,
    encode_terminal_with_commit_set, ensure_immutable_record, operation_digest, verify_dependency_closure,
};
use rootyard::ref_store::{RefName, RefPrecondition, RefTarget, RequestDigest};
use uuid::Uuid;

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
fn mixed_publish_delete_commit_set_is_canonical() {
    let realm = default_realm();
    let base_node = mint_publish(&realm, "refs/heads/main", oid(0x11), 1, vec![], vec![], 1100);
    let v_main = base_node.record.version_id();
    let v_topic = mint_node(MintSpec {
        realm: &realm,
        ref_name: "refs/heads/topic",
        kind: RefVersionKind::Delete,
        precondition: RefPrecondition::Present(oid(0x22)),
        base_record: Some(&base_node.record),
        target: RefTarget::Delete,
        authority_seq: 2,
        object_deps: vec![],
        own_packs: vec![],
        op_seed: 1101,
    })
    .record
    .version_id();
    let e_main = CommitSetVersionEntry::new(
        RefName::new("refs/heads/main").unwrap(),
        v_main,
        RefVersionKind::Publish,
        RefTarget::Oid(oid(0x11)),
    );
    let e_topic = CommitSetVersionEntry::new(
        RefName::new("refs/heads/topic").unwrap(),
        v_topic,
        RefVersionKind::Delete,
        RefTarget::Delete,
    );
    let head =
        CommitSetHead::Present { ref_name: RefName::new("refs/heads/main").unwrap(), target_oid: Some(oid(0x11)) };
    let cs1 = compute_commit_set_id(&CommitSetInput::new(
        realm,
        5,
        uid(1100),
        base_node.record.operation_digest(),
        vec![e_main.clone(), e_topic.clone()],
        head.clone(),
    ))
    .unwrap();
    let cs2 = compute_commit_set_id(&CommitSetInput::new(
        realm,
        5,
        uid(1100),
        base_node.record.operation_digest(),
        vec![e_topic, e_main.clone()],
        head.clone(),
    ))
    .unwrap();
    assert_eq!(cs1, cs2);

    let e_repack = CommitSetVersionEntry::new(
        RefName::new("refs/heads/repack").unwrap(),
        v_main,
        RefVersionKind::Repack,
        RefTarget::Oid(oid(0x11)),
    );
    assert!(
        compute_commit_set_id(&CommitSetInput::new(
            realm,
            5,
            uid(1100),
            base_node.record.operation_digest(),
            vec![e_main, e_repack],
            head,
        ))
        .is_err()
    );
}

#[test]
fn per_version_kind_is_not_inferred_from_target() {
    let realm = default_realm();
    let a = mint_publish(&realm, "refs/heads/main", oid(0x44), 1, vec![], vec![], 1200);
    let b = mint_node(MintSpec {
        realm: &realm,
        ref_name: "refs/heads/main",
        kind: RefVersionKind::Repack,
        precondition: RefPrecondition::Present(oid(0x44)),
        base_record: Some(&a.record),
        target: RefTarget::Oid(oid(0x44)),
        authority_seq: 1,
        object_deps: vec![],
        own_packs: vec![],
        op_seed: 1200,
    });
    assert_ne!(a.record.operation_digest(), b.record.operation_digest());
    assert_ne!(a.record.commit_set_id(), b.record.commit_set_id());
    assert_ne!(a.record.record_digest(), b.record.record_digest());
}

#[test]
fn version_id_record_binding_is_immutable() {
    let realm = default_realm();
    let node = mint_publish(&realm, "refs/heads/main", oid(0x77), 4, vec![], vec![], 1300);
    assert_eq!(ensure_immutable_record(&node.record, &node.record), Ok(()));
    let mutated = VersionRecord::seal(VersionRecordInput {
        version_id: node.record.version_id(),
        realm,
        ref_name: node.record.ref_name().clone(),
        ref_generation: node.record.ref_generation(),
        operation_id: node.record.operation_id(),
        operation_digest: node.record.operation_digest(),
        authority_seq: 5,
        kind: node.record.kind(),
        target: node.record.target().clone(),
        base_version_id: node.record.base_version_id(),
        object_deps: vec![],
        pack_set_digest: node.record.pack_set_digest(),
        commit_set_id: node.record.commit_set_id(),
    })
    .unwrap();
    assert_eq!(ensure_immutable_record(&node.record, &mutated), Err(CausalRejectCode::VersionIdRecordConflict));

    let other = mint_publish(&realm, "refs/heads/other", oid(0x78), 5, vec![], vec![], 1301);
    let mut g = VersionGraph::new();
    let forged_key = other.record.version_id();
    g.insert_entry_at(forged_key, VersionLookupEntry::Active(Box::new(node)));
    assert_eq!(verify_dependency_closure(&g, &realm, &forged_key), Err(CausalClosureError::DependencyCorrupt));
}

#[test]
fn record_digest_exact_preimage() {
    let realm = default_realm();
    let d1 = mint_publish(&realm, "refs/heads/d1", oid(0x01), 1, vec![], vec![], 1400);
    let d2 = mint_publish(&realm, "refs/heads/d2", oid(0x02), 2, vec![], vec![], 1401);
    let r1 = mint_publish(
        &realm,
        "refs/heads/r",
        oid(0x03),
        3,
        vec![d1.record.version_id(), d2.record.version_id()],
        vec![],
        1402,
    );
    let r2 = mint_publish(
        &realm,
        "refs/heads/r",
        oid(0x03),
        3,
        vec![d2.record.version_id(), d1.record.version_id()],
        vec![],
        1402,
    );
    r1.record.verify_digest().unwrap();
    assert_eq!(r1.record.record_digest(), r2.record.record_digest());

    let r_other_target = VersionRecord::seal(VersionRecordInput {
        version_id: r1.record.version_id(),
        realm,
        ref_name: r1.record.ref_name().clone(),
        ref_generation: 1,
        operation_id: r1.record.operation_id(),
        operation_digest: r1.record.operation_digest(),
        authority_seq: 3,
        kind: RefVersionKind::Publish,
        target: RefTarget::Oid(oid(0x04)),
        base_version_id: None,
        object_deps: vec![d1.record.version_id()],
        pack_set_digest: r1.record.pack_set_digest(),
        commit_set_id: r1.record.commit_set_id(),
    })
    .unwrap();
    assert_ne!(r1.record.record_digest(), r_other_target.record_digest());
}

#[test]
fn pack_set_digest_exact_preimage() {
    let e1 = PackSetEntry::new(uid(1), uid(101), RequestDigest::from_bytes([0x11; 32])).unwrap();
    let e2 = PackSetEntry::new(uid(2), uid(102), RequestDigest::from_bytes([0x22; 32])).unwrap();
    let e3 = PackSetEntry::new(uid(2), uid(103), RequestDigest::from_bytes([0x33; 32])).unwrap();
    let e4 = PackSetEntry::new(uid(4), uid(101), RequestDigest::from_bytes([0x44; 32])).unwrap();

    assert_eq!(compute_pack_set_digest(&[e1, e2]).unwrap(), compute_pack_set_digest(&[e2, e1]).unwrap());
    assert_eq!(compute_pack_set_digest(&[e1, e1]), Err(RefVersionCodecError::DuplicatePackIdentity));
    assert!(compute_pack_set_digest(&[e1, e3]).is_ok());
    assert_eq!(compute_pack_set_digest(&[e2, e3]), Err(RefVersionCodecError::DuplicatePackId));
    assert_eq!(compute_pack_set_digest(&[e1, e4]), Err(RefVersionCodecError::DuplicateRegistrationId));
    assert!(PackSetEntry::new(Uuid::nil(), uid(101), RequestDigest::from_bytes([0; 32])).is_err());
}

#[test]
fn operation_digest_binds_base_selector_kind_and_request_order() {
    let realm = default_realm();
    let base_v = mint_publish(&realm, "refs/heads/main", oid(0x10), 1, vec![], vec![], 1500).record.version_id();

    let r_a = intent(
        "refs/heads/a",
        RefVersionKind::Publish,
        RefPrecondition::Absent,
        BaseRequestSelector::ExplicitAbsent,
        RefTarget::Oid(oid(0x11)),
    );
    let r_b = intent(
        "refs/heads/b",
        RefVersionKind::Publish,
        RefPrecondition::Absent,
        BaseRequestSelector::ExplicitAbsent,
        RefTarget::Oid(oid(0x22)),
    );
    let d_ab =
        operation_digest(&op_input(realm, 1501, vec![r_a.clone(), r_b.clone()], vec![planned_pack(1, 256)])).unwrap();
    let d_ba = operation_digest(&op_input(realm, 1501, vec![r_b, r_a], vec![planned_pack(1, 256)])).unwrap();
    assert_ne!(d_ab, d_ba);

    let mk = |kind, base| {
        operation_digest(&op_input(
            realm,
            1502,
            vec![intent("refs/heads/a", kind, RefPrecondition::Absent, base, RefTarget::Oid(oid(0x11)))],
            vec![],
        ))
        .unwrap()
    };
    let d_legacy = mk(RefVersionKind::Publish, BaseRequestSelector::LegacyNotSupplied);
    let d_present = mk(RefVersionKind::Publish, BaseRequestSelector::Present(base_v));
    let d_repack = mk(RefVersionKind::Repack, BaseRequestSelector::Present(base_v));
    assert_ne!(d_legacy, d_present);
    assert_ne!(d_present, d_repack);
}

#[test]
fn base_version_change_changes_operation_and_version_id() {
    let realm = default_realm();
    let rname = RefName::new("refs/heads/main").unwrap();
    let v1 = mint_publish(&realm, "refs/heads/main", oid(0x11), 1, vec![], vec![], 1600).record.version_id();
    let v2 = mint_publish(&realm, "refs/heads/main", oid(0x11), 2, vec![], vec![], 1601).record.version_id();

    let in1 = op_input(
        realm,
        1602,
        vec![intent(
            "refs/heads/main",
            RefVersionKind::Publish,
            RefPrecondition::Present(oid(0x11)),
            BaseRequestSelector::Present(v1),
            RefTarget::Oid(oid(0x22)),
        )],
        vec![],
    );
    let in2 = op_input(
        realm,
        1602,
        vec![intent(
            "refs/heads/main",
            RefVersionKind::Publish,
            RefPrecondition::Present(oid(0x11)),
            BaseRequestSelector::Present(v2),
            RefTarget::Oid(oid(0x22)),
        )],
        vec![],
    );
    let od1 = operation_digest(&in1).unwrap();
    let od2 = operation_digest(&in2).unwrap();
    assert_ne!(od1, od2);
    assert_ne!(
        derive_candidate_version_id(&in1, od1, &rname, Some(1)).unwrap(),
        derive_candidate_version_id(&in2, od2, &rname, Some(1)).unwrap()
    );
}

#[test]
fn not_applied_encodes_requested_old_new_and_frozen_reason() {
    let realm = default_realm();
    let base = mint_publish(&realm, "refs/heads/main", oid(0x10), 1, vec![], vec![], 1700);
    let main = RefName::new("refs/heads/main").unwrap();
    let t1 = encode_terminal(&VersionTerminalInput {
        realm,
        authority_seq: 2,
        operation_id: uid(1701),
        operation_digest: base.record.operation_digest(),
        terminal_kind: VersionTerminalKind::Rejected,
        commit_set_id: None,
        results: vec![VersionResultEntry::new(
            main.clone(),
            VersionResultOutcome::NotApplied(CausalRejectCode::BaseVersionMismatch),
            Some(oid(0x10)),
            Some(oid(0x20)),
        )],
    })
    .unwrap();
    let t2 = encode_terminal(&VersionTerminalInput {
        realm,
        authority_seq: 2,
        operation_id: uid(1701),
        operation_digest: base.record.operation_digest(),
        terminal_kind: VersionTerminalKind::Rejected,
        commit_set_id: None,
        results: vec![VersionResultEntry::new(
            main,
            VersionResultOutcome::NotApplied(CausalRejectCode::OldOidMismatch),
            Some(oid(0x10)),
            Some(oid(0x20)),
        )],
    })
    .unwrap();
    assert_ne!(t1.digest(), t2.digest());
}

#[test]
fn terminal_optional_fields_and_result_order_are_exact() {
    let realm = default_realm();
    let base = mint_publish(&realm, "refs/heads/alpha", oid(0x10), 1, vec![], vec![], 1800);
    let alpha = RefName::new("refs/heads/alpha").unwrap();
    let beta = RefName::new("refs/heads/beta").unwrap();
    let cs = CommitSetInput::new(
        realm,
        5,
        uid(1801),
        base.record.operation_digest(),
        vec![CommitSetVersionEntry::new(
            alpha.clone(),
            base.record.version_id(),
            RefVersionKind::Publish,
            RefTarget::Oid(oid(0x10)),
        )],
        CommitSetHead::Absent,
    );
    let cs_id = compute_commit_set_id(&cs).unwrap();
    let r_alpha = VersionResultEntry::new(alpha, VersionResultOutcome::Applied, None, Some(oid(0x10)));
    let r_beta = VersionResultEntry::new(
        beta,
        VersionResultOutcome::NotApplied(CausalRejectCode::PolicyDenied),
        Some(oid(0x20)),
        None,
    );
    let ordered = encode_terminal_with_commit_set(
        &VersionTerminalInput {
            realm,
            authority_seq: 5,
            operation_id: uid(1801),
            operation_digest: base.record.operation_digest(),
            terminal_kind: VersionTerminalKind::Committed,
            commit_set_id: Some(cs_id),
            results: vec![r_alpha.clone(), r_beta.clone()],
        },
        Some(&cs),
    )
    .unwrap();
    let reversed = encode_terminal_with_commit_set(
        &VersionTerminalInput {
            realm,
            authority_seq: 5,
            operation_id: uid(1801),
            operation_digest: base.record.operation_digest(),
            terminal_kind: VersionTerminalKind::Committed,
            commit_set_id: Some(cs_id),
            results: vec![r_beta, r_alpha],
        },
        Some(&cs),
    )
    .unwrap();
    assert_eq!(ordered.digest(), reversed.digest());

    let cancelled = encode_terminal_with_commit_set(
        &VersionTerminalInput {
            realm,
            authority_seq: 6,
            operation_id: uid(1802),
            operation_digest: base.record.operation_digest(),
            terminal_kind: VersionTerminalKind::Cancelled,
            commit_set_id: None,
            results: vec![],
        },
        None,
    )
    .unwrap();
    assert_ne!(cancelled.digest(), ordered.digest());
}
