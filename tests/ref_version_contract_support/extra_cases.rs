//! Additional C3-C6 causal bridge, read-mode, retention and SHA-256 contract tests.

use super::fixtures::{
    MintSpec, closure_pack, default_realm, mint_node, mint_publish, oid, oid256, op_input, registered_pack, uid,
};
use rootyard::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, ContentDigest, PackArtifactRole, PackCommitRejectCode, RegisteredArtifact,
    RegisteredPack, pack_set_digest,
};
use rootyard::ref_store::core::publication_decision::codes::DecisionRejectCode;
use rootyard::ref_store::core::terminal::CommitRejectCode;
use rootyard::ref_store::ref_version::{
    AuthorityKind, BaseRequestSelector, CausalClosureError, CausalReadError, CausalReadOptions, CausalRejectCode,
    CommitSetHead, CommitSetInput, CommitSetVersionEntry, PackSetEntry, ReadConsumer, ReadModeKind, ReadTarget,
    RefVersionIntent, RefVersionKind, RefVersionRealm, RetentionProtector, StrongSnapshotState, VerifiedClosurePack,
    VersionGraph, VersionResultEntry, VersionResultOutcome, VersionTerminalInput, VersionTerminalKind,
    compute_commit_set_id, compute_pack_set_digest, encode_terminal_with_commit_set, evaluate_pack_retention,
    operation_digest, verify_causal_read, verify_dependency_closure,
};
use rootyard::ref_store::{GitObjectFormat, RefName, RefPrecondition, RefTarget, RequestDigest};

#[test]
fn registered_pack_bridge_builds_causal_pack_set_digest_and_closure_pack() {
    let backend = "a".repeat(64);
    let tenant_id = uid(1);
    let authority_id = uid(99);
    let p1_rev1 = registered_pack(tenant_id, authority_id, 1, "s3", &backend, 4096, Some(1));
    let p1_none = registered_pack(tenant_id, authority_id, 1, "s3", &backend, 4096, None);
    let p2 = registered_pack(tenant_id, authority_id, 2, "s3", &backend, 2048, Some(9));

    assert_eq!(
        pack_set_digest(std::slice::from_ref(&p1_rev1)).unwrap(),
        pack_set_digest(std::slice::from_ref(&p1_none)).unwrap()
    );
    assert_eq!(
        pack_set_digest(&[p1_rev1.clone(), p2.clone()]).unwrap(),
        pack_set_digest(&[p2, p1_rev1.clone()]).unwrap()
    );
    let entries =
        vec![PackSetEntry::from_registered(&p1_rev1).unwrap(), PackSetEntry::from_registered(&p1_none).unwrap()];
    assert!(compute_pack_set_digest(&entries).is_err());

    let closure_p1 = VerifiedClosurePack::from_registered(&p1_rev1).unwrap();
    assert_eq!(closure_p1.storage_tenant_id(), tenant_id);
    assert_eq!(closure_p1.authority_id(), authority_id);
    assert_eq!(closure_p1.provider(), "s3");
    assert_eq!(closure_p1.backend_identity(), backend);
    assert_eq!(closure_p1.verified_bytes(), 4096 + 128);
    assert_eq!(closure_p1.artifact_count(), 2);

    let sha_p = ContentDigest::parse(&"1".repeat(64)).unwrap();
    let sha_i = ContentDigest::parse(&"2".repeat(64)).unwrap();
    let loc_p = ArtifactLocator::new(tenant_id, authority_id, 1, uid(501), "core-pack", sha_p.clone(), 512).unwrap();
    let loc_i = ArtifactLocator::new(tenant_id, authority_id, 1, uid(502), "core-pack", sha_i.clone(), 128).unwrap();
    let art_p =
        RegisteredArtifact::new(PackArtifactRole::Pack, 0, uid(601), loc_p, "s3", &"a".repeat(64), sha_p, 512).unwrap();
    let art_i =
        RegisteredArtifact::new(PackArtifactRole::Idx, 1, uid(602), loc_i, "fs", &"b".repeat(64), sha_i, 128).unwrap();
    let mixed_arts = vec![art_p, art_i];
    let mixed_digest = ArtifactSetDigest::of(&mixed_arts);
    let bad_pack = RegisteredPack::new(uid(701), uid(702), mixed_digest, mixed_arts, None).unwrap();
    assert!(VerifiedClosurePack::from_registered(&bad_pack).is_err());
}

#[test]
fn mixed_backend_and_cross_tenant_pack_closure_fail_closed() {
    let realm = default_realm();
    let backend_a = "1".repeat(64);
    let backend_b = "2".repeat(64);
    let dep = mint_publish(
        &realm,
        "refs/heads/dep",
        oid(0x10),
        1,
        vec![],
        vec![closure_pack(realm.tenant_id(), 1, "s3", &backend_a, 1024)],
        101,
    );
    let dep_vid = dep.record.version_id();
    let root_mixed = mint_publish(
        &realm,
        "refs/heads/main",
        oid(0x20),
        2,
        vec![dep_vid],
        vec![closure_pack(realm.tenant_id(), 2, "s3", &backend_b, 1024)],
        102,
    );
    let root_vid = root_mixed.record.version_id();
    let mut graph = VersionGraph::new();
    graph.insert_active(dep);
    graph.insert_active(root_mixed);
    assert_eq!(verify_dependency_closure(&graph, &realm, &root_vid), Err(CausalClosureError::DependencyCorrupt));

    let foreign_pack = closure_pack(uid(999), 3, "s3", &backend_a, 1024);
    let root_foreign = mint_publish(&realm, "refs/heads/foreign", oid(0x30), 3, vec![dep_vid], vec![foreign_pack], 103);
    let foreign_vid = root_foreign.record.version_id();
    graph.insert_active(root_foreign);
    assert_eq!(
        verify_dependency_closure(&graph, &realm, &foreign_vid),
        Err(CausalClosureError::DependencyRealmMismatch)
    );
}

#[test]
fn read_mode_matrix_enforces_common_time_session_bound_and_explicit_fallback() {
    let realm = default_realm();
    let backend = "a".repeat(64);
    let tag_v1 = mint_publish(
        &realm,
        "refs/tags/v1",
        oid(0x11),
        1,
        vec![],
        vec![closure_pack(realm.tenant_id(), 10, "s3", &backend, 512)],
        201,
    );
    let tag_vid = tag_v1.record.version_id();
    let branch_v10 = mint_publish(
        &realm,
        "refs/heads/main",
        oid(0x22),
        10,
        vec![tag_vid],
        vec![closure_pack(realm.tenant_id(), 11, "s3", &backend, 512)],
        202,
    );
    let branch_vid = branch_v10.record.version_id();
    let tombstone = mint_node(MintSpec {
        realm: &realm,
        ref_name: "refs/heads/main",
        kind: RefVersionKind::Delete,
        precondition: RefPrecondition::Present(oid(0x22)),
        base_record: Some(&branch_v10.record),
        target: RefTarget::Delete,
        authority_seq: 11,
        object_deps: vec![],
        own_packs: vec![],
        op_seed: 203,
    });
    let tomb_vid = tombstone.record.version_id();
    let missing_dep = mint_publish(&realm, "refs/heads/never-stored", oid(0x41), 9, vec![], vec![], 204);
    let retired_node = mint_publish(&realm, "refs/heads/retired", oid(0x42), 9, vec![], vec![], 205);
    let retired_vid = retired_node.record.version_id();
    let corrupt_child =
        mint_publish(&realm, "refs/heads/corrupt", oid(0x44), 12, vec![missing_dep.record.version_id()], vec![], 206);
    let corrupt_vid = corrupt_child.record.version_id();

    let mut graph = VersionGraph::new();
    graph.insert_active(tag_v1);
    graph.insert_active(branch_v10);
    graph.insert_active(tombstone);
    graph.insert_active(corrupt_child);
    graph.mark_retired(retired_vid);

    let snap = Some(StrongSnapshotState { authority_seq: 12, snapshot_digest: RequestDigest::from_bytes([0x55; 32]) });

    for consumer in [ReadConsumer::SmartHttpFetch, ReadConsumer::PrMergeDecision, ReadConsumer::BackupRestore] {
        let err = verify_causal_read(
            Some(&graph),
            &realm,
            &CausalReadOptions {
                consumer,
                target: ReadTarget::VersionSet { version_ids: vec![tag_vid, branch_vid] },
                session_lower_bound: None,
                historical_pinned: false,
                allow_strong_fallback: true,
            },
            snap,
        )
        .unwrap_err();
        assert_eq!(err, CausalReadError::NotCommonTime);
    }

    let cmp_receipt = verify_causal_read(
        Some(&graph),
        &realm,
        &CausalReadOptions {
            consumer: ReadConsumer::CrossRefCompare,
            target: ReadTarget::VersionSet { version_ids: vec![tag_vid, branch_vid] },
            session_lower_bound: Some(10),
            historical_pinned: false,
            allow_strong_fallback: false,
        },
        snap,
    )
    .unwrap();
    assert_eq!(cmp_receipt.effective_mode, ReadModeKind::VersionSet);
    assert!(!cmp_receipt.common_time);
    assert!(!cmp_receipt.fallback_used);
    assert_eq!(cmp_receipt.authority_seq, 10);

    assert_eq!(
        verify_causal_read(
            Some(&graph),
            &realm,
            &CausalReadOptions {
                consumer: ReadConsumer::SessionReadYourWrites,
                target: ReadTarget::VersionClosure { version_id: tag_vid },
                session_lower_bound: Some(5),
                historical_pinned: false,
                allow_strong_fallback: false,
            },
            snap,
        )
        .unwrap_err(),
        CausalReadError::BehindSession
    );

    let pinned_ok = verify_causal_read(
        Some(&graph),
        &realm,
        &CausalReadOptions {
            consumer: ReadConsumer::CiCheckoutPin,
            target: ReadTarget::VersionClosure { version_id: tag_vid },
            session_lower_bound: Some(5),
            historical_pinned: true,
            allow_strong_fallback: false,
        },
        snap,
    )
    .unwrap();
    assert_eq!(pinned_ok.effective_mode, ReadModeKind::VersionClosure);
    assert_eq!(pinned_ok.authority_seq, 1);

    assert_eq!(
        verify_causal_read(
            Some(&graph),
            &realm,
            &CausalReadOptions {
                consumer: ReadConsumer::SingleRefBrowse,
                target: ReadTarget::VersionClosure { version_id: retired_vid },
                session_lower_bound: None,
                historical_pinned: false,
                allow_strong_fallback: false,
            },
            snap,
        )
        .unwrap_err(),
        CausalReadError::VersionRetired
    );

    let fallback_ok = verify_causal_read(
        Some(&graph),
        &realm,
        &CausalReadOptions {
            consumer: ReadConsumer::SingleRefBrowse,
            target: ReadTarget::VersionClosure { version_id: tomb_vid },
            session_lower_bound: None,
            historical_pinned: false,
            allow_strong_fallback: true,
        },
        snap,
    )
    .unwrap();
    assert!(fallback_ok.fallback_used);
    assert!(fallback_ok.common_time);
    assert_eq!(fallback_ok.effective_mode, ReadModeKind::StrongSnapshot);

    assert_eq!(
        verify_causal_read(
            Some(&graph),
            &realm,
            &CausalReadOptions {
                consumer: ReadConsumer::DurableComputeCache,
                target: ReadTarget::VersionClosure { version_id: corrupt_vid },
                session_lower_bound: None,
                historical_pinned: false,
                allow_strong_fallback: true,
            },
            snap,
        )
        .unwrap_err(),
        CausalReadError::DependencyMissing
    );

    assert_eq!(
        verify_causal_read(
            None,
            &realm,
            &CausalReadOptions {
                consumer: ReadConsumer::SmartHttpFetch,
                target: ReadTarget::StrongSnapshot,
                session_lower_bound: None,
                historical_pinned: false,
                allow_strong_fallback: false,
            },
            snap,
        )
        .unwrap_err(),
        CausalReadError::AuthorityUnavailable
    );

    let literals = [
        (CausalReadError::VersionNotFound, "version_not_found"),
        (CausalReadError::VersionRetired, "version_retired"),
        (CausalReadError::Deleted, "deleted"),
        (CausalReadError::DependencyMissing, "dependency_missing"),
        (CausalReadError::DependencyCorrupt, "dependency_corrupt"),
        (CausalReadError::DependencyRealmMismatch, "dependency_realm_mismatch"),
        (CausalReadError::DependencyCycleIntegrity, "dependency_cycle_integrity"),
        (CausalReadError::ClosureTooLarge, "closure_too_large"),
        (CausalReadError::BehindSession, "behind_session"),
        (CausalReadError::NotCommonTime, "not_common_time"),
        (CausalReadError::AuthorityUnavailable, "authority_unavailable"),
        (CausalReadError::UnknownOperation, "unknown_operation"),
    ];
    for (err, expected) in literals {
        assert_eq!(err.as_str(), expected);
    }
}

#[test]
fn retention_protectors_and_unknown_operation_never_collected_by_ttl() {
    let realm = default_realm();
    let backend = "c".repeat(64);
    let base_pack = closure_pack(realm.tenant_id(), 20, "s3", &backend, 1024);
    let top_pack = closure_pack(realm.tenant_id(), 21, "s3", &backend, 1024);
    let dep = mint_publish(&realm, "refs/heads/base", oid(0x10), 1, vec![], vec![base_pack.clone()], 301);
    let dep_vid = dep.record.version_id();
    let root = mint_publish(&realm, "refs/heads/main", oid(0x20), 2, vec![dep_vid], vec![top_pack], 302);
    let root_vid = root.record.version_id();
    let mut graph = VersionGraph::new();
    graph.insert_active(dep);
    graph.insert_active(root);
    let closure = verify_dependency_closure(&graph, &realm, &root_vid).unwrap();

    let unknown = evaluate_pack_retention(
        base_pack.entry(),
        &[&closure],
        &[RetentionProtector::PendingOrUnknownOperation {
            operation_id: uid(900),
            target_versions: vec![root_vid],
            planned_pack_ids: vec![],
            age_seconds: 365 * 86_400,
        }],
    );
    assert!(!unknown.collectible);
    assert!(unknown.protected_by_unknown_operation);

    let draining = evaluate_pack_retention(
        base_pack.entry(),
        &[&closure],
        &[RetentionProtector::CompactionInput {
            repack_operation_id: uid(901),
            old_version_ids: vec![root_vid],
            committed: true,
            readers_drained: false,
        }],
    );
    assert!(!draining.collectible);

    let released = evaluate_pack_retention(
        base_pack.entry(),
        &[&closure],
        &[
            RetentionProtector::SnapshotPin { pin_id: uid(902), version_ids: vec![root_vid], expired: true },
            RetentionProtector::RetentionRoot { root_id: uid(903), version_ids: vec![root_vid], released: true },
            RetentionProtector::CiCheckoutPin { job_id: uid(904), version_ids: vec![root_vid], revoked: true },
            RetentionProtector::PrMergeFinalizer { pull_id: uid(905), version_ids: vec![root_vid], settled: true },
            RetentionProtector::BackupManifest { manifest_id: uid(906), version_ids: vec![root_vid], retained: false },
            RetentionProtector::CompactionInput {
                repack_operation_id: uid(907),
                old_version_ids: vec![root_vid],
                committed: true,
                readers_drained: true,
            },
            RetentionProtector::QuarantineHold {
                incident_id: uid(908),
                pack_ids: vec![base_pack.entry().pack_id()],
                cleared: true,
            },
        ],
    );
    assert!(released.collectible);

    let retained_by_live = evaluate_pack_retention(
        base_pack.entry(),
        &[&closure],
        &[RetentionProtector::LiveRefHead { version_id: root_vid }],
    );
    assert!(!retained_by_live.collectible);
    assert!(retained_by_live.protected_versions.contains(&dep_vid));
    assert!(retained_by_live.protected_pack_ids.contains(&base_pack.entry().pack_id()));
}

#[test]
fn reason_code_vocabulary_and_commit_code_mapping_are_closed() {
    assert_eq!(CausalRejectCode::ALL.len(), 32);
    for code in DecisionRejectCode::ALL {
        assert!(CausalRejectCode::refine_decision_reason(code.as_str()).is_ok());
    }
    assert_eq!(
        CausalRejectCode::from_commit_reject_code(CommitRejectCode::PrefixConflict),
        CausalRejectCode::PrefixConflict
    );
    assert_eq!(
        CausalRejectCode::from_pack_commit_reject_code(PackCommitRejectCode::DecisionRejected),
        Some(CausalRejectCode::PolicyDenied)
    );
    assert_eq!(CausalRejectCode::from_pack_commit_reject_code(PackCommitRejectCode::ClosureMismatch), None);
    assert!(CausalRejectCode::parse("not_a_real_reason").is_err());
}

#[test]
fn sha256_repository_version_record_commit_set_and_terminal_round_trip() {
    let raft_sha256 =
        RefVersionRealm::new(uid(10), uid(20), uid(30), AuthorityKind::Raft, 4, 7, 12, GitObjectFormat::Sha256);
    let rname = RefName::new("refs/heads/main").unwrap();
    let oid_a = oid256(0xaa);
    let node = mint_publish(&raft_sha256, "refs/heads/main", oid_a, 1, vec![], vec![], 400);
    node.record.verify_digest().unwrap();

    let cs_input = CommitSetInput::new(
        raft_sha256,
        1,
        node.record.operation_id(),
        node.record.operation_digest(),
        vec![CommitSetVersionEntry::new(
            rname.clone(),
            node.record.version_id(),
            RefVersionKind::Publish,
            RefTarget::Oid(oid_a),
        )],
        CommitSetHead::Present { ref_name: rname.clone(), target_oid: Some(oid_a) },
    );
    let cs_id = compute_commit_set_id(&cs_input).unwrap();
    let encoded = encode_terminal_with_commit_set(
        &VersionTerminalInput {
            realm: raft_sha256,
            authority_seq: 1,
            operation_id: node.record.operation_id(),
            operation_digest: node.record.operation_digest(),
            terminal_kind: VersionTerminalKind::Committed,
            commit_set_id: Some(cs_id),
            results: vec![VersionResultEntry::new(rname, VersionResultOutcome::Applied, None, Some(oid_a))],
        },
        Some(&cs_input),
    )
    .unwrap();
    assert!(!encoded.bytes().is_empty());

    let bad_intent = RefVersionIntent::new(
        RefName::new("refs/heads/bad").unwrap(),
        RefVersionKind::Publish,
        RefPrecondition::Absent,
        BaseRequestSelector::ExplicitAbsent,
        RefTarget::Oid(oid(0x11)),
    );
    assert!(operation_digest(&op_input(raft_sha256, 401, vec![bad_intent], vec![])).is_err());
}
