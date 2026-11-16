//! Exact byte-vector tests for §2.1, §2.3, §2.5, §2.5.1 and §2.5.2 of
//! `docs/ref-version-pack-contract.md`.
use super::MAX_VERSION_TERMINAL_BYTES;
use super::commit_set::{CommitSetHead, CommitSetInput, CommitSetVersionEntry, encode_commit_set};
use super::contract::{
    AuthorityKind, OperationDigest, OperationDigestInput, RefVersionCodecError, RefVersionIntent, RefVersionKind,
    RefVersionRealm, VersionId,
};
use super::digest::{derive_candidate_version_id, operation_digest};
use super::pack_set::{PackSetEntry, compute_pack_set_digest};
use super::reasons::CausalRejectCode;
use super::record::{VersionRecord, VersionRecordInput};
use super::terminal::{
    VersionResultEntry, VersionResultOutcome, VersionTerminalInput, VersionTerminalKind, encode_terminal,
};
use crate::ref_store::contract::{IssuerLane, RequestDigest};
use crate::ref_store::core::pack_commit::PackCommitRejectCode;
use crate::ref_store::core::publication_decision::codes::DecisionRejectCode;
use crate::ref_store::core::terminal::CommitRejectCode;
use crate::ref_store::core::types::{GitObjectFormat, GitOid, RefName, RefTarget};
use uuid::Uuid;

fn synthetic_realm() -> RefVersionRealm {
    RefVersionRealm::new(
        Uuid::from_bytes(1_u128.to_be_bytes()),
        Uuid::from_bytes(2_u128.to_be_bytes()),
        Uuid::from_bytes(3_u128.to_be_bytes()),
        AuthorityKind::Pg,
        7,
        0,
        9,
        GitObjectFormat::Sha1,
    )
}

fn sha1(byte: u8) -> GitOid {
    GitOid::Sha1([byte; 20])
}

/// Real 128-ref rejected terminal input at the raw T byte boundary.
fn terminal_budget_input(long_name_extra: usize) -> VersionTerminalInput {
    let segment = "a".repeat(250);
    let tail = "b".repeat(10);
    let mut names = Vec::with_capacity(128);
    for index in 0..52 {
        let mut name = format!("refs/x{index:03}");
        for _ in 0..4 {
            name.push('/');
            name.push_str(&segment);
        }
        name.push('/');
        name.push_str(&tail);
        assert_eq!(name.len(), 1024);
        names.push(name);
    }
    names.push(format!("refs/x052/{}{}", "c".repeat(133), "d".repeat(long_name_extra)));
    for index in 53..128 {
        names.push(format!("refs/x{index:03}"));
    }
    assert_eq!(names.len(), 128);
    assert_eq!(names.iter().map(String::len).sum::<usize>(), 54_066 + long_name_extra);
    let results = names
        .into_iter()
        .map(|name| {
            VersionResultEntry::new(
                RefName::new(name).unwrap(),
                VersionResultOutcome::NotApplied(CausalRejectCode::PolicyDenied),
                Some(sha1(0x44)),
                Some(sha1(0x33)),
            )
        })
        .collect();
    VersionTerminalInput {
        realm: synthetic_realm(),
        authority_seq: 42,
        operation_id: Uuid::from_bytes(4_u128.to_be_bytes()),
        operation_digest: OperationDigest::from_test_bytes([0x11; 32]),
        terminal_kind: VersionTerminalKind::Rejected,
        commit_set_id: None,
        results,
    }
}

#[test]
fn canonical_fixed_and_mixed_commit_set_and_terminal_vectors_match_spec() {
    let realm = synthetic_realm();
    let op_id = Uuid::from_bytes(4_u128.to_be_bytes());
    let op_digest = OperationDigest::from_test_bytes([0x11; 32]);
    let main = RefName::new("refs/heads/main").unwrap();
    let topic = RefName::new("refs/heads/topic").unwrap();
    let feature = RefName::new("refs/heads/feature").unwrap();

    // 1. Fixed committed vector
    let cs_fixed = CommitSetInput::new(
        realm,
        42,
        op_id,
        op_digest,
        vec![CommitSetVersionEntry::new(
            main.clone(),
            VersionId::from_test_bytes([0x22; 32]),
            RefVersionKind::Publish,
            RefTarget::Oid(sha1(0x33)),
        )],
        CommitSetHead::Present { ref_name: main.clone(), target_oid: Some(sha1(0x33)) },
    );
    let (cs_bytes, cs_id) = encode_commit_set(&cs_fixed).unwrap();
    assert_eq!(cs_bytes.len(), 355);
    assert_eq!(cs_id.as_hex(), "00fee34e0745b3b5557cd40620d276b623a63a3cdcbd469fbea796968e53f7e5");

    let t_fixed = encode_terminal(&VersionTerminalInput {
        realm,
        authority_seq: 42,
        operation_id: op_id,
        operation_digest: op_digest,
        terminal_kind: VersionTerminalKind::Committed,
        commit_set_id: Some(cs_id),
        results: vec![VersionResultEntry::new(
            main.clone(),
            VersionResultOutcome::Applied,
            Some(sha1(0x44)),
            Some(sha1(0x33)),
        )],
    })
    .unwrap();
    assert_eq!(t_fixed.bytes().len(), 336);
    assert_eq!(t_fixed.digest().as_hex(), "081d960f2ce44a95fa19866189f83a604de5b6f78d9dfeac941ca7efddb92ab9");

    // 2. Mixed delete/publish vector
    let cs_mix = CommitSetInput::new(
        realm,
        42,
        op_id,
        op_digest,
        vec![
            CommitSetVersionEntry::new(
                main.clone(),
                VersionId::from_test_bytes([0x22; 32]),
                RefVersionKind::Publish,
                RefTarget::Oid(sha1(0x33)),
            ),
            CommitSetVersionEntry::new(
                topic.clone(),
                VersionId::from_test_bytes([0x66; 32]),
                RefVersionKind::Delete,
                RefTarget::Delete,
            ),
        ],
        CommitSetHead::Present { ref_name: main.clone(), target_oid: Some(sha1(0x33)) },
    );
    let (cs_mix_bytes, cs_mix_id) = encode_commit_set(&cs_mix).unwrap();
    assert_eq!(cs_mix_bytes.len(), 421);
    assert_eq!(cs_mix_id.as_hex(), "ffcd8426b98ee6724cffc3c2918ec6450c86a33203c0cc10f2c3820c0fddd6ad");

    let t_mix = encode_terminal(&VersionTerminalInput {
        realm,
        authority_seq: 42,
        operation_id: op_id,
        operation_digest: op_digest,
        terminal_kind: VersionTerminalKind::Committed,
        commit_set_id: Some(cs_mix_id),
        results: vec![
            VersionResultEntry::new(main.clone(), VersionResultOutcome::Applied, Some(sha1(0x44)), Some(sha1(0x33))),
            VersionResultEntry::new(topic.clone(), VersionResultOutcome::Applied, Some(sha1(0x77)), None),
        ],
    })
    .unwrap();
    assert_eq!(t_mix.bytes().len(), 399);
    assert_eq!(t_mix.digest().as_hex(), "24d30b09e01477656e53d93703cd968d1820f43edd5a985f77b684962fbfe37a");

    // 4. All-rejected vector
    let t_rej = encode_terminal(&VersionTerminalInput {
        realm,
        authority_seq: 42,
        operation_id: op_id,
        operation_digest: op_digest,
        terminal_kind: VersionTerminalKind::Rejected,
        commit_set_id: None,
        results: vec![
            VersionResultEntry::new(
                topic.clone(),
                VersionResultOutcome::NotApplied(CausalRejectCode::OldOidMismatch),
                Some(sha1(0x77)),
                None,
            ),
            VersionResultEntry::new(
                main.clone(),
                VersionResultOutcome::NotApplied(CausalRejectCode::BaseVersionMismatch),
                Some(sha1(0x44)),
                Some(sha1(0x33)),
            ),
        ],
    })
    .unwrap();
    assert_eq!(t_rej.bytes().len(), 396);
    assert_eq!(t_rej.digest().as_hex(), "7a610bec25315ef167631587e824b5ba03802e30c9f9b3f397d4fd5142eedb7f");

    // 5. Mixed accepted/rejected vector
    let t_sub = encode_terminal(&VersionTerminalInput {
        realm,
        authority_seq: 42,
        operation_id: op_id,
        operation_digest: op_digest,
        terminal_kind: VersionTerminalKind::Committed,
        commit_set_id: Some(cs_id),
        results: vec![
            VersionResultEntry::new(
                topic,
                VersionResultOutcome::NotApplied(CausalRejectCode::OldOidMismatch),
                Some(sha1(0x77)),
                None,
            ),
            VersionResultEntry::new(
                feature,
                VersionResultOutcome::NotApplied(CausalRejectCode::PolicyDenied),
                None,
                Some(sha1(0x88)),
            ),
            VersionResultEntry::new(main, VersionResultOutcome::Applied, Some(sha1(0x44)), Some(sha1(0x33))),
        ],
    })
    .unwrap();
    assert_eq!(t_sub.bytes().len(), 493);
    assert_eq!(t_sub.digest().as_hex(), "6a71a85aadbb0c4e0f44e59faa293e137a20819c5b57af7c34c227e1aae6d6fd");

    // 6. Cancelled vector
    let t_can = encode_terminal(&VersionTerminalInput {
        realm,
        authority_seq: 42,
        operation_id: op_id,
        operation_digest: op_digest,
        terminal_kind: VersionTerminalKind::Cancelled,
        commit_set_id: None,
        results: vec![],
    })
    .unwrap();
    assert_eq!(t_can.bytes().len(), 206);
    assert_eq!(t_can.digest().as_hex(), "b5d3703c67a4b055716eb806c9c6e51700a11fb1a9eae1a8ac5a3304bde9900e");
}

#[test]
fn identity_chain_vector_matches_spec_end_to_end() {
    let realm = synthetic_realm();
    let op_id = Uuid::from_bytes(4_u128.to_be_bytes());
    let op_digest = OperationDigest::from_test_bytes([0x11; 32]);
    let main = RefName::new("refs/heads/main").unwrap();

    // Compute VersionId directly over synthetic op_digest=0x11*32 matching spec §2.1 & §2.5 step 3.
    let mut writer = super::digest::CanonicalWriter::new();
    writer.push_len_prefixed(b"ry-ref-version-id-v1").unwrap();
    writer.push_len_prefixed(realm.tenant_id().as_bytes()).unwrap();
    writer.push_len_prefixed(realm.repository_id().as_bytes()).unwrap();
    writer.push_len_prefixed(realm.history_incarnation().as_bytes()).unwrap();
    writer.push_u8(realm.authority_kind().tag());
    writer.push_u64(7);
    writer.push_u64(0);
    writer.push_u64(9);
    writer.push_u8(1);
    writer.push_len_prefixed(main.as_str().as_bytes()).unwrap();
    writer.push_u64(1);
    writer.push_len_prefixed(op_id.as_bytes()).unwrap();
    writer.push_len_prefixed(op_digest.as_bytes()).unwrap();
    let vid = VersionId::from_canonical_hash(writer.finish());
    assert_eq!(vid.as_hex(), "7ed6b0d771d7133059718f42fa2dab89fb50003d57128536ffb908d11816c373");

    let pack_entry = PackSetEntry::new(
        Uuid::from_bytes([0x99; 16]),
        Uuid::from_bytes([0xaa; 16]),
        RequestDigest::from_bytes([0xbb; 32]),
    )
    .unwrap();
    let pack_set = compute_pack_set_digest(&[pack_entry]).unwrap();
    assert_eq!(pack_set.as_hex(), "fd3461afbd34e518f8bf1d6c677f2a023346733925ec9cd6eb7ca76f3c1a4c22");

    let cs = CommitSetInput::new(
        realm,
        42,
        op_id,
        op_digest,
        vec![CommitSetVersionEntry::new(main.clone(), vid, RefVersionKind::Publish, RefTarget::Oid(sha1(0x33)))],
        CommitSetHead::Present { ref_name: main.clone(), target_oid: Some(sha1(0x33)) },
    );
    let (cs_bytes, cs_id) = encode_commit_set(&cs).unwrap();
    assert_eq!(cs_bytes.len(), 355);
    assert_eq!(cs_id.as_hex(), "9ffcf9731fb04dd56ceac420d7707c1b2b792deaa431d0bd35e3f53bee721932");

    let rec = VersionRecord::seal(VersionRecordInput {
        version_id: vid,
        realm,
        ref_name: main.clone(),
        ref_generation: 1,
        operation_id: op_id,
        operation_digest: op_digest,
        authority_seq: 42,
        kind: RefVersionKind::Publish,
        target: RefTarget::Oid(sha1(0x33)),
        base_version_id: None,
        object_deps: vec![],
        pack_set_digest: pack_set,
        commit_set_id: cs_id,
    })
    .unwrap();
    assert_eq!(rec.record_digest().as_hex(), "01ef64d5effb40e4ee835437e78eeb31a9b7781500767ce9255cfb8e5e238da9");

    let t = encode_terminal(&VersionTerminalInput {
        realm,
        authority_seq: 42,
        operation_id: op_id,
        operation_digest: op_digest,
        terminal_kind: VersionTerminalKind::Committed,
        commit_set_id: Some(cs_id),
        results: vec![VersionResultEntry::new(main, VersionResultOutcome::Applied, Some(sha1(0x44)), Some(sha1(0x33)))],
    })
    .unwrap();
    assert_eq!(t.bytes().len(), 336);
    assert_eq!(t.digest().as_hex(), "25de02843735a28ec5b4fd178cb06d12de16e71a46915acb4a3cd99ee572da19");

    // Smoke-check §2.6 live operation_digest + derive_candidate_version_id linkage.
    let od_input = OperationDigestInput::new(
        realm,
        Uuid::from_bytes(5_u128.to_be_bytes()),
        Uuid::from_bytes(6_u128.to_be_bytes()),
        IssuerLane::new("main").unwrap(),
        3,
        op_id,
        41,
        RequestDigest::from_bytes([0x55; 32]),
        crate::ref_store::core::CommitMode::Atomic,
        crate::ref_store::core::HeadUpdate::Keep,
        vec![RefVersionIntent::new(
            RefName::new("refs/heads/main").unwrap(),
            RefVersionKind::Publish,
            crate::ref_store::core::RefPrecondition::Absent,
            super::contract::BaseRequestSelector::ExplicitAbsent,
            RefTarget::Oid(sha1(0x33)),
        )],
        RequestDigest::from_bytes([0x66; 32]),
        vec![],
    );
    let od = operation_digest(&od_input).unwrap();
    let minted = derive_candidate_version_id(&od_input, od, &RefName::new("refs/heads/main").unwrap(), None).unwrap();
    assert_ne!(minted, vid);
}

#[test]
fn reason_vocabulary_and_refinements_are_closed() {
    for (idx, code) in CausalRejectCode::ALL.iter().enumerate() {
        assert_eq!(usize::from(code.ordinal()), idx + 1);
        assert_eq!(CausalRejectCode::parse(code.as_str()).unwrap(), *code);
    }
    for code in DecisionRejectCode::ALL {
        assert!(CausalRejectCode::refine_decision_reason(code.as_str()).is_ok());
    }
    assert_eq!(CausalRejectCode::refine_decision_reason("force_push_denied").unwrap(), CausalRejectCode::PolicyDenied);
    assert_eq!(
        CausalRejectCode::refine_decision_reason("pull_flow_violation").unwrap(),
        CausalRejectCode::PolicyDenied
    );
    assert_eq!(
        CausalRejectCode::refine_decision_reason("self_approval_denied").unwrap(),
        CausalRejectCode::MissingApprovals
    );
    assert_eq!(
        CausalRejectCode::refine_decision_reason("check_untrusted").unwrap(),
        CausalRejectCode::RequiredCheckFailed
    );
    assert!(CausalRejectCode::parse("unknown_reason").is_err());
    assert!(CausalRejectCode::parse("BaseVersionMismatch").is_err());
    assert!(CausalRejectCode::parse("has space").is_err());
    assert!(CausalRejectCode::parse("has:colon").is_err());
    let _ = CausalRejectCode::from_commit_reject_code(CommitRejectCode::OldOidMismatch);
    assert_eq!(CausalRejectCode::from_pack_commit_reject_code(PackCommitRejectCode::LedgerIntegrity), None);
}

#[test]
fn terminal_bytes_boundary_is_exact_and_typed() {
    assert_eq!(MAX_VERSION_TERMINAL_BYTES, 65_536);
    let exact = encode_terminal(&terminal_budget_input(0)).unwrap();
    assert_eq!(exact.bytes().len(), 65_536);
    assert_eq!(exact.digest().as_hex(), "c04a91f6fc0b74f88c46bf70aa381e080f6f68b99be3603ec6b695c806cc9932");

    let over = encode_terminal(&terminal_budget_input(1)).unwrap_err();
    match over {
        RefVersionCodecError::Capacity { field, limit, actual } => {
            assert_eq!(field, "terminal_bytes");
            assert_eq!(limit, MAX_VERSION_TERMINAL_BYTES);
            assert_eq!(actual, 65_537);
        }
        other => panic!("expected terminal_bytes Capacity, got {other:?}"),
    }
}
