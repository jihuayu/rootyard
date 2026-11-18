//! Unit tests covering Smart HTTP pkt-line bounds, advertisement narrowing/authz,
//! `#180` closure checks, `CausalPushProofReceipt` binding, and RefCas SM retries (#183).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use async_compression::tokio::write::GzipEncoder;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use super::closure_prove::verify_base_packs_and_dependencies;
use super::commit_gate::evaluate_push_auth_precheck;
use super::protocol::{
    AdvertisementRequest, AdvertisementStrategy, ClientPushCapabilityProfile, VisibleRefEntry,
    build_push_ref_advertisement, decode_receive_pack_stream, encode_receive_pack_report, encode_ref_advertisement,
};
use super::quarantine::{HoldLifecycleState, OperationHoldGuard, QuarantineSlot, ingest_pack_to_quarantine};
use super::receipt::{AcceptedRefProof, CausalPushProofReceipt};
use super::types::{
    AuthorizedSnapshotState, BasePackRef, FaultInjectionHook, PushAuthContext, PushCausalError, ReceiveCapabilities,
    StreamIngestLimits,
};
use crate::blob_store::BlobLocator;
use crate::ref_store::contract::{IssuerLane, RequestDigest};
use crate::ref_store::core::contract::CommitMode;
use crate::ref_store::core::ref_version::{
    AuthorityKind, BaseRequestSelector, CausalVersionNode, CommitSetHead, CommitSetInput, CommitSetVersionEntry,
    OperationDigestInput, RefVersionIntent, RefVersionKind, RefVersionRealm, VerifiedClosurePack, VersionGraph,
    VersionRecord, VersionRecordInput, compute_commit_set_id, compute_pack_set_digest, derive_candidate_version_id,
    operation_digest,
};
use crate::ref_store::core::types::{GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget};

fn sample_auth(actor_id: Uuid) -> PushAuthContext {
    PushAuthContext {
        actor_id,
        token_scope_id: Some(Uuid::new_v4()),
        session_scope_id: Some(Uuid::new_v4()),
        lease_id: Some(Uuid::new_v4()),
        lease_expires_at_ms: Some(10_000),
        now_ms: 1_000,
        principal_authz_epoch: 5,
        min_required_authz_epoch: 3,
        write_authorized: true,
        allow_force_push: false,
        allow_branch_delete: true,
        protected_branches: BTreeSet::from(["refs/heads/main".to_owned()]),
        visible_refs: BTreeSet::new(),
    }
}

fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() + 4;
    let mut out = format!("{len:04x}").into_bytes();
    out.extend_from_slice(payload);
    out
}

#[tokio::test]
async fn decode_stream_handles_gzip_and_rejects_shallow_and_overflow() {
    let old = "0".repeat(40);
    let new = "a".repeat(40);
    let cmd = format!("{old} {new} refs/heads/feat\0report-status-v2 atomic side-band-64k ofs-delta\n");
    let mut wire = pkt_line(cmd.as_bytes());
    wire.extend_from_slice(b"0000");
    wire.extend_from_slice(b"PACK\x00\x00\x00\x02\x00\x00\x00\x00");
    wire.extend_from_slice(&[0x11; 20]);

    let mut enc = GzipEncoder::new(Vec::new());
    enc.write_all(&wire).await.unwrap();
    enc.shutdown().await.unwrap();
    let gz = enc.into_inner();

    let limits = StreamIngestLimits::default();
    let decoded = decode_receive_pack_stream(Cursor::new(gz), true, GitObjectFormat::Sha1, &limits).await.unwrap();
    assert_eq!(decoded.commands.len(), 1);
    assert!(decoded.capabilities.atomic && decoded.capabilities.report_status_v2);

    let mut slot = QuarantineSlot::create(None).unwrap();
    let ingested = ingest_pack_to_quarantine(
        decoded.remainder,
        &mut slot,
        GitObjectFormat::Sha1,
        decoded.command_bytes_read,
        &limits,
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(ingested.has_pack);
    assert!(ingested.incoming_pack_path.as_ref().unwrap().exists());
    let sweep = slot.sweep();
    assert!(sweep.dir_removed);

    let mut shallow_wire = pkt_line(b"shallow 1111111111111111111111111111111111111111\n");
    shallow_wire.extend_from_slice(&pkt_line(cmd.as_bytes()));
    shallow_wire.extend_from_slice(b"0000");
    let err = decode_receive_pack_stream(Cursor::new(shallow_wire), false, GitObjectFormat::Sha1, &limits).await;
    assert!(matches!(err, Err(PushCausalError::ShallowRejected)));

    let mut strict_limit = limits;
    strict_limit.max_stream_bytes = 24;
    let over = decode_receive_pack_stream(Cursor::new(wire), false, GitObjectFormat::Sha1, &strict_limit).await;
    assert!(matches!(over, Err(PushCausalError::LimitExceeded(_))));
}

#[tokio::test]
async fn quarantine_rejects_corrupt_version_truncated_pack_and_object_bomb() {
    let limits = StreamIngestLimits { max_pack_objects: 5, ..StreamIngestLimits::default() };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

    let mut slot1 = QuarantineSlot::create(None).unwrap();
    let bad_ver = [b'P', b'A', b'C', b'K', 0, 0, 0, 9, 0, 0, 0, 1];
    let r1 =
        ingest_pack_to_quarantine(Cursor::new(bad_ver), &mut slot1, GitObjectFormat::Sha1, 4, &limits, deadline).await;
    assert!(matches!(r1, Err(PushCausalError::CorruptPack(_))));
    assert!(slot1.sweep().dir_removed);

    let mut slot2 = QuarantineSlot::create(None).unwrap();
    let bomb = [b'P', b'A', b'C', b'K', 0, 0, 0, 2, 0, 0, 0, 99];
    let r2 =
        ingest_pack_to_quarantine(Cursor::new(bomb), &mut slot2, GitObjectFormat::Sha1, 4, &limits, deadline).await;
    assert!(matches!(r2, Err(PushCausalError::LimitExceeded(_))));
    assert!(slot2.sweep().dir_removed);

    let mut slot3 = QuarantineSlot::create(None).unwrap();
    let trunc = b"PACK\x00\x00\x00\x02\x00\x00\x00\x00short";
    let r3 =
        ingest_pack_to_quarantine(Cursor::new(trunc), &mut slot3, GitObjectFormat::Sha256, 4, &limits, deadline).await;
    assert!(matches!(r3, Err(PushCausalError::TruncatedPack(_))));
    assert!(slot3.sweep().dir_removed);
}

#[test]
fn ref_advertisement_verifies_capability_stacked_branches_force_with_lease_and_no_leak() {
    let oid1 = "1".repeat(40);
    let oid2 = "2".repeat(40);
    let oid_secret = "9".repeat(40);
    let refs = vec![
        VisibleRefEntry {
            ref_name: "refs/heads/main".into(),
            oid: oid1.clone(),
            visible_to_principal: true,
            is_shared_base: true,
            is_default_head: true,
        },
        VisibleRefEntry {
            ref_name: "refs/heads/stack-base".into(),
            oid: oid2.clone(),
            visible_to_principal: true,
            is_shared_base: false,
            is_default_head: false,
        },
        VisibleRefEntry {
            ref_name: "refs/heads/unrelated".into(),
            oid: oid2.clone(),
            visible_to_principal: true,
            is_shared_base: false,
            is_default_head: false,
        },
        VisibleRefEntry {
            ref_name: "refs/heads/secret".into(),
            oid: oid_secret,
            visible_to_principal: false,
            is_shared_base: false,
            is_default_head: false,
        },
    ];

    let client = ClientPushCapabilityProfile {
        protocol_version: 2,
        supports_narrowed_advertisement: true,
        compatibility_proof_id: Some("compat-v1".into()),
        supports_ofs_delta: true,
        supports_delete_refs: true,
        supports_atomic: true,
        object_format: GitObjectFormat::Sha1,
        requested_targets: BTreeSet::from(["refs/heads/stack-top".to_owned()]),
        stacked_parent_refs: BTreeMap::from([("refs/heads/stack-top".into(), vec!["refs/heads/stack-base".into()])]),
        force_with_lease_refs: BTreeMap::from([("refs/heads/main".into(), oid1.clone())]),
    };

    let narrowed = build_push_ref_advertisement(&AdvertisementRequest {
        repository_format: GitObjectFormat::Sha1,
        desired_strategy: AdvertisementStrategy::NarrowedSharedBases,
        client: client.clone(),
        auth: sample_auth(Uuid::new_v4()),
        refs: refs.clone(),
    })
    .unwrap();
    assert_eq!(narrowed.strategy_used, AdvertisementStrategy::NarrowedSharedBases);
    assert_eq!(narrowed.suppressed_unauthorized_count, 1);
    let names: BTreeSet<_> = narrowed.advertised_refs.iter().map(|r| r.ref_name.as_str()).collect();
    assert!(names.contains("refs/heads/main"));
    assert!(names.contains("refs/heads/stack-base"));
    assert!(!names.contains("refs/heads/secret"));
    assert!(!names.contains("refs/heads/unrelated"));

    let mut no_proof = client.clone();
    no_proof.compatibility_proof_id = None;
    let fallback = build_push_ref_advertisement(&AdvertisementRequest {
        repository_format: GitObjectFormat::Sha1,
        desired_strategy: AdvertisementStrategy::NarrowedSharedBases,
        client: no_proof,
        auth: sample_auth(Uuid::new_v4()),
        refs: refs.clone(),
    })
    .unwrap();
    assert_eq!(fallback.strategy_used, AdvertisementStrategy::FullAuthorizedFallback);
    assert!(fallback.advertised_refs.iter().all(|r| r.ref_name != "refs/heads/secret"));
    let adv_wire = encode_ref_advertisement(&fallback, GitObjectFormat::Sha1, true).unwrap();
    assert!(adv_wire.starts_with(b"001e# service=git-receive-pack\n0000"));

    let mut secret_lease = client;
    secret_lease.force_with_lease_refs.insert("refs/heads/secret".into(), oid2);
    let denied = build_push_ref_advertisement(&AdvertisementRequest {
        repository_format: GitObjectFormat::Sha1,
        desired_strategy: AdvertisementStrategy::NarrowedSharedBases,
        client: secret_lease,
        auth: sample_auth(Uuid::new_v4()),
        refs,
    });
    assert!(matches!(denied, Err(PushCausalError::AuthorizationDenied(_))));
}

#[test]
fn receipt_digest_binds_scope_and_auth_checks_lease_and_hold_retention() {
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let hist = Uuid::new_v4();
    let op = Uuid::new_v4();
    let mut receipt = CausalPushProofReceipt {
        receipt_version: 1,
        tenant_id: tenant,
        repository_id: repo,
        history_incarnation: hist,
        authority_epoch: 2,
        group_epoch: 1,
        object_format: GitObjectFormat::Sha256,
        operation_id: op,
        issuer_id: Uuid::new_v4(),
        lane: "push".into(),
        sequence: 1,
        base_snapshot_seq: 7,
        base_version_ids: vec![],
        required_ancestor_oids: vec![],
        resolved_thin_base_oids: vec![],
        base_closure_digest: "a".repeat(64),
        pack_sha256: None,
        pack_bytes: 0,
        idx_sha256: None,
        idx_bytes: 0,
        pack_locator: None,
        idx_locator: None,
        blob_backend_identity: "b".repeat(64),
        object_count: 1,
        delta_object_count: 0,
        max_delta_chain_depth: 0,
        duplicate_object_count: 0,
        blob_closure_digest: "c".repeat(64),
        accepted_updates: vec![AcceptedRefProof {
            ref_name: "refs/heads/main".into(),
            old_oid: None,
            new_oid: Some("d".repeat(64)),
            target_kind: "commit".into(),
        }],
        rejected_updates: vec![],
        accepted_subset_digest: "e".repeat(64),
        proof_digest: String::new(),
    };
    receipt.proof_digest = receipt.recompute_digest();
    receipt.verify_digest().unwrap();

    receipt.tenant_id = Uuid::new_v4();
    assert!(matches!(receipt.verify_digest(), Err(PushCausalError::ProofTampered(_))));

    let mut expired = sample_auth(Uuid::new_v4());
    expired.now_ms = 20_000;
    assert!(matches!(
        evaluate_push_auth_precheck(&expired, repo, None, FaultInjectionHook::None),
        Err(PushCausalError::StaleLease(_))
    ));

    let mut hold = OperationHoldGuard::acquire(op, vec![Uuid::new_v4()], vec![]);
    hold.mark_unknown_outcome();
    assert!(hold.release_on_proven_abort().is_err());
    assert_eq!(hold.state, HoldLifecycleState::ActiveHeld);

    let report = encode_receive_pack_report(
        &ReceiveCapabilities { report_status: true, sideband_64k: true, ..ReceiveCapabilities::default() },
        Ok(()),
        &[("refs/heads/main", Ok(())), ("refs/heads/other", Err("ref changed; retry from current refs"))],
    )
    .unwrap();
    let txt = String::from_utf8_lossy(&report);
    assert!(txt.contains("unpack ok\n") && txt.contains("ok refs/heads/main\n") && txt.contains("ng refs/heads/other"));
}

#[test]
fn version_graph_dependency_closure_blocks_foreign_or_retired_base_pack() {
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let hist = Uuid::new_v4();
    let realm = RefVersionRealm::new(tenant, repo, hist, AuthorityKind::Pg, 1, 0, 1, GitObjectFormat::Sha1);
    let other_realm =
        RefVersionRealm::new(Uuid::new_v4(), repo, hist, AuthorityKind::Pg, 1, 0, 1, GitObjectFormat::Sha1);

    let pack_id = Uuid::new_v4();
    let reg_id = Uuid::new_v4();
    let pack_digest = RequestDigest::of("pack", &[b"p1"]);
    let pack_entry = crate::ref_store::core::ref_version::PackSetEntry::new(pack_id, reg_id, pack_digest).unwrap();
    let pack_set_digest = compute_pack_set_digest(&[pack_entry]).unwrap();
    let op_id = Uuid::new_v4();
    let ref_name = RefName::branch("refs/heads/main").unwrap();
    let target_oid = GitOid::Sha1([0x11; 20]);
    let intent = RefVersionIntent::new(
        ref_name.clone(),
        RefVersionKind::Publish,
        RefPrecondition::Absent,
        BaseRequestSelector::ExplicitAbsent,
        RefTarget::Oid(target_oid),
    );
    let op_in = OperationDigestInput::new(
        other_realm,
        tenant,
        Uuid::new_v4(),
        IssuerLane::new("push").unwrap(),
        1,
        op_id,
        1,
        RequestDigest::of("gate", &[b"g"]),
        CommitMode::Atomic,
        HeadUpdate::Keep,
        vec![intent],
        RequestDigest::of("mem", &[b"m"]),
        vec![],
    );
    let op_dig = operation_digest(&op_in).unwrap();
    let vid = derive_candidate_version_id(&op_in, op_dig, &ref_name, None).unwrap();
    let cset = compute_commit_set_id(&CommitSetInput::new(
        other_realm,
        1,
        op_id,
        op_dig,
        vec![CommitSetVersionEntry::new(ref_name.clone(), vid, RefVersionKind::Publish, RefTarget::Oid(target_oid))],
        CommitSetHead::Absent,
    ))
    .unwrap();
    let rec = VersionRecord::seal(VersionRecordInput {
        version_id: vid,
        realm: other_realm,
        ref_name,
        ref_generation: 1,
        operation_id: op_id,
        operation_digest: op_dig,
        authority_seq: 1,
        kind: RefVersionKind::Publish,
        target: RefTarget::Oid(target_oid),
        base_version_id: None,
        object_deps: vec![],
        pack_set_digest,
        commit_set_id: cset,
    })
    .unwrap();
    let vpack = VerifiedClosurePack::new(pack_entry, tenant, repo, "s3", &"a".repeat(64), 1024, 2).unwrap();
    let mut graph = VersionGraph::new();
    graph.insert_active(CausalVersionNode { record: rec.clone(), own_packs: vec![vpack] });

    let snap = AuthorizedSnapshotState {
        realm,
        tenant_id: tenant,
        repository_id: repo,
        history_incarnation: hist,
        authority_epoch: 1,
        group_epoch: 1,
        expected_gate_revision: 1,
        object_format: GitObjectFormat::Sha1,
        snapshot_seq: 1,
        root_version_id: Some(rec.version_id()),
        current_refs: BTreeMap::new(),
        authorized_base_packs: vec![BasePackRef {
            version_id: rec.version_id().as_hex(),
            pack_id,
            registration_id: reg_id,
            artifact_set_digest_hex: pack_digest.as_hex(),
            pack_sha256: "b".repeat(64),
            pack_length: 512,
            idx_sha256: "c".repeat(64),
            idx_length: 512,
            pack_locator: BlobLocator::new(tenant, repo, 1, Uuid::new_v4(), "packs", &"b".repeat(64), 512).unwrap(),
            idx_locator: BlobLocator::new(tenant, repo, 1, Uuid::new_v4(), "pack-idx", &"c".repeat(64), 512).unwrap(),
            authorized_for_principal: true,
        }],
    };
    let res = verify_base_packs_and_dependencies(&snap, Some(&graph), &sample_auth(Uuid::new_v4()));
    assert!(matches!(res, Err(PushCausalError::UnauthorizedBaseDependency(_))));
}
