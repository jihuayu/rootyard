//! Unit tests covering shared-deadline pkt-line stalls, advertisement authz,
//! `#180` closure gates, `CausalPushProofReceipt` CAS subset binding, and reclaim ledgers (#183).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::time::{Duration, Instant};

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
use super::reclaim::{QuarantineReclaimLedger, StagingUploadIntent, UploadReclaimState};
use super::types::{
    AuthorizedSnapshotState, BasePackRef, FaultInjectionHook, OperationTicket, PushAuthContext, PushCausalError,
    ReceiveCapabilities, StreamIngestLimits,
};
use crate::blob_store::BlobLocator;
use crate::ref_store::contract::{IssuerLane, RequestDigest};
use crate::ref_store::core::contract::CommitMode;
use crate::ref_store::core::ref_version::{
    AuthorityKind, BaseRequestSelector, CausalVersionNode, CommitSetHead, CommitSetInput, CommitSetVersionEntry,
    OperationDigestInput, PackSetEntry, RefVersionIntent, RefVersionKind, RefVersionRealm, VersionGraph, VersionRecord,
    VersionRecordInput, compute_commit_set_id, compute_pack_set_digest, derive_candidate_version_id, operation_digest,
};
use crate::ref_store::core::terminal::{CommitRejectCode, RefCommitResult};
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
async fn decode_stream_handles_gzip_rejects_shallow_overflow_and_command_stall_deadline() {
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
    let shared_dl = Instant::now() + Duration::from_secs(5);
    let decoded =
        decode_receive_pack_stream(Cursor::new(gz), true, GitObjectFormat::Sha1, &limits, shared_dl).await.unwrap();
    assert_eq!(decoded.commands.len(), 1);
    assert!(decoded.capabilities.atomic && decoded.capabilities.report_status_v2);

    let mut slot = QuarantineSlot::create(None).unwrap();
    let ingested = ingest_pack_to_quarantine(
        decoded.remainder,
        &mut slot,
        GitObjectFormat::Sha1,
        decoded.command_bytes_read,
        &limits,
        shared_dl,
    )
    .await
    .unwrap();
    assert!(ingested.has_pack && ingested.incoming_pack_path.as_ref().unwrap().exists());
    assert!(slot.sweep().dir_removed);

    // Regression (#183 Merge Gate 1): slowloris stall mid-command fails closed on shared deadline.
    let (mut writer, reader) = tokio::io::duplex(256);
    let partial_cmd = &pkt_line(cmd.as_bytes())[..18];
    writer.write_all(partial_cmd).await.unwrap();
    let tight_dl = Instant::now() + Duration::from_millis(80);
    let stall_res = decode_receive_pack_stream(reader, false, GitObjectFormat::Sha1, &limits, tight_dl).await;
    assert!(matches!(stall_res, Err(PushCausalError::DeadlineExceeded)));
    drop(writer);

    let mut shallow_wire = pkt_line(b"shallow 1111111111111111111111111111111111111111\n");
    shallow_wire.extend_from_slice(&pkt_line(cmd.as_bytes()));
    shallow_wire.extend_from_slice(b"0000");
    let err =
        decode_receive_pack_stream(Cursor::new(shallow_wire), false, GitObjectFormat::Sha1, &limits, shared_dl).await;
    assert!(matches!(err, Err(PushCausalError::ShallowRejected)));

    let strict_limit = StreamIngestLimits { max_stream_bytes: 24, ..limits };
    let over =
        decode_receive_pack_stream(Cursor::new(wire), false, GitObjectFormat::Sha1, &strict_limit, shared_dl).await;
    assert!(matches!(over, Err(PushCausalError::LimitExceeded(_))));
}

#[tokio::test]
async fn quarantine_rejects_corrupt_version_truncated_pack_and_object_bomb() {
    let limits = StreamIngestLimits { max_pack_objects: 5, ..StreamIngestLimits::default() };
    let deadline = Instant::now() + Duration::from_secs(5);

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
            oid: "9".repeat(40),
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
        force_with_lease_refs: BTreeMap::from([("refs/heads/main".into(), oid1)]),
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
    let adv_wire = encode_ref_advertisement(&fallback, GitObjectFormat::Sha1, true).unwrap();
    assert!(adv_wire.starts_with(b"001f# service=git-receive-pack\n0000"));

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
fn receipt_binds_operation_snapshot_ticket_and_final_cas_subset_and_reclaim_persists() {
    let (tenant, repo, hist, op, issuer) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let realm = RefVersionRealm::new(tenant, repo, hist, AuthorityKind::Pg, 2, 0, 1, GitObjectFormat::Sha256);
    let snapshot = AuthorizedSnapshotState {
        realm,
        tenant_id: tenant,
        repository_id: repo,
        history_incarnation: hist,
        authority_epoch: 2,
        group_epoch: 1,
        expected_gate_revision: 4,
        object_format: GitObjectFormat::Sha256,
        snapshot_seq: 7,
        root_version_id: None,
        current_refs: BTreeMap::new(),
        authorized_base_packs: Vec::new(),
    };
    let ticket = OperationTicket { issuer_id: issuer, lane: "push".into(), sequence: 9, operation_id: op };
    let backend_hex = "b".repeat(64);
    let mut receipt = CausalPushProofReceipt {
        receipt_version: 2,
        tenant_id: tenant,
        repository_id: repo,
        history_incarnation: hist,
        authority_epoch: 2,
        group_epoch: 1,
        object_format: GitObjectFormat::Sha256,
        operation_id: op,
        issuer_id: issuer,
        lane: "push".into(),
        sequence: 9,
        base_snapshot_seq: 7,
        expected_gate_revision: 4,
        committed_gate_revision: None,
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
        blob_backend_identity: backend_hex.clone(),
        object_count: 2,
        delta_object_count: 0,
        max_delta_chain_depth: 0,
        duplicate_object_count: 0,
        blob_closure_digest: "c".repeat(64),
        accepted_updates: vec![
            AcceptedRefProof {
                ref_name: "refs/heads/main".into(),
                old_oid: None,
                new_oid: Some("d".repeat(64)),
                target_kind: "commit".into(),
            },
            AcceptedRefProof {
                ref_name: "refs/heads/stale".into(),
                old_oid: Some("1".repeat(64)),
                new_oid: Some("d".repeat(64)),
                target_kind: "commit".into(),
            },
        ],
        rejected_updates: vec![],
        accepted_subset_digest: "e".repeat(64),
        proof_digest: String::new(),
    };
    receipt.proof_digest = receipt.recompute_digest();
    receipt.verify_scope(&snapshot, &ticket, &backend_hex).unwrap();

    // Ticket mismatch (wrong sequence / operation_id) MUST fail closed.
    let bad_ticket = OperationTicket { sequence: 10, ..ticket.clone() };
    assert!(matches!(
        receipt.verify_scope(&snapshot, &bad_ticket, &backend_hex),
        Err(PushCausalError::ProofScopeMismatch)
    ));

    // AcceptedSubset CAS terminal rebinding: `stale` lost CAS race -> receipt must reflect exact CAS subset.
    let cas_refs = vec![
        RefCommitResult::Applied { name: "refs/heads/main".into(), old_oid: None, new_oid: Some("d".repeat(64)) },
        RefCommitResult::NotApplied { name: "refs/heads/stale".into(), reason: CommitRejectCode::OldOidMismatch },
    ];
    assert!(receipt.verify_commit_binding(&snapshot, &ticket, &backend_hex, &cas_refs).is_err());
    receipt.rebind_final_cas_terminal(&snapshot, &ticket, &backend_hex, Some(5), &cas_refs).unwrap();
    assert_eq!(receipt.accepted_updates.len(), 1);
    assert_eq!(receipt.rejected_updates.len(), 1);
    assert_eq!(receipt.committed_gate_revision, Some(5));
    receipt.verify_commit_binding(&snapshot, &ticket, &backend_hex, &cas_refs).unwrap();

    // Recoverable reclaim ledger (#183 Merge Gate 4): partial & unknown upload records survive & gate reclaim.
    let tmp = tempfile::tempdir().unwrap();
    let ledger = QuarantineReclaimLedger::open(tmp.path().join("reclaim")).unwrap();
    ledger
        .record_inflight(&StagingUploadIntent {
            operation_id: op,
            tenant_id: tenant,
            repository_id: repo,
            generation: 2,
            backend_identity: &backend_hex,
            pack_sha256: &"1".repeat(64),
            pack_bytes: 4096,
            idx_sha256: &"2".repeat(64),
            idx_bytes: 1024,
        })
        .unwrap();
    ledger.transition(op, UploadReclaimState::OutcomeUnknown, vec!["tenant/pack-a".into()], 4096, "timeout").unwrap();
    assert_eq!(ledger.list_recoverable().unwrap().len(), 1);
    assert!(matches!(ledger.mark_reclaimed_if_proven_aborted(op, false), Err(PushCausalError::CommitUnknown { .. })));
    ledger.mark_reclaimed_if_proven_aborted(op, true).unwrap();
    assert!(ledger.list_recoverable().unwrap().is_empty());

    let mut expired = sample_auth(Uuid::new_v4());
    expired.now_ms = 20_000;
    assert!(matches!(
        evaluate_push_auth_precheck(&expired, repo, None, FaultInjectionHook::None),
        Err(PushCausalError::StaleLease(_))
    ));
    let mut hold = OperationHoldGuard::acquire(op, vec![Uuid::new_v4()], vec![]);
    hold.mark_unknown_outcome();
    assert!(hold.release_on_proven_abort().is_err() && hold.state == HoldLifecycleState::ActiveHeld);

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
fn base_closure_rejects_missing_closure_empty_closure_and_foreign_pack() {
    let (tenant, repo, hist) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let realm = RefVersionRealm::new(tenant, repo, hist, AuthorityKind::Pg, 1, 0, 1, GitObjectFormat::Sha1);
    let pack_id = Uuid::new_v4();
    let reg_id = Uuid::new_v4();
    let pack_digest = RequestDigest::of("pack", &[b"p1"]);
    let pack_entry = PackSetEntry::new(pack_id, reg_id, pack_digest).unwrap();
    let base_ref = BasePackRef {
        version_id: "v1".into(),
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
    };

    // Case 1 (#183 Merge Gate 2): root_version_id absent (`None`) while base packs exist -> MUST fail closed.
    let missing_closure_snap = AuthorizedSnapshotState {
        realm,
        tenant_id: tenant,
        repository_id: repo,
        history_incarnation: hist,
        authority_epoch: 1,
        group_epoch: 1,
        expected_gate_revision: 1,
        object_format: GitObjectFormat::Sha1,
        snapshot_seq: 1,
        root_version_id: None,
        current_refs: BTreeMap::new(),
        authorized_base_packs: vec![base_ref.clone()],
    };
    assert!(matches!(
        verify_base_packs_and_dependencies(&missing_closure_snap, None, &sample_auth(Uuid::new_v4())),
        Err(PushCausalError::UnauthorizedBaseDependency(_))
    ));

    // Case 2 (#183 Merge Gate 2): verified VersionGraph with EMPTY `own_packs` -> MUST fail closed.
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
        realm,
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
        realm,
        1,
        op_id,
        op_dig,
        vec![CommitSetVersionEntry::new(ref_name.clone(), vid, RefVersionKind::Publish, RefTarget::Oid(target_oid))],
        CommitSetHead::Absent,
    ))
    .unwrap();
    let rec_empty = VersionRecord::seal(VersionRecordInput {
        version_id: vid,
        realm,
        ref_name,
        ref_generation: 1,
        operation_id: op_id,
        operation_digest: op_dig,
        authority_seq: 1,
        kind: RefVersionKind::Publish,
        target: RefTarget::Oid(target_oid),
        base_version_id: None,
        object_deps: vec![],
        pack_set_digest: compute_pack_set_digest(&[]).unwrap(),
        commit_set_id: cset,
    })
    .unwrap();
    let mut empty_pack_graph = VersionGraph::new();
    empty_pack_graph.insert_active(CausalVersionNode { record: rec_empty, own_packs: vec![] });
    let mut empty_closure_snap = missing_closure_snap;
    empty_closure_snap.root_version_id = Some(vid);
    assert!(matches!(
        verify_base_packs_and_dependencies(&empty_closure_snap, Some(&empty_pack_graph), &sample_auth(Uuid::new_v4()),),
        Err(PushCausalError::UnauthorizedBaseDependency(_))
    ));
    let _ = pack_entry;
}
