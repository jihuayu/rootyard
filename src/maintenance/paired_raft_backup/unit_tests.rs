use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::ref_store::contract::{MetadataPinPurpose, RequestDigest};
use crate::ref_store::core::state_machine::{
    BeginOperationCommand, CommitRefsCommand, CreateSnapshotPinCommand, InitializeGateCommand, RefCasCommand,
    RepositoryLane, ScopeLifecycle, SmPackMode, WireCommitRefsRequest, WireGateInit, WireOperationIdentity,
};
use crate::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, RefName,
    RefPrecondition, RefTarget, RefUpdate,
};

use super::freeze_drain::{InFlightOperation, RepoBackupRegistrationSpec, TriPartyBackupCoordinator};
use super::git_verify::{seed_commit_pack, verify_bare_repo_from_blobs};
use super::quorum_wal::{DurableRaftBackend, WalSyncedRaftBackend};
use super::restore::IncarnationAdmissionGuard;
use super::types::{
    BlobArtifactEntry, BlobClosureManifest, CloseScopeBarrierReceipt, DecisionExecutionTicket, DeleterLeaseTicket,
    ExpectedPackPairSpec, NewIncarnationAuthority, PAIRED_BACKUP_FORMAT_V1, PairedBackupError, PairedBackupManifest,
    PgCutpointProof, PgProjectionCursorCut, PgRepositoryRowProof, RaftCutpointProof, WriterGrantTicket,
    sha256_json_tagged,
};

pub(super) fn seed_wal_raft(
    wal_path: &std::path::Path,
    group_id: i64,
    repo: Uuid,
    tenant: Uuid,
    issuer: Uuid,
    history: Uuid,
    group_epoch: i64,
) -> (WalSyncedRaftBackend, String, ExpectedPackPairSpec) {
    let mut raft = WalSyncedRaftBackend::open_group(wal_path, group_id, 1).expect("open wal");
    let head = RefName::branch("refs/heads/main").expect("branch");
    let init = CoreGateInit::new(repo, tenant, GitObjectFormat::Sha256, history, 2, group_epoch, head).expect("gate");
    raft.commit_and_apply(RefCasCommand::InitializeGate(InitializeGateCommand {
        gate: WireGateInit::from(&init),
        pack_mode: SmPackMode::MetadataOnly,
        lane: RepositoryLane::ServingRefStore,
        authz_floor: 5,
    }))
    .expect("init gate");

    let commit_hex = "a".repeat(64);
    let oid = GitOid::parse(GitObjectFormat::Sha256, &commit_hex).expect("oid");
    let upd =
        RefUpdate::new(RefName::new("refs/heads/main").expect("ref"), RefPrecondition::Absent, RefTarget::Oid(oid));
    let lane = IssuerLane::new("pack").expect("lane");
    let req = CommitRefsRequest::new(
        repo,
        tenant,
        issuer,
        lane,
        1,
        Uuid::new_v4(),
        GitObjectFormat::Sha256,
        history,
        2,
        group_epoch,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![upd],
    )
    .expect("req");
    raft.commit_and_apply(RefCasCommand::CommitRefs(CommitRefsCommand {
        request: WireCommitRefsRequest::from(&req),
        decision_id: None,
        required_holds: Vec::new(),
        policy_rejects: BTreeMap::new(),
        logical_tick: 10,
    }))
    .expect("commit");
    let pair = ExpectedPackPairSpec {
        pack_id: Uuid::new_v4(),
        pack_sha256: RequestDigest::of("pack-sha", &[repo.as_bytes()]).as_hex(),
        pack_bytes: 2048,
        idx_sha256: RequestDigest::of("idx-sha", &[repo.as_bytes()]).as_hex(),
        idx_bytes: 512,
    };
    (raft, commit_hex, pair)
}

#[test]
fn tri_party_freeze_enforces_unknown_drain_and_complete_pin_closure() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (repo, tenant, issuer, history, auth_id) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (mut raft, _commit_hex, pair1) =
        seed_wal_raft(&dir.path().join("raft.wal"), 1, repo, tenant, issuer, history, 3);

    let extra_pack_sha = RequestDigest::of("extra-pinned-pack", &[tenant.as_bytes()]).as_hex();
    let gate_digest = raft
        .durable_state_machine()
        .read_gate_version(repo)
        .expect("read gate")
        .expect("gate exists")
        .digest()
        .as_hex();
    raft.commit_and_apply(RefCasCommand::CreateSnapshotPin(CreateSnapshotPinCommand {
        request_id: Uuid::new_v4(),
        repository_id: repo,
        tenant_id: tenant,
        owner_id: tenant,
        purpose: MetadataPinPurpose::Verification,
        snapshot_id: Uuid::new_v4(),
        pin_id: Uuid::new_v4(),
        object_format: GitObjectFormat::Sha256,
        history_incarnation: history,
        authority_epoch: 2,
        group_epoch: 3,
        expected_gate_digest: gate_digest,
        lease_ticks: 600,
        logical_tick: 11,
        pack_digests: vec![pair1.pack_sha256.clone(), extra_pack_sha.clone()],
        request_digest: RequestDigest::of("live-read-pin", &[repo.as_bytes()]).as_hex(),
    }))
    .expect("live read pin");

    let pending_op = Uuid::new_v4();
    let op_digest = RequestDigest::of("pending-op", &[pending_op.as_bytes()]).as_hex();
    let lane = IssuerLane::new("pack").expect("lane");
    raft.commit_and_apply(RefCasCommand::BeginOperation(BeginOperationCommand {
        identity: WireOperationIdentity {
            repository_id: repo,
            issuer_id: issuer,
            lane: lane.as_str().to_owned(),
            sequence: 2,
            operation_id: pending_op,
            digest: op_digest.clone(),
        },
        logical_tick: 12,
    }))
    .expect("begin op");

    let mut coord = TriPartyBackupCoordinator::new(10, 4);
    coord.track_in_flight(InFlightOperation {
        repository_id: repo,
        issuer_id: issuer,
        lane,
        sequence: 2,
        operation_id: pending_op,
        request_digest: op_digest,
        decision_id: None,
        settled_committed: false,
    });

    let pair2 = ExpectedPackPairSpec {
        pack_id: Uuid::new_v4(),
        pack_sha256: extra_pack_sha,
        pack_bytes: 1024,
        idx_sha256: RequestDigest::of("extra-pinned-idx", &[tenant.as_bytes()]).as_hex(),
        idx_bytes: 256,
    };
    let backend = RequestDigest::of("backend", &[auth_id.as_bytes()]).as_hex();
    let incomplete_specs = vec![RepoBackupRegistrationSpec {
        repository_id: repo,
        tenant_id: tenant,
        owner_id: tenant,
        object_format: GitObjectFormat::Sha256,
        history_incarnation: history,
        authority_epoch: 2,
        group_epoch: 3,
        authority_id: auth_id,
        authority_generation: 1,
        backend_identity: backend,
        expected_packs: vec![pair1.clone()],
    }];
    let full_specs =
        vec![RepoBackupRegistrationSpec { expected_packs: vec![pair1, pair2], ..incomplete_specs[0].clone() }];

    assert!(matches!(
        coord.freeze_drain_and_register(&mut raft, &full_specs, 12, false).unwrap_err(),
        PairedBackupError::UnknownInFlightOperations(1)
    ));
    assert!(!coord.status().app_paused && coord.active_barrier().is_none());

    assert!(matches!(
        coord.freeze_drain_and_register(&mut raft, &incomplete_specs, 12, true).unwrap_err(),
        PairedBackupError::BlobClosureIncomplete(_)
    ));
    assert!(!coord.status().app_paused && coord.active_barrier().is_none());

    let mut fresh_coord = TriPartyBackupCoordinator::new(10, 4);
    let barrier = fresh_coord.freeze_drain_and_register(&mut raft, &full_specs, 12, true).expect("durable freeze");
    barrier.verify().expect("barrier valid");
    assert_eq!(barrier.close_receipts.len(), 3);
    assert_eq!(barrier.backup_holds[0].hold_ids.len(), 4);
    for cr in &barrier.close_receipts {
        assert_eq!(cr.lifecycle, ScopeLifecycle::Closed);
    }
    assert!(raft.durable_state_machine().has_cancel_tombstone(repo, pending_op));
    assert!(fresh_coord.admit_app_write().is_err());
    assert!(fresh_coord.admit_worker_lease().is_err());
    assert!(fresh_coord.admit_deleter(11).is_err());
}

#[test]
fn manifest_digest_tamper_and_incarnation_guard_checks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (repo, tenant, issuer, history, auth_id) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (mut raft, commit_hex, pair) =
        seed_wal_raft(&dir.path().join("raft2.wal"), 1, repo, tenant, issuer, history, 3);
    let backend = RequestDigest::of("backend", &[auth_id.as_bytes()]).as_hex();
    let specs = vec![RepoBackupRegistrationSpec {
        repository_id: repo,
        tenant_id: tenant,
        owner_id: tenant,
        object_format: GitObjectFormat::Sha256,
        history_incarnation: history,
        authority_epoch: 2,
        group_epoch: 3,
        authority_id: auth_id,
        authority_generation: 1,
        backend_identity: backend.clone(),
        expected_packs: vec![pair.clone()],
    }];
    let mut coord = TriPartyBackupCoordinator::new(3, 1);
    let barrier = coord.freeze_drain_and_register(&mut raft, &specs, 15, true).expect("freeze");
    let (snap, state_digest) = raft.durable_state().expect("durable state");
    let applied = snap.body.last_applied.expect("applied");
    let refs = BTreeMap::from([("refs/heads/main".to_owned(), commit_hex)]);

    let pg = PgCutpointProof {
        schema_head_version: 149,
        wal_lsn: "0/16B6C50".into(),
        snapshot_tx: "100:100:".into(),
        postgres_major_version: "17.4".into(),
        source_cluster_incarnation: Uuid::new_v4(),
        source_storage_authority_id: auth_id,
        source_storage_generation: 1,
        remote_delete_fenced: true,
        max_decision_scope_version: 18,
        pending_decisions_count: 0,
        pending_outbox_count: 0,
        projection_cursors: vec![PgProjectionCursorCut {
            group_id: 1,
            history_incarnation: history,
            group_epoch: 3,
            applied_event_seq: snap.body.next_event_seq as i64,
            applied_log_index: applied.index as i64,
            applied_log_term: applied.term as i64,
            last_event_id: None,
            stream_state: "active".into(),
        }],
        repositories: vec![PgRepositoryRowProof {
            repository_id: repo,
            tenant_id: tenant,
            name: "demo".into(),
            object_format: GitObjectFormat::Sha256,
            storage_backend: "pg_refstore".into(),
            history_incarnation: history,
            authority_epoch: 2,
            group_epoch: 3,
            gate_revision: 2,
            refs_digest: sha256_json_tagged(b"rootyard-pg-refs-v1", &refs).expect("digest"),
            refs,
        }],
        cutpoint_digest: String::new(),
    }
    .seal()
    .expect("seal pg");

    let closure = BlobClosureManifest {
        backend_identity: backend.clone(),
        provider: "s3".into(),
        total_artifacts: 2,
        total_bytes: pair.pack_bytes + pair.idx_bytes,
        entries: vec![
            BlobArtifactEntry {
                repository_id: repo,
                tenant_id: tenant,
                pack_id: pair.pack_id,
                object_format: GitObjectFormat::Sha256,
                role: "pack".into(),
                locator_path: "blobs/pack".into(),
                archive_rel_path: "blobs/pack".into(),
                attempt_id: Uuid::new_v4(),
                generation: 1,
                length: pair.pack_bytes,
                sha256: pair.pack_sha256,
                backend_identity: backend.clone(),
            },
            BlobArtifactEntry {
                repository_id: repo,
                tenant_id: tenant,
                pack_id: pair.pack_id,
                object_format: GitObjectFormat::Sha256,
                role: "idx".into(),
                locator_path: "blobs/idx".into(),
                archive_rel_path: "blobs/idx".into(),
                attempt_id: Uuid::new_v4(),
                generation: 1,
                length: pair.idx_bytes,
                sha256: pair.idx_sha256,
                backend_identity: backend,
            },
        ],
        closure_digest: String::new(),
    }
    .seal()
    .expect("closure");

    let active_voter_ids = raft.voter_ids();
    let active_cutpoint_attestations =
        raft.attest_group_cutpoint(3, &snap, &state_digest).expect("cutpoint attestations");
    let manifest = PairedBackupManifest {
        format_version: PAIRED_BACKUP_FORMAT_V1.into(),
        backup_id: Uuid::new_v4(),
        created_unix_seconds: 1_760_000_000,
        freeze: barrier.status,
        pg_cutpoint: pg.clone(),
        raft_cutpoint: RaftCutpointProof {
            group_id: 1,
            group_epochs: BTreeMap::from([(1, 3)]),
            peer_groups: Vec::new(),
            applied_log_id: applied,
            logical_clock_floor: snap.body.logical_clock_floor,
            state_digest,
            group_membership_digest: raft.group_membership_digest(),
            voter_ids: active_voter_ids,
            cutpoint_attestations: active_cutpoint_attestations,
            snapshot_checksum: snap.checksum.clone(),
            snapshot: snap,
            close_receipts: barrier.close_receipts,
            backup_holds: barrier.backup_holds,
        },
        blob_closure: closure,
        paired_cut_digest: String::new(),
    }
    .seal()
    .expect("manifest");

    let mut raw_val = serde_json::to_value(&manifest).expect("json");
    raw_val.as_object_mut().expect("obj").insert("rogue_field".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<PairedBackupManifest>(raw_val).is_err());

    let mut tampered = manifest;
    tampered.pg_cutpoint.wal_lsn = "0/DEADBEEF".into();
    assert!(tampered.pg_cutpoint.verify().is_err());
    let mut bad_receipt: CloseScopeBarrierReceipt = tampered.raft_cutpoint.close_receipts[0].clone();
    bad_receipt.authz_floor += 1;
    assert!(bad_receipt.verify().is_err());

    let (new_cluster, new_auth, new_hist, fenced_dec) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let guard = IncarnationAdmissionGuard {
        live: NewIncarnationAuthority {
            new_cluster_incarnation: new_cluster,
            new_storage_authority_id: new_auth,
            new_storage_generation: 2,
            new_history_incarnation: new_hist,
            new_authority_epoch: 3,
            new_group_epoch: 4,
            new_authz_floor: 28,
            new_deleter_epoch: 5,
            fenced_prior_incarnations: BTreeSet::from([pg.source_cluster_incarnation, history, auth_id]),
            fenced_pre_backup_decision_ids: BTreeSet::from([fenced_dec]),
        },
    };
    assert!(
        guard
            .verify_writer_grant(&WriterGrantTicket {
                cluster_incarnation: new_cluster,
                history_incarnation: new_hist,
                authority_epoch: 3,
                group_epoch: 4,
                authz_epoch: 28,
            })
            .is_ok()
    );
    assert!(matches!(
        guard.verify_writer_grant(&WriterGrantTicket {
            cluster_incarnation: new_cluster,
            history_incarnation: new_hist,
            authority_epoch: 3,
            group_epoch: 4,
            authz_epoch: 27,
        }),
        Err(PairedBackupError::StaleGrantRefused(_))
    ));
    assert!(matches!(
        guard.verify_decision_execution(&DecisionExecutionTicket {
            decision_id: fenced_dec,
            history_incarnation: new_hist,
            authority_epoch: 3,
            group_epoch: 4,
            authz_epoch: 28,
        }),
        Err(PairedBackupError::StaleDecisionRefused(_))
    ));
    assert!(matches!(
        guard.verify_deleter_lease(&DeleterLeaseTicket {
            cluster_incarnation: new_cluster,
            storage_authority_id: auth_id,
            storage_generation: 1,
            deleter_epoch: 4,
        }),
        Err(PairedBackupError::StaleDeleterRefused(_))
    ));
}

#[test]
fn git_verify_roundtrip_sha1_and_sha256_reverse_pack_order_and_rejects_corrupt_pack() {
    for fmt in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let dir = tempfile::tempdir().expect("tempdir");
        let seed_dir = dir.path().join("seed");
        let (c1, pack1, idx1) =
            seed_commit_pack(&seed_dir, fmt, "hello.txt", b"paired-backup-payload\n", None).expect("seed commit 1");
        let (commit, pack2, idx2) =
            seed_commit_pack(&seed_dir, fmt, "next.txt", b"second-pack\n", Some(&c1)).expect("seed commit 2");
        let refs = BTreeMap::from([("refs/heads/main".to_owned(), commit)]);
        let n = verify_bare_repo_from_blobs(
            &dir.path().join("bare"),
            fmt,
            &refs,
            &[(pack2.clone(), idx2), (pack1.clone(), idx1.clone())],
            &dir.path().join("clone"),
        )
        .expect("git fsck & clone pass even when incremental pack precedes base pack");
        assert_eq!(n, 1);

        let corrupt_pack = dir.path().join("corrupt.pack");
        let mut bytes = std::fs::read(&pack1).expect("read pack");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        std::fs::write(&corrupt_pack, bytes).expect("write corrupt pack");
        assert!(
            verify_bare_repo_from_blobs(
                &dir.path().join("bare-bad"),
                fmt,
                &refs,
                &[(corrupt_pack, idx1)],
                &dir.path().join("clone-bad"),
            )
            .is_err()
        );
    }
}
